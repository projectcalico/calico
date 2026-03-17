// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v3

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	calicoapi "github.com/projectcalico/api"
	"github.com/sirupsen/logrus"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	celvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	schemadefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	schemavalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
)

var (
	// celValidators maps CRD Kind to its compiled CEL validator.
	celValidators map[string]*celvalidation.Validator

	// schemaValidators maps CRD Kind to its OpenAPI schema validator, which
	// enforces constraints like MinItems, MaxLength, Pattern, Enum, etc.
	schemaValidators map[string]schemavalidation.SchemaCreateValidator

	// schemas maps CRD Kind to its structural schema.
	schemas map[string]*structuralschema.Structural

	// crdInitErr captures any error from init() so callers can surface it.
	crdInitErr error
)

// init loads all embedded CRDs, converts their schemas, and compiles
// validators for CEL rules and OpenAPI schema constraints.
func init() {
	celValidators = make(map[string]*celvalidation.Validator)
	schemaValidators = make(map[string]schemavalidation.SchemaCreateValidator)
	schemas = make(map[string]*structuralschema.Structural)

	crds, err := calicoapi.AllCRDs()
	if err != nil {
		crdInitErr = fmt.Errorf("failed to load CRDs: %w", err)
		return
	}

	for _, crd := range crds {
		kind := crd.Spec.Names.Kind
		if len(crd.Spec.Versions) == 0 {
			continue
		}

		// Find the storage version's schema.
		var version *apiextensionsv1.CustomResourceDefinitionVersion
		for i := range crd.Spec.Versions {
			if crd.Spec.Versions[i].Storage {
				version = &crd.Spec.Versions[i]
				break
			}
		}
		if version == nil {
			version = &crd.Spec.Versions[0]
		}
		if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
			continue
		}

		// Convert v1 JSONSchemaProps to internal.
		internalSchema := &apiextensions.JSONSchemaProps{}
		err := apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
			version.Schema.OpenAPIV3Schema,
			internalSchema,
			nil,
		)
		if err != nil {
			logrus.WithError(err).WithField("kind", kind).Warn("Failed to convert CRD schema to internal format")
			continue
		}

		// Build OpenAPI schema validator for constraints like MinItems,
		// MaxLength, Pattern, Enum, Required, etc.
		sv, _, err := schemavalidation.NewSchemaValidator(internalSchema)
		if err != nil {
			logrus.WithError(err).WithField("kind", kind).Warn("Failed to create schema validator from CRD")
		} else {
			schemaValidators[kind] = sv
		}

		// Convert to structural schema for CEL compilation.
		structural, err := structuralschema.NewStructural(internalSchema)
		if err != nil {
			logrus.WithError(err).WithField("kind", kind).Warn("Failed to create structural schema from CRD")
			continue
		}
		schemas[kind] = structural

		// Compile CEL validator. Returns nil if no x-kubernetes-validations exist.
		v := celvalidation.NewValidator(structural, true, celconfig.PerCallLimit)
		if v != nil {
			celValidators[kind] = v
		}

		logrus.WithField("kind", kind).Debug("Compiled CRD validators")
	}
}

// defaultAndValidateCRD applies CRD schema defaults to the object in-place
// and then runs CRD validation rules (OpenAPI schema constraints + CEL
// x-kubernetes-validations). A single toUnstructured conversion is shared
// between defaulting and validation to avoid redundant JSON round-trips.
//
// For create operations, pass nil for oldObj.
// For update operations, pass the previous version as oldObj.
//
// Returns nil if the object's Kind has no CRD schema, or if defaulting and
// validation both succeed.
func defaultAndValidateCRD(ctx context.Context, obj runtime.Object, oldObj runtime.Object) field.ErrorList {
	if crdInitErr != nil {
		return field.ErrorList{field.InternalError(nil, crdInitErr)}
	}

	kind := resolveKind(obj)

	// Convert to unstructured map representation once, shared by both
	// defaulting and validation.
	unstructuredObj, err := toUnstructured(obj)
	if err != nil {
		return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to convert object to unstructured: %w", err))}
	}

	// Apply CRD schema defaults to the unstructured representation, then
	// marshal them back into the typed object so the caller sees the
	// defaulted values.
	if s, ok := schemas[kind]; ok {
		schemadefaulting.Default(unstructuredObj, s)

		raw, err := json.Marshal(unstructuredObj)
		if err != nil {
			return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to marshal defaulted %s: %w", kind, err))}
		}
		if err := json.Unmarshal(raw, obj); err != nil {
			return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to unmarshal defaulted %s: %w", kind, err))}
		}
	}

	var allErrs field.ErrorList

	// Run OpenAPI schema validation (MinItems, MaxLength, Pattern, Enum, etc.).
	if sv, ok := schemaValidators[kind]; ok {
		allErrs = append(allErrs, schemavalidation.ValidateCustomResource(nil, unstructuredObj, sv)...)
	}

	// Run CEL validation (x-kubernetes-validations rules).
	if cv, ok := celValidators[kind]; ok {
		var unstructuredOldObj any
		if oldObj != nil {
			unstructuredOldObj, err = toUnstructured(oldObj)
			if err != nil {
				return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to convert old object to unstructured: %w", err))}
			}
		}

		celErrs, _ := cv.Validate(ctx, nil, nil, unstructuredObj, unstructuredOldObj, int64(celconfig.RuntimeCELCostBudget))
		allErrs = append(allErrs, celErrs...)
	}

	return allErrs
}

// ApplyCRDDefaults applies CRD schema default values to the given object,
// matching the defaulting behavior the Kubernetes API server performs on
// admission. This is needed for etcd-mode clients where no API server is
// present to apply defaults.
//
// The object is modified in-place. Returns an error only on conversion
// failures; returns nil if the object's Kind has no CRD schema or no
// defaults to apply.
func ApplyCRDDefaults(obj runtime.Object) error {
	if crdInitErr != nil {
		return crdInitErr
	}

	kind := resolveKind(obj)
	s, ok := schemas[kind]
	if !ok {
		return nil
	}

	// Convert to unstructured so we can apply defaults.
	unstructuredObj, err := toUnstructured(obj)
	if err != nil {
		return fmt.Errorf("failed to convert %s to unstructured: %w", kind, err)
	}

	// Apply CRD schema defaults to the unstructured representation.
	schemadefaulting.Default(unstructuredObj, s)

	// Marshal the defaulted unstructured map back into the typed object.
	raw, err := json.Marshal(unstructuredObj)
	if err != nil {
		return fmt.Errorf("failed to marshal defaulted %s: %w", kind, err)
	}
	if err := json.Unmarshal(raw, obj); err != nil {
		return fmt.Errorf("failed to unmarshal defaulted %s: %w", kind, err)
	}

	return nil
}

// resolveKind returns the Kind string for a runtime.Object, falling back to
// the Go type name if TypeMeta isn't set.
func resolveKind(obj runtime.Object) string {
	kind := obj.GetObjectKind().GroupVersionKind().Kind
	if kind == "" {
		t := reflect.TypeOf(obj)
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		kind = t.Name()
	}
	return kind
}

func toUnstructured(obj runtime.Object) (any, error) {
	// If already unstructured, use the underlying map directly.
	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u.Object, nil
	}

	// Use JSON round-trip instead of runtime.DefaultUnstructuredConverter so
	// that numeric types match what the API server sees. The converter uses
	// reflection and preserves Go types (e.g. uint32 → uint64), but the API
	// server receives JSON where all numbers decode as float64 or int64.
	// Without this, CEL rules fail at runtime with type mismatches like
	// "expected int, got uint64" for fields such as numorstring.ASNumber.
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	// encoding/json decodes all numbers as float64 into interface{}, but CEL
	// expects integer-typed fields as int64. Convert exact-integer float64
	// values to int64, matching the k8s API server's internal representation.
	normalizeNumbers(data)
	return data, nil
}

// normalizeNumbers recursively walks an unstructured map and converts float64
// values that represent exact integers to int64.
func normalizeNumbers(v any) {
	switch val := v.(type) {
	case map[string]any:
		for k, elem := range val {
			if f, ok := elem.(float64); ok {
				if f == float64(int64(f)) {
					val[k] = int64(f)
				}
			} else {
				normalizeNumbers(elem)
			}
		}
	case []any:
		for i, elem := range val {
			if f, ok := elem.(float64); ok {
				if f == float64(int64(f)) {
					val[i] = int64(f)
				}
			} else {
				normalizeNumbers(elem)
			}
		}
	}
}
