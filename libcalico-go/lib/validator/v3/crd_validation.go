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

	schemadefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	schemavalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
)

// defaultAndValidateCRD applies CRD schema defaults to the object in-place
// and then runs CRD validation rules (OpenAPI schema constraints + CEL
// x-kubernetes-validations). A single toUnstructured conversion is shared
// between defaulting and validation to avoid redundant JSON round-trips.
//
// For create operations, pass nil for oldObj.
// For update operations, pass the previous version as oldObj.
//
// Returns nil if CRD validation is disabled, the object's Kind has no CRD
// schema, or if defaulting and validation both succeed.
func defaultAndValidateCRD(ctx context.Context, obj runtime.Object, oldObj runtime.Object) field.ErrorList {
	reg := crdRegistry.Load()
	if reg == nil {
		return nil
	}

	// Load all CRD schemas once (cheap).
	reg.loadOnce.Do(reg.load)
	if reg.loadErr != nil {
		return field.ErrorList{field.InternalError(nil, reg.loadErr)}
	}

	kind := resolveKind(obj)

	schema, ok := reg.schemas[kind]
	if !ok {
		return nil
	}

	// Compile validators for this Kind if needed (expensive, once per Kind).
	schema.compile(kind)

	// Convert to unstructured map representation once, shared by both
	// defaulting and validation.
	unstructuredObj, err := toUnstructured(obj)
	if err != nil {
		return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to convert object to unstructured: %w", err))}
	}

	// Apply CRD schema defaults to the unstructured representation.
	if schema.structural != nil {
		schemadefaulting.Default(unstructuredObj, schema.structural)
	}

	// Validate the defaulted unstructured data.
	var allErrs field.ErrorList

	// Run OpenAPI schema validation (MinItems, MaxLength, Pattern, Enum, etc.).
	if schema.schemaValidator != nil {
		allErrs = append(allErrs, schemavalidation.ValidateCustomResource(nil, unstructuredObj, schema.schemaValidator)...)
	}

	// Run CEL validation (x-kubernetes-validations rules).
	if schema.celValidator != nil {
		var unstructuredOldObj any
		if oldObj != nil {
			unstructuredOldObj, err = toUnstructured(oldObj)
			if err != nil {
				return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to convert old object to unstructured: %w", err))}
			}
		}

		celErrs, _ := schema.celValidator.Validate(ctx, nil, nil, unstructuredObj, unstructuredOldObj, int64(celconfig.RuntimeCELCostBudget))
		allErrs = append(allErrs, celErrs...)
	}

	// Convert the defaulted unstructured data back into the typed object so
	// the caller sees the applied defaults. We use the converter here (rather
	// than JSON) because the reverse direction doesn't have the numeric type
	// mismatch problem that forces toUnstructured to use a JSON round-trip.
	if m, ok := unstructuredObj.(map[string]any); ok {
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, obj); err != nil {
			allErrs = append(allErrs, field.InternalError(nil, fmt.Errorf("failed to convert defaulted %s from unstructured: %w", kind, err)))
		}
	}

	return allErrs
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
