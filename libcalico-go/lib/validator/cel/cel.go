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

package cel

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	celvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/projectcalico/calico/libcalico-go/config"
)

// validators maps CRD Kind to its compiled CEL validator.
// Populated once via initValidators.
var validators map[string]*celvalidation.Validator

// schemas maps CRD Kind to its structural schema (needed by Validate signature but unused internally).
var schemas map[string]*structuralschema.Structural

var initOnce sync.Once
var initErr error

// initValidators loads all embedded CRDs, converts their schemas, and compiles
// CEL validators for any that contain x-kubernetes-validations rules.
func initValidators() {
	validators = make(map[string]*celvalidation.Validator)
	schemas = make(map[string]*structuralschema.Structural)

	crds, err := config.AllCRDs()
	if err != nil {
		initErr = fmt.Errorf("failed to load CRDs: %w", err)
		return
	}

	for _, crd := range crds {
		kind := crd.Spec.Names.Kind
		if len(crd.Spec.Versions) == 0 {
			continue
		}

		// Use the first (storage) version's schema.
		version := crd.Spec.Versions[0]
		if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
			continue
		}

		// Convert v1 JSONSchemaProps to internal.
		internalSchema := &apiextensions.JSONSchemaProps{}
		if err := apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
			version.Schema.OpenAPIV3Schema, internalSchema, nil,
		); err != nil {
			log.WithError(err).WithField("kind", kind).Warn("Failed to convert CRD schema to internal format")
			continue
		}

		// Convert to structural schema.
		structural, err := structuralschema.NewStructural(internalSchema)
		if err != nil {
			log.WithError(err).WithField("kind", kind).Warn("Failed to create structural schema from CRD")
			continue
		}

		// Compile CEL validator. Returns nil if no x-kubernetes-validations exist.
		v := celvalidation.NewValidator(structural, true, celconfig.PerCallLimit)
		if v != nil {
			validators[kind] = v
			schemas[kind] = structural
			log.WithField("kind", kind).Debug("Compiled CEL validator for CRD")
		}
	}
}

// Validate runs the CEL validation rules from the CRD schema against the given
// object. It returns a field.ErrorList with any validation failures.
//
// For create operations, pass nil for oldObj.
// For update operations, pass the previous version as oldObj.
//
// Returns nil if the object's Kind has no CEL validation rules, or if
// validation passes.
func Validate(ctx context.Context, obj runtime.Object, oldObj runtime.Object) field.ErrorList {
	initOnce.Do(initValidators)
	if initErr != nil {
		return field.ErrorList{field.InternalError(nil, initErr)}
	}

	// Determine Kind from the object.
	gvk := obj.GetObjectKind().GroupVersionKind()
	kind := gvk.Kind
	if kind == "" {
		return nil
	}

	v, ok := validators[kind]
	if !ok {
		return nil
	}

	// Convert to unstructured map representation for CEL evaluation.
	unstructuredObj, err := toUnstructured(obj)
	if err != nil {
		return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to convert object to unstructured: %w", err))}
	}

	var unstructuredOldObj any
	if oldObj != nil {
		unstructuredOldObj, err = toUnstructured(oldObj)
		if err != nil {
			return field.ErrorList{field.InternalError(nil, fmt.Errorf("failed to convert old object to unstructured: %w", err))}
		}
	}

	errs, _ := v.Validate(ctx, nil, nil, unstructuredObj, unstructuredOldObj, int64(celconfig.RuntimeCELCostBudget))
	return errs
}

// HasValidator returns true if a CEL validator exists for the given Kind.
func HasValidator(kind string) bool {
	initOnce.Do(initValidators)
	_, ok := validators[kind]
	return ok
}

// ValidatorKinds returns the list of Kinds that have CEL validators.
func ValidatorKinds() []string {
	initOnce.Do(initValidators)
	kinds := make([]string, 0, len(validators))
	for k := range validators {
		kinds = append(kinds, k)
	}
	return kinds
}

func toUnstructured(obj runtime.Object) (any, error) {
	// If already unstructured, use the underlying map directly.
	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u.Object, nil
	}

	// Convert typed object to unstructured map.
	data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	return data, nil
}
