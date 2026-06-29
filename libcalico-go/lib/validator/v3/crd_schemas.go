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
	"fmt"
	"sync"
	"sync/atomic"

	calicoapi "github.com/projectcalico/api"
	"github.com/sirupsen/logrus"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	celvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	schemadefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	schemavalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
)

// crdSchemaRegistry holds parsed CRD schemas and their lazily compiled
// validators. A non-nil registry pointer means CRD validation is enabled.
type crdSchemaRegistry struct {
	loadOnce sync.Once
	loadErr  error
	schemas  map[string]*crdSchema
}

// DefaultAndValidate applies CRD schema defaults to obj in-place and then
// runs CRD validation rules (OpenAPI schema constraints + CEL
// x-kubernetes-validations). For create operations pass nil for oldObj.
// Returns nil if the object's Kind has no CRD schema or if defaulting and
// validation both succeed.
func (r *crdSchemaRegistry) DefaultAndValidate(ctx context.Context, kind string, obj, oldObj any) field.ErrorList {
	r.load()
	if r.loadErr != nil {
		return field.ErrorList{field.InternalError(nil, r.loadErr)}
	}

	s, ok := r.schemas[kind]
	if !ok {
		return nil
	}
	s.compile(kind)

	// Apply CRD schema defaults.
	if s.structural != nil {
		schemadefaulting.Default(obj, s.structural)
	}

	var allErrs field.ErrorList

	// Run OpenAPI schema validation (MinItems, MaxLength, Pattern, Enum, etc.).
	if s.schemaValidator != nil {
		allErrs = append(allErrs, schemavalidation.ValidateCustomResource(nil, obj, s.schemaValidator)...)
	}

	// Run CEL validation (x-kubernetes-validations rules).
	if s.celValidator != nil {
		celErrs, _ := s.celValidator.Validate(ctx, nil, nil, obj, oldObj, int64(celconfig.RuntimeCELCostBudget))
		allErrs = append(allErrs, celErrs...)
	}

	return allErrs
}

// load parses all embedded CRDs and stores their schemas. Safe for
// concurrent use; the actual work runs at most once.
func (r *crdSchemaRegistry) load() {
	r.loadOnce.Do(func() {
		r.schemas = make(map[string]*crdSchema)

		crds, err := calicoapi.AllCRDs()
		if err != nil {
			r.loadErr = fmt.Errorf("failed to load CRDs: %w", err)
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

			r.schemas[kind] = &crdSchema{rawSchema: internalSchema}
		}
	})
}

// crdSchema holds the raw schema and lazily-compiled validators for a
// single CRD Kind.
type crdSchema struct {
	rawSchema *apiextensions.JSONSchemaProps

	compileOnce     sync.Once
	celValidator    *celvalidation.Validator
	schemaValidator schemavalidation.SchemaCreateValidator
	structural      *structuralschema.Structural
}

// compile builds the OpenAPI schema validator, structural schema, and
// CEL validator from the raw schema. Safe for concurrent use; the actual
// work runs at most once.
func (s *crdSchema) compile(kind string) {
	s.compileOnce.Do(func() {
		sv, _, err := schemavalidation.NewSchemaValidator(s.rawSchema)
		if err != nil {
			logrus.WithError(err).WithField("kind", kind).Warn("Failed to create schema validator from CRD")
		} else {
			s.schemaValidator = sv
		}

		structural, err := structuralschema.NewStructural(s.rawSchema)
		if err != nil {
			logrus.WithError(err).WithField("kind", kind).Warn("Failed to create structural schema from CRD")
			return
		}
		s.structural = structural

		v := celvalidation.NewValidator(structural, true, celconfig.PerCallLimit)
		if v != nil {
			s.celValidator = v
		}

		logrus.WithField("kind", kind).Debug("Compiled CRD validators")
	})
}

// crdRegistry is the sole package-level variable. A non-nil value means
// CRD validation is enabled; nil means disabled (KDD mode).
var crdRegistry atomic.Pointer[crdSchemaRegistry]

// SetCRDValidationEnabled controls whether Validate() applies CRD schema
// defaults and runs CRD validation rules (CEL + OpenAPI constraints). When
// enabled, schemas are loaded lazily on first use and validators are
// compiled per-Kind on demand. This should be enabled when there is no
// kube-apiserver to enforce CRD rules (i.e., etcd datastore mode).
func SetCRDValidationEnabled(enabled bool) {
	if enabled {
		crdRegistry.CompareAndSwap(nil, &crdSchemaRegistry{})
	} else {
		crdRegistry.Store(nil)
	}
}
