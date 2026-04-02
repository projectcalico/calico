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
	"fmt"
	"sync"
	"sync/atomic"

	calicoapi "github.com/projectcalico/api"
	"github.com/sirupsen/logrus"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	celvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	schemavalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
)

// crdSchema holds the raw schema and lazily-compiled validators for a
// single CRD Kind. The sync.Once ensures compilation happens exactly
// once and all fields are visible to concurrent readers after Do returns.
type crdSchema struct {
	rawSchema *apiextensions.JSONSchemaProps

	once            sync.Once
	celValidator    *celvalidation.Validator
	schemaValidator schemavalidation.SchemaCreateValidator
	structural      *structuralschema.Structural
}

// compile builds the OpenAPI schema validator, structural schema, and
// CEL validator from the raw schema. Called via s.once.Do().
func (s *crdSchema) compile(kind string) {
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
}

var (
	// crdValidationEnabled controls whether CRD schema defaulting and
	// validation (CEL rules, OpenAPI constraints) run inside Validate().
	// In KDD mode the kube-apiserver enforces CRD rules on admission, so
	// the in-process check is redundant and the CEL compilation cost is
	// wasted. Disabled by default; enabled when an etcd-backed client is
	// created.
	crdValidationEnabled atomic.Bool

	// crdSchemasByKind maps CRD Kind to its schema and lazily compiled
	// validators. Populated once by loadSchemas, then read-only —
	// per-Kind compilation mutates only the crdSchema itself under its
	// own sync.Once.
	crdSchemasByKind map[string]*crdSchema
	schemasOnce      sync.Once
	schemasErr       error
)

// SetCRDValidationEnabled controls whether Validate() applies CRD schema
// defaults and runs CRD validation rules (CEL + OpenAPI constraints). When
// enabled, validators are compiled lazily per-Kind on first use. This
// should be enabled when there is no kube-apiserver to enforce CRD rules
// (i.e., etcd datastore mode).
func SetCRDValidationEnabled(enabled bool) {
	crdValidationEnabled.Store(enabled)
}

// loadSchemas loads all embedded CRDs and converts their schemas to
// internal format. This is the cheap part (~9 MB); CEL compilation
// happens per-Kind on demand via crdSchema.once.
func loadSchemas() {
	crdSchemasByKind = make(map[string]*crdSchema)

	crds, err := calicoapi.AllCRDs()
	if err != nil {
		schemasErr = fmt.Errorf("failed to load CRDs: %w", err)
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

		crdSchemasByKind[kind] = &crdSchema{rawSchema: internalSchema}
	}
}
