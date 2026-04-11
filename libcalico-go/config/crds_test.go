// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"testing"

	calicoapi "github.com/projectcalico/api"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

func ExampleCRDFiles() {
	var crd v1.CustomResourceDefinition
	rawYAML, err := CRDFiles.ReadFile("crd/crd.projectcalico.org_felixconfigurations.yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(rawYAML, &crd)
	if err != nil {
		panic(err)
	}
	fmt.Println(crd.GetName())
	// Output: felixconfigurations.crd.projectcalico.org
}

func ExampleLoadCRD() {
	crd, err := LoadCRD("crd.projectcalico.org", "felixconfigurations")
	if err != nil {
		panic(err)
	}
	fmt.Println(crd.GetName())
	// Output: felixconfigurations.crd.projectcalico.org
}

func TestAllCRDs(t *testing.T) {
	crds, err := AllCRDs()
	if err != nil {
		t.Fatal(err)
	}
	const expectedCRDs = 20
	if len(crds) < expectedCRDs {
		t.Fatal("Expected at least", expectedCRDs, "CRDs, got", len(crds))
	}
	// Basic sanity check that we didn't load anything we didn't expect.
	for _, crd := range crds {
		if crd.GetName() == "" {
			t.Fatal("CRD had no name?")
		}
		if crd.Spec.Group == "" {
			t.Fatal("CRD had no group?")
		}
		if len(crd.Spec.Versions) == 0 {
			t.Fatal("CRD had no versions?")
		}
	}
}

// TestV1CRDsMatchV3CELRules verifies that the crd.projectcalico.org (v1) CRDs
// have the same top-level CEL x-kubernetes-validations as the corresponding
// projectcalico.org (v3) CRDs. The v1 CRDs back the Calico API server; if
// their CEL rules drift from v3, validation that works in CRD mode will
// silently stop working in API server mode.
func TestV1CRDsMatchV3CELRules(t *testing.T) {
	v1CRDs, err := AllCRDs()
	if err != nil {
		t.Fatal(err)
	}
	v3CRDs, err := calicoapi.AllCRDs()
	if err != nil {
		t.Fatal(err)
	}

	// Build a map from Kind -> v3 CRD for quick lookup.
	v3ByKind := make(map[string]*v1.CustomResourceDefinition, len(v3CRDs))
	for _, crd := range v3CRDs {
		v3ByKind[crd.Spec.Names.Kind] = crd
	}

	for _, v1CRD := range v1CRDs {
		kind := v1CRD.Spec.Names.Kind
		v3CRD, ok := v3ByKind[kind]
		if !ok {
			continue
		}

		v1Schema := storageVersionSchema(v1CRD)
		v3Schema := storageVersionSchema(v3CRD)
		if v1Schema == nil || v3Schema == nil {
			continue
		}

		// Compare top-level x-kubernetes-validations. These are the rules
		// that reference self.metadata.name and can't be inherited from
		// shared Spec types.
		v3Rules := v3Schema.XValidations
		v1Rules := v1Schema.XValidations

		// Build maps keyed by message for bidirectional comparison.
		v1RulesByMsg := make(map[string]v1.ValidationRule, len(v1Rules))
		for _, r := range v1Rules {
			v1RulesByMsg[r.Message] = r
		}
		v3RulesByMsg := make(map[string]v1.ValidationRule, len(v3Rules))
		for _, r := range v3Rules {
			v3RulesByMsg[r.Message] = r
		}

		// Check that every v3 rule exists in v1 with matching fields.
		for _, v3Rule := range v3Rules {
			v1Rule, ok := v1RulesByMsg[v3Rule.Message]
			if !ok {
				t.Errorf("%s: v3 CEL rule missing from v1 CRD: %q", kind, v3Rule.Message)
				continue
			}
			if v1Rule.Rule != v3Rule.Rule {
				t.Errorf("%s: CEL rule %q differs:\n  v3: %s\n  v1: %s", kind, v3Rule.Message, v3Rule.Rule, v1Rule.Rule)
			}
			if ptrStr(v1Rule.Reason) != ptrStr(v3Rule.Reason) {
				t.Errorf("%s: CEL rule %q reason differs:\n  v3: %s\n  v1: %s", kind, v3Rule.Message, ptrStr(v3Rule.Reason), ptrStr(v1Rule.Reason))
			}
			if v1Rule.FieldPath != v3Rule.FieldPath {
				t.Errorf("%s: CEL rule %q fieldPath differs:\n  v3: %s\n  v1: %s", kind, v3Rule.Message, v3Rule.FieldPath, v1Rule.FieldPath)
			}
		}

		// Check that v1 doesn't have extra rules not in v3.
		for _, v1Rule := range v1Rules {
			if _, ok := v3RulesByMsg[v1Rule.Message]; !ok {
				t.Errorf("%s: v1 CEL rule not present in v3 CRD: %q", kind, v1Rule.Message)
			}
		}
	}
}

func ptrStr(p *v1.FieldValueErrorReason) string {
	if p == nil {
		return "<nil>"
	}
	return string(*p)
}

// storageVersionSchema returns the OpenAPI v3 schema for the storage version
// of the given CRD, or nil if none is found.
func storageVersionSchema(crd *v1.CustomResourceDefinition) *v1.JSONSchemaProps {
	for i := range crd.Spec.Versions {
		if crd.Spec.Versions[i].Storage {
			if crd.Spec.Versions[i].Schema != nil {
				return crd.Spec.Versions[i].Schema.OpenAPIV3Schema
			}
			return nil
		}
	}
	if len(crd.Spec.Versions) > 0 && crd.Spec.Versions[0].Schema != nil {
		return crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	}
	return nil
}
