// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apis

import (
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/tigera/operator/pkg/controller/migration/datastoremigration"
)

func mapResourceList() *metav1.APIResourceList {
	return &metav1.APIResourceList{
		GroupVersion: "admissionregistration.k8s.io/v1beta1",
		APIResources: []metav1.APIResource{{Name: "mutatingadmissionpolicies", Kind: "MutatingAdmissionPolicy"}},
	}
}

// emptyDynamicClient returns a dynamic fake with no DatastoreMigration CRs, so the migration check
// finds nothing and useV3CRDs falls through to API discovery.
func emptyDynamicClient() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			datastoremigration.GroupVersionV1.WithResource(datastoremigration.Resource):      "DatastoreMigrationList",
			datastoremigration.GroupVersionV1beta1.WithResource(datastoremigration.Resource): "DatastoreMigrationList",
		},
	)
}

func TestUseV3CRDs(t *testing.T) {
	v1 := &metav1.APIResourceList{GroupVersion: "crd.projectcalico.org/v1"}
	v3 := &metav1.APIResourceList{GroupVersion: "projectcalico.org/v3"}

	cases := []struct {
		name      string
		apiGroup  string
		resources []*metav1.APIResourceList
		want      bool
		wantErr   bool
	}{
		{"v1 present stays v1", "", []*metav1.APIResourceList{v1, mapResourceList()}, false, false},
		{"both present stays v1", "", []*metav1.APIResourceList{v1, v3, mapResourceList()}, false, false},
		{"v3 present with MAP stays v3", "", []*metav1.APIResourceList{v3, mapResourceList()}, true, false},
		{"v3 present without MAP errors", "", []*metav1.APIResourceList{v3}, false, true},
		{"greenfield capable goes v3", "", []*metav1.APIResourceList{mapResourceList()}, true, false},
		{"greenfield not capable stays v1", "", []*metav1.APIResourceList{}, false, false},

		{"override v3 with MAP goes v3", "projectcalico.org/v3", []*metav1.APIResourceList{mapResourceList()}, true, false},
		{"override v3 without MAP errors", "projectcalico.org/v3", []*metav1.APIResourceList{}, false, true},
		{"override v1 ignores MAP", "crd.projectcalico.org/v1", []*metav1.APIResourceList{}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.apiGroup != "" {
				t.Setenv("CALICO_API_GROUP", tc.apiGroup)
			}
			c := fake.NewClientset()
			c.Resources = tc.resources
			got, err := useV3CRDs(c.Discovery(), emptyDynamicClient())
			if (err != nil) != tc.wantErr {
				t.Fatalf("useV3CRDs() err = %v, wantErr %t", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("useV3CRDs() = %t, want %t", got, tc.want)
			}
		})
	}
}

// A cluster that migrated on v3.32 has a Converged v1beta1 CR and no v1 CRD, and still
// has to be detected as migrated.
// TODO: remove in v3.34, alongside GroupVersionV1beta1.
func TestCheckDatastoreMigrationFallsBackToLegacyGVR(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": datastoremigration.GroupVersionV1beta1.String(),
		"kind":       datastoremigration.Kind,
		"metadata":   map[string]interface{}{"name": "v1-to-v3"},
		"status":     map[string]interface{}{"phase": datastoremigration.PhaseConverged},
	}}

	dc := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			datastoremigration.GroupVersionV1beta1.WithResource(datastoremigration.Resource): "DatastoreMigrationList",
		},
		obj,
	)

	cs := fake.NewClientset()
	cs.Resources = []*metav1.APIResourceList{{
		GroupVersion: datastoremigration.GroupVersionV1beta1.String(),
		APIResources: []metav1.APIResource{{Name: datastoremigration.Resource, Kind: datastoremigration.Kind}},
	}}

	migrated, err := checkDatastoreMigration(cs.Discovery(), dc)
	if err != nil {
		t.Fatalf("checkDatastoreMigration() error = %v", err)
	}
	if !migrated {
		t.Errorf("checkDatastoreMigration() = false, want true (should fall back to the legacy v1beta1 resource)")
	}
}

// A cluster with no DatastoreMigration CRD at all must not look migrated.
func TestCheckDatastoreMigrationWithoutCRD(t *testing.T) {
	cs := fake.NewClientset()

	migrated, err := checkDatastoreMigration(cs.Discovery(), emptyDynamicClient())
	if err != nil {
		t.Fatalf("checkDatastoreMigration() error = %v", err)
	}
	if migrated {
		t.Errorf("checkDatastoreMigration() = true, want false")
	}
}

// A discovery failure must error rather than read as "no migration".
func TestCheckDatastoreMigrationReportsDiscoveryFailure(t *testing.T) {
	cs := fake.NewClientset()
	disco, ok := cs.Discovery().(*discoveryfake.FakeDiscovery)
	if !ok {
		t.Fatalf("discovery client is %T, want *discoveryfake.FakeDiscovery", cs.Discovery())
	}
	disco.PrependReactor("get", "resource", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})

	if _, err := checkDatastoreMigration(disco, emptyDynamicClient()); err == nil {
		t.Error("checkDatastoreMigration() error = nil, want an error")
	}
}

func TestIsMutatingAdmissionPolicyServed(t *testing.T) {
	cases := []struct {
		name      string
		resources []*metav1.APIResourceList
		want      bool
	}{
		{
			name: "served when MAP resource present",
			resources: []*metav1.APIResourceList{{
				GroupVersion: "admissionregistration.k8s.io/v1beta1",
				APIResources: []metav1.APIResource{{Name: "mutatingadmissionpolicies", Kind: "MutatingAdmissionPolicy"}},
			}},
			want: true,
		},
		{
			name: "not served when group present without MAP kind",
			resources: []*metav1.APIResourceList{{
				GroupVersion: "admissionregistration.k8s.io/v1",
				APIResources: []metav1.APIResource{{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"}},
			}},
			want: false,
		},
		{
			name:      "not served on empty cluster",
			resources: []*metav1.APIResourceList{},
			want:      false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientset()
			c.Resources = tc.resources
			got := isMutatingAdmissionPolicyServed(c.Discovery())
			if got != tc.want {
				t.Errorf("isMutatingAdmissionPolicyServed() = %t, want %t", got, tc.want)
			}
		})
	}
}
