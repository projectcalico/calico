// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package migration

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sdiscovery "k8s.io/client-go/discovery"
	discoveryfake "k8s.io/client-go/discovery/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
)

// TestResolveServedVersion covers the versions a cluster can be on. v3.32
// installs a v1beta1-only CRD and may never re-apply it.
func TestResolveServedVersion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		served   []string
		expected string
		wantErr  bool
	}{
		{
			name:     "v1 only",
			served:   []string{"v1"},
			expected: "v1",
		},
		{
			name:     "v1beta1 only",
			served:   []string{"v1beta1"},
			expected: "v1beta1",
		},
		{
			name:     "both served prefers v1",
			served:   []string{"v1beta1", "v1"},
			expected: "v1",
		},
		{
			name:    "neither served",
			served:  nil,
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			version, err := resolveServedVersion(fakeDiscovery(t, tc.served...))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got version %q", version)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve served version: %v", err)
			}
			if version != tc.expected {
				t.Errorf("got version %q, want %q", version, tc.expected)
			}
		})
	}
}

// TestResolveServedVersionIgnoresOtherResources checks that a group version
// carrying some other resource doesn't count as serving DatastoreMigration.
func TestResolveServedVersionIgnoresOtherResources(t *testing.T) {
	disco, ok := k8sfake.NewSimpleClientset().Discovery().(*discoveryfake.FakeDiscovery)
	if !ok {
		t.Fatal("fake clientset did not return a fake discovery client")
	}
	disco.Resources = []*metav1.APIResourceList{{
		GroupVersion: migrationv1.Group + "/v1",
		APIResources: []metav1.APIResource{{Name: "somethingelse", Kind: "SomethingElse"}},
	}}

	if version, err := resolveServedVersion(disco); err == nil {
		t.Fatalf("expected an error, got version %q", version)
	}
}

// fakeDiscovery returns a discovery client serving DatastoreMigration on each of
// the given versions of the migration group.
func fakeDiscovery(t *testing.T, versions ...string) k8sdiscovery.DiscoveryInterface {
	t.Helper()

	disco, ok := k8sfake.NewSimpleClientset().Discovery().(*discoveryfake.FakeDiscovery)
	if !ok {
		t.Fatal("fake clientset did not return a fake discovery client")
	}
	for _, version := range versions {
		disco.Resources = append(disco.Resources, &metav1.APIResourceList{
			GroupVersion: migrationv1.Group + "/" + version,
			APIResources: []metav1.APIResource{{
				Name: migrationv1.DatastoreMigrationGVR.Resource,
				Kind: "DatastoreMigration",
			}},
		})
	}
	return disco
}
