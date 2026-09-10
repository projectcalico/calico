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

package kubevirt

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestMockVirtDeployed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		client   dynamic.Interface
		expected bool
	}{
		{
			name:     "no KubeVirt CRD",
			client:   clientWithNoKubeVirtCRD(),
			expected: false,
		},
		{
			name:     "no KubeVirt CR",
			client:   fakeKubeVirtClient(),
			expected: false,
		},
		{
			name:     "real KubeVirt",
			client:   fakeKubeVirtClient(kubeVirtCR(map[string]any{})),
			expected: false,
		},
		{
			name:     "simulation mode off",
			client:   fakeKubeVirtClient(kubeVirtCR(map[string]any{"simulationMode": false})),
			expected: false,
		},
		{
			name:     "MockVirt",
			client:   fakeKubeVirtClient(kubeVirtCR(map[string]any{"simulationMode": true})),
			expected: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deployed, err := mockVirtDeployed(tc.client)
			if err != nil {
				t.Fatalf("mockVirtDeployed: %v", err)
			}
			if deployed != tc.expected {
				t.Errorf("mockVirtDeployed = %v, want %v", deployed, tc.expected)
			}
		})
	}
}

func TestMockVirtDeployedReportsOtherErrors(t *testing.T) {
	client := fakeKubeVirtClient()
	client.PrependReactor("get", "kubevirts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(kubeVirtResource.GroupResource(), "kubevirt", errors.New("nope"))
	})
	if _, err := mockVirtDeployed(client); err == nil {
		t.Error("mockVirtDeployed swallowed a Forbidden error from the API server")
	}
}

func fakeKubeVirtClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	listKinds := map[schema.GroupVersionResource]string{kubeVirtResource: "KubeVirtList"}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objs...)
}

// A cluster with no KubeVirt at all has no kubevirts resource to serve, which the
// API machinery reports as a no-kind-match rather than a NotFound.
func clientWithNoKubeVirtCRD() dynamic.Interface {
	client := fakeKubeVirtClient()
	client.PrependReactor("get", "kubevirts", func(k8stesting.Action) (bool, runtime.Object, error) {
		gk := schema.GroupKind{Group: kubeVirtResource.Group, Kind: "KubeVirt"}
		return true, nil, &meta.NoKindMatchError{GroupKind: gk, SearchedVersions: []string{kubeVirtResource.Version}}
	})
	return client
}

func kubeVirtCR(developerConfiguration map[string]any) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(kubeVirtResource.GroupVersion().WithKind("KubeVirt"))
	obj.SetNamespace("kubevirt")
	obj.SetName("kubevirt")
	if err := unstructured.SetNestedMap(obj.Object, developerConfiguration, "spec", "configuration", "developerConfiguration"); err != nil {
		panic(err)
	}
	return obj
}
