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

package validation_test

import (
	"context"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// expectApplySucceeds asserts that a server-side apply of obj succeeds. This is
// the same code path used by FluxCD, ArgoCD, and `kubectl apply --server-side`,
// and exercises the structural-merge-diff schema built from the CRD's listType,
// listMapKey, and mapType annotations. CRDs that misuse those annotations
// (e.g. listType=set on a list of objects) fail to build a typed schema and
// produce errors like "associative list without keys has an element that's a
// map type", regardless of the spec content.
func expectApplySucceeds(t *testing.T, obj client.Object) {
	t.Helper()
	ctx := context.Background()
	err := testClient.Patch(ctx, obj, client.Apply,
		client.FieldOwner("validation-test"),
		client.ForceOwnership)
	if err != nil {
		t.Fatalf("expected server-side apply to succeed but got: %v", err)
	}
	t.Cleanup(func() {
		_ = testClient.Delete(context.Background(), obj)
	})
}

// TestBGPConfiguration_ServerSideApply locks in the fix for
// https://github.com/projectcalico/calico/issues/12700. Each of the object-list
// fields below was tagged +listType=set in v3.32.0, which is invalid for lists
// of objects and breaks any server-side-apply client. Apply must succeed for
// all of them.
func TestBGPConfiguration_ServerSideApply(t *testing.T) {
	tests := []struct {
		name string
		spec v3.BGPConfigurationSpec
	}{
		{
			name: "serviceLoadBalancerIPs populated",
			spec: v3.BGPConfigurationSpec{
				ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{
					{CIDR: "10.0.0.0/24"},
					{CIDR: "10.1.0.0/24"},
				},
			},
		},
		{
			name: "serviceExternalIPs populated",
			spec: v3.BGPConfigurationSpec{
				ServiceExternalIPs: []v3.ServiceExternalIPBlock{
					{CIDR: "192.168.0.0/24"},
				},
			},
		},
		{
			name: "serviceClusterIPs populated",
			spec: v3.BGPConfigurationSpec{
				ServiceClusterIPs: []v3.ServiceClusterIPBlock{
					{CIDR: "172.16.0.0/16"},
				},
			},
		},
		{
			name: "communities populated",
			spec: v3.BGPConfigurationSpec{
				Communities: []v3.Community{
					{Name: "my-community", Value: "65001:100"},
				},
				PrefixAdvertisements: []v3.PrefixAdvertisement{
					{CIDR: "10.0.0.0/24", Communities: []string{"my-community"}},
				},
			},
		},
		{
			name: "prefixAdvertisements populated",
			spec: v3.BGPConfigurationSpec{
				PrefixAdvertisements: []v3.PrefixAdvertisement{
					{CIDR: "10.0.0.0/24", Communities: []string{"65001:100"}},
				},
			},
		},
		{
			name: "all object lists populated together",
			spec: v3.BGPConfigurationSpec{
				ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "10.0.0.0/24"}},
				ServiceExternalIPs:     []v3.ServiceExternalIPBlock{{CIDR: "192.168.0.0/24"}},
				ServiceClusterIPs:      []v3.ServiceClusterIPBlock{{CIDR: "172.16.0.0/16"}},
				Communities:            []v3.Community{{Name: "my-community", Value: "65001:100"}},
				PrefixAdvertisements: []v3.PrefixAdvertisement{
					{CIDR: "10.0.0.0/24", Communities: []string{"my-community"}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &v3.BGPConfiguration{
				TypeMeta: metav1.TypeMeta{
					APIVersion: v3.GroupVersionCurrent,
					Kind:       v3.KindBGPConfiguration,
				},
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpconfig-ssa")},
				Spec:       tt.spec,
			}
			expectApplySucceeds(t, obj)
		})
	}
}
