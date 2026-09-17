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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These three were defaulted on write by libcalico-go, which the native CRD path
// does not run. The values match Felix's own built-in defaults.
func TestFelixConfiguration_SchemaDefaults(t *testing.T) {
	name := uniqueName("felixconfig-defaults")
	mustCreate(t, &v3.FelixConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.FelixConfigurationSpec{},
	})

	got := &v3.FelixConfiguration{}
	if err := testClient.Get(context.Background(), client.ObjectKey{Name: name}, got); err != nil {
		t.Fatalf("failed to get config: %v", err)
	}

	if got.Spec.FloatingIPs == nil || *got.Spec.FloatingIPs != v3.FloatingIPsDisabled {
		t.Errorf("expected spec.floatingIPs=%q, got %v", v3.FloatingIPsDisabled, got.Spec.FloatingIPs)
	}
	if got.Spec.BPFConnectTimeLoadBalancing == nil || *got.Spec.BPFConnectTimeLoadBalancing != v3.BPFConnectTimeLBTCP {
		t.Errorf("expected spec.bpfConnectTimeLoadBalancing=%q, got %v", v3.BPFConnectTimeLBTCP, got.Spec.BPFConnectTimeLoadBalancing)
	}
	if got.Spec.BPFHostNetworkedNATWithoutCTLB == nil || *got.Spec.BPFHostNetworkedNATWithoutCTLB != v3.BPFHostNetworkedNATEnabled {
		t.Errorf("expected spec.bpfHostNetworkedNATWithoutCTLB=%q, got %v", v3.BPFHostNetworkedNATEnabled, got.Spec.BPFHostNetworkedNATWithoutCTLB)
	}
}

func TestFelixConfiguration_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "routeTableRange and routeTableRanges both set is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec: v3.FelixConfigurationSpec{
					RouteTableRange:  &v3.RouteTableRange{Min: 1, Max: 250},
					RouteTableRanges: &v3.RouteTableRanges{{Min: 1, Max: 250}},
				},
			},
			wantErr: "routeTableRange and routeTableRanges cannot both be set",
		},
		{
			name: "routeTableRange alone is accepted",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec: v3.FelixConfigurationSpec{
					RouteTableRange: &v3.RouteTableRange{Min: 1, Max: 250},
				},
			},
		},
		{
			name: "routeTableRanges alone is accepted",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec: v3.FelixConfigurationSpec{
					RouteTableRanges: &v3.RouteTableRanges{{Min: 1, Max: 250}},
				},
			},
		},
		{
			name: "natOutgoingAddress with IPv6 is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{NATOutgoingAddress: "fd00::1"},
			},
			wantErr: "natOutgoingAddress must be a valid IPv4 address",
		},
		{
			name: "natOutgoingAddress with invalid string is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{NATOutgoingAddress: "not-an-ip"},
			},
			wantErr: "natOutgoingAddress must be a valid IPv4 address",
		},
		{
			name: "natOutgoingAddress with IPv4 is accepted",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{NATOutgoingAddress: "10.0.0.1"},
			},
		},
		{
			name: "deviceRouteSourceAddress with IPv6 is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{DeviceRouteSourceAddress: "fd00::1"},
			},
			wantErr: "deviceRouteSourceAddress must be a valid IPv4 address",
		},
		{
			name: "deviceRouteSourceAddress with invalid string is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{DeviceRouteSourceAddress: "not-an-ip"},
			},
			wantErr: "deviceRouteSourceAddress must be a valid IPv4 address",
		},
		{
			name: "deviceRouteSourceAddressIPv6 with IPv4 is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{DeviceRouteSourceAddressIPv6: "10.0.0.1"},
			},
			wantErr: "deviceRouteSourceAddressIPv6 must be a valid IPv6 address",
		},
		{
			name: "deviceRouteSourceAddressIPv6 with invalid string is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{DeviceRouteSourceAddressIPv6: "not-an-ip"},
			},
			wantErr: "deviceRouteSourceAddressIPv6 must be a valid IPv6 address",
		},
		{
			name: "deviceRouteSourceAddressIPv6 with IPv6 is accepted",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{DeviceRouteSourceAddressIPv6: "fd00::1"},
			},
		},
		{
			name: "routeTableRange min=0 is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{RouteTableRange: &v3.RouteTableRange{Min: 0, Max: 250}},
			},
			wantErr: "must be a range of route table indices within 1..250",
		},
		{
			name: "routeTableRange max > 250 is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{RouteTableRange: &v3.RouteTableRange{Min: 1, Max: 251}},
			},
			wantErr: "must be a range of route table indices within 1..250",
		},
		{
			name: "routeTableRange min > max is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{RouteTableRange: &v3.RouteTableRange{Min: 200, Max: 100}},
			},
			wantErr: "must be a range of route table indices within 1..250",
		},
		{
			name: "routeTableIDRange min=0 is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{RouteTableRanges: &v3.RouteTableRanges{{Min: 0, Max: 100}}},
			},
			wantErr: "min must be >= 1",
		},
		{
			name: "routeTableIDRange min > max is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec:       v3.FelixConfigurationSpec{RouteTableRanges: &v3.RouteTableRanges{{Min: 200, Max: 100}}},
			},
			wantErr: "min must not be greater than max",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

// The bounds come from the libcalico-go struct tags, which only the calicoctl
// path enforced before they reached the schema.
func TestFelixConfiguration_NumericBounds(t *testing.T) {
	bounded := []struct {
		field string
		min   int64
		max   int64
	}{
		{field: "debugPort", min: 0, max: 65535},
		{field: "bpfExtToServiceConnmark", min: 0, max: 4294967295},
		{field: "bpfKubeProxyHealthzPort", min: 0, max: 65535},
		{field: "ipv4NormalRoutePriority", min: 1, max: 2147483646},
		{field: "ipv4ElevatedRoutePriority", min: 1, max: 2147483646},
		{field: "ipv6NormalRoutePriority", min: 1, max: 2147483646},
		{field: "ipv6ElevatedRoutePriority", min: 1, max: 2147483646},
		{field: "wireguardListeningPort", min: 1, max: 65535},
		{field: "wireguardListeningPortV6", min: 1, max: 65535},
		{field: "wireguardRoutingRulePriority", min: 1, max: 32765},
		{field: "bpfMaglevMaxEndpointsPerService", min: 1, max: 3000},
		{field: "bpfMaglevMaxServices", min: 1, max: 3000},
	}

	newConfig := func(field string, value int64) *unstructured.Unstructured {
		return &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "projectcalico.org/v3",
				"kind":       "FelixConfiguration",
				"metadata":   map[string]interface{}{"name": uniqueName("felixconfig")},
				"spec":       map[string]interface{}{field: value},
			},
		}
	}

	for _, b := range bounded {
		t.Run(b.field+" below minimum", func(t *testing.T) {
			expectCreateFails(t, newConfig(b.field, b.min-1), b.field)
		})
		t.Run(b.field+" above maximum", func(t *testing.T) {
			expectCreateFails(t, newConfig(b.field, b.max+1), b.field)
		})
		t.Run(b.field+" at the bounds", func(t *testing.T) {
			expectCreateSucceeds(t, newConfig(b.field, b.min))
			expectCreateSucceeds(t, newConfig(b.field, b.max))
		})
	}
}
