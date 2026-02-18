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
	"fmt"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// poolCounter provides unique CIDR ranges per test to avoid conflicts.
var poolCounter int

func nextPoolCIDR() string {
	poolCounter++
	return fmt.Sprintf("10.%d.%d.0/24", poolCounter/256, poolCounter%256)
}

func TestIPPool_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "ipipMode and vxlanMode both enabled is rejected",
			obj: &v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ippool")},
				Spec: v3.IPPoolSpec{
					CIDR:      nextPoolCIDR(),
					IPIPMode:  v3.IPIPModeAlways,
					VXLANMode: v3.VXLANModeAlways,
				},
			},
			wantErr: "ipipMode and vxlanMode cannot both be enabled",
		},
		{
			name: "LoadBalancer with ipipMode is rejected",
			obj: &v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ippool")},
				Spec: v3.IPPoolSpec{
					CIDR:        nextPoolCIDR(),
					IPIPMode:    v3.IPIPModeAlways,
					AllowedUses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer},
				},
			},
			wantErr: "LoadBalancer IP pool cannot have IPIP or VXLAN enabled",
		},
		{
			name: "LoadBalancer with Workload is rejected",
			obj: &v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ippool")},
				Spec: v3.IPPoolSpec{
					CIDR:        nextPoolCIDR(),
					AllowedUses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer, v3.IPPoolAllowedUseWorkload},
				},
			},
			wantErr: "LoadBalancer cannot be combined with Workload or Tunnel allowed uses",
		},
		{
			name: "LoadBalancer alone is accepted",
			obj: &v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ippool")},
				Spec: v3.IPPoolSpec{
					CIDR:        nextPoolCIDR(),
					AllowedUses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer},
				},
			},
		},
		{
			name: "Workload + Tunnel is accepted",
			obj: &v3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ippool")},
				Spec: v3.IPPoolSpec{
					CIDR:        nextPoolCIDR(),
					AllowedUses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload, v3.IPPoolAllowedUseTunnel},
				},
			},
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

func TestIPPool_Defaults(t *testing.T) {
	pool := &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ippool-dflt")},
		Spec: v3.IPPoolSpec{
			CIDR: nextPoolCIDR(),
		},
	}
	mustCreate(t, pool)

	got := &v3.IPPool{}
	if err := testClient.Get(context.Background(), client.ObjectKeyFromObject(pool), got); err != nil {
		t.Fatalf("failed to get ippool: %v", err)
	}
	if got.Spec.AssignmentMode == nil {
		t.Fatal("expected assignmentMode to be defaulted, got nil")
	}
	if *got.Spec.AssignmentMode != v3.Automatic {
		t.Fatalf("expected assignmentMode=Automatic, got %q", *got.Spec.AssignmentMode)
	}
}
