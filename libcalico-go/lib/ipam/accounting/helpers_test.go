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

package accounting

import (
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func pool(name, cidr string, blockSize int) *v3.IPPool {
	return &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.IPPoolSpec{
			CIDR:      cidr,
			BlockSize: blockSize,
		},
	}
}

// testBlock builds a block affine to affinity ("" for none) with no allocations.
func testBlock(cidr, affinity string) *model.AllocationBlock {
	_, ipNet, err := cnet.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	b := &model.AllocationBlock{
		CIDR:        *ipNet,
		Allocations: make([]*int, ipNet.NumAddrs().Int64()),
	}
	if affinity != "" {
		b.Affinity = ptr.To(affinity)
	}
	return b
}

// allocate records an allocation at ordinal with the given owner attributes.
func allocate(b *model.AllocationBlock, ordinal int, handle string, attrs map[string]string) *model.AllocationAttribute {
	b.Attributes = append(b.Attributes, model.AllocationAttribute{
		HandleID:         ptr.To(handle),
		ActiveOwnerAttrs: attrs,
	})
	b.Allocations[ordinal] = ptr.To(len(b.Attributes) - 1)
	return &b.Attributes[len(b.Attributes)-1]
}

func allocatePod(b *model.AllocationBlock, ordinal int, node string) {
	allocate(b, ordinal, "k8s-pod-network.x", map[string]string{
		model.IPAMBlockAttributePod:       "pod",
		model.IPAMBlockAttributeNamespace: "default",
		model.IPAMBlockAttributeNode:      node,
	})
}

// allocateCooling points the ordinal at a released attribute, which IPAM writes with no handle or owner.
func allocateCooling(b *model.AllocationBlock, ordinal int) {
	b.Attributes = append(b.Attributes, model.AllocationAttribute{ReleasedAt: &metav1.Time{Time: time.Now()}})
	b.Allocations[ordinal] = ptr.To(len(b.Attributes) - 1)
}

func allocateTunnel(b *model.AllocationBlock, ordinal int, node string) {
	allocate(b, ordinal, "vxlan-tunnel-addr-"+node, map[string]string{
		model.IPAMBlockAttributeNode: node,
		model.IPAMBlockAttributeType: model.IPAMBlockAttributeTypeVXLAN,
	})
}

func reservation(name string, cidrs ...string) *v3.IPReservation {
	return &v3.IPReservation{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.IPReservationSpec{ReservedCIDRs: cidrs},
	}
}
