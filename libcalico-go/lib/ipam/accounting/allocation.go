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
	"iter"
	"net"
	"slices"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// WindowsReservedHandle is the handle used to reserve addresses required for Windows
// networking so that workloads do not get assigned these addresses.
const WindowsReservedHandle = "windows-reserved-ipam-handle"

// KindUnknown is the kind of an allocation whose type attribute this package does not recognize.
const KindUnknown v3.IPPoolAllowedUse = "Unknown"

// KindWindowsReserved is the kind of an address a Windows node reserves for its own networking. No workload holds it.
const KindWindowsReserved v3.IPPoolAllowedUse = "WindowsReserved"

// trackedKinds is every kind Kind returns, in the order a block's per-kind counts are stored.
var trackedKinds = [...]v3.IPPoolAllowedUse{
	v3.IPPoolAllowedUseWorkload,
	v3.IPPoolAllowedUseTunnel,
	v3.IPPoolAllowedUseLoadBalancer,
	KindWindowsReserved,
	KindUnknown,
}

const numKinds = len(trackedKinds)

func kindIndex(kind v3.IPPoolAllowedUse) int {
	if i := slices.Index(trackedKinds[:], kind); i >= 0 {
		return i
	}
	return numKinds - 1
}

// Allocation is one assigned address with the attributes IPAM recorded for it.
type Allocation struct {
	IP      net.IP
	Ordinal int
	Block   *model.AllocationBlock
	Attr    *model.AllocationAttribute
}

// Handle is the allocation's handle ID, or empty when IPAM recorded none.
func (a Allocation) Handle() string {
	if a.Attr.HandleID == nil {
		return ""
	}
	return *a.Attr.HandleID
}

// Node is the node holding the address: the owner attribute, falling back to block affinity for older allocations.
func (a Allocation) Node() string {
	if owner := a.Attr.ActiveOwnerAttrs[model.IPAMBlockAttributeNode]; owner != "" {
		return owner
	}
	node, _ := NodeAffinity(a.Block)
	return node
}

// Kind names the allowed use the address serves, from its own attributes. A pod address is always Workload here.
// Every model.IPAMBlockAttributeType* constant needs a case; an unlisted one falls through to KindUnknown.
func (a Allocation) Kind() v3.IPPoolAllowedUse {
	if a.IsWindowsHandle() {
		return KindWindowsReserved
	}
	if a.Block.Affinity != nil && *a.Block.Affinity == model.IPAMAffinityLoadBalancer {
		return v3.IPPoolAllowedUseLoadBalancer
	}
	attrType := a.Attr.ActiveOwnerAttrs[model.IPAMBlockAttributeType]
	switch attrType {
	case "":
		if len(a.Attr.ActiveOwnerAttrs) == 0 && a.Attr.HandleID == nil {
			// Tunnel addresses predate both attributes and handles, while pod addresses always had a handle.
			return v3.IPPoolAllowedUseTunnel
		}
		return v3.IPPoolAllowedUseWorkload
	case model.IPAMBlockAttributeTypeIPIP,
		model.IPAMBlockAttributeTypeVXLAN,
		model.IPAMBlockAttributeTypeVXLANV6,
		model.IPAMBlockAttributeTypeWireguard,
		model.IPAMBlockAttributeTypeWireguardV6:
		return v3.IPPoolAllowedUseTunnel
	case string(corev1.ServiceTypeLoadBalancer):
		return v3.IPPoolAllowedUseLoadBalancer
	default:
		return KindUnknown
	}
}

// IsCooling is whether the address was released and is waiting out its cooldown before reuse.
func (a Allocation) IsCooling() bool {
	return a.Attr.ReleasedAt != nil
}

// IsBorrowed is whether a node other than the block's affine node holds the address. An unaffined block has no
// affine node, so any node holding one of its addresses borrowed it.
func (a Allocation) IsBorrowed() bool {
	node, _ := NodeAffinity(a.Block)
	owner := a.Attr.ActiveOwnerAttrs[model.IPAMBlockAttributeNode]
	return owner != "" && owner != node
}

// IsWindowsHandle is whether a Windows node reserved the address, which leaves it no owner to leak from.
func (a Allocation) IsWindowsHandle() bool {
	return strings.EqualFold(a.Handle(), WindowsReservedHandle)
}

// NodeAffinity names the node a block is affine to. Virtual affinities name none.
func NodeAffinity(b *model.AllocationBlock) (string, bool) {
	if b.AffinityType() != model.IPAMAffinityTypeHost {
		return "", false
	}
	node := b.Host()
	return node, node != ""
}

// allocations yields every well-formed allocated ordinal in the block, cooling included, leaving IP unset.
func allocations(b *model.AllocationBlock) iter.Seq[Allocation] {
	return func(yield func(Allocation) bool) {
		size := b.NumAddresses()
		for ordinal, idx := range b.Allocations {
			if idx == nil || *idx < 0 || *idx >= len(b.Attributes) || ordinal >= size {
				continue
			}
			if !yield(Allocation{Ordinal: ordinal, Block: b, Attr: &b.Attributes[*idx]}) {
				return
			}
		}
	}
}

// countAllocated counts the block's allocated ordinals, malformed ones included.
func countAllocated(b *model.AllocationBlock) int {
	n := 0
	for _, idx := range b.Allocations {
		if idx != nil {
			n++
		}
	}
	return n
}
