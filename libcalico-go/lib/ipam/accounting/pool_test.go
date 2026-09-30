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
	"net"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// poolForCIDR is the pool a tracker holding pools attributes a block with this CIDR to, or "" for none.
func poolForCIDR(t *testing.T, pools []*v3.IPPool, cidr string) string {
	_, block, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTracker()
	tr.AddPools(pools...)
	if pool := tr.poolFor(block); pool != nil {
		return pool.ipPool.Name
	}
	return ""
}

func TestPoolForAttribution(t *testing.T) {
	disabled := pool("disabled-inner", "10.0.0.0/24", 26)
	disabled.Spec.Disabled = true

	notAllocatable := pool("not-allocatable-inner", "10.1.0.0/24", 26)
	notAllocatable.Status = &v3.IPPoolStatus{Conditions: []metav1.Condition{
		{
			Type:   v3.IPPoolConditionAllocatable,
			Status: metav1.ConditionFalse,
			Reason: v3.IPPoolReasonCIDROverlap,
		},
	}}

	terminating := pool("terminating-outer", "10.2.0.0/16", 26)
	terminating.Status = &v3.IPPoolStatus{Conditions: []metav1.Condition{
		{
			Type:   v3.IPPoolConditionAllocatable,
			Status: metav1.ConditionFalse,
			Reason: v3.IPPoolReasonTerminating,
		},
	}}
	overlapInner := pool("overlap-inner", "10.2.0.0/24", 26)
	overlapInner.Status = &v3.IPPoolStatus{Conditions: []metav1.Condition{
		{
			Type:   v3.IPPoolConditionAllocatable,
			Status: metav1.ConditionFalse,
			Reason: v3.IPPoolReasonCIDROverlap,
		},
	}}

	tests := []struct {
		name  string
		pools []*v3.IPPool
		block string
		want  string
	}{
		{
			name:  "narrowest containing pool wins",
			pools: []*v3.IPPool{pool("outer", "10.0.0.0/16", 26), pool("inner", "10.0.0.0/24", 26)},
			block: "10.0.0.64/26",
			want:  "inner",
		},
		{
			name:  "block size match beats narrowness",
			pools: []*v3.IPPool{pool("outer", "10.0.0.0/16", 28), pool("inner", "10.0.0.0/24", 26)},
			block: "10.0.0.0/28",
			want:  "outer",
		},
		{
			name:  "a pool that only overlaps the block is not a candidate",
			pools: []*v3.IPPool{pool("small", "10.0.0.0/27", 27)},
			block: "10.0.0.0/26",
			want:  "",
		},
		{
			name:  "narrower disabled pool keeps its blocks from an enabled one",
			pools: []*v3.IPPool{pool("active-outer", "10.0.0.0/16", 26), disabled},
			block: "10.0.0.0/26",
			want:  "disabled-inner",
		},
		{
			name:  "disabled pool keeps its blocks when nothing else contains them",
			pools: []*v3.IPPool{disabled},
			block: "10.0.0.0/26",
			want:  "disabled-inner",
		},
		{
			name:  "allocatable pool beats a narrower overlap loser",
			pools: []*v3.IPPool{pool("outer", "10.1.0.0/16", 26), notAllocatable},
			block: "10.1.0.0/26",
			want:  "outer",
		},
		{
			name:  "terminating pool keeps its blocks from a nested overlap loser",
			pools: []*v3.IPPool{terminating, overlapInner},
			block: "10.2.0.0/26",
			want:  "terminating-outer",
		},
		{
			name:  "name breaks an exact tie",
			pools: []*v3.IPPool{pool("b", "10.0.0.0/24", 26), pool("a", "10.0.0.0/24", 26)},
			block: "10.0.0.0/26",
			want:  "a",
		},
		{
			name:  "IPv4 pool never claims an IPv6 block",
			pools: []*v3.IPPool{pool("v4", "0.0.0.0/0", 26)},
			block: "fd00::/122",
			want:  "",
		},
		{
			name:  "IPv6 block attributes to IPv6 pool",
			pools: []*v3.IPPool{pool("v4", "0.0.0.0/0", 26), pool("v6", "fd00::/64", 0)},
			block: "fd00::40/122",
			want:  "v6",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(poolForCIDR(t, tc.pools, tc.block)).To(Equal(tc.want))
		})
	}
}

func TestPoolForIsStableAcrossBuilds(t *testing.T) {
	RegisterTestingT(t)
	pools := []*v3.IPPool{pool("a", "10.0.0.0/16", 26), pool("b", "10.0.0.0/16", 26), pool("c", "10.0.0.0/16", 26)}
	for range 50 {
		Expect(poolForCIDR(t, pools, "10.0.3.0/26")).To(Equal("a"))
	}
}

func TestPoolSpecDefaults(t *testing.T) {
	RegisterTestingT(t)
	v4 := pool("v4", "10.0.0.0/16", 0)
	v6 := pool("v6", "fd00::/64", 0)
	Expect(BlockSize(v4)).To(Equal(26))
	Expect(BlockSize(v6)).To(Equal(122))
	Expect(BlockSize(pool("set", "10.0.0.0/16", 28))).To(Equal(28))
	Expect(AllowedUses(v4)).To(Equal([]v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload, v3.IPPoolAllowedUseTunnel}))
	Expect(NodeSelector(v4)).To(Equal("all()"))

	v4.Spec.NodeSelector = "role == 'x'"
	v4.Spec.AllowedUses = []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer}
	Expect(NodeSelector(v4)).To(Equal("role == 'x'"))
	Expect(AllowedUses(v4)).To(Equal([]v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer}))
}
