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

package ippool

import (
	"math/big"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

type nearlyFullCase struct {
	name          string
	total         *big.Int
	inUse         int
	reserved      int64
	inUseReserved int
	wantMessage   string
}

func TestNearlyFullCondition(t *testing.T) {
	v6Total := new(big.Int).Lsh(big.NewInt(1), 64)
	cases := []nearlyFullCase{
		{name: "just under 80%", total: big.NewInt(256), inUse: 204},
		{name: "at 80%", total: big.NewInt(256), inUse: 205, wantMessage: "80% of addresses are in use or reserved."},
		{name: "reserved counts as used", total: big.NewInt(256), inUse: 200, reserved: 5, wantMessage: "80% of addresses are in use or reserved."},
		{name: "reserved and in use counted once", total: big.NewInt(256), inUse: 204, reserved: 10, inUseReserved: 10},
		{name: "small pool over threshold", total: big.NewInt(64), inUse: 52, wantMessage: "81% of addresses are in use or reserved."},
		{name: "pool at the size floor", total: big.NewInt(32), inUse: 31},
		{name: "full pool", total: big.NewInt(256), inUse: 256, wantMessage: "100% of addresses are in use or reserved."},
		{name: "large IPv6 pool", total: v6Total, inUse: 100000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			counts := &accounting.Counts{
				Total:         tc.total,
				Reserved:      big.NewInt(tc.reserved),
				InUse:         tc.inUse,
				InUseReserved: tc.inUseReserved,
			}
			cond := nearlyFullCondition(counts)
			if tc.wantMessage == "" {
				if cond != nil {
					t.Fatalf("expected no condition, got %+v", cond)
				}
				return
			}
			if cond == nil {
				t.Fatal("expected a condition")
			}
			if cond.Type != v3.IPPoolConditionAddressSpaceNearlyFull || cond.Status != metav1.ConditionTrue || cond.Reason != v3.IPPoolReasonThresholdExceeded {
				t.Fatalf("unexpected condition %+v", cond)
			}
			if cond.Message != tc.wantMessage {
				t.Fatalf("expected message %q, got %q", tc.wantMessage, cond.Message)
			}
		})
	}
}

// allocatedBlock returns a block covering cidr with the first numAllocated ordinals allocated.
func allocatedBlock(t *testing.T, cidr string, numAllocated int) *model.AllocationBlock {
	t.Helper()
	_, blockNet, err := cnet.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %s: %v", cidr, err)
	}
	size := blockNet.NumAddrs().Int64()
	block := &model.AllocationBlock{
		CIDR:        *blockNet,
		Allocations: make([]*int, size),
		Attributes:  []model.AllocationAttribute{{HandleID: ptr.To("handle")}},
	}
	for i := range size {
		if int(i) < numAllocated {
			block.Allocations[i] = ptr.To(0)
		} else {
			block.Unallocated = append(block.Unallocated, int(i))
		}
	}
	return block
}

// Until the tracker sees a new CIDROverlap condition it credits a busy block to the narrower, losing pool. The pass
// writing the condition skips nearly-full; the next pass judges it correctly.
func TestReconcile_NearlyFullWaitsForANewCIDROverlap(t *testing.T) {
	wide := testPool("wide", "10.0.0.0/25")
	wide.Status = &v3.IPPoolStatus{Conditions: []metav1.Condition{{
		Type: v3.IPPoolConditionAllocatable, Status: metav1.ConditionTrue, Reason: v3.IPPoolReasonOK,
	}}}
	narrow := testPool("narrow", "10.0.0.0/26")
	cli := fake.NewClientset(wide, narrow)
	c, idx := newTestController(cli, wide, narrow)
	c.tracker.AddBlocks(allocatedBlock(t, "10.0.0.0/26", 52), allocatedBlock(t, "10.0.0.64/26", 52))

	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	gotNarrow, err := cli.ProjectcalicoV3().IPPools().Get(c.ctx, narrow.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !accounting.LostOverlap(gotNarrow) {
		t.Fatalf("expected the narrower, newer pool to lose the overlap, got %+v", gotNarrow.Status)
	}
	if hasCondition(gotNarrow, v3.IPPoolConditionAddressSpaceNearlyFull, metav1.ConditionTrue) {
		t.Fatalf("narrow is nearly full on the pass that ruled it out, from a block it no longer owns: %+v", gotNarrow.Status)
	}

	// Deliver the status update the way the informer would. Both blocks move to wide: 104 of 128 is nearly full.
	if err := idx.Update(gotNarrow); err != nil {
		t.Fatalf("update cache: %v", err)
	}
	c.tracker.AddPools(gotNarrow)
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	gotWide, err := cli.ProjectcalicoV3().IPPools().Get(c.ctx, wide.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !hasCondition(gotWide, v3.IPPoolConditionAddressSpaceNearlyFull, metav1.ConditionTrue) {
		t.Errorf("expected AddressSpaceNearlyFull on wide once it is credited with both blocks, got %+v", gotWide.Status)
	}
	gotNarrow, err = cli.ProjectcalicoV3().IPPools().Get(c.ctx, narrow.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if hasCondition(gotNarrow, v3.IPPoolConditionAddressSpaceNearlyFull, metav1.ConditionTrue) {
		t.Errorf("expected no AddressSpaceNearlyFull on narrow, which owns no blocks, got %+v", gotNarrow.Status)
	}
}

func TestReconcileNearlyFull_SetsAndClears(t *testing.T) {
	pool := testPool("pool-1", "10.0.0.0/26")
	cli := fake.NewClientset(pool)
	c, _ := newTestController(cli, pool)
	c.tracker.AddPools(pool)

	c.tracker.AddBlocks(allocatedBlock(t, "10.0.0.0/26", 52))
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, err := cli.ProjectcalicoV3().IPPools().Get(c.ctx, pool.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !hasCondition(got, v3.IPPoolConditionAddressSpaceNearlyFull, metav1.ConditionTrue) {
		t.Fatalf("expected AddressSpaceNearlyFull at 52 of 64, got %+v", got.Status)
	}

	// Refresh the cache the way the informer would, then drop usage below the threshold.
	if err := c.poolInformer.GetIndexer().Update(got); err != nil {
		t.Fatalf("update cache: %v", err)
	}
	c.tracker.AddBlocks(allocatedBlock(t, "10.0.0.0/26", 10))
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, err = cli.ProjectcalicoV3().IPPools().Get(c.ctx, pool.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	for _, cond := range got.Status.Conditions {
		if cond.Type == v3.IPPoolConditionAddressSpaceNearlyFull {
			t.Fatalf("expected AddressSpaceNearlyFull removed at 10 of 64, got %+v", cond)
		}
	}
	if !hasCondition(got, v3.IPPoolConditionAllocatable, metav1.ConditionTrue) {
		t.Fatalf("expected Allocatable to survive the removal, got %+v", got.Status.Conditions)
	}
}
