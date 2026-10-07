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
	"math/big"
	"net"
	"slices"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func mustSummarize(tr *Tracker, name string) *Counts {
	c, ok := tr.Summarize(name)
	Expect(ok).To(BeTrue(), "pool %s was not added", name)
	return c
}

func TestSummarizeCounts(t *testing.T) {
	RegisterTestingT(t)

	a := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(a, 0, "node-a")
	allocatePod(a, 1, "node-b")
	allocateTunnel(a, 2, "node-a")
	allocateCooling(a, 3)

	// A tunnel address from before handles and attributes still counts. It and a pod with no node attribute count
	// against the block's affine node.
	a.Attributes = append(a.Attributes, model.AllocationAttribute{})
	a.Allocations[4] = ptr.To(len(a.Attributes) - 1)
	allocate(a, 5, "k8s-pod-network.y", map[string]string{
		model.IPAMBlockAttributePod:       "pod",
		model.IPAMBlockAttributeNamespace: "default",
	})

	unaffined := testBlock("10.0.0.64/26", "")
	allocatePod(unaffined, 0, "node-c")

	lb := testBlock("10.0.0.128/26", model.IPAMAffinityLoadBalancer)
	allocate(lb, 0, "lb-handle", map[string]string{model.IPAMBlockAttributeService: "svc"})

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(a, unaffined, lb)
	counts := mustSummarize(tr, "p")

	Expect(counts.Total.String()).To(Equal("256"))
	Expect(counts.TotalBlocks.String()).To(Equal("4"))
	Expect(counts.Reserved.String()).To(Equal("0"))
	Expect(counts.BlocksInUse).To(Equal(3))

	// Cooling is inside InUse, not beside it.
	Expect(counts.InUse).To(Equal(8))
	Expect(counts.Cooling).To(Equal(1))
	Expect(counts.Assigned()).To(Equal(7))
	Expect(counts.Free().String()).To(Equal("248"))

	// node-b borrows from node-a's block, and node-c holds an address in a block affine to no node.
	Expect(counts.Borrowed).To(Equal(2))

	// The LoadBalancer block's virtual affinity is neither unaffined nor a node.
	Expect(counts.NoAffinity).To(Equal(1))
	Expect(counts.VirtualAffinity).To(Equal(1))
	Expect(counts.BlocksByNode).To(Equal(map[string]int{"node-a": 1}))
	Expect(counts.AddressesByKind).To(Equal(map[v3.IPPoolAllowedUse]int{
		v3.IPPoolAllowedUseWorkload:     4,
		v3.IPPoolAllowedUseTunnel:       2,
		v3.IPPoolAllowedUseLoadBalancer: 1,
	}))

	// The cooling address is not split by node, and the LoadBalancer address has no node to hold it.
	Expect(counts.AssignedByNode).To(Equal(map[string]int{
		"node-a": 4,
		"node-b": 1,
		"node-c": 1,
		"":       1,
	}))
	Expect(counts.BorrowedByNode).To(Equal(map[string]int{
		"node-b": 1,
		"node-c": 1,
	}))
}

func TestSummarizeNoPool(t *testing.T) {
	RegisterTestingT(t)
	orphan := testBlock("10.1.0.0/26", "host:node-a")
	allocatePod(orphan, 0, "node-a")
	allocatePod(orphan, 1, "node-b")
	owned := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(owned, 0, "node-a")

	tracker := NewTracker()
	tracker.AddPools(pool("p", "10.0.0.0/24", 26))
	tracker.AddBlocks(orphan, owned)
	counts := tracker.SummarizeNoPool()
	Expect(counts.Total.Sign()).To(BeZero())
	Expect(counts.BlocksInUse).To(Equal(1))
	Expect(counts.BlocksByNode).To(Equal(map[string]int{"node-a": 1}))
	Expect(counts.AssignedByNode).To(Equal(map[string]int{
		"node-a": 1,
		"node-b": 1,
	}))
	Expect(counts.BorrowedByNode).To(Equal(map[string]int{"node-b": 1}))

	tracker.AddPools(pool("q", "10.1.0.0/24", 26))
	Expect(tracker.SummarizeNoPool().BlocksInUse).To(BeZero(), "a pool that claims the block takes it out of the no-pool counts")
}

func TestSummarizeUnknownPool(t *testing.T) {
	RegisterTestingT(t)
	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	_, ok := tr.Summarize("other")
	Expect(ok).To(BeFalse())
	Expect(tr.SummarizeAll()).To(HaveKey("p"))
}

func TestSummarizeReturnsACopy(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(b, 0, "node-a")

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(b)
	c := mustSummarize(tr, "p")
	c.BlocksByNode["node-a"] = 99
	c.Total.SetInt64(0)
	c.InUse = 99

	again := mustSummarize(tr, "p")
	Expect(again.BlocksByNode["node-a"]).To(Equal(1))
	Expect(again.Total.String()).To(Equal("256"))
	Expect(again.InUse).To(Equal(1))
}

func TestReservedOverlapsInUse(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(b, 0, "node-a")
	allocatePod(b, 1, "node-a")
	allocateCooling(b, 2)

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(b)

	// Reserve 10.0.0.1-10.0.0.2 (one assigned, one cooling) and 10.0.0.200.
	tr.AddReservations(reservation("r", "10.0.0.1/32", "10.0.0.2/32", "10.0.0.200"))
	c := mustSummarize(tr, "p")
	Expect(c.Reserved.String()).To(Equal("3"))
	Expect(c.InUseReserved).To(Equal(2))

	// 256 total, 3 in use, 3 reserved, 2 counted by both.
	Expect(c.Free().String()).To(Equal("252"))

	tr.RemoveReservation("r")
	c = mustSummarize(tr, "p")
	Expect(c.Reserved.String()).To(Equal("0"))
	Expect(c.InUseReserved).To(Equal(0))
	Expect(c.Free().String()).To(Equal("253"))
}

func TestBlockAddedAfterReservationsCountsOverlap(t *testing.T) {
	RegisterTestingT(t)
	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddReservations(reservation("r", "10.0.0.0/30"))
	mustSummarize(tr, "p")

	b := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(b, 1, "node-a")
	allocatePod(b, 9, "node-a")
	tr.AddBlocks(b)
	Expect(mustSummarize(tr, "p").InUseReserved).To(Equal(1))
}

func TestIPv6CountsExceedInt(t *testing.T) {
	RegisterTestingT(t)
	tr := NewTracker()
	tr.AddPools(pool("v6", "fd00::/48", 0))
	tr.AddReservations(reservation("all", "fd00::/48"))
	c := mustSummarize(tr, "v6")

	want := new(big.Int).Lsh(big.NewInt(1), 80)
	Expect(c.Total.String()).To(Equal(want.String()))
	Expect(c.Reserved.String()).To(Equal(want.String()))
	Expect(c.TotalBlocks.String()).To(Equal(new(big.Int).Lsh(big.NewInt(1), 74).String()))
	Expect(c.Free().Sign()).To(Equal(0))
}

func TestStaleAffinity(t *testing.T) {
	RegisterTestingT(t)
	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(testBlock("10.0.0.0/26", "host:node-a"), testBlock("10.0.0.64/26", "host:node-b"))

	// A caller that never names nodes is not told every block is stale.
	Expect(mustSummarize(tr, "p").StaleAffinity).To(Equal(0))

	tr.AddNodes("node-a", "node-b")
	Expect(mustSummarize(tr, "p").StaleAffinity).To(Equal(0))

	tr.RemoveNode("node-b")
	Expect(mustSummarize(tr, "p").StaleAffinity).To(Equal(1))
}

func TestBlockUpdateReplacesEarlierCopy(t *testing.T) {
	RegisterTestingT(t)
	tracker := NewTracker()
	tracker.AddPools(pool("p", "10.0.0.0/24", 26))

	b := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(b, 0, "node-a")
	tracker.AddBlocks(b)
	Expect(mustSummarize(tracker, "p").InUse).To(Equal(1))

	updated := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(updated, 0, "node-a")
	allocatePod(updated, 1, "node-a")
	tracker.AddBlocks(updated)
	tracker.AddBlocks(updated)
	c := mustSummarize(tracker, "p")
	Expect(c.InUse).To(Equal(2))
	Expect(c.BlocksInUse).To(Equal(1))

	deleted := testBlock("10.0.0.0/26", "host:node-a")
	deleted.Deleted = true
	tracker.AddBlocks(deleted)
	Expect(mustSummarize(tracker, "p").BlocksInUse).To(Equal(0))

	tracker.AddBlocks(updated)
	Expect(mustSummarize(tracker, "p").BlocksInUse).To(Equal(1))
	tracker.RemoveBlock(updated.CIDR)
	Expect(mustSummarize(tracker, "p").BlocksInUse).To(Equal(0))
}

func TestPoolChangeReattributesBlocks(t *testing.T) {
	RegisterTestingT(t)
	block := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(block, 0, "node-a")

	tr := NewTracker()
	tr.AddPools(pool("outer", "10.0.0.0/16", 26))
	tr.AddBlocks(block)
	Expect(mustSummarize(tr, "outer").InUse).To(Equal(1))

	tr.AddPools(pool("inner", "10.0.0.0/24", 26))
	Expect(mustSummarize(tr, "outer").InUse).To(Equal(0))
	Expect(mustSummarize(tr, "inner").InUse).To(Equal(1))

	tr.RemovePool("inner")
	Expect(mustSummarize(tr, "outer").InUse).To(Equal(1))

	tr.RemovePool("outer")
	Expect(tr.NoPoolBlocks()).To(ConsistOf(block))
}

func TestNoPoolBlocksInAddressOrder(t *testing.T) {
	RegisterTestingT(t)
	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	high := testBlock("10.9.0.128/26", "")
	low := testBlock("10.9.0.64/26", "")
	tr.AddBlocks(high, testBlock("10.0.0.0/26", ""), low)
	Expect(tr.NoPoolBlocks()).To(Equal([]*model.AllocationBlock{low, high}))
}

func TestPoolBlocksAndBlockPool(t *testing.T) {
	RegisterTestingT(t)
	tracker := NewTracker()
	tracker.AddPools(pool("outer", "10.0.0.0/16", 26), pool("inner", "10.0.0.0/24", 26))
	inner := testBlock("10.0.0.64/26", "")
	outerHigh := testBlock("10.0.9.0/26", "")
	outerLow := testBlock("10.0.5.0/26", "")
	stray := testBlock("10.9.0.0/26", "")
	tracker.AddBlocks(outerHigh, inner, stray, outerLow)

	Expect(tracker.PoolBlocks("outer")).To(Equal([]*model.AllocationBlock{outerLow, outerHigh}))
	Expect(tracker.PoolBlocks("inner")).To(Equal([]*model.AllocationBlock{inner}))
	Expect(tracker.PoolBlocks("missing")).To(BeNil())

	owner, ok := tracker.BlockPool(inner.CIDR)
	Expect(ok).To(BeTrue())
	Expect(owner).To(Equal("inner"))
	_, ok = tracker.BlockPool(stray.CIDR)
	Expect(ok).To(BeFalse(), "no pool claims the stray block")
	_, ok = tracker.BlockPool(cnet.MustParseCIDR("10.0.7.0/26"))
	Expect(ok).To(BeFalse(), "the tracker has no such block")

	// The narrower pool's removal hands its block to the wider one.
	tracker.RemovePool("inner")
	owner, _ = tracker.BlockPool(inner.CIDR)
	Expect(owner).To(Equal("outer"))
	Expect(tracker.PoolBlocks("outer")).To(Equal([]*model.AllocationBlock{inner, outerLow, outerHigh}))
}

func TestHasBlocksWithin(t *testing.T) {
	RegisterTestingT(t)
	tracker := NewTracker()
	tracker.AddPools(pool("outer", "10.0.0.0/16", 26), pool("inner", "10.0.0.0/24", 26))
	inner := testBlock("10.0.0.64/26", "")
	tracker.AddBlocks(inner, testBlock("10.9.0.0/26", ""))

	Expect(tracker.HasBlocksWithin(cnet.MustParseCIDR("10.0.0.0/16"))).To(BeTrue(), "the inner pool's block still lies in the outer CIDR")
	Expect(tracker.HasBlocksWithin(cnet.MustParseCIDR("10.1.0.0/16"))).To(BeFalse())
	Expect(tracker.HasBlocksWithin(cnet.MustParseCIDR("10.0.0.64/27"))).To(BeFalse(), "a CIDR narrower than the block does not hold it")

	tracker.RemoveBlock(inner.CIDR)
	Expect(tracker.HasBlocksWithin(cnet.MustParseCIDR("10.0.0.0/16"))).To(BeFalse())
}

// TestIncrementalMatchesFresh reads between every change, then compares against a tracker given the end state at once.
func TestIncrementalMatchesFresh(t *testing.T) {
	RegisterTestingT(t)
	blockA := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(blockA, 1, "node-a")
	allocatePod(blockA, 2, "node-b")
	allocateCooling(blockA, 3)
	blockB := testBlock("10.0.0.64/26", "host:node-b")
	allocatePod(blockB, 1, "node-b")
	outer := pool("outer", "10.0.0.0/16", 26)
	inner := pool("inner", "10.0.0.64/26", 26)

	tracker := NewTracker()
	steps := []func(){
		func() { tracker.AddPools(outer) },
		func() { tracker.AddBlocks(blockA) },
		func() { tracker.AddReservations(reservation("r", "10.0.0.2")) },
		func() { tracker.AddBlocks(blockB) },
		func() { tracker.AddPools(inner) },
		func() { tracker.AddReservations(reservation("r", "10.0.0.2", "10.0.0.65")) },
		func() { tracker.AddReservations(reservation("elsewhere", "192.168.0.0/24")) },
		func() { tracker.AddNodes("node-a") },
	}
	for _, step := range steps {
		step()
		tracker.SummarizeAll()
	}

	fresh := NewTracker()
	fresh.AddPools(outer, inner)
	fresh.AddBlocks(blockA, blockB)
	fresh.AddReservations(reservation("r", "10.0.0.2", "10.0.0.65"), reservation("elsewhere", "192.168.0.0/24"))
	fresh.AddNodes("node-a")
	Expect(tracker.SummarizeAll()).To(Equal(fresh.SummarizeAll()))
	Expect(mustSummarize(tracker, "outer").InUseReserved).To(Equal(1))
	Expect(mustSummarize(tracker, "inner").InUseReserved).To(Equal(1))
}

func TestReservationChangeOutsideEveryPoolKeepsCounts(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(b, 1, "node-a")

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(b)
	tr.AddReservations(reservation("r", "10.0.0.1"))
	Expect(mustSummarize(tr, "p").InUseReserved).To(Equal(1))

	tr.AddReservations(reservation("r", "10.0.0.1"), reservation("elsewhere", "192.168.0.0/24"))
	tr.RemoveReservation("absent")
	c := mustSummarize(tr, "p")
	Expect(c.InUseReserved).To(Equal(1))
	Expect(c.Reserved.String()).To(Equal("1"))
}

func TestIPv4MappedReservation(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.9.0.0/26", "host:node-a")
	allocatePod(b, 5, "node-a")

	tr := NewTracker()
	tr.AddPools(pool("mapped", "10.9.0.0/24", 26), pool("other", "10.0.0.0/24", 26))
	tr.AddBlocks(b)

	// The allocator reads this as 10.9.0.0/24, and it must not poison the count for other pools.
	tr.AddReservations(reservation("mapped", "::ffff:10.9.0.0/120"), reservation("plain", "10.0.0.0/30"))
	mapped := mustSummarize(tr, "mapped")
	Expect(mapped.Reserved.String()).To(Equal("256"))
	Expect(mapped.InUseReserved).To(Equal(1))
	Expect(mustSummarize(tr, "other").Reserved.String()).To(Equal("4"))
}

func TestAllocationsSkipCooling(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocateCooling(b, 0)
	allocatePod(b, 3, "node-b")

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(b)
	allocs := tr.Allocations("p")
	Expect(allocs).To(HaveLen(1))
	Expect(allocs[0].IP.String()).To(Equal("10.0.0.3"))
	Expect(allocs[0].Ordinal).To(Equal(3))
	Expect(allocs[0].Node()).To(Equal("node-b"))
	Expect(allocs[0].IsBorrowed()).To(BeTrue())
}

func TestMalformedAllocationsAreSkipped(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(b, 0, "node-a")
	b.Allocations[1] = ptr.To(7)

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(b)
	Expect(mustSummarize(tr, "p").InUse).To(Equal(1))
}

func ref(ip string, kind v3.IPPoolAllowedUse, name string) AddressRef {
	return AddressRef{IP: net.ParseIP(ip), Kind: kind, Referrer: Referrer{Kind: "Test", Name: name}}
}

func unreferencedIPs(tr *Tracker, pool string) []string {
	var out []string
	for _, a := range tr.Unreferenced(pool) {
		out = append(out, a.IP.String())
	}
	return out
}

func TestUnreferenced(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(b, 0, "node-a")
	allocateTunnel(b, 1, "node-a")
	allocatePod(b, 2, "node-a")
	allocate(b, 3, WindowsReservedHandle, nil)
	allocateCooling(b, 4)

	tracker := NewTracker()
	tracker.AddPools(pool("p", "10.0.0.0/24", 26))
	tracker.AddBlocks(b)

	// With no references, every assigned address but the Windows one is leaked.
	Expect(unreferencedIPs(tracker, "p")).To(Equal([]string{"10.0.0.0", "10.0.0.1", "10.0.0.2"}))

	tracker.AddRefs(ref("10.0.0.0", v3.IPPoolAllowedUseWorkload, "endpoint/default/a"), ref("10.0.0.1", v3.IPPoolAllowedUseTunnel, "node/node-a"))
	Expect(unreferencedIPs(tracker, "p")).To(Equal([]string{"10.0.0.2"}))

	// A reference of the wrong kind does not account for the address.
	tracker.AddRefs(ref("10.0.0.2", v3.IPPoolAllowedUseTunnel, "node/node-a"))
	Expect(unreferencedIPs(tracker, "p")).To(Equal([]string{"10.0.0.2"}))

	// Two references to one address: removing one leaves it referenced.
	tracker.AddRefs(ref("10.0.0.2", v3.IPPoolAllowedUseWorkload, "endpoint/default/b"), ref("10.0.0.2", v3.IPPoolAllowedUseWorkload, "endpoint/default/c"))
	tracker.RemoveRefs(ref("10.0.0.2", v3.IPPoolAllowedUseWorkload, "endpoint/default/b"))
	Expect(unreferencedIPs(tracker, "p")).To(BeEmpty())

	tracker.RemoveRefs(ref("10.0.0.2", v3.IPPoolAllowedUseWorkload, "endpoint/default/c"))
	Expect(unreferencedIPs(tracker, "p")).To(Equal([]string{"10.0.0.2"}))

	// A reference never affects the counts.
	Expect(mustSummarize(tracker, "p").InUse).To(Equal(5))
}

// A stopped VM's persisted address has no owner attributes left, so only a reference to the VM keeps it.
func TestUnreferencedClearedOwnerNeedsAReference(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocate(b, 1, "k8s-pod-network.vmi.default.vm1", nil)

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(b)
	Expect(unreferencedIPs(tr, "p")).To(Equal([]string{"10.0.0.1"}))

	tr.AddRefs(ref("10.0.0.1", v3.IPPoolAllowedUseWorkload, "VirtualMachine(default/vm1)"))
	Expect(unreferencedIPs(tr, "p")).To(BeEmpty())
}

func TestUnreferencedKeepsWhatTheBlockCannotJudge(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocate(b, 2, "new", map[string]string{model.IPAMBlockAttributeType: "somethingNew"})
	allocate(b, 5, "manual", map[string]string{"note": "assigned by hand"})

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(b)

	// An unrecognized type cannot be judged. Anything else nothing references is a leak.
	Expect(unreferencedIPs(tr, "p")).To(Equal([]string{"10.0.0.5"}))
}

func TestNoPoolUnreferenced(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocatePod(b, 0, "node-a")

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(b)
	Expect(unreferencedIPs(tr, "p")).To(Equal([]string{"10.0.0.0"}))
	Expect(tr.NoPoolUnreferenced()).To(BeEmpty())

	tr.RemovePool("p")
	allocs := tr.NoPoolUnreferenced()
	Expect(allocs).To(HaveLen(1))
	Expect(allocs[0].IP.String()).To(Equal("10.0.0.0"))
}

type allocationKindCase struct {
	name     string
	affinity string
	handle   string
	noHandle bool
	attrType string
	want     v3.IPPoolAllowedUse
}

func TestAllocationKind(t *testing.T) {
	tests := []allocationKindCase{
		{name: "pod", affinity: "host:n", want: v3.IPPoolAllowedUseWorkload},
		{name: "tunnel from before attributes", affinity: "host:n", noHandle: true, want: v3.IPPoolAllowedUseTunnel},
		{name: "ipip", affinity: "host:n", attrType: model.IPAMBlockAttributeTypeIPIP, want: v3.IPPoolAllowedUseTunnel},
		{name: "wireguard v6", affinity: "host:n", attrType: model.IPAMBlockAttributeTypeWireguardV6, want: v3.IPPoolAllowedUseTunnel},
		{name: "load balancer type", affinity: "host:n", attrType: string(corev1.ServiceTypeLoadBalancer), want: v3.IPPoolAllowedUseLoadBalancer},
		{name: "load balancer block", affinity: model.IPAMAffinityLoadBalancer, want: v3.IPPoolAllowedUseLoadBalancer},
		{name: "windows reserved", affinity: "host:n", handle: WindowsReservedHandle, want: KindWindowsReserved},
		{name: "unrecognized type", affinity: "host:n", attrType: "somethingNew", want: KindUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			b := testBlock("10.0.0.0/26", tc.affinity)
			handle := tc.handle
			if handle == "" {
				handle = "h"
			}
			var attrs map[string]string
			if tc.attrType != "" {
				attrs = map[string]string{model.IPAMBlockAttributeType: tc.attrType}
			}
			attr := allocate(b, 0, handle, attrs)
			if tc.noHandle {
				attr.HandleID = nil
			}
			allocs := slices.Collect(allocations(b))
			Expect(allocs).To(HaveLen(1))
			Expect(allocs[0].Kind()).To(Equal(tc.want))
		})
	}
}

func TestWindowsReservedIsNotAWorkload(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	for _, ord := range []int{0, 1, 2, 63} {
		allocate(b, ord, WindowsReservedHandle, map[string]string{"note": "windows host rsvd"})
	}
	allocatePod(b, 5, "node-a")

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(b)
	Expect(mustSummarize(tr, "p").AddressesByKind).To(Equal(map[v3.IPPoolAllowedUse]int{
		v3.IPPoolAllowedUseWorkload: 1,
		KindWindowsReserved:         4,
	}))
	Expect(unreferencedIPs(tr, "p")).To(Equal([]string{"10.0.0.5"}))
}

func TestUnaffinedBlockBorrowing(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "")
	allocatePod(b, 0, "node-c")
	allocate(b, 1, "no-node", nil)
	allocs := slices.Collect(allocations(b))
	Expect(allocs[0].IsBorrowed()).To(BeTrue())
	Expect(allocs[1].IsBorrowed()).To(BeFalse())
}

func TestAllocationNodeFallsBackToAffinity(t *testing.T) {
	RegisterTestingT(t)
	b := testBlock("10.0.0.0/26", "host:node-a")
	allocate(b, 0, "h", nil)
	allocs := slices.Collect(allocations(b))
	a := allocs[0]
	Expect(a.Node()).To(Equal("node-a"))
	Expect(a.IsBorrowed()).To(BeFalse())
	Expect(a.Handle()).To(Equal("h"))
}

func TestNodeAffinity(t *testing.T) {
	RegisterTestingT(t)
	node, ok := NodeAffinity(testBlock("10.0.0.0/26", "host:node-a"))
	Expect(ok).To(BeTrue())
	Expect(node).To(Equal("node-a"))

	_, ok = NodeAffinity(testBlock("10.0.0.0/26", model.IPAMAffinityLoadBalancer))
	Expect(ok).To(BeFalse())

	_, ok = NodeAffinity(testBlock("10.0.0.0/26", ""))
	Expect(ok).To(BeFalse())
}

func TestCountReservedDeduplicatesOverlap(t *testing.T) {
	RegisterTestingT(t)
	n, err := countReserved(cnet.MustParseNetwork("10.0.0.0/24"), ReservationCIDRs([]*v3.IPReservation{
		reservation("a", "10.0.0.0/28", "10.0.0.4"),
		reservation("b", "10.0.0.8/29", "10.1.0.0/24", " "),
	}))
	Expect(err).NotTo(HaveOccurred())
	Expect(n.String()).To(Equal("16"))
}

func TestAllRefsInOrder(t *testing.T) {
	RegisterTestingT(t)
	tr := NewTracker()
	tr.AddRefs(ref("10.0.0.10", v3.IPPoolAllowedUseWorkload, "b"), ref("10.0.0.9", v3.IPPoolAllowedUseTunnel, "node/a"), ref("10.0.0.10", v3.IPPoolAllowedUseWorkload, "a"))
	var got []string
	for _, r := range tr.AllRefs() {
		got = append(got, r.IP.String()+" "+r.Referrer.Name)
	}
	Expect(got).To(Equal([]string{"10.0.0.9 node/a", "10.0.0.10 a", "10.0.0.10 b"}))
	Expect(tr.Refs(net.ParseIP("10.0.0.11"))).To(BeEmpty())
	Expect(tr.Refs(net.ParseIP("10.0.0.10"))).To(HaveLen(2))
}

func TestPoolLostOverlap(t *testing.T) {
	RegisterTestingT(t)
	tracker := NewTracker()
	p := pool("p", "10.0.0.0/24", 26)
	tracker.AddPools(p)

	lost, ok := tracker.PoolLostOverlap("p")
	Expect(ok).To(BeTrue())
	Expect(lost).To(BeFalse())

	p = p.DeepCopy()
	p.Status = &v3.IPPoolStatus{Conditions: []metav1.Condition{{
		Type: v3.IPPoolConditionAllocatable, Status: metav1.ConditionFalse, Reason: v3.IPPoolReasonCIDROverlap,
	}}}
	tracker.AddPools(p)
	lost, _ = tracker.PoolLostOverlap("p")
	Expect(lost).To(BeTrue())

	_, ok = tracker.PoolLostOverlap("missing")
	Expect(ok).To(BeFalse())
}
