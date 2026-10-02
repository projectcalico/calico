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
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// trackerInputs is what the tracker was last told, kept by the test so a fresh tracker can be built from it.
type trackerInputs struct {
	pools        map[string]*v3.IPPool
	blocks       map[string]*model.AllocationBlock
	reservations map[string]*v3.IPReservation
	nodes        map[string]bool
	namedNodes   bool
	refs         map[string]AddressRef
}

// rebuild is the answer the incremental tracker must match: everything added at once to a new tracker.
func (in *trackerInputs) rebuild() *Tracker {
	tr := NewTracker()
	tr.AddPools(slices.Collect(maps.Values(in.pools))...)
	tr.AddReservations(slices.Collect(maps.Values(in.reservations))...)
	tr.AddBlocks(slices.Collect(maps.Values(in.blocks))...)
	if in.namedNodes {
		tr.AddNodes(slices.Collect(maps.Keys(in.nodes))...)
	}
	tr.AddRefs(slices.Collect(maps.Values(in.refs))...)
	return tr
}

// Random add and remove sequences, checked after every step against a tracker built from scratch. This is what
// makes the incremental indexes safe to trust.
func TestIncrementalMatchesRebuild(t *testing.T) {
	RegisterTestingT(t)
	for seed := range uint64(20) {
		rng := rand.New(rand.NewPCG(seed, 1))
		tr := NewTracker()
		in := &trackerInputs{
			pools:        map[string]*v3.IPPool{},
			blocks:       map[string]*model.AllocationBlock{},
			reservations: map[string]*v3.IPReservation{},
			nodes:        map[string]bool{},
			refs:         map[string]AddressRef{},
		}
		for step := range 200 {
			op := randomOp(rng, tr, in)
			expectSameReads(tr, in.rebuild(), fmt.Sprintf("seed %d step %d after %s", seed, step, op))
		}
	}
}

var (
	propertyNodes      = []string{"node-a", "node-b", "node-c", "node-d"}
	propertyBlockCIDRs = []string{
		"10.0.0.0/26", "10.0.0.64/26", "10.0.1.0/26", "10.0.1.64/26", "10.0.4.0/26",
		"10.0.0.128/28", "10.0.0.144/28", "10.1.0.0/26", "10.9.0.0/26", "fd00::/122",
	}
	propertyReservations = []string{"10.0.0.0/30", "10.0.1.0/25", "10.0.0.130", "fd00::/126"}
)

// propertyPool is one of a fixed set of overlapping and nested pools, in a random state.
func propertyPool(rng *rand.Rand) *v3.IPPool {
	candidates := []*v3.IPPool{
		pool("outer", "10.0.0.0/16", 26),
		pool("inner", "10.0.0.0/20", 26),
		pool("small-blocks", "10.0.0.128/25", 28),
		pool("nested", "10.0.1.0/24", 26),
		pool("other", "10.1.0.0/16", 26),
		pool("v6", "fd00::/120", 122),
		pool("broken", "not-a-cidr", 26),
	}
	p := candidates[rng.IntN(len(candidates))].DeepCopy()
	p.Spec.Disabled = rng.IntN(4) == 0
	if rng.IntN(5) == 0 {
		p.Status = &v3.IPPoolStatus{Conditions: []metav1.Condition{{
			Type:   v3.IPPoolConditionAllocatable,
			Status: metav1.ConditionFalse,
			Reason: v3.IPPoolReasonCIDROverlap,
		}}}
	}
	return p
}

// propertyBlock is one of the fixed block CIDRs with random contents and affinity.
func propertyBlock(rng *rand.Rand) *model.AllocationBlock {
	cidr := propertyBlockCIDRs[rng.IntN(len(propertyBlockCIDRs))]
	affinity := ""
	switch rng.IntN(4) {
	case 0:
	case 1:
		affinity = model.IPAMAffinityLoadBalancer
	default:
		affinity = "host:" + propertyNodes[rng.IntN(len(propertyNodes))]
	}
	block := testBlock(cidr, affinity)
	for ord := range len(block.Allocations) {
		node := propertyNodes[rng.IntN(len(propertyNodes))]
		handle := fmt.Sprintf("h-%s-%d", cidr, ord)
		switch rng.IntN(10) {
		case 0:
			allocateTunnel(block, ord, node)
		case 1:
			allocateCooling(block, ord)
		case 2:
			allocate(block, ord, handle, map[string]string{
				model.IPAMBlockAttributeNode: node,
				model.IPAMBlockAttributeType: "somethingNew",
			})
		case 3:
			allocate(block, ord, WindowsReservedHandle, nil)
		case 4:
			allocate(block, ord, handle, nil)
		case 5, 6:
			allocate(block, ord, handle, map[string]string{
				model.IPAMBlockAttributePod:       handle,
				model.IPAMBlockAttributeNamespace: "default",
				model.IPAMBlockAttributeNode:      node,
			})
		}
	}
	block.Deleted = rng.IntN(20) == 0
	return block
}

// randomOp applies one random change to both the tracker and the recorded inputs, and names it.
func randomOp(rng *rand.Rand, tr *Tracker, in *trackerInputs) string {
	switch rng.IntN(11) {
	case 0, 1:
		p := propertyPool(rng)
		tr.AddPools(p)
		in.pools[p.Name] = p
		return "AddPools " + p.Name
	case 2:
		p := propertyPool(rng)
		tr.RemovePool(p.Name)
		delete(in.pools, p.Name)
		return "RemovePool " + p.Name
	case 3, 4, 5:
		b := propertyBlock(rng)
		tr.AddBlocks(b)
		if b.Deleted {
			delete(in.blocks, b.CIDR.String())
		} else {
			in.blocks[b.CIDR.String()] = b
		}
		return "AddBlocks " + b.CIDR.String()
	case 6:
		cidr := cnet.MustParseCIDR(propertyBlockCIDRs[rng.IntN(len(propertyBlockCIDRs))])
		tr.RemoveBlock(cidr)
		delete(in.blocks, cidr.String())
		return "RemoveBlock " + cidr.String()
	case 7:
		name := fmt.Sprintf("r%d", rng.IntN(3))
		if rng.IntN(3) == 0 {
			tr.RemoveReservation(name)
			delete(in.reservations, name)
			return "RemoveReservation " + name
		}
		r := reservation(name, propertyReservations[rng.IntN(len(propertyReservations))])
		tr.AddReservations(r)
		in.reservations[name] = r
		return "AddReservations " + name
	case 8:
		node := propertyNodes[rng.IntN(len(propertyNodes))]
		if rng.IntN(2) == 0 {
			tr.RemoveNode(node)
			delete(in.nodes, node)
			return "RemoveNode " + node
		}
		tr.AddNodes(node)
		in.nodes[node] = true
		in.namedNodes = true
		return "AddNodes " + node
	default:
		b := in.anyBlock(rng)
		if b == nil {
			return "no-op"
		}
		kinds := []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload, v3.IPPoolAllowedUseTunnel, v3.IPPoolAllowedUseLoadBalancer}
		r := AddressRef{
			IP:       b.OrdinalToIP(rng.IntN(b.NumAddresses())).IP,
			Kind:     kinds[rng.IntN(len(kinds))],
			Referrer: Referrer{Kind: "Node", Name: propertyNodes[rng.IntN(len(propertyNodes))]},
		}
		if rng.IntN(3) == 0 {
			tr.RemoveRefs(r)
			in.removeRef(r)
			return "RemoveRefs " + r.IP.String()
		}
		tr.AddRefs(r)
		in.addRef(r)
		return "AddRefs " + r.IP.String()
	}
}

func (in *trackerInputs) anyBlock(rng *rand.Rand) *model.AllocationBlock {
	if len(in.blocks) == 0 {
		return nil
	}
	keys := slices.Sorted(maps.Keys(in.blocks))
	return in.blocks[keys[rng.IntN(len(keys))]]
}

// refID is a recorded reference's map key. AddressRef holds a slice, so it cannot be one itself.
func refID(r AddressRef) string {
	return fmt.Sprintf("%s|%s|%s", r.IP, r.Kind, r.Referrer)
}

func (in *trackerInputs) addRef(r AddressRef) {
	in.refs[refID(r)] = r
}

func (in *trackerInputs) removeRef(r AddressRef) {
	delete(in.refs, refID(r))
}

// expectSameReads compares every read the two trackers answer.
func expectSameReads(got, want *Tracker, context string) {
	Expect(normalizeAll(got.SummarizeAll())).To(Equal(normalizeAll(want.SummarizeAll())), context)
	Expect(blockCIDRs(got.NoPoolBlocks())).To(Equal(blockCIDRs(want.NoPoolBlocks())), context)
	Expect(allocIPs(got.NoPoolUnreferenced())).To(Equal(allocIPs(want.NoPoolUnreferenced())), context)
	Expect(got.NoPoolBlockCounts()).To(Equal(want.NoPoolBlockCounts()), context)
	for _, b := range want.NoPoolBlocks() {
		gotCounts, _ := got.BlockCounts(b.CIDR)
		wantCounts, _ := want.BlockCounts(b.CIDR)
		Expect(gotCounts).To(Equal(wantCounts), context+" block "+b.CIDR.String())
	}
	for name := range want.SummarizeAll() {
		Expect(got.PoolBlockCounts(name)).To(Equal(want.PoolBlockCounts(name)), context+" pool "+name)
		Expect(allocIPs(got.Allocations(name))).To(Equal(allocIPs(want.Allocations(name))), context+" pool "+name)
		Expect(allocIPs(got.Unreferenced(name))).To(Equal(allocIPs(want.Unreferenced(name))), context+" pool "+name)
	}
}

// normalizedCounts is Counts with the big.Ints as strings, which compare by value.
type normalizedCounts struct {
	Total       string
	Reserved    string
	TotalBlocks string
	c           Counts
}

func normalizeAll(all map[string]*Counts) map[string]normalizedCounts {
	out := map[string]normalizedCounts{}
	for name, c := range all {
		n := normalizedCounts{Total: c.Total.String(), Reserved: c.Reserved.String(), TotalBlocks: c.TotalBlocks.String(), c: *c}
		n.c.Total, n.c.Reserved, n.c.TotalBlocks = nil, nil, nil
		out[name] = n
	}
	return out
}

func blockCIDRs(blocks []*model.AllocationBlock) []string {
	var out []string
	for _, b := range blocks {
		out = append(out, b.CIDR.String())
	}
	return out
}

func allocIPs(allocs []Allocation) []string {
	var out []string
	for _, a := range allocs {
		out = append(out, a.IP.String())
	}
	return out
}
