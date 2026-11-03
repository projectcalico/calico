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
	"runtime"
	"slices"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Run with: make -C libcalico-go benchmark WHAT=./lib/ipam/accounting/ [BENCH=<regexp>] [BENCHCOUNT=10]
// Every benchmark uses only the public API, so the numbers compare across tracker implementations.

type benchSize struct {
	name          string
	pools         int
	blocksPerPool int
	nodes         int
}

var benchSizes = []benchSize{
	{name: "1k-blocks", pools: 10, blocksPerPool: 100, nodes: 100},
	{name: "10k-blocks", pools: 20, blocksPerPool: 500, nodes: 1000},
}

// benchCluster is one cluster's worth of tracker input.
type benchCluster struct {
	pools        []*v3.IPPool
	blocks       []*model.AllocationBlock
	reservations []*v3.IPReservation
	nodes        []string
	refs         []AddressRef
}

// newBenchCluster fills each /26 block to 75% with pods, four cooling addresses, and a tunnel on one block in eight.
// One pod in ten is borrowed, and one in twenty is leaked.
func newBenchCluster(s benchSize) *benchCluster {
	cluster := &benchCluster{}
	for n := range s.nodes {
		cluster.nodes = append(cluster.nodes, fmt.Sprintf("node-%d", n))
	}
	for p := range s.pools {
		name := fmt.Sprintf("pool-%d", p)
		cluster.pools = append(cluster.pools, pool(name, fmt.Sprintf("10.%d.0.0/16", p), 26))
		cluster.reservations = append(cluster.reservations, reservation(name, fmt.Sprintf("10.%d.255.0/28", p)))
		for i := range s.blocksPerPool {
			node := cluster.nodes[(p*s.blocksPerPool+i)%s.nodes]
			block := testBlock(fmt.Sprintf("10.%d.%d.%d/26", p, i/4, i%4*64), "host:"+node)
			if i%8 == 0 {
				allocateTunnel(block, 0, node)
				cluster.refs = append(cluster.refs, AddressRef{IP: block.OrdinalToIP(0).IP, Kind: v3.IPPoolAllowedUseTunnel, Referrer: Referrer{Kind: "Node", Name: node}})
			}
			for ord := 1; ord < 44; ord++ {
				podNode := node
				if ord%10 == 0 {
					podNode = cluster.nodes[(p*s.blocksPerPool+i+1)%s.nodes]
				}
				handle := fmt.Sprintf("k8s-pod-network.%d-%d-%d", p, i, ord)
				allocate(block, ord, handle, map[string]string{
					model.IPAMBlockAttributePod:       handle,
					model.IPAMBlockAttributeNamespace: "default",
					model.IPAMBlockAttributeNode:      podNode,
				})
				if ord%20 != 0 {
					cluster.refs = append(cluster.refs, AddressRef{
						IP:       block.OrdinalToIP(ord).IP,
						Kind:     v3.IPPoolAllowedUseWorkload,
						Referrer: Referrer{Kind: "Workload", Namespace: "default", Name: handle},
					})
				}
			}
			for ord := 44; ord < 48; ord++ {
				allocateCooling(block, ord)
			}
			cluster.blocks = append(cluster.blocks, block)
		}
	}
	return cluster
}

// load is what an inline caller does: add everything, then read.
func (c *benchCluster) load() *Tracker {
	tr := NewTracker()
	tr.AddPools(c.pools...)
	tr.AddBlocks(c.blocks...)
	tr.AddReservations(c.reservations...)
	tr.AddNodes(c.nodes...)
	tr.AddRefs(c.refs...)
	tr.SummarizeAll()
	return tr
}

func forEachSize(b *testing.B, fn func(b *testing.B, c *benchCluster)) {
	for _, s := range benchSizes {
		c := newBenchCluster(s)
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			fn(b, c)
		})
	}
}

// BenchmarkLoad is the inline caller's whole cost: ipam check builds a tracker per call.
func BenchmarkLoad(b *testing.B) {
	forEachSize(b, func(b *testing.B, c *benchCluster) {
		for b.Loop() {
			c.load()
		}
	})
}

// BenchmarkRetainedMemory reports the heap a loaded tracker keeps, beyond the resources it was given.
func BenchmarkRetainedMemory(b *testing.B) {
	forEachSize(b, func(b *testing.B, c *benchCluster) {
		var before, after runtime.MemStats
		var retained int64
		for b.Loop() {
			runtime.GC()
			runtime.ReadMemStats(&before)
			tr := c.load()
			runtime.GC()
			runtime.ReadMemStats(&after)
			retained += int64(after.HeapAlloc) - int64(before.HeapAlloc)
			runtime.KeepAlive(tr)
		}
		b.ReportMetric(float64(retained)/float64(b.N), "retained-B/op")
	})
}

// benchRead is one tracker read to time.
type benchRead struct {
	name string
	read func()
}

// BenchmarkRead times each read on a loaded tracker with nothing pending, which is a syncer caller's steady state.
func BenchmarkRead(b *testing.B) {
	forEachSize(b, func(b *testing.B, c *benchCluster) {
		tr := c.load()
		first := c.pools[0].Name
		for _, r := range []benchRead{
			{"Summarize", func() { tr.Summarize(first) }},
			{"SummarizeAll", func() { tr.SummarizeAll() }},
			{"Allocations", func() { tr.Allocations(first) }},
			{"Unreferenced", func() { tr.Unreferenced(first) }},
			{"NoPoolBlocks", func() { tr.NoPoolBlocks() }},
		} {
			b.Run(r.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					r.read()
				}
			})
		}
	})
}

// BenchmarkWrite times one syncer event and the read that follows it. The read is included because the tracker may
// defer work to it, and a caller always pays for both.
func BenchmarkWrite(b *testing.B) {
	forEachSize(b, func(b *testing.B, c *benchCluster) {
		first := c.pools[0].Name

		b.Run("Block", func(b *testing.B) {
			tr := c.load()
			grown := growBlock(c.blocks[0])
			versions := []*model.AllocationBlock{grown, c.blocks[0]}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				tr.AddBlocks(versions[i%2])
				tr.Summarize(first)
				i++
			}
		})

		b.Run("Pool", func(b *testing.B) {
			tr := c.load()
			relabeled := c.pools[0].DeepCopy()
			relabeled.Labels = map[string]string{"bench": "relabeled"}
			versions := []*v3.IPPool{relabeled, c.pools[0]}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				tr.AddPools(versions[i%2])
				tr.Summarize(first)
				i++
			}
		})

		b.Run("Reservation", func(b *testing.B) {
			tr := c.load()
			grown := c.reservations[0].DeepCopy()
			grown.Spec.ReservedCIDRs = append(grown.Spec.ReservedCIDRs, "10.0.0.0/30")
			versions := []*v3.IPReservation{grown, c.reservations[0]}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				tr.AddReservations(versions[i%2])
				tr.Summarize(first)
				i++
			}
		})

		b.Run("Node", func(b *testing.B) {
			tr := c.load()
			node := c.nodes[0]
			b.ReportAllocs()
			for b.Loop() {
				tr.RemoveNode(node)
				tr.Summarize(first)
				tr.AddNodes(node)
				tr.Summarize(first)
			}
		})

		b.Run("Ref", func(b *testing.B) {
			tr := c.load()
			r := c.refs[0]
			b.ReportAllocs()
			for b.Loop() {
				tr.RemoveRefs(r)
				tr.Unreferenced(first)
				tr.AddRefs(r)
				tr.Unreferenced(first)
			}
		})
	})
}

// growBlock copies b with one more pod allocation, so re-adding it changes the block's counts.
func growBlock(b *model.AllocationBlock) *model.AllocationBlock {
	out := *b
	out.Allocations = slices.Clone(b.Allocations)
	out.Attributes = slices.Clone(b.Attributes)
	node, _ := NodeAffinity(b)
	allocate(&out, 60, "k8s-pod-network.grown", map[string]string{
		model.IPAMBlockAttributePod:       "grown",
		model.IPAMBlockAttributeNamespace: "default",
		model.IPAMBlockAttributeNode:      node,
	})
	return &out
}
