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

// Memory leak investigation tests for the IPAMController's onBlockDeleted cleanup paths.
// Tests marked "currently FAILS" document confirmed bugs; they will pass once fixed.
//
// The IPAMController tracks IPAM state across several cross-indexed maps:
//
//	allBlocks            — raw block KVPairs keyed by CIDR
//	allocationsByBlock   — per-block allocation index
//	handleTracker        — per-handle allocation index (for leak detection)
//	confirmedLeaks       — allocations confirmed as leaked, awaiting GC
//	nodesByBlock         — CIDR → affine node name
//	blocksByNode         — node name → set of affine block CIDRs
//
// All of these must be cleaned up consistently when a block is deleted.

package node

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// newLeakTestController builds a minimal IPAMController with all maps
// initialised but no goroutines running. Suitable for direct method calls.
func newLeakTestController() *IPAMController {
	return &IPAMController{
		allBlocks:           make(map[string]model.KVPair),
		allocationsByBlock:  make(map[string]map[string]*allocation),
		allocationState:     newAllocationState(),
		handleTracker:       newHandleTracker(),
		confirmedLeaks:      make(map[string]*allocation),
		nodesByBlock:        make(map[string]string),
		blocksByNode:        make(map[string]map[string]bool),
		emptyBlocks:         make(map[string]string),
		blockReleaseTracker: newBlockReleaseTracker(nil),
		poolManager:         newPoolManager(),
	}
}

// makeTestBlock builds a KVPair representing an affine AllocationBlock with a
// single allocated IP assigned to the given handle and node.
func makeTestBlock(cidrStr, nodeName, handle string) model.KVPair {
	cidr := cnet.MustParseCIDR(cidrStr)
	aff := "host:" + nodeName
	idx := 0
	b := model.AllocationBlock{
		CIDR:        cidr,
		Affinity:    &aff,
		Allocations: []*int{&idx, nil, nil, nil},
		Unallocated: []int{1, 2, 3},
		Attributes: []model.AllocationAttribute{
			{
				HandleID: &handle,
				ActiveOwnerAttrs: map[string]string{
					ipam.AttributeNode: nodeName,
				},
			},
		},
	}
	return model.KVPair{Key: model.BlockKey{CIDR: cidr}, Value: &b}
}

var _ = Describe("IPAMController onBlockDeleted leak investigation", func() {
	const (
		blockCIDR  = "10.0.0.0/30"
		nodeName   = "test-node"
		handle     = "test-handle"
		block2CIDR = "10.0.1.0/30"
	)

	var c *IPAMController

	BeforeEach(func() {
		c = newLeakTestController()
	})

	// ── Correct paths ───────────────────────────────────────────────────────

	Describe("correct cleanup paths", func() {
		It("removes the block from allBlocks, allocationsByBlock, nodesByBlock, and emptyBlocks", func() {
			kvp := makeTestBlock(blockCIDR, nodeName, handle)
			c.onBlockUpdated(kvp)
			c.onBlockDeleted(kvp.Key.(model.BlockKey))

			Expect(c.allBlocks).ToNot(HaveKey(blockCIDR))
			Expect(c.allocationsByBlock).ToNot(HaveKey(blockCIDR))
			Expect(c.nodesByBlock).ToNot(HaveKey(blockCIDR))
		})

		It("releases allocations from allocationState on block deletion", func() {
			kvp := makeTestBlock(blockCIDR, nodeName, handle)
			c.onBlockUpdated(kvp)
			c.onBlockDeleted(kvp.Key.(model.BlockKey))

			c.allocationState.iter(func(node string, allocs map[string]*allocation) {
				Expect(allocs).To(BeEmpty(),
					"allocationState should have no allocations after block deletion")
			})
		})
	})

	// ── Bug 1: onBlockDeleted skips handleTracker cleanup ───────────────────

	Describe("handleTracker cleanup on block deletion", func() {
		// These tests currently FAIL — they document a confirmed bug:
		// onBlockUpdated correctly calls handleTracker.removeAllocation for individual
		// allocation releases, but onBlockDeleted omits this call entirely. When a block
		// is deleted with live allocations still tracked, handleTracker.allocationsByHandle
		// accumulates stale entries indefinitely.
		// Fix: onBlockDeleted should call handleTracker.removeAllocation for each
		// allocation in the block before deleting the block from allocationsByBlock.
		It("removes allocations from handleTracker when a block is deleted (currently FAILS)", func() {
			kvp := makeTestBlock(blockCIDR, nodeName, handle)
			c.onBlockUpdated(kvp)
			Expect(c.handleTracker.allocationsByHandle).To(HaveKey(handle),
				"handleTracker should have the allocation after onBlockUpdated")

			c.onBlockDeleted(kvp.Key.(model.BlockKey))

			Expect(c.handleTracker.allocationsByHandle).ToNot(HaveKey(handle),
				"handleTracker should not retain stale handle entries after block deletion")
		})

		It("removes the handle key when the last allocation for that handle is deleted with the block (currently FAILS)", func() {
			kvp := makeTestBlock(blockCIDR, nodeName, handle)
			c.onBlockUpdated(kvp)
			c.onBlockDeleted(kvp.Key.(model.BlockKey))

			Expect(c.handleTracker.allocationsByHandle).To(BeEmpty(),
				"handleTracker.allocationsByHandle should be empty after the only block is deleted")
		})
	})

	// ── Bug 2: onBlockDeleted skips confirmedLeaks cleanup ──────────────────

	Describe("confirmedLeaks cleanup on block deletion", func() {
		// This test currently FAILS — it documents a confirmed bug:
		// onBlockUpdated correctly calls delete(c.confirmedLeaks, id) when an allocation
		// is released, but onBlockDeleted omits this cleanup. A confirmed-leak entry for
		// an allocation in a deleted block is never removed, so confirmedLeaks accumulates
		// stale entries that can never be GC'd (the block they referenced no longer exists).
		// Fix: onBlockDeleted should call delete(c.confirmedLeaks, alloc.id()) for each
		// allocation in the block.
		It("removes confirmed leak entries for allocations in a deleted block (currently FAILS)", func() {
			kvp := makeTestBlock(blockCIDR, nodeName, handle)
			c.onBlockUpdated(kvp)

			// Directly inject a confirmed leak for the allocation in this block.
			for id, alloc := range c.allocationsByBlock[blockCIDR] {
				alloc.markConfirmedLeak()
				c.confirmedLeaks[id] = alloc
			}
			Expect(c.confirmedLeaks).ToNot(BeEmpty(),
				"confirmedLeaks should have an entry before the block is deleted")

			c.onBlockDeleted(kvp.Key.(model.BlockKey))

			Expect(c.confirmedLeaks).To(BeEmpty(),
				"confirmedLeaks should be empty after the block containing the leaked allocation is deleted")
		})
	})

	// ── Bug 3: onBlockDeleted leaves empty blocksByNode inner maps ──────────

	Describe("blocksByNode cleanup on block deletion", func() {
		// This test currently FAILS — it documents a confirmed bug:
		// onBlockDeleted calls delete(c.blocksByNode[n], blockCIDR) to remove the block
		// from the node's inner set, but never removes the outer node key when the inner
		// set becomes empty. Empty map[string]bool{} values accumulate in blocksByNode
		// for every node whose last block was deleted, growing proportionally to cluster
		// node churn.
		// Fix: after deleting the block from the inner set, check if it is empty and
		// delete the outer node key if so.
		It("removes the node key from blocksByNode when its last block is deleted (currently FAILS)", func() {
			kvp := makeTestBlock(blockCIDR, nodeName, handle)
			c.onBlockUpdated(kvp)
			Expect(c.blocksByNode).To(HaveKey(nodeName),
				"blocksByNode should contain the node after block registration")

			c.onBlockDeleted(kvp.Key.(model.BlockKey))

			Expect(c.blocksByNode).ToNot(HaveKey(nodeName),
				"blocksByNode should not retain an empty inner map for a node with no remaining blocks")
		})

		It("keeps the node key in blocksByNode when the node still has other blocks", func() {
			kvp1 := makeTestBlock(blockCIDR, nodeName, handle)
			kvp2 := makeTestBlock(block2CIDR, nodeName, "test-handle-2")
			c.onBlockUpdated(kvp1)
			c.onBlockUpdated(kvp2)

			// Delete only the first block.
			c.onBlockDeleted(kvp1.Key.(model.BlockKey))

			Expect(c.blocksByNode).To(HaveKey(nodeName),
				"blocksByNode should still contain the node while it has remaining blocks")
			Expect(c.blocksByNode[nodeName]).To(HaveKey(block2CIDR),
				"blocksByNode[node] should still contain the remaining block")
		})
	})
})
