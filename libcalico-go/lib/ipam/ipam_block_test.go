// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.

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

package ipam

import (
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

type testBlock struct {
	allocationBlock
}

func makeTestBlock() *testBlock {
	_, blockNet, err := cnet.ParseCIDR("100.64.0.0/24")
	Expect(err).NotTo(HaveOccurred())
	return &testBlock{allocationBlock: newBlock(*blockNet, nil)}
}

func (b *testBlock) allocateAttrib(ordinals []int, attrib model.AllocationAttribute) {
	// Add a new item to Attributes and link all ordinals to it.
	attrIndex := len(b.Attributes)
	b.Attributes = append(b.Attributes, attrib)
	for _, o := range ordinals {
		b.Allocations[o] = &attrIndex
	}
	j := 0

	// Remove all ordinals from Unallocated.
	for _, o := range b.Unallocated {
		if !slices.Contains(ordinals, o) {
			b.Unallocated[j] = o
			j++
		}
	}
	b.Unallocated = b.Unallocated[:j]
}

func (b *testBlock) allocate(ordinals []int, handleID string) {
	b.allocateAttrib(ordinals, model.AllocationAttribute{HandleID: &handleID})
}

func (b *testBlock) allocatedOrdinals() []int {
	allocated := []int{}
	var o int
	for o = 0; o < b.NumAddresses(); o++ {
		if b.Allocations[o] != nil {
			allocated = append(allocated, o)
		}
	}
	return allocated
}

func (b *testBlock) unallocatedTail(n int) []int {
	return b.Unallocated[len(b.Unallocated)-n:]
}

func (b *testBlock) validate() {
	GinkgoHelper()

	// Check that all non-nil Allocations point to valid attributes.
	seenAttribs := map[int]struct{}{}
	seenOrdinals := map[int]struct{}{}
	var o int
	for o = 0; o < b.NumAddresses(); o++ {
		if b.Allocations[o] == nil {
			continue
		}
		attrIdx := *b.Allocations[o]
		Expect(attrIdx).To(SatisfyAll(BeNumerically(">=", 0), BeNumerically("<", len(b.Attributes))),
			"Allocations index is within Attributes")
		if attrIdx >= 0 && attrIdx < len(b.Attributes) {
			seenAttribs[attrIdx] = struct{}{}
		}
		seenOrdinals[o] = struct{}{}
	}

	// Check that all attributes are pointed to
	for i := range b.Attributes {
		Expect(i).To(BeKeyOf(seenAttribs), "Attribute index was seen in Allocations")
	}

	// Check that all unallocated ordinals are unique and not seen.
	for i, o := range b.Unallocated {
		Expect(b.Unallocated[:i]).ToNot(ContainElement(o), "Unallocated element did not already appear in Unallocated")
		Expect(o).ToNot(BeKeyOf(seenOrdinals), "Unallocated element was not in Allocated")
	}

	// Check that all addresses are either in Allocated or Unallocated
	Expect(len(b.Unallocated)+len(seenOrdinals)).To(Equal(b.NumAddresses()), "All addresses are accounted for")
}

var _ = Describe("Getting summary information about a block", func() {
	It("identifies an empty block as empty", func() {
		block := makeTestBlock()
		Expect(block.empty()).To(Equal(true))
	})

	It("identifies a block with only IPs reserved for Windows as empty", func() {
		block := makeTestBlock()
		block.allocate([]int{255}, WindowsReservedHandle)
		Expect(block.empty()).To(Equal(true))
	})

	It("identifies a non-empty block", func() {
		block := makeTestBlock()
		block.allocate([]int{32}, "alloc")
		Expect(block.empty()).To(Equal(false))
	})

	It("returns no in-use IPs for an empty block", func() {
		block := makeTestBlock()
		Expect(block.inUseIPs()).To(HaveLen(0))
	})

	It("returns all in-use IPs for a non-empty block", func() {
		block := makeTestBlock()
		block.allocate([]int{10, 20}, "tens")
		Expect(block.inUseIPs()).To(HaveLen(2))
		Expect(block.inUseIPs()).To(ContainElements("100.64.0.10", "100.64.0.20"))
	})

	It("returns free addresses with no reservations", func() {
		block := makeTestBlock()
		block.allocate([]int{10, 20}, "tens")
		Expect(block.NumFreeAddresses(nilAddrFilter{})).To(Equal(256 - 2))
	})

	It("returns free addresses with half the block reserved", func() {
		_, secondHalf, err := cnet.ParseCIDR("100.64.0.128/25")
		Expect(err).NotTo(HaveOccurred())
		block := makeTestBlock()
		block.allocate([]int{10, 20, 210, 220}, "tens")
		Expect(block.NumFreeAddresses(cidrSliceFilter([]cnet.IPNet{*secondHalf}))).To(Equal(128 - 2))
	})

	It("returns free addresses entire block reserved", func() {
		_, wholeBlock, err := cnet.ParseCIDR("100.64.0.128/24")
		Expect(err).NotTo(HaveOccurred())
		block := makeTestBlock()
		block.allocate([]int{10, 20, 210, 220}, "tens")
		Expect(block.NumFreeAddresses(cidrSliceFilter([]cnet.IPNet{*wholeBlock}))).To(Equal(0))
	})

	It("correctly returns IPs by handle, whether zero, one, or many", func() {
		block := makeTestBlock()
		block.allocate([]int{3}, "singleton")
		block.allocate([]int{10, 20}, "tens")
		block.allocate([]int{33}, "thirties")
		block.allocate([]int{34}, "thirties")
		Expect(block.ipsByHandle("no-such-handle")).To(HaveLen(0))
		Expect(block.ipsByHandle("singleton")).To(SatisfyAll(
			HaveLen(1),
			ContainElement(*cnet.ParseIP("100.64.0.3")),
		))
		Expect(block.ipsByHandle("tens")).To(SatisfyAll(
			HaveLen(2),
			ContainElements(*cnet.ParseIP("100.64.0.10"), *cnet.ParseIP("100.64.0.20")),
		))
		Expect(block.ipsByHandle("thirties")).To(SatisfyAll(
			HaveLen(2),
			ContainElements(*cnet.ParseIP("100.64.0.33"), *cnet.ParseIP("100.64.0.34")),
		))
	})

	It("returns an error getting allocationAttributes for an unallocated IP", func() {
		block := makeTestBlock()
		ip := cnet.ParseIP("100.64.0.32")
		Expect(block.allocationAttributesForIP(*ip)).Error().Should(HaveOccurred())
	})

	It("returns the same attributes for an allocated IP", func() {
		block := makeTestBlock()
		ip := cnet.ParseIP("100.64.0.32")
		block.allocateAttrib([]int{32}, model.AllocationAttribute{
			HandleID:            new("hand"),
			ActiveOwnerAttrs:    map[string]string{"is": "active"},
			AlternateOwnerAttrs: map[string]string{"is": "alternate"},
		})
		Expect(block.allocationAttributesForIP(*ip)).To(SatisfyAll(
			HaveField("HandleID", new("hand")),
			HaveField("ActiveOwnerAttrs", ConsistOf("active")),
			HaveField("AlternateOwnerAttrs", ConsistOf("alternate")),
		))
	})
})

var _ = Describe("Releasing IPs", func() {
	minIPReclaimAgeZeroCfg := IPAMConfig{}
	It("deallocates a single IP", func() {
		block := makeTestBlock()
		block.allocate([]int{13}, "unlucky")

		unallocated, countByHandle, err := block.release(&minIPReclaimAgeZeroCfg, []ReleaseOptions{{
			Address: "100.64.0.13",
			Handle:  "unlucky",
		}})
		Expect(err).To(Succeed())
		Expect(unallocated).To(HaveLen(0))
		Expect(countByHandle).To(Equal(map[string]int{"unlucky": 1}))
		Expect(block.allocatedOrdinals()).To(Equal([]int{}), "ordinal no longer Allocated")

		block.validate()
	})

	It("deallocates one IP leaving its shared attributes behind", func() {
		block := makeTestBlock()
		block.allocate([]int{13, 26, 39}, "lucky")

		unallocated, countByHandle, err := block.release(&minIPReclaimAgeZeroCfg, []ReleaseOptions{{
			Address: "100.64.0.13",
		}})
		Expect(err).To(Succeed())
		Expect(unallocated).To(HaveLen(0))
		Expect(countByHandle).To(Equal(map[string]int{"lucky": 1}))
		Expect(block.allocatedOrdinals()).To(SatisfyAll(
			HaveLen(2),
			ContainElements(26, 39),
		), "13 no longer Allocated, but 26, 39 remain")

		block.validate()
	})

	It("deallocates all IPs with a shared attribute", func() {
		block := makeTestBlock()
		block.allocate([]int{13, 26, 39}, "lucky")

		unallocated, countByHandle, err := block.release(&minIPReclaimAgeZeroCfg, []ReleaseOptions{
			{Address: "100.64.0.13"},
			{Address: "100.64.0.26"},
			{Address: "100.64.0.39"},
		})
		Expect(err).To(Succeed())
		Expect(unallocated).To(HaveLen(0))
		Expect(countByHandle).To(Equal(map[string]int{"lucky": 3}))
		Expect(block.allocatedOrdinals()).To(HaveLen(0),
			"all three IPs no longer Allocated")

		block.validate()
	})

	It("does nothing when no such IP exists", func() {
		block := makeTestBlock()

		unallocated, countByHandle, err := block.release(&minIPReclaimAgeZeroCfg, []ReleaseOptions{{
			Address: "100.64.0.13",
			Handle:  "unlucky",
		}})
		Expect(err).To(Succeed())
		Expect(unallocated).To(Equal([]cnet.IP{*cnet.ParseIP("100.64.0.13")}))
		Expect(countByHandle).To(Equal(map[string]int{}))

		block.validate()
	})

	It("returns an error if the handles do not match", func() {
		block := makeTestBlock()
		block.allocate([]int{100}, "newstuff")

		_, _, err := block.release(&minIPReclaimAgeZeroCfg, []ReleaseOptions{{
			Address: "100.64.0.100",
			Handle:  "oldstuff",
		}})
		Expect(err).ToNot(Succeed())

		block.validate()
	})

	It("returns an error if the sequence numbers do not match", func() {
		block := makeTestBlock()
		block.allocate([]int{13}, "unlucky")
		block.SequenceNumberForAllocation["13"] = 10

		_, _, err := block.release(&minIPReclaimAgeZeroCfg, []ReleaseOptions{{
			Address:        "100.64.0.13",
			Handle:         "unlucky",
			SequenceNumber: new(uint64(999)),
		}})
		Expect(err).ToNot(Succeed())

		block.validate()
	})
})

var _ = Describe("Releasing IPs by Handle", func() {
	minIPReclaimAgeZeroCfg := IPAMConfig{}
	It("does nothing when no such handle exists", func() {
		block := makeTestBlock()
		released := block.releaseByHandle(&minIPReclaimAgeZeroCfg, ReleaseOptions{
			Address:        "100.64.0.99",
			Handle:         "nosuchhandle",
			SequenceNumber: nil,
		})
		Expect(released).To(Equal(0))

		block.validate()
	})

	It("removes an existing allocation", func() {
		block := makeTestBlock()
		block.allocate([]int{15}, "fifteen")
		block.allocate([]int{20}, "twenty")
		released := block.releaseByHandle(&minIPReclaimAgeZeroCfg, ReleaseOptions{
			Address:        "100.64.0.99", // No need for this to match ordinal.
			Handle:         "fifteen",
			SequenceNumber: nil,
		})
		Expect(released).To(Equal(1))
		Expect(block.allocatedOrdinals()).To(Equal([]int{20}), "twenty not affected")
		Expect(block.unallocatedTail(1)).To(ContainElement(15),
			"Unallocated should have released block at the tail")

		block.validate()
	})

	It("skips removal if the sequence numbers do not match", func() {
		block := makeTestBlock()
		block.allocate([]int{15}, "teens")
		block.allocate([]int{16}, "teens")
		block.allocate([]int{17, 18}, "teens")
		block.SequenceNumberForAllocation["15"] = 10
		block.SequenceNumberForAllocation["16"] = 10
		block.SequenceNumberForAllocation["17"] = 999 // not removed
		block.SequenceNumberForAllocation["18"] = 10

		released := block.releaseByHandle(&minIPReclaimAgeZeroCfg, ReleaseOptions{
			Handle:         "teens",
			SequenceNumber: new(uint64(10)),
		})
		Expect(released).To(Equal(3))
		Expect(block.allocatedOrdinals()).To(Equal([]int{17}), "mismatched allocation not freed")

		block.validate()
	})

	It("removes multiple existing allocations with the same handle and different attributes", func() {
		block := makeTestBlock()
		block.allocate([]int{15}, "several")
		block.allocate([]int{25}, "several")
		block.allocate([]int{35}, "several")
		released := block.releaseByHandle(&minIPReclaimAgeZeroCfg, ReleaseOptions{
			Address:        "100.64.0.99",
			Handle:         "several",
			SequenceNumber: nil,
		})
		Expect(released).To(Equal(3))
		Expect(block.allocatedOrdinals()).To(HaveLen(0))
		Expect(block.unallocatedTail(3)).To(ContainElements(15, 25, 35),
			"Unallocated should have released blocks at the tail")

		block.validate()
	})

	It("removes multiple existing allocations with the same handle and attributes", func() {
		block := makeTestBlock()
		block.allocate([]int{15, 25, 35}, "several")
		released := block.releaseByHandle(&minIPReclaimAgeZeroCfg, ReleaseOptions{
			Address:        "100.64.0.99",
			Handle:         "several",
			SequenceNumber: nil,
		})
		Expect(released).To(Equal(3))
		Expect(block.allocatedOrdinals()).To(HaveLen(0))
		Expect(block.unallocatedTail(3)).To(ContainElements(15, 25, 35),
			"Unallocated should have released blocks at the tail")

		block.validate()
	})
})

var _ = Describe("Block garbage collection", func() {
	It("produces valid block from an empty block", func() {
		block := makeTestBlock()
		Expect(block.garbageCollect(0)).To(Equal(false))
		block.validate()
	})

	It("Clears unused attributes", func() {
		block := makeTestBlock()
		// Add some spurious attributes.
		block.Attributes = append(block.Attributes,
			model.AllocationAttribute{HandleID: new("spurious1")},
			model.AllocationAttribute{HandleID: new("spurious2")},
		)
		// Add a regular allocation.
		block.allocate([]int{32}, "thirty-two")

		Expect(block.garbageCollect(0)).To(Equal(true))

		Expect(block.allocatedOrdinals()).To(HaveLen(1))
		Expect(block.Attributes).To(HaveLen(1))
		block.validate()
	})

	It("produces valid block from a block with some old and some new released IPs", func() {
		block := makeTestBlock()
		// 31,33 are ready to deallocate.
		block.allocateAttrib([]int{31, 33}, model.AllocationAttribute{
			ReleasedAt: new(v1.NewTime(time.Now().Add(-time.Minute))),
		})
		// 42,44 are not.
		block.allocateAttrib([]int{42, 44}, model.AllocationAttribute{
			ReleasedAt: new(v1.NewTime(time.Now().Add(time.Minute))),
		})
		// 50,51 are not relased yet.
		block.allocate([]int{52, 54}, "fifties")

		Expect(block.garbageCollect(30)).To(Equal(true))

		Expect(block.allocatedOrdinals()).To(HaveLen(4), "42, 44, 50, 51 are still in Allocated")
		Expect(block.NumFreeAddresses(nilAddrFilter{})).To(Equal(256-4), "all but four addresses free")
		block.validate()
	})

})
