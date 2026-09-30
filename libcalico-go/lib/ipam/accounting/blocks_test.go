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
	"testing"

	. "github.com/onsi/gomega"
)

type rowCounts struct {
	total    string
	inUse    int
	reserved string
	free     string
}

type blockRowCounts struct {
	total    int
	inUse    int
	reserved int
	free     int
}

type reservedCountsCase struct {
	name      string
	reserved  []string
	wantPool  rowCounts
	wantBlock blockRowCounts
}

// These are the GetUtilization reservation cases: a /24 pool with one /26 block holding 10.0.0.5.
func TestBlockAndPoolReservedCounts(t *testing.T) {
	tests := []reservedCountsCase{
		{
			name:      "inside the block",
			reserved:  []string{"10.0.0.32/30"},
			wantPool:  rowCounts{total: "256", inUse: 1, reserved: "4", free: "251"},
			wantBlock: blockRowCounts{total: 64, inUse: 1, reserved: 4, free: 59},
		},
		{
			name:      "over pool space with no block",
			reserved:  []string{"10.0.0.128/25"},
			wantPool:  rowCounts{total: "256", inUse: 1, reserved: "128", free: "127"},
			wantBlock: blockRowCounts{total: 64, inUse: 1, reserved: 0, free: 63},
		},
		{
			name:      "over the allocated address",
			reserved:  []string{"10.0.0.5/32"},
			wantPool:  rowCounts{total: "256", inUse: 1, reserved: "1", free: "255"},
			wantBlock: blockRowCounts{total: 64, inUse: 1, reserved: 1, free: 63},
		},
		{
			name:      "overlapping each other",
			reserved:  []string{"10.0.0.0/25", "10.0.0.5/32", "10.0.0.64/26"},
			wantPool:  rowCounts{total: "256", inUse: 1, reserved: "128", free: "128"},
			wantBlock: blockRowCounts{total: 64, inUse: 1, reserved: 64, free: 0},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			b := testBlock("10.0.0.0/26", "host:host-a")
			allocatePod(b, 5, "host-a")

			tr := NewTracker()
			tr.AddPools(pool("p", "10.0.0.0/24", 26))
			tr.AddBlocks(b)
			tr.AddReservations(reservation("resv", tc.reserved...))

			c := mustSummarize(tr, "p")
			Expect(rowCounts{c.Total.String(), c.InUse, c.Reserved.String(), c.Free().String()}).To(Equal(tc.wantPool))

			blocks := tr.PoolBlockCounts("p")
			Expect(blocks).To(HaveLen(1))
			bc := blocks[0]
			Expect(blockRowCounts{bc.Total, bc.InUse, bc.Reserved, bc.Free()}).To(Equal(tc.wantBlock))
		})
	}
}

func TestBlockCountsFollowReservationChanges(t *testing.T) {
	RegisterTestingT(t)
	block := testBlock("10.0.0.0/26", "host:host-a")
	allocatePod(block, 5, "host-a")
	allocateCooling(block, 6)

	tracker := NewTracker()
	tracker.AddPools(pool("p", "10.0.0.0/24", 26))
	tracker.AddBlocks(block)
	counts, ok := tracker.BlockCounts(block.CIDR)
	Expect(ok).To(BeTrue())
	Expect(counts.InUse).To(Equal(2))
	Expect(counts.Cooling).To(Equal(1))
	Expect(counts.Reserved).To(Equal(0))
	Expect(counts.Free()).To(Equal(62))

	tracker.AddReservations(reservation("resv", "10.0.0.4/30"))
	counts, _ = tracker.BlockCounts(block.CIDR)
	Expect(counts.Reserved).To(Equal(4))
	Expect(counts.InUseReserved).To(Equal(2))
	Expect(counts.Free()).To(Equal(60))

	tracker.RemoveReservation("resv")
	counts, _ = tracker.BlockCounts(block.CIDR)
	Expect(counts.Reserved).To(Equal(0))
	Expect(counts.InUseReserved).To(Equal(0))
}

func TestBlockCountsForUnclaimedBlock(t *testing.T) {
	RegisterTestingT(t)
	orphan := testBlock("192.168.0.0/26", "")
	allocatePod(orphan, 0, "n")

	tr := NewTracker()
	tr.AddPools(pool("p", "10.0.0.0/24", 26))
	tr.AddBlocks(orphan)
	Expect(tr.PoolBlockCounts("p")).To(BeEmpty())

	bc, ok := tr.BlockCounts(orphan.CIDR)
	Expect(ok).To(BeTrue())
	Expect(bc.InUse).To(Equal(1))

	_, ok = tr.BlockCounts(testBlock("10.9.0.0/26", "").CIDR)
	Expect(ok).To(BeFalse())
}
