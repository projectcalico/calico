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
	"maps"
	"math/big"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Counts is what a pool's blocks add up to. Address counts cover every block the pool owns; Total and Reserved cover
// its whole CIDR, including space no block has been carved from yet.
type Counts struct {
	// Total is how many addresses the pool's CIDR holds. A big.Int, because an IPv6 pool overflows an int.
	Total *big.Int

	// Reserved is how many of those an IPReservation withholds, whether or not they are also in use.
	Reserved *big.Int

	// TotalBlocks is how many blocks the CIDR can be carved into at the pool's block size.
	TotalBlocks *big.Int

	// InUse is how many addresses a block has handed out, including cooling ones.
	InUse int

	// Cooling is the part of InUse released and waiting out its cooldown before reuse.
	Cooling int

	// Borrowed is the part of InUse held by a node other than its block's affine node.
	Borrowed int

	// InUseReserved is the overlap between InUse and Reserved: addresses allocated before a reservation covered them.
	InUseReserved int

	// BlocksInUse is how many blocks the pool owns.
	BlocksInUse int

	// NoAffinity is how many of those have no affinity at all.
	NoAffinity int

	// VirtualAffinity is how many are affine to a virtual owner, such as LoadBalancer blocks, rather than a node.
	VirtualAffinity int

	// StaleAffinity is how many are affine to a node the caller did not name. Zero until AddNodes is called.
	StaleAffinity int

	// BlocksByNode counts the pool's blocks per affine node.
	BlocksByNode map[string]int

	// AssignedByNode splits Assigned by the node holding each address, as Allocation.Node names it. An address no
	// node holds counts under "".
	AssignedByNode map[string]int

	// BorrowedByNode splits Borrowed by the node that borrowed each address.
	BorrowedByNode map[string]int

	// AddressesByKind counts assigned addresses, cooling excluded, per allowed use.
	AddressesByKind map[v3.IPPoolAllowedUse]int
}

// Assigned is the part of InUse a workload or tunnel still holds.
func (c *Counts) Assigned() int {
	return c.InUse - c.Cooling
}

// Free is every address that is neither in use nor reserved. InUseReserved comes back because the two overlap.
func (c *Counts) Free() *big.Int {
	free := new(big.Int).Sub(c.Total, c.Reserved)
	free.Sub(free, big.NewInt(int64(c.InUse-c.InUseReserved)))
	if free.Sign() < 0 {
		free.SetInt64(0)
	}
	return free
}

func newCounts() *Counts {
	return &Counts{
		Total:           big.NewInt(0),
		Reserved:        big.NewInt(0),
		TotalBlocks:     big.NewInt(0),
		BlocksByNode:    make(map[string]int),
		AssignedByNode:  make(map[string]int),
		BorrowedByNode:  make(map[string]int),
		AddressesByKind: make(map[v3.IPPoolAllowedUse]int),
	}
}

func (c *Counts) clone() *Counts {
	out := *c
	out.Total = new(big.Int).Set(c.Total)
	out.Reserved = new(big.Int).Set(c.Reserved)
	out.TotalBlocks = new(big.Int).Set(c.TotalBlocks)
	out.BlocksByNode = maps.Clone(c.BlocksByNode)
	out.AssignedByNode = maps.Clone(c.AssignedByNode)
	out.BorrowedByNode = maps.Clone(c.BorrowedByNode)
	out.AddressesByKind = maps.Clone(c.AddressesByKind)
	return &out
}

// BlockCounts is what one block's allocations add up to, using the same terms as Counts.
type BlockCounts struct {
	Block *model.AllocationBlock

	Total         int
	InUse         int
	Cooling       int
	Reserved      int
	InUseReserved int

	// Borrowed is the part of InUse held by a node other than the block's affine node, so what that node lends. Every
	// held address in an unaffined block is borrowed.
	Borrowed int
}

// Free is every address in the block that is neither in use nor reserved.
func (c *BlockCounts) Free() int {
	return max(c.Total-c.InUse-c.Reserved+c.InUseReserved, 0)
}
