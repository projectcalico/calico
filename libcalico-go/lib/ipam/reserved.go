// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"math"
	"math/big"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"
	"go4.org/netipx"
)

// countPoolSpace reports address counts for a whole IP pool CIDR, including the
// parts of it that no allocation block covers yet:
//
//   - capacity: how many IPs the pool CIDR holds;
//   - reserved: how many of those a reservation covers, whether or not they are
//     also allocated;
//   - availableOutsideBlocks: how many are neither reserved nor inside one of
//     the given blocks.  IPs inside a block are left to the caller, which has
//     the block's allocations and so can tell free from in-use.
//
// Reservations may overlap and nest arbitrarily — one IPReservation can cover a
// /24 while another names a single IP inside it, and an L2 subnet contributes
// its network and broadcast addresses on top — so the counting is a set
// operation rather than a sum over the CIDRs.
func countPoolSpace(poolCIDR net.IPNet, reserved cidrSliceFilter, blocks []BlockUtilization) (capacity, reservedCount, availableOutsideBlocks int, err error) {
	poolPrefix, ok := netipx.FromStdIPNet(&poolCIDR)
	if !ok {
		return 0, 0, 0, fmt.Errorf("IP pool CIDR %s cannot be represented as a prefix", poolCIDR.String())
	}

	// Start from the whole pool and subtract the reservations.  Subtracting a
	// prefix splits whatever it partly overlaps and repeats are no-ops, so
	// overlapping reservations need no deduplication of our own.
	var assignable netipx.IPSetBuilder
	assignable.AddPrefix(poolPrefix)
	for _, r := range reserved {
		if p, ok := netipx.FromStdIPNet(&r.IPNet); ok {
			assignable.RemovePrefix(p)
		} else {
			log.WithField("cidr", r.String()).Warn("Ignoring reservation that cannot be represented as a prefix.")
		}
	}

	// Clone before subtracting the blocks so we can measure the pool both with
	// and without them.  Clone drops errors accumulated so far, but they stay on
	// the original, which we check below.
	outsideBlocks := assignable.Clone()
	for _, b := range blocks {
		if p, ok := netipx.FromStdIPNet(&b.CIDR); ok {
			outsideBlocks.RemovePrefix(p)
		}
	}

	assignableSet, err := assignable.IPSet()
	if err != nil {
		return 0, 0, 0, err
	}
	outsideBlocksSet, err := outsideBlocks.IPSet()
	if err != nil {
		return 0, 0, 0, err
	}

	poolSize := numIPsInPrefix(poolPrefix)
	return clampToInt(poolSize),
		clampToInt(new(big.Int).Sub(poolSize, numIPsInSet(assignableSet))),
		clampToInt(numIPsInSet(outsideBlocksSet)),
		nil
}

func numIPsInSet(s *netipx.IPSet) *big.Int {
	total := big.NewInt(0)
	for _, p := range s.Prefixes() {
		total.Add(total, numIPsInPrefix(p))
	}
	return total
}

func numIPsInPrefix(p netip.Prefix) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
}

// clampToInt saturates rather than wrapping, so an IPv6 pool larger than an int
// can hold reports the largest number we can represent instead of a negative
// one.  The counts in BlockUtilization and PoolUtilization have always been
// ints; only pools bigger than 2^63 addresses are affected.
func clampToInt(n *big.Int) int {
	if !n.IsInt64() || n.Int64() > math.MaxInt {
		return math.MaxInt
	}
	return int(n.Int64())
}
