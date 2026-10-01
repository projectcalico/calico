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
	"math/big"
	"net"

	"go4.org/netipx"

	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
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
func countPoolSpace(poolCIDR net.IPNet, reserved cidrSliceFilter, blocks []BlockUtilization) (capacity, reservedCount, availableOutsideBlocks int, err error) {
	poolPrefix, err := accounting.PrefixFromCIDR(poolCIDR)
	if err != nil {
		return 0, 0, 0, err
	}
	assignable := accounting.SubtractReserved(poolPrefix, reserved)

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

	poolSize := accounting.NumIPsInPrefix(poolPrefix)
	return accounting.ClampToInt(poolSize),
		accounting.ClampToInt(new(big.Int).Sub(poolSize, accounting.NumIPsInSet(assignableSet))),
		accounting.ClampToInt(accounting.NumIPsInSet(outsideBlocksSet)),
		nil
}
