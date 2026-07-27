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
	"math"
	"testing"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func TestCountPoolSpace(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		pool                      string
		reservations              []string
		blocks                    []string
		wantCapacity              int
		wantReserved              int
		wantAvailableOutsideBlock int
	}{
		{
			name:                      "no reservations and no blocks",
			pool:                      "10.0.0.0/24",
			wantCapacity:              256,
			wantAvailableOutsideBlock: 256,
		},
		{
			name:                      "one reservation",
			pool:                      "10.0.0.0/24",
			reservations:              []string{"10.0.0.32/30"},
			wantCapacity:              256,
			wantReserved:              4,
			wantAvailableOutsideBlock: 252,
		},
		{
			// The nested and duplicated CIDRs must not be counted more than once.
			name:                      "overlapping reservations",
			pool:                      "10.0.0.0/24",
			reservations:              []string{"10.0.0.0/25", "10.0.0.5/32", "10.0.0.64/26", "10.0.0.0/25"},
			wantCapacity:              256,
			wantReserved:              128,
			wantAvailableOutsideBlock: 128,
		},
		{
			name:         "reservation covering the whole pool",
			pool:         "10.0.0.0/24",
			reservations: []string{"10.0.0.0/16"},
			wantCapacity: 256,
			wantReserved: 256,
		},
		{
			name:                      "reservation outside the pool",
			pool:                      "10.0.0.0/24",
			reservations:              []string{"192.168.0.0/24", "fd00::/120"},
			wantCapacity:              256,
			wantAvailableOutsideBlock: 256,
		},
		{
			name:                      "blocks carved from the pool",
			pool:                      "10.0.0.0/24",
			blocks:                    []string{"10.0.0.0/26", "10.0.0.64/26"},
			wantCapacity:              256,
			wantAvailableOutsideBlock: 128,
		},
		{
			// The reservation is inside a block, so it does not reduce the space
			// outside the blocks; the block's own count covers it.
			name:                      "reservation inside a block",
			pool:                      "10.0.0.0/24",
			reservations:              []string{"10.0.0.32/30"},
			blocks:                    []string{"10.0.0.0/26"},
			wantCapacity:              256,
			wantReserved:              4,
			wantAvailableOutsideBlock: 192,
		},
		{
			name:                      "reservation outside every block",
			pool:                      "10.0.0.0/24",
			reservations:              []string{"10.0.0.128/25"},
			blocks:                    []string{"10.0.0.0/26"},
			wantCapacity:              256,
			wantReserved:              128,
			wantAvailableOutsideBlock: 64,
		},
		{
			name:                      "IPv6 pool",
			pool:                      "fd00::/120",
			reservations:              []string{"fd00::/126"},
			wantCapacity:              256,
			wantReserved:              4,
			wantAvailableOutsideBlock: 252,
		},
		{
			// Bigger than validation allows, but the counts must saturate rather
			// than wrap if one ever gets this far.
			name:                      "pool too big for an int",
			pool:                      "fd00::/8",
			wantCapacity:              math.MaxInt,
			wantAvailableOutsideBlock: math.MaxInt,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reservations cidrSliceFilter
			for _, r := range tc.reservations {
				reservations = append(reservations, cnet.MustParseNetwork(r))
			}
			var blocks []BlockUtilization
			for _, b := range tc.blocks {
				blocks = append(blocks, BlockUtilization{CIDR: cnet.MustParseNetwork(b).IPNet})
			}

			capacity, reserved, availableOutsideBlocks, err := countPoolSpace(
				cnet.MustParseNetwork(tc.pool).IPNet, reservations, blocks)
			if err != nil {
				t.Fatalf("countPoolSpace returned an error: %v", err)
			}
			if capacity != tc.wantCapacity {
				t.Errorf("capacity = %d, want %d", capacity, tc.wantCapacity)
			}
			if reserved != tc.wantReserved {
				t.Errorf("reserved = %d, want %d", reserved, tc.wantReserved)
			}
			if availableOutsideBlocks != tc.wantAvailableOutsideBlock {
				t.Errorf("availableOutsideBlocks = %d, want %d", availableOutsideBlocks, tc.wantAvailableOutsideBlock)
			}
		})
	}
}
