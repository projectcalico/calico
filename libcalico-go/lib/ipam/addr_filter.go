// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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
	"sort"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

type addrFilter interface {
	// MatchesIP returns true if the given IP is matched by the filter.
	MatchesIP(ip net.IP) bool
	// MatchesWholeCIDR returns true if every address within the CIDR is matched by the filter.
	MatchesWholeCIDR(ip *net.IPNet) bool
	// MatchesSome returns true if any part of the given CIDR is matched by this filter.
	MatchesSome(ip *net.IPNet) bool
}

type nilAddrFilter struct{}

func (n nilAddrFilter) MatchesSome(ip *net.IPNet) bool {
	return false
}

func (n nilAddrFilter) MatchesIP(ip net.IP) bool {
	return false
}

func (n nilAddrFilter) MatchesWholeCIDR(ip *net.IPNet) bool {
	return false
}

var _ addrFilter = nilAddrFilter{}

type cidrSliceFilter []net.IPNet

func (c cidrSliceFilter) MatchesSome(ip *net.IPNet) bool {
	for _, cidr := range c {
		if cidr.IsNetOverlap(ip.IPNet) {
			return true
		}
	}
	return false
}

func (c cidrSliceFilter) MatchesIP(ip net.IP) bool {
	for _, cidr := range c {
		if cidr.Contains(ip.IP) {
			return true
		}
	}
	return false
}

func (c cidrSliceFilter) MatchesWholeCIDR(candidateCIDR *net.IPNet) bool {
	var cidrsOverlappingCandidate cidrSliceFilter
	for _, filterCIDR := range c {
		if filterCIDR.Covers(candidateCIDR.IPNet) {
			return true
		}
		if candidateCIDR.Contains(filterCIDR.IP) {
			// This CIDR overlaps the candidate but doesn't cover it.  Save it off so we can do a second pass.
			cidrsOverlappingCandidate = append(cidrsOverlappingCandidate, filterCIDR)
		}
	}
	if len(cidrsOverlappingCandidate) == 0 {
		return false
	}

	// If we get here, we have some CIDRs that overlap candidateCIDR but none that completely cover it.
	// Check if, together they cover it.

	// Now, everything that remains in cidrsOverlappingCandidate is non-overlapping and contained within the
	// candidate CIDR.  If the candidate CIDR contains the same number of IPs as the overlapping set then
	// we know that the overlapping set covers the candidate CIDR.
	cidrsOverlappingCandidate, numCoveredIPs := cidrsOverlappingCandidate.filterDupesAndGetNumCoveredIPs()
	return numCoveredIPs.Cmp(candidateCIDR.NumAddrs()) == 0
}

// filterDupesAndGetNumCoveredIPs returns the sum of the number of IPs covered by each CIDR in the slice.
// As aside effect is filters out duplicate and overlapping CIDRs and returns the updates slice.
func (c cidrSliceFilter) filterDupesAndGetNumCoveredIPs() (cidrSliceFilter, *big.Int) {
	filtered := c.filterOutDuplicates()
	num := big.NewInt(0)
	for _, cidr := range filtered {
		num = num.Add(num, cidr.NumAddrs())
	}
	return filtered, num
}

// filterOutDuplicates returns a cidrSliceFilter with duplicate CIDRs and overlapping CIDRs pruned out.
// It reuses the storage of the input slice.
func (c cidrSliceFilter) filterOutDuplicates() cidrSliceFilter {
	sort.SliceStable(c, func(i, j int) bool {
		return c[i].NumAddrs().Cmp(c[j].NumAddrs()) < 0
	})
	filteredOverlaps := c[:0]
outer:
	for i, cidr := range c {
		for _, largerCIDR := range c[i+1:] {
			if largerCIDR.Contains(cidr.IP) {
				continue outer
			}
		}
		filteredOverlaps = append(filteredOverlaps, cidr)
	}
	return filteredOverlaps
}

var _ addrFilter = cidrSliceFilter(nil)
