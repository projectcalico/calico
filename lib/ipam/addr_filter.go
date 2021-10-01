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
	"github.com/projectcalico/libcalico-go/lib/net"
)

type addrFilter interface {
	// MatchesIP returns true if the given IP is matched by the filter.
	MatchesIP(ip net.IP) bool
	// MatchesWholeCIDR returns true if every address within the CIDR is matched by the filter.
	MatchesWholeCIDR(ip *net.IPNet) bool
}

type nilAddrFilter struct{}

func (n nilAddrFilter) MatchesIP(ip net.IP) bool {
	return false
}

func (n nilAddrFilter) MatchesWholeCIDR(ip *net.IPNet) bool {
	return false
}

var _ addrFilter = nilAddrFilter{}

type cidrSliceFilter []net.IPNet

func (c cidrSliceFilter) MatchesIP(ip net.IP) bool {
	for _, cidr := range c {
		if cidr.Contains(ip.IP) {
			return true
		}
	}
	return false
}

func (c cidrSliceFilter) MatchesWholeCIDR(candidateCIDR *net.IPNet) bool {
	var overlaps cidrSliceFilter
	for _, filterCIDR := range c {
		if filterCIDR.Covers(candidateCIDR.IPNet) {
			return true
		}
		if candidateCIDR.Contains(filterCIDR.IP) {
			// This CIDR overlaps the candidate but doesn't cover it.  Save it off so we can do a second pass.
			overlaps = append(overlaps, filterCIDR)
		}
	}
	if len(overlaps) == 0 {
		return false
	}
	// Corner case, some CIDRs overlap the candidateCIDR but we don't yet know if together they cover it.
	// Check for _that_.
	numAddrs := candidateCIDR.NumAddrs()
	for i := 0; i < numAddrs; i++ {
		addr := candidateCIDR.NthIP(i)
		if !overlaps.MatchesIP(addr) {
			return false
		}
	}
	return true
}

var _ addrFilter = cidrSliceFilter(nil)
