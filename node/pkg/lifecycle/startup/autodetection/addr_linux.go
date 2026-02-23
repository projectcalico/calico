//go:build linux

// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package autodetection

import (
	"net"

	"github.com/vishvananda/netlink"
)

// Package-level variable for dependency injection (testing)
var netlinkAddrList = netlink.AddrList

// getAllInterfaceAddrs retrieves all addresses from all interfaces in one netlink call,
// then groups them by interface index for O(1) lookup.
// This avoids the O(N^2) behavior of calling i.Addrs() for each interface, which
// internally performs a full RTM_GETADDR netlink dump of all addresses on the system
// for each call, then filters to one interface.
func getAllInterfaceAddrs() (map[int][]net.Addr, error) {
	nlAddrs, err := netlinkAddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}

	addrsByIndex := make(map[int][]net.Addr)
	for _, nlAddr := range nlAddrs {
		linkIndex := nlAddr.LinkIndex
		netAddr := &net.IPNet{
			IP:   nlAddr.IP,
			Mask: nlAddr.Mask,
		}
		addrsByIndex[linkIndex] = append(addrsByIndex[linkIndex], netAddr)
	}

	return addrsByIndex, nil
}
