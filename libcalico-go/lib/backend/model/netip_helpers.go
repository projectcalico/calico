// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package model

import (
	"net"
	"net/netip"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// PrefixFromIPNet converts a calico net.IPNet to a netip.Prefix.
// The result is always masked (host bits cleared) for consistency.
func PrefixFromIPNet(n cnet.IPNet) netip.Prefix {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}
	}
	addr = addr.Unmap()
	ones, _ := n.Mask.Size()
	p := netip.PrefixFrom(addr, ones)
	return p.Masked()
}

// PrefixFromStdIPNet converts a stdlib net.IPNet to a netip.Prefix.
func PrefixFromStdIPNet(n net.IPNet) netip.Prefix {
	return PrefixFromIPNet(cnet.IPNet{IPNet: n})
}

// IPNetFromPrefix converts a netip.Prefix back to a calico net.IPNet.
func IPNetFromPrefix(p netip.Prefix) cnet.IPNet {
	addr := p.Addr()
	bits := p.Bits()
	var ipLen int
	if addr.Is4() {
		ipLen = net.IPv4len * 8
	} else {
		ipLen = net.IPv6len * 8
	}
	return cnet.IPNet{
		IPNet: net.IPNet{
			IP:   addr.AsSlice(),
			Mask: net.CIDRMask(bits, ipLen),
		},
	}
}

// AddrFromIP converts a calico net.IP to a netip.Addr.
func AddrFromIP(ip cnet.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip.IP)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// IPFromAddr converts a netip.Addr back to a calico net.IP.
func IPFromAddr(a netip.Addr) cnet.IP {
	return cnet.IP{IP: a.AsSlice()}
}

// prefixVersion returns the IP version (4 or 6) for a netip.Prefix.
func prefixVersion(p netip.Prefix) int {
	if p.Addr().Is4() {
		return 4
	}
	return 6
}

// addrVersion returns the IP version (4 or 6) for a netip.Addr.
func addrVersion(a netip.Addr) int {
	if a.Is4() {
		return 4
	}
	return 6
}
