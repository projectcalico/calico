// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package net

import "net"

// MustMACToIPv6LinkLocal converts a MAC address to the associated IPv6
// link-local address.
func MustMACToIPv6LinkLocal(mac net.HardwareAddr) net.IP {
	// First convert MAC to EUI-64.
	var eui [8]byte
	if len(mac) == 8 {
		copy(eui[:], mac)
	} else if len(mac) == 6 {
		copy(eui[:3], mac[:3])
		eui[3] = 0xff
		eui[4] = 0xfe
		copy(eui[5:], mac[3:])
	} else {
		panic("MustMACToIPv6LinkLocal: invalid MAC address: " + mac.String())
	}

	// Flip 7th bit, as required by LL algorithm.
	eui[0] = eui[0] ^ 0x02

	var addr [16]byte
	// LL prefix.
	addr[0] = 0xfe
	addr[1] = 0x80
	// Modified EUI in the second half.
	copy(addr[8:], eui[:])
	return addr[:]
}
