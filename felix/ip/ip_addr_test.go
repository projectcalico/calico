// Copyright (c) 2017-2018,2020 Tigera, Inc. All rights reserved.
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

package ip_test

import (
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"

	. "github.com/projectcalico/calico/felix/ip"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("IpAddr",
	func(version int, inputIP, canonical string, bytes []byte) {
		ip := FromString(inputIP)
		Expect([]byte(ip.AsNetIP())).To(Equal(bytes))
		Expect(ip.String()).To(Equal(canonical))
		Expect(int(ip.Version())).To(Equal(version))
		Expect(MustParseCIDROrIP(inputIP).Addr().String()).To(Equal(canonical))

		caliIP := calinet.ParseIP(inputIP)
		Expect([]byte(FromCalicoIP(*caliIP).AsNetIP())).To(Equal(bytes))
	},
	Entry("IPv4", 4, "10.0.0.1", "10.0.0.1", []byte{0xa, 0, 0, 1}),
	Entry("IPv6", 6, "dead::beef", "dead::beef", []byte{
		0xde, 0xad, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0xbe, 0xef},
	),
	Entry("IPv6 non-canon", 6, "dead:0:0::beef", "dead::beef", []byte{
		0xde, 0xad, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0xbe, 0xef},
	),
)

var _ = DescribeTable("CIDR",
	func(version int, inputCIDR, canonical string, bytes []byte, len int) {
		cidr := MustParseCIDROrIP(inputCIDR)
		Expect([]byte(cidr.Addr().AsNetIP())).To(Equal(bytes))
		Expect(int(cidr.Prefix())).To(Equal(len))
		Expect(cidr.String()).To(Equal(canonical))
		Expect(int(cidr.Version())).To(Equal(version))
	},
	Entry("IPv4", 4, "10.0.0.0/16", "10.0.0.0/16", []byte{0xa, 0, 0, 0}, 16),
	Entry("IPv4 should be masked", 4, "10.0.0.1/16", "10.0.0.0/16", []byte{0xa, 0, 0, 0}, 16),
	Entry("IPv6", 6, "dead::/16", "dead::/16", []byte{
		0xde, 0xad, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0},
		16,
	),
	Entry("IPv6 non-canon", 6, "dead:0:0::beef/16", "dead::/16", []byte{
		0xde, 0xad, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 00},
		16,
	),
)

var _ = DescribeTable("NthBit",
	func(inputAddr string, n uint, expected int) {
		addr := FromString(inputAddr)
		Expect(addr.NthBit(n)).To(Equal(expected))
	},
	Entry("IPv4 32nd bit", "10.10.10.1", uint(32), 1),
	Entry("IPv4 31st bit", "10.10.10.1", uint(31), 0),
	Entry("IPv4 32nd bit 2", "192.168.0.2", uint(32), 0),
	Entry("IPv4 31st bit 2", "192.168.0.2", uint(31), 1),
	Entry("IPv4 1st bit", "192.168.0.2", uint(1), 1),
	Entry("IPv6 128th bit", "fc00:fe11::1", uint(128), 1),
	Entry("IPv6 127th bit", "fc00:fe11::1", uint(127), 0),
	Entry("IPv6 128th bit 2", "fc00:fe11::2", uint(128), 0),
	Entry("IPv6 127th bit 2", "fc00:fe11::2", uint(127), 1),
	Entry("IPv6 1st bit", "fc00:fe11::2", uint(1), 1),
)

var _ = DescribeTable("Contains",
	func(inputCIDR string, inputAddr string, expected bool) {
		cidr := MustParseCIDROrIP(inputCIDR)
		addr := FromString(inputAddr)
		Expect(cidr.Contains(addr)).To(Equal(expected))
	},
	Entry("IPv4 /32 true", "10.10.10.1/32", "10.10.10.1", true),
	Entry("IPv4 /32 false", "10.10.10.1/32", "10.10.10.2", false),
	Entry("IPv4 /24 true", "10.10.10.0/24", "10.10.10.3", true),
	Entry("IPv4 /24 false", "10.10.10.0/24", "10.10.11.3", false),
	Entry("IPv6 /128 true", "fc00:fe11::1/128", "fc00:fe11::1", true),
	Entry("IPv6 /128 false", "fc00:fe11::1/128", "fc00:fe11::2", false),
	Entry("IPv6 /112 true", "fc00:fe11::/112", "fc00:fe11::3", true),
	Entry("IPv6 /112 false", "fc00:fe11::/112", "fc00:fe12::3", false),
)
