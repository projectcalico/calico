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
	"fmt"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/ip"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = DescribeTable("IpAddr",
	func(version int, inputIP, canonical string, bytes []byte, binvalue string) {
		ip := FromString(inputIP)
		Expect([]byte(ip.AsNetIP())).To(Equal(bytes))
		Expect(ip.String()).To(Equal(canonical))
		Expect(int(ip.Version())).To(Equal(version))
		Expect(MustParseCIDROrIP(inputIP).Addr().String()).To(Equal(canonical))
		Expect(ip.AsBinary()).To(Equal(binvalue))

		caliIP := calinet.ParseIP(inputIP)
		Expect([]byte(FromCalicoIP(*caliIP).AsNetIP())).To(Equal(bytes))
	},
	Entry("IPv4", 4, "10.0.0.1", "10.0.0.1", []byte{0xa, 0, 0, 1}, "010000001010000000000000000000000001"),
	Entry("IPv6", 6, "dead::beef", "dead::beef", []byte{
		0xde, 0xad, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0xbe, 0xef},
		"011011011110101011010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001011111011101111",
	),
	Entry("IPv6 non-canon", 6, "deaf:0:0::beef", "deaf::beef", []byte{
		0xde, 0xaf, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0xbe, 0xef},
		"011011011110101011110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001011111011101111",
	),
)

var _ = DescribeTable("Addr addition",
	func(addrStr string, n int, expected string) {
		addr := FromString(addrStr)
		out := addr.Add(n)
		exp := FromString(expected)
		Expect(out).To(Equal(exp), fmt.Sprintf("%s + %v should equal %s", addrStr, n, expected))
		sub := out.Add(-n)
		Expect(sub).To(Equal(addr), fmt.Sprintf("%s - %v should equal %s", expected, n, addrStr))
	},
	Entry("IPv4 + 0", "10.0.0.1", 0, "10.0.0.1"),
	Entry("IPv4 + 1", "10.0.0.1", 1, "10.0.0.2"),
	Entry("IPv4 + 256", "10.0.0.1", 256, "10.0.1.1"),
	Entry("IPv4 + 255", "10.0.0.1", 255, "10.0.1.0"),
	Entry("IPv6 + 0", "::1", 0, "::1"),
	Entry("IPv6 + 1", "::1", 1, "::2"),
	Entry("IPv6 + 255", "::1", 255, "::100"),
	Entry("IPv6 ::1:ffff:ffff:ffff + 1", "::1:ffff:ffff:ffff", 1, "::2:0:0:0"),
)

var _ = DescribeTable("CIDR",
	func(version int, inputCIDR, canonical string, bytes []byte, len int, binvalue string) {
		cidr := MustParseCIDROrIP(inputCIDR)
		Expect([]byte(cidr.Addr().AsNetIP())).To(Equal(bytes))
		Expect(int(cidr.Prefix())).To(Equal(len))
		Expect(cidr.String()).To(Equal(canonical))
		Expect(int(cidr.Version())).To(Equal(version))
		Expect(cidr.AsBinary()).To(Equal(binvalue))
	},
	Entry("IPv4", 4, "10.0.0.0/16", "10.0.0.0/16", []byte{0xa, 0, 0, 0}, 16, "01000000101000000000"),
	Entry("IPv4 should be masked", 4, "10.0.0.1/16", "10.0.0.0/16", []byte{0xa, 0, 0, 0}, 16, "01000000101000000000"),
	Entry("IPv6", 6, "dead::/16", "dead::/16", []byte{
		0xde, 0xad, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0},
		16,
		"01101101111010101101",
	),
	Entry("IPv6 non-canon", 6, "dead:0:0::beef/16", "dead::/16", []byte{
		0xde, 0xad, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 00},
		16,
		"01101101111010101101",
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

var _ = DescribeTable("IsSingleAddress",
	func(inputAddr string, expected bool) {
		cidr := MustParseCIDROrIP(inputAddr)
		Expect(cidr.IsSingleAddress()).To(Equal(expected))
	},
	Entry("0.0.0.0/0", "0.0.0.0/0", false),
	Entry("0.0.0.0", "0.0.0.0", true),
	Entry("10.0.0.0/8", "10.0.0.0/8", false),
	Entry("10.1.2.3/32", "10.1.2.3/32", true),
	Entry("10.1.2.0/31", "10.1.2.0/31", false),

	Entry("::/0", "::/0", false),
	Entry("::", "::", true),
	Entry("dead::/16", "dead::/16", false),
	Entry("dead::beef/128", "dead::beef/128", true),
	Entry("dead::beef/127", "dead::beef/127", false),
)
