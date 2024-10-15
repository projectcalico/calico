// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package nftables_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/nftables"
	. "github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/proto"
)

var portRanges = []*proto.PortRange{
	{First: 1234, Last: 1234},
	{First: 5678, Last: 6000},
}

var _ = Describe("MatchBuilder failure cases", func() {
	It("should panic if MarkSingleBitSet is passed more than one bit", func() {
		Expect(func() {
			Match().MarkSingleBitSet(0x4001)
		}).To(Panic())
	})
	It("should panic if MarkMatchesWithMask is passed an invalid mark", func() {
		Expect(func() {
			Match().MarkMatchesWithMask(0xf, 0x1)
		}).To(Panic())
	})
	It("should panic if MarkMatchesWithMask is passed a 0 mask", func() {
		Expect(func() {
			Match().MarkMatchesWithMask(0x0, 0x0)
		}).To(Panic())
	})
})

var _ = DescribeTable("MatchBuilder",
	func(match generictables.MatchCriteria, expRendering string) {
		Expect(match.Render()).To(Equal(expRendering))
	},

	// Marks.
	Entry("MarkClear", Match().MarkClear(0x400a), "meta mark & 0x400a == 0"),
	Entry("MarkClear", Match().MarkNotClear(0x400a), "meta mark & 0x400a != 0"),
	Entry("MarkSingleBitSet", Match().MarkSingleBitSet(0x4000), "meta mark & 0x4000 == 0x4000"),
	Entry("MarkMatchesWithMask", Match().MarkMatchesWithMask(0x400a, 0xf00f), "meta mark & 0xf00f == 0x400a"),
	Entry("NotMarkMatchesWithMask", Match().NotMarkMatchesWithMask(0x400a, 0xf00f), "meta mark & 0xf00f != 0x400a"),

	// Conntrack.
	Entry("ConntrackState", Match().ConntrackState("INVALID"), "ct state invalid"),

	// Interfaces.
	Entry("InInterface", Match().InInterface("tap1234abcd"), "iifname tap1234abcd"),
	Entry("OutInterface", Match().OutInterface("tap1234abcd"), "oifname tap1234abcd"),

	// Address types.
	Entry("SrcAddrType limit iface", Match().SrcAddrType(generictables.AddrTypeLocal, true), "fib saddr . oif type local"),
	Entry("SrcAddrType no limit iface", Match().SrcAddrType(generictables.AddrTypeLocal, false), "fib saddr type local"),
	Entry("NotSrcAddrType limit iface", Match().NotSrcAddrType(generictables.AddrTypeLocal, true), "fib saddr . oif type != local"),
	Entry("NotSrcAddrType no limit iface", Match().NotSrcAddrType(generictables.AddrTypeLocal, false), "fib saddr type != local"),
	Entry("DestAddrType no limit iface", Match().DestAddrType(generictables.AddrTypeLocal), "fib daddr type local"),

	// Protocol.
	Entry("Protocol", Match().Protocol("tcp"), "meta l4proto tcp"),
	Entry("NotProtocol", Match().NotProtocol("tcp"), "meta l4proto != tcp"),
	Entry("ProtocolNum", Match().ProtocolNum(123), "meta l4proto 123"),
	Entry("NotProtocolNum", Match().NotProtocolNum(123), "meta l4proto != 123"),
	Entry("ProtocolNum IPIP", Match().ProtocolNum(4), "meta l4proto 4"),

	// CIDRs.
	Entry("SourceNet", Match().SourceNet("10.0.0.4"), "ip saddr 10.0.0.4"),
	Entry("NotSourceNet", Match().NotSourceNet("10.0.0.4"), "ip saddr != 10.0.0.4"),
	Entry("DestNet", Match().DestNet("10.0.0.4"), "ip daddr 10.0.0.4"),
	Entry("NotDestNet", Match().NotDestNet("10.0.0.4"), "ip daddr != 10.0.0.4"),

	// IP sets.
	Entry("SourceIPSet", Match().SourceIPSet("calits:12345abc-_"), "ip saddr @calits-12345abc-_"),
	Entry("NotSourceIPSet", Match().NotSourceIPSet("calits:12345abc-_"), "ip saddr != @calits-12345abc-_"),
	Entry("DestIPSet", Match().DestIPSet("calits:12345abc-_"), "ip daddr @calits-12345abc-_"),
	Entry("NotDestIPSet", Match().NotDestIPSet("calits:12345abc-_"), "ip daddr != @calits-12345abc-_"),

	// IP,Port IP sets.
	Entry("SourceIPPortSet", Match().SourceIPPortSet("calitn:12345abc-_"), "ip saddr . meta l4proto . th sport @calitn-12345abc-_"),
	Entry("NotSourceIPPortSet", Match().NotSourceIPPortSet("calitn:12345abc-_"), "ip saddr . meta l4proto . th sport != @calitn-12345abc-_"),
	Entry("DestIPPortSet", Match().DestIPPortSet("calitn:12345abc-_"), "ip daddr . meta l4proto . th dport @calitn-12345abc-_"),
	Entry("NotDestIPPortSet", Match().NotDestIPPortSet("calitn:12345abc-_"), "ip daddr . meta l4proto . th dport != @calitn-12345abc-_"),

	// Ports.
	Entry("SourcePorts", Match().Protocol("tcp").SourcePorts(1234, 5678), "meta l4proto tcp tcp sport { 1234, 5678 }"),
	Entry("NotSourcePorts", Match().Protocol("udp").NotSourcePorts(1234, 5678), "meta l4proto udp udp sport != { 1234, 5678 }"),
	Entry("DestPorts", Match().Protocol("tcp").DestPorts(1234, 5678), "meta l4proto tcp tcp dport { 1234, 5678 }"),
	Entry("NotDestPorts", Match().Protocol("udp").NotDestPorts(1234, 5678), "meta l4proto udp udp dport != { 1234, 5678 }"),
	Entry("SourcePortRanges", Match().Protocol("udp").SourcePortRanges(portRanges), "meta l4proto udp udp sport { 1234, 5678-6000 }"),
	Entry("NotSourcePortRanges", Match().Protocol("udp").NotSourcePortRanges(portRanges), "meta l4proto udp udp sport != { 1234, 5678-6000 }"),
	Entry("DestPortRanges", Match().Protocol("udp").DestPortRanges(portRanges), "meta l4proto udp udp dport { 1234, 5678-6000 }"),
	Entry("NotDestPortRanges", Match().Protocol("udp").NotDestPortRanges(portRanges), "meta l4proto udp udp dport != { 1234, 5678-6000 }"),

	// Ports using protocol number.
	Entry("ProtocolNum.SourcePorts", Match().ProtocolNum(nftables.ProtoTCP).SourcePorts(1234, 5678), "meta l4proto 6 tcp sport { 1234, 5678 }"),
	Entry("ProtocolNum.NotSourcePorts", Match().ProtocolNum(nftables.ProtoUDP).NotSourcePorts(1234, 5678), "meta l4proto 17 udp sport != { 1234, 5678 }"),
	Entry("ProtocolNum.DestPorts", Match().ProtocolNum(nftables.ProtoTCP).DestPorts(1234, 5678), "meta l4proto 6 tcp dport { 1234, 5678 }"),
	Entry("ProtocolNum.NotDestPorts", Match().ProtocolNum(nftables.ProtoUDP).NotDestPorts(1234, 5678), "meta l4proto 17 udp dport != { 1234, 5678 }"),
	Entry("ProtocolNum.SourcePortRanges", Match().ProtocolNum(nftables.ProtoUDP).SourcePortRanges(portRanges), "meta l4proto 17 udp sport { 1234, 5678-6000 }"),
	Entry("ProtocolNum.NotSourcePortRanges", Match().ProtocolNum(nftables.ProtoUDP).NotSourcePortRanges(portRanges), "meta l4proto 17 udp sport != { 1234, 5678-6000 }"),
	Entry("ProtocolNum.DestPortRanges", Match().ProtocolNum(nftables.ProtoUDP).DestPortRanges(portRanges), "meta l4proto 17 udp dport { 1234, 5678-6000 }"),
	Entry("ProtocolNum.NotDestPortRanges", Match().ProtocolNum(nftables.ProtoUDP).NotDestPortRanges(portRanges), "meta l4proto 17 udp dport != { 1234, 5678-6000 }"),

	// ICMP.
	Entry("ICMPType", Match().ICMPType(123), "icmp type 123"),
	Entry("NotICMPType", Match().NotICMPType(123), "icmp type != 123"),
	Entry("ICMPTypeAndCode", Match().ICMPTypeAndCode(123, 5), "icmp type 123 code 5"),
	Entry("NotICMPTypeAndCode", Match().NotICMPTypeAndCode(123, 5), "icmp type != 123 code != 5"),
	Entry("ICMPV6Type", Match().ICMPV6Type(123), "icmpv6 type 123"),
	Entry("NotICMPV6Type", Match().NotICMPV6Type(123), "icmpv6 type != 123"),
	Entry("ICMPV6TypeAndCode", Match().ICMPV6TypeAndCode(123, 5), "icmpv6 type 123 code 5"),
	Entry("NotICMPV6TypeAndCode", Match().NotICMPV6TypeAndCode(123, 5), "icmpv6 type != 123 code != 5"),

	// Check multiple match criteria are joined correctly.
	Entry("Protocol and ports", Match().Protocol("tcp").SourcePorts(1234).DestPorts(8080), "meta l4proto tcp tcp sport { 1234 } tcp dport { 8080 }"),
)

var _ = DescribeTable("IPSetNames",
	func(match generictables.MatchCriteria, exp []string) {
		Expect(match.IPSetNames()).To(ConsistOf(exp))
	},

	// Valid IP set matches.
	Entry("SourceIPSet", Match().SourceIPSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("NotSourceIPSet", Match().NotSourceIPSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("DestIPSet", Match().DestIPSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("NotDestIPSet", Match().NotDestIPSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),

	// Valid IPPort set matches.
	Entry("SourceIPPortSet", Match().SourceIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("NotSourceIPPortSet", Match().NotSourceIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("DestIPPortSet", Match().DestIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("NotDestIPPortSet", Match().NotDestIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),

	// No IP set matches.
	Entry("empty match", Match(), nil),
	Entry("ICMPType", Match().ICMPType(123), nil),
	Entry("SourceNet", Match().SourceNet("10.0.0.0/24"), nil),

	// Multiple IP set matches.
	Entry("Multiple matches", Match().SourceIPSet("calits:12345abc-_").DestIPSet("calits:54321cba-_"), []string{"calits-12345abc-_", "calits-54321cba-_"}),
	Entry("Duplicate matches", Match().SourceIPPortSet("calits:12345abc-_").DestIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
)
