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

package nftrender_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/nftables/nftrender"
	"github.com/projectcalico/calico/felix/proto"
)

var portRanges = []*proto.PortRange{
	{First: 1234, Last: 1234},
	{First: 5678, Last: 6000},
}

var _ = Describe("MatchBuilder failure cases", func() {
	It("should panic if MarkSingleBitSet is passed more than one bit", func() {
		Expect(func() {
			nftrender.Match().MarkSingleBitSet(0x4001)
		}).To(Panic())
	})
	It("should panic if MarkMatchesWithMask is passed an invalid mark", func() {
		Expect(func() {
			nftrender.Match().MarkMatchesWithMask(0xf, 0x1)
		}).To(Panic())
	})
	It("should panic if MarkMatchesWithMask is passed a 0 mask", func() {
		Expect(func() {
			nftrender.Match().MarkMatchesWithMask(0x0, 0x0)
		}).To(Panic())
	})
})

var _ = DescribeTable("MatchBuilder",
	func(match generictables.MatchCriteria, expRendering string) {
		Expect(match.Render()).To(Equal(expRendering))
	},

	// Marks.
	Entry("MarkClear", nftrender.Match().MarkClear(0x400a), "meta mark & 0x400a == 0"),
	Entry("MarkClear", nftrender.Match().MarkNotClear(0x400a), "meta mark & 0x400a != 0"),
	Entry("MarkSingleBitSet", nftrender.Match().MarkSingleBitSet(0x4000), "meta mark & 0x4000 == 0x4000"),
	Entry("MarkMatchesWithMask", nftrender.Match().MarkMatchesWithMask(0x400a, 0xf00f), "meta mark & 0xf00f == 0x400a"),
	Entry("NotMarkMatchesWithMask", nftrender.Match().NotMarkMatchesWithMask(0x400a, 0xf00f), "meta mark & 0xf00f != 0x400a"),

	// Conntrack.
	Entry("ConntrackState", nftrender.Match().ConntrackState("INVALID"), "ct state invalid"),

	// Interfaces.
	Entry("InInterface", nftrender.Match().InInterface("tap1234abcd"), "iifname tap1234abcd"),
	Entry("OutInterface", nftrender.Match().OutInterface("tap1234abcd"), "oifname tap1234abcd"),

	// Address types.
	Entry("SrcAddrType limit iface", nftrender.Match().SrcAddrType(generictables.AddrTypeLocal, true), "fib saddr . oif type local"),
	Entry("SrcAddrType no limit iface", nftrender.Match().SrcAddrType(generictables.AddrTypeLocal, false), "fib saddr type local"),
	Entry("NotSrcAddrType limit iface", nftrender.Match().NotSrcAddrType(generictables.AddrTypeLocal, true), "fib saddr . oif type != local"),
	Entry("NotSrcAddrType no limit iface", nftrender.Match().NotSrcAddrType(generictables.AddrTypeLocal, false), "fib saddr type != local"),
	Entry("DestAddrType no limit iface", nftrender.Match().DestAddrType(generictables.AddrTypeLocal), "fib daddr type local"),

	// Protocol.
	Entry("Protocol", nftrender.Match().Protocol("tcp"), "meta l4proto tcp"),
	Entry("NotProtocol", nftrender.Match().NotProtocol("tcp"), "meta l4proto != tcp"),
	Entry("ProtocolNum", nftrender.Match().ProtocolNum(123), "meta l4proto 123"),
	Entry("NotProtocolNum", nftrender.Match().NotProtocolNum(123), "meta l4proto != 123"),
	Entry("ProtocolNum IPIP", nftrender.Match().ProtocolNum(4), "meta l4proto 4"),

	// CIDRs.
	Entry("SourceNet", nftrender.Match().SourceNet("10.0.0.4"), "ip saddr 10.0.0.4"),
	Entry("NotSourceNet", nftrender.Match().NotSourceNet("10.0.0.4"), "ip saddr != 10.0.0.4"),
	Entry("DestNet", nftrender.Match().DestNet("10.0.0.4"), "ip daddr 10.0.0.4"),
	Entry("NotDestNet", nftrender.Match().NotDestNet("10.0.0.4"), "ip daddr != 10.0.0.4"),

	// IP sets.
	Entry("SourceIPSet", nftrender.Match().SourceIPSet("calits:12345abc-_"), "ip saddr @calits-12345abc-_"),
	Entry("NotSourceIPSet", nftrender.Match().NotSourceIPSet("calits:12345abc-_"), "ip saddr != @calits-12345abc-_"),
	Entry("DestIPSet", nftrender.Match().DestIPSet("calits:12345abc-_"), "ip daddr @calits-12345abc-_"),
	Entry("NotDestIPSet", nftrender.Match().NotDestIPSet("calits:12345abc-_"), "ip daddr != @calits-12345abc-_"),

	// IP,Port IP sets.
	Entry("SourceIPPortSet", nftrender.Match().SourceIPPortSet("calitn:12345abc-_"), "ip saddr . meta l4proto . th sport @calitn-12345abc-_"),
	Entry("NotSourceIPPortSet", nftrender.Match().NotSourceIPPortSet("calitn:12345abc-_"), "ip saddr . meta l4proto . th sport != @calitn-12345abc-_"),
	Entry("DestIPPortSet", nftrender.Match().DestIPPortSet("calitn:12345abc-_"), "ip daddr . meta l4proto . th dport @calitn-12345abc-_"),
	Entry("NotDestIPPortSet", nftrender.Match().NotDestIPPortSet("calitn:12345abc-_"), "ip daddr . meta l4proto . th dport != @calitn-12345abc-_"),

	// Ports.
	Entry("SourcePorts", nftrender.Match().Protocol("tcp").SourcePorts(1234, 5678), "meta l4proto tcp tcp sport { 1234, 5678 }"),
	Entry("NotSourcePorts", nftrender.Match().Protocol("udp").NotSourcePorts(1234, 5678), "meta l4proto udp udp sport != { 1234, 5678 }"),
	Entry("DestPorts", nftrender.Match().Protocol("tcp").DestPorts(1234, 5678), "meta l4proto tcp tcp dport { 1234, 5678 }"),
	Entry("NotDestPorts", nftrender.Match().Protocol("udp").NotDestPorts(1234, 5678), "meta l4proto udp udp dport != { 1234, 5678 }"),
	Entry("SourcePortRanges", nftrender.Match().Protocol("udp").SourcePortRanges(portRanges), "meta l4proto udp udp sport { 1234, 5678-6000 }"),
	Entry("NotSourcePortRanges", nftrender.Match().Protocol("udp").NotSourcePortRanges(portRanges), "meta l4proto udp udp sport != { 1234, 5678-6000 }"),
	Entry("DestPortRanges", nftrender.Match().Protocol("udp").DestPortRanges(portRanges), "meta l4proto udp udp dport { 1234, 5678-6000 }"),
	Entry("NotDestPortRanges", nftrender.Match().Protocol("udp").NotDestPortRanges(portRanges), "meta l4proto udp udp dport != { 1234, 5678-6000 }"),

	// Ports using protocol number.
	Entry("ProtocolNum.SourcePorts", nftrender.Match().ProtocolNum(nftrender.ProtoTCP).SourcePorts(1234, 5678), "meta l4proto 6 tcp sport { 1234, 5678 }"),
	Entry("ProtocolNum.NotSourcePorts", nftrender.Match().ProtocolNum(nftrender.ProtoUDP).NotSourcePorts(1234, 5678), "meta l4proto 17 udp sport != { 1234, 5678 }"),
	Entry("ProtocolNum.DestPorts", nftrender.Match().ProtocolNum(nftrender.ProtoTCP).DestPorts(1234, 5678), "meta l4proto 6 tcp dport { 1234, 5678 }"),
	Entry("ProtocolNum.NotDestPorts", nftrender.Match().ProtocolNum(nftrender.ProtoUDP).NotDestPorts(1234, 5678), "meta l4proto 17 udp dport != { 1234, 5678 }"),
	Entry("ProtocolNum.SourcePortRanges", nftrender.Match().ProtocolNum(nftrender.ProtoUDP).SourcePortRanges(portRanges), "meta l4proto 17 udp sport { 1234, 5678-6000 }"),
	Entry("ProtocolNum.NotSourcePortRanges", nftrender.Match().ProtocolNum(nftrender.ProtoUDP).NotSourcePortRanges(portRanges), "meta l4proto 17 udp sport != { 1234, 5678-6000 }"),
	Entry("ProtocolNum.DestPortRanges", nftrender.Match().ProtocolNum(nftrender.ProtoUDP).DestPortRanges(portRanges), "meta l4proto 17 udp dport { 1234, 5678-6000 }"),
	Entry("ProtocolNum.NotDestPortRanges", nftrender.Match().ProtocolNum(nftrender.ProtoUDP).NotDestPortRanges(portRanges), "meta l4proto 17 udp dport != { 1234, 5678-6000 }"),

	// ICMP.
	Entry("ICMPType", nftrender.Match().ICMPType(123), "icmp type 123"),
	Entry("NotICMPType", nftrender.Match().NotICMPType(123), "icmp type != 123"),
	Entry("ICMPTypeAndCode", nftrender.Match().ICMPTypeAndCode(123, 5), "icmp type 123 code 5"),
	Entry("NotICMPTypeAndCode", nftrender.Match().NotICMPTypeAndCode(123, 5), "icmp type != 123 code != 5"),
	Entry("ICMPV6Type", nftrender.Match().ICMPV6Type(123), "icmpv6 type 123"),
	Entry("NotICMPV6Type", nftrender.Match().NotICMPV6Type(123), "icmpv6 type != 123"),
	Entry("ICMPV6TypeAndCode", nftrender.Match().ICMPV6TypeAndCode(123, 5), "icmpv6 type 123 code 5"),
	Entry("NotICMPV6TypeAndCode", nftrender.Match().NotICMPV6TypeAndCode(123, 5), "icmpv6 type != 123 code != 5"),

	// Limits.
	Entry("Limit with rate", nftrender.Match().Limit("10/minute", 0), "limit rate 10/minute"),
	Entry("Limit with rate and burst", nftrender.Match().Limit("20/hour", 10), "limit rate 20/hour burst 10 packets"),

	// VMAPs
	Entry("InInterfaceVMAP", nftrender.Match().InInterfaceVMAP("vmap1234").(nftrender.NFTMatchCriteria).SetLayer("filter"), "iifname vmap @filter-vmap1234"),
	Entry("OutInterfaceVMAP", nftrender.Match().OutInterfaceVMAP("vmap1234").(nftrender.NFTMatchCriteria).SetLayer("raw"), "oifname vmap @raw-vmap1234"),

	// ARP family matches.
	Entry("ARPOperation", nftrender.Match().ARPOperation("reply"), "arp operation reply"),
	Entry("ARPSrcIP", nftrender.Match().ARPSrcIP("10.0.0.1"), "arp saddr ip 10.0.0.1"),
	Entry("ARP combined", nftrender.Match().OutInterface("cali1234").ARPOperation("reply").ARPSrcIP("10.0.0.1"), "oifname cali1234 arp operation reply arp saddr ip 10.0.0.1"),

	// Check multiple match criteria are joined correctly.
	Entry("Protocol and ports", nftrender.Match().Protocol("tcp").SourcePorts(1234).DestPorts(8080), "meta l4proto tcp tcp sport { 1234 } tcp dport { 8080 }"),
)

var _ = DescribeTable("IPSetNames",
	func(match generictables.MatchCriteria, exp []string) {
		Expect(match.IPSetNames()).To(ConsistOf(exp))
	},

	// Valid IP set matches.
	Entry("SourceIPSet", nftrender.Match().SourceIPSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("NotSourceIPSet", nftrender.Match().NotSourceIPSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("DestIPSet", nftrender.Match().DestIPSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("NotDestIPSet", nftrender.Match().NotDestIPSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),

	// Valid IPPort set matches.
	Entry("SourceIPPortSet", nftrender.Match().SourceIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("NotSourceIPPortSet", nftrender.Match().NotSourceIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("DestIPPortSet", nftrender.Match().DestIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
	Entry("NotDestIPPortSet", nftrender.Match().NotDestIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),

	// No IP set matches.
	Entry("empty match", nftrender.Match(), nil),
	Entry("ICMPType", nftrender.Match().ICMPType(123), nil),
	Entry("SourceNet", nftrender.Match().SourceNet("10.0.0.0/24"), nil),

	// Multiple IP set matches.
	Entry("Multiple matches", nftrender.Match().SourceIPSet("calits:12345abc-_").DestIPSet("calits:54321cba-_"), []string{"calits-12345abc-_", "calits-54321cba-_"}),
	Entry("Duplicate matches", nftrender.Match().SourceIPPortSet("calits:12345abc-_").DestIPPortSet("calits:12345abc-_"), []string{"calits-12345abc-_"}),
)
