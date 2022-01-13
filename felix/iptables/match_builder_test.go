// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.
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

package iptables_test

import (
	. "github.com/projectcalico/calico/felix/iptables"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

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
	func(match MatchCriteria, expRendering string) {
		Expect(match.Render()).To(Equal(expRendering))
	},
	// Marks.
	Entry("MarkClear", Match().MarkClear(0x400a), "-m mark --mark 0/0x400a"),
	Entry("MarkClear", Match().MarkNotClear(0x400a), "-m mark ! --mark 0/0x400a"),
	Entry("MarkSingleBitSet", Match().MarkSingleBitSet(0x4000), "-m mark --mark 0x4000/0x4000"),
	Entry("MarkMatchesWithMask", Match().MarkMatchesWithMask(0x400a, 0xf00f), "-m mark --mark 0x400a/0xf00f"),
	Entry("NotMarkMatchesWithMask", Match().NotMarkMatchesWithMask(0x400a, 0xf00f), "-m mark ! --mark 0x400a/0xf00f"),
	// Conntrack.
	Entry("ConntrackState", Match().ConntrackState("INVALID"), "-m conntrack --ctstate INVALID"),
	// Interfaces.
	Entry("InInterface", Match().InInterface("tap1234abcd"), "--in-interface tap1234abcd"),
	Entry("OutInterface", Match().OutInterface("tap1234abcd"), "--out-interface tap1234abcd"),
	// Address types.
	Entry("SrcAddrType limit iface", Match().SrcAddrType(AddrTypeLocal, true), "-m addrtype --src-type LOCAL --limit-iface-out"),
	Entry("SrcAddrType no limit iface", Match().SrcAddrType(AddrTypeLocal, false), "-m addrtype --src-type LOCAL"),
	Entry("NotSrcAddrType limit iface", Match().NotSrcAddrType(AddrTypeLocal, true), "-m addrtype ! --src-type LOCAL --limit-iface-out"),
	Entry("NotSrcAddrType no limit iface", Match().NotSrcAddrType(AddrTypeLocal, false), "-m addrtype ! --src-type LOCAL"),
	Entry("DestAddrType no limit iface", Match().DestAddrType(AddrTypeLocal), "-m addrtype --dst-type LOCAL"),
	// Protocol.
	Entry("Protocol", Match().Protocol("tcp"), "-p tcp"),
	Entry("NotProtocol", Match().NotProtocol("tcp"), "! -p tcp"),
	Entry("ProtocolNum", Match().ProtocolNum(123), "-p 123"),
	Entry("NotProtocolNum", Match().NotProtocolNum(123), "! -p 123"),
	// CIDRs.
	Entry("SourceNet", Match().SourceNet("10.0.0.4"), "--source 10.0.0.4"),
	Entry("NotSourceNet", Match().NotSourceNet("10.0.0.4"), "! --source 10.0.0.4"),
	Entry("DestNet", Match().DestNet("10.0.0.4"), "--destination 10.0.0.4"),
	Entry("NotDestNet", Match().NotDestNet("10.0.0.4"), "! --destination 10.0.0.4"),
	// IP sets.
	Entry("SourceIPSet", Match().SourceIPSet("calits:12345abc-_"), "-m set --match-set calits:12345abc-_ src"),
	Entry("NotSourceIPSet", Match().NotSourceIPSet("calits:12345abc-_"), "-m set ! --match-set calits:12345abc-_ src"),
	Entry("DestIPSet", Match().DestIPSet("calits:12345abc-_"), "-m set --match-set calits:12345abc-_ dst"),
	Entry("NotDestIPSet", Match().NotDestIPSet("calits:12345abc-_"), "-m set ! --match-set calits:12345abc-_ dst"),
	// IP,Port IP sets.
	Entry("SourceIPPortSet", Match().SourceIPPortSet("calitn:12345abc-_"), "-m set --match-set calitn:12345abc-_ src,src"),
	Entry("NotSourceIPPortSet", Match().NotSourceIPPortSet("calitn:12345abc-_"), "-m set ! --match-set calitn:12345abc-_ src,src"),
	Entry("DestIPPortSet", Match().DestIPPortSet("calitn:12345abc-_"), "-m set --match-set calitn:12345abc-_ dst,dst"),
	Entry("NotDestIPPortSet", Match().NotDestIPPortSet("calitn:12345abc-_"), "-m set ! --match-set calitn:12345abc-_ dst,dst"),
	// Ports.
	Entry("SourcePorts", Match().SourcePorts(1234, 5678), "-m multiport --source-ports 1234,5678"),
	Entry("NotSourcePorts", Match().NotSourcePorts(1234, 5678), "-m multiport ! --source-ports 1234,5678"),
	Entry("DestPorts", Match().DestPorts(1234, 5678), "-m multiport --destination-ports 1234,5678"),
	Entry("NotDestPorts", Match().NotDestPorts(1234, 5678), "-m multiport ! --destination-ports 1234,5678"),
	Entry("SourcePortRanges", Match().SourcePortRanges(portRanges), "-m multiport --source-ports 1234,5678:6000"),
	Entry("NotSourcePortRanges", Match().NotSourcePortRanges(portRanges), "-m multiport ! --source-ports 1234,5678:6000"),
	Entry("DestPortRanges", Match().DestPortRanges(portRanges), "-m multiport --destination-ports 1234,5678:6000"),
	Entry("NotDestPortRanges", Match().NotDestPortRanges(portRanges), "-m multiport ! --destination-ports 1234,5678:6000"),
	// ICMP.
	Entry("ICMPType", Match().ICMPType(123), "-m icmp --icmp-type 123"),
	Entry("NotICMPType", Match().NotICMPType(123), "-m icmp ! --icmp-type 123"),
	Entry("ICMPTypeAndCode", Match().ICMPTypeAndCode(123, 5), "-m icmp --icmp-type 123/5"),
	Entry("NotICMPTypeAndCode", Match().NotICMPTypeAndCode(123, 5), "-m icmp ! --icmp-type 123/5"),
	Entry("ICMPV6Type", Match().ICMPV6Type(123), "-m icmp6 --icmpv6-type 123"),
	Entry("NotICMPV6Type", Match().NotICMPV6Type(123), "-m icmp6 ! --icmpv6-type 123"),
	Entry("ICMPV6TypeAndCode", Match().ICMPV6TypeAndCode(123, 5), "-m icmp6 --icmpv6-type 123/5"),
	Entry("NotICMPV6TypeAndCode", Match().NotICMPV6TypeAndCode(123, 5), "-m icmp6 ! --icmpv6-type 123/5"),
	// Check multiple match criteria are joined correctly.
	Entry("Protocol and ports", Match().Protocol("tcp").SourcePorts(1234).DestPorts(8080),
		"-p tcp -m multiport --source-ports 1234 -m multiport --destination-ports 8080"),
	// IPVS.
	Entry("IPVSConnection", Match().IPVSConnection(), "-m ipvs --ipvs"),
	Entry("NotIPVSConnection", Match().NotIPVSConnection(), "-m ipvs ! --ipvs"),
)
