// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package rules_test

import (
	. "github.com/projectcalico/felix/rules"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
)

var ruleTestData = []TableEntry{
	Entry("Empty rule", 4, proto.Rule{}, ""),

	// Non-negated matches...

	Entry("Protocol name", 4,
		proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{"tcp"}}},
		"-p tcp"),
	Entry("Protocol num", 4,
		proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{8}}},
		"-p 8"),

	Entry("Source net", 4,
		proto.Rule{SrcNet: []string{"10.0.0.0/16"}},
		"--source 10.0.0.0/16"),
	Entry("Source IP set", 4,
		proto.Rule{SrcIpSetIds: []string{"ipsetid1"}},
		"-m set --match-set cali4-ipsetid1 src"),
	Entry("Source IP sets", 4,
		proto.Rule{SrcIpSetIds: []string{"ipsetid1", "ipsetid2"}},
		"-m set --match-set cali4-ipsetid1 src -m set --match-set cali4-ipsetid2 src"),
	Entry("Source ports", 4,
		proto.Rule{SrcPorts: []*proto.PortRange{{First: 10, Last: 12}}},
		"-m multiport --source-ports 10:12"),
	Entry("Source ports (multiple)", 4,
		proto.Rule{SrcPorts: []*proto.PortRange{
			{First: 10, Last: 12},
			{First: 20, Last: 30},
			{First: 8080, Last: 8080},
		}},
		"-m multiport --source-ports 10:12,20:30,8080"),
	Entry("ICMP", 4,
		proto.Rule{Icmp: &proto.Rule_IcmpType{IcmpType: 10}},
		"-m icmp --icmp-type 10"),
	Entry("ICMP with code", 4,
		proto.Rule{Icmp: &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}},
		"-m icmp --icmp-type 10/12"),
	Entry("ICMP", 6,
		proto.Rule{Icmp: &proto.Rule_IcmpType{IcmpType: 10}},
		"-m icmp6 --icmpv6-type 10"),
	Entry("ICMP with code", 6,
		proto.Rule{Icmp: &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}},
		"-m icmp6 --icmpv6-type 10/12"),

	Entry("Dest net", 4,
		proto.Rule{DstNet: []string{"10.0.0.0/16"}},
		"--destination 10.0.0.0/16"),
	Entry("Dest IP set", 4,
		proto.Rule{DstIpSetIds: []string{"ipsetid1"}},
		"-m set --match-set cali4-ipsetid1 dst"),
	Entry("Dest IP sets", 4,
		proto.Rule{DstIpSetIds: []string{"ipsetid1", "ipsetid2"}},
		"-m set --match-set cali4-ipsetid1 dst -m set --match-set cali4-ipsetid2 dst"),
	Entry("Dest ports", 4,
		proto.Rule{DstPorts: []*proto.PortRange{{First: 10, Last: 12}}},
		"-m multiport --destination-ports 10:12"),
	Entry("Dest ports (multiple)", 4,
		proto.Rule{DstPorts: []*proto.PortRange{
			{First: 10, Last: 12},
			{First: 20, Last: 30},
			{First: 8080, Last: 8080},
		}},
		"-m multiport --destination-ports 10:12,20:30,8080"),

	// Negated matches...

	Entry("Protocol name", 4,
		proto.Rule{NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{"tcp"}}},
		"! -p tcp"),
	Entry("Protocol num", 4,
		proto.Rule{NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{8}}},
		"! -p 8"),

	Entry("Source net", 4,
		proto.Rule{NotSrcNet: []string{"10.0.0.0/16"}},
		"! --source 10.0.0.0/16"),
	Entry("Source IP set", 4,
		proto.Rule{NotSrcIpSetIds: []string{"ipsetid1"}},
		"-m set ! --match-set cali4-ipsetid1 src"),
	Entry("Source IP set v6", 6,
		proto.Rule{NotSrcIpSetIds: []string{"ipsetid1"}},
		"-m set ! --match-set cali6-ipsetid1 src"),
	Entry("Source IP sets", 4,
		proto.Rule{NotSrcIpSetIds: []string{"ipsetid1", "ipsetid2"}},
		"-m set ! --match-set cali4-ipsetid1 src -m set ! --match-set cali4-ipsetid2 src"),
	Entry("Source ports", 4,
		proto.Rule{NotSrcPorts: []*proto.PortRange{{First: 10, Last: 12}}},
		"-m multiport ! --source-ports 10:12"),
	Entry("Source ports (multiple)", 4,
		proto.Rule{NotSrcPorts: []*proto.PortRange{
			{First: 10, Last: 12},
			{First: 20, Last: 30},
			{First: 8080, Last: 8080},
		}},
		"-m multiport ! --source-ports 10:12,20:30,8080"),
	Entry("Source ports (>15) should be broken into blocks", 4,
		proto.Rule{NotSrcPorts: []*proto.PortRange{
			{First: 1, Last: 2},
			{First: 3, Last: 4},
			{First: 5, Last: 6},
			{First: 7, Last: 8},
			{First: 9, Last: 10},
			{First: 11, Last: 12},
			{First: 13, Last: 14},
			{First: 15, Last: 16},
		}},
		"-m multiport ! --source-ports 1:2,3:4,5:6,7:8,9:10,11:12,13:14 -m multiport ! --source-ports 15:16"),
	Entry("ICMP", 4,
		proto.Rule{NotIcmp: &proto.Rule_NotIcmpType{NotIcmpType: 10}},
		"-m icmp ! --icmp-type 10"),
	Entry("ICMP with code", 4,
		proto.Rule{NotIcmp: &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}},
		"-m icmp ! --icmp-type 10/12"),
	Entry("ICMP", 6,
		proto.Rule{NotIcmp: &proto.Rule_NotIcmpType{NotIcmpType: 10}},
		"-m icmp6 ! --icmpv6-type 10"),
	Entry("ICMP with code", 6,
		proto.Rule{NotIcmp: &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}},
		"-m icmp6 ! --icmpv6-type 10/12"),

	Entry("Dest net", 4,
		proto.Rule{NotDstNet: []string{"10.0.0.0/16"}},
		"! --destination 10.0.0.0/16"),
	Entry("Dest IP set", 4,
		proto.Rule{NotDstIpSetIds: []string{"ipsetid1"}},
		"-m set ! --match-set cali4-ipsetid1 dst"),
	Entry("Dest IP set", 6,
		proto.Rule{NotDstIpSetIds: []string{"ipsetid1"}},
		"-m set ! --match-set cali6-ipsetid1 dst"),
	Entry("Dest IP sets", 4,
		proto.Rule{NotDstIpSetIds: []string{"ipsetid1", "ipsetid2"}},
		"-m set ! --match-set cali4-ipsetid1 dst -m set ! --match-set cali4-ipsetid2 dst"),
	Entry("Dest ports", 4,
		proto.Rule{NotDstPorts: []*proto.PortRange{{First: 10, Last: 12}}},
		"-m multiport ! --destination-ports 10:12"),
	Entry("Dest ports (>15) should be broken into blocks", 4,
		proto.Rule{NotDstPorts: []*proto.PortRange{
			{First: 1, Last: 2},
			{First: 3, Last: 4},
			{First: 5, Last: 6},
			{First: 7, Last: 8},
			{First: 9, Last: 10},
			{First: 11, Last: 12},
			{First: 13, Last: 14},
			{First: 15, Last: 16},
		}},
		"-m multiport ! --destination-ports 1:2,3:4,5:6,7:8,9:10,11:12,13:14 -m multiport ! --destination-ports 15:16"),
	Entry("Dest ports (multiple)", 4,
		proto.Rule{NotDstPorts: []*proto.PortRange{
			{First: 10, Last: 12},
			{First: 20, Last: 30},
			{First: 8080, Last: 8080},
		}},
		"-m multiport ! --destination-ports 10:12,20:30,8080"),
}

var _ = Describe("Protobuf rule to iptables rule conversion", func() {
	var rrConfigNormal = Config{
		IPIPEnabled:          true,
		IPIPTunnelAddress:    nil,
		IPSetConfigV4:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
		IPSetConfigV6:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
		IptablesMarkAccept:   0x80,
		IptablesMarkPass:     0x100,
		IptablesMarkScratch0: 0x200,
		IptablesMarkScratch1: 0x400,
		IptablesLogPrefix:    "calico-packet",
	}

	DescribeTable(
		"Allow rules should be correctly rendered",
		func(ipVer int, in proto.Rule, expMatch string) {
			renderer := NewRenderer(rrConfigNormal)
			rules := renderer.ProtoRuleToIptablesRules(&in, uint8(ipVer))
			// For allow, should be one match rule that sets the mark, then one that reads the
			// mark and returns.
			Expect(len(rules)).To(Equal(2))
			Expect(rules[0].Match.Render()).To(Equal(expMatch))
			Expect(rules[0].Action).To(Equal(iptables.SetMarkAction{Mark: 0x80}))
			Expect(rules[1]).To(Equal(iptables.Rule{
				Match:  iptables.Match().MarkSet(0x80),
				Action: iptables.ReturnAction{},
			}))

			// Explicit allow should be treated the same as empty.
			in.Action = "allow"
			rules2 := renderer.ProtoRuleToIptablesRules(&in, uint8(ipVer))
			Expect(rules2).To(Equal(rules))
		},
		ruleTestData...,
	)

	DescribeTable(
		"pass rules should be correctly rendered",
		func(ipVer int, in proto.Rule, expMatch string) {
			for _, action := range []string{"next-tier", "pass"} {
				By("Rendering for action " + action)
				renderer := NewRenderer(rrConfigNormal)
				in.Action = action
				rules := renderer.ProtoRuleToIptablesRules(&in, uint8(ipVer))
				// For pass, should be one match rule that sets the mark, then one
				// that reads the mark and returns.
				Expect(len(rules)).To(Equal(2))
				Expect(rules[0].Match.Render()).To(Equal(expMatch))
				Expect(rules[0].Action).To(Equal(iptables.SetMarkAction{Mark: 0x100}))
				Expect(rules[1]).To(Equal(iptables.Rule{
					Match:  iptables.Match().MarkSet(0x100),
					Action: iptables.ReturnAction{},
				}))
			}
		},
		ruleTestData...,
	)

	DescribeTable(
		"Log rules should be correctly rendered",
		func(ipVer int, in proto.Rule, expMatch string) {
			renderer := NewRenderer(rrConfigNormal)
			logRule := in
			logRule.Action = "log"
			rules := renderer.ProtoRuleToIptablesRules(&logRule, uint8(ipVer))
			// For deny, should be one match rule that just does the DROP.
			Expect(len(rules)).To(Equal(1))
			Expect(rules[0].Match.Render()).To(Equal(expMatch))
			Expect(rules[0].Action).To(Equal(iptables.LogAction{Prefix: "calico-packet"}))
		},
		ruleTestData...,
	)

	DescribeTable(
		"Log rules should be correctly rendered with non-default prefix",
		func(ipVer int, in proto.Rule, expMatch string) {
			rrConfigPrefix := rrConfigNormal
			rrConfigPrefix.IptablesLogPrefix = "foobar"
			renderer := NewRenderer(rrConfigPrefix)
			logRule := in
			logRule.Action = "log"
			rules := renderer.ProtoRuleToIptablesRules(&logRule, uint8(ipVer))
			// For deny, should be one match rule that just does the DROP.
			Expect(len(rules)).To(Equal(1))
			Expect(rules[0].Match.Render()).To(Equal(expMatch))
			Expect(rules[0].Action).To(Equal(iptables.LogAction{Prefix: "foobar"}))
		},
		ruleTestData...,
	)

	DescribeTable(
		"Deny rules should be correctly rendered",
		func(ipVer int, in proto.Rule, expMatch string) {
			renderer := NewRenderer(rrConfigNormal)
			denyRule := in
			denyRule.Action = "deny"
			rules := renderer.ProtoRuleToIptablesRules(&denyRule, uint8(ipVer))
			// For deny, should be one match rule that just does the DROP.
			Expect(len(rules)).To(Equal(1))
			Expect(rules[0].Match.Render()).To(Equal(expMatch))
			Expect(rules[0].Action).To(Equal(iptables.DropAction{}))
		},
		ruleTestData...,
	)

	const (
		clearBothMarksRule      = "-A test --jump MARK --set-mark 0x0/0x600"
		preSetAllBlocksMarkRule = "-A test --jump MARK --set-mark 0x200/0x600"
		allowIfAllMarkRule      = "-A test -m mark --mark 0x200/0x200 --jump MARK --set-mark 0x80/0x80"
		returnRule              = "-A test -m mark --mark 0x80/0x80 --jump RETURN"
	)
	DescribeTable(
		"CIDR split tests",
		func(numSrc, numNotSrc, numDst, numNotDst int, expected []string) {
			renderer := NewRenderer(rrConfigNormal)
			pRule := proto.Rule{
				SrcNet:    []string{"10.0.0.0/24", "10.0.1.0/24"}[:numSrc],
				NotSrcNet: []string{"11.0.0.0/24", "11.0.1.0/24"}[:numNotSrc],
				DstNet:    []string{"12.0.0.0/24", "12.0.1.0/24"}[:numDst],
				NotDstNet: []string{"13.0.0.0/24", "13.0.1.0/24"}[:numNotDst],
				Action:    "allow",
			}
			iptRules := renderer.ProtoRuleToIptablesRules(&pRule, 4)
			rendered := []string{}
			for _, ir := range iptRules {
				s := ir.RenderAppend("test", "")
				rendered = append(rendered, s)
			}
			Expect(rendered).To(Equal(expected))
		},
		// Simple overflow of each match criteria...

		Entry("2 src, 0 !src, 0 dst, 0 !dst", 2, 0, 0, 0, []string{
			clearBothMarksRule,
			"-A test --source 10.0.0.0/24 --jump MARK --set-mark 0x200/0x200",
			"-A test --source 10.0.1.0/24 --jump MARK --set-mark 0x200/0x200",
			allowIfAllMarkRule,
			returnRule,
		}),
		Entry("0 src, 2 !src, 0 dst, 0 !dst", 0, 2, 0, 0, []string{
			preSetAllBlocksMarkRule,
			"-A test --source 11.0.0.0/24 --jump MARK --set-mark 0/0x200",
			"-A test --source 11.0.1.0/24 --jump MARK --set-mark 0/0x200",
			allowIfAllMarkRule,
			returnRule,
		}),
		Entry("0 src, 0 !src, 2 dst, 0 !dst", 0, 0, 2, 0, []string{
			clearBothMarksRule,
			"-A test --destination 12.0.0.0/24 --jump MARK --set-mark 0x200/0x200",
			"-A test --destination 12.0.1.0/24 --jump MARK --set-mark 0x200/0x200",
			allowIfAllMarkRule,
			returnRule,
		}),
		Entry("0 src, 0 !src, 0 dst, 2 !dst", 0, 0, 0, 2, []string{
			preSetAllBlocksMarkRule,
			"-A test --destination 13.0.0.0/24 --jump MARK --set-mark 0/0x200",
			"-A test --destination 13.0.1.0/24 --jump MARK --set-mark 0/0x200",
			allowIfAllMarkRule,
			returnRule,
		}),

		// Overflow of source even though each type would fit.
		Entry("1 src, 1 !src, 0 dst, 0 !dst", 1, 1, 0, 0, []string{
			preSetAllBlocksMarkRule,
			"-A test --source 11.0.0.0/24 --jump MARK --set-mark 0/0x200",
			"-A test --source 10.0.0.0/24 -m mark --mark 0x200/0x200 --jump MARK --set-mark 0x80/0x80",
			returnRule,
		}),
		Entry("2 src, 1 !src, 0 dst, 0 !dst", 2, 1, 0, 0, []string{
			clearBothMarksRule,
			"-A test --source 10.0.0.0/24 --jump MARK --set-mark 0x200/0x200",
			"-A test --source 10.0.1.0/24 --jump MARK --set-mark 0x200/0x200",
			"-A test --source 11.0.0.0/24 --jump MARK --set-mark 0/0x200",
			allowIfAllMarkRule,
			returnRule,
		}),

		// Ditto for dest.
		Entry("0 src, 0 !src, 1 dst, 1 !dst", 0, 0, 1, 1, []string{
			preSetAllBlocksMarkRule,
			"-A test --destination 13.0.0.0/24 --jump MARK --set-mark 0/0x200",
			"-A test --destination 12.0.0.0/24 -m mark --mark 0x200/0x200 --jump MARK --set-mark 0x80/0x80",
			returnRule,
		}),
		Entry("0 src, 0 !src, 2 dst, 1 !dst", 0, 0, 2, 1, []string{
			clearBothMarksRule,
			"-A test --destination 12.0.0.0/24 --jump MARK --set-mark 0x200/0x200",
			"-A test --destination 12.0.1.0/24 --jump MARK --set-mark 0x200/0x200",
			"-A test --destination 13.0.0.0/24 --jump MARK --set-mark 0/0x200",
			allowIfAllMarkRule,
			returnRule,
		}),

		// One of everything; only !src and !dst should overflow
		Entry("1 src, 1 !src, 1 dst, 1 !dst", 1, 1, 1, 1, []string{
			preSetAllBlocksMarkRule,
			"-A test --source 11.0.0.0/24 --jump MARK --set-mark 0/0x200",
			"-A test --destination 13.0.0.0/24 --jump MARK --set-mark 0/0x200",
			"-A test --source 10.0.0.0/24 --destination 12.0.0.0/24 -m mark --mark 0x200/0x200 --jump MARK --set-mark 0x80/0x80",
			returnRule,
		}),

		// Two of everything; everything overflows.
		Entry("2 src, 2 !src, 2 dst, 2 !dst", 2, 2, 2, 2, []string{
			// Both marks start as 0.
			clearBothMarksRule,

			// Source match directly sets the AllBlocks bit.
			"-A test --source 10.0.0.0/24 --jump MARK --set-mark 0x200/0x200",
			"-A test --source 10.0.1.0/24 --jump MARK --set-mark 0x200/0x200",

			// Then the Dest match sets a scratch bit.
			"-A test --destination 12.0.0.0/24 --jump MARK --set-mark 0x400/0x400",
			"-A test --destination 12.0.1.0/24 --jump MARK --set-mark 0x400/0x400",
			// If the scratch bit isn't set then we clear the AllBlocks bit.
			"-A test -m mark --mark 0/0x400 --jump MARK --set-mark 0/0x200",

			// The negated matches clear the AllBlocks bit directly if they match.
			"-A test --source 11.0.0.0/24 --jump MARK --set-mark 0/0x200",
			"-A test --source 11.0.1.0/24 --jump MARK --set-mark 0/0x200",
			"-A test --destination 13.0.0.0/24 --jump MARK --set-mark 0/0x200",
			"-A test --destination 13.0.1.0/24 --jump MARK --set-mark 0/0x200",

			allowIfAllMarkRule,
			returnRule,
		}),
	)

	var renderer *DefaultRuleRenderer
	BeforeEach(func() {
		renderer = NewRenderer(rrConfigNormal).(*DefaultRuleRenderer)
	})

	It("should skip rules of incorrect IP version", func() {
		rules := renderer.ProtoRulesToIptablesRules([]*proto.Rule{{IpVersion: 4}}, 6)
		Expect(rules).To(BeEmpty())
	})

	It("should skip with mixed source CIDR matches", func() {
		rules := renderer.ProtoRulesToIptablesRules([]*proto.Rule{{SrcNet: []string{"10.0.0.1"}}}, 6)
		Expect(rules).To(BeEmpty())
	})

	It("should skip with mixed source CIDR matches", func() {
		rules := renderer.ProtoRulesToIptablesRules([]*proto.Rule{{SrcNet: []string{"feed::beef"}}}, 4)
		Expect(rules).To(BeEmpty())
	})

	It("should skip with mixed dest CIDR matches", func() {
		rules := renderer.ProtoRulesToIptablesRules([]*proto.Rule{{DstNet: []string{"10.0.0.1"}}}, 6)
		Expect(rules).To(BeEmpty())
	})

	It("should skip with mixed dest CIDR matches", func() {
		rules := renderer.ProtoRulesToIptablesRules([]*proto.Rule{{DstNet: []string{"feed::beef"}}}, 4)
		Expect(rules).To(BeEmpty())
	})

	It("should skip with mixed negated source CIDR matches", func() {
		rules := renderer.ProtoRulesToIptablesRules([]*proto.Rule{{NotSrcNet: []string{"10.0.0.1"}}}, 6)
		Expect(rules).To(BeEmpty())
	})

	It("should skip with mixed negated source CIDR matches", func() {
		rules := renderer.ProtoRulesToIptablesRules([]*proto.Rule{{NotSrcNet: []string{"feed::beef"}}}, 4)
		Expect(rules).To(BeEmpty())
	})

	It("should skip with mixed negated dest CIDR matches", func() {
		rules := renderer.ProtoRulesToIptablesRules([]*proto.Rule{{NotDstNet: []string{"10.0.0.1"}}}, 6)
		Expect(rules).To(BeEmpty())
	})

	It("should skip with mixed negated dest CIDR matches", func() {
		rules := renderer.ProtoRulesToIptablesRules([]*proto.Rule{{NotDstNet: []string{"feed::beef"}}}, 4)
		Expect(rules).To(BeEmpty())
	})

	It("Should correctly render the cross-product of the source/dest ports", func() {
		srcPorts := []*proto.PortRange{
			{First: 1, Last: 2},
			{First: 3, Last: 4},
			{First: 5, Last: 6},
			{First: 7, Last: 8},
			{First: 9, Last: 10},
			{First: 11, Last: 12},
			{First: 13, Last: 14},
			{First: 15, Last: 16},
		}
		dstPorts := []*proto.PortRange{
			{First: 101, Last: 102},
			{First: 103, Last: 104},
			{First: 105, Last: 106},
			{First: 107, Last: 108},
			{First: 109, Last: 1010},
			{First: 1011, Last: 1012},
			{First: 1013, Last: 1014},
			{First: 1015, Last: 1016},
		}
		rule := proto.Rule{
			Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{"tcp"}},
			SrcPorts: srcPorts,
			DstPorts: dstPorts,
		}
		renderer := NewRenderer(rrConfigNormal)
		rules := renderer.ProtoRuleToIptablesRules(&rule, uint8(4))
		Expect(rules).To(Equal([]iptables.Rule{
			{
				Match: iptables.Match().Protocol("tcp").
					SourcePortRanges(srcPorts[:7]).
					DestPortRanges(dstPorts[:7]),
				Action: iptables.SetMarkAction{Mark: 0x80},
			},
			{Match: iptables.Match().MarkSet(0x80), Action: iptables.ReturnAction{}},
			{
				Match: iptables.Match().Protocol("tcp").
					SourcePortRanges(srcPorts[:7]).
					DestPortRanges(dstPorts[7:8]),
				Action: iptables.SetMarkAction{Mark: 0x80},
			},
			{Match: iptables.Match().MarkSet(0x80), Action: iptables.ReturnAction{}},
			{
				Match: iptables.Match().Protocol("tcp").
					SourcePortRanges(srcPorts[7:8]).
					DestPortRanges(dstPorts[:7]),
				Action: iptables.SetMarkAction{Mark: 0x80},
			},
			{Match: iptables.Match().MarkSet(0x80), Action: iptables.ReturnAction{}},
			{
				Match: iptables.Match().Protocol("tcp").
					SourcePortRanges(srcPorts[7:8]).
					DestPortRanges(dstPorts[7:8]),
				Action: iptables.SetMarkAction{Mark: 0x80},
			},
			{Match: iptables.Match().MarkSet(0x80), Action: iptables.ReturnAction{}},
		}))
	})
})

var _ = DescribeTable("Port split tests",
	func(in []*proto.PortRange, expected [][]*proto.PortRange) {
		Expect(SplitPortList(in)).To(Equal(expected))
	},
	Entry("nil input", ([]*proto.PortRange)(nil), [][]*proto.PortRange{{}}),
	Entry("empty input", []*proto.PortRange{}, [][]*proto.PortRange{{}}),
	Entry("single input", []*proto.PortRange{{First: 1, Last: 1}}, [][]*proto.PortRange{{{First: 1, Last: 1}}}),
	Entry("range input", []*proto.PortRange{{First: 1, Last: 10}}, [][]*proto.PortRange{{{First: 1, Last: 10}}}),
	Entry("exactly 15 single ports should give exactly one split", []*proto.PortRange{
		{First: 1, Last: 1},
		{First: 2, Last: 2},
		{First: 3, Last: 3},
		{First: 4, Last: 4},
		{First: 5, Last: 5},
		{First: 6, Last: 6},
		{First: 7, Last: 7},
		{First: 8, Last: 8},
		{First: 9, Last: 9},
		{First: 10, Last: 10},
		{First: 11, Last: 11},
		{First: 12, Last: 12},
		{First: 13, Last: 13},
		{First: 14, Last: 14},
		{First: 15, Last: 15},
	}, [][]*proto.PortRange{{
		{First: 1, Last: 1},
		{First: 2, Last: 2},
		{First: 3, Last: 3},
		{First: 4, Last: 4},
		{First: 5, Last: 5},
		{First: 6, Last: 6},
		{First: 7, Last: 7},
		{First: 8, Last: 8},
		{First: 9, Last: 9},
		{First: 10, Last: 10},
		{First: 11, Last: 11},
		{First: 12, Last: 12},
		{First: 13, Last: 13},
		{First: 14, Last: 14},
		{First: 15, Last: 15},
	}}),
	Entry("exactly 16 single ports should give exactly tow splits", []*proto.PortRange{
		{First: 1, Last: 1},
		{First: 2, Last: 2},
		{First: 3, Last: 3},
		{First: 4, Last: 4},
		{First: 5, Last: 5},
		{First: 6, Last: 6},
		{First: 7, Last: 7},
		{First: 8, Last: 8},
		{First: 9, Last: 9},
		{First: 10, Last: 10},
		{First: 11, Last: 11},
		{First: 12, Last: 12},
		{First: 13, Last: 13},
		{First: 14, Last: 14},
		{First: 15, Last: 15},
		{First: 16, Last: 16},
	}, [][]*proto.PortRange{{
		{First: 1, Last: 1},
		{First: 2, Last: 2},
		{First: 3, Last: 3},
		{First: 4, Last: 4},
		{First: 5, Last: 5},
		{First: 6, Last: 6},
		{First: 7, Last: 7},
		{First: 8, Last: 8},
		{First: 9, Last: 9},
		{First: 10, Last: 10},
		{First: 11, Last: 11},
		{First: 12, Last: 12},
		{First: 13, Last: 13},
		{First: 14, Last: 14},
		{First: 15, Last: 15},
	}, {
		{First: 16, Last: 16},
	}}),
	Entry("port ranges should count for 2 single ports", []*proto.PortRange{
		{First: 1, Last: 2},
		{First: 3, Last: 4},
		{First: 5, Last: 6},
		{First: 7, Last: 8},
		{First: 9, Last: 10},
		{First: 11, Last: 12},
		{First: 13, Last: 14},
		{First: 15, Last: 15},
	}, [][]*proto.PortRange{{
		{First: 1, Last: 2},
		{First: 3, Last: 4},
		{First: 5, Last: 6},
		{First: 7, Last: 8},
		{First: 9, Last: 10},
		{First: 11, Last: 12},
		{First: 13, Last: 14},
		{First: 15, Last: 15},
	}}),
	Entry("port range straggling 15-16 should be put in second group", []*proto.PortRange{
		{First: 1, Last: 2},
		{First: 3, Last: 4},
		{First: 5, Last: 6},
		{First: 7, Last: 8},
		{First: 9, Last: 10},
		{First: 11, Last: 12},
		{First: 13, Last: 14},
		{First: 15, Last: 16},
	}, [][]*proto.PortRange{{
		{First: 1, Last: 2},
		{First: 3, Last: 4},
		{First: 5, Last: 6},
		{First: 7, Last: 8},
		{First: 9, Last: 10},
		{First: 11, Last: 12},
		{First: 13, Last: 14},
	}, {
		{First: 15, Last: 16},
	}}),
	Entry("further splits should be made in correct place", []*proto.PortRange{
		{First: 1, Last: 2},
		{First: 3, Last: 4},
		{First: 5, Last: 6},
		{First: 7, Last: 8},
		{First: 9, Last: 10},
		{First: 11, Last: 12},
		{First: 13, Last: 14},
		{First: 15, Last: 16},
		{First: 21, Last: 22},
		{First: 23, Last: 24},
		{First: 23, Last: 26},
		{First: 27, Last: 28},
		{First: 29, Last: 210},
		{First: 211, Last: 212},
		{First: 213, Last: 214},
		{First: 215, Last: 216},
	}, [][]*proto.PortRange{{
		{First: 1, Last: 2},
		{First: 3, Last: 4},
		{First: 5, Last: 6},
		{First: 7, Last: 8},
		{First: 9, Last: 10},
		{First: 11, Last: 12},
		{First: 13, Last: 14},
	}, {
		{First: 15, Last: 16},
		{First: 21, Last: 22},
		{First: 23, Last: 24},
		{First: 23, Last: 26},
		{First: 27, Last: 28},
		{First: 29, Last: 210},
		{First: 211, Last: 212},
	}, {
		{First: 213, Last: 214},
		{First: 215, Last: 216},
	}}),
)
