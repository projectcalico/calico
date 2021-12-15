// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package calc

import (
	net2 "net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var ipv0 = 0
var ipv4 = 4
var ipv6 = 6
var icmpType10 = 10
var icmpCode12 = 12
var icmpType11 = 11
var icmpCode13 = 13
var proto123 = numorstring.ProtocolFromInt(uint8(123))
var protoTCP = numorstring.ProtocolFromStringV1("tcp")

var fullyLoadedParsedRule = ParsedRule{
	Action:    "allow",
	IPVersion: &ipv4,

	Protocol: &proto123,

	SrcNets:  []*net.IPNet{mustParseCalicoIPNet("10.0.0.0/8")},
	SrcPorts: []numorstring.Port{numorstring.SinglePort(10)},
	DstNets:  []*net.IPNet{mustParseCalicoIPNet("11.0.0.0/16")},
	DstPorts: []numorstring.Port{portFromRange(123, 456)},

	ICMPType: &icmpType10,
	ICMPCode: &icmpCode12,

	SrcIPSetIDs: []string{"srcID1", "srcID2"},
	DstIPSetIDs: []string{"dstID1", "dstID2"},

	SrcNamedPortIPSetIDs:    []string{"srcNP1"},
	DstNamedPortIPSetIDs:    []string{"dstNP1"},
	NotSrcNamedPortIPSetIDs: []string{"notSrcNP"},
	NotDstNamedPortIPSetIDs: []string{"notDstNP"},

	NotProtocol: &protoTCP,

	NotSrcNets:  []*net.IPNet{mustParseCalicoIPNet("12.0.0.0/8")},
	NotSrcPorts: []numorstring.Port{numorstring.SinglePort(11)},
	NotDstNets:  []*net.IPNet{mustParseCalicoIPNet("13.0.0.0/16")},
	NotDstPorts: []numorstring.Port{portFromRange(678, 910)},

	NotICMPType: &icmpType11,
	NotICMPCode: &icmpCode13,

	NotSrcIPSetIDs: []string{"srcID3", "srcID4"},
	NotDstIPSetIDs: []string{"dstID3", "dstID4"},

	OriginalSrcSelector:          "has(original-src)",
	OriginalDstSelector:          "has(original-dst)",
	OriginalNotSrcSelector:       "has(original-not-src)",
	OriginalNotDstSelector:       "has(original-not-dst)",
	OriginalSrcNamespaceSelector: "ns == 'src'",
	OriginalDstNamespaceSelector: "ns == 'dst'",

	OriginalSrcServiceAccountSelector: "has(sa-src)",
	OriginalSrcServiceAccountNames:    []string{"src-1"},

	OriginalDstServiceAccountSelector: "has(sa-dst)",
	OriginalDstServiceAccountNames:    []string{"dst-1"},

	HTTPMatch: &model.HTTPMatch{Methods: []string{"GET", "POST"}, Paths: []v3.HTTPPath{
		{Exact: "/foo"},
		{Prefix: "/bar"},
	}},

	Metadata: &model.RuleMetadata{Annotations: map[string]string{"key": "value"}},
}

var fullyLoadedProtoRule = proto.Rule{
	Action:    "allow",
	IpVersion: proto.IPVersion_IPV4,

	Protocol: &proto.Protocol{
		NumberOrName: &proto.Protocol_Number{Number: 123},
	},

	SrcNet:   []string{"10.0.0.0/8"},
	SrcPorts: []*proto.PortRange{{First: 10, Last: 10}},
	DstNet:   []string{"11.0.0.0/16"},
	DstPorts: []*proto.PortRange{{First: 123, Last: 456}},

	Icmp: &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{
		Type: 10,
		Code: 12,
	}},

	SrcIpSetIds: []string{"srcID1", "srcID2"},
	DstIpSetIds: []string{"dstID1", "dstID2"},

	NotProtocol: &proto.Protocol{
		NumberOrName: &proto.Protocol_Name{Name: "tcp"},
	},

	NotSrcNet:   []string{"12.0.0.0/8"},
	NotSrcPorts: []*proto.PortRange{{First: 11, Last: 11}},
	NotDstNet:   []string{"13.0.0.0/16"},
	NotDstPorts: []*proto.PortRange{{First: 678, Last: 910}},

	SrcNamedPortIpSetIds:    []string{"srcNP1"},
	DstNamedPortIpSetIds:    []string{"dstNP1"},
	NotSrcNamedPortIpSetIds: []string{"notSrcNP"},
	NotDstNamedPortIpSetIds: []string{"notDstNP"},

	NotIcmp: &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{
		Type: 11,
		Code: 13,
	}},

	NotSrcIpSetIds: []string{"srcID3", "srcID4"},
	NotDstIpSetIds: []string{"dstID3", "dstID4"},

	OriginalSrcSelector:          "has(original-src)",
	OriginalDstSelector:          "has(original-dst)",
	OriginalNotSrcSelector:       "has(original-not-src)",
	OriginalNotDstSelector:       "has(original-not-dst)",
	OriginalSrcNamespaceSelector: "ns == 'src'",
	OriginalDstNamespaceSelector: "ns == 'dst'",

	SrcServiceAccountMatch: &proto.ServiceAccountMatch{
		Selector: "has(sa-src)",
		Names:    []string{"src-1"},
	},
	DstServiceAccountMatch: &proto.ServiceAccountMatch{
		Selector: "has(sa-dst)",
		Names:    []string{"dst-1"},
	},

	HttpMatch: &proto.HTTPMatch{Methods: []string{"GET", "POST"},
		Paths: []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/foo"}},
			{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/bar"}},
		}},

	Metadata: &proto.RuleMetadata{Annotations: map[string]string{"key": "value"}},
}

var _ = DescribeTable("ParsedRulesToProtoRules",
	func(in ParsedRule, expected proto.Rule) {
		out := parsedRulesToProtoRules(
			[]*ParsedRule{&in},
			"test",
		)
		rule := *out[0]
		// Zero the rule ID so we can compare the other fields.
		ruleID := rule.RuleId
		rule.RuleId = ""
		Expect(rule).To(Equal(expected))
		Expect(len(ruleID)).To(Equal(16))
		Expect(ruleID).To(MatchRegexp("^[a-zA-Z0-9_-]+$"))
	},
	Entry("empty", ParsedRule{}, proto.Rule{}),
	Entry("IPv4",
		ParsedRule{IPVersion: &ipv4},
		proto.Rule{IpVersion: proto.IPVersion_IPV4}),
	Entry("IPv6",
		ParsedRule{IPVersion: &ipv6},
		proto.Rule{IpVersion: proto.IPVersion_IPV6}),
	Entry("IPv0",
		ParsedRule{IPVersion: &ipv0},
		proto.Rule{IpVersion: proto.IPVersion_ANY}),
	Entry("Multiple ports",
		ParsedRule{SrcPorts: []numorstring.Port{
			numorstring.SinglePort(10),
			numorstring.SinglePort(11),
			portFromRange(12, 13),
			portFromString("123"),
		}},
		proto.Rule{SrcPorts: []*proto.PortRange{
			{First: 10, Last: 10},
			{First: 11, Last: 11},
			{First: 12, Last: 13},
			{First: 123, Last: 123},
		}}),
	Entry("ICMP type-only rule",
		ParsedRule{
			ICMPType:    &icmpType10,
			NotICMPType: &icmpType11,
		},
		proto.Rule{
			Icmp: &proto.Rule_IcmpType{
				IcmpType: 10,
			},
			NotIcmp: &proto.Rule_NotIcmpType{
				NotIcmpType: 11,
			},
		}),
	Entry("Service match rule",
		ParsedRule{
			DstIPPortSetIDs: []string{"ipPortSetID"},
		},
		proto.Rule{
			DstIpPortSetIds: []string{"ipPortSetID"},
		}),
	Entry("fully-loaded rule",
		fullyLoadedParsedRule,
		fullyLoadedProtoRule),
)

var _ = Describe("rule ID tests", func() {
	It("should generate different IDs for different rules", func() {
		id1 := calculateRuleID("test", fullyLoadedParsedRule)
		id2 := calculateRuleID("test", ParsedRule{})
		Expect(id1).ToNot(Equal(id2))
	})
	It("should generate different IDs for different seeds", func() {
		id1 := calculateRuleID("test", fullyLoadedParsedRule)
		id2 := calculateRuleID("test2", fullyLoadedParsedRule)
		Expect(id1).ToNot(Equal(id2))
	})
	It("should generate the same ID for the same rule", func() {
		id1 := calculateRuleID("test", fullyLoadedParsedRule)
		id2 := calculateRuleID("test", fullyLoadedParsedRule)
		Expect(id1).To(Equal(id2))
	})
	It("should generate different IDs for different positions in chain", func() {
		out1 := parsedRulesToProtoRules(
			[]*ParsedRule{
				&fullyLoadedParsedRule,
				&fullyLoadedParsedRule,
			},
			"test",
		)
		out2 := parsedRulesToProtoRules(
			[]*ParsedRule{
				&ParsedRule{},
				&fullyLoadedParsedRule,
			},
			"test",
		)
		Expect(out1[0].RuleId).ToNot(Equal(out1[1].RuleId))
		Expect(out1[1].RuleId).ToNot(Equal(out2[1].RuleId))
	})
})

func calculateRuleID(seed string, in ParsedRule) string {
	out := parsedRulesToProtoRules(
		[]*ParsedRule{&in},
		seed,
	)
	ruleID := out[0].RuleId
	Expect(ruleID).To(MatchRegexp("^[a-zA-Z0-9_-]{16}$"))
	return ruleID
}

func portFromRange(minPort, maxPort uint16) numorstring.Port {
	port, _ := numorstring.PortFromRange(minPort, maxPort)
	return port
}

func portFromString(s string) numorstring.Port {
	port, _ := numorstring.PortFromString(s)
	return port
}

func mustParseCalicoIPNet(s string) *net.IPNet {
	_, ipNet, err := net2.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return &net.IPNet{IPNet: *ipNet}
}
