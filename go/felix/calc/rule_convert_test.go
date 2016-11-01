// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	net2 "net"
)

var ipv0 = 0
var ipv4 = 4
var ipv6 = 6
var icmpType10 = 10
var icmpCode12 = 12
var icmpType11 = 11
var icmpCode13 = 13
var proto123 = numorstring.ProtocolFromInt(uint8(123))
var protoTCP = numorstring.ProtocolFromString("tcp")

var _ = DescribeTable("ParsedRulesToProtoRules",
	func(in ParsedRule, expected proto.Rule) {
		out := parsedRulesToProtoRules([]*ParsedRule{&in})
		Expect(*out[0]).To(Equal(expected))
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
	Entry("fully-loaded rule",
		ParsedRule{
			Action:    "allow",
			IPVersion: &ipv4,

			Protocol: &proto123,

			SrcNet:   mustParseCalicoIPNet("10.0.0.0/8"),
			SrcPorts: []numorstring.Port{numorstring.SinglePort(10)},
			DstNet:   mustParseCalicoIPNet("11.0.0.0/16"),
			DstPorts: []numorstring.Port{portFromRange(123, 456)},

			ICMPType: &icmpType10,
			ICMPCode: &icmpCode12,

			SrcIPSetIDs: []string{"srcID1", "srcID2"},
			DstIPSetIDs: []string{"dstID1", "dstID2"},

			NotProtocol: &protoTCP,

			NotSrcNet:   mustParseCalicoIPNet("12.0.0.0/8"),
			NotSrcPorts: []numorstring.Port{numorstring.SinglePort(11)},
			NotDstNet:   mustParseCalicoIPNet("13.0.0.0/16"),
			NotDstPorts: []numorstring.Port{portFromRange(678, 910)},

			NotICMPType: &icmpType11,
			NotICMPCode: &icmpCode13,

			NotSrcIPSetIDs: []string{"srcID3", "srcID4"},
			NotDstIPSetIDs: []string{"dstID3", "dstID4"},

			LogPrefix: "foobar",
		},
		proto.Rule{
			Action:    "allow",
			IpVersion: proto.IPVersion_IPV4,

			Protocol: &proto.Protocol{
				NumberOrName: &proto.Protocol_Number{123},
			},

			SrcNet:   "10.0.0.0/8",
			SrcPorts: []*proto.PortRange{{First: 10, Last: 10}},
			DstNet:   "11.0.0.0/16",
			DstPorts: []*proto.PortRange{{First: 123, Last: 456}},

			Icmp: &proto.Rule_IcmpTypeCode{&proto.IcmpTypeAndCode{
				Type: 10,
				Code: 12,
			}},

			SrcIpSetIds: []string{"srcID1", "srcID2"},
			DstIpSetIds: []string{"dstID1", "dstID2"},

			NotProtocol: &proto.Protocol{
				NumberOrName: &proto.Protocol_Name{"tcp"},
			},

			NotSrcNet:   "12.0.0.0/8",
			NotSrcPorts: []*proto.PortRange{{First: 11, Last: 11}},
			NotDstNet:   "13.0.0.0/16",
			NotDstPorts: []*proto.PortRange{{First: 678, Last: 910}},

			NotIcmp: &proto.Rule_NotIcmpTypeCode{&proto.IcmpTypeAndCode{
				Type: 11,
				Code: 13,
			}},

			NotSrcIpSetIds: []string{"srcID3", "srcID4"},
			NotDstIpSetIds: []string{"dstID3", "dstID4"},

			LogPrefix: "foobar",
		}),
)

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
	return &net.IPNet{*ipNet}
}
