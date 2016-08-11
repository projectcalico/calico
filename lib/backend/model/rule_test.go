// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package model_test

import (
	. "github.com/tigera/libcalico-go/lib/backend/model"

	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/libcalico-go/lib/net"
	"github.com/tigera/libcalico-go/lib/numorstring"
)

type ruleTest struct {
	rule           Rule
	expectedOutput string
}

var tcpProto = numorstring.ProtocolFromString("tcp")
var icmpProto = numorstring.ProtocolFromString("icmp")
var intProto = numorstring.ProtocolFromInt(123)
var icmpType = 10
var icmpCode = 6
var ports = []numorstring.Port{
	numorstring.PortFromInt(1234),
	numorstring.PortFromRange(10, 20),
}
var ports2 = []numorstring.Port{
	numorstring.PortFromInt(4567),
}
var _, cidr, _ = net.ParseCIDR("10.0.0.0/16")

var ruleStringTests = []ruleTest{
	// Empty
	{Rule{}, "allow"},

	// Int/string handling.
	{Rule{Protocol: &intProto}, "allow 123"},
	{Rule{Protocol: &tcpProto}, "allow tcp"},

	// Explicit actions, packet-wide matches.
	{Rule{Action: "allow", Protocol: &tcpProto}, "allow tcp"},
	{Rule{Action: "deny", Protocol: &icmpProto, ICMPType: &icmpType},
		"deny icmp type 10"},
	{Rule{Protocol: &icmpProto, ICMPType: &icmpType, ICMPCode: &icmpCode},
		"allow icmp type 10 code 6"},
	// And negations of packet-wide matches.
	{Rule{Action: "allow", NotProtocol: &tcpProto}, "allow !tcp"},
	{Rule{Action: "deny", Protocol: &icmpProto, NotICMPType: &icmpType},
		"deny icmp !type 10"},
	{Rule{Protocol: &icmpProto, NotICMPType: &icmpType, NotICMPCode: &icmpCode},
		"allow icmp !type 10 !code 6"},

	// From rules.
	{Rule{SrcPorts: ports}, "allow from ports 1234,10:20"},
	{Rule{SrcTag: "foo"}, "allow from tag foo"},
	{Rule{SrcSelector: "bar"}, "allow from selector \"bar\""},
	{Rule{SrcNet: cidr}, "allow from cidr 10.0.0.0/16"},
	{Rule{NotSrcPorts: ports}, "allow from !ports 1234,10:20"},
	{Rule{NotSrcTag: "foo"}, "allow from !tag foo"},
	{Rule{NotSrcSelector: "bar"}, "allow from !selector \"bar\""},
	{Rule{NotSrcNet: cidr}, "allow from !cidr 10.0.0.0/16"},

	// To rules.
	{Rule{DstPorts: ports}, "allow to ports 1234,10:20"},
	{Rule{DstTag: "foo"}, "allow to tag foo"},
	{Rule{DstSelector: "bar"}, "allow to selector \"bar\""},
	{Rule{DstNet: cidr}, "allow to cidr 10.0.0.0/16"},
	{Rule{NotDstPorts: ports}, "allow to !ports 1234,10:20"},
	{Rule{NotDstTag: "foo"}, "allow to !tag foo"},
	{Rule{NotDstSelector: "bar"}, "allow to !selector \"bar\""},
	{Rule{NotDstNet: cidr}, "allow to !cidr 10.0.0.0/16"},

	// Complex rule.
	{Rule{Protocol: &tcpProto,
		SrcPorts:       ports,
		SrcTag:         "srcTag",
		DstTag:         "dstTag",
		DstNet:         cidr,
		NotDstPorts:    ports2,
		NotSrcTag:      "notSrc",
		NotSrcSelector: "foo",
	},
		`allow tcp from ports 1234,10:20 tag srcTag !tag notSrc ` +
			`!selector "foo" to tag dstTag cidr 10.0.0.0/16 !ports 4567`,
	},
}

var _ = Describe("Rule", func() {
	for _, test := range ruleStringTests {
		test := test // For closure
		Describe(fmt.Sprintf("%#v", test.rule), func() {
			It("should stringify as "+test.expectedOutput, func() {
				Expect(fmt.Sprintf("%s", test.rule)).To(Equal(test.expectedOutput))
			})
		})
	}
})
