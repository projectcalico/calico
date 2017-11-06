// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

type ruleTest struct {
	rule           model.Rule
	expectedOutput string
}

var tcpProto = numorstring.ProtocolFromString("tcp")
var icmpProto = numorstring.ProtocolFromString("icmp")
var intProto = numorstring.ProtocolFromInt(123)
var icmpType = 10
var icmpCode = 6
var icmpTypeZero = 0
var icmpCodeZero = 0
var portRange, _ = numorstring.PortFromRange(10, 20)
var ports = []numorstring.Port{
	numorstring.SinglePort(1234),
	portRange,
}
var ports2 = []numorstring.Port{
	numorstring.SinglePort(4567),
}
var _, cidr, _ = net.ParseCIDR("10.0.0.0/16")

var ruleStringTests = []ruleTest{
	// Empty
	{model.Rule{}, "allow"},

	// Int/string handling.
	{model.Rule{Protocol: &intProto}, "allow 123"},
	{model.Rule{Protocol: &tcpProto}, "allow tcp"},

	// Explicit actions, packet-wide matches.
	{model.Rule{Action: "allow", Protocol: &tcpProto}, "allow tcp"},
	{model.Rule{Action: "deny", Protocol: &icmpProto, ICMPType: &icmpType},
		"deny icmp type 10"},
	{model.Rule{Protocol: &icmpProto, ICMPType: &icmpType, ICMPCode: &icmpCode},
		"allow icmp type 10 code 6"},
	{model.Rule{Action: "deny", Protocol: &icmpProto, ICMPType: &icmpTypeZero},
		"deny icmp type 0"},
	{model.Rule{Protocol: &icmpProto, ICMPType: &icmpTypeZero, ICMPCode: &icmpCodeZero},
		"allow icmp type 0 code 0"},
	// And negations of packet-wide matches.
	{model.Rule{Action: "allow", NotProtocol: &tcpProto}, "allow !tcp"},
	{model.Rule{Action: "deny", Protocol: &icmpProto, NotICMPType: &icmpType},
		"deny icmp !type 10"},
	{model.Rule{Protocol: &icmpProto, NotICMPType: &icmpType, NotICMPCode: &icmpCode},
		"allow icmp !type 10 !code 6"},

	// From rules.
	{model.Rule{SrcPorts: ports}, "allow from ports 1234,10:20"},
	{model.Rule{SrcTag: "foo"}, "allow from tag foo"},
	{model.Rule{SrcSelector: "bar"}, "allow from selector \"bar\""},
	{model.Rule{SrcNet: cidr}, "allow from cidr 10.0.0.0/16"},
	{model.Rule{NotSrcPorts: ports}, "allow from !ports 1234,10:20"},
	{model.Rule{NotSrcTag: "foo"}, "allow from !tag foo"},
	{model.Rule{NotSrcSelector: "bar"}, "allow from !selector \"bar\""},
	{model.Rule{NotSrcNet: cidr}, "allow from !cidr 10.0.0.0/16"},

	// To rules.
	{model.Rule{DstPorts: ports}, "allow to ports 1234,10:20"},
	{model.Rule{DstTag: "foo"}, "allow to tag foo"},
	{model.Rule{DstSelector: "bar"}, "allow to selector \"bar\""},
	{model.Rule{DstNet: cidr}, "allow to cidr 10.0.0.0/16"},
	{model.Rule{NotDstPorts: ports}, "allow to !ports 1234,10:20"},
	{model.Rule{NotDstTag: "foo"}, "allow to !tag foo"},
	{model.Rule{NotDstSelector: "bar"}, "allow to !selector \"bar\""},
	{model.Rule{NotDstNet: cidr}, "allow to !cidr 10.0.0.0/16"},

	// Complex rule.
	{model.Rule{Protocol: &tcpProto,
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
