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
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

type ruleTest struct {
	rule           model.Rule
	expectedOutput string
}

var tcpProto = numorstring.ProtocolFromString("TCP")
var icmpProto = numorstring.ProtocolFromString("ICMP")
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
var httpMethod = &model.HTTPMatch{Methods: []string{"GET", "PUT"}}
var httpPath = &model.HTTPMatch{Paths: []apiv3.HTTPPath{{Exact: "/foo"}, {Prefix: "/bar"}}}

var ruleStringTests = []ruleTest{
	// Empty
	{model.Rule{}, "Allow"},

	// Int/string handling.
	{model.Rule{Protocol: &intProto}, "Allow 123"},
	{model.Rule{Protocol: &tcpProto}, "Allow TCP"},

	// Explicit actions, packet-wide matches.
	{model.Rule{Action: "Allow", Protocol: &tcpProto}, "Allow TCP"},
	{model.Rule{Action: "Deny", Protocol: &icmpProto, ICMPType: &icmpType},
		"Deny ICMP type 10"},
	{model.Rule{Protocol: &icmpProto, ICMPType: &icmpType, ICMPCode: &icmpCode},
		"Allow ICMP type 10 code 6"},
	{model.Rule{Action: "Deny", Protocol: &icmpProto, ICMPType: &icmpTypeZero},
		"Deny ICMP type 0"},
	{model.Rule{Protocol: &icmpProto, ICMPType: &icmpTypeZero, ICMPCode: &icmpCodeZero},
		"Allow ICMP type 0 code 0"},
	// And negations of packet-wide matches.
	{model.Rule{Action: "Allow", NotProtocol: &tcpProto}, "Allow !TCP"},
	{model.Rule{Action: "Deny", Protocol: &icmpProto, NotICMPType: &icmpType},
		"Deny ICMP !type 10"},
	{model.Rule{Protocol: &icmpProto, NotICMPType: &icmpType, NotICMPCode: &icmpCode},
		"Allow ICMP !type 10 !code 6"},

	// From rules.
	{model.Rule{SrcPorts: ports}, "Allow from ports 1234,10:20"},
	{model.Rule{SrcTag: "foo"}, "Allow from tag foo"},
	{model.Rule{SrcSelector: "bar"}, "Allow from selector \"bar\""},
	{model.Rule{SrcNet: cidr}, "Allow from cidr 10.0.0.0/16"},
	{model.Rule{NotSrcPorts: ports}, "Allow from !ports 1234,10:20"},
	{model.Rule{NotSrcTag: "foo"}, "Allow from !tag foo"},
	{model.Rule{NotSrcSelector: "bar"}, "Allow from !selector \"bar\""},
	{model.Rule{NotSrcNet: cidr}, "Allow from !cidr 10.0.0.0/16"},

	// To rules.
	{model.Rule{DstPorts: ports}, "Allow to ports 1234,10:20"},
	{model.Rule{DstTag: "foo"}, "Allow to tag foo"},
	{model.Rule{DstSelector: "bar"}, "Allow to selector \"bar\""},
	{model.Rule{DstNet: cidr}, "Allow to cidr 10.0.0.0/16"},
	{model.Rule{NotDstPorts: ports}, "Allow to !ports 1234,10:20"},
	{model.Rule{NotDstTag: "foo"}, "Allow to !tag foo"},
	{model.Rule{NotDstSelector: "bar"}, "Allow to !selector \"bar\""},
	{model.Rule{NotDstNet: cidr}, "Allow to !cidr 10.0.0.0/16"},

	// Application layer rules.
	{model.Rule{HTTPMatch: httpMethod}, "Allow to httpMethods [GET PUT]"},
	{model.Rule{HTTPMatch: httpPath}, "Allow to httpPaths [{Exact:/foo Prefix:} {Exact: Prefix:/bar}]"},

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
		`Allow TCP from ports 1234,10:20 tag srcTag !tag notSrc ` +
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
