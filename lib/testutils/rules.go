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

package testutils

import (
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var ipv4 = 4
var ipv6 = 6
var strProtocol1 = numorstring.ProtocolFromString("icmp")
var strProtocol2 = numorstring.ProtocolFromString("udp")
var numProtocol1 = numorstring.ProtocolFromInt(240)

var icmpType1 = 100
var icmpCode1 = 200

var cidr1 = net.MustParseNetwork("10.0.0.1/24")
var cidr2 = net.MustParseNetwork("20.0.0.1/24")
var cidrv61 = net.MustParseNetwork("abcd:5555::/120")
var cidrv62 = net.MustParseNetwork("abcd:2345::/120")

var icmp1 = api.ICMPFields{
	Type: &icmpType1,
	Code: &icmpCode1,
}

var InRule1 = api.Rule{
	Action:    "allow",
	IPVersion: &ipv4,
	Protocol:  &strProtocol1,
	ICMP:      &icmp1,
	Source: api.EntityRule{
		Tag:      "tag1",
		Net:      &cidr1,
		Selector: "label1 == 'value1'",
	},
}

var InRule1AfterRead = api.Rule{
	Action:    "allow",
	IPVersion: &ipv4,
	Protocol:  &strProtocol1,
	ICMP:      &icmp1,
	Source: api.EntityRule{
		Tag:      "tag1",
		Nets:     []*net.IPNet{&cidr1},
		Selector: "label1 == 'value1'",
	},
}

var InRule2 = api.Rule{
	Action:    "deny",
	IPVersion: &ipv6,
	Protocol:  &numProtocol1,
	ICMP:      &icmp1,
	Source: api.EntityRule{
		Tag:      "tag2",
		Net:      &cidrv61,
		Selector: "has(label2)",
	},
}

var InRule2AfterRead = api.Rule{
	Action:    "deny",
	IPVersion: &ipv6,
	Protocol:  &numProtocol1,
	ICMP:      &icmp1,
	Source: api.EntityRule{
		Tag:      "tag2",
		Nets:     []*net.IPNet{&cidrv61},
		Selector: "has(label2)",
	},
}

var EgressRule1 = api.Rule{
	Action:    "pass",
	IPVersion: &ipv4,
	Protocol:  &numProtocol1,
	ICMP:      &icmp1,
	Source: api.EntityRule{
		Tag:      "tag3",
		Net:      &cidr2,
		Selector: "all()",
	},
}

var EgressRule1AfterRead = api.Rule{
	Action:    "pass",
	IPVersion: &ipv4,
	Protocol:  &numProtocol1,
	ICMP:      &icmp1,
	Source: api.EntityRule{
		Tag:      "tag3",
		Nets:     []*net.IPNet{&cidr2},
		Selector: "all()",
	},
}

var EgressRule2 = api.Rule{
	Action:    "allow",
	IPVersion: &ipv6,
	Protocol:  &strProtocol2,
	ICMP:      &icmp1,
	Source: api.EntityRule{
		Tag:      "tag4",
		Net:      &cidrv62,
		Selector: "label2 == '1234'",
	},
}

var EgressRule2AfterRead = api.Rule{
	Action:    "allow",
	IPVersion: &ipv6,
	Protocol:  &strProtocol2,
	ICMP:      &icmp1,
	Source: api.EntityRule{
		Tag:      "tag4",
		Nets:     []*net.IPNet{&cidrv62},
		Selector: "label2 == '1234'",
	},
}
