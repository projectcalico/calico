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

package testutils

import (
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var ipv4 = 4
var ipv6 = 6
var strProtocol1 = numorstring.ProtocolFromString("icmp")
var strProtocol2 = numorstring.ProtocolFromString("udp")
var numProtocol1 = numorstring.ProtocolFromInt(240)

var icmpType1 = 100
var icmpCode1 = 200

var cidr1 = MustParseCIDR("10.0.0.1/24")
var cidr2 = MustParseCIDR("20.0.0.1/24")
var cidrv61 = MustParseCIDR("abcd:5555::/120")
var cidrv62 = MustParseCIDR("abcd:2345::/120")

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
		Selector: "selector1",
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
		Selector: "selector2",
	},
}

var EgressRule1 = api.Rule{
	Action:    "deny",
	IPVersion: &ipv4,
	Protocol:  &numProtocol1,
	ICMP:      &icmp1,
	Source: api.EntityRule{
		Tag:      "tag3",
		Net:      &cidr2,
		Selector: "selector3",
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
		Selector: "selector4",
	},
}
