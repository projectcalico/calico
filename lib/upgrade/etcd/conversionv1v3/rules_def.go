// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package conversionv1v3

import (
	apiv1 "github.com/projectcalico/libcalico-go/lib/apis/v1"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var ipv4 = 4
var ipv6 = 6
var v1strProtocol1 = numorstring.ProtocolFromStringV1("icmp")
var v3strProtocol1 = numorstring.ProtocolFromString("ICMP")
var v1strProtocol2 = numorstring.ProtocolFromStringV1("udp")
var v3strProtocol2 = numorstring.ProtocolFromString("UDP")
var numProtocol1 = numorstring.ProtocolFromInt(240)

var icmpType1 = 100
var icmpCode1 = 200

var cidr1StrictMaskStr = "10.0.0.0/24"
var cidr2StrictMaskStr = "20.0.0.0/24"
var cidr1Str = "10.0.0.1/24"
var cidr2Str = "20.0.0.2/24"
var cidrv61Str = "abcd:5555::/120"
var cidrv62Str = "abcd:2345::/120"

var cidr1 = net.MustParseNetwork(cidr1Str)
var cidr2 = net.MustParseNetwork(cidr2Str)
var cidrv61 = net.MustParseNetwork(cidrv61Str)
var cidrv62 = net.MustParseNetwork(cidrv62Str)

var icmp1 = apiv1.ICMPFields{
	Type: &icmpType1,
	Code: &icmpCode1,
}

var v3icmp1 = apiv3.ICMPFields{
	Type: &icmpType1,
	Code: &icmpCode1,
}

var V1InRule1 = apiv1.Rule{
	Action:    "allow",
	IPVersion: &ipv4,
	Protocol:  &v1strProtocol1,
	ICMP:      &icmp1,
	Source: apiv1.EntityRule{
		Tag:      "tag1",
		Net:      &cidr1,
		Selector: "label1 == 'value1' || bake == 'cake'",
	},
}

var V1ModelInRule1 = model.Rule{
	Action:      "allow",
	IPVersion:   &ipv4,
	Protocol:    &v1strProtocol1,
	ICMPType:    &icmpType1,
	ICMPCode:    &icmpCode1,
	SrcTag:      "tag1",
	SrcNet:      &cidr1,
	SrcSelector: "label1 == 'value1' || bake == 'cake'",
}

var V3InRule1 = apiv3.Rule{
	Action:    apiv3.Allow,
	IPVersion: &ipv4,
	Protocol:  &v3strProtocol1,
	ICMP:      &v3icmp1,
	Source: apiv3.EntityRule{
		Nets:     []string{cidr1StrictMaskStr},
		Selector: "(label1 == 'value1' || bake == 'cake') && tag1 == ''",
	},
}

var V1InRule2 = apiv1.Rule{
	Action:    "deny",
	IPVersion: &ipv6,
	Protocol:  &numProtocol1,
	ICMP:      &icmp1,
	Source: apiv1.EntityRule{
		Tag:      "tag2",
		Net:      &cidrv61,
		Selector: "has(label2)",
	},
}

var V1ModelInRule2 = model.Rule{
	Action:      "deny",
	IPVersion:   &ipv6,
	Protocol:    &numProtocol1,
	ICMPType:    &icmpType1,
	ICMPCode:    &icmpCode1,
	SrcTag:      "tag2",
	SrcNet:      &cidrv61,
	SrcSelector: "has(label2)",
}

var V3InRule2 = apiv3.Rule{
	Action:    apiv3.Deny,
	IPVersion: &ipv6,
	Protocol:  &numProtocol1,
	ICMP:      &v3icmp1,
	Source: apiv3.EntityRule{
		Nets:     []string{cidrv61Str},
		Selector: "(has(label2)) && tag2 == ''",
	},
}

var V1EgressRule1 = apiv1.Rule{
	Action:    "pass",
	IPVersion: &ipv4,
	Protocol:  &numProtocol1,
	ICMP:      &icmp1,
	Source: apiv1.EntityRule{
		Tag:      "tag3",
		Net:      &cidr2,
		Selector: "all()",
	},
}

var V1ModelEgressRule1 = model.Rule{
	Action:      "next-tier",
	IPVersion:   &ipv4,
	Protocol:    &numProtocol1,
	ICMPType:    &icmpType1,
	ICMPCode:    &icmpCode1,
	SrcTag:      "tag3",
	SrcNet:      &cidr2,
	SrcSelector: "all()",
}

var V3EgressRule1 = apiv3.Rule{
	Action:    apiv3.Pass,
	IPVersion: &ipv4,
	Protocol:  &numProtocol1,
	ICMP:      &v3icmp1,
	Source: apiv3.EntityRule{
		Nets:     []string{cidr2StrictMaskStr},
		Selector: "(all()) && tag3 == ''",
	},
}

var V1EgressRule2 = apiv1.Rule{
	Action:    "allow",
	IPVersion: &ipv6,
	Protocol:  &v1strProtocol2,
	ICMP:      &icmp1,
	Source: apiv1.EntityRule{
		Tag:      "tag4",
		Net:      &cidrv62,
		Selector: "label2 == '1234'",
	},
}

var V1ModelEgressRule2 = model.Rule{
	Action:      "allow",
	IPVersion:   &ipv6,
	Protocol:    &v1strProtocol2,
	ICMPType:    &icmpType1,
	ICMPCode:    &icmpCode1,
	SrcTag:      "tag4",
	SrcNet:      &cidrv62,
	SrcSelector: "label2 == '1234'",
}

var V3EgressRule2 = apiv3.Rule{
	Action:    apiv3.Allow,
	IPVersion: &ipv6,
	Protocol:  &v3strProtocol2,
	ICMP:      &v3icmp1,
	Source: apiv3.EntityRule{
		Nets:     []string{cidrv62Str},
		Selector: "(label2 == '1234') && tag4 == ''",
	},
}
