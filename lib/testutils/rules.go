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
	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/sirupsen/logrus"
)

var ipv4 = 4
var ipv6 = 6
var strProtocol1 = numorstring.ProtocolFromString("icmp")
var strProtocol2 = numorstring.ProtocolFromString("udp")
var numProtocol1 = numorstring.ProtocolFromInt(240)

var portRange, singlePort, namedPort numorstring.Port

func init() {
	var err error
	portRange, err = numorstring.PortFromRange(10, 20)
	if err != nil {
		logrus.WithError(err).Panic("Failed to create port range")
	}
	singlePort = numorstring.SinglePort(1024)
	namedPort = numorstring.NamedPort("named-port")
}

var icmpType1 = 100
var icmpCode1 = 200

var cidr1 = "10.0.0.0/24"
var cidr2 = "20.0.0.0/24"
var cidrv61 = "abcd:5555::/120"
var cidrv62 = "abcd:2345::/120"

var icmp1 = apiv2.ICMPFields{
	Type: &icmpType1,
	Code: &icmpCode1,
}

var InRule1 = apiv2.Rule{
	Action:    "allow",
	IPVersion: &ipv4,
	Protocol:  &strProtocol1,
	ICMP:      &icmp1,
	Source: apiv2.EntityRule{
		Nets:     []string{cidr1},
		Selector: "label1 == 'value1'",
		Ports: []numorstring.Port{
			portRange,
			singlePort,
			namedPort,
		},
	},
}

var InRule2 = apiv2.Rule{
	Action:    "deny",
	IPVersion: &ipv6,
	Protocol:  &numProtocol1,
	ICMP:      &icmp1,
	Source: apiv2.EntityRule{
		Nets:     []string{cidrv61},
		Selector: "has(label2)",
	},
}

var EgressRule1 = apiv2.Rule{
	Action:    "pass",
	IPVersion: &ipv4,
	Protocol:  &numProtocol1,
	ICMP:      &icmp1,
	Source: apiv2.EntityRule{
		Nets:     []string{cidr2},
		Selector: "all()",
	},
}

var EgressRule2 = apiv2.Rule{
	Action:    "allow",
	IPVersion: &ipv6,
	Protocol:  &strProtocol2,
	ICMP:      &icmp1,
	Source: apiv2.EntityRule{
		Nets:     []string{cidrv62},
		Selector: "label2 == '1234'",
	},
}
