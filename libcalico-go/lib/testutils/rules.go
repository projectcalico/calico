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
	"github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
)

var InRule1, InRule2, EgressRule1, EgressRule2 apiv3.Rule

func init() {
	portRange, err := numorstring.PortFromRange(10, 20)
	if err != nil {
		logrus.WithError(err).Panic("Failed to create port range")
	}
	singlePort := numorstring.SinglePort(1024)
	namedPort := numorstring.NamedPort("named-port")

	ipv4 := 4
	ipv6 := 6
	strProtocol1 := numorstring.ProtocolFromString("TCP")
	strProtocolIcmpv6 := numorstring.ProtocolFromString("ICMPv6")
	numProtocol1 := numorstring.ProtocolFromInt(240)

	icmpType1 := 100
	icmpCode1 := 200

	cidr1 := "10.0.0.0/24"
	cidr2 := "20.0.0.0/24"
	cidrv61 := "abcd:5555::/120"
	cidrv62 := "abcd:2345::/120"

	icmp1 := apiv3.ICMPFields{
		Type: &icmpType1,
		Code: &icmpCode1,
	}

	InRule1 = apiv3.Rule{
		Action:    "Allow",
		IPVersion: &ipv4,
		Protocol:  &strProtocol1,
		Source: apiv3.EntityRule{
			Nets:     []string{cidr1},
			Selector: "label1 == 'value1'",
			Ports: []numorstring.Port{
				portRange,
				singlePort,
				namedPort,
			},
		},
	}

	InRule2 = apiv3.Rule{
		Action:    "Deny",
		IPVersion: &ipv6,
		Protocol:  &strProtocolIcmpv6,
		ICMP:      &icmp1,
		Source: apiv3.EntityRule{
			Nets:     []string{cidrv61},
			Selector: "has(label2)",
		},
	}

	EgressRule1 = apiv3.Rule{
		Action:    "Pass",
		IPVersion: &ipv4,
		Protocol:  &numProtocol1,
		Source: apiv3.EntityRule{
			Nets:     []string{cidr2},
			Selector: "all()",
		},
	}

	EgressRule2 = apiv3.Rule{
		Action:    "Allow",
		IPVersion: &ipv6,
		Protocol:  &strProtocolIcmpv6,
		ICMP:      &icmp1,
		Source: apiv3.EntityRule{
			Nets:     []string{cidrv62},
			Selector: "label2 == '1234'",
		},
	}
}
