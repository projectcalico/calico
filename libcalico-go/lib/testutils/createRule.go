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
	"log"
	"math"
	"net"
	"strconv"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// CreateRule takes all fields necessary to create a api.Rule object and returns ingress and egress api.Rules.
func CreateRule(ipv, icmpType, icmpCode int, proto, cidrStr, tag, selector, inAction, eAction string) (api.Rule, api.Rule) {

	var protocol numorstring.Protocol

	i, err := strconv.Atoi(proto)
	if err != nil {
		protocol = numorstring.ProtocolFromString(proto)
	} else {
		if i > math.MaxUint8 || i < 0 {
			log.Printf("i = %v should be between 0 and 255 \n", i)
		}
		protocol = numorstring.ProtocolFromInt(uint8(i))
	}

	icmp := api.ICMPFields{
		Type: &icmpType,
		Code: &icmpCode,
	}

	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		log.Printf("Error parsing CIDR: %v\n", err)
	}

	src := api.EntityRule{
		Tag: tag,
		Net: &cnet.IPNet{
			*cidr,
		},
		Selector: selector,
	}

	inRule := api.Rule{
		Action:    inAction,
		IPVersion: &ipv,
		Protocol:  &protocol,
		ICMP:      &icmp,
		Source:    src,
	}

	eRule := api.Rule{
		Action:    eAction,
		IPVersion: &ipv,
		Protocol:  &protocol,
		ICMP:      &icmp,
	}

	return inRule, eRule
}
