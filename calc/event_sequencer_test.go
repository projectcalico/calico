// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package calc_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/calc"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
)

var _ = DescribeTable("ModelWorkloadEndpointToProto",
	func(in model.WorkloadEndpoint, expected proto.WorkloadEndpoint) {
		out := calc.ModelWorkloadEndpointToProto(&in, []*proto.TierInfo{})
		Expect(*out).To(Equal(expected))
	},
	Entry("workload endpoint with NAT", model.WorkloadEndpoint{
		State:      "up",
		Name:       "bill",
		Mac:        mustParseMac("01:02:03:04:05:06"),
		ProfileIDs: []string{},
		IPv4Nets:   []net.IPNet{mustParseNet("10.28.0.13/32")},
		IPv6Nets:   []net.IPNet{},
		IPv4NAT: []model.IPNAT{
			{
				IntIP: mustParseIP("10.28.0.13"),
				ExtIP: mustParseIP("172.16.1.3"),
			},
		},
		IPv6NAT: []model.IPNAT{},
	}, proto.WorkloadEndpoint{
		State:      "up",
		Name:       "bill",
		Mac:        "01:02:03:04:05:06",
		ProfileIds: []string{},
		Ipv4Nets:   []string{"10.28.0.13/32"},
		Ipv6Nets:   []string{},
		Tiers:      []*proto.TierInfo{},
		Ipv4Nat: []*proto.NatInfo{
			{
				ExtIp: "172.16.1.3",
				IntIp: "10.28.0.13",
			},
		},
		Ipv6Nat: []*proto.NatInfo{},
	}),
)

var _ = DescribeTable("ModelHostEndpointToProto",
	func(in model.HostEndpoint, tiers, untrackedTiers []*proto.TierInfo, expected proto.HostEndpoint) {
		out := calc.ModelHostEndpointToProto(&in, tiers, untrackedTiers, nil)
		Expect(*out).To(Equal(expected))
	},
	Entry("minimal endpoint",
		model.HostEndpoint{
			ExpectedIPv4Addrs: []net.IP{mustParseIP("10.28.0.13")},
		},
		nil,
		nil,
		proto.HostEndpoint{
			ExpectedIpv4Addrs: []string{"10.28.0.13"},
			ExpectedIpv6Addrs: []string{},
		},
	),
	Entry("fully loaded endpoint",
		model.HostEndpoint{
			Name:              "eth0",
			ExpectedIPv4Addrs: []net.IP{mustParseIP("10.28.0.13"), mustParseIP("10.28.0.14")},
			ExpectedIPv6Addrs: []net.IP{mustParseIP("dead::beef"), mustParseIP("dead::bee5")},
			Labels: map[string]string{
				"a": "b",
			},
			ProfileIDs: []string{"prof1"},
		},
		[]*proto.TierInfo{{Name: "a", Policies: []string{"b", "c"}}},
		[]*proto.TierInfo{{Name: "d", Policies: []string{"e", "f"}}},
		proto.HostEndpoint{
			Name:              "eth0",
			ExpectedIpv4Addrs: []string{"10.28.0.13", "10.28.0.14"},
			ExpectedIpv6Addrs: []string{"dead::beef", "dead::bee5"},
			Tiers:             []*proto.TierInfo{{Name: "a", Policies: []string{"b", "c"}}},
			UntrackedTiers:    []*proto.TierInfo{{Name: "d", Policies: []string{"e", "f"}}},
			ProfileIds:        []string{"prof1"},
		},
	),
	Entry("fully loaded endpoint with policies in same tier",
		model.HostEndpoint{
			Name:              "eth0",
			ExpectedIPv4Addrs: []net.IP{mustParseIP("10.28.0.13"), mustParseIP("10.28.0.14")},
			ExpectedIPv6Addrs: []net.IP{mustParseIP("dead::beef"), mustParseIP("dead::bee5")},
			Labels: map[string]string{
				"a": "b",
			},
			ProfileIDs: []string{"prof1"},
		},
		[]*proto.TierInfo{{Name: "a", Policies: []string{"b"}}},
		[]*proto.TierInfo{{Name: "a", Policies: []string{"c"}}},
		proto.HostEndpoint{
			Name:              "eth0",
			ExpectedIpv4Addrs: []string{"10.28.0.13", "10.28.0.14"},
			ExpectedIpv6Addrs: []string{"dead::beef", "dead::bee5"},
			Tiers:             []*proto.TierInfo{{Name: "a", Policies: []string{"b"}}},
			UntrackedTiers:    []*proto.TierInfo{{Name: "a", Policies: []string{"c"}}},
			ProfileIds:        []string{"prof1"},
		},
	),
)
