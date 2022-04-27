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

package converter_test

import (
	. "github.com/projectcalico/calico/libcalico-go/lib/converter"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	cidr1    = net.MustParseCIDR("10.0.0.1/24")
	cidr2    = net.MustParseCIDR("11.0.0.1/24")
	cidr3    = net.MustParseCIDR("12.0.0.1/24")
	cidr4    = net.MustParseCIDR("13.0.0.1/24")
	cidr1Net = net.MustParseNetwork("10.0.0.0/24")
	cidr2Net = net.MustParseNetwork("11.0.0.0/24")
	cidr3Net = net.MustParseNetwork("12.0.0.0/24")
	cidr4Net = net.MustParseNetwork("13.0.0.0/24")
)

var _ = DescribeTable("RulesAPIToBackend",
	func(input api.Rule, expected model.Rule) {
		output := RulesAPIToBackend([]api.Rule{input})
		Expect(output).To(ConsistOf(expected))
	},
	Entry("empty rule", api.Rule{}, model.Rule{}),
	Entry("should normalize source and destination net fields",
		api.Rule{
			Source: api.EntityRule{
				Net:    &cidr1,
				NotNet: &cidr2,
			},
			Destination: api.EntityRule{
				Net:    &cidr3,
				NotNet: &cidr4,
			},
		},
		model.Rule{
			SrcNet:    &cidr1Net,
			NotSrcNet: &cidr2Net,
			DstNet:    &cidr3Net,
			NotDstNet: &cidr4Net,
		},
	),
	Entry("should normalize source and destination nets fields",
		api.Rule{
			Source: api.EntityRule{
				Nets:    []*net.IPNet{&cidr1},
				NotNets: []*net.IPNet{&cidr2},
			},
			Destination: api.EntityRule{
				Nets:    []*net.IPNet{&cidr3},
				NotNets: []*net.IPNet{&cidr4},
			},
		},
		model.Rule{
			SrcNets:    []*net.IPNet{&cidr1Net},
			NotSrcNets: []*net.IPNet{&cidr2Net},
			DstNets:    []*net.IPNet{&cidr3Net},
			NotDstNets: []*net.IPNet{&cidr4Net},
		},
	),
)

var _ = DescribeTable("RulesBackendToAPI",
	func(input model.Rule, expected api.Rule) {
		output := RulesBackendToAPI([]model.Rule{input})
		Expect(output).To(ConsistOf(expected))
	},
	Entry("empty rule should get explicit action", model.Rule{}, api.Rule{Action: "allow"}),
	Entry("should convert net to nets fields",
		model.Rule{
			SrcNet:    &cidr1,
			NotSrcNet: &cidr2,
			DstNet:    &cidr3,
			NotDstNet: &cidr4,
		},
		api.Rule{
			Action: "allow",
			Source: api.EntityRule{
				Nets:    []*net.IPNet{&cidr1Net},
				NotNets: []*net.IPNet{&cidr2Net},
			},
			Destination: api.EntityRule{
				Nets:    []*net.IPNet{&cidr3Net},
				NotNets: []*net.IPNet{&cidr4Net},
			},
		},
	),
	Entry("should pass through nets fields",
		model.Rule{
			SrcNets:    []*net.IPNet{&cidr1},
			NotSrcNets: []*net.IPNet{&cidr2},
			DstNets:    []*net.IPNet{&cidr3},
			NotDstNets: []*net.IPNet{&cidr4},
		},
		api.Rule{
			Action: "allow",
			Source: api.EntityRule{
				Nets:    []*net.IPNet{&cidr1Net},
				NotNets: []*net.IPNet{&cidr2Net},
			},
			Destination: api.EntityRule{
				Nets:    []*net.IPNet{&cidr3Net},
				NotNets: []*net.IPNet{&cidr4Net},
			},
		},
	),
)
