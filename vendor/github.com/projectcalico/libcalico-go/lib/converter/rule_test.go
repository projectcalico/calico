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
	. "github.com/projectcalico/libcalico-go/lib/converter"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
)

var (
	cidr1     = net.MustParseCIDR("10.0.0.1/24")
	cidr2     = net.MustParseCIDR("11.0.0.1/24")
	cidr3     = net.MustParseCIDR("12.0.0.1/24")
	cidr4     = net.MustParseCIDR("13.0.0.1/24")
	cidr3Net  = net.MustParseCIDR("12.0.0.0/24")
	cidr4Net  = net.MustParseCIDR("13.0.0.0/24")
	cidr3Norm = (&cidr3Net).Network()
	cidr4Norm = (&cidr4Net).Network()
)

var _ = DescribeTable("RulesAPIToBackend",
	func(input api.Rule, expected model.Rule) {
		output := RulesAPIToBackend([]api.Rule{input})
		Expect(output).To(ConsistOf(expected))
	},
	Entry("empty rule", api.Rule{}, model.Rule{}),
	Entry("should normalise destination net fields",
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
			SrcNet:    &cidr1,
			NotSrcNet: &cidr2,
			DstNet:    cidr3Norm,
			NotDstNet: cidr4Norm,
		},
	),
	Entry("should normalise destination nets fields",
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
			SrcNets:    []*net.IPNet{&cidr1},
			NotSrcNets: []*net.IPNet{&cidr2},
			DstNets:    []*net.IPNet{cidr3Norm},
			NotDstNets: []*net.IPNet{cidr4Norm},
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
				Nets:    []*net.IPNet{&cidr1},
				NotNets: []*net.IPNet{&cidr2},
			},
			Destination: api.EntityRule{
				Nets:    []*net.IPNet{&cidr3},
				NotNets: []*net.IPNet{&cidr4},
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
				Nets:    []*net.IPNet{&cidr1},
				NotNets: []*net.IPNet{&cidr2},
			},
			Destination: api.EntityRule{
				Nets:    []*net.IPNet{&cidr3},
				NotNets: []*net.IPNet{&cidr4},
			},
		},
	),
)
