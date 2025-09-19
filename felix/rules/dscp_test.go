// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package rules_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/generictables"
	. "github.com/projectcalico/calico/felix/iptables"
	. "github.com/projectcalico/calico/felix/rules"
)

var _ = Describe("DSCP", func() {
	rrConfigNormal := Config{
		IPIPEnabled:  true,
		MarkAccept:   0x8,
		MarkPass:     0x10,
		MarkScratch0: 0x20,
		MarkScratch1: 0x40,
		MarkDrop:     0x80,
		MarkEndpoint: 0xff00,
	}

	var renderer RuleRenderer
	BeforeEach(func() {
		renderer = NewRenderer(rrConfigNormal)
	})

	It("should render empty chain for no policies", func() {
		Expect(renderer.EgressDSCPChain([]*DSCPRule{})).To(Equal(&generictables.Chain{
			Name:  ChainEgressDSCP,
			Rules: nil,
		}))
	})

	It("should render correct chain for policies", func() {
		rules := []*DSCPRule{
			{SrcAddrs: "192.168.10.20", Value: 10},
			{SrcAddrs: "192.168.10.100,172.17.1.100", Value: 40},
			{SrcAddrs: "192.168.20.1", Value: 0},
		}
		Expect(renderer.EgressDSCPChain(rules)).To(Equal(&generictables.Chain{
			Name: ChainEgressDSCP,
			Rules: []generictables.Rule{
				{
					Match:  Match().SourceNet("192.168.10.20"),
					Action: DSCPAction{Value: 10},
				},
				{
					Match:  Match().SourceNet("192.168.10.100,172.17.1.100"),
					Action: DSCPAction{Value: 40},
				},
				{
					Match:  Match().SourceNet("192.168.20.1"),
					Action: DSCPAction{Value: 0},
				},
			},
		}))
	})

	It("should render correct IPv6 chain for policies", func() {
		rules := []*DSCPRule{
			{SrcAddrs: "dead:beef::1:20", Value: 10},
			{SrcAddrs: "dead:beef::1:100,dead:beef::10:1", Value: 40},
			{SrcAddrs: "dead:beef::2:2", Value: 22},
		}
		Expect(renderer.EgressDSCPChain(rules)).To(Equal(&generictables.Chain{
			Name: ChainEgressDSCP,
			Rules: []generictables.Rule{
				{
					Match:  Match().SourceNet("dead:beef::1:20"),
					Action: DSCPAction{Value: 10},
				},
				{
					Match:  Match().SourceNet("dead:beef::1:100,dead:beef::10:1"),
					Action: DSCPAction{Value: 40},
				},
				{
					Match:  Match().SourceNet("dead:beef::2:2"),
					Action: DSCPAction{Value: 22},
				},
			},
		}))
	})
})
