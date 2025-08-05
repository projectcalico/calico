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

package intdataplane

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

var _ = Describe("QoS policy manager", func() {
	var (
		manager      *qosPolicyManager
		mangleTable  *mockTable
		ruleRenderer rules.RuleRenderer
	)

	BeforeEach(func() {
		mangleTable = newMockTable("mangle")
		ruleRenderer = rules.NewRenderer(rules.Config{
			IPSetConfigV4: ipsets.NewIPVersionConfig(
				ipsets.IPFamilyV4,
				"cali",
				nil,
				nil,
			),
			MarkPass:     0x1,
			MarkAccept:   0x2,
			MarkScratch0: 0x4,
			MarkScratch1: 0x8,
			MarkDrop:     0x10,
			MarkEndpoint: 0x11110000,
		})
		manager = newQoSPolicyManager(mangleTable, ruleRenderer, 4)
	})

	Describe("QoS policy: after adding a workload with DSCP annotation", func() {
		BeforeEach(func() {
			manager.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "pool-1",
				Pool: &proto.IPAMPool{
					Cidr: "10.0.0.0/16",
				},
			})
			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should program QoS policy chain with no rule", func() {
			mangleTable.checkChains([][]*generictables.Chain{{{
				Name:  rules.ChainQoSPolicy,
				Rules: nil,
			}}})
		})

		It("should handle workload updates correctly", func() {
			By("sending workload endpoint updates with DSCP annotion")
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &wlEPID1,
				Endpoint: &proto.WorkloadEndpoint{
					State:       "active",
					Name:        "cali12345-ab",
					Ipv4Nets:    []string{"10.0.240.2/24"},
					Ipv6Nets:    []string{"2001:db8:2::2/128"},
					QosPolicies: []*proto.QoSPolicy{{Dscp: 44}},
				},
			})

			err := manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQoSPolicy,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 44},
						Match: iptables.Match().
							SourceNet("10.0.240.2"),
					},
				},
			}}})

			By("sending another workload endpoint updates with DSCP annotion")
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &wlEPID2,
				Endpoint: &proto.WorkloadEndpoint{
					State:       "active",
					Name:        "cali2",
					Ipv4Nets:    []string{"10.0.240.3/24"},
					Ipv6Nets:    []string{"2001:db8:2::3/128"},
					QosPolicies: []*proto.QoSPolicy{{Dscp: 20}},
				},
			})

			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQoSPolicy,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 44},
						Match: iptables.Match().
							SourceNet("10.0.240.2"),
					},
					{
						Action: iptables.DSCPAction{Value: 20},
						Match: iptables.Match().
							SourceNet("10.0.240.3"),
					},
				},
			}}})

			By("verifying update to DSCP value takes effect")
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &wlEPID1,
				Endpoint: &proto.WorkloadEndpoint{
					State:       "active",
					Name:        "cali12345-ab",
					Ipv4Nets:    []string{"10.0.240.2/24"},
					Ipv6Nets:    []string{"2001:db8:2::2/128"},
					QosPolicies: []*proto.QoSPolicy{{Dscp: 13}},
				},
			})

			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQoSPolicy,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 13},
						Match: iptables.Match().
							SourceNet("10.0.240.2"),
					},
					{
						Action: iptables.DSCPAction{Value: 20},
						Match: iptables.Match().
							SourceNet("10.0.240.3"),
					},
				},
			}}})

			By("verifying QoS policy rules removed when annotation is removed")
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &wlEPID1,
				Endpoint: &proto.WorkloadEndpoint{
					State:    "active",
					Name:     "cali12345-ab",
					Ipv4Nets: []string{"10.0.240.2/24"},
					Ipv6Nets: []string{"2001:db8:2::2/128"},
				},
			})

			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQoSPolicy,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 20},
						Match: iptables.Match().
							SourceNet("10.0.240.3"),
					},
				},
			}}})

			By("verifying QoS policy rules removed when workload is removed")
			manager.OnUpdate(&proto.WorkloadEndpointRemove{
				Id: &wlEPID2,
			})

			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name:  rules.ChainQoSPolicy,
				Rules: nil,
			}}})
		})
	})
})
