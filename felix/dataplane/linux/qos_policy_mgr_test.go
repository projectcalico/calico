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
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

var _ = Describe("QoS policy manager IPv4", qosPolicyManagerTests(4))
var _ = Describe("QoS policy manager IPv6", qosPolicyManagerTests(6))

func qosPolicyManagerTests(ipVersion uint8) func() {
	return func() {
		var (
			manager      *qosPolicyManager
			mangleTable  *mockTable
			ruleRenderer rules.RuleRenderer
		)

		BeforeEach(func() {
			mangleTable = newMockTable("mangle")
			ruleRenderer = rules.NewRenderer(rules.Config{
				MarkPass:     0x1,
				MarkAccept:   0x2,
				MarkScratch0: 0x4,
				MarkScratch1: 0x8,
				MarkDrop:     0x10,
				MarkEndpoint: 0x11110000,
			})
			manager = newQoSPolicyManager(mangleTable, ruleRenderer, ipVersion)
		})

		It("should program QoS policy chain with no rule", func() {
			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			mangleTable.checkChains([][]*generictables.Chain{{{
				Name:  rules.ChainQoSPolicy,
				Rules: nil,
			}}})
		})

		It("should handle workload updates correctly", func() {
			By("sending workload endpoint updates with DSCP annotion")
			endpoint1 := &proto.WorkloadEndpoint{
				State:       "active",
				Name:        "cali12345-ab",
				Ipv4Nets:    []string{"10.0.240.2/24", "20.0.240.2/24"},
				Ipv6Nets:    []string{"2001:db8:2::2/112", "dead:beef::2/112"},
				QosPolicies: []*proto.QoSPolicy{{Dscp: 44}},
			}
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id:       &wlEPID1,
				Endpoint: endpoint1,
			})

			err := manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQoSPolicy,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 44},
						Match:  iptables.Match().SourceNet(addrFromWlUpdate(endpoint1, ipVersion)),
					},
				},
			}}})

			By("sending another workload endpoint updates with DSCP annotion")
			endpoint2 := &proto.WorkloadEndpoint{
				State:       "active",
				Name:        "cali2",
				Ipv4Nets:    []string{"10.0.240.1/24"},
				Ipv6Nets:    []string{"2001:db8:2::1/112"},
				QosPolicies: []*proto.QoSPolicy{{Dscp: 20}},
			}
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id:       &wlEPID2,
				Endpoint: endpoint2,
			})

			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQoSPolicy,
				Rules: []generictables.Rule{
					// Rendered policies are sorted.
					{
						Action: iptables.DSCPAction{Value: 20},
						Match:  iptables.Match().SourceNet(addrFromWlUpdate(endpoint2, ipVersion)),
					},
					{
						Action: iptables.DSCPAction{Value: 44},
						Match:  iptables.Match().SourceNet(addrFromWlUpdate(endpoint1, ipVersion)),
					},
				},
			}}})

			By("verifying update to DSCP value takes effect")
			endpoint1.QosPolicies = []*proto.QoSPolicy{{Dscp: 13}}
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id:       &wlEPID1,
				Endpoint: endpoint1,
			})

			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQoSPolicy,
				Rules: []generictables.Rule{
					// Rendered policies are sorted.
					{
						Action: iptables.DSCPAction{Value: 20},
						Match:  iptables.Match().SourceNet(addrFromWlUpdate(endpoint2, ipVersion)),
					},
					{
						Action: iptables.DSCPAction{Value: 13},
						Match:  iptables.Match().SourceNet(addrFromWlUpdate(endpoint1, ipVersion)),
					},
				},
			}}})

			By("verifying QoS policy rules removed when annotation is removed")
			endpoint1.QosPolicies = nil
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id:       &wlEPID1,
				Endpoint: endpoint1,
			})

			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQoSPolicy,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 20},
						Match:  iptables.Match().SourceNet(addrFromWlUpdate(endpoint2, ipVersion)),
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
	}
}

func addrFromWlUpdate(endpoint *proto.WorkloadEndpoint, ipVersion uint8) string {
	addr := endpoint.Ipv4Nets
	if ipVersion == 6 {
		addr = endpoint.Ipv6Nets
	}
	return normaliseSourceAddr(addr)
}
