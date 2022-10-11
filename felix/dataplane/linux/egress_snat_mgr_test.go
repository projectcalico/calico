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

package intdataplane

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

func expectedEgressSNATChain(ipSetName string, snats ...snat) *iptables.Chain {
	rules := []iptables.Rule{}
	for _, snat := range snats {
		rules = append(rules, iptables.Rule{
			Match:  iptables.Match().NotDestIPSet(ipSetName).SourceNet(snat.intIP),
			Action: iptables.SNATAction{ToAddr: snat.extIP},

		})
	}
	return &iptables.Chain{
		Name:  "cali-nat-egress",
		Rules: rules,
	}
}

func egressSNATManagerTests(ipVersion uint8) func() {
	return func() {
		var (
			egressSNATMgr *egressSNATManager
			natTable       *mockTable
			rrConfigNormal rules.Config
			allIPsSetName string
		)

		BeforeEach(func() {
			rrConfigNormal = rules.Config{
				IPIPEnabled:          true,
				IPIPTunnelAddress:    nil,
				IPSetConfigV4:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
				IPSetConfigV6:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
				IptablesMarkAccept:   0x8,
				IptablesMarkPass:     0x10,
				IptablesMarkScratch0: 0x20,
				IptablesMarkScratch1: 0x40,
				IptablesMarkEndpoint: 0xff00,
			}
		})

		JustBeforeEach(func() {
			renderer := rules.NewRenderer(rrConfigNormal)
			if ipVersion == 4 {
				allIPsSetName = rrConfigNormal.IPSetConfigV4.NameForMainIPSet("all-ipam-pools")
			} else if ipVersion == 6 {
				allIPsSetName = rrConfigNormal.IPSetConfigV6.NameForMainIPSet("all-ipam-pools")
			}
			natTable = newMockTable("nat")
			egressSNATMgr = newEgressSNATManager(natTable, renderer, ipVersion, true)
		})

		It("should be constructable", func() {
			Expect(egressSNATMgr).ToNot(BeNil())
		})

		Context("with egressSNAT enabled", func() {
			JustBeforeEach(func() {
				egressSNATMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						OrchestratorId: "k8s",
						WorkloadId:     "pod-11",
						EndpointId:     "endpoint-id-11",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State:      "up",
						Mac:        "01:02:03:04:05:06",
						Name:       "cali12345-ab",
						ProfileIds: []string{},
						Tiers:      []*proto.TierInfo{},
						Ipv4Nets:   []string{"10.0.240.2/24"},
						Ipv6Nets:   []string{"2001:db8:2::2/128"},
					},
				})
				err := egressSNATMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should have empty egressSNAT chains", func() {
				natTable.checkChains([][]*iptables.Chain{{
					expectedEgressSNATChain(allIPsSetName),
				}})
			})

			Context("with egressSNAT added to the endpoint", func() {
				JustBeforeEach(func() {
					egressSNATMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
						Id: &proto.WorkloadEndpointID{
							OrchestratorId: "k8s",
							WorkloadId:     "pod-11",
							EndpointId:     "endpoint-id-11",
						},
						Endpoint: &proto.WorkloadEndpoint{
							State:      "up",
							Mac:        "01:02:03:04:05:06",
							Name:       "cali12345-ab",
							ProfileIds: []string{},
							Tiers:      []*proto.TierInfo{},
							Ipv4Nets:   []string{"10.0.240.2/24"},
							Ipv6Nets:   []string{"2001:db8:2::2/128"},
							Ipv4Snat: []*proto.NatInfo{
								{ExtIp: "172.16.1.3", IntIp: "10.0.240.2"},
								{ExtIp: "172.18.1.4", IntIp: "10.0.240.2"},
							},
							Ipv6Snat: []*proto.NatInfo{
								{ExtIp: "2001:db8:3::2", IntIp: "2001:db8:2::2"},
								{ExtIp: "2001:db8:4::2", IntIp: "2001:db8:2::2"},
							},
						},
					})
					err := egressSNATMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				It("should have expected egressSNAT chains", func() {
					if ipVersion == 4 {
						natTable.checkChains([][]*iptables.Chain{{
							expectedEgressSNATChain(allIPsSetName, []snat{
								{extIP: "172.16.1.3", intIP: "10.0.240.2"},
							}...),
						}})
					} else {
						natTable.checkChains([][]*iptables.Chain{{
							expectedEgressSNATChain(allIPsSetName, []snat{
								{extIP: "2001:db8:3::2", intIP: "2001:db8:2::2"},
							}...),
						}})
					}
				})

				Context("with the endpoint removed", func() {
					JustBeforeEach(func() {
						egressSNATMgr.OnUpdate(&proto.WorkloadEndpointRemove{
							Id: &proto.WorkloadEndpointID{
								OrchestratorId: "k8s",
								WorkloadId:     "pod-11",
								EndpointId:     "endpoint-id-11",
							},
						})
						err := egressSNATMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})

					It("should have empty egressSNAT chains", func() {
						natTable.checkChains([][]*iptables.Chain{{
							expectedEgressSNATChain(allIPsSetName),
						}})
					})
				})
			})
		})

		Context("with egressSNAT disabled", func() {
			JustBeforeEach(func() {
				egressSNATMgr.enabled = false
				egressSNATMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						OrchestratorId: "k8s",
						WorkloadId:     "pod-11",
						EndpointId:     "endpoint-id-11",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State:      "up",
						Mac:        "01:02:03:04:05:06",
						Name:       "cali12345-ab",
						ProfileIds: []string{},
						Tiers:      []*proto.TierInfo{},
						Ipv4Nets:   []string{"10.0.240.2/24"},
						Ipv6Nets:   []string{"2001:db8:2::2/128"},
						Ipv4Snat: []*proto.NatInfo{
							{ExtIp: "172.16.1.3", IntIp: "10.0.240.2"},
							{ExtIp: "172.18.1.4", IntIp: "10.0.240.2"},
						},
						Ipv6Snat: []*proto.NatInfo{
							{ExtIp: "2001:db8:3::2", IntIp: "2001:db8:2::2"},
							{ExtIp: "2001:db8:4::2", IntIp: "2001:db8:2::2"},
						},
					},
				})
				err := egressSNATMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should have empty egressSNAT chains", func() {
				natTable.checkChains([][]*iptables.Chain{{
					expectedEgressSNATChain(allIPsSetName),
				}})
			})

			Context("with the endpoint removed", func() {
				JustBeforeEach(func() {
					egressSNATMgr.OnUpdate(&proto.WorkloadEndpointRemove{
						Id: &proto.WorkloadEndpointID{
							OrchestratorId: "k8s",
							WorkloadId:     "pod-11",
							EndpointId:     "endpoint-id-11",
						},
					})
					err := egressSNATMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				It("should have empty egressSNAT chains", func() {
					natTable.checkChains([][]*iptables.Chain{{
						expectedEgressSNATChain(allIPsSetName),
					}})
				})
			})
		})
	}
}

var _ = Describe("EgressSNATManager IPv4", egressSNATManagerTests(4))

var _ = Describe("EgressSNATManager IPv6", egressSNATManagerTests(6))
