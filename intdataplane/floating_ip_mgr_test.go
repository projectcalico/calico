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
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
)

type dnat struct {
	extIP string
	intIP string
}

type snat struct {
	intIP string
	extIP string
}

func expectedDNATChain(dnats ...dnat) *iptables.Chain {
	rules := []iptables.Rule{}
	for _, dnat := range dnats {
		rules = append(rules, iptables.Rule{
			Match:  iptables.Match().DestNet(dnat.extIP),
			Action: iptables.DNATAction{DestAddr: dnat.intIP},
		})
	}
	return &iptables.Chain{
		Name:  "cali-fip-dnat",
		Rules: rules,
	}
}

func expectedSNATChain(snats ...snat) *iptables.Chain {
	rules := []iptables.Rule{}
	for _, snat := range snats {
		rules = append(rules, iptables.Rule{
			Match:  iptables.Match().DestNet(snat.intIP).SourceNet(snat.intIP),
			Action: iptables.SNATAction{ToAddr: snat.extIP},
		})
	}
	return &iptables.Chain{
		Name:  "cali-fip-snat",
		Rules: rules,
	}
}

func floatingIPManagerTests(ipVersion uint8) func() {
	return func() {
		var (
			fipMgr         *floatingIPManager
			natTable       *mockTable
			rrConfigNormal rules.Config
		)

		BeforeEach(func() {
			rrConfigNormal = rules.Config{
				IPIPEnabled:          true,
				IPIPTunnelAddress:    nil,
				IPSetConfigV4:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
				IPSetConfigV6:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
				IptablesMarkAccept:   0x8,
				IptablesMarkNextTier: 0x10,
			}
		})

		JustBeforeEach(func() {
			renderer := rules.NewRenderer(rrConfigNormal)
			natTable = newMockTable("nat")
			fipMgr = newFloatingIPManager(natTable, renderer, ipVersion)
		})

		It("should be constructable", func() {
			Expect(fipMgr).ToNot(BeNil())
		})

		Context("with a workload endpoint", func() {
			JustBeforeEach(func() {
				fipMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
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
				fipMgr.CompleteDeferredWork()
			})

			It("should have empty NAT chains", func() {
				natTable.checkChains([][]*iptables.Chain{{
					expectedDNATChain(),
					expectedSNATChain(),
				}})
			})

			Context("with floating IPs added to the endpoint", func() {
				JustBeforeEach(func() {
					fipMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
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
							Ipv4Nat: []*proto.NatInfo{
								{ExtIp: "172.16.1.3", IntIp: "10.0.240.2"},
								{ExtIp: "172.18.1.4", IntIp: "10.0.240.2"},
							},
							Ipv6Nat: []*proto.NatInfo{
								{ExtIp: "2001:db8:3::2", IntIp: "2001:db8:2::2"},
								{ExtIp: "2001:db8:4::2", IntIp: "2001:db8:2::2"},
							},
						},
					})
					fipMgr.CompleteDeferredWork()
				})

				It("should have expected NAT chains", func() {
					if ipVersion == 4 {
						natTable.checkChains([][]*iptables.Chain{{
							expectedDNATChain([]dnat{
								{extIP: "172.16.1.3", intIP: "10.0.240.2"},
								{extIP: "172.18.1.4", intIP: "10.0.240.2"},
							}...),
							expectedSNATChain([]snat{
								{extIP: "172.16.1.3", intIP: "10.0.240.2"},
							}...),
						}})
					} else {
						natTable.checkChains([][]*iptables.Chain{{
							expectedDNATChain([]dnat{
								{extIP: "2001:db8:3::2", intIP: "2001:db8:2::2"},
								{extIP: "2001:db8:4::2", intIP: "2001:db8:2::2"},
							}...),
							expectedSNATChain([]snat{
								{extIP: "2001:db8:3::2", intIP: "2001:db8:2::2"},
							}...),
						}})
					}
				})

				Context("with the endpoint removed", func() {
					JustBeforeEach(func() {
						fipMgr.OnUpdate(&proto.WorkloadEndpointRemove{
							Id: &proto.WorkloadEndpointID{
								OrchestratorId: "k8s",
								WorkloadId:     "pod-11",
								EndpointId:     "endpoint-id-11",
							},
						})
						fipMgr.CompleteDeferredWork()
					})

					It("should have empty NAT chains", func() {
						natTable.checkChains([][]*iptables.Chain{{
							expectedDNATChain(),
							expectedSNATChain(),
						}})
					})
				})
			})
		})
	}
}

var _ = Describe("FloatingIPManager IPv4", floatingIPManagerTests(4))

var _ = Describe("FloatingIPManager IPv6", floatingIPManagerTests(6))
