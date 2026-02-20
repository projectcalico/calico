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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	_ = Describe("DSCP manager - IPv4", dscpManagerTests(4))
	_ = Describe("DSCP manager - IPv6", dscpManagerTests(6))
)

func dscpManagerTests(ipVersion uint8) func() {
	return func() {
		var (
			manager      *dscpManager
			ipSets       *dpsets.MockIPSets
			mangleTable  *mockTable
			ruleRenderer rules.RuleRenderer
		)

		BeforeEach(func() {
			ipSets = dpsets.NewMockIPSets()
			mangleTable = newMockTable("mangle")
			ruleRenderer = rules.NewRenderer(rules.Config{
				MarkPass:     0x1,
				MarkAccept:   0x2,
				MarkScratch0: 0x4,
				MarkScratch1: 0x8,
				MarkDrop:     0x10,
				MarkEndpoint: 0x11110000,
			}, false)
			manager = newDSCPManager(ipSets, mangleTable, ruleRenderer, ipVersion,
				Config{
					MaxIPSetSize: 1024,
					Hostname:     "node1",
				})
		})

		dscpSet := func() set.Set[string] {
			logrus.Info(ipSets.Members)
			Expect(ipSets.Members).To(HaveLen(1))

			return ipSets.Members["dscp-src-net"]
		}

		It("should handle endpoint updates correctly", func() {
			By("checking initial state")
			Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
			err := manager.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name:  rules.ChainEgressDSCP,
				Rules: nil,
			}}})
			members := dscpSet()
			Expect(members.Slice()).To(BeNil())

			By("sending first workload endpoint update with DSCP annotation")
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

			ipSets.AddOrReplaceCalled = false // Reset
			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainEgressDSCP,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 44},
						Match:  iptables.Match().SourceNet(addrFromWlUpdate(endpoint1, ipVersion)),
					},
				},
			}}})

			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			members.AddAll(ipsetMembersFromWlUpdate(endpoint1, ipVersion))
			Expect(dscpSet()).To(Equal(members))

			By("sending another workload endpoint update with DSCP annotation")
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

			ipSets.AddOrReplaceCalled = false // Reset
			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainEgressDSCP,
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

			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			members.AddAll(ipsetMembersFromWlUpdate(endpoint2, ipVersion))
			Expect(dscpSet()).To(Equal(members))

			By("verifying update to first workload DSCP value")
			endpoint1.QosPolicies = []*proto.QoSPolicy{{Dscp: 13}}
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id:       &wlEPID1,
				Endpoint: endpoint1,
			})

			ipSets.AddOrReplaceCalled = false // Reset
			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainEgressDSCP,
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

			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			Expect(dscpSet()).To(Equal(members))

			By("sending a host endpoint update with DSCP annotation")
			hep1ID := &proto.HostEndpointID{
				EndpointId: "id1",
			}
			hep1 := &proto.HostEndpoint{
				Name:              "eth0",
				ExpectedIpv4Addrs: []string{"192.168.1.2", "192.168.2.2"},
				ExpectedIpv6Addrs: []string{"2001:db9:10::2", "dead:beff::20:2"},
				QosPolicies:       []*proto.QoSPolicy{{Dscp: 44}},
			}
			manager.OnUpdate(&proto.HostEndpointUpdate{
				Id:       hep1ID,
				Endpoint: hep1,
			})

			ipSets.AddOrReplaceCalled = false // Reset
			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainEgressDSCP,
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
					{
						Action: iptables.DSCPAction{Value: 44},
						Match:  iptables.Match().SourceNet(addrFromHepUpdate(hep1, ipVersion)),
					},
				},
			}}})

			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			members.AddAll(ipsetMembersFromHepUpdate(hep1, ipVersion))
			Expect(dscpSet()).To(Equal(members))

			By("verifying update to host endpoint DSCP value")
			hep1.QosPolicies = []*proto.QoSPolicy{{Dscp: 30}}
			manager.OnUpdate(&proto.HostEndpointUpdate{
				Id:       hep1ID,
				Endpoint: hep1,
			})

			ipSets.AddOrReplaceCalled = false // Reset
			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainEgressDSCP,
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
					{
						Action: iptables.DSCPAction{Value: 30},
						Match:  iptables.Match().SourceNet(addrFromHepUpdate(hep1, ipVersion)),
					},
				},
			}}})

			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			Expect(dscpSet()).To(Equal(members))

			By("verifying DSCP rule removed when first workload annotation is removed")
			endpoint1.QosPolicies = nil
			manager.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id:       &wlEPID1,
				Endpoint: endpoint1,
			})

			ipSets.AddOrReplaceCalled = false // Reset
			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainEgressDSCP,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 20},
						Match:  iptables.Match().SourceNet(addrFromWlUpdate(endpoint2, ipVersion)),
					},
					{
						Action: iptables.DSCPAction{Value: 30},
						Match:  iptables.Match().SourceNet(addrFromHepUpdate(hep1, ipVersion)),
					},
				},
			}}})

			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			for _, v := range ipsetMembersFromWlUpdate(endpoint1, ipVersion) {
				members.Discard(v)
			}
			Expect(dscpSet()).To(Equal(members))

			By("verifying DSCP rule removed when second workload is removed")
			manager.OnUpdate(&proto.WorkloadEndpointRemove{
				Id: &wlEPID2,
			})

			ipSets.AddOrReplaceCalled = false // Reset
			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainEgressDSCP,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 30},
						Match:  iptables.Match().SourceNet(addrFromHepUpdate(hep1, ipVersion)),
					},
				},
			}}})

			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			for _, v := range ipsetMembersFromWlUpdate(endpoint2, ipVersion) {
				members.Discard(v)
			}
			Expect(dscpSet()).To(Equal(members))

			By("verifying DSCP rule removed when host endpoint is removed")
			manager.OnUpdate(&proto.HostEndpointRemove{
				Id: hep1ID,
			})

			ipSets.AddOrReplaceCalled = false // Reset
			err = manager.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			mangleTable.checkChains([][]*generictables.Chain{{{
				Name:  rules.ChainEgressDSCP,
				Rules: nil,
			}}})

			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			for _, v := range ipsetMembersFromHepUpdate(hep1, ipVersion) {
				members.Discard(v)
			}
			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			Expect(members.Slice()).To(BeNil())
		})
	}
}

func addrFromWlUpdate(endpoint *proto.WorkloadEndpoint, ipVersion uint8) string {
	addrs := endpoint.Ipv4Nets
	if ipVersion == 6 {
		addrs = endpoint.Ipv6Nets
	}
	return addrFromUpdate(addrs)
}

func addrFromHepUpdate(endpoint *proto.HostEndpoint, ipVersion uint8) string {
	addrs := endpoint.ExpectedIpv4Addrs
	if ipVersion == 6 {
		addrs = endpoint.ExpectedIpv6Addrs
	}
	return addrFromUpdate(addrs)
}

func addrFromUpdate(addrs []string) string {
	normalisedAddr, err := normaliseSourceAddr(addrs)
	Expect(err).ToNot(HaveOccurred())
	return normalisedAddr
}

func ipsetMembersFromWlUpdate(endpoint *proto.WorkloadEndpoint, ipVersion uint8) []string {
	addrs := endpoint.Ipv4Nets
	if ipVersion == 6 {
		addrs = endpoint.Ipv6Nets
	}
	return ipsetMembersFromUpdate(addrs)
}

func ipsetMembersFromHepUpdate(endpoint *proto.HostEndpoint, ipVersion uint8) []string {
	addrs := endpoint.ExpectedIpv4Addrs
	if ipVersion == 6 {
		addrs = endpoint.ExpectedIpv6Addrs
	}
	return ipsetMembersFromUpdate(addrs)
}

func ipsetMembersFromUpdate(addrs []string) []string {
	members := make([]string, 0, len(addrs))
	for _, a := range addrs {
		m, err := removeSubnetMask(a)
		Expect(err).NotTo(HaveOccurred())
		members = append(members, m)
	}
	return members
}
