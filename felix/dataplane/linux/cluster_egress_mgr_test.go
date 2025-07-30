// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Cluster egress manager - Masquerade", func() {
	var (
		masqMgr      *clusterEgressManager
		natTable     *mockTable
		mangleTable  *mockTable
		ipSets       *dpsets.MockIPSets
		ruleRenderer rules.RuleRenderer
	)

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		natTable = newMockTable("nat")
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
		masqMgr = newClusterEgressManager(ipSets, natTable, mangleTable, ruleRenderer, 1024, 4)
	})

	It("should create its IP sets on startup", func() {
		Expect(ipSets.Members).To(Equal(map[string]set.Set[string]{
			"all-ipam-pools":  set.New[string](),
			"masq-ipam-pools": set.New[string](),
		}))
	})

	Describe("after adding a masq pool", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "pool-1",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: true,
				},
			})
			// This one should be ignored due to wrong IP version.
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "pool-1v6",
				Pool: &proto.IPAMPool{
					Cidr:       "feed:beef::/96",
					Masquerade: true,
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add the pool to the masq IP set", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})
		It("should add the pool to the all IP set", func() {
			Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})
		It("should program the chain", func() {
			Expect(natTable.UpdateCalled).To(BeTrue())
			natTable.checkChains([][]*generictables.Chain{{{
				Name: "cali-nat-outgoing",
				Rules: []generictables.Rule{
					{
						Action: iptables.MasqAction{},
						Match: iptables.Match().
							SourceIPSet("cali40masq-ipam-pools").
							NotDestIPSet("cali40all-ipam-pools"),
					},
				},
			}}})
		})
		It("an extra CompleteDeferredWork should be a no-op", func() {
			natTable.UpdateCalled = false
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(natTable.UpdateCalled).To(BeFalse())
		})
		It("an unrelated update shouldn't trigger work", func() {
			natTable.UpdateCalled = false
			masqMgr.OnUpdate(&proto.HostMetadataUpdate{
				Hostname: "foo",
				Ipv4Addr: "10.0.0.17",
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
			Expect(natTable.UpdateCalled).To(BeFalse())
		})

		Describe("after adding a non-masq pool", func() {
			BeforeEach(func() {
				masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
					Id: "pool-2",
					Pool: &proto.IPAMPool{
						Cidr:       "10.2.0.0/16",
						Masquerade: false,
					},
				})
				err := masqMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			It("should not add the pool to the masq IP set", func() {
				Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
			})
			It("should add the pool to the all IP set", func() {
				Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From(
					"10.0.0.0/16", "10.2.0.0/16")))
			})
			It("should program the chain", func() {
				natTable.checkChains([][]*generictables.Chain{{{
					Name: "cali-nat-outgoing",
					Rules: []generictables.Rule{
						{
							Action: iptables.MasqAction{},
							Match: iptables.Match().
								SourceIPSet("cali40masq-ipam-pools").
								NotDestIPSet("cali40all-ipam-pools"),
						},
					},
				}}})
			})

			Describe("after removing masq pool", func() {
				BeforeEach(func() {
					masqMgr.OnUpdate(&proto.IPAMPoolRemove{
						Id: "pool-1",
					})
					err := masqMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})
				It("should remove from the masq IP set", func() {
					Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
				})
				It("should remove from the all IP set", func() {
					Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From(
						"10.2.0.0/16")))
				})
				It("should program empty chain", func() {
					natTable.checkChains([][]*generictables.Chain{{{
						Name:  "cali-nat-outgoing",
						Rules: nil,
					}}})
				})

				Describe("after removing the non-masq pool", func() {
					BeforeEach(func() {
						masqMgr.OnUpdate(&proto.IPAMPoolRemove{
							Id: "pool-2",
						})
						err := masqMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})
					It("masq set should be empty", func() {
						Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
					})
					It("all set should be empty", func() {
						Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.New[string]()))
					})
					It("should program empty chain", func() {
						natTable.checkChains([][]*generictables.Chain{{{
							Name:  "cali-nat-outgoing",
							Rules: nil,
						}}})
					})
				})
			})
		})
	})

	Describe("after adding a non-masq pool", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "pool-1",
				Pool: &proto.IPAMPool{
					Cidr:       "10.0.0.0/16",
					Masquerade: false,
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should not add the pool to the masq IP set", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
		})
		It("should add the pool to the all IP set", func() {
			Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})
		It("should program empty chain", func() {
			natTable.checkChains([][]*generictables.Chain{{{
				Name:  "cali-nat-outgoing",
				Rules: nil,
			}}})
		})
	})

	Describe("QoS policy: after adding a workload with DSCP annotation", func() {
		BeforeEach(func() {
			masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "pool-1",
				Pool: &proto.IPAMPool{
					Cidr: "10.0.0.0/16",
				},
			})
			err := masqMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add the pool to the all IP set", func() {
			Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})

		It("should program QoS policy chain with no rule", func() {
			mangleTable.checkChains([][]*generictables.Chain{{{
				Name:  rules.ChainQosPolicy,
				Rules: nil,
			}}})
		})

		It("should handle workload updates correctly", func() {
			By("sending workload endpoint updates with DSCP annotion")
			masqMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &wlEPID1,
				Endpoint: &proto.WorkloadEndpoint{
					State:       "active",
					Name:        "cali12345-ab",
					Ipv4Nets:    []string{"10.0.240.2/24"},
					Ipv6Nets:    []string{"2001:db8:2::2/128"},
					QosPolicies: []*proto.QoSPolicy{{Dscp: 44}},
				},
			})

			err := masqMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQosPolicy,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 44},
						Match: iptables.Match().
							SourceNet("10.0.240.2"),
					},
				},
			}}})

			By("sending another workload endpoint updates with DSCP annotion")
			masqMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &wlEPID2,
				Endpoint: &proto.WorkloadEndpoint{
					State:       "active",
					Name:        "cali2",
					Ipv4Nets:    []string{"10.0.240.3/24"},
					Ipv6Nets:    []string{"2001:db8:2::3/128"},
					QosPolicies: []*proto.QoSPolicy{{Dscp: 20}},
				},
			})

			err = masqMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQosPolicy,
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
			masqMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &wlEPID1,
				Endpoint: &proto.WorkloadEndpoint{
					State:       "active",
					Name:        "cali12345-ab",
					Ipv4Nets:    []string{"10.0.240.2/24"},
					Ipv6Nets:    []string{"2001:db8:2::2/128"},
					QosPolicies: []*proto.QoSPolicy{{Dscp: 13}},
				},
			})

			err = masqMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQosPolicy,
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
			masqMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &wlEPID1,
				Endpoint: &proto.WorkloadEndpoint{
					State:    "active",
					Name:     "cali12345-ab",
					Ipv4Nets: []string{"10.0.240.2/24"},
					Ipv6Nets: []string{"2001:db8:2::2/128"},
				},
			})

			err = masqMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name: rules.ChainQosPolicy,
				Rules: []generictables.Rule{
					{
						Action: iptables.DSCPAction{Value: 20},
						Match: iptables.Match().
							SourceNet("10.0.240.3"),
					},
				},
			}}})

			By("verifying QoS policy rules removed when workload is removed")
			masqMgr.OnUpdate(&proto.WorkloadEndpointRemove{
				Id: &wlEPID2,
			})

			err = masqMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			mangleTable.checkChains([][]*generictables.Chain{{{
				Name:  rules.ChainQosPolicy,
				Rules: nil,
			}}})
		})
	})
})
