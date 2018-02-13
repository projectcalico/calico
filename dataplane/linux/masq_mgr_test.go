// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/libcalico-go/lib/set"
)

var _ = Describe("Masquerade manager", func() {
	var (
		masqMgr      *masqManager
		natTable     *mockTable
		ipSets       *mockIPSets
		ruleRenderer rules.RuleRenderer
	)

	BeforeEach(func() {
		ipSets = newMockIPSets()
		natTable = newMockTable("nat")
		ruleRenderer = rules.NewRenderer(rules.Config{
			IPSetConfigV4: ipsets.NewIPVersionConfig(
				ipsets.IPFamilyV4,
				"cali",
				nil,
				nil,
			),
			IptablesMarkPass:     0x1,
			IptablesMarkAccept:   0x2,
			IptablesMarkScratch0: 0x4,
			IptablesMarkScratch1: 0x8,
			IptablesMarkEndpoint: 0x11110000,
		})
		masqMgr = newMasqManager(ipSets, natTable, ruleRenderer, 1024, 4)
	})

	It("should create its IP sets on startup", func() {
		Expect(ipSets.Members).To(Equal(map[string]set.Set{
			"all-ipam-pools":  set.New(),
			"masq-ipam-pools": set.New(),
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
			masqMgr.CompleteDeferredWork()
		})

		It("should add the pool to the masq IP set", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})
		It("should add the pool to the all IP set", func() {
			Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})
		It("should program the chain", func() {
			Expect(natTable.UpdateCalled).To(BeTrue())
			natTable.checkChains([][]*iptables.Chain{{{
				Name: "cali-nat-outgoing",
				Rules: []iptables.Rule{
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
			masqMgr.CompleteDeferredWork()
			Expect(natTable.UpdateCalled).To(BeFalse())
		})
		It("an unrelated update shouldn't trigger work", func() {
			natTable.UpdateCalled = false
			masqMgr.OnUpdate(&proto.HostMetadataUpdate{
				Hostname: "foo",
				Ipv4Addr: "10.0.0.17",
			})
			masqMgr.CompleteDeferredWork()
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
				masqMgr.CompleteDeferredWork()
			})

			It("should not add the pool to the masq IP set", func() {
				Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
			})
			It("should add the pool to the all IP set", func() {
				Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From(
					"10.0.0.0/16", "10.2.0.0/16")))
			})
			It("should program the chain", func() {
				natTable.checkChains([][]*iptables.Chain{{{
					Name: "cali-nat-outgoing",
					Rules: []iptables.Rule{
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
					masqMgr.CompleteDeferredWork()
				})
				It("should remove from the masq IP set", func() {
					Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New()))
				})
				It("should remove from the all IP set", func() {
					Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From(
						"10.2.0.0/16")))
				})
				It("should program empty chain", func() {
					natTable.checkChains([][]*iptables.Chain{{{
						Name:  "cali-nat-outgoing",
						Rules: nil,
					}}})
				})

				Describe("after removing the non-masq pool", func() {
					BeforeEach(func() {
						masqMgr.OnUpdate(&proto.IPAMPoolRemove{
							Id: "pool-2",
						})
						masqMgr.CompleteDeferredWork()
					})
					It("masq set should be empty", func() {
						Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New()))
					})
					It("all set should be empty", func() {
						Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.New()))
					})
					It("should program empty chain", func() {
						natTable.checkChains([][]*iptables.Chain{{{
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
			masqMgr.CompleteDeferredWork()
		})

		It("should not add the pool to the masq IP set", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New()))
		})
		It("should add the pool to the all IP set", func() {
			Expect(ipSets.Members["all-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		})
		It("should program empty chain", func() {
			natTable.checkChains([][]*iptables.Chain{{{
				Name:  "cali-nat-outgoing",
				Rules: nil,
			}}})
		})
	})
})
