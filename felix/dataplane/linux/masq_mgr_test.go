// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
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
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Masquerade manager", func() {
	var (
		masqMgr      *masqManager
		natTable     *mockTable
		ipSets       *dpsets.MockIPSets
		ruleRenderer rules.RuleRenderer
	)

	masqChain := func() [][]*generictables.Chain {
		return [][]*generictables.Chain{{{
			Name: "cali-nat-outgoing",
			Rules: []generictables.Rule{
				{
					Action: iptables.MasqAction{},
					Match: iptables.Match().
						SourceIPSet("cali40masq-ipam-pools").
						NotDestIPSet("cali40network-ip-pools"),
				},
			},
		}}}
	}
	emptyChain := func() [][]*generictables.Chain {
		return [][]*generictables.Chain{{{
			Name:  "cali-nat-outgoing",
			Rules: nil,
		}}}
	}

	addPool := func(id, cidr string, masq bool, allowedUses ...string) {
		masqMgr.OnUpdate(&proto.IPAMPoolUpdate{
			Id: id,
			Pool: &proto.IPAMPool{
				Cidr:        cidr,
				Masquerade:  masq,
				AllowedUses: allowedUses,
			},
		})
	}

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		natTable = newMockTable("nat")
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
		}, false)
		masqMgr = newMasqManager(ipSets, natTable, ruleRenderer, 1024, 4)
	})

	It("should create its IP sets on startup", func() {
		Expect(ipSets.Members).To(Equal(map[string]set.Set[string]{
			"network-ip-pools": set.New[string](),
			"masq-ipam-pools":  set.New[string](),
		}))
	})

	Describe("after adding a masq pool", func() {
		BeforeEach(func() {
			addPool("pool-1", "10.0.0.0/16", true)
			// This one should be ignored due to wrong IP version.
			addPool("pool-1v6", "feed:beef::/96", true)
			Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())
		})

		It("should populate the IP sets and program the chain", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
			Expect(ipSets.Members["network-ip-pools"]).To(Equal(set.From("10.0.0.0/16")))
			Expect(natTable.UpdateCalled).To(BeTrue())
			natTable.checkChains(masqChain())
		})

		It("an extra CompleteDeferredWork should be a no-op", func() {
			natTable.UpdateCalled = false
			Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())
			Expect(natTable.UpdateCalled).To(BeFalse())
		})

		It("shouldn't trigger work after an unrelated update", func() {
			natTable.UpdateCalled = false
			masqMgr.OnUpdate(&proto.HostMetadataUpdate{
				Hostname: "foo",
				Ipv4Addr: "10.0.0.17",
			})
			Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())
			Expect(natTable.UpdateCalled).To(BeFalse())
		})
	})

	It("should populate only the network-pools IP set and program an empty chain, after adding a non-masq pool", func() {
		addPool("pool-1", "10.0.0.0/16", false)
		Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())

		Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
		Expect(ipSets.Members["network-ip-pools"]).To(Equal(set.From("10.0.0.0/16")))
		natTable.checkChains(emptyChain())
	})

	It("should populate the IP sets and program the chain, after adding both a masq and a non-masq pool", func() {
		addPool("pool-1", "10.0.0.0/16", true)
		addPool("pool-2", "10.2.0.0/16", false)
		Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())

		Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.0.0.0/16")))
		Expect(ipSets.Members["network-ip-pools"]).To(Equal(set.From("10.0.0.0/16", "10.2.0.0/16")))
		natTable.checkChains(masqChain())
	})

	It("should leave only the non-masq pool in the network-pools set and program an empty chain, after adding both pools then removing the masq pool", func() {
		addPool("pool-1", "10.0.0.0/16", true)
		addPool("pool-2", "10.2.0.0/16", false)
		masqMgr.OnUpdate(&proto.IPAMPoolRemove{Id: "pool-1"})
		Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())

		Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
		Expect(ipSets.Members["network-ip-pools"]).To(Equal(set.From("10.2.0.0/16")))
		natTable.checkChains(emptyChain())
	})

	It("should empty both IP sets and program an empty chain, after adding both pools then removing both", func() {
		addPool("pool-1", "10.0.0.0/16", true)
		addPool("pool-2", "10.2.0.0/16", false)
		masqMgr.OnUpdate(&proto.IPAMPoolRemove{Id: "pool-1"})
		masqMgr.OnUpdate(&proto.IPAMPoolRemove{Id: "pool-2"})
		Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())

		Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
		Expect(ipSets.Members["network-ip-pools"]).To(Equal(set.New[string]()))
		natTable.checkChains(emptyChain())
	})

	Describe("after adding a LoadBalancer-only pool", func() {
		BeforeEach(func() {
			addPool("lb-pool", "10.20.40.64/27", true, string(apiv3.IPPoolAllowedUseLoadBalancer))
			Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())
		})

		It("should add the pool to the masq IP set but not the network IP set", func() {
			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.20.40.64/27")))
			Expect(ipSets.Members["network-ip-pools"]).To(Equal(set.New[string]()))
		})

		It("should empty both IP sets after removing the LoadBalancer-only pool", func() {
			masqMgr.OnUpdate(&proto.IPAMPoolRemove{Id: "lb-pool"})
			Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())

			Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.New[string]()))
			Expect(ipSets.Members["network-ip-pools"]).To(Equal(set.New[string]()))
		})
	})

	It("should add the pool to both the masq and network IP sets since it includes Workload, after adding a pool with Workload and LoadBalancer uses,", func() {
		addPool("mixed-pool", "10.1.0.0/16", true,
			string(apiv3.IPPoolAllowedUseWorkload), string(apiv3.IPPoolAllowedUseLoadBalancer))
		Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())

		Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.1.0.0/16")))
		Expect(ipSets.Members["network-ip-pools"]).To(Equal(set.From("10.1.0.0/16")))
	})

	It("should partition pools by their AllowedUses across the IP sets, after adding a Workload pool and a LoadBalancer-only pool", func() {
		addPool("workload-pool", "10.0.0.0/16", false, string(apiv3.IPPoolAllowedUseWorkload))
		addPool("lb-pool", "10.20.0.0/16", true, string(apiv3.IPPoolAllowedUseLoadBalancer))
		Expect(masqMgr.CompleteDeferredWork()).ToNot(HaveOccurred())

		Expect(ipSets.Members["network-ip-pools"]).To(Equal(set.From("10.0.0.0/16")))
		Expect(ipSets.Members["masq-ipam-pools"]).To(Equal(set.From("10.20.0.0/16")))
	})
})
