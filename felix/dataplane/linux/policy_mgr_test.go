// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Policy manager", func() {
	var (
		policyMgr    *policyManager
		rawTable     *mockTable
		mangleTable  *mockTable
		filterTable  *mockTable
		ruleRenderer *mockPolRenderer
	)

	BeforeEach(func() {
		rawTable = newMockTable("raw")
		mangleTable = newMockTable("mangle")
		filterTable = newMockTable("filter")
		ruleRenderer = newMockPolRenderer()
		policyMgr = newPolicyManager(rawTable, mangleTable, filterTable, ruleRenderer, 4)
	})

	It("shouldn't touch iptables", func() {
		Expect(filterTable.UpdateCalled).To(BeFalse())
		Expect(mangleTable.UpdateCalled).To(BeFalse())
	})

	Describe("after a policy update", func() {
		BeforeEach(func() {
			policyMgr.OnUpdate(&proto.ActivePolicyUpdate{
				Id: &proto.PolicyID{Name: "pol1", Tier: "default"},
				Policy: &proto.Policy{
					InboundRules: []*proto.Rule{
						{Action: "deny"},
					},
					OutboundRules: []*proto.Rule{
						{Action: "allow"},
					},
				},
			})
			err := policyMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should install the in and out chain", func() {
			filterTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
			mangleTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})

		Describe("after a policy remove", func() {
			BeforeEach(func() {
				policyMgr.OnUpdate(&proto.ActivePolicyRemove{
					Id: &proto.PolicyID{Name: "pol1", Tier: "default"},
				})
			})

			It("should remove the in and out chain", func() {
				filterTable.checkChains([][]*generictables.Chain{})
				mangleTable.checkChains([][]*generictables.Chain{})
			})
		})
	})

	Describe("after an untracked policy update", func() {
		BeforeEach(func() {
			policyMgr.OnUpdate(&proto.ActivePolicyUpdate{
				Id: &proto.PolicyID{Name: "pol1", Tier: "default"},
				Policy: &proto.Policy{
					InboundRules: []*proto.Rule{
						{Action: "deny"},
					},
					OutboundRules: []*proto.Rule{
						{Action: "allow"},
					},
					Untracked: true,
				},
			})
			err := policyMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should install the raw chains", func() {
			rawTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})
		It("should install to the filter table", func() {
			filterTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})
		It("should install to the mangle table", func() {
			mangleTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})

		Describe("after a policy remove", func() {
			BeforeEach(func() {
				policyMgr.OnUpdate(&proto.ActivePolicyRemove{
					Id: &proto.PolicyID{Name: "pol1", Tier: "default"},
				})
			})

			It("should remove the raw chains", func() {
				rawTable.checkChains([][]*generictables.Chain{})
			})
			It("should not insert any filter chains", func() {
				filterTable.checkChains([][]*generictables.Chain{})
			})
			It("should remove any mangle chains", func() {
				mangleTable.checkChains([][]*generictables.Chain{})
			})
		})
	})

	Describe("after a pre-DNAT policy update", func() {
		BeforeEach(func() {
			policyMgr.OnUpdate(&proto.ActivePolicyUpdate{
				Id: &proto.PolicyID{Name: "pol1", Tier: "default"},
				Policy: &proto.Policy{
					InboundRules: []*proto.Rule{
						{Action: "deny"},
					},
					OutboundRules: []*proto.Rule{
						{Action: "allow"},
					},
					PreDnat: true,
				},
			})
			err := policyMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should install the raw chains", func() {
			rawTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})
		It("should install to the filter table", func() {
			filterTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})
		It("should install to the mangle table", func() {
			mangleTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})

		Describe("after a policy remove", func() {
			BeforeEach(func() {
				policyMgr.OnUpdate(&proto.ActivePolicyRemove{
					Id: &proto.PolicyID{Name: "pol1", Tier: "default"},
				})
			})

			It("should remove the raw chains", func() {
				rawTable.checkChains([][]*generictables.Chain{})
			})
			It("should not insert any filter chains", func() {
				filterTable.checkChains([][]*generictables.Chain{})
			})
			It("should remove any mangle chains", func() {
				mangleTable.checkChains([][]*generictables.Chain{})
			})
		})
	})

	Describe("after a profile update", func() {
		BeforeEach(func() {
			policyMgr.OnUpdate(&proto.ActiveProfileUpdate{
				Id: &proto.ProfileID{Name: "prof1"},
				Profile: &proto.Profile{
					InboundRules: []*proto.Rule{
						{Action: "deny"},
					},
					OutboundRules: []*proto.Rule{
						{Action: "allow"},
					},
				},
			})
			err := policyMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should install the in and out chain", func() {
			filterTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pri-prof1"},
				{Name: "cali-pro-prof1"},
			}})
		})

		It("should install the out chain to the mangle table", func() {
			mangleTable.checkChains([][]*generictables.Chain{{
				{Name: "cali-pro-prof1"},
			}})
		})

		Describe("after a policy remove", func() {
			BeforeEach(func() {
				policyMgr.OnUpdate(&proto.ActiveProfileRemove{
					Id: &proto.ProfileID{Name: "prof1"},
				})
			})

			It("should remove the in and out chain", func() {
				filterTable.checkChains([][]*generictables.Chain{})
				mangleTable.checkChains([][]*generictables.Chain{})
			})
		})
	})
})

var _ = Describe("Raw egress policy manager", func() {
	var (
		policyMgr        *policyManager
		rawTable         *mockTable
		neededIPSets     set.Set[string]
		numCallbackCalls int
	)

	BeforeEach(func() {
		neededIPSets = nil
		numCallbackCalls = 0
		rawTable = newMockTable("raw")
		ruleRenderer := rules.NewRenderer(rules.Config{
			IPSetConfigV4:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			IptablesMarkAccept:          0x8,
			IptablesMarkPass:            0x10,
			IptablesMarkScratch0:        0x20,
			IptablesMarkScratch1:        0x40,
			IptablesMarkEndpoint:        0xff00,
			IptablesMarkNonCaliEndpoint: 0x0100,
		})
		policyMgr = newRawEgressPolicyManager(
			rawTable,
			ruleRenderer,
			4,
			func(ipSets set.Set[string]) {
				neededIPSets = ipSets
				numCallbackCalls++
			})
	})

	It("correctly reports no IP sets at start of day", func() {
		err := policyMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(neededIPSets).ToNot(BeNil())
		Expect(neededIPSets.Len()).To(BeZero())
		Expect(numCallbackCalls).To(Equal(1))

		By("Not repeating the callback.")
		err = policyMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(numCallbackCalls).To(Equal(1))
	})

	It("correctly reports needed IP sets", func() {
		By("defining one untracked policy with an IP set")
		policyMgr.OnUpdate(&proto.ActivePolicyUpdate{
			Id: &proto.PolicyID{Tier: "default", Name: "pol1"},
			Policy: &proto.Policy{
				Untracked: true,
				OutboundRules: []*proto.Rule{
					{
						Action:      "deny",
						DstIpSetIds: []string{"ipsetA"},
					},
				},
			},
		})
		err := policyMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(neededIPSets).To(MatchIPSets("ipsetA"))

		By("defining another untracked policy with a different IP set")
		policyMgr.OnUpdate(&proto.ActivePolicyUpdate{
			Id: &proto.PolicyID{Tier: "default", Name: "pol2"},
			Policy: &proto.Policy{
				Untracked: true,
				OutboundRules: []*proto.Rule{
					{
						Action:      "deny",
						DstIpSetIds: []string{"ipsetB"},
					},
				},
			},
		})
		err = policyMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(neededIPSets).To(MatchIPSets("ipsetA", "ipsetB"))

		By("defining a non-untracked policy with a third IP set")
		policyMgr.OnUpdate(&proto.ActivePolicyUpdate{
			Id: &proto.PolicyID{Tier: "default", Name: "pol3"},
			Policy: &proto.Policy{
				OutboundRules: []*proto.Rule{
					{
						Action:      "deny",
						DstIpSetIds: []string{"ipsetC"},
					},
				},
			},
		})
		err = policyMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// The non-untracked policy IP set is not needed.
		Expect(neededIPSets).To(MatchIPSets("ipsetA", "ipsetB"))

		By("removing the first untracked policy")
		policyMgr.OnUpdate(&proto.ActivePolicyRemove{
			Id: &proto.PolicyID{Tier: "default", Name: "pol1"},
		})
		err = policyMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(neededIPSets).To(MatchIPSets("ipsetB"))

		By("removing the second untracked policy")
		policyMgr.OnUpdate(&proto.ActivePolicyRemove{
			Id: &proto.PolicyID{Tier: "default", Name: "pol2"},
		})
		err = policyMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(neededIPSets).To(MatchIPSets())
	})
})

type ipSetsMatcher struct {
	items []interface{}
}

func MatchIPSets(items ...interface{}) *ipSetsMatcher {
	return &ipSetsMatcher{
		items: items,
	}
}

func (m *ipSetsMatcher) Match(actual interface{}) (success bool, err error) {
	actualSet := actual.(set.Set[string])
	actualCopy := actualSet.Copy()
	for _, expected := range m.items {
		actualCopy.Add("cali40" + expected.(string))
	}
	success = (actualSet.Len() == len(m.items)) && (actualCopy.Len() == len(m.items))
	return
}

func (m *ipSetsMatcher) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected %v to match IP set IDs: %v", actual.(set.Set[string]), m.items)
}

func (m *ipSetsMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected %v not to match IP set IDs: %v", actual.(set.Set[string]), m.items)
}

type mockPolRenderer struct{}

func (r *mockPolRenderer) PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*generictables.Chain {
	inName := rules.PolicyChainName(rules.PolicyInboundPfx, policyID)
	outName := rules.PolicyChainName(rules.PolicyOutboundPfx, policyID)
	return []*generictables.Chain{
		{Name: inName},
		{Name: outName},
	}
}

func (r *mockPolRenderer) ProfileToIptablesChains(profID *proto.ProfileID, policy *proto.Profile, ipVersion uint8) (inbound, outbound *generictables.Chain) {
	inbound = &generictables.Chain{
		Name: rules.ProfileChainName(rules.ProfileInboundPfx, profID),
	}
	outbound = &generictables.Chain{
		Name: rules.ProfileChainName(rules.ProfileOutboundPfx, profID),
	}
	return
}

func newMockPolRenderer() *mockPolRenderer {
	return &mockPolRenderer{}
}
