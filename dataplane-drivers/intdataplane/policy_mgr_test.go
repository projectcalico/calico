// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
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
			policyMgr.CompleteDeferredWork()
		})

		It("should install the in and out chain", func() {
			filterTable.checkChains([][]*iptables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
			mangleTable.checkChains([][]*iptables.Chain{{
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
				filterTable.checkChains([][]*iptables.Chain{})
				mangleTable.checkChains([][]*iptables.Chain{})
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
			policyMgr.CompleteDeferredWork()
		})

		It("should install the raw chains", func() {
			rawTable.checkChains([][]*iptables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})
		It("should install to the filter table", func() {
			filterTable.checkChains([][]*iptables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})
		It("should install to the mangle table", func() {
			mangleTable.checkChains([][]*iptables.Chain{{
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
				rawTable.checkChains([][]*iptables.Chain{})
			})
			It("should not insert any filter chains", func() {
				filterTable.checkChains([][]*iptables.Chain{})
			})
			It("should remove any mangle chains", func() {
				mangleTable.checkChains([][]*iptables.Chain{})
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
			policyMgr.CompleteDeferredWork()
		})

		It("should install the raw chains", func() {
			rawTable.checkChains([][]*iptables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})
		It("should install to the filter table", func() {
			filterTable.checkChains([][]*iptables.Chain{{
				{Name: "cali-pi-pol1"},
				{Name: "cali-po-pol1"},
			}})
		})
		It("should install to the mangle table", func() {
			mangleTable.checkChains([][]*iptables.Chain{{
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
				rawTable.checkChains([][]*iptables.Chain{})
			})
			It("should not insert any filter chains", func() {
				filterTable.checkChains([][]*iptables.Chain{})
			})
			It("should remove any mangle chains", func() {
				mangleTable.checkChains([][]*iptables.Chain{})
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
			policyMgr.CompleteDeferredWork()
		})

		It("should install the in and out chain", func() {
			filterTable.checkChains([][]*iptables.Chain{{
				{Name: "cali-pri-prof1"},
				{Name: "cali-pro-prof1"},
			}})
		})

		It("should not install to the mangle table", func() {
			mangleTable.checkChains([][]*iptables.Chain{})
		})

		Describe("after a policy remove", func() {
			BeforeEach(func() {
				policyMgr.OnUpdate(&proto.ActiveProfileRemove{
					Id: &proto.ProfileID{Name: "prof1"},
				})
			})

			It("should remove the in and out chain", func() {
				filterTable.checkChains([][]*iptables.Chain{})
				mangleTable.checkChains([][]*iptables.Chain{})
			})
		})
	})
})

type mockPolRenderer struct {
}

func (r *mockPolRenderer) PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*iptables.Chain {
	inName := rules.PolicyChainName(rules.PolicyInboundPfx, policyID)
	outName := rules.PolicyChainName(rules.PolicyOutboundPfx, policyID)
	return []*iptables.Chain{
		{Name: inName},
		{Name: outName},
	}
}
func (r *mockPolRenderer) ProfileToIptablesChains(profID *proto.ProfileID, policy *proto.Profile, ipVersion uint8) []*iptables.Chain {
	inName := rules.ProfileChainName(rules.ProfileInboundPfx, profID)
	outName := rules.ProfileChainName(rules.ProfileOutboundPfx, profID)
	return []*iptables.Chain{
		{Name: inName},
		{Name: outName},
	}
}

func newMockPolRenderer() *mockPolRenderer {
	return &mockPolRenderer{}
}
