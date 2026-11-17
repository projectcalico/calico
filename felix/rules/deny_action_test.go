// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package rules_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	. "github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/nftables/nftrender"
	"github.com/projectcalico/calico/felix/proto"
	. "github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

func denyActionTestConfig(filterDenyAction string) Config {
	return Config{
		IPSetConfigV4:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
		IPSetConfigV6:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
		WorkloadIfacePrefixes: []string{"cali"},
		MarkAccept:            0x8,
		MarkPass:              0x10,
		MarkScratch0:          0x20,
		MarkScratch1:          0x40,
		MarkDrop:              0x80,
		MarkEndpoint:          0xff00,
		MarkNonCaliEndpoint:   0x0100,
		FilterDenyAction:      filterDenyAction,
	}
}

func chainActions(chains ...*generictables.Chain) []generictables.Action {
	var actions []generictables.Action
	for _, chain := range chains {
		for _, rule := range chain.Rules {
			actions = append(actions, rule.Action)
		}
	}
	return actions
}

var _ = Describe("Deny action outside the filter table", func() {
	for _, nft := range []bool{false, true} {
		var reject, drop generictables.Action = RejectAction{}, DropAction{}
		if nft {
			reject, drop = nftrender.RejectAction{}, nftrender.DropAction{}
		}

		Describe(fmt.Sprintf("nftables=%v", nft), func() {
			var renderer RuleRenderer

			tiers := tiersToSinglePolGroups([]*proto.TierInfo{{
				Name:            "default",
				IngressPolicies: []*proto.PolicyID{{Name: "a", Kind: v3.KindGlobalNetworkPolicy}},
				EgressPolicies:  []*proto.PolicyID{{Name: "a", Kind: v3.KindGlobalNetworkPolicy}},
			}})

			BeforeEach(func() {
				renderer = NewRenderer(denyActionTestConfig("REJECT"), nft)
			})

			It("should REJECT in host endpoint filter chains", func() {
				chains := renderer.HostEndpointToFilterChains("eth0", tiers, tiers, NewEndpointMarkMapper(0xff00, 0x0100), []string{"prof1"})
				Expect(chainActions(chains...)).To(ContainElement(reject))
			})

			It("should DROP in the raw cali-PREROUTING RPF check", func() {
				for _, ipVersion := range []uint8{4, 6} {
					actions := chainActions(renderer.StaticRawTableChains(ipVersion)...)
					Expect(actions).To(ContainElement(drop))
					Expect(actions).NotTo(ContainElement(reject))
				}
			})

			It("should DROP in host endpoint mangle egress chains", func() {
				actions := chainActions(renderer.HostEndpointToMangleEgressChains("eth0", tiers, []string{"prof1"})...)
				Expect(actions).To(ContainElement(drop))
				Expect(actions).NotTo(ContainElement(reject))
			})

			It("should DROP in host endpoint pre-DNAT mangle chains", func() {
				actions := chainActions(renderer.HostEndpointToMangleIngressChains("eth0", tiers)...)
				Expect(actions).To(ContainElement(drop))
				Expect(actions).NotTo(ContainElement(reject))
			})

			It("should render policy deny rules as DROP only with the non-filter table renderer", func() {
				policyID := &types.PolicyID{Name: "a", Kind: v3.KindGlobalNetworkPolicy}
				policy := &proto.Policy{
					InboundRules:  []*proto.Rule{{Action: "deny"}},
					OutboundRules: []*proto.Rule{{Action: "deny"}},
				}

				filterActions := chainActions(renderer.PolicyToIptablesChains(policyID, policy, 4)...)
				Expect(filterActions).To(ContainElement(reject))
				Expect(filterActions).NotTo(ContainElement(drop))

				nonFilterActions := chainActions(renderer.NonFilterTableRenderer().PolicyToIptablesChains(policyID, policy, 4)...)
				Expect(nonFilterActions).To(ContainElement(drop))
				Expect(nonFilterActions).NotTo(ContainElement(reject))
			})

			It("should render profile deny rules as DROP only with the non-filter table renderer", func() {
				profileID := &types.ProfileID{Name: "prof1"}
				profile := &proto.Profile{OutboundRules: []*proto.Rule{{Action: "deny"}}}

				_, filterOutbound := renderer.ProfileToIptablesChains(profileID, profile, 4)
				Expect(chainActions(filterOutbound)).To(ContainElement(reject))

				_, nonFilterOutbound := renderer.NonFilterTableRenderer().ProfileToIptablesChains(profileID, profile, 4)
				Expect(chainActions(nonFilterOutbound)).To(ContainElement(drop))
				Expect(chainActions(nonFilterOutbound)).NotTo(ContainElement(reject))
			})

			It("should use the same renderer for every table when the deny action is already DROP", func() {
				renderer = NewRenderer(denyActionTestConfig("DROP"), nft)
				Expect(renderer.NonFilterTableRenderer()).To(BeIdenticalTo(renderer))
			})
		})
	}
})
