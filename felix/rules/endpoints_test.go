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

package rules_test

import (
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	. "github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	. "github.com/projectcalico/calico/felix/rules"
)

func init() {
	// Stop Gomega from chopping off diffs in logs.
	format.MaxLength = 0
}

var _ = Describe("Endpoints", func() {
	const (
		ProtoUDP          = 17
		ProtoIPIP         = 4
		VXLANPort         = 4789
		EgressIPVXLANPort = 4790
		VXLANVNI          = 4096
	)

	for _, trueOrFalse := range []bool{true, false} {
		var denyAction generictables.Action
		denyAction = DropAction{}
		denyActionCommand := "DROP"
		denyActionString := "Drop"
		if trueOrFalse {
			denyAction = RejectAction{}
			denyActionCommand = "REJECT"
			denyActionString = "Reject"
		}

		kubeIPVSEnabled := trueOrFalse
		rrConfigNormalMangleReturn := Config{
			IPIPEnabled:            true,
			IPIPTunnelAddress:      nil,
			IPSetConfigV4:          ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:          ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			MarkAccept:             0x8,
			MarkPass:               0x10,
			MarkScratch0:           0x20,
			MarkScratch1:           0x40,
			MarkDrop:               0x80,
			MarkEndpoint:           0xff00,
			MarkNonCaliEndpoint:    0x0100,
			KubeIPVSSupportEnabled: kubeIPVSEnabled,
			MangleAllowAction:      "RETURN",
			FilterDenyAction:       denyActionCommand,
			VXLANPort:              4789,
			VXLANVNI:               4096,
		}

		rrConfigConntrackDisabledReturnAction := Config{
			IPIPEnabled:             true,
			IPIPTunnelAddress:       nil,
			IPSetConfigV4:           ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:           ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			MarkAccept:              0x8,
			MarkPass:                0x10,
			MarkScratch0:            0x20,
			MarkScratch1:            0x40,
			MarkDrop:                0x80,
			MarkEndpoint:            0xff00,
			MarkNonCaliEndpoint:     0x0100,
			KubeIPVSSupportEnabled:  kubeIPVSEnabled,
			DisableConntrackInvalid: true,
			FilterAllowAction:       "RETURN",
			FilterDenyAction:        denyActionCommand,
			VXLANPort:               4789,
			VXLANVNI:                4096,
		}

		var renderer RuleRenderer
		var epMarkMapper EndpointMarkMapper

		Context("with normal config", func() {
			BeforeEach(func() {
				rrConfigNormalMangleReturn.FlowLogsEnabled = false
				renderer = NewRenderer(rrConfigNormalMangleReturn)
				epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
					rrConfigNormalMangleReturn.MarkNonCaliEndpoint)
			})

			It("should render a minimal workload endpoint", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234", epMarkMapper,
					true,
					nil,
					nil,
					nil,
				)).To(Equal(expected))
			})

			It("should render a disabled workload endpoint", func() {
				commonRule := []generictables.Rule{
					endpointAdminDisabledRule(denyAction),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: commonRule,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: commonRule,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234", epMarkMapper,
					false,
					nil,
					nil,
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "ai"),
					policyAcceptedRule(),
					matchPolicyIngress("default", "bi"),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					matchPolicyEgress("default", "ae"),
					policyAcceptedRule(),
					matchPolicyEgress("default", "be"),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"ai", "bi"},
						EgressPolicies:  []string{"ae", "be"},
					}}),
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a workload endpoint with policy groups", func() {
				polGrpInABC := &PolicyGroup{
					Tier:        "default",
					Direction:   PolicyDirectionInbound,
					PolicyNames: []string{"a", "b", "c"},
					Selector:    "all()",
				}
				polGrpInEF := &PolicyGroup{
					Tier:        "default",
					Direction:   PolicyDirectionInbound,
					PolicyNames: []string{"e", "f"},
					Selector:    "someLabel == 'bar'",
				}
				polGrpOutAB := &PolicyGroup{
					Tier:        "default",
					Direction:   PolicyDirectionOutbound,
					PolicyNames: []string{"a", "b"},
					Selector:    "all()",
				}
				polGrpOutDE := &PolicyGroup{
					Tier:        "default",
					Direction:   PolicyDirectionOutbound,
					PolicyNames: []string{"d", "e"},
					Selector:    "someLabel == 'bar'",
				}

				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					jumpToPolicyGroup(polGrpInABC.ChainName(), 0x10),
					policyAcceptedRule(),
					jumpToPolicyGroup(polGrpInEF.ChainName(), 0x10),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					jumpToPolicyGroup(polGrpOutAB.ChainName(), 0x10),
					policyAcceptedRule(),
					jumpToPolicyGroup(polGrpOutDE.ChainName(), 0x10),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})

				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					[]TierPolicyGroups{
						{
							Name: "default",
							IngressPolicies: []*PolicyGroup{
								polGrpInABC,
								polGrpInEF,
							},
							EgressPolicies: []*PolicyGroup{
								polGrpOutAB,
								polGrpOutDE,
							},
						},
					},
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint - one staged policy, one enforced", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "bi"),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					matchPolicyEgress("default", "ae"),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"staged:ai", "bi"},
						EgressPolicies:  []string{"ae", "staged:be"},
					}}),
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint - both staged, end-of-tier action is pass", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"staged:ai", "staged:bi"},
						EgressPolicies:  []string{"staged:ae", "staged:be"},
					}}),
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint - staged policy group, end-of-tier pass", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					[]TierPolicyGroups{
						{
							Name: "default",
							IngressPolicies: []*PolicyGroup{{
								Tier:        "default",
								Direction:   PolicyDirectionInbound,
								PolicyNames: []string{"staged:ai", "staged:bi"},
								Selector:    "all()",
							}},
							EgressPolicies: []*PolicyGroup{{
								Tier:        "default",
								Direction:   PolicyDirectionOutbound,
								PolicyNames: []string{"staged:ae", "staged:be"},
								Selector:    "all()",
							}},
						},
					},
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint with tier DefaultAction is Pass", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "ai"),
					policyAcceptedRule(),
					matchPolicyIngress("default", "bi"),
					policyAcceptedRule(),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					matchPolicyEgress("default", "ae"),
					policyAcceptedRule(),
					matchPolicyEgress("default", "be"),
					policyAcceptedRule(),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						DefaultAction:   "Pass",
						IngressPolicies: []string{"ai", "bi"},
						EgressPolicies:  []string{"ae", "be"},
					}}),
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a host endpoint", func() {
				actual := renderer.HostEndpointToFilterChains("eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"ai", "bi"},
						EgressPolicies:  []string{"ae", "be"},
					}}),
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"afi", "bfi"},
						EgressPolicies:  []string{"afe", "bfe"},
					}}),
					epMarkMapper,
					[]string{"prof1", "prof2"},
				)
				toHostRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					// Host endpoints get extra failsafe rules.
					failSafeEgress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyEgress("default", "ae"),
					policyAcceptedRule(),
					matchPolicyEgress("default", "be"),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromHostRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					// Host endpoints get extra failsafe rules.
					failSafeIngress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "ai"),
					policyAcceptedRule(),
					matchPolicyIngress("default", "bi"),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				toHostFWRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyEgress("default", "afe"),
					policyAcceptedRule(),
					matchPolicyEgress("default", "bfe"),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
				}
				fromHostFWRUles := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "afi"),
					policyAcceptedRule(),
					matchPolicyIngress("default", "bfi"),
					policyAcceptedRule(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-th-eth0",
						Rules: toHostRules,
					},
					{
						Name:  "cali-fh-eth0",
						Rules: fromHostRules,
					},
					{
						Name:  "cali-thfw-eth0",
						Rules: toHostFWRules,
					},
					{
						Name:  "cali-fhfw-eth0",
						Rules: fromHostFWRUles,
					},
					{
						Name:  "cali-sm-eth0",
						Rules: setEndpointMarkRules(0xa200, 0xff00),
					},
				})
				Expect(actual).To(Equal(expected), cmp.Diff(actual, expected))
			})

			It("should render host endpoint raw chains with untracked policies", func() {
				toHostRules := []generictables.Rule{
					// Host endpoints get extra failsafe rules.
					failSafeEgress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyEgress("default", "c"),
					// Extra NOTRACK action before returning in raw table.
					untrackedRule(),
					policyAcceptedRule(),
					// No drop actions or profiles in raw table.
				}
				fromHostRules := []generictables.Rule{
					// Host endpoints get extra failsafe rules.
					failSafeIngress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "c"),
					// Extra NOTRACK action before returning in raw table.
					untrackedRule(),
					policyAcceptedRule(),
					// No drop actions or profiles in raw table.
				}

				expected := []*generictables.Chain{
					{
						Name:  "cali-th-eth0",
						Rules: toHostRules,
					},
					{
						Name:  "cali-fh-eth0",
						Rules: fromHostRules,
					},
				}
				Expect(renderer.HostEndpointToRawChains("eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"c"},
						EgressPolicies:  []string{"c"},
					}}),
				)).To(Equal(expected))
			})

			It("should render host endpoint mangle chains with pre-DNAT policies", func() {
				fromHostRules := []generictables.Rule{
					// conntrack rules.
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: SetMarkAction{Mark: 0x8},
					},
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: ReturnAction{},
					},
					conntrackDenyRule(denyAction),
					// Host endpoints get extra failsafe rules.
					failSafeIngress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "c"),
					policyAcceptedRule(),
					// No drop actions or profiles in raw table.
				}
				expected := []*generictables.Chain{
					{
						Name:  "cali-fh-eth0",
						Rules: fromHostRules,
					},
				}
				Expect(renderer.HostEndpointToMangleIngressChains(
					"eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"c"},
					}}),
				)).To(Equal(expected))
			})

			It("should render a workload endpoint with packet rate limiting QoSControls", func() {
				toWlRules := qosControlRules()
				toWlRules = append(toWlRules,
					conntrackAcceptRule(), // conntrack rules.
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				)

				expected := []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name: "cali-fw-cali1234",
						Rules: []generictables.Rule{
							// egress packet rate rules
							{
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x20},
								Comment: []string{"Clear egress packet rate limit mark"},
							},
							{
								Match:   Match(),
								Action:  LimitPacketRateAction{Rate: 1000, Burst: 2000, Mark: 0x20},
								Comment: []string{"Mark packets within egress packet rate limit"},
							},
							{
								Match:   Match().NotMarkMatchesWithMask(0x20, 0x20),
								Action:  DropAction{},
								Comment: []string{"Drop packets over egress packet rate limit"},
							},
							{
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x20},
								Comment: []string{"Clear egress packet rate limit mark"},
							},
							// conntrack rules.
							conntrackAcceptRule(),
							conntrackDenyRule(denyAction),
							clearMarkRule(),
							dropVXLANRule(VXLANPort, denyAction, denyActionString),
							dropIPIPRule(denyAction, denyActionString),
							noProfiletMatchedRule(denyAction, denyActionString),
						},
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				}
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234", epMarkMapper,
					true,
					nil,
					nil,
					&proto.QoSControls{
						EgressPacketRate:   1000,
						IngressPacketRate:  2000,
						EgressPacketBurst:  2000,
						IngressPacketBurst: 4000,
					},
				)).To(Equal(trimSMChain(kubeIPVSEnabled, expected)))
			})

			It("should render a workload endpoint with connection limiting QoSControls", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					// ingress max connection rules
					{
						Match:  Match(),
						Action: LimitNumConnectionsAction{Num: 20, RejectWith: generictables.RejectWithTCPReset},

						Comment: []string{"Reject connections over ingress connection limit"},
					},
					clearMarkRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					// egress max connection rules
					{
						Match:  Match(),
						Action: LimitNumConnectionsAction{Num: 10, RejectWith: generictables.RejectWithTCPReset},

						Comment: []string{"Reject connections over egress connection limit"},
					},
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234", epMarkMapper,
					true,
					nil,
					nil,
					&proto.QoSControls{
						EgressMaxConnections:  10,
						IngressMaxConnections: 20,
					},
				)).To(Equal(expected))
			})
		})

		Context("with normal config and flow logs enabled", func() {
			BeforeEach(func() {
				rrConfigNormalMangleReturn.FlowLogsEnabled = true
				renderer = NewRenderer(rrConfigNormalMangleReturn)
				epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
					rrConfigNormalMangleReturn.MarkNonCaliEndpoint)
			})

			It("should render a minimal workload endpoint", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					nflogProfileIngress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					nflogProfileEgress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})

				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234", epMarkMapper,
					true,
					nil,
					nil,
					nil)).To(Equal(expected))
			})

			It("should render a disabled workload endpoint", func() {
				commonRules := []generictables.Rule{
					endpointAdminDisabledRule(denyAction),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: commonRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: commonRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})

				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234", epMarkMapper,
					false,
					nil,
					nil,
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "ai"),
					policyAcceptedRule(),
					matchPolicyIngress("default", "bi"),
					policyAcceptedRule(),
					nflogDefaultTierIngress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					nflogProfileIngress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					matchPolicyEgress("default", "ae"),
					policyAcceptedRule(),
					matchPolicyEgress("default", "be"),
					policyAcceptedRule(),
					nflogDefaultTierEgress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					nflogProfileEgress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"ai", "bi"},
						EgressPolicies:  []string{"ae", "be"},
					}}),
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a workload endpoint with policy groups", func() {
				polGrpInABC := &PolicyGroup{
					Tier:        "default",
					Direction:   PolicyDirectionInbound,
					PolicyNames: []string{"a", "b", "c"},
					Selector:    "all()",
				}
				polGrpInEF := &PolicyGroup{
					Tier:        "default",
					Direction:   PolicyDirectionInbound,
					PolicyNames: []string{"e", "f"},
					Selector:    "someLabel == 'bar'",
				}
				polGrpOutAB := &PolicyGroup{
					Tier:        "default",
					Direction:   PolicyDirectionOutbound,
					PolicyNames: []string{"a", "b"},
					Selector:    "all()",
				}
				polGrpOutDE := &PolicyGroup{
					Tier:        "default",
					Direction:   PolicyDirectionOutbound,
					PolicyNames: []string{"d", "e"},
					Selector:    "someLabel == 'bar'",
				}

				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					jumpToPolicyGroup(polGrpInABC.ChainName(), 0x10),
					policyAcceptedRule(),
					jumpToPolicyGroup(polGrpInEF.ChainName(), 0x10),
					policyAcceptedRule(),
					nflogDefaultTierIngress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					nflogProfileIngress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					jumpToPolicyGroup(polGrpOutAB.ChainName(), 0x10),
					policyAcceptedRule(),
					jumpToPolicyGroup(polGrpOutDE.ChainName(), 0x10),
					policyAcceptedRule(),
					nflogDefaultTierEgress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					nflogProfileEgress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})

				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					[]TierPolicyGroups{
						{
							Name: "default",
							IngressPolicies: []*PolicyGroup{
								polGrpInABC,
								polGrpInEF,
							},
							EgressPolicies: []*PolicyGroup{
								polGrpOutAB,
								polGrpOutDE,
							},
						},
					},
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint - one staged policy, one enforced", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "bi"),
					policyAcceptedRule(),
					nflogDefaultTierIngress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					nflogProfileIngress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					matchPolicyEgress("default", "ae"),
					policyAcceptedRule(),
					nflogDefaultTierEgress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					nflogProfileEgress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"staged:ai", "bi"},
						EgressPolicies:  []string{"ae", "staged:be"},
					}}),
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint - both staged, end-of-tier action is pass", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					nflogDefaultTierIngressWithPassAction(),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					nflogProfileIngress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					nflogDefaultTierEgressWithPassAction(),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					nflogProfileEgress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"staged:ai", "staged:bi"},
						EgressPolicies:  []string{"staged:ae", "staged:be"},
					}}),
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint - staged policy group, end-of-tier pass", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					nflogDefaultTierIngressWithPassAction(),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					nflogProfileIngress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					nflogDefaultTierEgressWithPassAction(),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					nflogProfileEgress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					[]TierPolicyGroups{
						{
							Name: "default",
							IngressPolicies: []*PolicyGroup{{
								Tier:        "default",
								Direction:   PolicyDirectionInbound,
								PolicyNames: []string{"staged:ai", "staged:bi"},
								Selector:    "all()",
							}},
							EgressPolicies: []*PolicyGroup{{
								Tier:        "default",
								Direction:   PolicyDirectionOutbound,
								PolicyNames: []string{"staged:ae", "staged:be"},
								Selector:    "all()",
							}},
						},
					},
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a fully-loaded workload endpoint with tier DefaultAction is Pass", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "ai"),
					policyAcceptedRule(),
					matchPolicyIngress("default", "bi"),
					policyAcceptedRule(),
					nflogDefaultTierIngressWithPassAction(),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					nflogProfileIngress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					startOfTierDefault(),
					matchPolicyEgress("default", "ae"),
					policyAcceptedRule(),
					matchPolicyEgress("default", "be"),
					policyAcceptedRule(),
					nflogDefaultTierEgressWithPassAction(),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					nflogProfileEgress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						DefaultAction:   "Pass",
						IngressPolicies: []string{"ai", "bi"},
						EgressPolicies:  []string{"ae", "be"},
					}}),
					[]string{"prof1", "prof2"},
					nil,
				)).To(Equal(expected))
			})

			It("should render a host endpoint", func() {
				actual := renderer.HostEndpointToFilterChains("eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"ai", "bi"},
						EgressPolicies:  []string{"ae", "be"},
					}}),
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"afi", "bfi"},
						EgressPolicies:  []string{"afe", "bfe"},
					}}),
					epMarkMapper,
					[]string{"prof1", "prof2"},
				)

				toHostRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					// Host endpoints get extra failsafe rules.
					failSafeEgress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyEgress("default", "ae"),
					policyAcceptedRule(),
					matchPolicyEgress("default", "be"),
					policyAcceptedRule(),
					nflogDefaultTierEgress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileEgress("prof1"),
					profileAcceptedRule(),
					matchProfileEgress("prof2"),
					profileAcceptedRule(),
					nflogProfileEgress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromHostRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					// Host endpoints get extra failsafe rules.
					failSafeIngress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "ai"),
					policyAcceptedRule(),
					matchPolicyIngress("default", "bi"),
					policyAcceptedRule(),
					nflogDefaultTierIngress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
					matchProfileIngress("prof1"),
					profileAcceptedRule(),
					matchProfileIngress("prof2"),
					profileAcceptedRule(),
					nflogProfileIngress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				toHostFWRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					jumpToPolicyGroup("cali-po-default/afe", 0x10),
					policyAcceptedRule(),
					jumpToPolicyGroup("cali-po-default/bfe", 0x10),
					policyAcceptedRule(),
					nflogDefaultTierEgress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
				}

				fromHostFWRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					conntrackDenyRule(denyAction),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "afi"),
					policyAcceptedRule(),
					matchPolicyIngress("default", "bfi"),
					policyAcceptedRule(),
					nflogDefaultTierIngress(),
					defaultTierDefaultDropRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-th-eth0",
						Rules: toHostRules,
					},
					{
						Name:  "cali-fh-eth0",
						Rules: fromHostRules,
					},
					{
						Name:  "cali-thfw-eth0",
						Rules: toHostFWRules,
					},
					{
						Name:  "cali-fhfw-eth0",
						Rules: fromHostFWRules,
					},
					{
						Name:  "cali-sm-eth0",
						Rules: setEndpointMarkRules(0xa200, 0xff00),
					},
				})
				Expect(actual).To(Equal(expected), cmp.Diff(actual, expected))
			})

			It("should render host endpoint raw chains with untracked policies", func() {
				toHostRules := []generictables.Rule{
					// Host endpoints get extra failsafe rules.
					failSafeEgress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyEgress("default", "c"),
					// Extra NOTRACK action before returning in raw table.
					untrackedRule(),
					policyAcceptedRule(),
					// No drop actions or profiles in raw table.
				}
				fromHostRules := []generictables.Rule{
					// Host endpoints get extra failsafe rules.
					failSafeIngress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "c"),
					// Extra NOTRACK action before returning in raw table.
					untrackedRule(),
					policyAcceptedRule(),
					// No drop actions or profiles in raw table.
				}

				expected := []*generictables.Chain{
					{
						Name:  "cali-th-eth0",
						Rules: toHostRules,
					},
					{
						Name:  "cali-fh-eth0",
						Rules: fromHostRules,
					},
				}
				Expect(renderer.HostEndpointToRawChains("eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"c"},
						EgressPolicies:  []string{"c"},
					}}),
				)).To(Equal(expected))
			})

			It("should render host endpoint mangle chains with pre-DNAT policies", func() {
				fromHostRules := []generictables.Rule{
					// conntrack rules.
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: SetMarkAction{Mark: 0x8},
					},
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: ReturnAction{},
					},
					conntrackDenyRule(denyAction),
					// Host endpoints get extra failsafe rules.
					failSafeIngress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "c"),
					policyAcceptedRule(),
					// No drop actions or profiles in raw table.
				}

				expected := []*generictables.Chain{
					{
						Name:  "cali-fh-eth0",
						Rules: fromHostRules,
					},
				}
				Expect(renderer.HostEndpointToMangleIngressChains(
					"eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"c"},
					}}),
				)).To(Equal(expected))
			})
		})

		Describe("with ctstate=INVALID disabled", func() {
			BeforeEach(func() {
				rrConfigConntrackDisabledReturnAction.FlowLogsEnabled = false
				renderer = NewRenderer(rrConfigConntrackDisabledReturnAction)
				epMarkMapper = NewEndpointMarkMapper(rrConfigConntrackDisabledReturnAction.MarkEndpoint,
					rrConfigConntrackDisabledReturnAction.MarkNonCaliEndpoint)
			})

			It("should render a minimal workload endpoint", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: SetMarkAction{Mark: 0x8},
					},
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: ReturnAction{},
					},
					clearMarkRule(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: SetMarkAction{Mark: 0x8},
					},
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: ReturnAction{},
					},
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					nil,
					nil,
					nil,
				)).To(Equal(expected))
			})

			It("should render host endpoint mangle chains with pre-DNAT policies", func() {
				fromHostRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					// Host endpoints get extra failsafe rules.
					failSafeIngress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "c"),
					policyAcceptedRule(),
					// No drop actions or profiles in raw table.
				}

				expected := []*generictables.Chain{
					{
						Name:  "cali-fh-eth0",
						Rules: fromHostRules,
					},
				}
				Expect(renderer.HostEndpointToMangleIngressChains(
					"eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"c"},
					}}),
				)).To(Equal(expected))
			})
		})

		Describe("with ctstate=INVALID disabled and flow logs enabled", func() {
			BeforeEach(func() {
				rrConfigConntrackDisabledReturnAction.FlowLogsEnabled = true
				renderer = NewRenderer(rrConfigConntrackDisabledReturnAction)
				epMarkMapper = NewEndpointMarkMapper(rrConfigConntrackDisabledReturnAction.MarkEndpoint,
					rrConfigConntrackDisabledReturnAction.MarkNonCaliEndpoint)
			})

			It("should render a minimal workload endpoint", func() {
				toWlRules := []generictables.Rule{
					// conntrack rules.
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: SetMarkAction{Mark: 0x8},
					},
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: ReturnAction{},
					},
					clearMarkRule(),
					nflogProfileIngress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}
				fromWlRules := []generictables.Rule{
					// conntrack rules.
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: SetMarkAction{Mark: 0x8},
					},
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: ReturnAction{},
					},
					clearMarkRule(),
					dropVXLANRule(VXLANPort, denyAction, denyActionString),
					dropIPIPRule(denyAction, denyActionString),
					nflogProfileEgress(),
					noProfiletMatchedRule(denyAction, denyActionString),
				}

				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name:  "cali-tw-cali1234",
						Rules: toWlRules,
					},
					{
						Name:  "cali-fw-cali1234",
						Rules: fromWlRules,
					},
					{
						Name:  "cali-sm-cali1234",
						Rules: setEndpointMarkRules(0xd400, 0xff00),
					},
				})
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					nil,
					nil,
					nil,
				)).To(Equal(expected))
			})

			It("should render host endpoint mangle chains with pre-DNAT policies", func() {
				fromHostRules := []generictables.Rule{
					// conntrack rules.
					conntrackAcceptRule(),
					// Host endpoints get extra failsafe rules.
					failSafeIngress(),
					clearMarkRule(),
					startOfTierDefault(),
					matchPolicyIngress("default", "c"),
					policyAcceptedRule(),
					// No drop actions or profiles in raw table.
				}
				expected := []*generictables.Chain{
					{
						Name:  "cali-fh-eth0",
						Rules: fromHostRules,
					},
				}
				Expect(renderer.HostEndpointToMangleIngressChains(
					"eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"c"},
					}}),
				)).To(Equal(expected))
			})
		})

		Describe("Disabling adding drop encap rules", func() {
			Context("VXLAN allowed, IPIP dropped", func() {
				It("should render a minimal workload endpoint without VXLAN drop encap rule and with IPIP drop encap rule", func() {
					rrConfigNormalMangleReturn.FlowLogsEnabled = false
					rrConfigNormalMangleReturn.AllowVXLANPacketsFromWorkloads = true
					renderer = NewRenderer(rrConfigNormalMangleReturn)
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
						rrConfigNormalMangleReturn.MarkNonCaliEndpoint)

					toWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}
					fromWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						dropIPIPRule(denyAction, denyActionString),
						noProfiletMatchedRule(denyAction, denyActionString),
					}

					expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name:  "cali-tw-cali1234",
							Rules: toWlRules,
						},
						{
							Name:  "cali-fw-cali1234",
							Rules: fromWlRules,
						},
						{
							Name:  "cali-sm-cali1234",
							Rules: setEndpointMarkRules(0xd400, 0xff00),
						},
					})
					Expect(renderer.WorkloadEndpointToIptablesChains(
						"cali1234", epMarkMapper,
						true,
						nil,
						nil,
						nil,
					)).To(Equal(expected))
				})

				It("should render a minimal workload endpoint without VXLAN drop encap rule and with IPIP drop encap rule with flowlogs", func() {
					rrConfigNormalMangleReturn.FlowLogsEnabled = true
					rrConfigNormalMangleReturn.AllowVXLANPacketsFromWorkloads = true
					renderer = NewRenderer(rrConfigNormalMangleReturn)
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
						rrConfigNormalMangleReturn.MarkNonCaliEndpoint)

					toWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						nflogProfileIngress(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}
					fromWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						dropIPIPRule(denyAction, denyActionString),
						nflogProfileEgress(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}

					expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name:  "cali-tw-cali1234",
							Rules: toWlRules,
						},
						{
							Name:  "cali-fw-cali1234",
							Rules: fromWlRules,
						},
						{
							Name:  "cali-sm-cali1234",
							Rules: setEndpointMarkRules(0xd400, 0xff00),
						},
					})

					Expect(renderer.WorkloadEndpointToIptablesChains(
						"cali1234", epMarkMapper,
						true,
						nil,
						nil,
						nil,
					)).To(Equal(expected))
				})
			})

			Context("VXLAN dropped, IPIP allowed", func() {
				It("should render a minimal workload endpoint with VXLAN drop encap rule and without IPIP drop encap rule", func() {
					rrConfigNormalMangleReturn.FlowLogsEnabled = false
					rrConfigNormalMangleReturn.AllowIPIPPacketsFromWorkloads = true
					renderer = NewRenderer(rrConfigNormalMangleReturn)
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
						rrConfigNormalMangleReturn.MarkNonCaliEndpoint)

					actual := renderer.WorkloadEndpointToIptablesChains(
						"cali1234", epMarkMapper,
						true,
						nil,
						nil,
						nil,
					)

					toWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}
					fromWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						dropVXLANRule(VXLANPort, denyAction, denyActionString),
						noProfiletMatchedRule(denyAction, denyActionString),
					}

					expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name:  "cali-tw-cali1234",
							Rules: toWlRules,
						},
						{
							Name:  "cali-fw-cali1234",
							Rules: fromWlRules,
						},
						{
							Name:  "cali-sm-cali1234",
							Rules: setEndpointMarkRules(0xd400, 0xff00),
						},
					})
					Expect(actual).To(Equal(expected), cmp.Diff(actual, expected))
				})

				It("should render a minimal workload endpoint with VXLAN drop encap rule and without IPIP drop encap rule with flowlogs", func() {
					rrConfigNormalMangleReturn.FlowLogsEnabled = true
					rrConfigNormalMangleReturn.AllowIPIPPacketsFromWorkloads = true
					renderer = NewRenderer(rrConfigNormalMangleReturn)
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
						rrConfigNormalMangleReturn.MarkNonCaliEndpoint)

					actual := renderer.WorkloadEndpointToIptablesChains(
						"cali1234", epMarkMapper,
						true,
						nil,
						nil,
						nil,
					)

					toWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						nflogProfileIngress(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}
					fromWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						dropVXLANRule(VXLANPort, denyAction, denyActionString),
						nflogProfileEgress(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}

					expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name:  "cali-tw-cali1234",
							Rules: toWlRules,
						},
						{
							Name:  "cali-fw-cali1234",
							Rules: fromWlRules,
						},
						{
							Name:  "cali-sm-cali1234",
							Rules: setEndpointMarkRules(0xd400, 0xff00),
						},
					})
					Expect(actual).To(Equal(expected), cmp.Diff(actual, expected))
				})
			})

			Context("VXLAN and IPIP allowed", func() {
				It("should render a minimal workload endpoint without both VXLAN and IPIP drop encap rule", func() {
					rrConfigNormalMangleReturn.FlowLogsEnabled = false
					rrConfigNormalMangleReturn.AllowVXLANPacketsFromWorkloads = true
					rrConfigNormalMangleReturn.AllowIPIPPacketsFromWorkloads = true
					renderer = NewRenderer(rrConfigNormalMangleReturn)
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
						rrConfigNormalMangleReturn.MarkNonCaliEndpoint)

					toWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}
					fromWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}

					expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name:  "cali-tw-cali1234",
							Rules: toWlRules,
						},
						{
							Name:  "cali-fw-cali1234",
							Rules: fromWlRules,
						},
						{
							Name:  "cali-sm-cali1234",
							Rules: setEndpointMarkRules(0xd400, 0xff00),
						},
					})

					Expect(renderer.WorkloadEndpointToIptablesChains(
						"cali1234", epMarkMapper,
						true,
						nil,
						nil,
						nil,
					)).To(Equal(expected))
				})

				It("should render a minimal workload endpoint without both VXLAN and IPIP drop encap rule with flowlogs", func() {
					rrConfigNormalMangleReturn.FlowLogsEnabled = true
					rrConfigNormalMangleReturn.AllowVXLANPacketsFromWorkloads = true
					rrConfigNormalMangleReturn.AllowIPIPPacketsFromWorkloads = true
					renderer = NewRenderer(rrConfigNormalMangleReturn)
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
						rrConfigNormalMangleReturn.MarkNonCaliEndpoint)

					toWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						nflogProfileIngress(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}
					fromWlRules := []generictables.Rule{
						// conntrack rules.
						conntrackAcceptRule(),
						conntrackDenyRule(denyAction),
						clearMarkRule(),
						nflogProfileEgress(),
						noProfiletMatchedRule(denyAction, denyActionString),
					}

					expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name:  "cali-tw-cali1234",
							Rules: toWlRules,
						},
						{
							Name:  "cali-fw-cali1234",
							Rules: fromWlRules,
						},
						{
							Name:  "cali-sm-cali1234",
							Rules: setEndpointMarkRules(0xd400, 0xff00),
						},
					})

					Expect(renderer.WorkloadEndpointToIptablesChains(
						"cali1234", epMarkMapper,
						true,
						nil,
						nil,
						nil,
					)).To(Equal(expected))
				})
			})
			AfterEach(func() {
				rrConfigNormalMangleReturn.AllowIPIPPacketsFromWorkloads = false
				rrConfigNormalMangleReturn.AllowVXLANPacketsFromWorkloads = false
			})
		})
	}
})

func trimSMChain(ipvsEnable bool, chains []*generictables.Chain) []*generictables.Chain {
	result := []*generictables.Chain{}
	for _, chain := range chains {
		if !ipvsEnable && strings.HasPrefix(chain.Name, "cali-sm") {
			continue
		}
		result = append(result, chain)
	}

	return result
}

func tiersToSinglePolGroups(tiers []*proto.TierInfo) (tierGroups []TierPolicyGroups) {
	for _, t := range tiers {
		tg := TierPolicyGroups{
			Name:          t.Name,
			DefaultAction: t.DefaultAction,
		}
		for _, n := range t.IngressPolicies {
			tg.IngressPolicies = append(tg.IngressPolicies, &PolicyGroup{
				Tier:        t.Name,
				PolicyNames: []string{n},
			})
		}
		for _, n := range t.EgressPolicies {
			tg.EgressPolicies = append(tg.EgressPolicies, &PolicyGroup{
				Tier:        t.Name,
				PolicyNames: []string{n},
			})
		}
		tierGroups = append(tierGroups, tg)
	}

	return
}

var _ = Describe("PolicyGroups", func() {
	It("should make sensible UIDs", func() {
		pgs := []PolicyGroup{
			{
				Tier:        "default",
				Direction:   PolicyDirectionInbound,
				PolicyNames: nil,
				Selector:    "all()",
			},
			{
				Tier:        "foo",
				Direction:   PolicyDirectionInbound,
				PolicyNames: nil,
				Selector:    "all()",
			},
			{
				Tier:        "default",
				Direction:   PolicyDirectionOutbound,
				PolicyNames: nil,
				Selector:    "all()",
			},
			{
				Tier:        "default",
				Direction:   PolicyDirectionInbound,
				PolicyNames: []string{"a"},
				Selector:    "all()",
			},
			{
				Tier:        "default",
				Direction:   PolicyDirectionInbound,
				PolicyNames: nil,
				Selector:    "a == 'b'",
			},
			{
				Tier:        "default",
				Direction:   PolicyDirectionInbound,
				PolicyNames: []string{"a", "b"},
				Selector:    "all()",
			},
			{
				Tier:        "default",
				Direction:   PolicyDirectionInbound,
				PolicyNames: []string{"ab"},
				Selector:    "all()",
			},
			{
				Tier:        "default",
				Direction:   PolicyDirectionInbound,
				PolicyNames: []string{"aaa", "bbb"},
				Selector:    "all()",
			},
			{
				Tier:      "default",
				Direction: PolicyDirectionInbound,
				// Between this and the entry above, we check that the data
				// sent to the hasher is delimited somehow.
				PolicyNames: []string{"aaab", "bb"},
				Selector:    "all()",
			},
		}

		seenUIDs := map[string]PolicyGroup{}
		for _, pg := range pgs {
			uid := pg.UniqueID()
			Expect(seenUIDs).NotTo(HaveKey(uid), fmt.Sprintf("UID clash with %v", pg))
			Expect(pg.UniqueID()).To(Equal(uid), "UID different on each call")
		}
	})

	It("should detect staged policies", func() {
		pg := PolicyGroup{
			Tier:      "default",
			Direction: PolicyDirectionInbound,
			PolicyNames: []string{
				"namespace/staged:foo",
			},
			Selector: "all()",
		}
		Expect(pg.HasNonStagedPolicies()).To(BeFalse())

		pg.PolicyNames = []string{
			"staged:foo",
		}
		Expect(pg.HasNonStagedPolicies()).To(BeFalse())

		pg.PolicyNames = []string{
			"namespace/staged:foo",
			"namespace/bar",
		}
		Expect(pg.HasNonStagedPolicies()).To(BeTrue())
	})
})

var _ = table.DescribeTable("PolicyGroup chains",
	func(group PolicyGroup, expectedRules []generictables.Rule) {
		renderer := NewRenderer(Config{
			MarkAccept:          0x8,
			MarkPass:            0x10,
			MarkScratch0:        0x20,
			MarkScratch1:        0x40,
			MarkDrop:            0x80,
			MarkEndpoint:        0xff00,
			MarkNonCaliEndpoint: 0x0100,
		})
		chains := renderer.PolicyGroupToIptablesChains(&group)
		Expect(chains).To(HaveLen(1))
		Expect(chains[0].Name).ToNot(BeEmpty())
		Expect(chains[0].Name).To(Equal(group.ChainName()))
		Expect(chains[0].Rules).To(Equal(expectedRules))
	},
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionInbound,
			PolicyNames: []string{"a"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			jumpToPolicyGroup("cali-pi-default/a", 0),
		},
	),
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionInbound,
			PolicyNames: []string{"a", "b"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			jumpToPolicyGroup("cali-pi-default/a", 0),
			jumpToPolicyGroup("cali-pi-default/b", 0x18),
		},
	),
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionInbound,
			PolicyNames: []string{"a", "b", "c"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			jumpToPolicyGroup("cali-pi-default/a", 0),
			jumpToPolicyGroup("cali-pi-default/b", 0x18),
			jumpToPolicyGroup("cali-pi-default/c", 0x18),
		},
	),
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionInbound,
			PolicyNames: []string{"a", "b", "c", "d"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			jumpToPolicyGroup("cali-pi-default/a", 0),
			jumpToPolicyGroup("cali-pi-default/b", 0x18),
			jumpToPolicyGroup("cali-pi-default/c", 0x18),
			jumpToPolicyGroup("cali-pi-default/d", 0x18),
		},
	),
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionInbound,
			PolicyNames: []string{"a", "b", "c", "d", "e"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			jumpToPolicyGroup("cali-pi-default/a", 0),
			jumpToPolicyGroup("cali-pi-default/b", 0x18),
			jumpToPolicyGroup("cali-pi-default/c", 0x18),
			jumpToPolicyGroup("cali-pi-default/d", 0x18),
			jumpToPolicyGroup("cali-pi-default/e", 0x18),
		},
	),
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionInbound,
			PolicyNames: []string{"a", "b", "c", "d", "e", "f"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			jumpToPolicyGroup("cali-pi-default/a", 0),
			jumpToPolicyGroup("cali-pi-default/b", 0x18),
			jumpToPolicyGroup("cali-pi-default/c", 0x18),
			jumpToPolicyGroup("cali-pi-default/d", 0x18),
			jumpToPolicyGroup("cali-pi-default/e", 0x18),
			{
				// Only get a return action every 5 rules and only if it's
				// not the last action.
				Match:   Match().MarkNotClear(0x18),
				Action:  ReturnAction{},
				Comment: []string{"Return on verdict"},
			},
			jumpToPolicyGroup("cali-pi-default/f", 0),
		},
	),
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionOutbound,
			PolicyNames: []string{"a", "b", "c", "d", "e", "f", "g"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			jumpToPolicyGroup("cali-po-default/a", 0),
			jumpToPolicyGroup("cali-po-default/b", 0x18),
			jumpToPolicyGroup("cali-po-default/c", 0x18),
			jumpToPolicyGroup("cali-po-default/d", 0x18),
			jumpToPolicyGroup("cali-po-default/e", 0x18),
			{
				Match:   Match().MarkNotClear(0x18),
				Action:  ReturnAction{},
				Comment: []string{"Return on verdict"},
			},
			jumpToPolicyGroup("cali-po-default/f", 0),
			jumpToPolicyGroup("cali-po-default/g", 0x18),
		},
	),
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionOutbound,
			PolicyNames: []string{"staged:a", "staged:b", "c", "d", "e", "f", "g", "h", "i"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			// Match criteria and return rules get skipped until we hit the
			// first non-staged policy.
			jumpToPolicyGroup("cali-po-default/c", 0),
			jumpToPolicyGroup("cali-po-default/d", 0x18),
			jumpToPolicyGroup("cali-po-default/e", 0x18),
			jumpToPolicyGroup("cali-po-default/f", 0x18),
			jumpToPolicyGroup("cali-po-default/g", 0x18),
			{
				Match:   Match().MarkNotClear(0x18),
				Action:  ReturnAction{},
				Comment: []string{"Return on verdict"},
			},
			jumpToPolicyGroup("cali-po-default/h", 0),
			jumpToPolicyGroup("cali-po-default/i", 0x18),
		},
	),
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionOutbound,
			PolicyNames: []string{"staged:a", "staged:b", "staged:c", "d", "staged:e", "f", "g"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			// Match criteria and return rules get skipped until we hit the
			// first non-staged policy.
			jumpToPolicyGroup("cali-po-default/d", 0),
			jumpToPolicyGroup("cali-po-default/f", 0x18),
			jumpToPolicyGroup("cali-po-default/g", 0x18),
		},
	),
	polGroupEntry(
		PolicyGroup{
			Tier:        "default",
			Direction:   PolicyDirectionOutbound,
			PolicyNames: []string{"staged:a", "staged:b", "staged:c", "staged:d", "staged:e", "f", "g"},
			Selector:    "all()",
		},
		[]generictables.Rule{
			// Match criteria and return rules get skipped until we hit the
			// first non-staged policy.
			jumpToPolicyGroup("cali-po-default/f", 0),
			jumpToPolicyGroup("cali-po-default/g", 0x18),
		},
	),
)

func polGroupEntry(group PolicyGroup, rules []generictables.Rule) table.TableEntry {
	return table.Entry(
		fmt.Sprintf("%v", group),
		group,
		rules,
	)
}

func conntrackAcceptRule() generictables.Rule {
	return generictables.Rule{
		Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
		Action: AcceptAction{},
	}
}

func conntrackDenyRule(denyAction generictables.Action) generictables.Rule {
	return generictables.Rule{
		Match:  Match().ConntrackState("INVALID"),
		Action: denyAction,
	}
}

func clearMarkRule() generictables.Rule {
	return generictables.Rule{
		Match:  Match(),
		Action: ClearMarkAction{Mark: 0x18},
	}
}

func nflogActionProfile(group int, prefix string) generictables.Rule {
	return generictables.Rule{
		Match:  Match(),
		Action: NflogAction{Group: uint16(group), Prefix: prefix},
	}
}

func nflogProfileIngress() generictables.Rule {
	return nflogActionProfile(1, "DRI")
}

func nflogProfileEgress() generictables.Rule {
	return nflogActionProfile(2, "DRE")
}

func nflogActionDefaultTier(group int, prefix string) generictables.Rule {
	return generictables.Rule{
		Match:  Match().MarkClear(0x10),
		Action: NflogAction{Group: uint16(group), Prefix: prefix},
	}
}

func nflogDefaultTierIngress() generictables.Rule {
	return nflogActionDefaultTier(1, "DPI|default")
}

func nflogDefaultTierEgress() generictables.Rule {
	return nflogActionDefaultTier(2, "DPE|default")
}

func nflogDefaultTierIngressWithPassAction() generictables.Rule {
	return nflogActionDefaultTier(1, "PPI|default")
}

func nflogDefaultTierEgressWithPassAction() generictables.Rule {
	return nflogActionDefaultTier(2, "PPE|default")
}

func startOfTierDefault() generictables.Rule {
	return generictables.Rule{
		Comment: []string{"Start of tier default"},
		Match:   Match(),
		Action:  ClearMarkAction{Mark: 0x10},
	}
}

func defaultTierDefaultDropRule(action generictables.Action, actionStr string) generictables.Rule {
	return tierDefaultActionRule(action, actionStr, "default")
}

func tierDefaultActionRule(
	action generictables.Action,
	actionStr string,
	tier string,
) generictables.Rule {
	return generictables.Rule{
		Match:  Match().MarkClear(0x10),
		Action: action,
		Comment: []string{fmt.Sprintf("End of tier %s. %s if no policies passed packet",
			tier,
			actionStr,
		)},
	}
}

func matchPolicy(target string) generictables.Rule {
	return generictables.Rule{
		Match:  Match().MarkClear(0x10),
		Action: JumpAction{Target: target},
	}
}

func matchPolicyIngress(tier, name string) generictables.Rule {
	return matchPolicy(fmt.Sprintf("cali-pi-%v/%v", tier, name))
}

func matchPolicyEgress(tier, name string) generictables.Rule {
	return matchPolicy(fmt.Sprintf("cali-po-%v/%v", tier, name))
}

func matchProfile(target string) generictables.Rule {
	return generictables.Rule{
		Match:  Match(),
		Action: JumpAction{Target: target},
	}
}

func matchProfileIngress(name string) generictables.Rule {
	return matchProfile(fmt.Sprintf("cali-pri-%v", name))
}

func matchProfileEgress(name string) generictables.Rule {
	return matchProfile(fmt.Sprintf("cali-pro-%v", name))
}

func noProfiletMatchedRule(action generictables.Action, actionStr string) generictables.Rule {
	return generictables.Rule{
		Match:   Match(),
		Action:  action,
		Comment: []string{fmt.Sprintf("%s if no profiles matched", actionStr)},
	}
}

func profileAcceptedRule() generictables.Rule {
	return generictables.Rule{
		Match:   Match().MarkSingleBitSet(0x8),
		Action:  ReturnAction{},
		Comment: []string{"Return if profile accepted"},
	}
}

func policyAcceptedRule() generictables.Rule {
	return generictables.Rule{
		Match:   Match().MarkSingleBitSet(0x8),
		Action:  ReturnAction{},
		Comment: []string{"Return if policy accepted"},
	}
}

func failSafeIngress() generictables.Rule {
	return generictables.Rule{
		Match:  Match(),
		Action: JumpAction{Target: "cali-failsafe-in"},
	}
}

func failSafeEgress() generictables.Rule {
	return generictables.Rule{
		Match:  Match(),
		Action: JumpAction{Target: "cali-failsafe-out"},
	}
}

func endpointAdminDisabledRule(denyAction generictables.Action) generictables.Rule {
	return generictables.Rule{
		Match:   Match(),
		Action:  denyAction,
		Comment: []string{"Endpoint admin disabled"},
	}
}

func untrackedRule() generictables.Rule {
	return generictables.Rule{
		Match:  Match().MarkSingleBitSet(0x8),
		Action: NoTrackAction{},
	}
}

func jumpToPolicyGroup(target string, clearMark uint32) generictables.Rule {
	match := Match()
	if clearMark != 0 {
		match = Match().MarkClear(clearMark)
	}
	return generictables.Rule{
		Match:  match,
		Action: JumpAction{Target: target},
	}
}

func setEndpointMarkRules(mark, mask uint32) []generictables.Rule {
	return []generictables.Rule{
		{
			Match:  Match(),
			Action: SetMaskedMarkAction{Mark: mark, Mask: 0xff00},
		},
	}
}

func dropIPIPRule(action generictables.Action, actionStr string) generictables.Rule {
	return generictables.Rule{
		Match:   Match().ProtocolNum(ProtoIPIP),
		Action:  action,
		Comment: []string{fmt.Sprintf("%s IPinIP encapped packets originating in workloads", actionStr)},
	}
}

func dropVXLANRule(port int, action generictables.Action, actionStr string) generictables.Rule {
	return generictables.Rule{
		Match: Match().ProtocolNum(ProtoUDP).
			DestPorts(uint16(port)),
		Action:  action,
		Comment: []string{fmt.Sprintf("%s VXLAN encapped packets originating in workloads", actionStr)},
	}
}

func qosControlRules() []generictables.Rule {
	return []generictables.Rule{
		// ingress packet rate rules
		{
			Match:   Match(),
			Action:  ClearMarkAction{Mark: 0x20},
			Comment: []string{"Clear ingress packet rate limit mark"},
		},
		{
			Match:   Match(),
			Action:  LimitPacketRateAction{Rate: 2000, Burst: 4000, Mark: 0x20},
			Comment: []string{"Mark packets within ingress packet rate limit"},
		},
		{
			Match:   Match().NotMarkMatchesWithMask(0x20, 0x20),
			Action:  DropAction{},
			Comment: []string{"Drop packets over ingress packet rate limit"},
		},
		{
			Match:   Match(),
			Action:  ClearMarkAction{Mark: 0x20},
			Comment: []string{"Clear ingress packet rate limit mark"},
		},
	}
}
