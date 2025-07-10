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

var _ = Describe("Endpoints", endpointRulesTests(false))
var _ = Describe("Endpoints with flowlogs", endpointRulesTests(true))

func endpointRulesTests(flowLogsEnabled bool) func() {
	return func() {
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
				FlowLogsEnabled:        flowLogsEnabled,
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
				FlowLogsEnabled:         flowLogsEnabled,
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
					renderer = NewRenderer(rrConfigNormalMangleReturn)
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
						rrConfigNormalMangleReturn.MarkNonCaliEndpoint)
				})

				It("should render a minimal workload endpoint", func() {
					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
						withEgress(),
					).build()

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
					rules := newRuleBuilder(
						withDenyAction(denyAction),
						withFlowLogs(flowLogsEnabled),
						withDisabledEndpoint(),
					).build()

					expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name:  "cali-tw-cali1234",
							Rules: rules,
						},
						{
							Name:  "cali-fw-cali1234",
							Rules: rules,
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
					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("ai", "bi"),
						withProfiles("prof1", "prof2"),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
						withEgress(),
						withPolicies("ae", "be"),
						withProfiles("prof1", "prof2"),
					).build()

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

					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicyGroups(polGrpInABC.ChainName(), polGrpInEF.ChainName()),
						withProfiles("prof1", "prof2"),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withEgress(),
						withPolicyGroups(polGrpOutAB.ChainName(), polGrpOutDE.ChainName()),
						withProfiles("prof1", "prof2"),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
					).build()

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
					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("staged:ai", "bi"),
						withProfiles("prof1", "prof2"),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withEgress(),
						withPolicies("ae", "staged:be"),
						withProfiles("prof1", "prof2"),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
					).build()

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
					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("staged:ai", "staged:bi"),
						withProfiles("prof1", "prof2"),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withEgress(),
						withPolicies("staged:ae", "staged:be"),
						withProfiles("prof1", "prof2"),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
					).build()

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
					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicyGroups("staged:ai", "staged:bi"),
						withProfiles("prof1", "prof2"),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withEgress(),
						withPolicies("staged:ae", "staged:be"),
						withProfiles("prof1", "prof2"),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
					).build()

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
					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("ai", "bi"),
						withProfiles("prof1", "prof2"),
						withTierPassAction(),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withEgress(),
						withPolicies("ae", "be"),
						withProfiles("prof1", "prof2"),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
						withTierPassAction(),
					).build()

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
					toHostRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("ae", "be"),
						withProfiles("prof1", "prof2"),
						forHostEndpoint(),
						withEgress(),
					).build()

					fromHostRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("ai", "bi"),
						withProfiles("prof1", "prof2"),
						forHostEndpoint(),
					).build()

					toHostFWRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("afe", "bfe"),
						withForwardPolicies(),
						withEgress(),
						forHostEndpoint(),
					).build()

					fromHostFWRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("afi", "bfi"),
						withForwardPolicies(),
						forHostEndpoint(),
					).build()

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
					toHostRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("c"),
						forHostEndpoint(),
						withUntrackedPolicies(),
						withEgress(),
					).build()

					fromHostRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("c"),
						forHostEndpoint(),
						withUntrackedPolicies(),
					).build()

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
					fromHostRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("c"),
						forHostEndpoint(),
						withPreDNATPolicies(),
					).build()
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
					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withQoSControls(2000, 4000),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withEgress(),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
						withQoSControls(1000, 2000),
					).build()

					expected := []*generictables.Chain{
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
					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withQoSConnection(20),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withEgress(),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
						withQoSConnection(10),
					).build()

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

			Describe("with ctstate=INVALID disabled", func() {
				BeforeEach(func() {
					renderer = NewRenderer(rrConfigConntrackDisabledReturnAction)
					epMarkMapper = NewEndpointMarkMapper(rrConfigConntrackDisabledReturnAction.MarkEndpoint,
						rrConfigConntrackDisabledReturnAction.MarkNonCaliEndpoint)
				})

				It("should render a minimal workload endpoint", func() {
					toWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withInvalidCTStateDisabled(),
					).build()

					fromWlRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withInvalidCTStateDisabled(),
						withEgress(),
						withDropIPIP(),
						withDropVXLAN(VXLANPort),
					).build()

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
					fromHostRules := newRuleBuilder(
						withFlowLogs(flowLogsEnabled),
						withDenyAction(denyAction),
						withDenyActionString(denyActionString),
						withPolicies("c"),
						forHostEndpoint(),
						withPreDNATPolicies(),
						withInvalidCTStateDisabled(),
					).build()

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
						rrConfigNormalMangleReturn.AllowVXLANPacketsFromWorkloads = true
						renderer = NewRenderer(rrConfigNormalMangleReturn)
						epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
							rrConfigNormalMangleReturn.MarkNonCaliEndpoint)

						toWlRules := newRuleBuilder(
							withFlowLogs(flowLogsEnabled),
							withDenyAction(denyAction),
							withDenyActionString(denyActionString),
						).build()

						fromWlRules := newRuleBuilder(
							withFlowLogs(flowLogsEnabled),
							withDenyAction(denyAction),
							withDenyActionString(denyActionString),
							withDropIPIP(),
							withEgress(),
						).build()

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

						toWlRules := newRuleBuilder(
							withFlowLogs(flowLogsEnabled),
							withDenyAction(denyAction),
							withDenyActionString(denyActionString),
						).build()

						fromWlRules := newRuleBuilder(
							withFlowLogs(flowLogsEnabled),
							withDenyAction(denyAction),
							withDenyActionString(denyActionString),
							withDropVXLAN(VXLANPort),
							withEgress(),
						).build()

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
						rrConfigNormalMangleReturn.AllowVXLANPacketsFromWorkloads = true
						rrConfigNormalMangleReturn.AllowIPIPPacketsFromWorkloads = true
						renderer = NewRenderer(rrConfigNormalMangleReturn)
						epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.MarkEndpoint,
							rrConfigNormalMangleReturn.MarkNonCaliEndpoint)

						toWlRules := newRuleBuilder(
							withFlowLogs(flowLogsEnabled),
							withDenyAction(denyAction),
							withDenyActionString(denyActionString),
						).build()

						fromWlRules := newRuleBuilder(
							withFlowLogs(flowLogsEnabled),
							withDenyAction(denyAction),
							withDenyActionString(denyActionString),
							withEgress(),
						).build()

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
	}
}

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
	return table.Entry(fmt.Sprintf("%v", group), group, rules)
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

type ruleBuilderOpt func(*ruleBuilder)

func withEgress() ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.egress = true
	}
}

func withDenyAction(action generictables.Action) ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.denyAction = action
	}
}

func withDenyActionString(actionStr string) ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.denyActionString = actionStr
	}
}

func withDropIPIP() ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.dropIPIP = true
	}
}

func withDropVXLAN(vxlanPort int) ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.vxlanPort = vxlanPort
		r.dropVXLAN = true
	}
}

func withPolicies(policies ...string) ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.policies = append(r.policies, policies...)
	}
}

func withPolicyGroups(groups ...string) ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.policyGroups = append(r.policyGroups, groups...)
	}
}

func withProfiles(profiles ...string) ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.profiles = append(r.profiles, profiles...)
	}
}

func withTierPassAction() ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.tierPassAction = true
	}
}

func withQoSControls(rate, burst int64) ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.qosControlsEnabled = true
		r.qosRate = rate
		r.qosburst = burst
	}
}

func withQoSConnection(maxConn int64) ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.qosMaxConn = maxConn
	}
}

func withFlowLogs(flowLogsEnabled bool) ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.flowLogsEnabled = flowLogsEnabled
	}
}

func withInvalidCTStateDisabled() ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.invalidCTStateDisabled = true
	}
}

func withForwardPolicies() ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.forForward = true
	}
}

func withUntrackedPolicies() ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.forUntrack = true
	}
}

func withPreDNATPolicies() ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.forPreDNAT = true
	}
}

func withDisabledEndpoint() ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.disabled = true
	}
}

func forHostEndpoint() ruleBuilderOpt {
	return func(r *ruleBuilder) {
		r.forHostEndpoint = true
	}
}

type ruleBuilder struct {
	disabled bool

	forHostEndpoint bool
	forForward      bool
	forUntrack      bool
	forPreDNAT      bool

	invalidCTStateDisabled bool
	egress                 bool
	direction              string
	denyAction             generictables.Action
	denyActionString       string

	dropIPIP  bool
	dropVXLAN bool
	vxlanPort int

	policyGroups []string
	policies     []string
	profiles     []string

	tierPassAction bool

	qosControlsEnabled bool
	qosRate            int64
	qosburst           int64
	qosMaxConn         int64

	flowLogsEnabled bool
}

func newRuleBuilder(opts ...ruleBuilderOpt) *ruleBuilder {
	b := &ruleBuilder{}
	for _, o := range opts {
		o(b)
	}

	b.direction = "ingress"
	if b.egress {
		b.direction = "egress"
	}
	return b
}

func (b *ruleBuilder) build() []generictables.Rule {
	var rules []generictables.Rule
	if b.disabled {
		return []generictables.Rule{{
			Match:   Match(),
			Action:  b.denyAction,
			Comment: []string{"Endpoint admin disabled"},
		}}
	}
	// Add rules only if endpoint is not disabled.

	// Initially, add QoS control rules.
	if b.qosControlsEnabled {
		rules = append(rules, b.qosControlRules(b.qosRate, b.qosburst)...)
	}

	// Add connection tracking rules, unless building rules for host endpoints with untracked policies.
	if !b.forUntrack {
		rules = append(rules, b.conntrackRules()...)
	}

	// Add the rest of QoS control, i.e. max connection rules.
	if b.qosMaxConn > 0 {
		rules = append(rules, b.qosMaxConnectionRule(b.qosMaxConn))
	}

	// Host endpoints get extra failsafe rules except for forward policies.
	if b.forHostEndpoint && !b.forForward {
		rules = append(rules, b.failSafeRule())
	}

	// Clean marks.
	rules = append(rules, generictables.Rule{
		Match:  Match(),
		Action: ClearMarkAction{Mark: 0x18},
	})

	// Drop VXLAN traffic originating from workloads, if not allowed.
	if b.dropVXLAN {
		rules = append(rules, generictables.Rule{
			Match: Match().ProtocolNum(ProtoUDP).
				DestPorts(uint16(b.vxlanPort)),
			Action:  b.denyAction,
			Comment: []string{fmt.Sprintf("%s VXLAN encapped packets originating in workloads", b.denyActionString)},
		})
	}

	// Drop IPIP traffic originating from workloads, if not allowed.
	if b.dropIPIP {
		rules = append(rules, generictables.Rule{
			Match:   Match().ProtocolNum(ProtoIPIP),
			Action:  b.denyAction,
			Comment: []string{fmt.Sprintf("%s IPinIP encapped packets originating in workloads", b.denyActionString)},
		})
	}

	// Add rules for policies.
	rules = append(rules, b.matchPolicies()...)

	// For host endpoints, profiles are only added for normal policies.
	if b.forHostEndpoint && (b.forForward || b.forUntrack || b.forPreDNAT) {
		return rules
	}

	// Add rules for profiles.
	rules = append(rules, b.matchProfiles()...)
	return rules
}

func (b *ruleBuilder) conntrackRules() []generictables.Rule {
	var rules []generictables.Rule

	// For PreDNAT policies.
	if b.forHostEndpoint && b.forPreDNAT {
		if b.invalidCTStateDisabled {
			rules = append(rules, conntrackAcceptRule())
			return rules
		}

		rules = append(rules, conntrackRulesWithInvalidStateDisabled()...)
		rules = append(rules, b.conntrackDenyInvalidConnections())
		return rules
	}

	// For normal policies
	if b.invalidCTStateDisabled {
		rules = append(rules, conntrackRulesWithInvalidStateDisabled()...)
	} else {
		rules = append(rules,
			conntrackAcceptRule(),
			b.conntrackDenyInvalidConnections(),
		)
	}

	return rules
}

func conntrackRulesWithInvalidStateDisabled() []generictables.Rule {
	return []generictables.Rule{
		{
			Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
			Action: SetMarkAction{Mark: 0x8},
		},
		{
			Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
			Action: ReturnAction{},
		},
	}
}

func conntrackAcceptRule() generictables.Rule {
	return generictables.Rule{
		Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
		Action: AcceptAction{},
	}
}

func (b *ruleBuilder) conntrackDenyInvalidConnections() generictables.Rule {
	return generictables.Rule{
		Match:  Match().ConntrackState("INVALID"),
		Action: b.denyAction,
	}
}

func (b *ruleBuilder) qosControlRules(rate, burst int64) []generictables.Rule {
	return []generictables.Rule{
		{
			Match:   Match(),
			Action:  ClearMarkAction{Mark: 0x20},
			Comment: []string{fmt.Sprintf("Clear %v packet rate limit mark", b.direction)},
		},
		{
			Match:   Match(),
			Action:  LimitPacketRateAction{Rate: rate, Burst: burst, Mark: 0x20},
			Comment: []string{fmt.Sprintf("Mark packets within %v packet rate limit", b.direction)},
		},
		{
			Match:   Match().NotMarkMatchesWithMask(0x20, 0x20),
			Action:  DropAction{},
			Comment: []string{fmt.Sprintf("Drop packets over %v packet rate limit", b.direction)},
		},
		{
			Match:   Match(),
			Action:  ClearMarkAction{Mark: 0x20},
			Comment: []string{fmt.Sprintf("Clear %v packet rate limit mark", b.direction)},
		},
	}
}

func (b *ruleBuilder) qosMaxConnectionRule(conn int64) generictables.Rule {
	return generictables.Rule{
		Match:   Match(),
		Action:  LimitNumConnectionsAction{Num: conn, RejectWith: generictables.RejectWithTCPReset},
		Comment: []string{fmt.Sprintf("Reject connections over %v connection limit", b.direction)},
	}
}

func (b *ruleBuilder) failSafeRule() generictables.Rule {
	if b.egress {
		return generictables.Rule{
			Match:  Match(),
			Action: JumpAction{Target: "cali-failsafe-out"},
		}
	} else {
		return generictables.Rule{
			Match:  Match(),
			Action: JumpAction{Target: "cali-failsafe-in"},
		}
	}
}

func (b *ruleBuilder) nflogAction(dropAction, forProfile bool) generictables.Rule {
	group := 1
	dir := "I" // Ingress
	if b.egress {
		group = 2
		dir = "E" // Egress
	}
	action := "D" // Drop
	if !dropAction {
		action = "P" // Pass
	}
	kind := "P" // Policy
	if forProfile {
		kind = "R" // Profile
	}

	var prefix string
	if forProfile {
		prefix = fmt.Sprintf("%v%v%v", action, kind, dir)
	} else {
		prefix = fmt.Sprintf("%v%v%v|default", action, kind, dir)
	}

	var match generictables.MatchCriteria
	if forProfile {
		match = Match()
	} else {
		match = Match().MarkClear(0x10)
	}

	return generictables.Rule{
		Match:  match,
		Action: NflogAction{Group: uint16(group), Prefix: prefix},
	}
}

func (b *ruleBuilder) matchPolicies() []generictables.Rule {
	var rules []generictables.Rule

	// No policy or policy group defined.
	if len(b.policies) == 0 && len(b.policyGroups) == 0 {
		return rules
	}

	// In these tests, all policies are in the default tier.
	// Add start of tier rule, for the default tier.
	rules = append(rules,
		generictables.Rule{
			Comment: []string{"Start of tier default"},
			Match:   Match(),
			Action:  ClearMarkAction{Mark: 0x10},
		},
	)

	var endOfTierDrop bool
	// Add rules for policy groups.
	for _, g := range b.policyGroups {
		if strings.Contains(g, "staged:") {
			// Skip staged policies.
			continue
		}
		endOfTierDrop = true
		rules = append(rules,
			jumpToPolicyGroup(g, 0x10),
			returnIfAccepted(),
		)
	}

	// Add rules for policies.
	for _, p := range b.policies {
		if strings.Contains(p, "staged:") {
			// Skip staged policies.
			continue
		}
		endOfTierDrop = true
		target := fmt.Sprintf("cali-pi-default/%v", p)
		if b.egress {
			target = fmt.Sprintf("cali-po-default/%v", p)
		}
		rules = append(rules, generictables.Rule{
			Match:  Match().MarkClear(0x10),
			Action: JumpAction{Target: target},
		})

		if b.forHostEndpoint && b.forUntrack {
			// Extra NOTRACK action before returning in raw table.
			rules = append(rules, generictables.Rule{
				Match:  Match().MarkSingleBitSet(0x8),
				Action: NoTrackAction{},
			})
		}
		rules = append(rules, returnIfAccepted())
	}

	// No drop actions or profiles in raw table.
	if b.forHostEndpoint && (b.forUntrack || b.forPreDNAT) {
		return rules
	}

	if b.tierPassAction {
		endOfTierDrop = false
	}

	if b.flowLogsEnabled {
		rules = append(rules, b.nflogAction(endOfTierDrop, false))
	}
	if endOfTierDrop {
		rules = append(rules,
			generictables.Rule{
				Match:  Match().MarkClear(0x10),
				Action: b.denyAction,
				Comment: []string{fmt.Sprintf("End of tier default. %s if no policies passed packet",
					b.denyActionString,
				)},
			})
	}
	return rules
}

func (b *ruleBuilder) matchProfiles() []generictables.Rule {
	var rules []generictables.Rule
	for _, p := range b.profiles {
		target := fmt.Sprintf("cali-pri-%v", p)
		if b.egress {
			target = fmt.Sprintf("cali-pro-%v", p)
		}
		rules = append(rules,
			generictables.Rule{
				Match:  Match(),
				Action: JumpAction{Target: target},
			},
			generictables.Rule{
				Match:   Match().MarkSingleBitSet(0x8),
				Action:  ReturnAction{},
				Comment: []string{"Return if profile accepted"},
			},
		)
	}
	if b.flowLogsEnabled {
		rules = append(rules, b.nflogAction(true, true))
	}
	rules = append(rules,
		generictables.Rule{
			Match:   Match(),
			Action:  b.denyAction,
			Comment: []string{fmt.Sprintf("%s if no profiles matched", b.denyActionString)},
		},
	)
	return rules
}

func returnIfAccepted() generictables.Rule {
	return generictables.Rule{
		Match:   Match().MarkSingleBitSet(0x8),
		Action:  ReturnAction{},
		Comment: []string{"Return if policy accepted"},
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
