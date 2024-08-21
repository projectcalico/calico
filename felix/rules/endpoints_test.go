// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.
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
			IPIPEnabled:                 true,
			IPIPTunnelAddress:           nil,
			IPSetConfigV4:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			IptablesMarkAccept:          0x8,
			IptablesMarkPass:            0x10,
			IptablesMarkScratch0:        0x20,
			IptablesMarkScratch1:        0x40,
			IptablesMarkEndpoint:        0xff00,
			IptablesMarkNonCaliEndpoint: 0x0100,
			KubeIPVSSupportEnabled:      kubeIPVSEnabled,
			IptablesMangleAllowAction:   "RETURN",
			IptablesFilterDenyAction:    denyActionCommand,
			VXLANPort:                   4789,
			VXLANVNI:                    4096,
		}

		rrConfigConntrackDisabledReturnAction := Config{
			IPIPEnabled:                 true,
			IPIPTunnelAddress:           nil,
			IPSetConfigV4:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			IptablesMarkAccept:          0x8,
			IptablesMarkPass:            0x10,
			IptablesMarkScratch0:        0x20,
			IptablesMarkScratch1:        0x40,
			IptablesMarkEndpoint:        0xff00,
			IptablesMarkNonCaliEndpoint: 0x0100,
			KubeIPVSSupportEnabled:      kubeIPVSEnabled,
			DisableConntrackInvalid:     true,
			IptablesFilterAllowAction:   "RETURN",
			IptablesFilterDenyAction:    denyActionCommand,
			VXLANPort:                   4789,
			VXLANVNI:                    4096,
		}

		var renderer RuleRenderer
		var epMarkMapper EndpointMarkMapper

		dropVXLANRule := generictables.Rule{
			Match: Match().ProtocolNum(ProtoUDP).
				DestPorts(uint16(VXLANPort)),
			Action:  denyAction,
			Comment: []string{fmt.Sprintf("%s VXLAN encapped packets originating in workloads", denyActionString)},
		}
		dropIPIPRule := generictables.Rule{
			Match:   Match().ProtocolNum(ProtoIPIP),
			Action:  denyAction,
			Comment: []string{fmt.Sprintf("%s IPinIP encapped packets originating in workloads", denyActionString)},
		}

		Context("with normal config", func() {
			BeforeEach(func() {
				renderer = NewRenderer(rrConfigNormalMangleReturn)
				epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.IptablesMarkEndpoint,
					rrConfigNormalMangleReturn.IptablesMarkNonCaliEndpoint)
			})

			It("should render a minimal workload endpoint", func() {
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234", epMarkMapper,
					true,
					nil,
					nil)).To(Equal(trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name: "cali-tw-cali1234",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-fw-cali1234",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},
							dropVXLANRule,
							dropIPIPRule,
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-sm-cali1234",
						Rules: []generictables.Rule{
							{
								Match:  Match(),
								Action: SetMaskedMarkAction{Mark: 0xd400, Mask: 0xff00},
							},
						},
					},
				})))
			})

			It("should render a disabled workload endpoint", func() {
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234", epMarkMapper,
					false,
					nil,
					nil,
				)).To(Equal(trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name: "cali-tw-cali1234",
						Rules: []generictables.Rule{
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{"Endpoint admin disabled"},
							},
						},
					},
					{
						Name: "cali-fw-cali1234",
						Rules: []generictables.Rule{
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{"Endpoint admin disabled"},
							},
						},
					},
					{
						Name: "cali-sm-cali1234",
						Rules: []generictables.Rule{
							{
								Match:  Match(),
								Action: SetMaskedMarkAction{Mark: 0xd400, Mask: 0xff00},
							},
						},
					},
				})))
			})

			It("should render a fully-loaded workload endpoint", func() {
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
				)).To(Equal(trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name: "cali-tw-cali1234",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Comment: []string{"Start of tier default"},
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-pi-default/ai"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-pi-default/bi"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:   Match().MarkClear(0x10),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no policies passed packet", denyActionString)},
							},

							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pri-prof1"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pri-prof2"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-fw-cali1234",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},
							dropVXLANRule,
							dropIPIPRule,

							{
								Comment: []string{"Start of tier default"},
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-po-default/ae"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-po-default/be"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:   Match().MarkClear(0x10),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no policies passed packet", denyActionString)},
							},

							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pro-prof1"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pro-prof2"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-sm-cali1234",
						Rules: []generictables.Rule{
							{
								Match:  Match(),
								Action: SetMaskedMarkAction{Mark: 0xd400, Mask: 0xff00},
							},
						},
					},
				})))
			})

			It("should render a workload endpoint with policy groups", func() {
				format.MaxLength = 1000000

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
				)).To(Equal(trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name: "cali-tw-cali1234",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Comment: []string{"Start of tier default"},
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: polGrpInABC.ChainName()},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: polGrpInEF.ChainName()},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},

							{
								Match:   Match().MarkClear(0x10),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no policies passed packet", denyActionString)},
							},

							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pri-prof1"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pri-prof2"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-fw-cali1234",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},
							dropVXLANRule,
							dropIPIPRule,

							{
								Comment: []string{"Start of tier default"},
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: polGrpOutAB.ChainName()},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: polGrpOutDE.ChainName()},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:   Match().MarkClear(0x10),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no policies passed packet", denyActionString)},
							},

							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pro-prof1"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pro-prof2"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-sm-cali1234",
						Rules: []generictables.Rule{
							{
								Match:  Match(),
								Action: SetMaskedMarkAction{Mark: 0xd400, Mask: 0xff00},
							},
						},
					},
				})))
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
				expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name: "cali-th-eth0",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							// Host endpoints get extra failsafe rules.
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-failsafe-out"},
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Comment: []string{"Start of tier default"},
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-po-default/ae"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-po-default/be"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:   Match().MarkClear(0x10),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no policies passed packet", denyActionString)},
							},
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pro-prof1"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pro-prof2"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-fh-eth0",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							// Host endpoints get extra failsafe rules.
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-failsafe-in"},
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Comment: []string{"Start of tier default"},
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-pi-default/ai"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-pi-default/bi"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:   Match().MarkClear(0x10),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no policies passed packet", denyActionString)},
							},
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pri-prof1"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-pri-prof2"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if profile accepted"},
							},
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-thfw-eth0",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Comment: []string{"Start of tier default"},
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-po-default/afe"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-po-default/bfe"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:   Match().MarkClear(0x10),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no policies passed packet", denyActionString)},
							},
						},
					},
					{
						Name: "cali-fhfw-eth0",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Match:   Match(),
								Comment: []string{"Start of tier default"},
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-pi-default/afi"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-pi-default/bfi"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},
							{
								Match:   Match().MarkClear(0x10),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no policies passed packet", denyActionString)},
							},
						},
					},
					{
						Name: "cali-sm-eth0",
						Rules: []generictables.Rule{
							{
								Match:  Match(),
								Action: SetMaskedMarkAction{Mark: 0xa200, Mask: 0xff00},
							},
						},
					},
				})
				Expect(actual).To(Equal(expected), cmp.Diff(actual, expected))
			})

			It("should render host endpoint raw chains with untracked policies", func() {
				Expect(renderer.HostEndpointToRawChains("eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"c"},
						EgressPolicies:  []string{"c"},
					}}),
				)).To(Equal([]*generictables.Chain{
					{
						Name: "cali-th-eth0",
						Rules: []generictables.Rule{
							// Host endpoints get extra failsafe rules.
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-failsafe-out"},
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Match:   Match(),
								Comment: []string{"Start of tier default"},
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-po-default/c"},
							},
							// Extra NOTRACK action before returning in raw table.
							{
								Match:  Match().MarkSingleBitSet(0x8),
								Action: NoTrackAction{},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},

							// No drop actions or profiles in raw table.
						},
					},
					{
						Name: "cali-fh-eth0",
						Rules: []generictables.Rule{
							// Host endpoints get extra failsafe rules.
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-failsafe-in"},
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Match:   Match(),
								Comment: []string{"Start of tier default"},
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-pi-default/c"},
							},
							// Extra NOTRACK action before returning in raw table.
							{
								Match:  Match().MarkSingleBitSet(0x8),
								Action: NoTrackAction{},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},

							// No drop actions or profiles in raw table.
						},
					},
				}))
			})

			It("should render host endpoint mangle chains with pre-DNAT policies", func() {
				Expect(renderer.HostEndpointToMangleIngressChains(
					"eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"c"},
					}}),
				)).To(Equal([]*generictables.Chain{
					{
						Name: "cali-fh-eth0",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: SetMarkAction{Mark: 0x8},
							},
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: ReturnAction{},
							},
							{
								Match:  Match().ConntrackState("INVALID"),
								Action: denyAction,
							},

							// Host endpoints get extra failsafe rules.
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-failsafe-in"},
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Comment: []string{"Start of tier default"},
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-pi-default/c"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},

							// No drop actions or profiles in raw table.
						},
					},
				}))
			})
		})

		Describe("with ctstate=INVALID disabled", func() {
			BeforeEach(func() {
				renderer = NewRenderer(rrConfigConntrackDisabledReturnAction)
				epMarkMapper = NewEndpointMarkMapper(rrConfigConntrackDisabledReturnAction.IptablesMarkEndpoint,
					rrConfigConntrackDisabledReturnAction.IptablesMarkNonCaliEndpoint)
			})

			It("should render a minimal workload endpoint", func() {
				Expect(renderer.WorkloadEndpointToIptablesChains(
					"cali1234",
					epMarkMapper,
					true,
					nil,
					nil,
				)).To(Equal(trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
					{
						Name: "cali-tw-cali1234",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: SetMarkAction{Mark: 0x8},
							},
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: ReturnAction{},
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-fw-cali1234",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: SetMarkAction{Mark: 0x8},
							},
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: ReturnAction{},
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},
							dropVXLANRule,
							dropIPIPRule,
							{
								Match:   Match(),
								Action:  denyAction,
								Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
							},
						},
					},
					{
						Name: "cali-sm-cali1234",
						Rules: []generictables.Rule{
							{
								Match:  Match(),
								Action: SetMaskedMarkAction{Mark: 0xd400, Mask: 0xff00},
							},
						},
					},
				})))
			})

			It("should render host endpoint mangle chains with pre-DNAT policies", func() {
				Expect(renderer.HostEndpointToMangleIngressChains(
					"eth0",
					tiersToSinglePolGroups([]*proto.TierInfo{{
						Name:            "default",
						IngressPolicies: []string{"c"},
					}}),
				)).To(Equal([]*generictables.Chain{
					{
						Name: "cali-fh-eth0",
						Rules: []generictables.Rule{
							// conntrack rules.
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{},
							},

							// Host endpoints get extra failsafe rules.
							{
								Match:  Match(),
								Action: JumpAction{Target: "cali-failsafe-in"},
							},

							{
								Match:  Match(),
								Action: ClearMarkAction{Mark: 0x18},
							},

							{
								Comment: []string{"Start of tier default"},
								Match:   Match(),
								Action:  ClearMarkAction{Mark: 0x10},
							},
							{
								Match:  Match().MarkClear(0x10),
								Action: JumpAction{Target: "cali-pi-default/c"},
							},
							{
								Match:   Match().MarkSingleBitSet(0x8),
								Action:  ReturnAction{},
								Comment: []string{"Return if policy accepted"},
							},

							// No drop actions or profiles in raw table.
						},
					},
				}))
			})
		})

		Describe("Disabling adding drop encap rules", func() {
			Context("VXLAN allowed, IPIP dropped", func() {
				It("should render a minimal workload endpoint without VXLAN drop encap rule and with IPIP drop encap rule", func() {
					rrConfigNormalMangleReturn.AllowVXLANPacketsFromWorkloads = true
					renderer = NewRenderer(rrConfigNormalMangleReturn)
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.IptablesMarkEndpoint,
						rrConfigNormalMangleReturn.IptablesMarkNonCaliEndpoint)
					Expect(renderer.WorkloadEndpointToIptablesChains(
						"cali1234", epMarkMapper,
						true,
						nil,
						nil,
					)).To(Equal(trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name: "cali-tw-cali1234",
							Rules: []generictables.Rule{
								// conntrack rules.
								{
									Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
									Action: AcceptAction{},
								},
								{
									Match:  Match().ConntrackState("INVALID"),
									Action: denyAction,
								},

								{
									Match:  Match(),
									Action: ClearMarkAction{Mark: 0x18},
								},
								{
									Match:   Match(),
									Action:  denyAction,
									Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
								},
							},
						},
						{
							Name: "cali-fw-cali1234",
							Rules: []generictables.Rule{
								// conntrack rules.
								{
									Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
									Action: AcceptAction{},
								},
								{
									Match:  Match().ConntrackState("INVALID"),
									Action: denyAction,
								},
								{
									Match:  Match(),
									Action: ClearMarkAction{Mark: 0x18},
								},
								dropIPIPRule,
								{
									Match:   Match(),
									Action:  denyAction,
									Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
								},
							},
						},
						{
							Name: "cali-sm-cali1234",
							Rules: []generictables.Rule{
								{
									Match:  Match(),
									Action: SetMaskedMarkAction{Mark: 0xd400, Mask: 0xff00},
								},
							},
						},
					})))
				})
			})
			Context("VXLAN dropped, IPIP allowed", func() {
				It("should render a minimal workload endpoint with VXLAN drop encap rule and without IPIP drop encap rule", func() {
					rrConfigNormalMangleReturn.AllowIPIPPacketsFromWorkloads = true
					renderer = NewRenderer(rrConfigNormalMangleReturn)
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.IptablesMarkEndpoint,
						rrConfigNormalMangleReturn.IptablesMarkNonCaliEndpoint)

					actual := renderer.WorkloadEndpointToIptablesChains(
						"cali1234", epMarkMapper,
						true,
						nil,
						nil,
					)
					expected := trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name: "cali-tw-cali1234",
							Rules: []generictables.Rule{
								// conntrack rules.
								{
									Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
									Action: AcceptAction{},
								},
								{
									Match:  Match().ConntrackState("INVALID"),
									Action: denyAction,
								},

								{
									Match:  Match(),
									Action: ClearMarkAction{Mark: 0x18},
								},
								{
									Match:   Match(),
									Action:  denyAction,
									Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
								},
							},
						},
						{
							Name: "cali-fw-cali1234",
							Rules: []generictables.Rule{
								// conntrack rules.
								{
									Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
									Action: AcceptAction{},
								},
								{
									Match:  Match().ConntrackState("INVALID"),
									Action: denyAction,
								},
								{
									Match:  Match(),
									Action: ClearMarkAction{Mark: 0x18},
								},
								dropVXLANRule,
								{
									Match:   Match(),
									Action:  denyAction,
									Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
								},
							},
						},
						{
							Name: "cali-sm-cali1234",
							Rules: []generictables.Rule{
								{
									Match:  Match(),
									Action: SetMaskedMarkAction{Mark: 0xd400, Mask: 0xff00},
								},
							},
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
					epMarkMapper = NewEndpointMarkMapper(rrConfigNormalMangleReturn.IptablesMarkEndpoint,
						rrConfigNormalMangleReturn.IptablesMarkNonCaliEndpoint)
					Expect(renderer.WorkloadEndpointToIptablesChains(
						"cali1234", epMarkMapper,
						true,
						nil,
						nil,
					)).To(Equal(trimSMChain(kubeIPVSEnabled, []*generictables.Chain{
						{
							Name: "cali-tw-cali1234",
							Rules: []generictables.Rule{
								// conntrack rules.
								{
									Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
									Action: AcceptAction{},
								},
								{
									Match:  Match().ConntrackState("INVALID"),
									Action: denyAction,
								},
								{
									Match:  Match(),
									Action: ClearMarkAction{Mark: 0x18},
								},
								{
									Match:   Match(),
									Action:  denyAction,
									Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
								},
							},
						},
						{
							Name: "cali-fw-cali1234",
							Rules: []generictables.Rule{
								// conntrack rules.
								{
									Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
									Action: AcceptAction{},
								},
								{
									Match:  Match().ConntrackState("INVALID"),
									Action: denyAction,
								},

								{
									Match:  Match(),
									Action: ClearMarkAction{Mark: 0x18},
								},
								{
									Match:   Match(),
									Action:  denyAction,
									Comment: []string{fmt.Sprintf("%s if no profiles matched", denyActionString)},
								},
							},
						},
						{
							Name: "cali-sm-cali1234",
							Rules: []generictables.Rule{
								{
									Match:  Match(),
									Action: SetMaskedMarkAction{Mark: 0xd400, Mask: 0xff00},
								},
							},
						},
					})))
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
			Name: t.Name,
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
})

var _ = table.DescribeTable("PolicyGroup chains",
	func(group PolicyGroup, expectedRules []generictables.Rule) {
		renderer := NewRenderer(Config{
			IptablesMarkAccept:          0x8,
			IptablesMarkPass:            0x10,
			IptablesMarkScratch0:        0x20,
			IptablesMarkScratch1:        0x40,
			IptablesMarkEndpoint:        0xff00,
			IptablesMarkNonCaliEndpoint: 0x0100,
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
			{
				Match:  Match(),
				Action: JumpAction{Target: "cali-pi-default/a"},
			},
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
			{
				Match:  Match(),
				Action: JumpAction{Target: "cali-pi-default/a"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/b"},
			},
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
			{
				Match:  Match(),
				Action: JumpAction{Target: "cali-pi-default/a"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/b"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/c"},
			},
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
			{
				Match:  Match(),
				Action: JumpAction{Target: "cali-pi-default/a"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/b"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/c"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/d"},
			},
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
			{
				Match:  Match(),
				Action: JumpAction{Target: "cali-pi-default/a"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/b"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/c"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/d"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/e"},
			},
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
			{
				Match:  Match(),
				Action: JumpAction{Target: "cali-pi-default/a"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/b"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/c"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/d"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-pi-default/e"},
			},
			{
				// Only get a return action every 5 rules and only if it's
				// not the last action.
				Match:   Match().MarkNotClear(0x18),
				Action:  ReturnAction{},
				Comment: []string{"Return on verdict"},
			},
			{
				Match:  Match(),
				Action: JumpAction{Target: "cali-pi-default/f"},
			},
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
			{
				Match:  Match(),
				Action: JumpAction{Target: "cali-po-default/a"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-po-default/b"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-po-default/c"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-po-default/d"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-po-default/e"},
			},
			{
				Match:   Match().MarkNotClear(0x18),
				Action:  ReturnAction{},
				Comment: []string{"Return on verdict"},
			},
			{
				Match:  Match(),
				Action: JumpAction{Target: "cali-po-default/f"},
			},
			{
				Match:  Match().MarkClear(0x18),
				Action: JumpAction{Target: "cali-po-default/g"},
			},
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
