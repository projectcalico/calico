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

package rules_test

import (
	. "github.com/projectcalico/calico/felix/rules"

	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
)

var _ = Describe("Dispatch chains", func() {
	for _, trueOrFalse := range []bool{true, false} {
		kubeIPVSEnabled := trueOrFalse
		var rrConfigNormal = Config{
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
			WorkloadIfacePrefixes:       []string{"cali", "tap"},
			KubeIPVSSupportEnabled:      kubeIPVSEnabled,
		}

		var expDropRule = iptables.Rule{
			Action:  iptables.DropAction{},
			Comment: []string{"Unknown interface"},
		}

		var smNonCaliSetMarkRule = iptables.Rule{
			Action: iptables.SetMaskedMarkAction{
				Mark: rrConfigNormal.IptablesMarkNonCaliEndpoint,
				Mask: rrConfigNormal.IptablesMarkEndpoint,
			},
			Comment: []string{"Non-Cali endpoint mark"},
		}

		var epMarkMapper EndpointMarkMapper
		var renderer RuleRenderer
		BeforeEach(func() {
			renderer = NewRenderer(rrConfigNormal)
			epMarkMapper = NewEndpointMarkMapper(rrConfigNormal.IptablesMarkEndpoint, rrConfigNormal.IptablesMarkNonCaliEndpoint)
		})

		It("should panic if interface name is empty", func() {
			endpointID := proto.WorkloadEndpointID{
				OrchestratorId: "foobar",
				WorkloadId:     "workload",
				EndpointId:     "noname",
			}
			input := map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{
				endpointID: {},
			}
			Expect(func() { renderer.WorkloadDispatchChains(input) }).To(Panic())
		})

		DescribeTable("workload rendering tests",
			func(names []string, expectedChains map[bool][]*iptables.Chain) {
				var input map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
				if names != nil {
					input = map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{}
					for i, name := range names {
						id := proto.WorkloadEndpointID{
							OrchestratorId: "foobar",
							WorkloadId:     fmt.Sprintf("workload-%v", i),
							EndpointId:     name,
						}
						// Current impl only cares about names.
						input[id] = &proto.WorkloadEndpoint{
							Name: name,
						}
					}
				}
				// Note: order of chains and rules should be deterministic.
				var result []*iptables.Chain
				if kubeIPVSEnabled {
					result = append(renderer.WorkloadDispatchChains(input),
						renderer.EndpointMarkDispatchChains(epMarkMapper, input, map[string]proto.HostEndpointID{})...)
				} else {
					result = renderer.WorkloadDispatchChains(input)
				}

				mapChain := map[string]*iptables.Chain{}
				for _, chain := range result {
					mapChain[chain.Name] = chain
				}

				for _, chain := range expectedChains[kubeIPVSEnabled] {
					//log.WithField("chain", *chain).Debug("")
					Expect(mapChain[chain.Name]).To(Equal(chain))
				}
				Expect(result).To(Equal(expectedChains[kubeIPVSEnabled]))
			},
			Entry("nil map", nil, map[bool][]*iptables.Chain{
				true: {
					{
						Name:  "cali-from-wl-dispatch",
						Rules: []iptables.Rule{expDropRule},
					},
					{
						Name:  "cali-to-wl-dispatch",
						Rules: []iptables.Rule{expDropRule},
					},
					{
						Name: "cali-set-endpoint-mark",
						Rules: []iptables.Rule{
							smUnknownEndpointDropRule("cali"),
							smUnknownEndpointDropRule("tap"),
							smNonCaliSetMarkRule,
						},
					},
					{
						Name:  "cali-from-endpoint-mark",
						Rules: []iptables.Rule{expDropRule},
					},
				},
				false: {
					{
						Name:  "cali-from-wl-dispatch",
						Rules: []iptables.Rule{expDropRule},
					},
					{
						Name:  "cali-to-wl-dispatch",
						Rules: []iptables.Rule{expDropRule},
					},
				},
			}),
			Entry("single interface", []string{"cali1234"}, map[bool][]*iptables.Chain{
				true: {
					{
						Name: "cali-from-wl-dispatch",
						Rules: []iptables.Rule{
							inboundGotoRule("cali1234", "cali-fw-cali1234"),
							expDropRule,
						},
					},
					{
						Name: "cali-to-wl-dispatch",
						Rules: []iptables.Rule{
							outboundGotoRule("cali1234", "cali-tw-cali1234"),
							expDropRule,
						},
					},
					{
						Name: "cali-set-endpoint-mark",
						Rules: []iptables.Rule{
							inboundGotoRule("cali1234", "cali-sm-cali1234"),
							smUnknownEndpointDropRule("cali"),
							smUnknownEndpointDropRule("tap"),
							smNonCaliSetMarkRule,
						},
					},
					{
						Name: "cali-from-endpoint-mark",
						Rules: []iptables.Rule{
							epMarkFromGotoRule(0xd400, 0xff00, "cali-fw-cali1234"),
							expDropRule,
						},
					},
				},
				false: {
					{
						Name: "cali-from-wl-dispatch",
						Rules: []iptables.Rule{
							inboundGotoRule("cali1234", "cali-fw-cali1234"),
							expDropRule,
						},
					},
					{
						Name: "cali-to-wl-dispatch",
						Rules: []iptables.Rule{
							outboundGotoRule("cali1234", "cali-tw-cali1234"),
							expDropRule,
						},
					},
				},
			}),
			Entry("interfaces sharing prefix", []string{"cali1234", "cali2333", "cali2444"}, map[bool][]*iptables.Chain{
				true: {
					{
						Name: "cali-from-wl-dispatch-2",
						Rules: []iptables.Rule{
							inboundGotoRule("cali2333", "cali-fw-cali2333"),
							inboundGotoRule("cali2444", "cali-fw-cali2444"),
							expDropRule,
						},
					},
					{
						Name: "cali-from-wl-dispatch",
						Rules: []iptables.Rule{
							inboundGotoRule("cali1234", "cali-fw-cali1234"),
							inboundGotoRule("cali2+", "cali-from-wl-dispatch-2"),
							expDropRule,
						},
					},
					{
						Name: "cali-to-wl-dispatch-2",
						Rules: []iptables.Rule{
							outboundGotoRule("cali2333", "cali-tw-cali2333"),
							outboundGotoRule("cali2444", "cali-tw-cali2444"),
							expDropRule,
						},
					},
					{
						Name: "cali-to-wl-dispatch",
						Rules: []iptables.Rule{
							outboundGotoRule("cali1234", "cali-tw-cali1234"),
							outboundGotoRule("cali2+", "cali-to-wl-dispatch-2"),
							expDropRule,
						},
					},
					{
						Name: "cali-set-endpoint-mark-2",
						Rules: []iptables.Rule{
							inboundGotoRule("cali2333", "cali-sm-cali2333"),
							inboundGotoRule("cali2444", "cali-sm-cali2444"),
						},
					},
					{
						Name: "cali-set-endpoint-mark",
						Rules: []iptables.Rule{
							inboundGotoRule("cali1234", "cali-sm-cali1234"),
							inboundGotoRule("cali2+", "cali-set-endpoint-mark-2"),
							smUnknownEndpointDropRule("cali"),
							smUnknownEndpointDropRule("tap"),
							smNonCaliSetMarkRule,
						},
					},
					{
						Name: "cali-from-endpoint-mark",
						Rules: []iptables.Rule{
							epMarkFromGotoRule(0xd400, 0xff00, "cali-fw-cali1234"),
							epMarkFromGotoRule(0xa700, 0xff00, "cali-fw-cali2333"),
							epMarkFromGotoRule(0x5200, 0xff00, "cali-fw-cali2444"),
							expDropRule,
						},
					},
				},
				false: {
					{
						Name: "cali-from-wl-dispatch-2",
						Rules: []iptables.Rule{
							inboundGotoRule("cali2333", "cali-fw-cali2333"),
							inboundGotoRule("cali2444", "cali-fw-cali2444"),
							expDropRule,
						},
					},
					{
						Name: "cali-from-wl-dispatch",
						Rules: []iptables.Rule{
							inboundGotoRule("cali1234", "cali-fw-cali1234"),
							inboundGotoRule("cali2+", "cali-from-wl-dispatch-2"),
							expDropRule,
						},
					},
					{
						Name: "cali-to-wl-dispatch-2",
						Rules: []iptables.Rule{
							outboundGotoRule("cali2333", "cali-tw-cali2333"),
							outboundGotoRule("cali2444", "cali-tw-cali2444"),
							expDropRule,
						},
					},
					{
						Name: "cali-to-wl-dispatch",
						Rules: []iptables.Rule{
							outboundGotoRule("cali1234", "cali-tw-cali1234"),
							outboundGotoRule("cali2+", "cali-to-wl-dispatch-2"),
							expDropRule,
						},
					},
				},
			}),
			Entry("Multiple interfaces sharing multiple prefixes",
				[]string{"cali11", "cali12", "cali13", "cali21", "cali22"},
				map[bool][]*iptables.Chain{
					true: {
						{
							Name: "cali-from-wl-dispatch-1",
							Rules: []iptables.Rule{
								inboundGotoRule("cali11", "cali-fw-cali11"),
								inboundGotoRule("cali12", "cali-fw-cali12"),
								inboundGotoRule("cali13", "cali-fw-cali13"),
								expDropRule,
							},
						},
						{
							Name: "cali-from-wl-dispatch-2",
							Rules: []iptables.Rule{
								inboundGotoRule("cali21", "cali-fw-cali21"),
								inboundGotoRule("cali22", "cali-fw-cali22"),
								expDropRule,
							},
						},
						{
							Name: "cali-from-wl-dispatch",
							Rules: []iptables.Rule{
								inboundGotoRule("cali1+", "cali-from-wl-dispatch-1"),
								inboundGotoRule("cali2+", "cali-from-wl-dispatch-2"),
								expDropRule,
							},
						},
						{
							Name: "cali-to-wl-dispatch-1",
							Rules: []iptables.Rule{
								outboundGotoRule("cali11", "cali-tw-cali11"),
								outboundGotoRule("cali12", "cali-tw-cali12"),
								outboundGotoRule("cali13", "cali-tw-cali13"),
								expDropRule,
							},
						},
						{
							Name: "cali-to-wl-dispatch-2",
							Rules: []iptables.Rule{
								outboundGotoRule("cali21", "cali-tw-cali21"),
								outboundGotoRule("cali22", "cali-tw-cali22"),
								expDropRule,
							},
						},
						{
							Name: "cali-to-wl-dispatch",
							Rules: []iptables.Rule{
								outboundGotoRule("cali1+", "cali-to-wl-dispatch-1"),
								outboundGotoRule("cali2+", "cali-to-wl-dispatch-2"),
								expDropRule,
							},
						},
						{
							Name: "cali-set-endpoint-mark-1",
							Rules: []iptables.Rule{
								inboundGotoRule("cali11", "cali-sm-cali11"),
								inboundGotoRule("cali12", "cali-sm-cali12"),
								inboundGotoRule("cali13", "cali-sm-cali13"),
							},
						},
						{
							Name: "cali-set-endpoint-mark-2",
							Rules: []iptables.Rule{
								inboundGotoRule("cali21", "cali-sm-cali21"),
								inboundGotoRule("cali22", "cali-sm-cali22"),
							},
						},
						{
							Name: "cali-set-endpoint-mark",
							Rules: []iptables.Rule{
								inboundGotoRule("cali1+", "cali-set-endpoint-mark-1"),
								inboundGotoRule("cali2+", "cali-set-endpoint-mark-2"),
								smUnknownEndpointDropRule("cali"),
								smUnknownEndpointDropRule("tap"),
								smNonCaliSetMarkRule,
							},
						},
						{
							Name: "cali-from-endpoint-mark",
							Rules: []iptables.Rule{
								epMarkFromGotoRule(0x200, 0xff00, "cali-fw-cali11"),
								epMarkFromGotoRule(0x300, 0xff00, "cali-fw-cali12"),
								epMarkFromGotoRule(0x400, 0xff00, "cali-fw-cali13"),
								epMarkFromGotoRule(0xf700, 0xff00, "cali-fw-cali21"),
								epMarkFromGotoRule(0xf400, 0xff00, "cali-fw-cali22"),
								expDropRule,
							},
						},
					},
					false: {
						{
							Name: "cali-from-wl-dispatch-1",
							Rules: []iptables.Rule{
								inboundGotoRule("cali11", "cali-fw-cali11"),
								inboundGotoRule("cali12", "cali-fw-cali12"),
								inboundGotoRule("cali13", "cali-fw-cali13"),
								expDropRule,
							},
						},
						{
							Name: "cali-from-wl-dispatch-2",
							Rules: []iptables.Rule{
								inboundGotoRule("cali21", "cali-fw-cali21"),
								inboundGotoRule("cali22", "cali-fw-cali22"),
								expDropRule,
							},
						},
						{
							Name: "cali-from-wl-dispatch",
							Rules: []iptables.Rule{
								inboundGotoRule("cali1+", "cali-from-wl-dispatch-1"),
								inboundGotoRule("cali2+", "cali-from-wl-dispatch-2"),
								expDropRule,
							},
						},
						{
							Name: "cali-to-wl-dispatch-1",
							Rules: []iptables.Rule{
								outboundGotoRule("cali11", "cali-tw-cali11"),
								outboundGotoRule("cali12", "cali-tw-cali12"),
								outboundGotoRule("cali13", "cali-tw-cali13"),
								expDropRule,
							},
						},
						{
							Name: "cali-to-wl-dispatch-2",
							Rules: []iptables.Rule{
								outboundGotoRule("cali21", "cali-tw-cali21"),
								outboundGotoRule("cali22", "cali-tw-cali22"),
								expDropRule,
							},
						},
						{
							Name: "cali-to-wl-dispatch",
							Rules: []iptables.Rule{
								outboundGotoRule("cali1+", "cali-to-wl-dispatch-1"),
								outboundGotoRule("cali2+", "cali-to-wl-dispatch-2"),
								expDropRule,
							},
						},
					},
				}),
			// Duplicate interfaces could occur during transient misconfigurations, while
			// there's no way to make them "work" since we can't distinguish the dupes, we
			// should still render something sensible.
			Entry("duplicate interface", []string{"cali1234", "cali1234"}, map[bool][]*iptables.Chain{
				true: {
					{
						Name: "cali-from-wl-dispatch",
						Rules: []iptables.Rule{
							inboundGotoRule("cali1234", "cali-fw-cali1234"),
							expDropRule,
						},
					},
					{
						Name: "cali-to-wl-dispatch",
						Rules: []iptables.Rule{
							outboundGotoRule("cali1234", "cali-tw-cali1234"),
							expDropRule,
						},
					},
					{
						Name: "cali-set-endpoint-mark",
						Rules: []iptables.Rule{
							inboundGotoRule("cali1234", "cali-sm-cali1234"),
							smUnknownEndpointDropRule("cali"),
							smUnknownEndpointDropRule("tap"),
							smNonCaliSetMarkRule,
						},
					},
					{
						Name: "cali-from-endpoint-mark",
						Rules: []iptables.Rule{
							epMarkFromGotoRule(0xd400, 0xff00, "cali-fw-cali1234"),
							expDropRule,
						},
					},
				},
				false: {
					{
						Name: "cali-from-wl-dispatch",
						Rules: []iptables.Rule{
							inboundGotoRule("cali1234", "cali-fw-cali1234"),
							expDropRule,
						},
					},
					{
						Name: "cali-to-wl-dispatch",
						Rules: []iptables.Rule{
							outboundGotoRule("cali1234", "cali-tw-cali1234"),
							expDropRule,
						},
					},
				},
			}),
		)

		Describe("host endpoint rendering tests", func() {
			convertToInput := func(names []string, expectedChains []*iptables.Chain) map[string]proto.HostEndpointID {
				var input map[string]proto.HostEndpointID
				if names != nil {
					input = map[string]proto.HostEndpointID{}
					for _, name := range names {
						input[name] = proto.HostEndpointID{} // Data is currently ignored.
					}
				}

				return input
			}

			DescribeTable("host endpoint rendering tests preDNAT",
				func(names []string, expectedChains []*iptables.Chain) {
					input := convertToInput(names, expectedChains)
					// Note: order of chains and rules should be deterministic.
					Expect(renderer.FromHostDispatchChains(input, "")).To(Equal(expectedChains))
				},
				Entry("nil map", nil, []*iptables.Chain{
					{
						Name:  "cali-from-host-endpoint",
						Rules: []iptables.Rule{},
					},
				}),
				Entry("single interface", []string{"eth1234"}, []*iptables.Chain{
					{
						Name: "cali-from-host-endpoint",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fh-eth1234"),
						},
					},
				}),
				Entry("interfaces sharing prefix", []string{"eth1234", "eth2333", "eth2444"}, []*iptables.Chain{
					{
						Name: "cali-from-host-endpoint-2",
						Rules: []iptables.Rule{
							inboundGotoRule("eth2333", "cali-fh-eth2333"),
							inboundGotoRule("eth2444", "cali-fh-eth2444"),
						},
					},
					{
						Name: "cali-from-host-endpoint",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fh-eth1234"),
							inboundGotoRule("eth2+", "cali-from-host-endpoint-2"),
						},
					},
				}),
				Entry("Multiple interfaces sharing multiple prefixes",
					[]string{"eth11", "eth12", "eth13", "eth21", "eth22"},
					[]*iptables.Chain{
						{
							Name: "cali-from-host-endpoint-1",
							Rules: []iptables.Rule{
								inboundGotoRule("eth11", "cali-fh-eth11"),
								inboundGotoRule("eth12", "cali-fh-eth12"),
								inboundGotoRule("eth13", "cali-fh-eth13"),
							},
						},
						{
							Name: "cali-from-host-endpoint-2",
							Rules: []iptables.Rule{
								inboundGotoRule("eth21", "cali-fh-eth21"),
								inboundGotoRule("eth22", "cali-fh-eth22"),
							},
						},
						{
							Name: "cali-from-host-endpoint",
							Rules: []iptables.Rule{
								inboundGotoRule("eth1+", "cali-from-host-endpoint-1"),
								inboundGotoRule("eth2+", "cali-from-host-endpoint-2"),
							},
						},
					}),
			)

			DescribeTable("host endpoint rendering tests untracked",
				func(names []string, expectedChains []*iptables.Chain) {
					input := convertToInput(names, expectedChains)
					// Note: order of chains and rules should be deterministic.
					Expect(renderer.HostDispatchChains(input, "", false)).To(Equal(expectedChains))
				},
				Entry("nil map", nil, []*iptables.Chain{
					{
						Name:  "cali-from-host-endpoint",
						Rules: []iptables.Rule{},
					},
					{
						Name:  "cali-to-host-endpoint",
						Rules: []iptables.Rule{},
					},
				}),
				Entry("single interface", []string{"eth1234"}, []*iptables.Chain{
					{
						Name: "cali-from-host-endpoint",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fh-eth1234"),
						},
					},
					{
						Name: "cali-to-host-endpoint",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-th-eth1234"),
						},
					},
				}),
				Entry("interfaces sharing prefix", []string{"eth1234", "eth2333", "eth2444"}, []*iptables.Chain{
					{
						Name: "cali-from-host-endpoint-2",
						Rules: []iptables.Rule{
							inboundGotoRule("eth2333", "cali-fh-eth2333"),
							inboundGotoRule("eth2444", "cali-fh-eth2444"),
						},
					},
					{
						Name: "cali-from-host-endpoint",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fh-eth1234"),
							inboundGotoRule("eth2+", "cali-from-host-endpoint-2"),
						},
					},
					{
						Name: "cali-to-host-endpoint-2",
						Rules: []iptables.Rule{
							outboundGotoRule("eth2333", "cali-th-eth2333"),
							outboundGotoRule("eth2444", "cali-th-eth2444"),
						},
					},
					{
						Name: "cali-to-host-endpoint",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-th-eth1234"),
							outboundGotoRule("eth2+", "cali-to-host-endpoint-2"),
						},
					},
				}),
				Entry("Multiple interfaces sharing multiple prefixes",
					[]string{"eth11", "eth12", "eth13", "eth21", "eth22"},
					[]*iptables.Chain{
						{
							Name: "cali-from-host-endpoint-1",
							Rules: []iptables.Rule{
								inboundGotoRule("eth11", "cali-fh-eth11"),
								inboundGotoRule("eth12", "cali-fh-eth12"),
								inboundGotoRule("eth13", "cali-fh-eth13"),
							},
						},
						{
							Name: "cali-from-host-endpoint-2",
							Rules: []iptables.Rule{
								inboundGotoRule("eth21", "cali-fh-eth21"),
								inboundGotoRule("eth22", "cali-fh-eth22"),
							},
						},
						{
							Name: "cali-from-host-endpoint",
							Rules: []iptables.Rule{
								inboundGotoRule("eth1+", "cali-from-host-endpoint-1"),
								inboundGotoRule("eth2+", "cali-from-host-endpoint-2"),
							},
						},
						{
							Name: "cali-to-host-endpoint-1",
							Rules: []iptables.Rule{
								outboundGotoRule("eth11", "cali-th-eth11"),
								outboundGotoRule("eth12", "cali-th-eth12"),
								outboundGotoRule("eth13", "cali-th-eth13"),
							},
						},
						{
							Name: "cali-to-host-endpoint-2",
							Rules: []iptables.Rule{
								outboundGotoRule("eth21", "cali-th-eth21"),
								outboundGotoRule("eth22", "cali-th-eth22"),
							},
						},
						{
							Name: "cali-to-host-endpoint",
							Rules: []iptables.Rule{
								outboundGotoRule("eth1+", "cali-to-host-endpoint-1"),
								outboundGotoRule("eth2+", "cali-to-host-endpoint-2"),
							},
						},
					}),
			)

			DescribeTable("host endpoint rendering tests apply on forward",
				func(names []string, expectedChains []*iptables.Chain) {
					input := convertToInput(names, expectedChains)
					// Note: order of chains and rules should be deterministic.
					Expect(renderer.HostDispatchChains(input, "", true)).To(Equal(expectedChains))
				},
				Entry("nil map", nil, []*iptables.Chain{
					{
						Name:  "cali-from-host-endpoint",
						Rules: []iptables.Rule{},
					},
					{
						Name:  "cali-to-host-endpoint",
						Rules: []iptables.Rule{},
					},
					{
						Name:  "cali-from-hep-forward",
						Rules: []iptables.Rule{},
					},
					{
						Name:  "cali-to-hep-forward",
						Rules: []iptables.Rule{},
					},
				}),
				Entry("single interface", []string{"eth1234"}, []*iptables.Chain{
					{
						Name: "cali-from-host-endpoint",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fh-eth1234"),
						},
					},
					{
						Name: "cali-to-host-endpoint",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-th-eth1234"),
						},
					},
					{
						Name: "cali-from-hep-forward",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fhfw-eth1234"),
						},
					},
					{
						Name: "cali-to-hep-forward",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-thfw-eth1234"),
						},
					},
				}),
				Entry("interfaces sharing prefix", []string{"eth1234", "eth2333", "eth2444"}, []*iptables.Chain{
					{
						Name: "cali-from-host-endpoint-2",
						Rules: []iptables.Rule{
							inboundGotoRule("eth2333", "cali-fh-eth2333"),
							inboundGotoRule("eth2444", "cali-fh-eth2444"),
						},
					},
					{
						Name: "cali-from-host-endpoint",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fh-eth1234"),
							inboundGotoRule("eth2+", "cali-from-host-endpoint-2"),
						},
					},
					{
						Name: "cali-to-host-endpoint-2",
						Rules: []iptables.Rule{
							outboundGotoRule("eth2333", "cali-th-eth2333"),
							outboundGotoRule("eth2444", "cali-th-eth2444"),
						},
					},
					{
						Name: "cali-to-host-endpoint",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-th-eth1234"),
							outboundGotoRule("eth2+", "cali-to-host-endpoint-2"),
						},
					},
					{
						Name: "cali-from-hep-forward-2",
						Rules: []iptables.Rule{
							inboundGotoRule("eth2333", "cali-fhfw-eth2333"),
							inboundGotoRule("eth2444", "cali-fhfw-eth2444"),
						},
					},
					{
						Name: "cali-from-hep-forward",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fhfw-eth1234"),
							inboundGotoRule("eth2+", "cali-from-hep-forward-2"),
						},
					},
					{
						Name: "cali-to-hep-forward-2",
						Rules: []iptables.Rule{
							outboundGotoRule("eth2333", "cali-thfw-eth2333"),
							outboundGotoRule("eth2444", "cali-thfw-eth2444"),
						},
					},
					{
						Name: "cali-to-hep-forward",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-thfw-eth1234"),
							outboundGotoRule("eth2+", "cali-to-hep-forward-2"),
						},
					},
				}),
				Entry("Multiple interfaces sharing multiple prefixes",
					[]string{"eth11", "eth12", "eth13", "eth21", "eth22"},
					[]*iptables.Chain{
						{
							Name: "cali-from-host-endpoint-1",
							Rules: []iptables.Rule{
								inboundGotoRule("eth11", "cali-fh-eth11"),
								inboundGotoRule("eth12", "cali-fh-eth12"),
								inboundGotoRule("eth13", "cali-fh-eth13"),
							},
						},
						{
							Name: "cali-from-host-endpoint-2",
							Rules: []iptables.Rule{
								inboundGotoRule("eth21", "cali-fh-eth21"),
								inboundGotoRule("eth22", "cali-fh-eth22"),
							},
						},
						{
							Name: "cali-from-host-endpoint",
							Rules: []iptables.Rule{
								inboundGotoRule("eth1+", "cali-from-host-endpoint-1"),
								inboundGotoRule("eth2+", "cali-from-host-endpoint-2"),
							},
						},
						{
							Name: "cali-to-host-endpoint-1",
							Rules: []iptables.Rule{
								outboundGotoRule("eth11", "cali-th-eth11"),
								outboundGotoRule("eth12", "cali-th-eth12"),
								outboundGotoRule("eth13", "cali-th-eth13"),
							},
						},
						{
							Name: "cali-to-host-endpoint-2",
							Rules: []iptables.Rule{
								outboundGotoRule("eth21", "cali-th-eth21"),
								outboundGotoRule("eth22", "cali-th-eth22"),
							},
						},
						{
							Name: "cali-to-host-endpoint",
							Rules: []iptables.Rule{
								outboundGotoRule("eth1+", "cali-to-host-endpoint-1"),
								outboundGotoRule("eth2+", "cali-to-host-endpoint-2"),
							},
						},
						{
							Name: "cali-from-hep-forward-1",
							Rules: []iptables.Rule{
								inboundGotoRule("eth11", "cali-fhfw-eth11"),
								inboundGotoRule("eth12", "cali-fhfw-eth12"),
								inboundGotoRule("eth13", "cali-fhfw-eth13"),
							},
						},
						{
							Name: "cali-from-hep-forward-2",
							Rules: []iptables.Rule{
								inboundGotoRule("eth21", "cali-fhfw-eth21"),
								inboundGotoRule("eth22", "cali-fhfw-eth22"),
							},
						},
						{
							Name: "cali-from-hep-forward",
							Rules: []iptables.Rule{
								inboundGotoRule("eth1+", "cali-from-hep-forward-1"),
								inboundGotoRule("eth2+", "cali-from-hep-forward-2"),
							},
						},
						{
							Name: "cali-to-hep-forward-1",
							Rules: []iptables.Rule{
								outboundGotoRule("eth11", "cali-thfw-eth11"),
								outboundGotoRule("eth12", "cali-thfw-eth12"),
								outboundGotoRule("eth13", "cali-thfw-eth13"),
							},
						},
						{
							Name: "cali-to-hep-forward-2",
							Rules: []iptables.Rule{
								outboundGotoRule("eth21", "cali-thfw-eth21"),
								outboundGotoRule("eth22", "cali-thfw-eth22"),
							},
						},
						{
							Name: "cali-to-hep-forward",
							Rules: []iptables.Rule{
								outboundGotoRule("eth1+", "cali-to-hep-forward-1"),
								outboundGotoRule("eth2+", "cali-to-hep-forward-2"),
							},
						},
					}),
			)

			DescribeTable("host endpoint rendering tests apply on forward, with default interface name",
				func(names []string, expectedChains []*iptables.Chain) {
					input := convertToInput(names, expectedChains)
					// Note: order of chains and rules should be deterministic.
					Expect(renderer.HostDispatchChains(input, "eth-default", true)).To(Equal(expectedChains))
				},
				Entry("nil map", nil, []*iptables.Chain{
					{
						Name: "cali-from-host-endpoint",
						Rules: []iptables.Rule{
							gotoRule("cali-fh-eth-default"),
						},
					},
					{
						Name: "cali-to-host-endpoint",
						Rules: []iptables.Rule{
							gotoRule("cali-th-eth-default"),
						},
					},
					{
						Name: "cali-from-hep-forward",
						Rules: []iptables.Rule{
							gotoRule("cali-fhfw-eth-default"),
						},
					},
					{
						Name: "cali-to-hep-forward",
						Rules: []iptables.Rule{
							gotoRule("cali-thfw-eth-default"),
						},
					},
				}),
				Entry("single interface", []string{"eth1234"}, []*iptables.Chain{
					{
						Name: "cali-from-host-endpoint",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fh-eth1234"),
							gotoRule("cali-fh-eth-default"),
						},
					},
					{
						Name: "cali-to-host-endpoint",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-th-eth1234"),
							gotoRule("cali-th-eth-default"),
						},
					},
					{
						Name: "cali-from-hep-forward",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fhfw-eth1234"),
							gotoRule("cali-fhfw-eth-default"),
						},
					},
					{
						Name: "cali-to-hep-forward",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-thfw-eth1234"),
							gotoRule("cali-thfw-eth-default"),
						},
					},
				}),
				Entry("interfaces sharing prefix", []string{"eth1234", "eth2333", "eth2444"}, []*iptables.Chain{
					{
						Name: "cali-from-host-endpoint-2",
						Rules: []iptables.Rule{
							inboundGotoRule("eth2333", "cali-fh-eth2333"),
							inboundGotoRule("eth2444", "cali-fh-eth2444"),
							gotoRule("cali-fh-eth-default"),
						},
					},
					{
						Name: "cali-from-host-endpoint",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fh-eth1234"),
							inboundGotoRule("eth2+", "cali-from-host-endpoint-2"),
							gotoRule("cali-fh-eth-default"),
						},
					},
					{
						Name: "cali-to-host-endpoint-2",
						Rules: []iptables.Rule{
							outboundGotoRule("eth2333", "cali-th-eth2333"),
							outboundGotoRule("eth2444", "cali-th-eth2444"),
							gotoRule("cali-th-eth-default"),
						},
					},
					{
						Name: "cali-to-host-endpoint",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-th-eth1234"),
							outboundGotoRule("eth2+", "cali-to-host-endpoint-2"),
							gotoRule("cali-th-eth-default"),
						},
					},
					{
						Name: "cali-from-hep-forward-2",
						Rules: []iptables.Rule{
							inboundGotoRule("eth2333", "cali-fhfw-eth2333"),
							inboundGotoRule("eth2444", "cali-fhfw-eth2444"),
							gotoRule("cali-fhfw-eth-default"),
						},
					},
					{
						Name: "cali-from-hep-forward",
						Rules: []iptables.Rule{
							inboundGotoRule("eth1234", "cali-fhfw-eth1234"),
							inboundGotoRule("eth2+", "cali-from-hep-forward-2"),
							gotoRule("cali-fhfw-eth-default"),
						},
					},
					{
						Name: "cali-to-hep-forward-2",
						Rules: []iptables.Rule{
							outboundGotoRule("eth2333", "cali-thfw-eth2333"),
							outboundGotoRule("eth2444", "cali-thfw-eth2444"),
							gotoRule("cali-thfw-eth-default"),
						},
					},
					{
						Name: "cali-to-hep-forward",
						Rules: []iptables.Rule{
							outboundGotoRule("eth1234", "cali-thfw-eth1234"),
							outboundGotoRule("eth2+", "cali-to-hep-forward-2"),
							gotoRule("cali-thfw-eth-default"),
						},
					},
				}),
				Entry("Multiple interfaces sharing multiple prefixes",
					[]string{"eth11", "eth12", "eth13", "eth21", "eth22"},
					[]*iptables.Chain{
						{
							Name: "cali-from-host-endpoint-1",
							Rules: []iptables.Rule{
								inboundGotoRule("eth11", "cali-fh-eth11"),
								inboundGotoRule("eth12", "cali-fh-eth12"),
								inboundGotoRule("eth13", "cali-fh-eth13"),
								gotoRule("cali-fh-eth-default"),
							},
						},
						{
							Name: "cali-from-host-endpoint-2",
							Rules: []iptables.Rule{
								inboundGotoRule("eth21", "cali-fh-eth21"),
								inboundGotoRule("eth22", "cali-fh-eth22"),
								gotoRule("cali-fh-eth-default"),
							},
						},
						{
							Name: "cali-from-host-endpoint",
							Rules: []iptables.Rule{
								inboundGotoRule("eth1+", "cali-from-host-endpoint-1"),
								inboundGotoRule("eth2+", "cali-from-host-endpoint-2"),
								gotoRule("cali-fh-eth-default"),
							},
						},
						{
							Name: "cali-to-host-endpoint-1",
							Rules: []iptables.Rule{
								outboundGotoRule("eth11", "cali-th-eth11"),
								outboundGotoRule("eth12", "cali-th-eth12"),
								outboundGotoRule("eth13", "cali-th-eth13"),
								gotoRule("cali-th-eth-default"),
							},
						},
						{
							Name: "cali-to-host-endpoint-2",
							Rules: []iptables.Rule{
								outboundGotoRule("eth21", "cali-th-eth21"),
								outboundGotoRule("eth22", "cali-th-eth22"),
								gotoRule("cali-th-eth-default"),
							},
						},
						{
							Name: "cali-to-host-endpoint",
							Rules: []iptables.Rule{
								outboundGotoRule("eth1+", "cali-to-host-endpoint-1"),
								outboundGotoRule("eth2+", "cali-to-host-endpoint-2"),
								gotoRule("cali-th-eth-default"),
							},
						},
						{
							Name: "cali-from-hep-forward-1",
							Rules: []iptables.Rule{
								inboundGotoRule("eth11", "cali-fhfw-eth11"),
								inboundGotoRule("eth12", "cali-fhfw-eth12"),
								inboundGotoRule("eth13", "cali-fhfw-eth13"),
								gotoRule("cali-fhfw-eth-default"),
							},
						},
						{
							Name: "cali-from-hep-forward-2",
							Rules: []iptables.Rule{
								inboundGotoRule("eth21", "cali-fhfw-eth21"),
								inboundGotoRule("eth22", "cali-fhfw-eth22"),
								gotoRule("cali-fhfw-eth-default"),
							},
						},
						{
							Name: "cali-from-hep-forward",
							Rules: []iptables.Rule{
								inboundGotoRule("eth1+", "cali-from-hep-forward-1"),
								inboundGotoRule("eth2+", "cali-from-hep-forward-2"),
								gotoRule("cali-fhfw-eth-default"),
							},
						},
						{
							Name: "cali-to-hep-forward-1",
							Rules: []iptables.Rule{
								outboundGotoRule("eth11", "cali-thfw-eth11"),
								outboundGotoRule("eth12", "cali-thfw-eth12"),
								outboundGotoRule("eth13", "cali-thfw-eth13"),
								gotoRule("cali-thfw-eth-default"),
							},
						},
						{
							Name: "cali-to-hep-forward-2",
							Rules: []iptables.Rule{
								outboundGotoRule("eth21", "cali-thfw-eth21"),
								outboundGotoRule("eth22", "cali-thfw-eth22"),
								gotoRule("cali-thfw-eth-default"),
							},
						},
						{
							Name: "cali-to-hep-forward",
							Rules: []iptables.Rule{
								outboundGotoRule("eth1+", "cali-to-hep-forward-1"),
								outboundGotoRule("eth2+", "cali-to-hep-forward-2"),
								gotoRule("cali-thfw-eth-default"),
							},
						},
					}),
			)
		})
	}
})

func gotoRule(target string) iptables.Rule {
	return iptables.Rule{
		Action: iptables.GotoAction{Target: target},
	}
}

func inboundGotoRule(ifaceMatch string, target string) iptables.Rule {
	return iptables.Rule{
		Match:  iptables.Match().InInterface(ifaceMatch),
		Action: iptables.GotoAction{Target: target},
	}
}

func outboundGotoRule(ifaceMatch string, target string) iptables.Rule {
	return iptables.Rule{
		Match:  iptables.Match().OutInterface(ifaceMatch),
		Action: iptables.GotoAction{Target: target},
	}
}

func smUnknownEndpointDropRule(ifacePrefix string) iptables.Rule {
	return iptables.Rule{
		Match:   iptables.Match().InInterface(ifacePrefix + "+"),
		Action:  iptables.DropAction{},
		Comment: []string{"Unknown endpoint"},
	}
}

func epMarkFromGotoRule(epMark, mask uint32, target string) iptables.Rule {
	return iptables.Rule{
		Match:  iptables.Match().MarkMatchesWithMask(epMark, mask),
		Action: iptables.GotoAction{Target: target},
	}
}
