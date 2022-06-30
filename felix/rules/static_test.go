// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/ipsets"
	. "github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
)

var _ = Describe("Static", func() {
	var rr *DefaultRuleRenderer
	var conf Config
	JustBeforeEach(func() {
		// Cast back to the expected type so we can access a finer-grained API for testing.
		rr = NewRenderer(conf).(*DefaultRuleRenderer)
	})

	checkManglePostrouting := func(ipVersion uint8, ipvs bool) {
		It("should generate expected cali-POSTROUTING chain in the mangle table", func() {
			expRules := []Rule{
				// Accept already accepted.
				{Match: Match().MarkSingleBitSet(0x10),
					Action: ReturnAction{},
				},
			}
			if ipvs {
				// Accept IPVS-forwarded traffic.
				expRules = append(expRules, Rule{
					Match:  Match().MarkNotClear(0xff00),
					Action: ReturnAction{},
				})
			}
			expRules = append(expRules, []Rule{
				// Clear all Calico mark bits.
				{Action: ClearMarkAction{Mark: 0xf0}},
				// For DNAT'd traffic, apply host endpoint policy.
				{
					Match:  Match().ConntrackState("DNAT"),
					Action: JumpAction{Target: ChainDispatchToHostEndpoint},
				},
				// Accept if policy allowed packet.
				{
					Match:   Match().MarkSingleBitSet(0x10),
					Action:  ReturnAction{},
					Comment: []string{"Host endpoint policy accepted packet."},
				},
			}...)
			Expect(rr.StaticManglePostroutingChain(ipVersion)).To(Equal(&Chain{
				Name:  "cali-POSTROUTING",
				Rules: expRules,
			}))
		})
	}

	for _, trueOrFalse := range []bool{true, false} {
		kubeIPVSEnabled := trueOrFalse
		Describe(fmt.Sprintf("with default config and IPVS=%v", kubeIPVSEnabled), func() {
			BeforeEach(func() {
				conf = Config{
					WorkloadIfacePrefixes: []string{"cali"},
					IPSetConfigV4:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
					IPSetConfigV6:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
					FailsafeInboundHostPorts: []config.ProtoPort{
						{Net: "0.0.0.0/0", Protocol: "tcp", Port: 22},
						{Net: "0.0.0.0/0", Protocol: "tcp", Port: 1022},
					},
					FailsafeOutboundHostPorts: []config.ProtoPort{
						{Net: "0.0.0.0/0", Protocol: "tcp", Port: 23},
						{Net: "0.0.0.0/0", Protocol: "tcp", Port: 1023},
					},
					IptablesMarkAccept:          0x10,
					IptablesMarkPass:            0x20,
					IptablesMarkScratch0:        0x40,
					IptablesMarkScratch1:        0x80,
					IptablesMarkEndpoint:        0xff00,
					IptablesMarkNonCaliEndpoint: 0x100,
					KubeIPVSSupportEnabled:      kubeIPVSEnabled,
					KubeNodePortRanges:          []numorstring.Port{{MinPort: 30030, MaxPort: 30040, PortName: ""}},
				}
			})

			Context("with OpenStack special cases", func() {
				BeforeEach(func() {
					conf.OpenStackSpecialCasesEnabled = true
				})

				It("IPv4: Should return expected raw PREROUTING chain", func() {
					Expect(findChain(rr.StaticRawTableChains(4), "cali-PREROUTING")).To(Equal(&Chain{
						Name: "cali-PREROUTING",
						Rules: []Rule{
							{Action: ClearMarkAction{Mark: 0xf0}},
							{Match: Match().InInterface("cali+"),
								Action: SetMarkAction{Mark: 0x40}},
							{Match: Match().MarkMatchesWithMask(0x40, 0x40),
								Action: JumpAction{Target: ChainRpfSkip}},
							{Match: Match().Protocol("udp").SourceNet("0.0.0.0").SourcePorts(68).DestPorts(67),
								Action: AcceptAction{}},
							{Match: Match().MarkSingleBitSet(0x40).RPFCheckFailed(false),
								Action: DropAction{}},
							{Match: Match().MarkClear(0x40),
								Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
							{Match: Match().MarkSingleBitSet(0x10),
								Action: AcceptAction{}},
						},
					}))
				})

				It("IPv6: Should return expected raw PREROUTING chain", func() {
					Expect(findChain(rr.StaticRawTableChains(6), "cali-PREROUTING")).To(Equal(&Chain{
						Name: "cali-PREROUTING",
						Rules: []Rule{
							{Action: ClearMarkAction{Mark: 0xf0}},
							{Match: Match().InInterface("cali+"),
								Action: SetMarkAction{Mark: 0x40}},
							{Match: Match().MarkMatchesWithMask(0x40, 0x40),
								Action: JumpAction{Target: ChainRpfSkip}},
							{Match: Match().MarkSingleBitSet(0x40).RPFCheckFailed(false),
								Action: DropAction{}},
							{Match: Match().MarkClear(0x40),
								Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
							{Match: Match().MarkSingleBitSet(0x10),
								Action: AcceptAction{}},
						},
					}))
				})
			})

			for _, ipVersion := range []uint8{4, 6} {
				Describe(fmt.Sprintf("IPv%d", ipVersion), func() {
					// Capture current value of ipVersion.
					ipVersion := ipVersion
					ipSetThisHost := fmt.Sprintf("cali%d0this-host", ipVersion)

					var portRanges []*proto.PortRange
					portRange := &proto.PortRange{
						First: 30030,
						Last:  30040,
					}
					portRanges = append(portRanges, portRange)

					expRawFailsafeIn := &Chain{
						Name: "cali-failsafe-in",
						Rules: []Rule{
							{Match: Match().Protocol("tcp").DestPorts(22), Action: AcceptAction{}},
							{Match: Match().Protocol("tcp").DestPorts(1022), Action: AcceptAction{}},
							{Match: Match().Protocol("tcp").SourcePorts(23), Action: AcceptAction{}},
							{Match: Match().Protocol("tcp").SourcePorts(1023), Action: AcceptAction{}},
						},
					}

					expRawFailsafeOut := &Chain{
						Name: "cali-failsafe-out",
						Rules: []Rule{
							{Match: Match().Protocol("tcp").DestPorts(23), Action: AcceptAction{}},
							{Match: Match().Protocol("tcp").DestPorts(1023), Action: AcceptAction{}},
							{Match: Match().Protocol("tcp").SourcePorts(22), Action: AcceptAction{}},
							{Match: Match().Protocol("tcp").SourcePorts(1022), Action: AcceptAction{}},
						},
					}

					expFailsafeIn := &Chain{
						Name: "cali-failsafe-in",
						Rules: []Rule{
							{Match: Match().Protocol("tcp").DestPorts(22), Action: AcceptAction{}},
							{Match: Match().Protocol("tcp").DestPorts(1022), Action: AcceptAction{}},
						},
					}

					expFailsafeOut := &Chain{
						Name: "cali-failsafe-out",
						Rules: []Rule{
							{Match: Match().Protocol("tcp").DestPorts(23), Action: AcceptAction{}},
							{Match: Match().Protocol("tcp").DestPorts(1023), Action: AcceptAction{}},
						},
					}

					if ipVersion == 4 {
						expRawFailsafeIn = &Chain{
							Name: "cali-failsafe-in",
							Rules: []Rule{
								{Match: Match().Protocol("tcp").DestPorts(22).SourceNet("0.0.0.0/0"), Action: AcceptAction{}},
								{Match: Match().Protocol("tcp").DestPorts(1022).SourceNet("0.0.0.0/0"), Action: AcceptAction{}},
								{Match: Match().Protocol("tcp").SourcePorts(23).SourceNet("0.0.0.0/0"), Action: AcceptAction{}},
								{Match: Match().Protocol("tcp").SourcePorts(1023).SourceNet("0.0.0.0/0"), Action: AcceptAction{}},
							},
						}

						expRawFailsafeOut = &Chain{
							Name: "cali-failsafe-out",
							Rules: []Rule{
								{Match: Match().Protocol("tcp").DestPorts(23).DestNet("0.0.0.0/0"), Action: AcceptAction{}},
								{Match: Match().Protocol("tcp").DestPorts(1023).DestNet("0.0.0.0/0"), Action: AcceptAction{}},
								{Match: Match().Protocol("tcp").SourcePorts(22).SourceNet("0.0.0.0/0"), Action: AcceptAction{}},
								{Match: Match().Protocol("tcp").SourcePorts(1022).SourceNet("0.0.0.0/0"), Action: AcceptAction{}},
							},
						}

						expFailsafeIn = &Chain{
							Name: "cali-failsafe-in",
							Rules: []Rule{
								{Match: Match().Protocol("tcp").DestPorts(22).SourceNet("0.0.0.0/0"), Action: AcceptAction{}},
								{Match: Match().Protocol("tcp").DestPorts(1022).SourceNet("0.0.0.0/0"), Action: AcceptAction{}},
							},
						}

						expFailsafeOut = &Chain{
							Name: "cali-failsafe-out",
							Rules: []Rule{
								{Match: Match().Protocol("tcp").DestPorts(23).DestNet("0.0.0.0/0"), Action: AcceptAction{}},
								{Match: Match().Protocol("tcp").DestPorts(1023).DestNet("0.0.0.0/0"), Action: AcceptAction{}},
							},
						}
					}

					expForwardCheck := &Chain{
						Name: "cali-forward-check",
						Rules: []Rule{
							{
								Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: ReturnAction{},
							},
							{
								Match: Match().Protocol("tcp").
									DestPortRanges(portRanges).
									DestIPSet(ipSetThisHost),
								Action:  GotoAction{Target: ChainDispatchSetEndPointMark},
								Comment: []string{"To kubernetes NodePort service"},
							},
							{
								Match: Match().Protocol("udp").
									DestPortRanges(portRanges).
									DestIPSet(ipSetThisHost),
								Action:  GotoAction{Target: ChainDispatchSetEndPointMark},
								Comment: []string{"To kubernetes NodePort service"},
							},
							{
								Match:   Match().NotDestIPSet(ipSetThisHost),
								Action:  JumpAction{Target: ChainDispatchSetEndPointMark},
								Comment: []string{"To kubernetes service"},
							},
						},
					}

					expForwardEndpointMark := &Chain{
						Name: "cali-forward-endpoint-mark",
						Rules: []Rule{
							{
								Match:  Match().NotMarkMatchesWithMask(0x100, 0xff00),
								Action: JumpAction{Target: ChainDispatchFromEndPointMark},
							},
							{
								Match:  Match().OutInterface("cali+"),
								Action: JumpAction{Target: ChainToWorkloadDispatch},
							},
							{
								Action: JumpAction{Target: ChainDispatchToHostEndpointForward},
							},
							{
								Action: ClearMarkAction{Mark: 0xff00},
							},
							{
								Match:   Match().MarkSingleBitSet(0x10),
								Action:  AcceptAction{},
								Comment: []string{"Policy explicitly accepted packet."},
							},
						},
					}

					checkManglePostrouting(ipVersion, kubeIPVSEnabled)

					It("should include the expected forward chain in the filter chains", func() {
						Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-FORWARD")).To(Equal(&Chain{
							Name: "cali-FORWARD",
							Rules: []Rule{
								// Incoming host endpoint chains.
								{Action: ClearMarkAction{Mark: 0xe0}},
								{Match: Match().MarkClear(0x10),
									Action: JumpAction{Target: ChainDispatchFromHostEndPointForward}},
								// Per-prefix workload jump rules.
								{Match: Match().InInterface("cali+"),
									Action: JumpAction{Target: ChainFromWorkloadDispatch}},
								{Match: Match().OutInterface("cali+"),
									Action: JumpAction{Target: ChainToWorkloadDispatch}},
								// Outgoing host endpoint chains.
								{Action: JumpAction{Target: ChainDispatchToHostEndpointForward}},
								{Action: JumpAction{Target: ChainCIDRBlock}},
							},
						}))
					})
					It("should include the expected input chain in the filter chains", func() {
						if kubeIPVSEnabled {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-INPUT")).To(Equal(&Chain{
								Name: "cali-INPUT",
								Rules: []Rule{
									// Forward check chain.
									{Action: ClearMarkAction{Mark: conf.IptablesMarkEndpoint}},
									{Action: JumpAction{Target: ChainForwardCheck}},
									{Match: Match().MarkNotClear(conf.IptablesMarkEndpoint),
										Action: ReturnAction{},
									},

									// Per-prefix workload jump rules.  Note use of goto so that we
									// don't return here.
									{Match: Match().InInterface("cali+"),
										Action: GotoAction{Target: "cali-wl-to-host"}},

									// Untracked packets already matched in raw table.
									{Match: Match().MarkSingleBitSet(0x10),
										Action: AcceptAction{},
									},

									// Non-workload traffic, send to host chains.
									{Action: ClearMarkAction{Mark: 0xf0}},
									{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
									{
										Match:   Match().MarkSingleBitSet(0x10),
										Action:  AcceptAction{},
										Comment: []string{"Host endpoint policy accepted packet."},
									},
								},
							}))
						} else {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-INPUT")).To(Equal(&Chain{
								Name: "cali-INPUT",
								Rules: []Rule{
									// Per-prefix workload jump rules.  Note use of goto so that we
									// don't return here.
									{Match: Match().InInterface("cali+"),
										Action: GotoAction{Target: "cali-wl-to-host"}},

									// Untracked packets already matched in raw table.
									{Match: Match().MarkSingleBitSet(0x10),
										Action: AcceptAction{},
									},

									// Non-workload traffic, send to host chains.
									{Action: ClearMarkAction{Mark: 0xf0}},
									{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
									{
										Match:   Match().MarkSingleBitSet(0x10),
										Action:  AcceptAction{},
										Comment: []string{"Host endpoint policy accepted packet."},
									},
								},
							}))
						}
					})
					It("should include the expected output chain in the filter chains", func() {
						if kubeIPVSEnabled {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&Chain{
								Name: "cali-OUTPUT",
								Rules: []Rule{
									// Untracked packets already matched in raw table.
									{Match: Match().MarkSingleBitSet(0x10),
										Action: AcceptAction{},
									},

									// From endpoint mark chain
									{Match: Match().MarkNotClear(conf.IptablesMarkEndpoint),
										Action: GotoAction{Target: ChainForwardEndpointMark},
									},

									// To workload traffic.
									{Match: Match().OutInterface("cali+"), Action: ReturnAction{}},

									// Non-workload traffic, send to host chains.
									{Action: ClearMarkAction{Mark: 0xf0}},
									{
										Match:  Match().NotConntrackState("DNAT"),
										Action: JumpAction{Target: ChainDispatchToHostEndpoint},
									},
									{
										Match:   Match().MarkSingleBitSet(0x10),
										Action:  AcceptAction{},
										Comment: []string{"Host endpoint policy accepted packet."},
									},
								},
							}))
						} else {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&Chain{
								Name: "cali-OUTPUT",
								Rules: []Rule{
									// Untracked packets already matched in raw table.
									{Match: Match().MarkSingleBitSet(0x10),
										Action: AcceptAction{},
									},

									// To workload traffic.
									{Match: Match().OutInterface("cali+"), Action: ReturnAction{}},

									// Non-workload traffic, send to host chains.
									{Action: ClearMarkAction{Mark: 0xf0}},
									{
										Match:  Match().NotConntrackState("DNAT"),
										Action: JumpAction{Target: ChainDispatchToHostEndpoint},
									},
									{
										Match:   Match().MarkSingleBitSet(0x10),
										Action:  AcceptAction{},
										Comment: []string{"Host endpoint policy accepted packet."},
									},
								},
							}))
						}
					})
					It("should include the expected failsafe-in chain in the filter chains", func() {
						Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-failsafe-in")).To(Equal(expFailsafeIn))
					})
					It("should include the expected failsafe-out chain in the filter chains", func() {
						Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-failsafe-out")).To(Equal(expFailsafeOut))
					})
					It("should include the expected forward-check chain in the filter chains", func() {
						if kubeIPVSEnabled {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-forward-check")).To(Equal(expForwardCheck))
						} else {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-forward-check")).To(BeNil())
						}
					})
					It("should include the expected forward-endpoint-mark chain in the filter chains", func() {
						if kubeIPVSEnabled {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-forward-endpoint-mark")).To(Equal(expForwardEndpointMark))
						} else {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-forward-endpoint-mark")).To(BeNil())
						}
					})
					It("should return only the expected filter chains", func() {
						if kubeIPVSEnabled {
							Expect(len(rr.StaticFilterTableChains(ipVersion))).To(Equal(8))
						} else {
							Expect(len(rr.StaticFilterTableChains(ipVersion))).To(Equal(6))
						}
					})

					It("Should return expected raw OUTPUT chain", func() {
						Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&Chain{
							Name: "cali-OUTPUT",
							Rules: []Rule{
								// For safety, clear all our mark bits before we start.  (We could be in
								// append mode and another process' rules could have left the mark bit set.)
								{Action: ClearMarkAction{Mark: 0xf0}},
								// Then, jump to the untracked policy chains.
								{Action: JumpAction{Target: "cali-to-host-endpoint"}},
								// Then, if the packet was marked as allowed, accept it.  Packets also
								// return here without the mark bit set if the interface wasn't one that
								// we're policing.
								{Match: Match().MarkSingleBitSet(0x10), Action: AcceptAction{}},
							},
						}))
					})
					It("Should return expected raw failsafe in chain", func() {
						Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-failsafe-in")).To(Equal(expRawFailsafeIn))
					})
					It("Should return expected raw failsafe out chain", func() {
						Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-failsafe-out")).To(Equal(expRawFailsafeOut))
					})
					It("should return only the expected raw chains", func() {
						Expect(len(rr.StaticRawTableChains(ipVersion))).To(Equal(5))
					})
				})
			}

			It("IPv4: Should return expected raw PREROUTING chain", func() {
				Expect(findChain(rr.StaticRawTableChains(4), "cali-PREROUTING")).To(Equal(&Chain{
					Name: "cali-PREROUTING",
					Rules: []Rule{
						{Action: ClearMarkAction{Mark: 0xf0}},
						{Match: Match().InInterface("cali+"),
							Action: SetMarkAction{Mark: 0x40}},
						{Match: Match().MarkMatchesWithMask(0x40, 0x40),
							Action: JumpAction{Target: ChainRpfSkip}},
						{Match: Match().MarkSingleBitSet(0x40).RPFCheckFailed(false),
							Action: DropAction{}},
						{Match: Match().MarkClear(0x40),
							Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
						{Match: Match().MarkSingleBitSet(0x10),
							Action: AcceptAction{}},
					},
				}))
			})
			It("IPv6: Should return expected raw PREROUTING chain", func() {
				Expect(findChain(rr.StaticRawTableChains(6), "cali-PREROUTING")).To(Equal(&Chain{
					Name: "cali-PREROUTING",
					Rules: []Rule{
						{Action: ClearMarkAction{Mark: 0xf0}},
						{Match: Match().InInterface("cali+"),
							Action: SetMarkAction{Mark: 0x40}},
						{Match: Match().MarkMatchesWithMask(0x40, 0x40),
							Action: JumpAction{Target: ChainRpfSkip}},
						{Match: Match().MarkSingleBitSet(0x40).RPFCheckFailed(false),
							Action: DropAction{}},
						{Match: Match().MarkClear(0x40),
							Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
						{Match: Match().MarkSingleBitSet(0x10),
							Action: AcceptAction{}},
					},
				}))
			})

			It("IPv4: Should return expected mangle PREROUTING chain", func() {
				Expect(findChain(rr.StaticMangleTableChains(4), "cali-PREROUTING")).To(Equal(&Chain{
					Name: "cali-PREROUTING",
					Rules: []Rule{
						{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
							Action: AcceptAction{}},
						{Match: Match().MarkSingleBitSet(0x10),
							Action: AcceptAction{}},
						{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
						{Match: Match().MarkSingleBitSet(0x10),
							Action:  AcceptAction{},
							Comment: []string{"Host endpoint policy accepted packet."}},
					},
				}))
			})
			It("IPv6: Should return expected mangle PREROUTING chain", func() {
				Expect(findChain(rr.StaticMangleTableChains(6), "cali-PREROUTING")).To(Equal(&Chain{
					Name: "cali-PREROUTING",
					Rules: []Rule{
						{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
							Action: AcceptAction{}},
						{Match: Match().MarkSingleBitSet(0x10),
							Action: AcceptAction{}},
						{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
						{Match: Match().MarkSingleBitSet(0x10),
							Action:  AcceptAction{},
							Comment: []string{"Host endpoint policy accepted packet."}},
					},
				}))
			})

			It("IPv4: should include the expected workload-to-host chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(4), "cali-wl-to-host")).To(Equal(&Chain{
					Name: "cali-wl-to-host",
					Rules: []Rule{
						{Action: JumpAction{Target: "cali-from-wl-dispatch"}},
						{Action: ReturnAction{},
							Comment: []string{"Configured DefaultEndpointToHostAction"}},
					},
				}))
			})
			It("IPv6: should include the expected workload-to-host chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(6), "cali-wl-to-host")).To(Equal(&Chain{
					Name: "cali-wl-to-host",
					Rules: []Rule{
						{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(130), Action: AcceptAction{}},
						{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(131), Action: AcceptAction{}},
						{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(132), Action: AcceptAction{}},
						{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(133), Action: AcceptAction{}},
						{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(135), Action: AcceptAction{}},
						{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(136), Action: AcceptAction{}},
						{Action: JumpAction{Target: "cali-from-wl-dispatch"}},
						{Action: ReturnAction{},
							Comment: []string{"Configured DefaultEndpointToHostAction"}},
					},
				}))
			})

			It("IPv4: Should return expected NAT prerouting chain", func() {
				Expect(findChain(rr.StaticNATTableChains(4), "cali-PREROUTING")).To(Equal(&Chain{
					Name: "cali-PREROUTING",
					Rules: []Rule{
						{Action: JumpAction{Target: "cali-fip-dnat"}},
					}}))
			})
			It("IPv4: Should return expected NAT postrouting chain", func() {
				Expect(findChain(rr.StaticNATTableChains(4), "cali-POSTROUTING")).To(Equal(&Chain{
					Name: "cali-POSTROUTING",
					Rules: []Rule{
						{Action: JumpAction{Target: "cali-fip-snat"}},
						{Action: JumpAction{Target: "cali-nat-outgoing"}},
					},
				}))
			})
			It("IPv4: Should return expected NAT output chain", func() {
				Expect(findChain(rr.StaticNATTableChains(4), "cali-OUTPUT")).To(Equal(&Chain{
					Name: "cali-OUTPUT",
					Rules: []Rule{
						{Action: JumpAction{Target: "cali-fip-dnat"}},
					},
				}))
			})
			It("IPv4: Should return only the expected nat chains", func() {
				Expect(len(rr.StaticNATTableChains(4))).To(Equal(3))
			})
			It("IPv6: Should return only the expected nat chains", func() {
				Expect(len(rr.StaticNATTableChains(6))).To(Equal(3))
			})
		})

		Describe(fmt.Sprintf("with IPIP enabled and IPVS=%v", kubeIPVSEnabled), func() {
			epMark := uint32(0xff00)
			BeforeEach(func() {
				conf = Config{
					WorkloadIfacePrefixes:       []string{"cali"},
					IPIPEnabled:                 true,
					IPIPTunnelAddress:           net.ParseIP("10.0.0.1"),
					IPSetConfigV4:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
					IPSetConfigV6:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
					IptablesMarkAccept:          0x10,
					IptablesMarkPass:            0x20,
					IptablesMarkScratch0:        0x40,
					IptablesMarkScratch1:        0x80,
					IptablesMarkEndpoint:        epMark,
					IptablesMarkNonCaliEndpoint: 0x100,
					KubeIPVSSupportEnabled:      kubeIPVSEnabled,
				}
			})

			checkManglePostrouting(4, kubeIPVSEnabled)

			expInputChainIPIPV4IPVS := &Chain{
				Name: "cali-INPUT",
				Rules: []Rule{
					// IPIP rules
					{Match: Match().
						ProtocolNum(4).
						SourceIPSet("cali40all-hosts-net").
						DestAddrType("LOCAL"),

						Action:  AcceptAction{},
						Comment: []string{"Allow IPIP packets from Calico hosts"}},
					{Match: Match().ProtocolNum(4),
						Action:  DropAction{},
						Comment: []string{"Drop IPIP packets from non-Calico hosts"}},

					// Forward check chain.
					{Action: ClearMarkAction{Mark: epMark}},
					{Action: JumpAction{Target: ChainForwardCheck}},
					{Match: Match().MarkNotClear(epMark),
						Action: ReturnAction{},
					},

					// Per-prefix workload jump rules.  Note use of goto so that we
					// don't return here.
					{Match: Match().InInterface("cali+"),
						Action: GotoAction{Target: "cali-wl-to-host"}},

					// Untracked packets already matched in raw table.
					{Match: Match().MarkSingleBitSet(0x10),
						Action: AcceptAction{}},

					// Not from a workload, apply host policy.
					{Action: ClearMarkAction{Mark: 0xf0}},
					{Action: JumpAction{Target: "cali-from-host-endpoint"}},
					{
						Match:   Match().MarkSingleBitSet(0x10),
						Action:  AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			expInputChainIPIPV4NoIPVS := &Chain{
				Name: "cali-INPUT",
				Rules: []Rule{
					// IPIP rules
					{Match: Match().
						ProtocolNum(4).
						SourceIPSet("cali40all-hosts-net").
						DestAddrType("LOCAL"),

						Action:  AcceptAction{},
						Comment: []string{"Allow IPIP packets from Calico hosts"}},
					{Match: Match().ProtocolNum(4),
						Action:  DropAction{},
						Comment: []string{"Drop IPIP packets from non-Calico hosts"}},

					// Per-prefix workload jump rules.  Note use of goto so that we
					// don't return here.
					{Match: Match().InInterface("cali+"),
						Action: GotoAction{Target: "cali-wl-to-host"}},

					// Untracked packets already matched in raw table.
					{Match: Match().MarkSingleBitSet(0x10),
						Action: AcceptAction{}},

					// Not from a workload, apply host policy.
					{Action: ClearMarkAction{Mark: 0xf0}},
					{Action: JumpAction{Target: "cali-from-host-endpoint"}},
					{
						Match:   Match().MarkSingleBitSet(0x10),
						Action:  AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			// V6 should be unaffected.
			expInputChainIPIPV6IPVS := &Chain{
				Name: "cali-INPUT",
				Rules: []Rule{
					// Forward check chain.
					{Action: ClearMarkAction{Mark: epMark}},
					{Action: JumpAction{Target: ChainForwardCheck}},
					{Match: Match().MarkNotClear(epMark),
						Action: ReturnAction{},
					},

					// Per-prefix workload jump rules.  Note use of goto so that we
					// don't return here.
					{Match: Match().InInterface("cali+"),
						Action: GotoAction{Target: "cali-wl-to-host"}},

					// Untracked packets already matched in raw table.
					{Match: Match().MarkSingleBitSet(0x10),
						Action: AcceptAction{}},

					// Not from a workload, apply host policy.
					{Action: ClearMarkAction{Mark: 0xf0}},
					{Action: JumpAction{Target: "cali-from-host-endpoint"}},
					{
						Match:   Match().MarkSingleBitSet(0x10),
						Action:  AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}
			expInputChainIPIPV6NoIPVS := &Chain{
				Name: "cali-INPUT",
				Rules: []Rule{
					// Per-prefix workload jump rules.  Note use of goto so that we
					// don't return here.
					{Match: Match().InInterface("cali+"),
						Action: GotoAction{Target: "cali-wl-to-host"}},

					// Untracked packets already matched in raw table.
					{Match: Match().MarkSingleBitSet(0x10),
						Action: AcceptAction{}},

					// Not from a workload, apply host policy.
					{Action: ClearMarkAction{Mark: 0xf0}},
					{Action: JumpAction{Target: "cali-from-host-endpoint"}},
					{
						Match:   Match().MarkSingleBitSet(0x10),
						Action:  AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			expOutputChainIPIPV4IPVS := &Chain{
				Name: "cali-OUTPUT",
				Rules: []Rule{
					// Untracked packets already matched in raw table.
					{Match: Match().MarkSingleBitSet(0x10),
						Action: AcceptAction{}},

					// From endpoint mark chain
					{Match: Match().MarkNotClear(epMark),
						Action: GotoAction{Target: ChainForwardEndpointMark},
					},

					// To workload traffic.
					{Match: Match().OutInterface("cali+"), Action: ReturnAction{}},

					// Auto-allow IPIP traffic to other Calico hosts.
					{
						Match: Match().ProtocolNum(4).
							DestIPSet("cali40all-hosts-net").
							SrcAddrType(AddrTypeLocal, false),
						Action:  AcceptAction{},
						Comment: []string{"Allow IPIP packets to other Calico hosts"},
					},

					// Non-workload traffic, send to host chains.
					{Action: ClearMarkAction{Mark: 0xf0}},
					{
						Match:  Match().NotConntrackState("DNAT"),
						Action: JumpAction{Target: ChainDispatchToHostEndpoint},
					},
					{
						Match:   Match().MarkSingleBitSet(0x10),
						Action:  AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			expOutputChainIPIPV4NoIPVS := &Chain{
				Name: "cali-OUTPUT",
				Rules: []Rule{
					// Untracked packets already matched in raw table.
					{Match: Match().MarkSingleBitSet(0x10),
						Action: AcceptAction{}},

					// To workload traffic.
					{Match: Match().OutInterface("cali+"), Action: ReturnAction{}},

					// Auto-allow IPIP traffic to other Calico hosts.
					{
						Match: Match().ProtocolNum(4).
							DestIPSet("cali40all-hosts-net").
							SrcAddrType(AddrTypeLocal, false),
						Action:  AcceptAction{},
						Comment: []string{"Allow IPIP packets to other Calico hosts"},
					},

					// Non-workload traffic, send to host chains.
					{Action: ClearMarkAction{Mark: 0xf0}},
					{
						Match:  Match().NotConntrackState("DNAT"),
						Action: JumpAction{Target: ChainDispatchToHostEndpoint},
					},
					{
						Match:   Match().MarkSingleBitSet(0x10),
						Action:  AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			// V6 should be unaffected.
			expOutputChainIPIPV6IPVS := &Chain{
				Name: "cali-OUTPUT",
				Rules: []Rule{
					// Untracked packets already matched in raw table.
					{Match: Match().MarkSingleBitSet(0x10),
						Action: AcceptAction{}},

					// From endpoint mark chain
					{Match: Match().MarkNotClear(epMark),
						Action: GotoAction{Target: ChainForwardEndpointMark},
					},

					// To workload traffic.
					{Match: Match().OutInterface("cali+"), Action: ReturnAction{}},

					// Non-workload traffic, send to host chains.
					{Action: ClearMarkAction{Mark: 0xf0}},
					{
						Match:  Match().NotConntrackState("DNAT"),
						Action: JumpAction{Target: ChainDispatchToHostEndpoint},
					},
					{
						Match:   Match().MarkSingleBitSet(0x10),
						Action:  AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			expOutputChainIPIPV6NoIPVS := &Chain{
				Name: "cali-OUTPUT",
				Rules: []Rule{
					// Untracked packets already matched in raw table.
					{Match: Match().MarkSingleBitSet(0x10),
						Action: AcceptAction{}},

					// To workload traffic.
					{Match: Match().OutInterface("cali+"), Action: ReturnAction{}},

					// Non-workload traffic, send to host chains.
					{Action: ClearMarkAction{Mark: 0xf0}},
					{
						Match:  Match().NotConntrackState("DNAT"),
						Action: JumpAction{Target: ChainDispatchToHostEndpoint},
					},
					{
						Match:   Match().MarkSingleBitSet(0x10),
						Action:  AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			It("IPv4: should include the expected input chain in the filter chains", func() {
				if kubeIPVSEnabled {
					Expect(findChain(rr.StaticFilterTableChains(4), "cali-INPUT")).To(Equal(expInputChainIPIPV4IPVS))
				} else {
					Expect(findChain(rr.StaticFilterTableChains(4), "cali-INPUT")).To(Equal(expInputChainIPIPV4NoIPVS))
				}
			})
			It("IPv6: should include the expected input chain in the filter chains", func() {
				if kubeIPVSEnabled {
					Expect(findChain(rr.StaticFilterTableChains(6), "cali-INPUT")).To(Equal(expInputChainIPIPV6IPVS))
				} else {
					Expect(findChain(rr.StaticFilterTableChains(6), "cali-INPUT")).To(Equal(expInputChainIPIPV6NoIPVS))
				}
			})
			It("IPv4: should include the expected output chain in the filter chains", func() {
				if kubeIPVSEnabled {
					Expect(findChain(rr.StaticFilterTableChains(4), "cali-OUTPUT")).To(Equal(expOutputChainIPIPV4IPVS))
				} else {
					Expect(findChain(rr.StaticFilterTableChains(4), "cali-OUTPUT")).To(Equal(expOutputChainIPIPV4NoIPVS))
				}
			})
			It("IPv6: should include the expected output chain in the filter chains", func() {
				if kubeIPVSEnabled {
					Expect(findChain(rr.StaticFilterTableChains(6), "cali-OUTPUT")).To(Equal(expOutputChainIPIPV6IPVS))
				} else {
					Expect(findChain(rr.StaticFilterTableChains(6), "cali-OUTPUT")).To(Equal(expOutputChainIPIPV6NoIPVS))
				}
			})
			It("IPv4: Should return expected NAT postrouting chain", func() {
				Expect(rr.StaticNATPostroutingChains(4)).To(Equal([]*Chain{
					{
						Name: "cali-POSTROUTING",
						Rules: []Rule{
							{Action: JumpAction{Target: "cali-fip-snat"}},
							{Action: JumpAction{Target: "cali-nat-outgoing"}},
							{
								Match: Match().
									OutInterface("tunl0").
									NotSrcAddrType(AddrTypeLocal, true).
									SrcAddrType(AddrTypeLocal, false),
								Action: MasqAction{},
							},
						},
					},
				}))
			})

			Describe("with IPv4 VXLAN enabled", func() {
				BeforeEach(func() {
					conf.VXLANEnabled = true
				})

				checkManglePostrouting(4, kubeIPVSEnabled)

				It("IPv4: Should return expected NAT postrouting chain", func() {
					Expect(rr.StaticNATPostroutingChains(4)).To(Equal([]*Chain{
						{
							Name: "cali-POSTROUTING",
							Rules: []Rule{
								{Action: JumpAction{Target: "cali-fip-snat"}},
								{Action: JumpAction{Target: "cali-nat-outgoing"}},
								{
									Match: Match().
										OutInterface("tunl0").
										NotSrcAddrType(AddrTypeLocal, true).
										SrcAddrType(AddrTypeLocal, false),
									Action: MasqAction{},
								},
							},
						},
					}))
				})

				Describe("and IPv4 tunnel IP", func() {
					BeforeEach(func() {
						conf.VXLANTunnelAddress = net.IP{10, 0, 0, 1}
					})

					It("IPv4: Should return expected NAT postrouting chain", func() {
						Expect(rr.StaticNATPostroutingChains(4)).To(Equal([]*Chain{
							{
								Name: "cali-POSTROUTING",
								Rules: []Rule{
									{Action: JumpAction{Target: "cali-fip-snat"}},
									{Action: JumpAction{Target: "cali-nat-outgoing"}},
									{
										Match: Match().
											OutInterface("tunl0").
											NotSrcAddrType(AddrTypeLocal, true).
											SrcAddrType(AddrTypeLocal, false),
										Action: MasqAction{},
									},
									{
										Match: Match().
											OutInterface("vxlan.calico").
											NotSrcAddrType(AddrTypeLocal, true).
											SrcAddrType(AddrTypeLocal, false),
										Action: MasqAction{},
									},
								},
							},
						}))
					})
				})
			})

			Describe("with IPv6 VXLAN enabled", func() {
				BeforeEach(func() {
					conf.VXLANEnabledV6 = true
				})

				checkManglePostrouting(6, kubeIPVSEnabled)

				It("IPv6: Should return expected NAT postrouting chain", func() {
					Expect(rr.StaticNATPostroutingChains(6)).To(Equal([]*Chain{
						{
							Name: "cali-POSTROUTING",
							Rules: []Rule{
								{Action: JumpAction{Target: "cali-fip-snat"}},
								{Action: JumpAction{Target: "cali-nat-outgoing"}},
							},
						},
					}))
				})

				Describe("and IPv6 tunnel IP", func() {
					BeforeEach(func() {
						conf.VXLANTunnelAddressV6 = net.ParseIP("dead:beef::1")

					})

					It("IPv6: Should return expected NAT postrouting chain", func() {
						Expect(rr.StaticNATPostroutingChains(6)).To(Equal([]*Chain{
							{
								Name: "cali-POSTROUTING",
								Rules: []Rule{
									{Action: JumpAction{Target: "cali-fip-snat"}},
									{Action: JumpAction{Target: "cali-nat-outgoing"}},
									{
										Match: Match().
											OutInterface("vxlan-v6.calico").
											NotSrcAddrType(AddrTypeLocal, true).
											SrcAddrType(AddrTypeLocal, false),
										Action: MasqAction{},
									},
								},
							},
						}))
					})
				})
			})

			It("IPv6: Should return expected NAT postrouting chain", func() {
				Expect(rr.StaticNATPostroutingChains(6)).To(Equal([]*Chain{
					{
						Name: "cali-POSTROUTING",
						Rules: []Rule{
							{Action: JumpAction{Target: "cali-fip-snat"}},
							{Action: JumpAction{Target: "cali-nat-outgoing"}},
						},
					},
				}))
			})
		})
	}

	Describe("with multiple KubePortRanges", func() {
		BeforeEach(func() {
			conf = Config{
				WorkloadIfacePrefixes:       []string{"cali"},
				IPSetConfigV4:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
				IPSetConfigV6:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
				IptablesMarkAccept:          0x10,
				IptablesMarkPass:            0x20,
				IptablesMarkScratch0:        0x40,
				IptablesMarkScratch1:        0x80,
				IptablesMarkEndpoint:        0xff00,
				IptablesMarkNonCaliEndpoint: 0x100,
				KubeIPVSSupportEnabled:      true,
				KubeNodePortRanges: []numorstring.Port{
					{MinPort: 30030, MaxPort: 30040, PortName: ""},
					{MinPort: 30130, MaxPort: 30140, PortName: ""},
					{MinPort: 30230, MaxPort: 30240, PortName: ""},
					{MinPort: 30330, MaxPort: 30340, PortName: ""},
					{MinPort: 30430, MaxPort: 30440, PortName: ""},
					{MinPort: 30530, MaxPort: 30540, PortName: ""},
					{MinPort: 30630, MaxPort: 30640, PortName: ""},
					{MinPort: 30730, MaxPort: 30740, PortName: ""},
					{MinPort: 30830, MaxPort: 30840, PortName: ""},
				},
			}
		})
		for _, ipVersion := range []uint8{4, 6} {
			// Capture current value of ipVersion.
			ipVersion := ipVersion
			ipSetThisHost := fmt.Sprintf("cali%d0this-host", ipVersion)

			portRanges1 := []*proto.PortRange{
				{First: 30030, Last: 30040},
				{First: 30130, Last: 30140},
				{First: 30230, Last: 30240},
				{First: 30330, Last: 30340},
				{First: 30430, Last: 30440},
				{First: 30530, Last: 30540},
				{First: 30630, Last: 30640},
			}

			portRanges2 := []*proto.PortRange{
				{First: 30730, Last: 30740},
				{First: 30830, Last: 30840},
			}

			expForwardCheck := &Chain{
				Name: "cali-forward-check",
				Rules: []Rule{
					{
						Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: ReturnAction{},
					},
					{
						Match: Match().Protocol("tcp").
							DestPortRanges(portRanges1).
							DestIPSet(ipSetThisHost),
						Action:  GotoAction{Target: ChainDispatchSetEndPointMark},
						Comment: []string{"To kubernetes NodePort service"},
					},
					{
						Match: Match().Protocol("udp").
							DestPortRanges(portRanges1).
							DestIPSet(ipSetThisHost),
						Action:  GotoAction{Target: ChainDispatchSetEndPointMark},
						Comment: []string{"To kubernetes NodePort service"},
					},
					{
						Match: Match().Protocol("tcp").
							DestPortRanges(portRanges2).
							DestIPSet(ipSetThisHost),
						Action:  GotoAction{Target: ChainDispatchSetEndPointMark},
						Comment: []string{"To kubernetes NodePort service"},
					},
					{
						Match: Match().Protocol("udp").
							DestPortRanges(portRanges2).
							DestIPSet(ipSetThisHost),
						Action:  GotoAction{Target: ChainDispatchSetEndPointMark},
						Comment: []string{"To kubernetes NodePort service"},
					},
					{
						Match:   Match().NotDestIPSet(ipSetThisHost),
						Action:  JumpAction{Target: ChainDispatchSetEndPointMark},
						Comment: []string{"To kubernetes service"},
					},
				},
			}

			It("should include the expected forward-check chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-forward-check")).To(Equal(expForwardCheck))
			})
		}
	})

	Describe("with openstack special-cases", func() {
		BeforeEach(func() {
			conf = Config{
				WorkloadIfacePrefixes:        []string{"tap"},
				IPSetConfigV4:                ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
				IPSetConfigV6:                ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
				OpenStackSpecialCasesEnabled: true,
				OpenStackMetadataIP:          net.ParseIP("10.0.0.1"),
				OpenStackMetadataPort:        1234,
				IptablesMarkAccept:           0x10,
				IptablesMarkPass:             0x20,
				IptablesMarkScratch0:         0x40,
				IptablesMarkScratch1:         0x80,
				IptablesMarkEndpoint:         0xff00,
				IptablesMarkNonCaliEndpoint:  0x100,
			}
		})

		expWlToHostV4 := &Chain{
			Name: "cali-wl-to-host",
			Rules: []Rule{
				// OpenStack special cases.
				{
					Match: Match().
						Protocol("tcp").
						DestNet("10.0.0.1").
						DestPorts(1234),
					Action: AcceptAction{},
				},
				{Match: Match().Protocol("udp").SourcePorts(68).DestPorts(67),
					Action: AcceptAction{}},
				{Match: Match().Protocol("udp").DestPorts(53),
					Action: AcceptAction{}},

				{Action: JumpAction{Target: "cali-from-wl-dispatch"}},
				{Action: ReturnAction{},
					Comment: []string{"Configured DefaultEndpointToHostAction"}},
			},
		}

		expWlToHostV6 := &Chain{
			Name: "cali-wl-to-host",
			Rules: []Rule{
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(130), Action: AcceptAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(131), Action: AcceptAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(132), Action: AcceptAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(133), Action: AcceptAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(135), Action: AcceptAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(136), Action: AcceptAction{}},

				// OpenStack special cases.
				{Match: Match().Protocol("udp").SourcePorts(546).DestPorts(547),
					Action: AcceptAction{}},
				{Match: Match().Protocol("udp").DestPorts(53),
					Action: AcceptAction{}},

				{Action: JumpAction{Target: "cali-from-wl-dispatch"}},
				{Action: ReturnAction{},
					Comment: []string{"Configured DefaultEndpointToHostAction"}},
			},
		}

		It("IPv4: should include the expected workload-to-host chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(4), "cali-wl-to-host")).To(Equal(expWlToHostV4))
		})
		It("IPv6: should include the expected workload-to-host chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(6), "cali-wl-to-host")).To(Equal(expWlToHostV6))
		})

		It("IPv4: Should return expected NAT prerouting chain", func() {
			Expect(rr.StaticNATPreroutingChains(4)).To(Equal([]*Chain{
				{
					Name: "cali-PREROUTING",
					Rules: []Rule{
						{
							Action: JumpAction{Target: "cali-fip-dnat"},
						},
						{
							Match: Match().
								Protocol("tcp").
								DestPorts(80).
								DestNet("169.254.169.254/32"),
							Action: DNATAction{
								DestAddr: "10.0.0.1",
								DestPort: 1234,
							},
						},
					},
				},
			}))
		})
		It("IPv6: Should return expected NAT prerouting chain", func() {
			Expect(rr.StaticNATPreroutingChains(6)).To(Equal([]*Chain{
				{
					Name: "cali-PREROUTING",
					Rules: []Rule{
						{Action: JumpAction{Target: "cali-fip-dnat"}},
					},
				},
			}))
		})
	})

	Describe("with openstack special-cases and RETURN action", func() {
		BeforeEach(func() {
			conf = Config{
				WorkloadIfacePrefixes:        []string{"tap"},
				IPSetConfigV4:                ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
				IPSetConfigV6:                ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
				OpenStackSpecialCasesEnabled: true,
				OpenStackMetadataIP:          net.ParseIP("10.0.0.1"),
				OpenStackMetadataPort:        1234,
				IptablesMarkAccept:           0x10,
				IptablesMarkPass:             0x20,
				IptablesMarkScratch0:         0x40,
				IptablesMarkScratch1:         0x80,
				IptablesMarkEndpoint:         0xff00,
				IptablesMarkNonCaliEndpoint:  0x100,
				IptablesFilterAllowAction:    "RETURN",
			}
		})

		expWlToHostV4 := &Chain{
			Name: "cali-wl-to-host",
			Rules: []Rule{
				// OpenStack special cases.
				{
					Match: Match().
						Protocol("tcp").
						DestNet("10.0.0.1").
						DestPorts(1234),
					Action: ReturnAction{},
				},
				{Match: Match().Protocol("udp").SourcePorts(68).DestPorts(67),
					Action: ReturnAction{}},
				{Match: Match().Protocol("udp").DestPorts(53),
					Action: ReturnAction{}},

				{Action: JumpAction{Target: "cali-from-wl-dispatch"}},
				{Action: ReturnAction{},
					Comment: []string{"Configured DefaultEndpointToHostAction"}},
			},
		}

		expWlToHostV6 := &Chain{
			Name: "cali-wl-to-host",
			Rules: []Rule{
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(130), Action: ReturnAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(131), Action: ReturnAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(132), Action: ReturnAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(133), Action: ReturnAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(135), Action: ReturnAction{}},
				{Match: Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(136), Action: ReturnAction{}},

				// OpenStack special cases.
				{Match: Match().Protocol("udp").SourcePorts(546).DestPorts(547),
					Action: ReturnAction{}},
				{Match: Match().Protocol("udp").DestPorts(53),
					Action: ReturnAction{}},

				{Action: JumpAction{Target: "cali-from-wl-dispatch"}},
				{Action: ReturnAction{},
					Comment: []string{"Configured DefaultEndpointToHostAction"}},
			},
		}

		It("IPv4: should include the expected workload-to-host chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(4), "cali-wl-to-host")).To(Equal(expWlToHostV4))
		})
		It("IPv6: should include the expected workload-to-host chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(6), "cali-wl-to-host")).To(Equal(expWlToHostV6))
		})
	})

	Describe("with RETURN accept action", func() {
		epMark := uint32(0xff00)
		BeforeEach(func() {
			conf = Config{
				WorkloadIfacePrefixes:       []string{"cali"},
				IPSetConfigV4:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
				IPSetConfigV6:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
				IptablesMarkAccept:          0x10,
				IptablesMarkPass:            0x20,
				IptablesMarkScratch0:        0x40,
				IptablesMarkScratch1:        0x80,
				IptablesMarkEndpoint:        epMark,
				IptablesMarkNonCaliEndpoint: 0x100,
				IptablesFilterAllowAction:   "RETURN",
				IptablesMangleAllowAction:   "RETURN",
			}
		})

		for _, ipVersion := range []uint8{4, 6} {

			It("should include the expected forward chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-FORWARD")).To(Equal(&Chain{
					Name: "cali-FORWARD",
					Rules: []Rule{
						// Incoming host endpoint chains.
						{Action: ClearMarkAction{Mark: 0xe0}},
						{Match: Match().MarkClear(0x10),
							Action: JumpAction{Target: ChainDispatchFromHostEndPointForward}},
						// Per-prefix workload jump rules.
						{Match: Match().InInterface("cali+"),
							Action: JumpAction{Target: ChainFromWorkloadDispatch}},
						{Match: Match().OutInterface("cali+"),
							Action: JumpAction{Target: ChainToWorkloadDispatch}},
						// Outgoing host endpoint chains.
						{Action: JumpAction{Target: ChainDispatchToHostEndpointForward}},
						{Action: JumpAction{Target: ChainCIDRBlock}},
					},
				}))
			})
			It("should include the expected input chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-INPUT")).To(Equal(&Chain{
					Name: "cali-INPUT",
					Rules: []Rule{
						// Per-prefix workload jump rules.  Note use of goto so that we
						// don't return here.
						{Match: Match().InInterface("cali+"),
							Action: GotoAction{Target: "cali-wl-to-host"}},

						// Untracked packets already matched in raw table.
						{Match: Match().MarkSingleBitSet(0x10),
							Action: ReturnAction{}},

						// Non-workload traffic, send to host chains.
						{Action: ClearMarkAction{Mark: 0xf0}},
						{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
						{
							Match:   Match().MarkSingleBitSet(0x10),
							Action:  ReturnAction{},
							Comment: []string{"Host endpoint policy accepted packet."},
						},
					},
				}))
			})
			It("should include the expected output chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&Chain{
					Name: "cali-OUTPUT",
					Rules: []Rule{
						// Untracked packets already matched in raw table.
						{Match: Match().MarkSingleBitSet(0x10),
							Action: ReturnAction{}},

						// To workload traffic.
						{Match: Match().OutInterface("cali+"), Action: ReturnAction{}},

						// Non-workload traffic, send to host chains.
						{Action: ClearMarkAction{Mark: 0xf0}},
						{
							Match:  Match().NotConntrackState("DNAT"),
							Action: JumpAction{Target: ChainDispatchToHostEndpoint},
						},
						{
							Match:   Match().MarkSingleBitSet(0x10),
							Action:  ReturnAction{},
							Comment: []string{"Host endpoint policy accepted packet."},
						},
					},
				}))
			})
		}
	})

	Describe("with WireGuard enabled", func() {
		type testConf struct {
			IPVersion  uint8
			EnableIPv4 bool
			EnableIPv6 bool
		}
		for _, testConfig := range []testConf{
			{4, true, false},
			{6, true, false},
			{4, false, true},
			{6, false, true},
			{4, true, true},
			{6, true, true},
		} {
			enableIPv4 := testConfig.EnableIPv4
			enableIPv6 := testConfig.EnableIPv6
			ipVersion := testConfig.IPVersion
			Describe(fmt.Sprintf("IPv4 enabled: %v, IPv6 enabled: %v", enableIPv4, enableIPv6), func() {
				BeforeEach(func() {
					conf = Config{
						WorkloadIfacePrefixes:       []string{"cali"},
						IPSetConfigV4:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
						IPSetConfigV6:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
						IptablesMarkAccept:          0x10,
						IptablesMarkPass:            0x20,
						IptablesMarkScratch0:        0x40,
						IptablesMarkScratch1:        0x80,
						IptablesMarkEndpoint:        0xff00,
						IptablesMarkNonCaliEndpoint: 0x100,
						WireguardEnabled:            enableIPv4,
						WireguardEnabledV6:          enableIPv6,
						WireguardInterfaceName:      "wireguard.cali",
						WireguardInterfaceNameV6:    "wg-v6.cali",
						WireguardIptablesMark:       0x100000,
						WireguardListeningPort:      51820,
						WireguardEncryptHostTraffic: true,
						RouteSource:                 "WorkloadIPs",
					}
				})

				It("should include the expected input chain in the filter chains", func() {
					rules := []Rule{}
					if (ipVersion == 4 && enableIPv4) || (ipVersion == 6 && enableIPv6) {
						// Wireguard rules
						rules = append(rules,
							Rule{Match: Match().
								ProtocolNum(17).
								DestPorts(51820).
								DestAddrType("LOCAL"),

								Action:  AcceptAction{},
								Comment: []string{"Allow incoming Wireguard packets"}})
					}
					rules = append(rules,
						// Per-prefix workload jump rules.  Note use of goto so that we
						// don't return here.
						Rule{Match: Match().InInterface("cali+"),
							Action: GotoAction{Target: "cali-wl-to-host"}},

						// Untracked packets already matched in raw table.
						Rule{Match: Match().MarkSingleBitSet(0x10),
							Action: AcceptAction{},
						},

						// Non-workload traffic, send to host chains.
						Rule{Action: ClearMarkAction{Mark: 0xf0}},
						Rule{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
						Rule{
							Match:   Match().MarkSingleBitSet(0x10),
							Action:  AcceptAction{},
							Comment: []string{"Host endpoint policy accepted packet."},
						},
					)

					Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-INPUT")).To(Equal(&Chain{
						Name:  "cali-INPUT",
						Rules: rules,
					}))
				})

				It("should include the expected WireGuard PREROUTING chain in the raw chains", func() {
					Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-PREROUTING")).To(Equal(&Chain{
						Name: "cali-PREROUTING",
						Rules: []Rule{
							{Match: nil,
								Action: ClearMarkAction{Mark: 0xf0}},
							{Match: nil,
								Action: JumpAction{Target: "cali-wireguard-incoming-mark"}},
							{Match: Match().InInterface("cali+"),
								Action: SetMarkAction{Mark: 0x40}},
							{Match: Match().MarkMatchesWithMask(0x40, 0x40),
								Action: JumpAction{Target: ChainRpfSkip}},
							{Match: Match().MarkMatchesWithMask(0x40, 0x40).RPFCheckFailed(false),
								Action: DropAction{}},
							{Match: Match().MarkClear(0x40),
								Action: JumpAction{Target: "cali-from-host-endpoint"}},
							{Match: Match().MarkMatchesWithMask(0x10, 0x10),
								Action: AcceptAction{}},
						},
					}))
					Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-wireguard-incoming-mark")).To(Equal(&Chain{
						Name: "cali-wireguard-incoming-mark",
						Rules: []Rule{
							{Match: Match().InInterface("lo"),
								Action: ReturnAction{}},
							{Match: Match().InInterface("wireguard.cali"),
								Action: ReturnAction{}},
							{Match: Match().InInterface("wg-v6.cali"),
								Action: ReturnAction{}},
							{Match: Match().InInterface("cali+"),
								Action: ReturnAction{}},
							{Match: nil,
								Action: SetMarkAction{Mark: 0x100000}},
						},
					}))
				})
			})
		}
	})
})

func findChain(chains []*Chain, name string) *Chain {
	for _, chain := range chains {
		if chain.Name == name {
			return chain
		}
	}
	return nil
}
