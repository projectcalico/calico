// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	. "github.com/projectcalico/calico/felix/rules"
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
			expRules := []generictables.Rule{}
			if !rr.BPFEnabled {
				allPoolSetName := fmt.Sprintf("cali%v0all-ipam-pools", ipVersion)
				thisHostSetName := fmt.Sprintf("cali%v0this-host", ipVersion)
				dscpSetName := fmt.Sprintf("cali%v0dscp-src-net", ipVersion)
				expRules = append(expRules, generictables.Rule{
					// DSCP rule.
					Match: iptables.Match().
						SourceIPSet(dscpSetName).
						NotDestIPSet(allPoolSetName).
						NotDestIPSet(thisHostSetName),
					Action:  iptables.JumpAction{Target: ChainEgressDSCP},
					Comment: []string{"set dscp for traffic leaving cluster."},
				})
			}
			// Accept already accepted.
			expRules = append(expRules, generictables.Rule{
				Match:  iptables.Match().MarkSingleBitSet(0x10),
				Action: iptables.ReturnAction{},
			})
			if ipvs {
				// Accept IPVS-forwarded traffic.
				expRules = append(expRules, generictables.Rule{
					Match:  iptables.Match().MarkNotClear(conf.MarkEndpoint),
					Action: iptables.ReturnAction{},
				})
			}
			expRules = append(expRules, []generictables.Rule{
				// Clear all Calico mark bits.
				{Action: iptables.ClearMarkAction{Mark: 0xf0}},
				// For DNAT'd traffic, apply host endpoint policy.
				{
					Match:  iptables.Match().ConntrackState("DNAT"),
					Action: iptables.JumpAction{Target: ChainDispatchToHostEndpoint},
				},
				// Accept if policy allowed packet.
				{
					Match:   iptables.Match().MarkSingleBitSet(0x10),
					Action:  iptables.ReturnAction{},
					Comment: []string{"Host endpoint policy accepted packet."},
				},
			}...)
			Expect(rr.StaticManglePostroutingChain(ipVersion)).To(Equal(&generictables.Chain{
				Name:  "cali-POSTROUTING",
				Rules: expRules,
			}))
		})
	}

	for _, trueOrFalse := range []bool{true, false} {
		var denyAction generictables.Action
		denyAction = iptables.DropAction{}
		denyActionString := "DROP"
		if trueOrFalse {
			denyAction = iptables.RejectAction{}
			denyActionString = "REJECT"
		}

		kubeIPVSEnabled := trueOrFalse
		Describe(fmt.Sprintf("with default config and IPVS=%v", kubeIPVSEnabled), func() {
			BeforeEach(func() {
				conf = Config{
					WorkloadIfacePrefixes: []string{"cali"},
					IPSetConfigV4:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
					IPSetConfigV6:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
					FailsafeInboundHostPorts: []config.ProtoPort{
						{Net: "0.0.0.0/0", Protocol: "tcp", Port: 22},
						{Net: "10.0.0.0/24", Protocol: "tcp", Port: 1022},
						{Net: "::/0", Protocol: "tcp", Port: 1022},
					},
					FailsafeOutboundHostPorts: []config.ProtoPort{
						{Net: "0.0.0.0/0", Protocol: "tcp", Port: 23},
						{Net: "0.0.0.0/0", Protocol: "tcp", Port: 1023},
					},
					MarkAccept:             0x10,
					MarkPass:               0x20,
					MarkScratch0:           0x40,
					MarkScratch1:           0x80,
					MarkDrop:               0x200,
					MarkEndpoint:           0xff000,
					MarkNonCaliEndpoint:    0x1000,
					KubeIPVSSupportEnabled: kubeIPVSEnabled,
					KubeNodePortRanges:     []numorstring.Port{{MinPort: 30030, MaxPort: 30040, PortName: ""}},
					FilterDenyAction:       denyActionString,
				}
			})

			Context("with OpenStack special cases", func() {
				BeforeEach(func() {
					conf.OpenStackSpecialCasesEnabled = true
				})

				It("IPv4: Should return expected raw PREROUTING chain", func() {
					Expect(findChain(rr.StaticRawTableChains(4), "cali-PREROUTING")).To(Equal(&generictables.Chain{
						Name: "cali-PREROUTING",
						Rules: []generictables.Rule{
							{Action: iptables.ClearMarkAction{Mark: 0xf0}},
							{
								Match:  iptables.Match().InInterface("cali+"),
								Action: iptables.SetMarkAction{Mark: 0x40},
							},
							{
								Match:  iptables.Match().MarkMatchesWithMask(0x40, 0x40),
								Action: iptables.JumpAction{Target: ChainRpfSkip},
							},
							{
								Match:  iptables.Match().Protocol("udp").SourceNet("0.0.0.0").SourcePorts(68).DestPorts(67),
								Action: iptables.AcceptAction{},
							},
							{
								Match:  iptables.Match().MarkSingleBitSet(0x40).RPFCheckFailed(),
								Action: denyAction,
							},
							{
								Match:  iptables.Match().MarkClear(0x40),
								Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint},
							},
							{
								Match:  iptables.Match().MarkSingleBitSet(0x10),
								Action: iptables.AcceptAction{},
							},
						},
					}))
				})

				It("IPv6: Should return expected raw PREROUTING chain", func() {
					Expect(findChain(rr.StaticRawTableChains(6), "cali-PREROUTING")).To(Equal(&generictables.Chain{
						Name: "cali-PREROUTING",
						Rules: []generictables.Rule{
							{Action: iptables.ClearMarkAction{Mark: 0xf0}},
							{
								Match:  iptables.Match().InInterface("cali+"),
								Action: iptables.SetMarkAction{Mark: 0x40},
							},
							{
								Match:  iptables.Match().MarkMatchesWithMask(0x40, 0x40),
								Action: iptables.JumpAction{Target: ChainRpfSkip},
							},
							{
								Match:  iptables.Match().MarkSingleBitSet(0x40).RPFCheckFailed(),
								Action: denyAction,
							},
							{
								Match:  iptables.Match().MarkClear(0x40),
								Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint},
							},
							{
								Match:  iptables.Match().MarkSingleBitSet(0x10),
								Action: iptables.AcceptAction{},
							},
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

					expRawFailsafeIn := &generictables.Chain{
						Name: "cali-failsafe-in",
						Rules: []generictables.Rule{
							{Match: iptables.Match().Protocol("tcp").DestPorts(1022).SourceNet("::/0"), Action: iptables.AcceptAction{}},
						},
					}

					expRawFailsafeOut := &generictables.Chain{
						Name: "cali-failsafe-out",
						Rules: []generictables.Rule{
							{Match: iptables.Match().Protocol("tcp").SourcePorts(1022).DestNet("::/0"), Action: iptables.AcceptAction{}},
						},
					}

					expFailsafeIn := &generictables.Chain{
						Name: "cali-failsafe-in",
						Rules: []generictables.Rule{
							{Match: iptables.Match().Protocol("tcp").DestPorts(1022).SourceNet("::/0"), Action: iptables.AcceptAction{}},
						},
					}

					expFailsafeOut := &generictables.Chain{
						Name:  "cali-failsafe-out",
						Rules: []generictables.Rule{},
					}

					if ipVersion == 4 {
						expRawFailsafeIn = &generictables.Chain{
							Name: "cali-failsafe-in",
							Rules: []generictables.Rule{
								{Match: iptables.Match().Protocol("tcp").DestPorts(22).SourceNet("0.0.0.0/0"), Action: iptables.AcceptAction{}},
								{Match: iptables.Match().Protocol("tcp").DestPorts(1022).SourceNet("10.0.0.0/24"), Action: iptables.AcceptAction{}},
								{Match: iptables.Match().Protocol("tcp").SourcePorts(23).SourceNet("0.0.0.0/0"), Action: iptables.AcceptAction{}},
								{Match: iptables.Match().Protocol("tcp").SourcePorts(1023).SourceNet("0.0.0.0/0"), Action: iptables.AcceptAction{}},
							},
						}

						expRawFailsafeOut = &generictables.Chain{
							Name: "cali-failsafe-out",
							Rules: []generictables.Rule{
								{Match: iptables.Match().Protocol("tcp").DestPorts(23).DestNet("0.0.0.0/0"), Action: iptables.AcceptAction{}},
								{Match: iptables.Match().Protocol("tcp").DestPorts(1023).DestNet("0.0.0.0/0"), Action: iptables.AcceptAction{}},
								{Match: iptables.Match().Protocol("tcp").SourcePorts(22).DestNet("0.0.0.0/0"), Action: iptables.AcceptAction{}},
								{Match: iptables.Match().Protocol("tcp").SourcePorts(1022).DestNet("10.0.0.0/24"), Action: iptables.AcceptAction{}},
							},
						}

						expFailsafeIn = &generictables.Chain{
							Name: "cali-failsafe-in",
							Rules: []generictables.Rule{
								{Match: iptables.Match().Protocol("tcp").DestPorts(22).SourceNet("0.0.0.0/0"), Action: iptables.AcceptAction{}},
								{Match: iptables.Match().Protocol("tcp").DestPorts(1022).SourceNet("10.0.0.0/24"), Action: iptables.AcceptAction{}},
							},
						}

						expFailsafeOut = &generictables.Chain{
							Name: "cali-failsafe-out",
							Rules: []generictables.Rule{
								{Match: iptables.Match().Protocol("tcp").DestPorts(23).DestNet("0.0.0.0/0"), Action: iptables.AcceptAction{}},
								{Match: iptables.Match().Protocol("tcp").DestPorts(1023).DestNet("0.0.0.0/0"), Action: iptables.AcceptAction{}},
							},
						}
					}

					expForwardCheck := &generictables.Chain{
						Name: "cali-forward-check",
						Rules: []generictables.Rule{
							{
								Match:  iptables.Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: iptables.ReturnAction{},
							},
							{
								Match: iptables.Match().Protocol("tcp").
									DestPortRanges(portRanges).
									DestIPSet(ipSetThisHost),
								Action:  iptables.GotoAction{Target: ChainDispatchSetEndPointMark},
								Comment: []string{"To kubernetes NodePort service"},
							},
							{
								Match: iptables.Match().Protocol("udp").
									DestPortRanges(portRanges).
									DestIPSet(ipSetThisHost),
								Action:  iptables.GotoAction{Target: ChainDispatchSetEndPointMark},
								Comment: []string{"To kubernetes NodePort service"},
							},
							{
								Match:   iptables.Match().NotDestIPSet(ipSetThisHost),
								Action:  iptables.JumpAction{Target: ChainDispatchSetEndPointMark},
								Comment: []string{"To kubernetes service"},
							},
						},
					}

					expForwardEndpointMark := &generictables.Chain{
						Name: "cali-forward-endpoint-mark",
						Rules: []generictables.Rule{
							{
								Match:  iptables.Match().NotMarkMatchesWithMask(0x1000, 0xff000),
								Action: iptables.JumpAction{Target: ChainDispatchFromEndPointMark},
							},
							{
								Match:  iptables.Match().OutInterface("cali+"),
								Action: iptables.JumpAction{Target: ChainToWorkloadDispatch},
							},
							{
								Action: iptables.JumpAction{Target: ChainDispatchToHostEndpointForward},
							},
							{
								Action: iptables.ClearMarkAction{Mark: 0xff000},
							},
							{
								Match:   iptables.Match().MarkSingleBitSet(0x10),
								Action:  iptables.AcceptAction{},
								Comment: []string{"Policy explicitly accepted packet."},
							},
						},
					}

					checkManglePostrouting(ipVersion, kubeIPVSEnabled)

					It("should include the expected forward chain in the filter chains", func() {
						Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-FORWARD")).To(Equal(&generictables.Chain{
							Name: "cali-FORWARD",
							Rules: []generictables.Rule{
								// Incoming host endpoint chains.
								{Action: iptables.ClearMarkAction{Mark: 0xe0}},
								{
									Match:  iptables.Match().MarkClear(0x10),
									Action: iptables.JumpAction{Target: ChainDispatchFromHostEndPointForward},
								},
								// Per-prefix workload jump rules.
								{
									Match:  iptables.Match().InInterface("cali+"),
									Action: iptables.JumpAction{Target: ChainFromWorkloadDispatch},
								},
								{
									Match:  iptables.Match().OutInterface("cali+"),
									Action: iptables.JumpAction{Target: ChainToWorkloadDispatch},
								},
								// Outgoing host endpoint chains.
								{Action: iptables.JumpAction{Target: ChainDispatchToHostEndpointForward}},
								{Action: iptables.JumpAction{Target: ChainCIDRBlock}},
							},
						}))
					})
					It("should include the expected input chain in the filter chains", func() {
						if kubeIPVSEnabled {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-INPUT")).To(Equal(&generictables.Chain{
								Name: "cali-INPUT",
								Rules: []generictables.Rule{
									// Forward check chain.
									{Action: iptables.ClearMarkAction{Mark: conf.MarkEndpoint}},
									{Action: iptables.JumpAction{Target: ChainForwardCheck}},
									{
										Match:  iptables.Match().MarkNotClear(conf.MarkEndpoint),
										Action: iptables.ReturnAction{},
									},

									// Per-prefix workload jump rules.  Note use of goto so that we
									// don't return here.
									{
										Match:  iptables.Match().InInterface("cali+"),
										Action: iptables.GotoAction{Target: "cali-wl-to-host"},
									},

									// Untracked packets already matched in raw table.
									{
										Match:  iptables.Match().MarkSingleBitSet(0x10),
										Action: iptables.AcceptAction{},
									},

									// Non-workload traffic, send to host chains.
									{Action: iptables.ClearMarkAction{Mark: 0xf0}},
									{Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint}},
									{
										Match:   iptables.Match().MarkSingleBitSet(0x10),
										Action:  iptables.AcceptAction{},
										Comment: []string{"Host endpoint policy accepted packet."},
									},
								},
							}))
						} else {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-INPUT")).To(Equal(&generictables.Chain{
								Name: "cali-INPUT",
								Rules: []generictables.Rule{
									// Per-prefix workload jump rules.  Note use of goto so that we
									// don't return here.
									{
										Match:  iptables.Match().InInterface("cali+"),
										Action: iptables.GotoAction{Target: "cali-wl-to-host"},
									},

									// Untracked packets already matched in raw table.
									{
										Match:  iptables.Match().MarkSingleBitSet(0x10),
										Action: iptables.AcceptAction{},
									},

									// Non-workload traffic, send to host chains.
									{Action: iptables.ClearMarkAction{Mark: 0xf0}},
									{Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint}},
									{
										Match:   iptables.Match().MarkSingleBitSet(0x10),
										Action:  iptables.AcceptAction{},
										Comment: []string{"Host endpoint policy accepted packet."},
									},
								},
							}))
						}
					})
					It("should include the expected output chain in the filter chains", func() {
						if kubeIPVSEnabled {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&generictables.Chain{
								Name: "cali-OUTPUT",
								Rules: []generictables.Rule{
									// Untracked packets already matched in raw table.
									{
										Match:  iptables.Match().MarkSingleBitSet(0x10),
										Action: iptables.AcceptAction{},
									},

									// From endpoint mark chain
									{
										Match:  iptables.Match().MarkNotClear(conf.MarkEndpoint),
										Action: iptables.GotoAction{Target: ChainForwardEndpointMark},
									},

									// To workload traffic.
									{Match: iptables.Match().OutInterface("cali+"), Action: iptables.ReturnAction{}},

									// Non-workload traffic, send to host chains.
									{Action: iptables.ClearMarkAction{Mark: 0xf0}},
									{
										Match:  iptables.Match().NotConntrackState("DNAT"),
										Action: iptables.JumpAction{Target: ChainDispatchToHostEndpoint},
									},
									{
										Match:   iptables.Match().MarkSingleBitSet(0x10),
										Action:  iptables.AcceptAction{},
										Comment: []string{"Host endpoint policy accepted packet."},
									},
								},
							}))
						} else {
							Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&generictables.Chain{
								Name: "cali-OUTPUT",
								Rules: []generictables.Rule{
									// Untracked packets already matched in raw table.
									{
										Match:  iptables.Match().MarkSingleBitSet(0x10),
										Action: iptables.AcceptAction{},
									},

									// To workload traffic.
									{Match: iptables.Match().OutInterface("cali+"), Action: iptables.ReturnAction{}},

									// Non-workload traffic, send to host chains.
									{Action: iptables.ClearMarkAction{Mark: 0xf0}},
									{
										Match:  iptables.Match().NotConntrackState("DNAT"),
										Action: iptables.JumpAction{Target: ChainDispatchToHostEndpoint},
									},
									{
										Match:   iptables.Match().MarkSingleBitSet(0x10),
										Action:  iptables.AcceptAction{},
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
						Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&generictables.Chain{
							Name: "cali-OUTPUT",
							Rules: []generictables.Rule{
								// For safety, clear all our mark bits before we start.  (We could be in
								// append mode and another process' rules could have left the mark bit set.)
								{Action: iptables.ClearMarkAction{Mark: 0xf0}},
								// Then, jump to the untracked policy chains.
								{Action: iptables.JumpAction{Target: "cali-to-host-endpoint"}},
								// Then, if the packet was marked as allowed, accept it.  Packets also
								// return here without the mark bit set if the interface wasn't one that
								// we're policing.
								{Match: iptables.Match().MarkSingleBitSet(0x10), Action: iptables.AcceptAction{}},
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
				Expect(findChain(rr.StaticRawTableChains(4), "cali-PREROUTING")).To(Equal(&generictables.Chain{
					Name: "cali-PREROUTING",
					Rules: []generictables.Rule{
						{Action: iptables.ClearMarkAction{Mark: 0xf0}},
						{
							Match:  iptables.Match().InInterface("cali+"),
							Action: iptables.SetMarkAction{Mark: 0x40},
						},
						{
							Match:  iptables.Match().MarkMatchesWithMask(0x40, 0x40),
							Action: iptables.JumpAction{Target: ChainRpfSkip},
						},
						{
							Match:  iptables.Match().MarkSingleBitSet(0x40).RPFCheckFailed(),
							Action: denyAction,
						},
						{
							Match:  iptables.Match().MarkClear(0x40),
							Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint},
						},
						{
							Match:  iptables.Match().MarkSingleBitSet(0x10),
							Action: iptables.AcceptAction{},
						},
					},
				}))
			})
			It("IPv6: Should return expected raw PREROUTING chain", func() {
				Expect(findChain(rr.StaticRawTableChains(6), "cali-PREROUTING")).To(Equal(&generictables.Chain{
					Name: "cali-PREROUTING",
					Rules: []generictables.Rule{
						{Action: iptables.ClearMarkAction{Mark: 0xf0}},
						{
							Match:  iptables.Match().InInterface("cali+"),
							Action: iptables.SetMarkAction{Mark: 0x40},
						},
						{
							Match:  iptables.Match().MarkMatchesWithMask(0x40, 0x40),
							Action: iptables.JumpAction{Target: ChainRpfSkip},
						},
						{
							Match:  iptables.Match().MarkSingleBitSet(0x40).RPFCheckFailed(),
							Action: denyAction,
						},
						{
							Match:  iptables.Match().MarkClear(0x40),
							Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint},
						},
						{
							Match:  iptables.Match().MarkSingleBitSet(0x10),
							Action: iptables.AcceptAction{},
						},
					},
				}))
			})

			It("IPv4: Should return expected mangle PREROUTING chain", func() {
				Expect(findChain(rr.StaticMangleTableChains(4), "cali-PREROUTING")).To(Equal(&generictables.Chain{
					Name: "cali-PREROUTING",
					Rules: []generictables.Rule{
						{
							Match:  iptables.Match().ConntrackState("RELATED,ESTABLISHED"),
							Action: iptables.AcceptAction{},
						},
						{
							Match:  iptables.Match().MarkSingleBitSet(0x10),
							Action: iptables.AcceptAction{},
						},
						{Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint}},
						{
							Match:   iptables.Match().MarkSingleBitSet(0x10),
							Action:  iptables.AcceptAction{},
							Comment: []string{"Host endpoint policy accepted packet."},
						},
					},
				}))
			})
			It("IPv6: Should return expected mangle PREROUTING chain", func() {
				Expect(findChain(rr.StaticMangleTableChains(6), "cali-PREROUTING")).To(Equal(&generictables.Chain{
					Name: "cali-PREROUTING",
					Rules: []generictables.Rule{
						{
							Match:  iptables.Match().ConntrackState("RELATED,ESTABLISHED"),
							Action: iptables.AcceptAction{},
						},
						{
							Match:  iptables.Match().MarkSingleBitSet(0x10),
							Action: iptables.AcceptAction{},
						},
						{Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint}},
						{
							Match:   iptables.Match().MarkSingleBitSet(0x10),
							Action:  iptables.AcceptAction{},
							Comment: []string{"Host endpoint policy accepted packet."},
						},
					},
				}))
			})

			It("IPv4: should include the expected workload-to-host chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(4), "cali-wl-to-host")).To(Equal(&generictables.Chain{
					Name: "cali-wl-to-host",
					Rules: []generictables.Rule{
						{Action: iptables.JumpAction{Target: "cali-from-wl-dispatch"}},
						{
							Action:  iptables.ReturnAction{},
							Comment: []string{"Configured DefaultEndpointToHostAction"},
						},
					},
				}))
			})
			It("IPv6: should include the expected workload-to-host chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(6), "cali-wl-to-host")).To(Equal(&generictables.Chain{
					Name: "cali-wl-to-host",
					Rules: []generictables.Rule{
						{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(130), Action: iptables.AcceptAction{}},
						{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(131), Action: iptables.AcceptAction{}},
						{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(132), Action: iptables.AcceptAction{}},
						{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(133), Action: iptables.AcceptAction{}},
						{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(135), Action: iptables.AcceptAction{}},
						{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(136), Action: iptables.AcceptAction{}},
						{Action: iptables.JumpAction{Target: "cali-from-wl-dispatch"}},
						{
							Action:  iptables.ReturnAction{},
							Comment: []string{"Configured DefaultEndpointToHostAction"},
						},
					},
				}))
			})

			It("IPv4: Should return expected NAT prerouting chain", func() {
				Expect(findChain(rr.StaticNATTableChains(4), "cali-PREROUTING")).To(Equal(&generictables.Chain{
					Name: "cali-PREROUTING",
					Rules: []generictables.Rule{
						{Action: iptables.JumpAction{Target: "cali-fip-dnat"}},
					},
				}))
			})
			It("IPv4: Should return expected NAT postrouting chain", func() {
				Expect(findChain(rr.StaticNATTableChains(4), "cali-POSTROUTING")).To(Equal(&generictables.Chain{
					Name: "cali-POSTROUTING",
					Rules: []generictables.Rule{
						{Action: iptables.JumpAction{Target: "cali-fip-snat"}},
						{Action: iptables.JumpAction{Target: "cali-nat-outgoing"}},
					},
				}))
			})
			It("IPv4: Should return expected NAT output chain", func() {
				Expect(findChain(rr.StaticNATTableChains(4), "cali-OUTPUT")).To(Equal(&generictables.Chain{
					Name: "cali-OUTPUT",
					Rules: []generictables.Rule{
						{Action: iptables.JumpAction{Target: "cali-fip-dnat"}},
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
			epMark := uint32(0xff000)
			BeforeEach(func() {
				conf = Config{
					WorkloadIfacePrefixes:  []string{"cali"},
					IPIPEnabled:            true,
					IPIPTunnelAddress:      net.ParseIP("10.0.0.1"),
					IPSetConfigV4:          ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
					IPSetConfigV6:          ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
					MarkAccept:             0x10,
					MarkPass:               0x20,
					MarkScratch0:           0x40,
					MarkScratch1:           0x80,
					MarkDrop:               0x200,
					MarkEndpoint:           epMark,
					MarkNonCaliEndpoint:    0x1000,
					KubeIPVSSupportEnabled: kubeIPVSEnabled,
					FilterDenyAction:       denyActionString,
				}
			})

			checkManglePostrouting(4, kubeIPVSEnabled)

			expInputChainIPIPV4IPVS := &generictables.Chain{
				Name: "cali-INPUT",
				Rules: []generictables.Rule{
					// IPIP rules
					{
						Match: iptables.Match().
							ProtocolNum(4).
							SourceIPSet("cali40all-hosts-net").
							DestAddrType("LOCAL"),

						Action:  iptables.AcceptAction{},
						Comment: []string{"Allow IPIP packets from Calico hosts"},
					},
					{
						Match:   iptables.Match().ProtocolNum(4),
						Action:  iptables.RejectAction{},
						Comment: []string{"Reject IPIP packets from non-Calico hosts"},
					},

					// Forward check chain.
					{Action: iptables.ClearMarkAction{Mark: epMark}},
					{Action: iptables.JumpAction{Target: ChainForwardCheck}},
					{
						Match:  iptables.Match().MarkNotClear(epMark),
						Action: iptables.ReturnAction{},
					},

					// Per-prefix workload jump rules.  Note use of goto so that we
					// don't return here.
					{
						Match:  iptables.Match().InInterface("cali+"),
						Action: iptables.GotoAction{Target: "cali-wl-to-host"},
					},

					// Untracked packets already matched in raw table.
					{
						Match:  iptables.Match().MarkSingleBitSet(0x10),
						Action: iptables.AcceptAction{},
					},

					// Not from a workload, apply host policy.
					{Action: iptables.ClearMarkAction{Mark: 0xf0}},
					{Action: iptables.JumpAction{Target: "cali-from-host-endpoint"}},
					{
						Match:   iptables.Match().MarkSingleBitSet(0x10),
						Action:  iptables.AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			expInputChainIPIPV4NoIPVS := &generictables.Chain{
				Name: "cali-INPUT",
				Rules: []generictables.Rule{
					// IPIP rules
					{
						Match: iptables.Match().
							ProtocolNum(4).
							SourceIPSet("cali40all-hosts-net").
							DestAddrType("LOCAL"),

						Action:  iptables.AcceptAction{},
						Comment: []string{"Allow IPIP packets from Calico hosts"},
					},
					{
						Match:   iptables.Match().ProtocolNum(4),
						Action:  iptables.DropAction{},
						Comment: []string{"Drop IPIP packets from non-Calico hosts"},
					},

					// Per-prefix workload jump rules.  Note use of goto so that we
					// don't return here.
					{
						Match:  iptables.Match().InInterface("cali+"),
						Action: iptables.GotoAction{Target: "cali-wl-to-host"},
					},

					// Untracked packets already matched in raw table.
					{
						Match:  iptables.Match().MarkSingleBitSet(0x10),
						Action: iptables.AcceptAction{},
					},

					// Not from a workload, apply host policy.
					{Action: iptables.ClearMarkAction{Mark: 0xf0}},
					{Action: iptables.JumpAction{Target: "cali-from-host-endpoint"}},
					{
						Match:   iptables.Match().MarkSingleBitSet(0x10),
						Action:  iptables.AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			// V6 should be unaffected.
			expInputChainIPIPV6IPVS := &generictables.Chain{
				Name: "cali-INPUT",
				Rules: []generictables.Rule{
					// Forward check chain.
					{Action: iptables.ClearMarkAction{Mark: epMark}},
					{Action: iptables.JumpAction{Target: ChainForwardCheck}},
					{
						Match:  iptables.Match().MarkNotClear(epMark),
						Action: iptables.ReturnAction{},
					},

					// Per-prefix workload jump rules.  Note use of goto so that we
					// don't return here.
					{
						Match:  iptables.Match().InInterface("cali+"),
						Action: iptables.GotoAction{Target: "cali-wl-to-host"},
					},

					// Untracked packets already matched in raw table.
					{
						Match:  iptables.Match().MarkSingleBitSet(0x10),
						Action: iptables.AcceptAction{},
					},

					// Not from a workload, apply host policy.
					{Action: iptables.ClearMarkAction{Mark: 0xf0}},
					{Action: iptables.JumpAction{Target: "cali-from-host-endpoint"}},
					{
						Match:   iptables.Match().MarkSingleBitSet(0x10),
						Action:  iptables.AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}
			expInputChainIPIPV6NoIPVS := &generictables.Chain{
				Name: "cali-INPUT",
				Rules: []generictables.Rule{
					// Per-prefix workload jump rules.  Note use of goto so that we
					// don't return here.
					{
						Match:  iptables.Match().InInterface("cali+"),
						Action: iptables.GotoAction{Target: "cali-wl-to-host"},
					},

					// Untracked packets already matched in raw table.
					{
						Match:  iptables.Match().MarkSingleBitSet(0x10),
						Action: iptables.AcceptAction{},
					},

					// Not from a workload, apply host policy.
					{Action: iptables.ClearMarkAction{Mark: 0xf0}},
					{Action: iptables.JumpAction{Target: "cali-from-host-endpoint"}},
					{
						Match:   iptables.Match().MarkSingleBitSet(0x10),
						Action:  iptables.AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			expOutputChainIPIPV4IPVS := &generictables.Chain{
				Name: "cali-OUTPUT",
				Rules: []generictables.Rule{
					// Untracked packets already matched in raw table.
					{
						Match:  iptables.Match().MarkSingleBitSet(0x10),
						Action: iptables.AcceptAction{},
					},

					// From endpoint mark chain
					{
						Match:  iptables.Match().MarkNotClear(epMark),
						Action: iptables.GotoAction{Target: ChainForwardEndpointMark},
					},

					// To workload traffic.
					{Match: iptables.Match().OutInterface("cali+"), Action: iptables.ReturnAction{}},

					// Auto-allow IPIP traffic to other Calico hosts.
					{
						Match: iptables.Match().ProtocolNum(4).
							DestIPSet("cali40all-hosts-net").
							SrcAddrType(generictables.AddrTypeLocal, false),
						Action:  iptables.AcceptAction{},
						Comment: []string{"Allow IPIP packets to other Calico hosts"},
					},

					// Non-workload traffic, send to host chains.
					{Action: iptables.ClearMarkAction{Mark: 0xf0}},
					{
						Match:  iptables.Match().NotConntrackState("DNAT"),
						Action: iptables.JumpAction{Target: ChainDispatchToHostEndpoint},
					},
					{
						Match:   iptables.Match().MarkSingleBitSet(0x10),
						Action:  iptables.AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			expOutputChainIPIPV4NoIPVS := &generictables.Chain{
				Name: "cali-OUTPUT",
				Rules: []generictables.Rule{
					// Untracked packets already matched in raw table.
					{
						Match:  iptables.Match().MarkSingleBitSet(0x10),
						Action: iptables.AcceptAction{},
					},

					// To workload traffic.
					{Match: iptables.Match().OutInterface("cali+"), Action: iptables.ReturnAction{}},

					// Auto-allow IPIP traffic to other Calico hosts.
					{
						Match: iptables.Match().ProtocolNum(4).
							DestIPSet("cali40all-hosts-net").
							SrcAddrType(generictables.AddrTypeLocal, false),
						Action:  iptables.AcceptAction{},
						Comment: []string{"Allow IPIP packets to other Calico hosts"},
					},

					// Non-workload traffic, send to host chains.
					{Action: iptables.ClearMarkAction{Mark: 0xf0}},
					{
						Match:  iptables.Match().NotConntrackState("DNAT"),
						Action: iptables.JumpAction{Target: ChainDispatchToHostEndpoint},
					},
					{
						Match:   iptables.Match().MarkSingleBitSet(0x10),
						Action:  iptables.AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			// V6 should be unaffected.
			expOutputChainIPIPV6IPVS := &generictables.Chain{
				Name: "cali-OUTPUT",
				Rules: []generictables.Rule{
					// Untracked packets already matched in raw table.
					{
						Match:  iptables.Match().MarkSingleBitSet(0x10),
						Action: iptables.AcceptAction{},
					},

					// From endpoint mark chain
					{
						Match:  iptables.Match().MarkNotClear(epMark),
						Action: iptables.GotoAction{Target: ChainForwardEndpointMark},
					},

					// To workload traffic.
					{Match: iptables.Match().OutInterface("cali+"), Action: iptables.ReturnAction{}},

					// Non-workload traffic, send to host chains.
					{Action: iptables.ClearMarkAction{Mark: 0xf0}},
					{
						Match:  iptables.Match().NotConntrackState("DNAT"),
						Action: iptables.JumpAction{Target: ChainDispatchToHostEndpoint},
					},
					{
						Match:   iptables.Match().MarkSingleBitSet(0x10),
						Action:  iptables.AcceptAction{},
						Comment: []string{"Host endpoint policy accepted packet."},
					},
				},
			}

			expOutputChainIPIPV6NoIPVS := &generictables.Chain{
				Name: "cali-OUTPUT",
				Rules: []generictables.Rule{
					// Untracked packets already matched in raw table.
					{
						Match:  iptables.Match().MarkSingleBitSet(0x10),
						Action: iptables.AcceptAction{},
					},

					// To workload traffic.
					{Match: iptables.Match().OutInterface("cali+"), Action: iptables.ReturnAction{}},

					// Non-workload traffic, send to host chains.
					{Action: iptables.ClearMarkAction{Mark: 0xf0}},
					{
						Match:  iptables.Match().NotConntrackState("DNAT"),
						Action: iptables.JumpAction{Target: ChainDispatchToHostEndpoint},
					},
					{
						Match:   iptables.Match().MarkSingleBitSet(0x10),
						Action:  iptables.AcceptAction{},
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
				Expect(rr.StaticNATPostroutingChains(4)).To(Equal([]*generictables.Chain{
					{
						Name: "cali-POSTROUTING",
						Rules: []generictables.Rule{
							{Action: iptables.JumpAction{Target: "cali-fip-snat"}},
							{Action: iptables.JumpAction{Target: "cali-nat-outgoing"}},
							{
								Match: iptables.Match().
									OutInterface(dataplanedefs.IPIPIfaceName).
									NotSrcAddrType(generictables.AddrTypeLocal, true).
									SrcAddrType(generictables.AddrTypeLocal, false),
								Action: iptables.MasqAction{},
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
					Expect(rr.StaticNATPostroutingChains(4)).To(Equal([]*generictables.Chain{
						{
							Name: "cali-POSTROUTING",
							Rules: []generictables.Rule{
								{Action: iptables.JumpAction{Target: "cali-fip-snat"}},
								{Action: iptables.JumpAction{Target: "cali-nat-outgoing"}},
								{
									Match: iptables.Match().
										OutInterface(dataplanedefs.IPIPIfaceName).
										NotSrcAddrType(generictables.AddrTypeLocal, true).
										SrcAddrType(generictables.AddrTypeLocal, false),
									Action: iptables.MasqAction{},
								},
							},
						},
					}))
				})

				It("IPv4: Should return expected VXLAN notrack PREROUTING chain", func() {
					allCalicoMarkBits := rr.MarkAccept |
						rr.MarkPass |
						rr.MarkScratch0 |
						rr.MarkScratch1
					markFromWorkload := rr.MarkScratch0

					chain := &generictables.Chain{
						Name: "cali-PREROUTING",
						Rules: []generictables.Rule{
							{Action: iptables.ClearMarkAction{Mark: allCalicoMarkBits}},
							{
								Match:  iptables.Match().Protocol("udp").DestPort(uint16(rr.VXLANPort)),
								Action: iptables.NoTrackAction{},
							},
						},
					}

					for _, ifacePrefix := range rr.WorkloadIfacePrefixes {
						chain.Rules = append(chain.Rules, generictables.Rule{
							Match:  iptables.Match().InInterface(ifacePrefix + iptables.Wildcard),
							Action: iptables.SetMarkAction{Mark: markFromWorkload},
						})
					}

					chain.Rules = append(chain.Rules, generictables.Rule{
						Match:  iptables.Match().MarkMatchesWithMask(markFromWorkload, markFromWorkload),
						Action: iptables.JumpAction{Target: ChainRpfSkip},
					})

					chain.Rules = append(chain.Rules, rr.RPFilter(4, markFromWorkload, markFromWorkload, rr.OpenStackSpecialCasesEnabled, rr.IptablesFilterDenyAction())...)
					chain.Rules = append(chain.Rules, generictables.Rule{
						Match:  iptables.Match().MarkClear(markFromWorkload),
						Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint},
					}, generictables.Rule{
						Match:  iptables.Match().MarkSingleBitSet(rr.MarkAccept),
						Action: iptables.AcceptAction{},
					})

					Expect(rr.StaticRawPreroutingChain(4)).To(Equal(chain))
				})

				It("IPv4: Should return expected VXLAN notrack OUTPUT chain", func() {
					allCalicoMarkBits := rr.MarkAccept |
						rr.MarkPass |
						rr.MarkScratch0 |
						rr.MarkScratch1
					Expect(rr.StaticRawOutputChain(0, 4)).To(Equal(&generictables.Chain{
						Name: "cali-OUTPUT",
						Rules: []generictables.Rule{
							{Action: iptables.ClearMarkAction{Mark: allCalicoMarkBits}},
							{Action: iptables.JumpAction{Target: ChainDispatchToHostEndpoint}},
							{
								Match:  iptables.Match().Protocol("udp").DestPort(uint16(rr.VXLANPort)),
								Action: iptables.NoTrackAction{},
							},
							{
								Match:  iptables.Match().MarkSingleBitSet(rr.MarkAccept),
								Action: iptables.AcceptAction{},
							},
						},
					},
					))
				})

				Describe("and IPv4 tunnel IP", func() {
					BeforeEach(func() {
						conf.VXLANTunnelAddress = net.IP{10, 0, 0, 1}
					})

					It("IPv4: Should return expected NAT postrouting chain", func() {
						Expect(rr.StaticNATPostroutingChains(4)).To(Equal([]*generictables.Chain{
							{
								Name: "cali-POSTROUTING",
								Rules: []generictables.Rule{
									{Action: iptables.JumpAction{Target: "cali-fip-snat"}},
									{Action: iptables.JumpAction{Target: "cali-nat-outgoing"}},
									{
										Match: iptables.Match().
											OutInterface(dataplanedefs.IPIPIfaceName).
											NotSrcAddrType(generictables.AddrTypeLocal, true).
											SrcAddrType(generictables.AddrTypeLocal, false),
										Action: iptables.MasqAction{},
									},
									{
										Match: iptables.Match().
											OutInterface(dataplanedefs.VXLANIfaceNameV4).
											NotSrcAddrType(generictables.AddrTypeLocal, true).
											SrcAddrType(generictables.AddrTypeLocal, false),
										Action: iptables.MasqAction{},
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
					Expect(rr.StaticNATPostroutingChains(6)).To(Equal([]*generictables.Chain{
						{
							Name: "cali-POSTROUTING",
							Rules: []generictables.Rule{
								{Action: iptables.JumpAction{Target: "cali-fip-snat"}},
								{Action: iptables.JumpAction{Target: "cali-nat-outgoing"}},
							},
						},
					}))
				})

				It("IPv6: Should return expected VXLAN notrack PREROUTING chain", func() {
					allCalicoMarkBits := rr.MarkAccept |
						rr.MarkPass |
						rr.MarkScratch0 |
						rr.MarkScratch1
					markFromWorkload := rr.MarkScratch0

					chain := &generictables.Chain{
						Name: "cali-PREROUTING",
						Rules: []generictables.Rule{
							{Action: iptables.ClearMarkAction{Mark: allCalicoMarkBits}},
							{
								Match:  iptables.Match().Protocol("udp").DestPort(uint16(rr.VXLANPort)),
								Action: iptables.NoTrackAction{},
							},
						},
					}

					for _, ifacePrefix := range rr.WorkloadIfacePrefixes {
						chain.Rules = append(chain.Rules, generictables.Rule{
							Match:  iptables.Match().InInterface(ifacePrefix + iptables.Wildcard),
							Action: iptables.SetMarkAction{Mark: markFromWorkload},
						})
					}

					chain.Rules = append(chain.Rules, generictables.Rule{
						Match:  iptables.Match().MarkMatchesWithMask(markFromWorkload, markFromWorkload),
						Action: iptables.JumpAction{Target: ChainRpfSkip},
					})

					chain.Rules = append(chain.Rules, rr.RPFilter(6, markFromWorkload, markFromWorkload, rr.OpenStackSpecialCasesEnabled, rr.IptablesFilterDenyAction())...)
					chain.Rules = append(chain.Rules, generictables.Rule{
						Match:  iptables.Match().MarkClear(markFromWorkload),
						Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint},
					}, generictables.Rule{
						Match:  iptables.Match().MarkSingleBitSet(rr.MarkAccept),
						Action: iptables.AcceptAction{},
					})

					Expect(rr.StaticRawPreroutingChain(6)).To(Equal(chain))
				})

				Describe("and IPv6 tunnel IP", func() {
					BeforeEach(func() {
						conf.VXLANTunnelAddressV6 = net.ParseIP("dead:beef::1")
					})

					It("IPv6: Should return expected NAT postrouting chain", func() {
						Expect(rr.StaticNATPostroutingChains(6)).To(Equal([]*generictables.Chain{
							{
								Name: "cali-POSTROUTING",
								Rules: []generictables.Rule{
									{Action: iptables.JumpAction{Target: "cali-fip-snat"}},
									{Action: iptables.JumpAction{Target: "cali-nat-outgoing"}},
									{
										Match: iptables.Match().
											OutInterface(dataplanedefs.VXLANIfaceNameV6).
											NotSrcAddrType(generictables.AddrTypeLocal, true).
											SrcAddrType(generictables.AddrTypeLocal, false),
										Action: iptables.MasqAction{},
									},
								},
							},
						}))
					})
				})
			})

			It("IPv6: Should return expected NAT postrouting chain", func() {
				Expect(rr.StaticNATPostroutingChains(6)).To(Equal([]*generictables.Chain{
					{
						Name: "cali-POSTROUTING",
						Rules: []generictables.Rule{
							{Action: iptables.JumpAction{Target: "cali-fip-snat"}},
							{Action: iptables.JumpAction{Target: "cali-nat-outgoing"}},
						},
					},
				}))
			})
		})
	}

	Describe("with multiple KubePortRanges", func() {
		BeforeEach(func() {
			conf = Config{
				WorkloadIfacePrefixes:  []string{"cali"},
				IPSetConfigV4:          ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
				IPSetConfigV6:          ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
				MarkAccept:             0x10,
				MarkPass:               0x20,
				MarkScratch0:           0x40,
				MarkScratch1:           0x80,
				MarkDrop:               0x200,
				MarkEndpoint:           0xff000,
				MarkNonCaliEndpoint:    0x1000,
				KubeIPVSSupportEnabled: true,
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

			expForwardCheck := &generictables.Chain{
				Name: "cali-forward-check",
				Rules: []generictables.Rule{
					{
						Match:  iptables.Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: iptables.ReturnAction{},
					},
					{
						Match: iptables.Match().Protocol("tcp").
							DestPortRanges(portRanges1).
							DestIPSet(ipSetThisHost),
						Action:  iptables.GotoAction{Target: ChainDispatchSetEndPointMark},
						Comment: []string{"To kubernetes NodePort service"},
					},
					{
						Match: iptables.Match().Protocol("udp").
							DestPortRanges(portRanges1).
							DestIPSet(ipSetThisHost),
						Action:  iptables.GotoAction{Target: ChainDispatchSetEndPointMark},
						Comment: []string{"To kubernetes NodePort service"},
					},
					{
						Match: iptables.Match().Protocol("tcp").
							DestPortRanges(portRanges2).
							DestIPSet(ipSetThisHost),
						Action:  iptables.GotoAction{Target: ChainDispatchSetEndPointMark},
						Comment: []string{"To kubernetes NodePort service"},
					},
					{
						Match: iptables.Match().Protocol("udp").
							DestPortRanges(portRanges2).
							DestIPSet(ipSetThisHost),
						Action:  iptables.GotoAction{Target: ChainDispatchSetEndPointMark},
						Comment: []string{"To kubernetes NodePort service"},
					},
					{
						Match:   iptables.Match().NotDestIPSet(ipSetThisHost),
						Action:  iptables.JumpAction{Target: ChainDispatchSetEndPointMark},
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
				MarkAccept:                   0x10,
				MarkPass:                     0x20,
				MarkScratch0:                 0x40,
				MarkScratch1:                 0x80,
				MarkDrop:                     0x200,
				MarkEndpoint:                 0xff000,
				MarkNonCaliEndpoint:          0x1000,
			}
		})

		expWlToHostV4 := &generictables.Chain{
			Name: "cali-wl-to-host",
			Rules: []generictables.Rule{
				// OpenStack special cases.
				{
					Match: iptables.Match().
						Protocol("tcp").
						DestNet("10.0.0.1").
						DestPorts(1234),
					Action: iptables.AcceptAction{},
				},
				{
					Match:  iptables.Match().Protocol("udp").SourcePorts(68).DestPorts(67),
					Action: iptables.AcceptAction{},
				},
				{
					Match:  iptables.Match().Protocol("udp").DestPorts(53),
					Action: iptables.AcceptAction{},
				},

				{Action: iptables.JumpAction{Target: "cali-from-wl-dispatch"}},
				{
					Action:  iptables.ReturnAction{},
					Comment: []string{"Configured DefaultEndpointToHostAction"},
				},
			},
		}

		expWlToHostV6 := &generictables.Chain{
			Name: "cali-wl-to-host",
			Rules: []generictables.Rule{
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(130), Action: iptables.AcceptAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(131), Action: iptables.AcceptAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(132), Action: iptables.AcceptAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(133), Action: iptables.AcceptAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(135), Action: iptables.AcceptAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(136), Action: iptables.AcceptAction{}},

				// OpenStack special cases.
				{
					Match:  iptables.Match().Protocol("udp").SourcePorts(546).DestPorts(547),
					Action: iptables.AcceptAction{},
				},
				{
					Match:  iptables.Match().Protocol("udp").DestPorts(53),
					Action: iptables.AcceptAction{},
				},

				{Action: iptables.JumpAction{Target: "cali-from-wl-dispatch"}},
				{
					Action:  iptables.ReturnAction{},
					Comment: []string{"Configured DefaultEndpointToHostAction"},
				},
			},
		}

		It("IPv4: should include the expected workload-to-host chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(4), "cali-wl-to-host")).To(Equal(expWlToHostV4))
		})
		It("IPv6: should include the expected workload-to-host chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(6), "cali-wl-to-host")).To(Equal(expWlToHostV6))
		})

		It("IPv4: Should return expected NAT prerouting chain", func() {
			Expect(rr.StaticNATPreroutingChains(4)).To(Equal([]*generictables.Chain{
				{
					Name: "cali-PREROUTING",
					Rules: []generictables.Rule{
						{
							Action: iptables.JumpAction{Target: "cali-fip-dnat"},
						},
						{
							Match: iptables.Match().
								Protocol("tcp").
								DestPorts(80).
								DestNet("169.254.169.254/32"),
							Action: iptables.DNATAction{
								DestAddr: "10.0.0.1",
								DestPort: 1234,
							},
						},
					},
				},
			}))
		})
		It("IPv6: Should return expected NAT prerouting chain", func() {
			Expect(rr.StaticNATPreroutingChains(6)).To(Equal([]*generictables.Chain{
				{
					Name: "cali-PREROUTING",
					Rules: []generictables.Rule{
						{Action: iptables.JumpAction{Target: "cali-fip-dnat"}},
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
				MarkAccept:                   0x10,
				MarkPass:                     0x20,
				MarkScratch0:                 0x40,
				MarkScratch1:                 0x80,
				MarkDrop:                     0x200,
				MarkEndpoint:                 0xff000,
				MarkNonCaliEndpoint:          0x1000,
				FilterAllowAction:            "RETURN",
			}
		})

		expWlToHostV4 := &generictables.Chain{
			Name: "cali-wl-to-host",
			Rules: []generictables.Rule{
				// OpenStack special cases.
				{
					Match: iptables.Match().
						Protocol("tcp").
						DestNet("10.0.0.1").
						DestPorts(1234),
					Action: iptables.ReturnAction{},
				},
				{
					Match:  iptables.Match().Protocol("udp").SourcePorts(68).DestPorts(67),
					Action: iptables.ReturnAction{},
				},
				{
					Match:  iptables.Match().Protocol("udp").DestPorts(53),
					Action: iptables.ReturnAction{},
				},

				{Action: iptables.JumpAction{Target: "cali-from-wl-dispatch"}},
				{
					Action:  iptables.ReturnAction{},
					Comment: []string{"Configured DefaultEndpointToHostAction"},
				},
			},
		}

		expWlToHostV6 := &generictables.Chain{
			Name: "cali-wl-to-host",
			Rules: []generictables.Rule{
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(130), Action: iptables.ReturnAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(131), Action: iptables.ReturnAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(132), Action: iptables.ReturnAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(133), Action: iptables.ReturnAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(135), Action: iptables.ReturnAction{}},
				{Match: iptables.Match().ProtocolNum(ProtoICMPv6).ICMPV6Type(136), Action: iptables.ReturnAction{}},

				// OpenStack special cases.
				{
					Match:  iptables.Match().Protocol("udp").SourcePorts(546).DestPorts(547),
					Action: iptables.ReturnAction{},
				},
				{
					Match:  iptables.Match().Protocol("udp").DestPorts(53),
					Action: iptables.ReturnAction{},
				},

				{Action: iptables.JumpAction{Target: "cali-from-wl-dispatch"}},
				{
					Action:  iptables.ReturnAction{},
					Comment: []string{"Configured DefaultEndpointToHostAction"},
				},
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
		epMark := uint32(0xff000)
		BeforeEach(func() {
			conf = Config{
				WorkloadIfacePrefixes: []string{"cali"},
				IPSetConfigV4:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
				IPSetConfigV6:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
				MarkAccept:            0x10,
				MarkPass:              0x20,
				MarkScratch0:          0x40,
				MarkScratch1:          0x80,
				MarkDrop:              0x200,
				MarkEndpoint:          epMark,
				MarkNonCaliEndpoint:   0x1000,
				FilterAllowAction:     "RETURN",
				MangleAllowAction:     "RETURN",
			}
		})

		for _, ipVersion := range []uint8{4, 6} {

			It("should include the expected forward chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-FORWARD")).To(Equal(&generictables.Chain{
					Name: "cali-FORWARD",
					Rules: []generictables.Rule{
						// Incoming host endpoint chains.
						{Action: iptables.ClearMarkAction{Mark: 0xe0}},
						{
							Match:  iptables.Match().MarkClear(0x10),
							Action: iptables.JumpAction{Target: ChainDispatchFromHostEndPointForward},
						},
						// Per-prefix workload jump rules.
						{
							Match:  iptables.Match().InInterface("cali+"),
							Action: iptables.JumpAction{Target: ChainFromWorkloadDispatch},
						},
						{
							Match:  iptables.Match().OutInterface("cali+"),
							Action: iptables.JumpAction{Target: ChainToWorkloadDispatch},
						},
						// Outgoing host endpoint chains.
						{Action: iptables.JumpAction{Target: ChainDispatchToHostEndpointForward}},
						{Action: iptables.JumpAction{Target: ChainCIDRBlock}},
					},
				}))
			})
			It("should include the expected input chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-INPUT")).To(Equal(&generictables.Chain{
					Name: "cali-INPUT",
					Rules: []generictables.Rule{
						// Per-prefix workload jump rules.  Note use of goto so that we
						// don't return here.
						{
							Match:  iptables.Match().InInterface("cali+"),
							Action: iptables.GotoAction{Target: "cali-wl-to-host"},
						},

						// Untracked packets already matched in raw table.
						{
							Match:  iptables.Match().MarkSingleBitSet(0x10),
							Action: iptables.ReturnAction{},
						},

						// Non-workload traffic, send to host chains.
						{Action: iptables.ClearMarkAction{Mark: 0xf0}},
						{Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint}},
						{
							Match:   iptables.Match().MarkSingleBitSet(0x10),
							Action:  iptables.ReturnAction{},
							Comment: []string{"Host endpoint policy accepted packet."},
						},
					},
				}))
			})
			It("should include the expected output chain in the filter chains", func() {
				Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&generictables.Chain{
					Name: "cali-OUTPUT",
					Rules: []generictables.Rule{
						// Untracked packets already matched in raw table.
						{
							Match:  iptables.Match().MarkSingleBitSet(0x10),
							Action: iptables.ReturnAction{},
						},

						// To workload traffic.
						{Match: iptables.Match().OutInterface("cali+"), Action: iptables.ReturnAction{}},

						// Non-workload traffic, send to host chains.
						{Action: iptables.ClearMarkAction{Mark: 0xf0}},
						{
							Match:  iptables.Match().NotConntrackState("DNAT"),
							Action: iptables.JumpAction{Target: ChainDispatchToHostEndpoint},
						},
						{
							Match:   iptables.Match().MarkSingleBitSet(0x10),
							Action:  iptables.ReturnAction{},
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
						MarkAccept:                  0x10,
						MarkPass:                    0x20,
						MarkScratch0:                0x40,
						MarkScratch1:                0x80,
						MarkDrop:                    0x200,
						MarkEndpoint:                0xff000,
						MarkNonCaliEndpoint:         0x1000,
						WireguardEnabled:            enableIPv4,
						WireguardEnabledV6:          enableIPv6,
						WireguardInterfaceName:      "wireguard.cali",
						WireguardInterfaceNameV6:    "wg-v6.cali",
						WireguardMark:               0x100000,
						WireguardListeningPort:      51820,
						WireguardListeningPortV6:    51821,
						WireguardEncryptHostTraffic: true,
						RouteSource:                 "WorkloadIPs",
					}
				})

				It("should include the expected input chain in the filter chains", func() {
					rules := []generictables.Rule{}
					if ipVersion == 4 && enableIPv4 {
						// IPv4 Wireguard rules
						rules = append(rules,
							generictables.Rule{
								Match: iptables.Match().
									ProtocolNum(17).
									DestPorts(51820).
									DestAddrType("LOCAL"),

								Action:  iptables.AcceptAction{},
								Comment: []string{"Allow incoming IPv4 Wireguard packets"},
							})
					}
					if ipVersion == 6 && enableIPv6 {
						// IPv6 Wireguard rules
						rules = append(rules,
							generictables.Rule{
								Match: iptables.Match().
									ProtocolNum(17).
									DestPorts(51821).
									DestAddrType("LOCAL"),

								Action:  iptables.AcceptAction{},
								Comment: []string{"Allow incoming IPv6 Wireguard packets"},
							})
					}
					rules = append(rules,
						// Per-prefix workload jump rules.  Note use of goto so that we
						// don't return here.
						generictables.Rule{
							Match:  iptables.Match().InInterface("cali+"),
							Action: iptables.GotoAction{Target: "cali-wl-to-host"},
						},

						// Untracked packets already matched in raw table.
						generictables.Rule{
							Match:  iptables.Match().MarkSingleBitSet(0x10),
							Action: iptables.AcceptAction{},
						},

						// Non-workload traffic, send to host chains.
						generictables.Rule{Action: iptables.ClearMarkAction{Mark: 0xf0}},
						generictables.Rule{Action: iptables.JumpAction{Target: ChainDispatchFromHostEndpoint}},
						generictables.Rule{
							Match:   iptables.Match().MarkSingleBitSet(0x10),
							Action:  iptables.AcceptAction{},
							Comment: []string{"Host endpoint policy accepted packet."},
						},
					)

					Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-INPUT")).To(Equal(&generictables.Chain{
						Name:  "cali-INPUT",
						Rules: rules,
					}))
				})

				It("should include the expected WireGuard PREROUTING chain in the raw chains", func() {
					Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-PREROUTING")).To(Equal(&generictables.Chain{
						Name: "cali-PREROUTING",
						Rules: []generictables.Rule{
							{
								Match:  nil,
								Action: iptables.ClearMarkAction{Mark: 0xf0},
							},
							{
								Match:  nil,
								Action: iptables.JumpAction{Target: "cali-wireguard-incoming-mark"},
							},
							{
								Match:  iptables.Match().InInterface("cali+"),
								Action: iptables.SetMarkAction{Mark: 0x40},
							},
							{
								Match:  iptables.Match().MarkMatchesWithMask(0x40, 0x40),
								Action: iptables.JumpAction{Target: ChainRpfSkip},
							},
							{
								Match:  iptables.Match().MarkMatchesWithMask(0x40, 0x40).RPFCheckFailed(),
								Action: iptables.DropAction{},
							},
							{
								Match:  iptables.Match().MarkClear(0x40),
								Action: iptables.JumpAction{Target: "cali-from-host-endpoint"},
							},
							{
								Match:  iptables.Match().MarkMatchesWithMask(0x10, 0x10),
								Action: iptables.AcceptAction{},
							},
						},
					}))
					Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-wireguard-incoming-mark")).To(Equal(&generictables.Chain{
						Name: "cali-wireguard-incoming-mark",
						Rules: []generictables.Rule{
							{
								Match:  iptables.Match().InInterface("lo"),
								Action: iptables.ReturnAction{},
							},
							{
								Match:  iptables.Match().InInterface("wireguard.cali"),
								Action: iptables.ReturnAction{},
							},
							{
								Match:  iptables.Match().InInterface("wg-v6.cali"),
								Action: iptables.ReturnAction{},
							},
							{
								Match:  iptables.Match().InInterface("cali+"),
								Action: iptables.ReturnAction{},
							},
							{
								Match:  nil,
								Action: iptables.SetMarkAction{Mark: 0x100000},
							},
						},
					}))
				})
			})
		}
	})

	Describe("with BPF mode raw chains", func() {
		staticBPFModeRawRules := []generictables.Rule{
			{
				Match:   iptables.Match().DestNet("169.254.0.0/16"),
				Action:  iptables.ReturnAction{},
				Comment: []string{"link-local"},
			},
			{
				Match:   iptables.Match().MarkMatchesWithMask(0x1100000, 0x1100000),
				Action:  iptables.ReturnAction{},
				Comment: []string{"MarkSeenSkipFIB Mark"},
			},
			{
				Match:   iptables.Match().MarkMatchesWithMask(0x5000000, 0x5000000),
				Action:  iptables.ReturnAction{},
				Comment: []string{"MarkSeenFallThrough Mark"},
			},
			{
				Match:   iptables.Match().MarkMatchesWithMask(0x3600000, 0x3f00000),
				Action:  iptables.ReturnAction{},
				Comment: []string{"MarkSeenMASQ Mark"},
			},
			{
				Match:   iptables.Match().MarkMatchesWithMask(0x3800000, 0x3f00000),
				Action:  iptables.ReturnAction{},
				Comment: []string{"MarkSeenNATOutgoing Mark"},
			},
			{
				Action: iptables.NoTrackAction{},
			},
		}

		BeforeEach(func() {
			conf = Config{
				MarkAccept:   0x10,
				MarkPass:     0x20,
				MarkScratch0: 0x40,
				MarkDrop:     0x200,
				BPFEnabled:   true,
			}
		})

		Context("with default BPF config", func() {
			It("should return no BPF untracked rules when bypassHostConntrack is false", func() {
				outputBPFModeRawChains := rr.StaticBPFModeRawChains(4, false, false)
				actualBPFModeRawChains := findChain(outputBPFModeRawChains, "cali-untracked-flows")
				expectBPFModeRawChains := &generictables.Chain{Name: "cali-untracked-flows", Rules: nil}
				Expect(actualBPFModeRawChains).To(Equal(expectBPFModeRawChains))
			})

			It("should return default static BPF untracked rules when bypassHostConntrack is true", func() {
				outputBPFModeRawChains := rr.StaticBPFModeRawChains(4, false, true)
				actualBPFModeRawChains := findChain(outputBPFModeRawChains, "cali-untracked-flows")
				expectBPFModeRawChains := &generictables.Chain{Name: "cali-untracked-flows", Rules: staticBPFModeRawRules}
				Expect(actualBPFModeRawChains).To(Equal(expectBPFModeRawChains))
			})
		})

		Context("with default BPF Force Track Packets From Ifaces config", func() {
			BeforeEach(func() {
				conf.BPFForceTrackPacketsFromIfaces = []string{"docker+"}
			})

			It("should return single BPF force track interface rule plus default static BPF untracked rules", func() {
				expectBPFModeRawRules := []generictables.Rule{
					{
						Match:   iptables.Match().InInterface("docker+"),
						Action:  iptables.ReturnAction{},
						Comment: []string{"Track interface docker+"},
					},
				}
				expectBPFModeRawRules = append(expectBPFModeRawRules, staticBPFModeRawRules...)

				outputBPFModeRawChains := rr.StaticBPFModeRawChains(4, false, true)
				actualBPFModeRawChains := findChain(outputBPFModeRawChains, "cali-untracked-flows")
				expectBPFModeRawChains := &generictables.Chain{Name: "cali-untracked-flows", Rules: expectBPFModeRawRules}
				Expect(actualBPFModeRawChains).To(Equal(expectBPFModeRawChains))
			})
		})

		Context("with custom BPF Force Track Packets From Ifaces config", func() {
			BeforeEach(func() {
				conf.BPFForceTrackPacketsFromIfaces = []string{"docker0", "docker1"}
			})

			It("should return single BPF force track interface rule plus default static BPF untracked rules", func() {
				expectBPFModeRawRules := []generictables.Rule{
					{
						Match:   iptables.Match().InInterface("docker0"),
						Action:  iptables.ReturnAction{},
						Comment: []string{"Track interface docker0"},
					},
					{
						Match:   iptables.Match().InInterface("docker1"),
						Action:  iptables.ReturnAction{},
						Comment: []string{"Track interface docker1"},
					},
				}
				expectBPFModeRawRules = append(expectBPFModeRawRules, staticBPFModeRawRules...)

				outputBPFModeRawChains := rr.StaticBPFModeRawChains(4, false, true)
				actualBPFModeRawChains := findChain(outputBPFModeRawChains, "cali-untracked-flows")
				expectBPFModeRawChains := &generictables.Chain{Name: "cali-untracked-flows", Rules: expectBPFModeRawRules}
				Expect(actualBPFModeRawChains).To(Equal(expectBPFModeRawChains))
			})
		})
	})
})

func findChain(chains []*generictables.Chain, name string) *generictables.Chain {
	for _, chain := range chains {
		if chain.Name == name {
			return chain
		}
	}
	return nil
}
