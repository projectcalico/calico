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

package rules_test

import (
	. "github.com/projectcalico/felix/rules"

	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/ipsets"
	. "github.com/projectcalico/felix/iptables"
	"net"
)

var _ = Describe("Static", func() {
	var rr *DefaultRuleRenderer
	var config Config
	JustBeforeEach(func() {
		// Cast back to the expected type so we can access a finer-grained API for testing.
		rr = NewRenderer(config).(*DefaultRuleRenderer)
	})

	Describe("with default config", func() {
		BeforeEach(func() {
			config = Config{
				WorkloadIfacePrefixes:     []string{"cali"},
				FailsafeInboundHostPorts:  []uint16{22, 1022},
				FailsafeOutboundHostPorts: []uint16{23, 1023},
				IptablesMarkAccept:        0x10,
				IptablesMarkNextTier:      0x20,
				IptablesMarkFromWorkload:  0x40,
			}
		})

		for _, ipVersion := range []uint8{4, 6} {
			Describe(fmt.Sprintf("IPv%d", ipVersion), func() {
				// Capture current value of ipVersion.
				ipVersion := ipVersion

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

				It("should include the expected forward chain in the filter chains", func() {
					Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-FORWARD")).To(Equal(&Chain{
						Name: "cali-FORWARD",
						Rules: []Rule{
							// Untracked packets already matched in raw table.
							{Match: Match().MarkSet(0x10).ConntrackState("UNTRACKED"),
								Action: AcceptAction{}},

							// conntrack rules.
							{Match: Match().ConntrackState("INVALID"),
								Action: DropAction{}},
							{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{}},

							// Per-prefix workload jump rules.
							{Match: Match().InInterface("cali+"),
								Action: JumpAction{Target: ChainFromWorkloadDispatch}},
							{Match: Match().OutInterface("cali+"),
								Action: JumpAction{Target: ChainToWorkloadDispatch}},

							// Accept if workload policy matched.
							{Match: Match().InInterface("cali+"),
								Action: AcceptAction{}},
							{Match: Match().OutInterface("cali+"),
								Action: AcceptAction{}},

							// Non-workload through-traffic, pass to host endpoint chains.
							{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
							{Action: JumpAction{Target: ChainDispatchToHostEndpoint}},
						},
					}))
				})
				It("should include the expected input chain in the filter chains", func() {
					Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-INPUT")).To(Equal(&Chain{
						Name: "cali-INPUT",
						Rules: []Rule{
							// Untracked packets already matched in raw table.
							{Match: Match().MarkSet(0x10).ConntrackState("UNTRACKED"),
								Action: AcceptAction{}},

							// conntrack rules.
							{Match: Match().ConntrackState("INVALID"),
								Action: DropAction{}},
							{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{}},

							// Per-prefix workload jump rules.  Note use of goto so that we
							// don't return here.
							{Match: Match().InInterface("cali+"),
								Action: GotoAction{Target: "cali-wl-to-host"}},

							// Non-workload traffic, pass to host endpoint chain. Note use of
							// goto so that we don't return here.
							{Action: GotoAction{Target: "cali-from-host-endpoint"}},
						},
					}))
				})
				It("should include the expected output chain in the filter chains", func() {
					Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&Chain{
						Name: "cali-OUTPUT",
						Rules: []Rule{
							// Untracked packets already matched in raw table.
							{Match: Match().MarkSet(0x10).ConntrackState("UNTRACKED"),
								Action: AcceptAction{}},

							// conntrack rules.
							{Match: Match().ConntrackState("INVALID"),
								Action: DropAction{}},
							{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
								Action: AcceptAction{}},

							// Return if to workload.
							{Match: Match().OutInterface("cali+"), Action: ReturnAction{}},

							// Non-workload traffic, pass to host endpoint chain. Note use of
							// goto so that we don't return here.
							{Action: GotoAction{Target: "cali-to-host-endpoint"}},
						},
					}))
				})
				It("should include the expected failsafe-in chain in the filter chains", func() {
					Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-failsafe-in")).To(Equal(expFailsafeIn))
				})
				It("should include the expected failsafe-out chain in the filter chains", func() {
					Expect(findChain(rr.StaticFilterTableChains(ipVersion), "cali-failsafe-out")).To(Equal(expFailsafeOut))
				})
				It("should return only the expected filter chains", func() {
					Expect(len(rr.StaticFilterTableChains(ipVersion))).To(Equal(6))
				})

				It("Should return expected raw OUTPUT chain", func() {
					Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-OUTPUT")).To(Equal(&Chain{
						Name: "cali-OUTPUT",
						Rules: []Rule{
							// For safety, clear all our mark bits before we start.  (We could be in
							// append mode and another process' rules could have left the mark bit set.)
							{Action: ClearMarkAction{Mark: 0x70}},
							// Then, jump to the untracked policy chains.
							{Action: JumpAction{Target: "cali-to-host-endpoint"}},
							// Then, if the packet was marked as allowed, accept it.  Packets also
							// return here without the mark bit set if the interface wasn't one that
							// we're policing.
							{Match: Match().MarkSet(0x10), Action: AcceptAction{}},
						},
					}))
				})
				It("Should return expected raw failsafe in chain", func() {
					Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-failsafe-in")).To(Equal(expFailsafeIn))
				})
				It("Should return expected raw failsafe out chain", func() {
					Expect(findChain(rr.StaticRawTableChains(ipVersion), "cali-failsafe-out")).To(Equal(expFailsafeOut))
				})
				It("should return only the expected raw chains", func() {
					Expect(len(rr.StaticRawTableChains(ipVersion))).To(Equal(4))
				})
			})
		}

		It("IPv4: Should return expected raw PREROUTING chain", func() {
			Expect(findChain(rr.StaticRawTableChains(4), "cali-PREROUTING")).To(Equal(&Chain{
				Name: "cali-PREROUTING",
				Rules: []Rule{
					{Action: ClearMarkAction{Mark: 0x70}},
					{Match: Match().InInterface("cali+"),
						Action: SetMarkAction{Mark: 0x40}},
					{Match: Match().MarkClear(0x40),
						Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
					{Match: Match().MarkSet(0x10),
						Action: AcceptAction{}},
				},
			}))
		})
		It("IPv6: Should return expected raw PREROUTING chain", func() {
			Expect(findChain(rr.StaticRawTableChains(6), "cali-PREROUTING")).To(Equal(&Chain{
				Name: "cali-PREROUTING",
				Rules: []Rule{
					{Action: ClearMarkAction{Mark: 0x70}},
					{Match: Match().InInterface("cali+"),
						Action: SetMarkAction{Mark: 0x40}},
					{Match: Match().MarkSet(0x40).RPFCheckFailed(),
						Action: DropAction{}},
					{Match: Match().MarkClear(0x40),
						Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
					{Match: Match().MarkSet(0x10),
						Action: AcceptAction{}},
				},
			}))
		})

		It("IPv4: should include the expected workload-to-host chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(4), "cali-wl-to-host")).To(Equal(&Chain{
				Name: "cali-wl-to-host",
				Rules: []Rule{
					{Action: JumpAction{Target: "cali-from-wl-dispatch"}},
					{Action: ReturnAction{},
						Comment: "Configured DefaultEndpointToHostAction"},
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
						Comment: "Configured DefaultEndpointToHostAction"},
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
		It("IPv4: Should return only the expected nat chains", func() {
			Expect(len(rr.StaticNATTableChains(4))).To(Equal(3))
		})
		It("IPv6: Should return only the expected nat chains", func() {
			Expect(len(rr.StaticNATTableChains(6))).To(Equal(3))
		})
	})

	Describe("with openstack special-cases", func() {
		BeforeEach(func() {
			config = Config{
				WorkloadIfacePrefixes:        []string{"tap"},
				OpenStackSpecialCasesEnabled: true,
				OpenStackMetadataIP:          net.ParseIP("10.0.0.1"),
				OpenStackMetadataPort:        1234,
				IptablesMarkAccept:           0x10,
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
					Comment: "Configured DefaultEndpointToHostAction"},
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
					Comment: "Configured DefaultEndpointToHostAction"},
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

	Describe("with IPIP enabled", func() {
		BeforeEach(func() {
			config = Config{
				WorkloadIfacePrefixes: []string{"cali"},
				IPIPEnabled:           true,
				IPIPTunnelAddress:     net.ParseIP("10.0.0.1"),
				IPSetConfigV4:         ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
				IptablesMarkAccept:    0x10,
			}
		})

		expInputChainIPIPV4 := &Chain{
			Name: "cali-INPUT",
			Rules: []Rule{
				// Untracked packets already matched in raw table.
				{Match: Match().MarkSet(0x10).ConntrackState("UNTRACKED"),
					Action: AcceptAction{}},

				// IPIP rule
				{Match: Match().ProtocolNum(4).NotSourceIPSet("cali4-all-hosts"),
					Action:  DropAction{},
					Comment: "Drop IPIP packets from non-Calico hosts"},

				// conntrack rules.
				{Match: Match().ConntrackState("INVALID"),
					Action: DropAction{}},
				{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
					Action: AcceptAction{}},

				// Per-prefix workload jump rules.  Note use of goto so that we
				// don't return here.
				{Match: Match().InInterface("cali+"),
					Action: GotoAction{Target: "cali-wl-to-host"}},

				// Non-workload traffic, pass to host endpoint chain. Note use of
				// goto so that we don't return here.
				{Action: GotoAction{Target: "cali-from-host-endpoint"}},
			},
		}

		// V6 should be unaffected.
		expInputChainIPIPV6 := &Chain{
			Name: "cali-INPUT",
			Rules: []Rule{
				// Untracked packets already matched in raw table.
				{Match: Match().MarkSet(0x10).ConntrackState("UNTRACKED"),
					Action: AcceptAction{}},

				// conntrack rules.
				{Match: Match().ConntrackState("INVALID"),
					Action: DropAction{}},
				{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
					Action: AcceptAction{}},

				// Per-prefix workload jump rules.  Note use of goto so that we
				// don't return here.
				{Match: Match().InInterface("cali+"),
					Action: GotoAction{Target: "cali-wl-to-host"}},

				// Non-workload traffic, pass to host endpoint chain. Note use of
				// goto so that we don't return here.
				{Action: GotoAction{Target: "cali-from-host-endpoint"}},
			},
		}

		It("IPv4: should include the expected input chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(4), "cali-INPUT")).To(Equal(expInputChainIPIPV4))
		})
		It("IPv6: should include the expected input chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(6), "cali-INPUT")).To(Equal(expInputChainIPIPV6))
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
		It("IPv4: Should return expected NAT postrouting chain", func() {
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

	Describe("with drop override and multiple prefixes", func() {
		BeforeEach(func() {
			config = Config{
				WorkloadIfacePrefixes: []string{"cali", "tap"},
				ActionOnDrop:          "ACCEPT",
				IptablesMarkAccept:    0x10,
			}
		})

		expForwardChain := &Chain{
			Name: "cali-FORWARD",
			Rules: []Rule{
				// Untracked packets already matched in raw table.
				{Match: Match().MarkSet(0x10).ConntrackState("UNTRACKED"),
					Action: AcceptAction{}},

				// conntrack rules.
				{Match: Match().ConntrackState("INVALID"),
					Action: AcceptAction{}}, // OVERRIDDEN.
				{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
					Action: AcceptAction{}},

				// Per-prefix workload jump rules.
				{Match: Match().InInterface("cali+"),
					Action: JumpAction{Target: ChainFromWorkloadDispatch}},
				{Match: Match().OutInterface("cali+"),
					Action: JumpAction{Target: ChainToWorkloadDispatch}},
				{Match: Match().InInterface("tap+"),
					Action: JumpAction{Target: ChainFromWorkloadDispatch}},
				{Match: Match().OutInterface("tap+"),
					Action: JumpAction{Target: ChainToWorkloadDispatch}},

				// Accept if workload policy matched.
				{Match: Match().InInterface("cali+"),
					Action: AcceptAction{}},
				{Match: Match().OutInterface("cali+"),
					Action: AcceptAction{}},
				{Match: Match().InInterface("tap+"),
					Action: AcceptAction{}},
				{Match: Match().OutInterface("tap+"),
					Action: AcceptAction{}},

				// Non-workload through-traffic, pass to host endpoint chains.
				{Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
				{Action: JumpAction{Target: ChainDispatchToHostEndpoint}},
			},
		}

		expInputChainIPIP := &Chain{
			Name: "cali-INPUT",
			Rules: []Rule{
				// Untracked packets already matched in raw table.
				{Match: Match().MarkSet(0x10).ConntrackState("UNTRACKED"),
					Action: AcceptAction{}},

				// conntrack rules.
				{Match: Match().ConntrackState("INVALID"),
					Action: AcceptAction{}}, // OVERRIDDEN.
				{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
					Action: AcceptAction{}},

				// Per-prefix workload jump rules.  Note use of goto so that we
				// don't return here.
				{Match: Match().InInterface("cali+"),
					Action: GotoAction{Target: "cali-wl-to-host"}},
				{Match: Match().InInterface("tap+"),
					Action: GotoAction{Target: "cali-wl-to-host"}},

				// Non-workload traffic, pass to host endpoint chain. Note use of
				// goto so that we don't return here.
				{Action: GotoAction{Target: "cali-from-host-endpoint"}},
			},
		}

		expOutputChain := &Chain{
			Name: "cali-OUTPUT",
			Rules: []Rule{
				// Untracked packets already matched in raw table.
				{Match: Match().MarkSet(0x10).ConntrackState("UNTRACKED"),
					Action: AcceptAction{}},

				// conntrack rules.
				{Match: Match().ConntrackState("INVALID"),
					Action: AcceptAction{}}, // OVERRIDDEN.
				{Match: Match().ConntrackState("RELATED,ESTABLISHED"),
					Action: AcceptAction{}},

				// Return if to workload.
				{Match: Match().OutInterface("cali+"), Action: ReturnAction{}},
				{Match: Match().OutInterface("tap+"), Action: ReturnAction{}},

				// Non-workload traffic, pass to host endpoint chain. Note use of
				// goto so that we don't return here.
				{Action: GotoAction{Target: "cali-to-host-endpoint"}},
			},
		}

		expWlToHostV4 := &Chain{
			Name: "cali-wl-to-host",
			Rules: []Rule{
				{Action: JumpAction{Target: "cali-from-wl-dispatch"}},
				{Action: ReturnAction{},
					Comment: "Configured DefaultEndpointToHostAction"},
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
				{Action: JumpAction{Target: "cali-from-wl-dispatch"}},
				{Action: ReturnAction{},
					Comment: "Configured DefaultEndpointToHostAction"},
			},
		}

		It("IPv4: should include the expected forward chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(4), "cali-FORWARD")).To(Equal(expForwardChain))
		})
		It("IPv6: should include the expected forward chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(6), "cali-FORWARD")).To(Equal(expForwardChain))
		})
		It("IPv4: should include the expected input chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(4), "cali-INPUT")).To(Equal(expInputChainIPIP))
		})
		It("IPv6: should include the expected input chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(6), "cali-INPUT")).To(Equal(expInputChainIPIP))
		})
		It("IPv4: should include the expected output chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(4), "cali-OUTPUT")).To(Equal(expOutputChain))
		})
		It("IPv6: should include the expected output chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(6), "cali-OUTPUT")).To(Equal(expOutputChain))
		})
		It("IPv4: should include the expected workload-to-host chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(4), "cali-wl-to-host")).To(Equal(expWlToHostV4))
		})
		It("IPv6: should include the expected workload-to-host chain in the filter chains", func() {
			Expect(findChain(rr.StaticFilterTableChains(6), "cali-wl-to-host")).To(Equal(expWlToHostV6))
		})
	})
})

var _ = Describe("DropRules", func() {
	var rr *DefaultRuleRenderer
	var config Config

	JustBeforeEach(func() {
		// Cast back to the expected type so we can access a finer-grained API for testing.
		rr = NewRenderer(config).(*DefaultRuleRenderer)
	})

	Describe("with LOG-and-DROP override", func() {
		BeforeEach(func() {
			config = Config{
				WorkloadIfacePrefixes: []string{"cali", "tap"},
				ActionOnDrop:          "LOG-and-DROP",
				IptablesMarkAccept:    0x10,
			}
		})

		It("should render a log and a drop", func() {
			Expect(rr.DropRules(Match().Protocol("tcp"))).To(Equal([]Rule{
				{Match: Match().Protocol("tcp"), Action: LogAction{Prefix: "calico-drop"}},
				{Match: Match().Protocol("tcp"), Action: DropAction{}},
			}))
		})

		Describe("with a custom prefix", func() {
			BeforeEach(func() {
				config.DropLogPrefix = "my-prefix"
			})

			It("should render a log and a drop", func() {
				Expect(rr.DropRules(Match().Protocol("tcp"))).To(Equal([]Rule{
					{Match: Match().Protocol("tcp"), Action: LogAction{Prefix: "my-prefix"}},
					{Match: Match().Protocol("tcp"), Action: DropAction{}},
				}))
			})
		})
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
