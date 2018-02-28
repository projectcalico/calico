// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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
	"errors"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/routetable"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/felix/testutils"
	"github.com/projectcalico/libcalico-go/lib/set"
)

var wlDispatchEmpty = []*iptables.Chain{
	{
		Name: "cali-to-wl-dispatch",
		Rules: []iptables.Rule{
			{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: "Unknown interface",
			},
		},
	},
	{
		Name: "cali-from-wl-dispatch",
		Rules: []iptables.Rule{
			{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: "Unknown interface",
			},
		},
	},
	{
		Name: "cali-from-endpoint-mark",
		Rules: []iptables.Rule{
			{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: "Unknown interface",
			},
		},
	},
	{
		Name: "cali-set-endpoint-mark",
		Rules: []iptables.Rule{
			iptables.Rule{
				Match:   iptables.Match().InInterface("cali+"),
				Action:  iptables.DropAction{},
				Comment: "Unknown endpoint",
			},
			iptables.Rule{
				Match:   iptables.Match().InInterface("tap+"),
				Action:  iptables.DropAction{},
				Comment: "Unknown endpoint",
			},
			{
				Action:  iptables.SetMaskedMarkAction{Mark: 0x0100, Mask: 0xff00},
				Comment: "Non-Cali endpoint mark",
			},
		},
	},
}

var hostDispatchEmptyNormal = []*iptables.Chain{
	{
		Name:  "cali-to-host-endpoint",
		Rules: []iptables.Rule{},
	},
	{
		Name:  "cali-from-host-endpoint",
		Rules: []iptables.Rule{},
	},
}

var hostDispatchEmptyForward = []*iptables.Chain{
	{
		Name:  "cali-to-hep-forward",
		Rules: []iptables.Rule{},
	},
	{
		Name:  "cali-from-hep-forward",
		Rules: []iptables.Rule{},
	},
}

var fromHostDispatchEmpty = []*iptables.Chain{
	{
		Name:  "cali-from-host-endpoint",
		Rules: []iptables.Rule{},
	},
}

func hostChainsForIfaces(ifaceMetadata []string, epMarkMapper rules.EndpointMarkMapper) []*iptables.Chain {
	return append(chainsForIfaces(ifaceMetadata, epMarkMapper, true, "normal"),
		chainsForIfaces(ifaceMetadata, epMarkMapper, true, "applyOnForward")...,
	)
}

func rawChainsForIfaces(ifaceMetadata []string, epMarkMapper rules.EndpointMarkMapper) []*iptables.Chain {
	return chainsForIfaces(ifaceMetadata, epMarkMapper, true, "untracked")
}

func preDNATChainsForIfaces(ifaceMetadata []string, epMarkMapper rules.EndpointMarkMapper) []*iptables.Chain {
	return chainsForIfaces(ifaceMetadata, epMarkMapper, true, "preDNAT")
}

func wlChainsForIfaces(ifaceMetadata []string, epMarkMapper rules.EndpointMarkMapper) []*iptables.Chain {
	return chainsForIfaces(ifaceMetadata, epMarkMapper, false, "normal")
}

func chainsForIfaces(ifaceMetadata []string,
	epMarkMapper rules.EndpointMarkMapper,
	host bool,
	tableKind string) []*iptables.Chain {
	log.WithFields(log.Fields{
		"ifaces":    ifaceMetadata,
		"host":      host,
		"tableKind": tableKind,
	}).Debug("Calculating chains for interface")
	chains := []*iptables.Chain{}
	dispatchOut := []iptables.Rule{}
	dispatchIn := []iptables.Rule{}
	epMarkSet := []iptables.Rule{}
	epMarkFrom := []iptables.Rule{}
	hostOrWlLetter := "w"
	hostOrWlDispatch := "wl-dispatch"
	outPrefix := "cali-from-"
	inPrefix := "cali-to-"
	epMarkSetName := "cali-set-endpoint-mark"
	epMarkFromName := "cali-from-endpoint-mark"
	epMarkSetOnePrefix := "cali-sm-"
	epmarkFromPrefix := outPrefix[:6]

	if host {
		hostOrWlLetter = "h"
		hostOrWlDispatch = "host-endpoint"
		if tableKind == "applyOnForward" {
			hostOrWlLetter = "hfw"
			hostOrWlDispatch = "hep-forward"
		}
		outPrefix = "cali-to-"
		inPrefix = "cali-from-"
		epmarkFromPrefix = inPrefix[:6]
	}
	for _, ifaceMetadata := range ifaceMetadata {
		var ifaceName, polName string
		nameParts := strings.Split(ifaceMetadata, "_")
		ifaceKind := "normal"
		ingress := true
		egress := true
		if len(nameParts) == 1 {
			// Just an interface name "eth0", apply no tweaks.
			log.Debug("Interface name only")
			ifaceName = nameParts[0]
			polName = ""
		} else if len(nameParts) == 2 {
			// Interface name and a policy name  "eth0_polA".
			log.Debug("Interface name and policy name")
			ifaceName = nameParts[0]
			polName = nameParts[1]
		} else {
			// Interface name, policy name and untracked "eth0_polA_untracked"
			// or applyOnForwrd "eth0_polA_applyOnForward".
			log.Debug("Interface name policy name and untracked/ingress/egress")
			ifaceName = nameParts[0]
			polName = nameParts[1]
			switch nameParts[2] {
			case "ingress":
				egress = false
			case "egress":
				ingress = false
			default:
				ifaceKind = nameParts[2]
			}
		}
		epMark, err := epMarkMapper.GetEndpointMark(ifaceName)
		if err != nil {
			log.WithFields(log.Fields{
				"ifaces":    ifaceMetadata,
				"host":      host,
				"tableKind": tableKind,
			}).Debug("Failed to get endpoint mark for interface")
			continue
		}

		if tableKind != ifaceKind && tableKind != "normal" && tableKind != "applyOnForward" {
			continue
		}

		outRules := []iptables.Rule{}

		if tableKind != "untracked" {
			outRules = append(outRules,
				iptables.Rule{
					Match:  iptables.Match().ConntrackState("RELATED,ESTABLISHED"),
					Action: iptables.AcceptAction{},
				},
			)
			outRules = append(outRules, iptables.Rule{
				Match:  iptables.Match().ConntrackState("INVALID"),
				Action: iptables.DropAction{},
			})
		}

		if host && tableKind != "applyOnForward" {
			outRules = append(outRules, iptables.Rule{
				Match:  iptables.Match(),
				Action: iptables.JumpAction{Target: "cali-failsafe-out"},
			})
		}
		outRules = append(outRules, iptables.Rule{
			Match:  iptables.Match(),
			Action: iptables.ClearMarkAction{Mark: 8},
		})
		if egress && polName != "" && tableKind == ifaceKind {
			outRules = append(outRules, iptables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.ClearMarkAction{Mark: 16},
				Comment: "Start of policies",
			})
			outRules = append(outRules, iptables.Rule{
				Match:  iptables.Match().MarkClear(16),
				Action: iptables.JumpAction{Target: "cali-po-" + polName},
			})
			if tableKind == "untracked" {
				outRules = append(outRules, iptables.Rule{
					Match:  iptables.Match().MarkSingleBitSet(8),
					Action: iptables.NoTrackAction{},
				})
			}
			outRules = append(outRules, iptables.Rule{
				Match:   iptables.Match().MarkSingleBitSet(8),
				Action:  iptables.ReturnAction{},
				Comment: "Return if policy accepted",
			})
			if tableKind == "normal" || tableKind == "applyOnForward" {
				// Only end with a drop rule in the filter chain.  In the raw chain,
				// we consider the policy as unfinished, because some of the
				// policy may live in the filter chain.
				outRules = append(outRules, iptables.Rule{
					Match:   iptables.Match().MarkClear(16),
					Action:  iptables.DropAction{},
					Comment: "Drop if no policies passed packet",
				})
			}
		}

		if tableKind == "normal" {
			outRules = append(outRules, iptables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: "Drop if no profiles matched",
			})
		}

		inRules := []iptables.Rule{}

		if tableKind != "untracked" {
			inRules = append(inRules,
				iptables.Rule{
					Match:  iptables.Match().ConntrackState("RELATED,ESTABLISHED"),
					Action: iptables.AcceptAction{},
				},
			)
			inRules = append(inRules, iptables.Rule{
				Match:  iptables.Match().ConntrackState("INVALID"),
				Action: iptables.DropAction{},
			})
		}

		if host && tableKind != "applyOnForward" {
			inRules = append(inRules, iptables.Rule{
				Match:  iptables.Match(),
				Action: iptables.JumpAction{Target: "cali-failsafe-in"},
			})
		}
		inRules = append(inRules, iptables.Rule{
			Match:  iptables.Match(),
			Action: iptables.ClearMarkAction{Mark: 8},
		})
		if ingress && polName != "" && tableKind == ifaceKind {
			inRules = append(inRules, iptables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.ClearMarkAction{Mark: 16},
				Comment: "Start of policies",
			})
			// For untracked policy, we expect a tier with a policy in it.
			inRules = append(inRules, iptables.Rule{
				Match:  iptables.Match().MarkClear(16),
				Action: iptables.JumpAction{Target: "cali-pi-" + polName},
			})
			if tableKind == "untracked" {
				inRules = append(inRules, iptables.Rule{
					Match:  iptables.Match().MarkSingleBitSet(8),
					Action: iptables.NoTrackAction{},
				})
			}
			inRules = append(inRules, iptables.Rule{
				Match:   iptables.Match().MarkSingleBitSet(8),
				Action:  iptables.ReturnAction{},
				Comment: "Return if policy accepted",
			})
			if tableKind == "normal" || tableKind == "applyOnForward" {
				// Only end with a drop rule in the filter chain.  In the raw chain,
				// we consider the policy as unfinished, because some of the
				// policy may live in the filter chain.
				inRules = append(inRules, iptables.Rule{
					Match:   iptables.Match().MarkClear(16),
					Action:  iptables.DropAction{},
					Comment: "Drop if no policies passed packet",
				})
			}
		}
		if tableKind == "normal" {
			inRules = append(inRules, iptables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: "Drop if no profiles matched",
			})
		}
		if tableKind == "preDNAT" {
			chains = append(chains,
				&iptables.Chain{
					Name:  inPrefix[:6] + hostOrWlLetter + "-" + ifaceName,
					Rules: inRules,
				},
			)
		} else {
			chains = append(chains,
				&iptables.Chain{
					Name:  outPrefix[:6] + hostOrWlLetter + "-" + ifaceName,
					Rules: outRules,
				},
				&iptables.Chain{
					Name:  inPrefix[:6] + hostOrWlLetter + "-" + ifaceName,
					Rules: inRules,
				},
			)
		}

		if host {
			dispatchOut = append(dispatchOut,
				iptables.Rule{
					Match:  iptables.Match().OutInterface(ifaceName),
					Action: iptables.GotoAction{Target: outPrefix[:6] + hostOrWlLetter + "-" + ifaceName},
				},
			)
			dispatchIn = append(dispatchIn,
				iptables.Rule{
					Match:  iptables.Match().InInterface(ifaceName),
					Action: iptables.GotoAction{Target: inPrefix[:6] + hostOrWlLetter + "-" + ifaceName},
				},
			)
		} else {
			dispatchOut = append(dispatchOut,
				iptables.Rule{
					Match:  iptables.Match().InInterface(ifaceName),
					Action: iptables.GotoAction{Target: outPrefix[:6] + hostOrWlLetter + "-" + ifaceName},
				},
			)
			dispatchIn = append(dispatchIn,
				iptables.Rule{
					Match:  iptables.Match().OutInterface(ifaceName),
					Action: iptables.GotoAction{Target: inPrefix[:6] + hostOrWlLetter + "-" + ifaceName},
				},
			)
		}

		if tableKind != "preDNAT" && tableKind != "untracked" {
			chains = append(chains,
				&iptables.Chain{
					Name: epMarkSetOnePrefix + ifaceName,
					Rules: []iptables.Rule{
						iptables.Rule{
							Action: iptables.SetMaskedMarkAction{Mark: epMark, Mask: epMarkMapper.GetMask()},
						},
					},
				},
			)
			epMarkSet = append(epMarkSet,
				iptables.Rule{
					Match:  iptables.Match().InInterface(ifaceName),
					Action: iptables.GotoAction{Target: epMarkSetOnePrefix + ifaceName},
				},
			)
			epMarkFrom = append(epMarkFrom,
				iptables.Rule{
					Match:  iptables.Match().MarkMatchesWithMask(epMark, epMarkMapper.GetMask()),
					Action: iptables.GotoAction{Target: epmarkFromPrefix + hostOrWlLetter + "-" + ifaceName},
				},
			)
		}

	}
	if !host {
		dispatchOut = append(dispatchOut,
			iptables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: "Unknown interface",
			},
		)
		dispatchIn = append(dispatchIn,
			iptables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: "Unknown interface",
			},
		)
	}

	if tableKind != "preDNAT" && tableKind != "untracked" {
		epMarkSet = append(epMarkSet,
			iptables.Rule{
				Match:   iptables.Match().InInterface("cali+"),
				Action:  iptables.DropAction{},
				Comment: "Unknown endpoint",
			},
			iptables.Rule{
				Match:   iptables.Match().InInterface("tap+"),
				Action:  iptables.DropAction{},
				Comment: "Unknown endpoint",
			},
			iptables.Rule{
				Action:  iptables.SetMaskedMarkAction{Mark: 0x0100, Mask: 0xff00},
				Comment: "Non-Cali endpoint mark",
			},
		)
		epMarkFrom = append(epMarkFrom,
			iptables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: "Unknown interface",
			},
		)
		chains = append(chains,
			&iptables.Chain{
				Name:  epMarkSetName,
				Rules: epMarkSet,
			},
			&iptables.Chain{
				Name:  epMarkFromName,
				Rules: epMarkFrom,
			},
		)
	}

	if tableKind == "preDNAT" {
		chains = append(chains,
			&iptables.Chain{
				Name:  inPrefix + hostOrWlDispatch,
				Rules: dispatchIn,
			},
		)
	} else {
		chains = append(chains,
			&iptables.Chain{
				Name:  outPrefix + hostOrWlDispatch,
				Rules: dispatchOut,
			},
			&iptables.Chain{
				Name:  inPrefix + hostOrWlDispatch,
				Rules: dispatchIn,
			},
		)
	}

	return chains
}

type mockRouteTable struct {
	currentRoutes map[string][]routetable.Target
}

func (t *mockRouteTable) SetRoutes(ifaceName string, targets []routetable.Target) {
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"targets":   targets,
	}).Debug("SetRoutes")
	t.currentRoutes[ifaceName] = targets
}

func (t *mockRouteTable) checkRoutes(ifaceName string, expected []routetable.Target) {
	Expect(t.currentRoutes[ifaceName]).To(Equal(expected))
}

type statusReportRecorder struct {
	currentState map[interface{}]string
}

func (r *statusReportRecorder) endpointStatusUpdateCallback(ipVersion uint8, id interface{}, status string) {
	log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"id":        id,
		"status":    status,
	}).Debug("endpointStatusUpdateCallback")
	if status == "" {
		delete(r.currentState, id)
	} else {
		r.currentState[id] = status
	}
}

type hostEpSpec struct {
	id        string
	name      string
	ipv4Addrs []string
	ipv6Addrs []string
	polName   string
}

func endpointManagerTests(ipVersion uint8) func() {
	return func() {
		const (
			ipv4     = "10.0.240.10"
			ipv4Eth1 = "10.0.240.30"
			ipv6     = "2001:db8::10.0.240.10"
		)
		var (
			epMgr           *endpointManager
			rawTable        *mockTable
			mangleTable     *mockTable
			filterTable     *mockTable
			rrConfigNormal  rules.Config
			eth0Addrs       set.Set
			loAddrs         set.Set
			eth1Addrs       set.Set
			routeTable      *mockRouteTable
			mockProcSys     *testProcSys
			statusReportRec *statusReportRecorder
		)

		BeforeEach(func() {
			rrConfigNormal = rules.Config{
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
				KubeIPVSSupportEnabled:      true,
				WorkloadIfacePrefixes:       []string{"cali", "tap"},
			}
			eth0Addrs = set.New()
			eth0Addrs.Add(ipv4)
			eth0Addrs.Add(ipv6)
			loAddrs = set.New()
			loAddrs.Add("127.0.1.1")
			loAddrs.Add("::1")
			eth1Addrs = set.New()
			eth1Addrs.Add(ipv4Eth1)
		})

		JustBeforeEach(func() {
			renderer := rules.NewRenderer(rrConfigNormal)
			rawTable = newMockTable("raw")
			mangleTable = newMockTable("mangle")
			filterTable = newMockTable("filter")
			routeTable = &mockRouteTable{
				currentRoutes: map[string][]routetable.Target{},
			}
			mockProcSys = &testProcSys{state: map[string]string{}}
			statusReportRec = &statusReportRecorder{currentState: map[interface{}]string{}}
			epMgr = newEndpointManagerWithShims(
				rawTable,
				mangleTable,
				filterTable,
				renderer,
				routeTable,
				ipVersion,
				rules.NewEndpointMarkMapper(rrConfigNormal.IptablesMarkEndpoint, rrConfigNormal.IptablesMarkNonCaliEndpoint),
				rrConfigNormal.KubeIPVSSupportEnabled,
				[]string{"cali"},
				statusReportRec.endpointStatusUpdateCallback,
				mockProcSys.write,
			)
		})

		It("should be constructable", func() {
			Expect(epMgr).ToNot(BeNil())
		})

		configureHostEp := func(spec *hostEpSpec) func() {
			tiers := []*proto.TierInfo{}
			untrackedTiers := []*proto.TierInfo{}
			preDNATTiers := []*proto.TierInfo{}
			forwardTiers := []*proto.TierInfo{}
			if spec.polName != "" {
				parts := strings.Split(spec.polName, "_")
				if len(parts) == 1 {
					tiers = append(tiers, &proto.TierInfo{
						Name:            "default",
						IngressPolicies: []string{spec.polName},
						EgressPolicies:  []string{spec.polName},
					})
				} else if len(parts) == 2 && parts[1] == "untracked" {
					untrackedTiers = append(untrackedTiers, &proto.TierInfo{
						Name:            "default",
						IngressPolicies: []string{parts[0]},
						EgressPolicies:  []string{parts[0]},
					})
				} else if len(parts) == 2 && parts[1] == "preDNAT" {
					preDNATTiers = append(preDNATTiers, &proto.TierInfo{
						Name:            "default",
						IngressPolicies: []string{parts[0]},
					})
				} else if len(parts) == 2 && parts[1] == "applyOnForward" {
					forwardTiers = append(forwardTiers, &proto.TierInfo{
						Name:            "default",
						IngressPolicies: []string{parts[0]},
						EgressPolicies:  []string{parts[0]},
					})
				} else if len(parts) == 2 && parts[1] == "ingress" {
					tiers = append(tiers, &proto.TierInfo{
						Name:            "default",
						IngressPolicies: []string{parts[0]},
					})
				} else if len(parts) == 2 && parts[1] == "egress" {
					tiers = append(tiers, &proto.TierInfo{
						Name:           "default",
						EgressPolicies: []string{parts[0]},
					})
				} else {
					panic("Failed to parse policy name " + spec.polName)
				}
			}
			return func() {
				epMgr.OnUpdate(&proto.HostEndpointUpdate{
					Id: &proto.HostEndpointID{
						EndpointId: spec.id,
					},
					Endpoint: &proto.HostEndpoint{
						Name:              spec.name,
						ProfileIds:        []string{},
						Tiers:             tiers,
						UntrackedTiers:    untrackedTiers,
						PreDnatTiers:      preDNATTiers,
						ForwardTiers:      forwardTiers,
						ExpectedIpv4Addrs: spec.ipv4Addrs,
						ExpectedIpv6Addrs: spec.ipv6Addrs,
					},
				})
				epMgr.CompleteDeferredWork()
			}
		}

		expectChainsFor := func(names ...string) func() {
			return func() {
				filterTable.checkChains([][]*iptables.Chain{
					wlDispatchEmpty,
					hostChainsForIfaces(names, epMgr.epMarkMapper),
				})
				rawTable.checkChains([][]*iptables.Chain{
					rawChainsForIfaces(names, epMgr.epMarkMapper),
				})
				mangleTable.checkChains([][]*iptables.Chain{
					preDNATChainsForIfaces(names, epMgr.epMarkMapper),
				})
			}
		}

		expectEmptyChains := func() func() {
			return func() {
				filterTable.checkChains([][]*iptables.Chain{
					wlDispatchEmpty,
					hostDispatchEmptyNormal,
					hostDispatchEmptyForward,
				})
				rawTable.checkChains([][]*iptables.Chain{
					hostDispatchEmptyNormal,
				})
				mangleTable.checkChains([][]*iptables.Chain{
					fromHostDispatchEmpty,
				})
			}
		}

		removeHostEp := func(id string) func() {
			return func() {
				epMgr.OnUpdate(&proto.HostEndpointRemove{
					Id: &proto.HostEndpointID{
						EndpointId: id,
					},
				})
				epMgr.CompleteDeferredWork()
			}
		}

		Context("with host interfaces eth0, lo", func() {
			JustBeforeEach(func() {
				epMgr.OnUpdate(&ifaceUpdate{
					Name:  "eth0",
					State: "up",
				})
				epMgr.OnUpdate(&ifaceAddrsUpdate{
					Name:  "eth0",
					Addrs: eth0Addrs,
				})
				epMgr.OnUpdate(&ifaceUpdate{
					Name:  "lo",
					State: "up",
				})
				epMgr.OnUpdate(&ifaceAddrsUpdate{
					Name:  "lo",
					Addrs: loAddrs,
				})
				epMgr.CompleteDeferredWork()
			})

			It("should have empty dispatch chains", expectEmptyChains())
			It("should make no status reports", func() {
				Expect(statusReportRec.currentState).To(BeEmpty())
			})

			// Configure host endpoints with tier names here, so we can check which of
			// the host endpoints gets used in the programming for a particular host
			// interface.  When more than one host endpoint matches a given interface,
			// we expect the one used to be the one with the alphabetically earliest ID.
			Describe("with host endpoint with tier matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:      "id1",
					name:    "eth0",
					polName: "polA",
				}))
				It("should have expected chains", expectChainsFor("eth0_polA"))
				It("should report id1 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id1"}: "up",
					}))
				})

				Context("with another host ep (>ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id2",
						ipv4Addrs: []string{ipv4},
						polName:   "polB",
					}))
					It("should have expected chains", expectChainsFor("eth0_polA"))
					It("should report id1 up, but id2 now in error", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							proto.HostEndpointID{EndpointId: "id1"}: "up",
							proto.HostEndpointID{EndpointId: "id2"}: "error",
						}))
					})

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor("eth0_polB"))
						It("should report id2 up only", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								proto.HostEndpointID{EndpointId: "id2"}: "up",
							}))
						})
						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id2"))
							It("should have empty dispatch chains", expectEmptyChains())
						})
					})
				})

				Context("with another host ep (<ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id0",
						ipv4Addrs: []string{ipv4},
						polName:   "polB",
					}))
					It("should have expected chains", expectChainsFor("eth0_polB"))
					It("should report id0 up, but id1 now in error", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							proto.HostEndpointID{EndpointId: "id0"}: "up",
							proto.HostEndpointID{EndpointId: "id1"}: "error",
						}))
					})

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor("eth0_polB"))
						It("should report id0 up only", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								proto.HostEndpointID{EndpointId: "id0"}: "up",
							}))
						})

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id0"))
							It("should have empty dispatch chains", expectEmptyChains())

							It("should remove all status reports", func() {
								Expect(statusReportRec.currentState).To(BeEmpty())
							})
						})
					})
				})

				Describe("replaced with untracked version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:      "id1",
						name:    "eth0",
						polName: "polA_untracked",
					}))
					It("should have expected chains", expectChainsFor("eth0_polA_untracked"))
				})

				Describe("replaced with applyOnForward version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:      "id1",
						name:    "eth0",
						polName: "polA_applyOnForward",
					}))
					It("should have expected chains", expectChainsFor("eth0_polA_applyOnForward"))
				})

				Describe("replaced with pre-DNAT version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:      "id1",
						name:    "eth0",
						polName: "polA_preDNAT",
					}))
					It("should have expected chains", expectChainsFor("eth0_polA_preDNAT"))
				})

				Describe("replaced with ingress-only version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:      "id1",
						name:    "eth0",
						polName: "polA_ingress",
					}))
					It("should have expected chains", expectChainsFor("eth0_polA_ingress"))
				})

				Describe("replaced with egress-only version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:      "id1",
						name:    "eth0",
						polName: "polA_egress",
					}))
					It("should have expected chains", expectChainsFor("eth0_polA_egress"))
				})
			})

			Describe("with host endpoint with untracked tier matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:      "id1",
					name:    "eth0",
					polName: "polA_untracked",
				}))
				It("should have expected chains", expectChainsFor("eth0_polA_untracked"))

				Context("with another host ep (<ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id0",
						ipv4Addrs: []string{ipv4},
						polName:   "polB_untracked",
					}))

					It("should have expected chains", expectChainsFor("eth0_polB_untracked"))

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor("eth0_polB_untracked"))

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id0"))
							It("should have empty dispatch chains", expectEmptyChains())
						})
					})
				})

				Describe("replaced with a tracked version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:      "id1",
						name:    "eth0",
						polName: "polA",
					}))
					It("should have expected chains", expectChainsFor("eth0_polA"))
				})
			})

			Context("with a host ep that matches the IPv4 address with untracked policy", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id0",
					ipv4Addrs: []string{ipv4},
					polName:   "polB_untracked",
				}))

				It("should have expected chains", expectChainsFor("eth0_polB_untracked"))
			})

			Describe("with host endpoint with applyOnForward tier matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:      "id1",
					name:    "eth0",
					polName: "polA_applyOnForward",
				}))
				It("should have expected chains", expectChainsFor("eth0_polA_applyOnForward"))

				Context("with another host ep (<ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id0",
						ipv4Addrs: []string{ipv4},
						polName:   "polB_applyOnForward",
					}))

					It("should have expected chains", expectChainsFor("eth0_polB_applyOnForward"))

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor("eth0_polB_applyOnForward"))

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id0"))
							It("should have empty dispatch chains", expectEmptyChains())
						})
					})
				})

				Describe("replaced with a tracked version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:      "id1",
						name:    "eth0",
						polName: "polA",
					}))
					It("should have expected chains", expectChainsFor("eth0_polA"))
				})
			})

			Context("with a host ep that matches the IPv4 address with applyOnForward policy", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id0",
					ipv4Addrs: []string{ipv4},
					polName:   "polB_applyOnForward",
				}))

				It("should have expected chains", expectChainsFor("eth0_polB_applyOnForward"))
			})

			Describe("with host endpoint with pre-DNAT tier matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:      "id1",
					name:    "eth0",
					polName: "polA_preDNAT",
				}))
				It("should have expected chains", expectChainsFor("eth0_polA_preDNAT"))

				Context("with another host ep (<ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id0",
						ipv4Addrs: []string{ipv4},
						polName:   "polB_preDNAT",
					}))

					It("should have expected chains", expectChainsFor("eth0_polB_preDNAT"))

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor("eth0_polB_preDNAT"))

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id0"))
							It("should have empty dispatch chains", expectEmptyChains())
						})
					})
				})

				Describe("replaced with a tracked version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:      "id1",
						name:    "eth0",
						polName: "polA",
					}))
					It("should have expected chains", expectChainsFor("eth0_polA"))
				})
			})

			Context("with a host ep that matches the IPv4 address with pre-DNAT policy", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id0",
					ipv4Addrs: []string{ipv4},
					polName:   "polB_preDNAT",
				}))

				It("should have expected chains", expectChainsFor("eth0_polB_preDNAT"))
			})

			Describe("with host endpoint matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:   "id1",
					name: "eth0",
				}))
				It("should have expected chains", expectChainsFor("eth0"))
				It("should report id1 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id1"}: "up",
					}))
				})

				Context("with another host interface eth1", func() {
					JustBeforeEach(func() {
						epMgr.OnUpdate(&ifaceUpdate{
							Name:  "eth1",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth1",
							Addrs: eth1Addrs,
						})
						epMgr.CompleteDeferredWork()
					})

					It("should have expected chains", expectChainsFor("eth0"))
					It("should report id1 up", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							proto.HostEndpointID{EndpointId: "id1"}: "up",
						}))
					})

					Context("with host ep matching eth1's IP", func() {
						JustBeforeEach(configureHostEp(&hostEpSpec{
							id:        "id22",
							ipv4Addrs: []string{ipv4Eth1},
						}))
						It("should have expected chains", expectChainsFor("eth0", "eth1"))
						It("should report id1 and id22 up", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								proto.HostEndpointID{EndpointId: "id1"}:  "up",
								proto.HostEndpointID{EndpointId: "id22"}: "up",
							}))
						})
					})

					Context("with host ep matching both eth0 and eth1 IPs", func() {
						JustBeforeEach(configureHostEp(&hostEpSpec{
							id:        "id0",
							ipv4Addrs: []string{ipv4Eth1, ipv4},
						}))
						It("should have expected chains", expectChainsFor("eth0", "eth1"))
						// The "id0" host endpoint matches both eth0 and
						// eth1, and is preferred for eth0 over "id1"
						// because of alphabetical ordering.  "id1" is then
						// unused, and so reported as in error.
						It("should report id1 error and id0 up", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								proto.HostEndpointID{EndpointId: "id1"}: "error",
								proto.HostEndpointID{EndpointId: "id0"}: "up",
							}))
						})
					})

					Context("with host ep matching eth1", func() {
						JustBeforeEach(configureHostEp(&hostEpSpec{
							id:   "id22",
							name: "eth1",
						}))
						It("should have expected chains", expectChainsFor("eth0", "eth1"))
						It("should report id1 and id22 up", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								proto.HostEndpointID{EndpointId: "id1"}:  "up",
								proto.HostEndpointID{EndpointId: "id22"}: "up",
							}))
						})
					})
				})
			})

			Describe("with host endpoint matching non-existent interface", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:   "id3",
					name: "eth1",
				}))
				It("should have empty dispatch chains", expectEmptyChains())
				It("should report endpoint in error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id3"}: "error",
					}))
				})
			})

			Describe("with host endpoint matching IPv4 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id4",
					ipv4Addrs: []string{ipv4},
				}))
				It("should have expected chains", expectChainsFor("eth0"))
				It("should report id4 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id4"}: "up",
					}))
				})
			})

			Describe("with host endpoint matching IPv6 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id5",
					ipv6Addrs: []string{ipv6},
				}))
				It("should have expected chains", expectChainsFor("eth0"))
				It("should report id5 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id5"}: "up",
					}))
				})
			})

			Describe("with host endpoint matching IPv4 address and correct interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth0",
					ipv4Addrs: []string{ipv4},
				}))
				It("should have expected chains", expectChainsFor("eth0"))
				It("should report id3 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id3"}: "up",
					}))
				})
			})

			Describe("with host endpoint matching IPv6 address and correct interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth0",
					ipv6Addrs: []string{ipv6},
				}))
				It("should have expected chains", expectChainsFor("eth0"))
				It("should report id3 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id3"}: "up",
					}))
				})
			})

			Describe("with host endpoint matching IPv4 address and wrong interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth1",
					ipv4Addrs: []string{ipv4},
				}))
				It("should have empty dispatch chains", expectEmptyChains())
				It("should report id3 error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id3"}: "error",
					}))
				})
			})

			Describe("with host endpoint matching IPv6 address and wrong interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth1",
					ipv6Addrs: []string{ipv6},
				}))
				It("should have empty dispatch chains", expectEmptyChains())
				It("should report id3 error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id3"}: "error",
					}))
				})
			})

			Describe("with host endpoint with unmatched IPv4 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id4",
					ipv4Addrs: []string{"8.8.8.8"},
				}))
				It("should have empty dispatch chains", expectEmptyChains())
				It("should report id4 error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id4"}: "error",
					}))
				})
			})

			Describe("with host endpoint with unmatched IPv6 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id5",
					ipv6Addrs: []string{"fe08::2"},
				}))
				It("should have empty dispatch chains", expectEmptyChains())
				It("should report id5 error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id5"}: "error",
					}))
				})
			})

		})

		Context("with host endpoint configured before interface signaled", func() {
			JustBeforeEach(configureHostEp(&hostEpSpec{
				id:   "id3",
				name: "eth0",
			}))
			It("should have empty dispatch chains", expectEmptyChains())
			It("should report id3 error", func() {
				Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
					proto.HostEndpointID{EndpointId: "id3"}: "error",
				}))
			})

			Context("with interface signaled", func() {
				JustBeforeEach(func() {
					epMgr.OnUpdate(&ifaceUpdate{
						Name:  "eth0",
						State: "up",
					})
					epMgr.OnUpdate(&ifaceAddrsUpdate{
						Name:  "eth0",
						Addrs: eth0Addrs,
					})
					epMgr.CompleteDeferredWork()
				})
				It("should have expected chains", expectChainsFor("eth0"))
				It("should report id3 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						proto.HostEndpointID{EndpointId: "id3"}: "up",
					}))
				})
			})
		})

		expectWlChainsFor := func(names ...string) func() {
			return func() {
				filterTable.checkChains([][]*iptables.Chain{
					hostDispatchEmptyNormal,
					hostDispatchEmptyForward,
					wlChainsForIfaces(names, epMgr.epMarkMapper),
				})
				mangleTable.checkChains([][]*iptables.Chain{
					fromHostDispatchEmpty,
				})
			}
		}

		Describe("workload endpoints", func() {

			Context("with a workload endpoint", func() {
				wlEPID1 := proto.WorkloadEndpointID{
					OrchestratorId: "k8s",
					WorkloadId:     "pod-11",
					EndpointId:     "endpoint-id-11",
				}
				var tiers []*proto.TierInfo

				BeforeEach(func() {
					tiers = []*proto.TierInfo{}
				})

				JustBeforeEach(func() {
					epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
						Id: &wlEPID1,
						Endpoint: &proto.WorkloadEndpoint{
							State:      "active",
							Mac:        "01:02:03:04:05:06",
							Name:       "cali12345-ab",
							ProfileIds: []string{},
							Tiers:      tiers,
							Ipv4Nets:   []string{"10.0.240.2/24"},
							Ipv6Nets:   []string{"2001:db8:2::2/128"},
						},
					})
					epMgr.CompleteDeferredWork()
				})

				Context("with policy", func() {
					BeforeEach(func() {
						tiers = []*proto.TierInfo{&proto.TierInfo{
							Name:            "default",
							IngressPolicies: []string{"policy1"},
							EgressPolicies:  []string{"policy1"},
						}}
					})

					It("should have expected chains", expectWlChainsFor("cali12345-ab_policy1"))
				})

				Context("with ingress-only policy", func() {
					BeforeEach(func() {
						tiers = []*proto.TierInfo{&proto.TierInfo{
							Name:            "default",
							IngressPolicies: []string{"policy1"},
						}}
					})

					It("should have expected chains", expectWlChainsFor("cali12345-ab_policy1_ingress"))
				})

				Context("with egress-only policy", func() {
					BeforeEach(func() {
						tiers = []*proto.TierInfo{&proto.TierInfo{
							Name:           "default",
							EgressPolicies: []string{"policy1"},
						}}
					})

					It("should have expected chains", expectWlChainsFor("cali12345-ab_policy1_egress"))
				})

				It("should have expected chains", expectWlChainsFor("cali12345-ab"))

				It("should set routes", func() {
					if ipVersion == 6 {
						routeTable.checkRoutes("cali12345-ab", []routetable.Target{{
							CIDR:    ip.MustParseCIDROrIP("2001:db8:2::2/128"),
							DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
						}})
					} else {
						routeTable.checkRoutes("cali12345-ab", []routetable.Target{{
							CIDR:    ip.MustParseCIDROrIP("10.0.240.0/24"),
							DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
						}})
					}
				})
				It("should report endpoint down", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						wlEPID1: "down",
					}))
				})

				Context("with updates for the workload's iface and proc/sys failure", func() {
					JustBeforeEach(func() {
						mockProcSys.Fail = true
						epMgr.OnUpdate(&ifaceUpdate{
							Name:  "cali12345-ab",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "cali12345-ab",
							Addrs: set.New(),
						})
						epMgr.CompleteDeferredWork()
					})
					It("should report the interface in error", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							wlEPID1: "error",
						}))
					})
				})

				Context("with updates for the workload's iface", func() {
					JustBeforeEach(func() {
						epMgr.OnUpdate(&ifaceUpdate{
							Name:  "cali12345-ab",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "cali12345-ab",
							Addrs: set.New(),
						})
						epMgr.CompleteDeferredWork()
					})

					It("should have expected chains", expectWlChainsFor("cali12345-ab"))
					It("should report endpoint up", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							wlEPID1: "up",
						}))
					})

					It("should write /proc/sys entries", func() {
						if ipVersion == 6 {
							mockProcSys.checkState(map[string]string{
								"/proc/sys/net/ipv6/conf/cali12345-ab/proxy_ndp":  "1",
								"/proc/sys/net/ipv6/conf/cali12345-ab/forwarding": "1",
							})
						} else {
							mockProcSys.checkState(map[string]string{
								"/proc/sys/net/ipv4/conf/cali12345-ab/forwarding":     "1",
								"/proc/sys/net/ipv4/conf/cali12345-ab/rp_filter":      "1",
								"/proc/sys/net/ipv4/conf/cali12345-ab/route_localnet": "1",
								"/proc/sys/net/ipv4/conf/cali12345-ab/proxy_arp":      "1",
								"/proc/sys/net/ipv4/neigh/cali12345-ab/proxy_delay":   "0",
							})
						}
					})

					Context("with floating IPs added to the endpoint", func() {
						JustBeforeEach(func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
								Id: &wlEPID1,
								Endpoint: &proto.WorkloadEndpoint{
									State:      "active",
									Mac:        "01:02:03:04:05:06",
									Name:       "cali12345-ab",
									ProfileIds: []string{},
									Tiers:      []*proto.TierInfo{},
									Ipv4Nets:   []string{"10.0.240.2/24"},
									Ipv6Nets:   []string{"2001:db8:2::2/128"},
									Ipv4Nat: []*proto.NatInfo{
										{ExtIp: "172.16.1.3", IntIp: "10.0.240.2"},
										{ExtIp: "172.18.1.4", IntIp: "10.0.240.2"},
									},
									Ipv6Nat: []*proto.NatInfo{
										{ExtIp: "2001:db8:3::2", IntIp: "2001:db8:2::2"},
										{ExtIp: "2001:db8:4::2", IntIp: "2001:db8:4::2"},
									},
								},
							})
							epMgr.CompleteDeferredWork()
						})

						It("should have expected chains", expectWlChainsFor("cali12345-ab"))

						It("should set routes", func() {
							if ipVersion == 6 {
								routeTable.checkRoutes("cali12345-ab", []routetable.Target{
									{
										CIDR:    ip.MustParseCIDROrIP("2001:db8:2::2/128"),
										DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
									},
									{
										CIDR:    ip.MustParseCIDROrIP("2001:db8:3::2/128"),
										DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
									},
									{
										CIDR:    ip.MustParseCIDROrIP("2001:db8:4::2/128"),
										DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
									},
								})
							} else {
								routeTable.checkRoutes("cali12345-ab", []routetable.Target{
									{
										CIDR:    ip.MustParseCIDROrIP("10.0.240.0/24"),
										DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
									},
									{
										CIDR:    ip.MustParseCIDROrIP("172.16.1.3/32"),
										DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
									},
									{
										CIDR:    ip.MustParseCIDROrIP("172.18.1.4/32"),
										DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
									},
								})
							}
						})
					})

					Context("with the endpoint removed", func() {
						JustBeforeEach(func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
								Id: &wlEPID1,
							})
							epMgr.CompleteDeferredWork()
						})

						It("should have empty dispatch chains", expectEmptyChains())

						It("should have removed routes", func() {
							routeTable.checkRoutes("cali12345-ab", nil)
						})
						It("should report endpoint gone", func() {
							Expect(statusReportRec.currentState).To(BeEmpty())
						})
					})

					Context("changing the endpoint to another up interface", func() {
						JustBeforeEach(func() {
							epMgr.OnUpdate(&ifaceUpdate{
								Name:  "cali12345-cd",
								State: "up",
							})
							epMgr.OnUpdate(&ifaceAddrsUpdate{
								Name:  "cali12345-cd",
								Addrs: set.New(),
							})
							epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
								Id: &wlEPID1,
								Endpoint: &proto.WorkloadEndpoint{
									State:      "active",
									Mac:        "01:02:03:04:05:06",
									Name:       "cali12345-cd",
									ProfileIds: []string{},
									Tiers:      []*proto.TierInfo{},
									Ipv4Nets:   []string{"10.0.240.2/24"},
									Ipv6Nets:   []string{"2001:db8:2::2/128"},
								},
							})
							epMgr.CompleteDeferredWork()
						})

						It("should have expected chains", expectWlChainsFor("cali12345-cd"))

						It("should have removed routes for old iface", func() {
							routeTable.checkRoutes("cali12345-ab", nil)
						})
						It("should report endpoint up", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								wlEPID1: "up",
							}))
						})

						It("should have set routes for new iface", func() {
							if ipVersion == 6 {
								routeTable.checkRoutes("cali12345-cd", []routetable.Target{{
									CIDR:    ip.MustParseCIDROrIP("2001:db8:2::2/128"),
									DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
								}})
							} else {
								routeTable.checkRoutes("cali12345-cd", []routetable.Target{{
									CIDR:    ip.MustParseCIDROrIP("10.0.240.0/24"),
									DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
								}})
							}
						})
					})
				})
			})

			Context("with an inactive workload endpoint", func() {
				wlEPID1 := proto.WorkloadEndpointID{
					OrchestratorId: "k8s",
					WorkloadId:     "pod-11",
					EndpointId:     "endpoint-id-11",
				}
				JustBeforeEach(func() {
					epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
						Id: &wlEPID1,
						Endpoint: &proto.WorkloadEndpoint{
							State:      "inactive",
							Mac:        "01:02:03:04:05:06",
							Name:       "cali12345-ab",
							ProfileIds: []string{},
							Tiers:      []*proto.TierInfo{},
							Ipv4Nets:   []string{"10.0.240.2/24"},
							Ipv6Nets:   []string{"2001:db8:2::2/128"},
						},
					})
					epMgr.CompleteDeferredWork()
				})

				It("should have expected chains", func() {
					Expect(filterTable.currentChains["cali-tw-cali12345-ab"]).To(Equal(
						&iptables.Chain{
							Name: "cali-tw-cali12345-ab",
							Rules: []iptables.Rule{{
								Action:  iptables.DropAction{},
								Comment: "Endpoint admin disabled",
							}},
						},
					))
					Expect(filterTable.currentChains["cali-fw-cali12345-ab"]).To(Equal(
						&iptables.Chain{
							Name: "cali-fw-cali12345-ab",
							Rules: []iptables.Rule{{
								Action:  iptables.DropAction{},
								Comment: "Endpoint admin disabled",
							}},
						},
					))
					_, ok := mangleTable.currentChains["cali-tw-cali12345-ab"]
					Expect(ok).To(BeFalse())
					_, ok = mangleTable.currentChains["cali-fw-cali12345-ab"]
					Expect(ok).To(BeFalse())
				})

				It("should remove routes", func() {
					routeTable.checkRoutes("cali12345-ab", nil)
				})
			})
		})
	}
}

var _ = Describe("EndpointManager IPv4", endpointManagerTests(4))

var _ = Describe("EndpointManager IPv6", endpointManagerTests(6))

type testProcSys struct {
	state map[string]string
	Fail  bool
}

var (
	procSysFail = errors.New("mock proc sys failure")
)

func (t *testProcSys) write(path, value string) error {
	log.WithFields(log.Fields{
		"path":  path,
		"value": value,
	}).Info("testProcSys writer")
	if t.Fail {
		return procSysFail
	}
	t.state[path] = value
	return nil
}

func (t *testProcSys) checkState(expected map[string]string) {
	Expect(t.state).To(Equal(expected))
}
