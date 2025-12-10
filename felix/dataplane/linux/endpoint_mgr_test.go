// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/linkaddrs"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/testutils"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var wlDispatchEmpty = []*generictables.Chain{
	{
		Name: "cali-to-wl-dispatch",
		Rules: []generictables.Rule{
			{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown interface"},
			},
		},
	},
	{
		Name: "cali-from-wl-dispatch",
		Rules: []generictables.Rule{
			{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown interface"},
			},
		},
	},
	{
		Name: "cali-from-endpoint-mark",
		Rules: []generictables.Rule{
			{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown interface"},
			},
		},
	},
	{
		Name: "cali-set-endpoint-mark",
		Rules: []generictables.Rule{
			{
				Match:   iptables.Match().InInterface("cali+"),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown endpoint"},
			},
			{
				Match:   iptables.Match().InInterface("tap+"),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown endpoint"},
			},
			{
				Match:   iptables.Match(),
				Action:  iptables.SetMaskedMarkAction{Mark: 0x0100, Mask: 0xff00},
				Comment: []string{"Non-Cali endpoint mark"},
			},
		},
	},
}

var hostDispatchEmptyNormal = []*generictables.Chain{
	{
		Name:  "cali-to-host-endpoint",
		Rules: []generictables.Rule{},
	},
	{
		Name:  "cali-from-host-endpoint",
		Rules: []generictables.Rule{},
	},
}

var hostDispatchEmptyForward = []*generictables.Chain{
	{
		Name:  "cali-to-hep-forward",
		Rules: []generictables.Rule{},
	},
	{
		Name:  "cali-from-hep-forward",
		Rules: []generictables.Rule{},
	},
}

var fromHostDispatchEmpty = []*generictables.Chain{
	{
		Name:  "cali-from-host-endpoint",
		Rules: []generictables.Rule{},
	},
}

var toHostDispatchEmpty = []*generictables.Chain{
	{
		Name:  "cali-to-host-endpoint",
		Rules: []generictables.Rule{},
	},
}

var wlEPID1 = proto.WorkloadEndpointID{
	OrchestratorId: "k8s",
	WorkloadId:     "pod-11",
	EndpointId:     "endpoint-id-11",
}

var wlEPID2 = proto.WorkloadEndpointID{
	OrchestratorId: "k8s",
	WorkloadId:     "pod-12",
	EndpointId:     "endpoint-id-12",
}

func hostChainsForIfaces(ipVersion uint8, ifaceTierNames []string, epMarkMapper rules.EndpointMarkMapper, flowlogs bool) []*generictables.Chain {
	return append(chainsForIfaces(ipVersion, ifaceTierNames, epMarkMapper, true, "normal", false, flowlogs, iptables.AcceptAction{}),
		chainsForIfaces(ipVersion, ifaceTierNames, epMarkMapper, true, "applyOnForward", false, flowlogs, iptables.AcceptAction{})...,
	)
}

func mangleEgressChainsForIfaces(ipVersion uint8, ifaceTierNames []string, epMarkMapper rules.EndpointMarkMapper, flowlogs bool) []*generictables.Chain {
	return chainsForIfaces(ipVersion, ifaceTierNames, epMarkMapper, true, "normal", true, flowlogs, iptables.SetMarkAction{Mark: 0x8}, iptables.ReturnAction{})
}

func rawChainsForIfaces(ipVersion uint8, ifaceTierNames []string, epMarkMapper rules.EndpointMarkMapper, flowlogs bool) []*generictables.Chain {
	return chainsForIfaces(ipVersion, ifaceTierNames, epMarkMapper, true, "untracked", false, flowlogs, iptables.AcceptAction{})
}

func preDNATChainsForIfaces(ipVersion uint8, ifaceTierNames []string, epMarkMapper rules.EndpointMarkMapper, flowlogs bool) []*generictables.Chain {
	return chainsForIfaces(ipVersion, ifaceTierNames, epMarkMapper, true, "preDNAT", false, flowlogs, iptables.AcceptAction{})
}

func wlChainsForIfaces(ipVersion uint8, ifaceTierNames []string, epMarkMapper rules.EndpointMarkMapper, flowlogs bool) []*generictables.Chain {
	return chainsForIfaces(ipVersion, ifaceTierNames, epMarkMapper, false, "normal", false, flowlogs, iptables.AcceptAction{})
}

func tierToPolicyName(tierName string) string {
	if strings.HasPrefix(tierName, "tier") {
		return "pol" + strings.TrimPrefix(tierName, "tier")
	}
	return "a"
}

func chainsForIfaces(ipVersion uint8,
	ifaceTierNames []string,
	epMarkMapper rules.EndpointMarkMapper,
	host bool,
	tableKind string,
	egressOnly bool,
	flowlogs bool,
	allowActions ...generictables.Action,
) []*generictables.Chain {
	const (
		ProtoUDP  = 17
		ProtoTCP  = 6
		ProtoIPIP = 4
		VXLANPort = 4789
	)

	log.WithFields(log.Fields{
		"ifaces":    ifaceTierNames,
		"host":      host,
		"tableKind": tableKind,
	}).Debug("Calculating chains for interface")

	chains := []*generictables.Chain{}
	dispatchOut := []generictables.Rule{}
	dispatchIn := []generictables.Rule{}
	epMarkSet := []generictables.Rule{}
	epMarkFrom := []generictables.Rule{}
	hostOrWlLetter := "w"
	hostOrWlDispatch := "wl-dispatch"
	outPrefix := "cali-from-"
	inPrefix := "cali-to-"
	inboundGroup := uint16(1)
	outboundGroup := uint16(2)
	epMarkSetName := "cali-set-endpoint-mark"
	epMarkFromName := "cali-from-endpoint-mark"
	epMarkSetOnePrefix := "cali-sm-"
	epmarkFromPrefix := outPrefix[:6]
	dropEncapRules := []generictables.Rule{
		{
			Match: iptables.Match().ProtocolNum(ProtoUDP).
				DestPorts(uint16(VXLANPort)),
			Action:  iptables.DropAction{},
			Comment: []string{"Drop VXLAN encapped packets originating in workloads"},
		},
		{
			Match:   iptables.Match().ProtocolNum(ProtoIPIP),
			Action:  iptables.DropAction{},
			Comment: []string{"Drop IPinIP encapped packets originating in workloads"},
		},
	}

	if host {
		hostOrWlLetter = "h"
		hostOrWlDispatch = "host-endpoint"
		if tableKind == "applyOnForward" {
			hostOrWlLetter = "hfw"
			hostOrWlDispatch = "hep-forward"
		}
		outPrefix = "cali-to-"
		inPrefix = "cali-from-"
		inboundGroup = uint16(1)
		outboundGroup = uint16(2)
		epmarkFromPrefix = inPrefix[:6]
	}
	for _, ifaceTierName := range ifaceTierNames {
		var ifaceName, tierName, polName string
		nameParts := strings.Split(ifaceTierName, "_")
		ifaceKind := "normal"
		ingress := true
		egress := true
		if len(nameParts) == 1 {
			// Just an interface name "eth0", apply no tweaks.
			ifaceName = nameParts[0]
			tierName = ""
			polName = ""
		} else if len(nameParts) == 2 {
			// Interface name and a policy name  "eth0_tierA".
			ifaceName = nameParts[0]
			if strings.HasPrefix(nameParts[1], "pol") {
				tierName = "default"
				polName = nameParts[1]
			} else {
				tierName = nameParts[1]
				polName = tierToPolicyName(tierName)
			}
			ifaceKind = "normal"
		} else {
			// Interface name, policy name and untracked "eth0_polA_untracked"
			// or applyOnForward "eth0_polA_applyOnForward".
			log.Debug("Interface name policy name and untracked/ingress/egress")
			ifaceName = nameParts[0]
			if strings.HasPrefix(nameParts[1], "pol") {
				tierName = "default"
				polName = nameParts[1]
			} else {
				tierName = nameParts[1]
				polName = tierToPolicyName(tierName)
			}
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
				"ifaces":    ifaceTierNames,
				"host":      host,
				"tableKind": tableKind,
			}).Debug("Failed to get endpoint mark for interface")
			continue
		}

		if tableKind != ifaceKind && tableKind != "normal" && tableKind != "applyOnForward" {
			continue
		}

		outRules := []generictables.Rule{}

		if tableKind != "untracked" {
			for _, allowAction := range allowActions {
				outRules = append(outRules,
					generictables.Rule{
						Match:  iptables.Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: allowAction,
					},
				)
			}
			outRules = append(outRules, generictables.Rule{
				Match:  iptables.Match().ConntrackState("INVALID"),
				Action: iptables.DropAction{},
			})
		}

		if host && tableKind != "applyOnForward" {
			outRules = append(outRules, generictables.Rule{
				Match:  iptables.Match(),
				Action: iptables.JumpAction{Target: "cali-failsafe-out"},
			})
		}
		outRules = append(outRules, generictables.Rule{
			Match:  iptables.Match(),
			Action: iptables.ClearMarkAction{Mark: 0x18}, // IptablesMarkAccept + IptablesMarkPass
		})

		if !host {
			outRules = append(outRules, dropEncapRules...)
		}
		if egress && polName != "" && tierName != "" && tableKind == ifaceKind {
			outRules = append(outRules, generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.ClearMarkAction{Mark: 16},
				Comment: []string{"Start of tier " + tierName},
			})

			// Determine the policy chain name.
			target := rules.PolicyChainName(
				"cali-po-",
				&types.PolicyID{Name: polName, Kind: v3.KindGlobalNetworkPolicy},
				false,
			)
			outRules = append(outRules, generictables.Rule{
				Match:  iptables.Match().MarkClear(16),
				Action: iptables.JumpAction{Target: target},
			})
			if tableKind == "untracked" {
				outRules = append(outRules, generictables.Rule{
					Match:  iptables.Match().MarkSingleBitSet(8),
					Action: iptables.NoTrackAction{},
				})
			}
			outRules = append(outRules, generictables.Rule{
				Match:   iptables.Match().MarkSingleBitSet(8),
				Action:  iptables.ReturnAction{},
				Comment: []string{"Return if policy accepted"},
			})
			if tableKind == "normal" || tableKind == "applyOnForward" {
				// Only end with a drop rule in the filter chain.  In the raw chain,
				// we consider the policy as unfinished, because some of the
				// policy may live in the filter chain.
				if flowlogs {
					outRules = append(outRules, []generictables.Rule{
						{
							Match: iptables.Match().MarkClear(16),
							Action: iptables.NflogAction{
								Group:  outboundGroup,
								Prefix: fmt.Sprintf("DPE|%s", tierName),
							},
						},
					}...)
				}

				outRules = append(outRules, []generictables.Rule{
					{
						Match:   iptables.Match().MarkClear(16),
						Action:  iptables.DropAction{},
						Comment: []string{fmt.Sprintf("End of tier %v. Drop if no policies passed packet", tierName)},
					},
				}...)
			}

		} else if tableKind == "applyOnForward" {
			// Expect forwarded traffic to be allowed when there are no
			// applicable policies.
			outRules = append(outRules, generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.SetMarkAction{Mark: 8},
				Comment: []string{"Allow forwarded traffic by default"},
			})
			outRules = append(outRules, generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.ReturnAction{},
				Comment: []string{"Return for accepted forward traffic"},
			})
		}

		if tableKind == "normal" {
			if flowlogs {
				outRules = append(outRules, []generictables.Rule{
					{
						Match: iptables.Match(),
						Action: iptables.NflogAction{
							Group:  outboundGroup,
							Prefix: "DRE",
						},
					},
				}...)
			}
			outRules = append(outRules, []generictables.Rule{
				{
					Match:   iptables.Match(),
					Action:  iptables.DropAction{},
					Comment: []string{"Drop if no profiles matched"},
				},
			}...)
		}

		inRules := []generictables.Rule{}

		if tableKind != "untracked" {
			for _, allowAction := range allowActions {
				inRules = append(inRules,
					generictables.Rule{
						Match:  iptables.Match().ConntrackState("RELATED,ESTABLISHED"),
						Action: allowAction,
					},
				)
			}
			inRules = append(inRules, generictables.Rule{
				Match:  iptables.Match().ConntrackState("INVALID"),
				Action: iptables.DropAction{},
			})
		}

		if host && tableKind != "applyOnForward" {
			inRules = append(inRules, generictables.Rule{
				Match:  iptables.Match(),
				Action: iptables.JumpAction{Target: "cali-failsafe-in"},
			})
		}
		inRules = append(inRules, generictables.Rule{
			Match:  iptables.Match(),
			Action: iptables.ClearMarkAction{Mark: 0x18}, // IptablesMarkAccept + IptablesMarkPass
		})

		if ingress && tierName != "" && tableKind == ifaceKind {
			inRules = append(inRules, generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.ClearMarkAction{Mark: 16},
				Comment: []string{"Start of tier " + tierName},
			})
			// For untracked policy, we expect a tier with a policy in it.
			// Determine the policy chain name.
			target := rules.PolicyChainName(
				"cali-pi-",
				&types.PolicyID{Name: polName, Kind: v3.KindGlobalNetworkPolicy},
				false,
			)
			inRules = append(inRules, generictables.Rule{
				Match:  iptables.Match().MarkClear(16),
				Action: iptables.JumpAction{Target: target},
			})
			if tableKind == "untracked" {
				inRules = append(inRules, generictables.Rule{
					Match:  iptables.Match().MarkSingleBitSet(8),
					Action: iptables.NoTrackAction{},
				})
			}
			inRules = append(inRules, generictables.Rule{
				Match:   iptables.Match().MarkSingleBitSet(8),
				Action:  iptables.ReturnAction{},
				Comment: []string{"Return if policy accepted"},
			})
			if tableKind == "normal" || tableKind == "applyOnForward" {
				// Only end with a drop rule in the filter chain.  In the raw chain,
				// we consider the policy as unfinished, because some of the
				// policy may live in the filter chain.
				if flowlogs {
					inRules = append(inRules, []generictables.Rule{
						{
							Match: iptables.Match().MarkClear(16),
							Action: iptables.NflogAction{
								Group:  inboundGroup,
								Prefix: fmt.Sprintf("DPI|%s", tierName),
							},
						},
					}...)
				}
				inRules = append(inRules, []generictables.Rule{
					{
						Match:   iptables.Match().MarkClear(16),
						Action:  iptables.DropAction{},
						Comment: []string{fmt.Sprintf("End of tier %v. Drop if no policies passed packet", tierName)},
					},
				}...)
			}

		} else if tableKind == "applyOnForward" {
			// Expect forwarded traffic to be allowed when there are no
			// applicable policies.
			inRules = append(inRules, generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.SetMarkAction{Mark: 8},
				Comment: []string{"Allow forwarded traffic by default"},
			})
			inRules = append(inRules, generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.ReturnAction{},
				Comment: []string{"Return for accepted forward traffic"},
			})
		}

		if tableKind == "normal" {
			dropComment := "Drop if no profiles matched"
			if flowlogs {
				inRules = append(inRules, []generictables.Rule{
					{
						Match: iptables.Match(),
						Action: iptables.NflogAction{
							Group:  inboundGroup,
							Prefix: "DRI",
						},
					},
				}...)
			}

			inRules = append(inRules, []generictables.Rule{
				{
					Match:   iptables.Match(),
					Action:  iptables.DropAction{},
					Comment: []string{dropComment},
				},
			}...)
		}

		if tableKind == "preDNAT" {
			chains = append(chains,
				&generictables.Chain{
					Name:  inPrefix[:6] + hostOrWlLetter + "-" + ifaceName,
					Rules: inRules,
				},
			)
		} else {
			chains = append(chains,
				&generictables.Chain{
					Name:  outPrefix[:6] + hostOrWlLetter + "-" + ifaceName,
					Rules: outRules,
				},
			)
			if !egressOnly {
				chains = append(chains,
					&generictables.Chain{
						Name:  inPrefix[:6] + hostOrWlLetter + "-" + ifaceName,
						Rules: inRules,
					},
				)
			}
		}

		if host {
			dispatchOut = append(dispatchOut,
				generictables.Rule{
					Match:  iptables.Match().OutInterface(ifaceName),
					Action: iptables.GotoAction{Target: outPrefix[:6] + hostOrWlLetter + "-" + ifaceName},
				},
			)
			if !egressOnly {
				dispatchIn = append(dispatchIn,
					generictables.Rule{
						Match:  iptables.Match().InInterface(ifaceName),
						Action: iptables.GotoAction{Target: inPrefix[:6] + hostOrWlLetter + "-" + ifaceName},
					},
				)
			}
		} else {
			dispatchOut = append(dispatchOut,
				generictables.Rule{
					Match:  iptables.Match().InInterface(ifaceName),
					Action: iptables.GotoAction{Target: outPrefix[:6] + hostOrWlLetter + "-" + ifaceName},
				},
			)
			dispatchIn = append(dispatchIn,
				generictables.Rule{
					Match:  iptables.Match().OutInterface(ifaceName),
					Action: iptables.GotoAction{Target: inPrefix[:6] + hostOrWlLetter + "-" + ifaceName},
				},
			)
		}

		if tableKind != "preDNAT" && tableKind != "untracked" && !egressOnly {
			chains = append(chains,
				&generictables.Chain{
					Name: epMarkSetOnePrefix + ifaceName,
					Rules: []generictables.Rule{
						{
							Match:  iptables.Match(),
							Action: iptables.SetMaskedMarkAction{Mark: epMark, Mask: epMarkMapper.GetMask()},
						},
					},
				},
			)
			epMarkSet = append(epMarkSet,
				generictables.Rule{
					Match:  iptables.Match().InInterface(ifaceName),
					Action: iptables.GotoAction{Target: epMarkSetOnePrefix + ifaceName},
				},
			)
			epMarkFrom = append(epMarkFrom,
				generictables.Rule{
					Match:  iptables.Match().MarkMatchesWithMask(epMark, epMarkMapper.GetMask()),
					Action: iptables.GotoAction{Target: epmarkFromPrefix + hostOrWlLetter + "-" + ifaceName},
				},
			)
		}
	}

	if !host {
		dispatchOut = append(dispatchOut,
			generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown interface"},
			},
		)
		dispatchIn = append(dispatchIn,
			generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown interface"},
			},
		)
	}

	if tableKind != "preDNAT" && tableKind != "untracked" && !egressOnly {
		epMarkSet = append(epMarkSet,
			generictables.Rule{
				Match:   iptables.Match().InInterface("cali+"),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown endpoint"},
			},
			generictables.Rule{
				Match:   iptables.Match().InInterface("tap+"),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown endpoint"},
			},
			generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.SetMaskedMarkAction{Mark: 0x0100, Mask: 0xff00},
				Comment: []string{"Non-Cali endpoint mark"},
			},
		)
		epMarkFrom = append(epMarkFrom,
			generictables.Rule{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: []string{"Unknown interface"},
			},
		)
		chains = append(chains,
			&generictables.Chain{
				Name:  epMarkSetName,
				Rules: epMarkSet,
			},
			&generictables.Chain{
				Name:  epMarkFromName,
				Rules: epMarkFrom,
			},
		)
	}

	if tableKind == "untracked" {
		chains = append(chains,
			&generictables.Chain{
				Name:  rules.ChainRpfSkip,
				Rules: []generictables.Rule{},
			},
		)
	}

	if tableKind == "preDNAT" {
		chains = append(chains,
			&generictables.Chain{
				Name:  inPrefix + hostOrWlDispatch,
				Rules: dispatchIn,
			},
		)
	} else {
		chains = append(chains,
			&generictables.Chain{
				Name:  outPrefix + hostOrWlDispatch,
				Rules: dispatchOut,
			},
		)
		if !egressOnly {
			chains = append(chains,
				&generictables.Chain{
					Name:  inPrefix + hostOrWlDispatch,
					Rules: dispatchIn,
				},
			)
		}
	}

	return chains
}

type mockRouteTable struct {
	index         int
	kernelRoutes  map[string][]routetable.Target
	currentRoutes map[string][]routetable.Target
}

func (t *mockRouteTable) SetRoutes(routeClass routetable.RouteClass, ifaceName string, targets []routetable.Target) {
	log.WithFields(log.Fields{
		"index":     t.index,
		"ifaceName": ifaceName,
		"targets":   targets,
	}).Debug("SetRoutes")
	t.currentRoutes[ifaceName] = targets
}

func (t *mockRouteTable) RouteRemove(routeClass routetable.RouteClass, ifaceName string, cidr ip.CIDR) {
}

func (t *mockRouteTable) RouteUpdate(routeClass routetable.RouteClass, ifaceName string, target routetable.Target) {
}

func (t *mockRouteTable) OnIfaceStateChanged(string, int, ifacemonitor.State) {}
func (t *mockRouteTable) QueueResync()                                        {}
func (t *mockRouteTable) QueueResyncIface(ifaceName string)                   {}

func (t *mockRouteTable) Index() int {
	return t.index
}

func (t *mockRouteTable) ReadRoutesFromKernel(ifaceName string) ([]routetable.Target, error) {
	// TODO implement me
	panic("implement me")
}

func (t *mockRouteTable) Apply() error {
	return nil
}

func (t *mockRouteTable) checkRoutes(ifaceName string, expected []routetable.Target) {
	Expect(t.currentRoutes[ifaceName]).To(ConsistOf(expected), "Expect route to exist in table %d. Current routes = %v", t.index, t.currentRoutes)
}

type statusReportRecorder struct {
	currentState map[interface{}]string
	extraInfo    map[interface{}]interface{}
}

func (r *statusReportRecorder) endpointStatusUpdateCallback(ipVersion uint8, id interface{}, status string, extraInfo interface{}) {
	log.WithFields(log.Fields{
		"ipVersion": ipVersion,
		"id":        id,
		"status":    status,
	}).Debug("endpointStatusUpdateCallback")
	if status == "" {
		delete(r.currentState, id)
		delete(r.extraInfo, id)
	} else {
		r.currentState[id] = status
		r.extraInfo[id] = extraInfo
	}
}

type hostEpSpec struct {
	id        string
	name      string
	ipv4Addrs []string
	ipv6Addrs []string
	tierName  string
}

func applyUpdates(epMgr *endpointManager) {
	err := epMgr.ResolveUpdateBatch()
	Expect(err).ToNot(HaveOccurred())
	err = epMgr.CompleteDeferredWork()
	Expect(err).ToNot(HaveOccurred())
}

func endpointManagerTests(ipVersion uint8, flowlogs bool) func() {
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
			eth0Addrs       set.Set[string]
			loAddrs         set.Set[string]
			eth1Addrs       set.Set[string]
			routeTable      *mockRouteTable
			mockProcSys     *testProcSys
			statusReportRec *statusReportRecorder
			hepListener     *testHEPListener
			nlDataplane     *mocknetlink.MockNetlinkDataplane
			linkAddrsMgr    *linkaddrs.LinkAddrsManager
			nl              netlinkshim.Interface
			err             error
		)

		BeforeEach(func() {
			rrConfigNormal = rules.Config{
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
				KubeIPVSSupportEnabled: true,
				WorkloadIfacePrefixes:  []string{"cali", "tap"},
				VXLANPort:              4789,
				VXLANVNI:               4096,
				FlowLogsEnabled:        flowlogs,
			}
			eth0Addrs = set.New[string]()
			eth0Addrs.Add(ipv4)
			eth0Addrs.Add(ipv6)
			loAddrs = set.New[string]()
			loAddrs.Add("127.0.1.1")
			loAddrs.Add("::1")
			eth1Addrs = set.New[string]()
			eth1Addrs.Add(ipv4Eth1)
		})

		JustBeforeEach(func() {
			renderer := rules.NewRenderer(rrConfigNormal)
			rawTable = newMockTable("raw")
			mangleTable = newMockTable("mangle")
			filterTable = newMockTable("filter")
			routeTable = &mockRouteTable{
				index:         0,
				currentRoutes: map[string][]routetable.Target{},
			}
			mockProcSys = &testProcSys{state: map[string]string{}, pathsThatExist: map[string]bool{}}
			statusReportRec = &statusReportRecorder{currentState: map[interface{}]string{}, extraInfo: map[interface{}]interface{}{}}
			hepListener = &testHEPListener{}
			nlDataplane = mocknetlink.New()
			Expect(err).NotTo(HaveOccurred())
			linkAddrsMgr = linkaddrs.New(
				int(ipVersion),
				[]string{"cali"},
				&environment.FakeFeatureDetector{
					Features: environment.Features{},
				},
				10*time.Second,
				linkaddrs.WithNetlinkHandleShim(nlDataplane.NewMockNetlink),
			)
			nl, err = linkAddrsMgr.GetNlHandle()
			Expect(err).NotTo(HaveOccurred())

			epMgr = newEndpointManagerWithShims(
				rawTable,
				mangleTable,
				filterTable,
				renderer,
				routeTable,
				ipVersion,
				rules.NewEndpointMarkMapper(rrConfigNormal.MarkEndpoint, rrConfigNormal.MarkNonCaliEndpoint),
				rrConfigNormal.KubeIPVSSupportEnabled,
				[]string{"cali"},
				statusReportRec.endpointStatusUpdateCallback,
				mockProcSys.write,
				mockProcSys.stat,
				"1",
				nil,
				false,
				v3.BPFAttachOptionTCX,
				hepListener,
				common.NewCallbacks(),
				true,
				false,
				linkAddrsMgr,
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
			if spec.tierName != "" {
				parts := strings.Split(spec.tierName, "_")
				var tierName string
				var policies []*proto.PolicyID
				if len(parts) == 1 {
					if strings.HasPrefix(parts[0], "pol") {
						tierName = "default"
						policies = []*proto.PolicyID{{
							Name: parts[0],
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					} else {
						tierName = parts[0]
						policies = []*proto.PolicyID{{
							Name: tierToPolicyName(tierName),
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					}
					tiers = append(tiers, &proto.TierInfo{
						Name:            tierName,
						IngressPolicies: policies,
						EgressPolicies:  policies,
					})
				} else if len(parts) == 2 && parts[1] == "untracked" {
					if strings.HasPrefix(parts[0], "pol") {
						tierName = "default"
						policies = []*proto.PolicyID{{
							Name: parts[0],
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					} else {
						tierName = parts[0]
						policies = []*proto.PolicyID{{
							Name: tierToPolicyName(tierName),
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					}
					untrackedTiers = append(untrackedTiers, &proto.TierInfo{
						Name:            tierName,
						IngressPolicies: policies,
						EgressPolicies:  policies,
					})
				} else if len(parts) == 2 && parts[1] == "preDNAT" {
					if strings.HasPrefix(parts[0], "pol") {
						tierName = "default"
						policies = []*proto.PolicyID{{
							Name: parts[0],
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					} else {
						tierName = parts[0]
						policies = []*proto.PolicyID{{
							Name: tierToPolicyName(tierName),
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					}
					preDNATTiers = append(preDNATTiers, &proto.TierInfo{
						Name:            tierName,
						IngressPolicies: policies,
					})
				} else if len(parts) == 2 && parts[1] == "applyOnForward" {
					forwardTiers = append(forwardTiers, &proto.TierInfo{
						Name:            "default",
						IngressPolicies: []*proto.PolicyID{{Name: parts[0], Kind: v3.KindGlobalNetworkPolicy}},
						EgressPolicies:  []*proto.PolicyID{{Name: parts[0], Kind: v3.KindGlobalNetworkPolicy}},
					})
				} else if len(parts) == 2 && parts[1] == "ingress" {
					if strings.HasPrefix(parts[0], "pol") {
						tierName = "default"
						policies = []*proto.PolicyID{{
							Name: parts[0],
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					} else {
						tierName = parts[0]
						policies = []*proto.PolicyID{{
							Name: tierToPolicyName(tierName),
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					}
					tiers = append(tiers, &proto.TierInfo{
						Name:            tierName,
						IngressPolicies: policies,
					})
				} else if len(parts) == 2 && parts[1] == "egress" {
					if strings.HasPrefix(parts[0], "pol") {
						tierName = "default"
						policies = []*proto.PolicyID{{
							Name: parts[0],
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					} else {
						tierName = parts[0]
						policies = []*proto.PolicyID{{
							Name: tierToPolicyName(tierName),
							Kind: v3.KindGlobalNetworkPolicy,
						}}
					}
					tiers = append(tiers, &proto.TierInfo{
						Name:           tierName,
						EgressPolicies: policies,
					})
				} else {
					panic("Failed to parse policy name " + spec.tierName)
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
				applyUpdates(epMgr)
			}
		}

		expectChainsFor := func(ipVersion uint8, flowlogs bool, names ...string) func() {
			return func() {
				filterTable.checkChains([][]*generictables.Chain{
					wlDispatchEmpty,
					hostChainsForIfaces(ipVersion, names, epMgr.epMarkMapper, flowlogs),
				})
				rawTable.checkChains([][]*generictables.Chain{
					rawChainsForIfaces(ipVersion, names, epMgr.epMarkMapper, flowlogs),
				})
				mangleTable.checkChains([][]*generictables.Chain{
					preDNATChainsForIfaces(ipVersion, names, epMgr.epMarkMapper, flowlogs),
					mangleEgressChainsForIfaces(ipVersion, names, epMgr.epMarkMapper, flowlogs),
				})
			}
		}

		expectEmptyChains := func(ipVersion uint8) func() {
			return func() {
				filterTable.checkChains([][]*generictables.Chain{
					wlDispatchEmpty,
					hostDispatchEmptyNormal,
					hostDispatchEmptyForward,
				})
				rawTable.checkChains([][]*generictables.Chain{
					hostDispatchEmptyNormal,
					{{
						Name:  "cali-rpf-skip",
						Rules: []generictables.Rule{},
					}},
				})
				mangleTable.checkChains([][]*generictables.Chain{
					fromHostDispatchEmpty,
					toHostDispatchEmpty,
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
				applyUpdates(epMgr)
			}
		}

		Context("with host interfaces eth0, lo", func() {
			JustBeforeEach(func() {
				epMgr.OnUpdate(&ifaceStateUpdate{
					Name:  "eth0",
					State: "up",
				})
				epMgr.OnUpdate(&ifaceAddrsUpdate{
					Name:  "eth0",
					Addrs: eth0Addrs,
				})
				epMgr.OnUpdate(&ifaceStateUpdate{
					Name:  "lo",
					State: "up",
				})
				epMgr.OnUpdate(&ifaceAddrsUpdate{
					Name:  "lo",
					Addrs: loAddrs,
				})
				applyUpdates(epMgr)
			})

			It("should have empty dispatch chains", expectEmptyChains(ipVersion))
			It("should make no status reports", func() {
				Expect(statusReportRec.currentState).To(BeEmpty())
			})

			Describe("with * host endpoint", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:       "id1",
					name:     "*",
					tierName: "polA",
				}))

				It("should report id1 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id1"}: "up",
					}))
				})

				It("should define host endpoints", func() {
					Expect(hepListener.state).To(Equal(map[string]string{
						"any-interface-at-all": "profiles=,normal=I=polA,E=polA,untracked=,preDNAT=,AoF=",
					}))
				})
			})

			// Configure host endpoints with tier names here, so we can check which of
			// the host endpoints gets used in the programming for a particular host
			// interface.  When more than one host endpoint matches a given interface,
			// we expect the one used to be the one with the alphabetically earliest ID.
			Describe("with host endpoint with tier matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:       "id1",
					name:     "eth0",
					tierName: "tierA",
				}))
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierA"))
				It("should report id1 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id1"}: "up",
					}))
				})

				It("should define host endpoints", func() {
					Expect(hepListener.state).To(Equal(map[string]string{
						"eth0": "profiles=,normal=I=polA,E=polA,untracked=,preDNAT=,AoF=",
					}))
				})

				Context("with another host ep (>ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id2",
						ipv4Addrs: []string{ipv4},
						tierName:  "tierB",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierA"))
					It("should report id1 up, but id2 now in error", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							types.HostEndpointID{EndpointId: "id1"}: "up",
							types.HostEndpointID{EndpointId: "id2"}: "error",
						}))
					})

					It("should define host endpoints", func() {
						Expect(hepListener.state).To(Equal(map[string]string{
							"eth0": "profiles=,normal=I=polA,E=polA,untracked=,preDNAT=,AoF=",
						}))
					})

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierB"))
						It("should report id2 up only", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								types.HostEndpointID{EndpointId: "id2"}: "up",
							}))
						})

						It("should define host endpoints", func() {
							Expect(hepListener.state).To(Equal(map[string]string{
								"eth0": "profiles=,normal=I=polB,E=polB,untracked=,preDNAT=,AoF=",
							}))
						})

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id2"))
							It("should have empty dispatch chains", expectEmptyChains(ipVersion))

							It("should define host endpoints", func() {
								Expect(hepListener.state).To(BeEmpty())
							})
						})
					})
				})

				Context("with another host ep (<ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id0",
						ipv4Addrs: []string{ipv4},
						tierName:  "tierB",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierB"))
					It("should report id0 up, but id1 now in error", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							types.HostEndpointID{EndpointId: "id0"}: "up",
							types.HostEndpointID{EndpointId: "id1"}: "error",
						}))
					})

					It("should define host endpoints", func() {
						Expect(hepListener.state).To(Equal(map[string]string{
							"eth0": "profiles=,normal=I=polB,E=polB,untracked=,preDNAT=,AoF=",
						}))
					})

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierB"))
						It("should report id0 up only", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								types.HostEndpointID{EndpointId: "id0"}: "up",
							}))
						})

						It("should define host endpoints", func() {
							Expect(hepListener.state).To(Equal(map[string]string{
								"eth0": "profiles=,normal=I=polB,E=polB,untracked=,preDNAT=,AoF=",
							}))
						})

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id0"))
							It("should have empty dispatch chains", expectEmptyChains(ipVersion))

							It("should remove all status reports", func() {
								Expect(statusReportRec.currentState).To(BeEmpty())
							})

							It("should define host endpoints", func() {
								Expect(hepListener.state).To(BeEmpty())
							})
						})
					})
				})

				Describe("replaced with untracked version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:       "id1",
						name:     "eth0",
						tierName: "tierA_untracked",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierA_untracked"))

					It("should define host endpoints", func() {
						Expect(hepListener.state).To(Equal(map[string]string{
							"eth0": "profiles=,normal=,untracked=I=polA,E=polA,preDNAT=,AoF=",
						}))
					})
				})

				Describe("replaced with applyOnForward version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:       "id1",
						name:     "eth0",
						tierName: "polA_applyOnForward",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polA_applyOnForward"))

					It("should define host endpoints", func() {
						Expect(hepListener.state).To(Equal(map[string]string{
							"eth0": "profiles=,normal=,untracked=,preDNAT=,AoF=I=polA,E=polA",
						}))
					})
				})

				Describe("replaced with pre-DNAT version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:       "id1",
						name:     "eth0",
						tierName: "polA_preDNAT",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polA_preDNAT"))

					It("should define host endpoints", func() {
						Expect(hepListener.state).To(Equal(map[string]string{
							"eth0": "profiles=,normal=,untracked=,preDNAT=I=polA,E=,AoF=",
						}))
					})
				})

				Describe("replaced with ingress-only version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:       "id1",
						name:     "eth0",
						tierName: "polA_ingress",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polA_ingress"))

					It("should define host endpoints", func() {
						Expect(hepListener.state).To(Equal(map[string]string{
							"eth0": "profiles=,normal=I=polA,E=,untracked=,preDNAT=,AoF=",
						}))
					})
				})

				Describe("replaced with egress-only version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:       "id1",
						name:     "eth0",
						tierName: "polA_egress",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polA_egress"))

					It("should define host endpoints", func() {
						Expect(hepListener.state).To(Equal(map[string]string{
							"eth0": "profiles=,normal=I=,E=polA,untracked=,preDNAT=,AoF=",
						}))
					})
				})
			})

			Describe("with host endpoint with untracked tier matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:       "id1",
					name:     "eth0",
					tierName: "tierA_untracked",
				}))
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierA_untracked"))

				Context("with another host ep (<ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id0",
						ipv4Addrs: []string{ipv4},
						tierName:  "tierB_untracked",
					}))

					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierB_untracked"))

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierB_untracked"))

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id0"))
							It("should have empty dispatch chains", expectEmptyChains(ipVersion))
						})
					})
				})

				Describe("replaced with a tracked version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:       "id1",
						name:     "eth0",
						tierName: "tierA",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierA"))
				})
			})

			Context("with a host ep that matches the IPv4 address with untracked policy", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id0",
					ipv4Addrs: []string{ipv4},
					tierName:  "tierB_untracked",
				}))

				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_tierB_untracked"))
			})

			Describe("with host endpoint with applyOnForward tier matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:       "id1",
					name:     "eth0",
					tierName: "polA_applyOnForward",
				}))
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polA_applyOnForward"))

				Context("with another host ep (<ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id0",
						ipv4Addrs: []string{ipv4},
						tierName:  "polB_applyOnForward",
					}))

					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polB_applyOnForward"))

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polB_applyOnForward"))

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id0"))
							It("should have empty dispatch chains", expectEmptyChains(ipVersion))
						})
					})
				})

				Describe("replaced with a tracked version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:       "id1",
						name:     "eth0",
						tierName: "polA",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polA"))
				})
			})

			Context("with a host ep that matches the IPv4 address with applyOnForward policy", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id0",
					ipv4Addrs: []string{ipv4},
					tierName:  "polB_applyOnForward",
				}))

				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polB_applyOnForward"))
			})

			Describe("with host endpoint with pre-DNAT tier matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:       "id1",
					name:     "eth0",
					tierName: "polA_preDNAT",
				}))
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polA_preDNAT"))

				Context("with another host ep (<ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id0",
						ipv4Addrs: []string{ipv4},
						tierName:  "polB_preDNAT",
					}))

					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polB_preDNAT"))

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polB_preDNAT"))

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id0"))
							It("should have empty dispatch chains", expectEmptyChains(ipVersion))
						})
					})
				})

				Describe("replaced with a tracked version", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:       "id1",
						name:     "eth0",
						tierName: "polA",
					}))
					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polA"))
				})
			})

			Context("with a host ep that matches the IPv4 address with pre-DNAT policy", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id0",
					ipv4Addrs: []string{ipv4},
					tierName:  "polB_preDNAT",
				}))

				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0_polB_preDNAT"))
			})

			Describe("with host endpoint matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:   "id1",
					name: "eth0",
				}))
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0"))
				It("should report id1 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id1"}: "up",
					}))
				})

				Context("with another host interface eth1", func() {
					JustBeforeEach(func() {
						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth1",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth1",
							Addrs: eth1Addrs,
						})
						applyUpdates(epMgr)
					})

					It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0"))
					It("should report id1 up", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							types.HostEndpointID{EndpointId: "id1"}: "up",
						}))
					})

					Context("with host ep matching eth1's IP", func() {
						JustBeforeEach(configureHostEp(&hostEpSpec{
							id:        "id22",
							ipv4Addrs: []string{ipv4Eth1},
						}))
						It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0", "eth1"))
						It("should report id1 and id22 up", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								types.HostEndpointID{EndpointId: "id1"}:  "up",
								types.HostEndpointID{EndpointId: "id22"}: "up",
							}))
						})
					})

					Context("with host ep matching both eth0 and eth1 IPs", func() {
						JustBeforeEach(configureHostEp(&hostEpSpec{
							id:        "id0",
							ipv4Addrs: []string{ipv4Eth1, ipv4},
						}))
						It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0", "eth1"))
						// The "id0" host endpoint matches both eth0 and
						// eth1, and is preferred for eth0 over "id1"
						// because of alphabetical ordering.  "id1" is then
						// unused, and so reported as in error.
						It("should report id1 error and id0 up", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								types.HostEndpointID{EndpointId: "id1"}: "error",
								types.HostEndpointID{EndpointId: "id0"}: "up",
							}))
						})
					})

					Context("with host ep matching eth1", func() {
						JustBeforeEach(configureHostEp(&hostEpSpec{
							id:   "id22",
							name: "eth1",
						}))
						It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0", "eth1"))
						It("should report id1 and id22 up", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								types.HostEndpointID{EndpointId: "id1"}:  "up",
								types.HostEndpointID{EndpointId: "id22"}: "up",
							}))
						})
					})
				})
			})

			Describe("with host endpoint matching nonexistent interface", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:   "id3",
					name: "eth1",
				}))
				It("should have empty dispatch chains", expectEmptyChains(ipVersion))
				It("should report endpoint in error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id3"}: "error",
					}))
				})
			})

			Describe("with host endpoint matching IPv4 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id4",
					ipv4Addrs: []string{ipv4},
				}))
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0"))
				It("should report id4 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id4"}: "up",
					}))
				})
			})

			Describe("with host endpoint matching IPv6 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id5",
					ipv6Addrs: []string{ipv6},
				}))
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0"))
				It("should report id5 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id5"}: "up",
					}))
				})
			})

			Describe("with host endpoint matching IPv4 address and correct interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth0",
					ipv4Addrs: []string{ipv4},
				}))
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0"))
				It("should report id3 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id3"}: "up",
					}))
				})
			})

			Describe("with host endpoint matching IPv6 address and correct interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth0",
					ipv6Addrs: []string{ipv6},
				}))
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0"))
				It("should report id3 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id3"}: "up",
					}))
				})
			})

			Describe("with host endpoint matching IPv4 address and wrong interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth1",
					ipv4Addrs: []string{ipv4},
				}))
				It("should have empty dispatch chains", expectEmptyChains(ipVersion))
				It("should report id3 error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id3"}: "error",
					}))
				})
			})

			Describe("with host endpoint matching IPv6 address and wrong interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth1",
					ipv6Addrs: []string{ipv6},
				}))
				It("should have empty dispatch chains", expectEmptyChains(ipVersion))
				It("should report id3 error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id3"}: "error",
					}))
				})
			})

			Describe("with host endpoint with unmatched IPv4 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id4",
					ipv4Addrs: []string{"8.8.8.8"},
				}))
				It("should have empty dispatch chains", expectEmptyChains(ipVersion))
				It("should report id4 error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id4"}: "error",
					}))
				})
			})

			Describe("with host endpoint with unmatched IPv6 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id5",
					ipv6Addrs: []string{"fe08::2"},
				}))
				It("should have empty dispatch chains", expectEmptyChains(ipVersion))
				It("should report id5 error", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id5"}: "error",
					}))
				})
			})
		})

		Context("with host endpoint configured before interface signaled", func() {
			JustBeforeEach(configureHostEp(&hostEpSpec{
				id:   "id3",
				name: "eth0",
			}))
			It("should have empty dispatch chains", expectEmptyChains(ipVersion))
			It("should report id3 error", func() {
				Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
					types.HostEndpointID{EndpointId: "id3"}: "error",
				}))
			})

			Context("with interface signaled", func() {
				JustBeforeEach(func() {
					epMgr.OnUpdate(&ifaceStateUpdate{
						Name:  "eth0",
						State: "up",
					})
					epMgr.OnUpdate(&ifaceAddrsUpdate{
						Name:  "eth0",
						Addrs: eth0Addrs,
					})
					applyUpdates(epMgr)
				})
				It("should have expected chains", expectChainsFor(ipVersion, flowlogs, "eth0"))
				It("should report id3 up", func() {
					Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
						types.HostEndpointID{EndpointId: "id3"}: "up",
					}))
				})
			})
		})

		expectWlChainsFor := func(ipVersion uint8, flowlogs bool, names ...string) func() {
			return func() {
				filterTable.checkChains([][]*generictables.Chain{
					hostDispatchEmptyNormal,
					hostDispatchEmptyForward,
					wlChainsForIfaces(ipVersion, names, epMgr.epMarkMapper, flowlogs),
				})
				mangleTable.checkChains([][]*generictables.Chain{
					fromHostDispatchEmpty,
					toHostDispatchEmpty,
				})
			}
		}

		Describe("workload endpoints", func() {
			Context("with a workload endpoint", func() {
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
					applyUpdates(epMgr)
				})

				Context("with policy", func() {
					BeforeEach(func() {
						tiers = []*proto.TierInfo{{
							Name:            "default",
							IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
							EgressPolicies:  []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
						}}
					})

					It("should have expected chains", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab_policy1"))

					Context("with another endpoint with the same interface name and earlier workload ID, and no policy", func() {
						JustBeforeEach(func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
								Id: &proto.WorkloadEndpointID{
									OrchestratorId: "k8s",
									WorkloadId:     "pod-10a",
									EndpointId:     "endpoint-id-11",
								},
								Endpoint: &proto.WorkloadEndpoint{
									State:      "active",
									Mac:        "01:02:03:04:05:06",
									Name:       "cali12345-ab",
									ProfileIds: []string{},
									Tiers:      []*proto.TierInfo{},
									Ipv4Nets:   []string{"10.0.240.2/24"},
									Ipv6Nets:   []string{"2001:db8:2::2/128"},
								},
							})
							applyUpdates(epMgr)
						})

						It("should have expected chains with no policy", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab"))

						Context("with the first endpoint removed", func() {
							JustBeforeEach(func() {
								epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
									Id: &wlEPID1,
								})
								applyUpdates(epMgr)
							})

							It("should have expected chains with no policy", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab"))

							Context("with the second endpoint removed", func() {
								JustBeforeEach(func() {
									epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
										Id: &proto.WorkloadEndpointID{
											OrchestratorId: "k8s",
											WorkloadId:     "pod-10a",
											EndpointId:     "endpoint-id-11",
										},
									})
									applyUpdates(epMgr)
								})

								It("should have empty dispatch chains", expectEmptyChains(ipVersion))
							})
						})
					})

					Context("with another endpoint with the same interface name and later workload ID, and no policy", func() {
						JustBeforeEach(func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
								Id: &proto.WorkloadEndpointID{
									OrchestratorId: "k8s",
									WorkloadId:     "pod-11a",
									EndpointId:     "endpoint-id-11",
								},
								Endpoint: &proto.WorkloadEndpoint{
									State:      "active",
									Mac:        "01:02:03:04:05:06",
									Name:       "cali12345-ab",
									ProfileIds: []string{},
									Tiers:      []*proto.TierInfo{},
									Ipv4Nets:   []string{"10.0.240.2/24"},
									Ipv6Nets:   []string{"2001:db8:2::2/128"},
								},
							})
							applyUpdates(epMgr)
						})

						It("should have expected chains", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab_policy1"))

						Context("with the first endpoint removed", func() {
							JustBeforeEach(func() {
								epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
									Id: &wlEPID1,
								})
								applyUpdates(epMgr)
							})

							It("should have expected chains with no policy", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab"))

							Context("with the second endpoint removed", func() {
								JustBeforeEach(func() {
									epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
										Id: &proto.WorkloadEndpointID{
											OrchestratorId: "k8s",
											WorkloadId:     "pod-11a",
											EndpointId:     "endpoint-id-11",
										},
									})
									applyUpdates(epMgr)
								})

								It("should have empty dispatch chains", expectEmptyChains(ipVersion))
							})
						})
					})
				})

				Context("with ingress-only policy", func() {
					BeforeEach(func() {
						tiers = []*proto.TierInfo{{
							Name:            "default",
							IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
						}}
					})

					It("should have expected chains", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab_policy1_ingress"))
				})

				Context("with egress-only policy", func() {
					BeforeEach(func() {
						tiers = []*proto.TierInfo{{
							Name:           "default",
							EgressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
						}}
					})

					It("should have expected chains", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab_policy1_egress"))
				})

				It("should have expected chains", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab"))

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
						types.ProtoToWorkloadEndpointID(&wlEPID1): "down",
					}))
				})

				Context("with updates for the workload's iface and proc/sys failure", func() {
					JustBeforeEach(func() {
						mockProcSys.Fail = true
						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "cali12345-ab",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "cali12345-ab",
							Addrs: set.New[string](),
						})
						applyUpdates(epMgr)
					})
					It("should report the interface as down", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							types.ProtoToWorkloadEndpointID(&wlEPID1): "down",
						}))
					})
				})

				Context("with updates for the workload's iface", func() {
					JustBeforeEach(func() {
						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "cali12345-ab",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "cali12345-ab",
							Addrs: set.New[string](),
						})
						applyUpdates(epMgr)
					})

					It("should have expected chains", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab"))
					It("should report endpoint up", func() {
						Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
							types.ProtoToWorkloadEndpointID(&wlEPID1): "up",
						}))
					})

					It("should write /proc/sys entries", func() {
						if ipVersion == 6 {
							mockProcSys.checkState(map[string]string{
								"/proc/sys/net/ipv6/conf/cali12345-ab/accept_ra":  "0",
								"/proc/sys/net/ipv6/conf/cali12345-ab/proxy_ndp":  "1",
								"/proc/sys/net/ipv6/conf/cali12345-ab/forwarding": "1",
							})
						} else {
							mockProcSys.checkState(map[string]string{
								"/proc/sys/net/ipv6/conf/cali12345-ab/accept_ra":      "0",
								"/proc/sys/net/ipv4/conf/cali12345-ab/forwarding":     "1",
								"/proc/sys/net/ipv4/conf/cali12345-ab/route_localnet": "1",
								"/proc/sys/net/ipv4/conf/cali12345-ab/rp_filter":      "1",
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
							applyUpdates(epMgr)
						})

						It("should have expected chains", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab"))

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

					// Test that by disabling floatingIPs on the endpoint manager, even workload endpoints
					// that have floating IP NAT addresses specified will not result in those routes being
					// programmed.
					Context("with floating IPs disabled, but added to the endpoint", func() {
						JustBeforeEach(func() {
							epMgr.floatingIPsEnabled = false
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
							err := epMgr.ResolveUpdateBatch()
							Expect(err).ToNot(HaveOccurred())
							err = epMgr.CompleteDeferredWork()
							Expect(err).ToNot(HaveOccurred())
						})

						It("should have expected chains", expectWlChainsFor(ipVersion, flowlogs, "cali12345-ab"))

						It("should set routes with no floating IPs", func() {
							if ipVersion == 6 {
								routeTable.checkRoutes("cali12345-ab", []routetable.Target{
									{
										CIDR:    ip.MustParseCIDROrIP("2001:db8:2::2/128"),
										DestMAC: testutils.MustParseMAC("01:02:03:04:05:06"),
									},
								})
							} else {
								routeTable.checkRoutes("cali12345-ab", []routetable.Target{
									{
										CIDR:    ip.MustParseCIDROrIP("10.0.240.0/24"),
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
							applyUpdates(epMgr)
						})

						It("should have empty dispatch chains", expectEmptyChains(ipVersion))

						It("should have removed routes", func() {
							routeTable.checkRoutes("cali12345-ab", nil)
						})
						It("should report endpoint gone", func() {
							Expect(statusReportRec.currentState).To(BeEmpty())
						})
					})

					Context("changing the endpoint to another up interface", func() {
						JustBeforeEach(func() {
							epMgr.OnUpdate(&ifaceStateUpdate{
								Name:  "cali12345-cd",
								State: "up",
							})
							epMgr.OnUpdate(&ifaceAddrsUpdate{
								Name:  "cali12345-cd",
								Addrs: set.New[string](),
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
							applyUpdates(epMgr)
						})

						It("should have expected chains", expectWlChainsFor(ipVersion, flowlogs, "cali12345-cd"))

						It("should have removed routes for old iface", func() {
							routeTable.checkRoutes("cali12345-ab", nil)
						})
						It("should report endpoint up", func() {
							Expect(statusReportRec.currentState).To(Equal(map[interface{}]string{
								types.ProtoToWorkloadEndpointID(&wlEPID1): "up",
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

			Context("with RPF checking disabled", func() {
				var (
					wlEPID1        proto.WorkloadEndpointID
					workloadUpdate *proto.WorkloadEndpointUpdate
					interfaceUp    *ifaceStateUpdate
				)

				BeforeEach(func() {
					wlEPID1 = proto.WorkloadEndpointID{
						OrchestratorId: "k8s",
						WorkloadId:     "pod-12",
						EndpointId:     "endpoint-id-12",
					}
					workloadUpdate = &proto.WorkloadEndpointUpdate{
						Id: &wlEPID1,
						Endpoint: &proto.WorkloadEndpoint{
							State:                      "active",
							Mac:                        "01:02:03:04:05:06",
							Name:                       "cali23456-cd",
							ProfileIds:                 []string{},
							Tiers:                      []*proto.TierInfo{},
							Ipv4Nets:                   []string{"10.0.240.2/24"},
							Ipv6Nets:                   []string{"2001:db8:2::2/128"},
							AllowSpoofedSourcePrefixes: []string{"8.8.8.8/32", "2001:feed::1/64"},
						},
					}
					interfaceUp = &ifaceStateUpdate{
						Name:  "cali23456-cd",
						State: "up",
					}
				})

				It("should properly handle the source IP spoofing configuration", func() {
					By("Creating a workload with IP spoofing configured")
					epMgr.OnUpdate(workloadUpdate)
					// Set the interface up so that the sysctls are configured
					epMgr.OnUpdate(interfaceUp)
					applyUpdates(epMgr)
					if ipVersion == 4 {
						mockProcSys.checkStateContains(map[string]string{
							"/proc/sys/net/ipv4/conf/cali23456-cd/rp_filter": "0",
						})
						rawTable.checkChains([][]*generictables.Chain{hostDispatchEmptyNormal, {
							&generictables.Chain{Name: rules.ChainRpfSkip, Rules: []generictables.Rule{
								{
									Match:  iptables.Match().InInterface("cali23456-cd").SourceNet("8.8.8.8/32"),
									Action: iptables.AcceptAction{},
								},
							}},
						}})
					} else {
						rawTable.checkChains([][]*generictables.Chain{hostDispatchEmptyNormal, {
							&generictables.Chain{Name: rules.ChainRpfSkip, Rules: []generictables.Rule{
								{
									Match:  iptables.Match().InInterface("cali23456-cd").SourceNet("2001:feed::1/64"),
									Action: iptables.AcceptAction{},
								},
							}},
						}})
					}

					By("Re-enabling rpf check on an existing workload")
					workloadUpdate.Endpoint.AllowSpoofedSourcePrefixes = []string{}
					epMgr.OnUpdate(workloadUpdate)
					applyUpdates(epMgr)
					if ipVersion == 4 {
						mockProcSys.checkStateContains(map[string]string{
							"/proc/sys/net/ipv4/conf/cali23456-cd/rp_filter": "1",
						})
					}
					rawTable.checkChains([][]*generictables.Chain{hostDispatchEmptyNormal, {
						&generictables.Chain{Name: rules.ChainRpfSkip, Rules: []generictables.Rule{}},
					}})

					By("Enabling IP spoofing on an existing workload")
					workloadUpdate.Endpoint.AllowSpoofedSourcePrefixes = []string{"8.8.8.8/32", "2001:feed::1/64"}
					epMgr.OnUpdate(workloadUpdate)
					applyUpdates(epMgr)
					if ipVersion == 4 {
						mockProcSys.checkStateContains(map[string]string{
							"/proc/sys/net/ipv4/conf/cali23456-cd/rp_filter": "0",
						})
					}
					if ipVersion == 4 {
						rawTable.checkChains([][]*generictables.Chain{hostDispatchEmptyNormal, {
							&generictables.Chain{Name: rules.ChainRpfSkip, Rules: []generictables.Rule{
								{
									Match:  iptables.Match().InInterface("cali23456-cd").SourceNet("8.8.8.8/32"),
									Action: iptables.AcceptAction{},
								},
							}},
						}})
					} else {
						rawTable.checkChains([][]*generictables.Chain{hostDispatchEmptyNormal, {
							&generictables.Chain{Name: rules.ChainRpfSkip, Rules: []generictables.Rule{
								{
									Match:  iptables.Match().InInterface("cali23456-cd").SourceNet("2001:feed::1/64"),
									Action: iptables.AcceptAction{},
								},
							}},
						}})
					}

					By("Removing a workload with IP spoofing configured")
					epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
						Id: &wlEPID1,
					})
					applyUpdates(epMgr)
					rawTable.checkChains([][]*generictables.Chain{hostDispatchEmptyNormal, {
						&generictables.Chain{Name: rules.ChainRpfSkip, Rules: []generictables.Rule{}},
					}})
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
					applyUpdates(epMgr)
				})

				It("should have expected chains", func() {
					Expect(filterTable.currentChains["cali-tw-cali12345-ab"]).To(Equal(
						&generictables.Chain{
							Name: "cali-tw-cali12345-ab",
							Rules: []generictables.Rule{{
								Match:   iptables.Match(),
								Action:  iptables.DropAction{},
								Comment: []string{"Endpoint admin disabled"},
							}},
						},
					))
					Expect(filterTable.currentChains["cali-fw-cali12345-ab"]).To(Equal(
						&generictables.Chain{
							Name: "cali-fw-cali12345-ab",
							Rules: []generictables.Rule{{
								Match:   iptables.Match(),
								Action:  iptables.DropAction{},
								Comment: []string{"Endpoint admin disabled"},
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

		Describe("workloads as local bgp peer", func() {
			var linkCali1, linkCali2 netlink.Link
			listLinkAddrs := func(nl netlinkshim.Interface, link netlink.Link) []string {
				netlinkAddrs, err := nl.AddrList(link, 4)
				Expect(err).NotTo(HaveOccurred())

				addrs := []string{}
				for _, a := range netlinkAddrs {
					ipNetStr := a.IPNet.String()
					addrs = append(addrs, ipNetStr)
				}
				return addrs
			}

			Context("workloads as local bgp peer", func() {
				JustBeforeEach(func() {
					epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
						Id: &wlEPID1,
						Endpoint: &proto.WorkloadEndpoint{
							State:        "active",
							Mac:          "01:02:03:04:05:06",
							Name:         "cali1",
							Ipv4Nets:     []string{"10.0.240.2/24"},
							Ipv6Nets:     []string{"2001:db8:2::2/128"},
							LocalBgpPeer: &proto.LocalBGPPeer{BgpPeerName: "global-peer"},
						},
					})
					epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
						Id: &wlEPID2,
						Endpoint: &proto.WorkloadEndpoint{
							State:    "active",
							Mac:      "01:02:03:04:05:06",
							Name:     "cali2",
							Ipv4Nets: []string{"10.0.240.3/24"},
							Ipv6Nets: []string{"2001:db8:2::3/128"},
						},
					})
					epMgr.OnUpdate(&proto.GlobalBGPConfigUpdate{
						LocalWorkloadPeeringIpV4: "169.254.0.179",
						LocalWorkloadPeeringIpV6: "fe80::179",
					})
					applyUpdates(epMgr)
				})

				Context("with local bgp peer role and iface up", func() {
					JustBeforeEach(func() {
						linkCali1 = nlDataplane.AddIface(5, "cali1", true, true)
						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "cali1",
							State: "up",
							Index: 5,
						})
						linkCali2 = nlDataplane.AddIface(6, "cali2", true, true)
						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "cali2",
							State: "up",
							Index: 6,
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "cali1",
							Addrs: set.New[string](),
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "cali2",
							Addrs: set.New[string](),
						})
						err := epMgr.ResolveUpdateBatch()
						Expect(err).ToNot(HaveOccurred())
						err = epMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})

					It("should have configured the interface for local bgp peer role", func() {
						err := epMgr.linkAddrsMgr.Apply()
						Expect(err).NotTo(HaveOccurred())

						addrsCali1 := listLinkAddrs(nl, linkCali1)
						addrsCali2 := listLinkAddrs(nl, linkCali2)
						if ipVersion == 4 {
							Expect(addrsCali1).To(ConsistOf("169.254.0.179/32"))
							Expect(addrsCali2).NotTo(ContainElement("169.254.0.179/32"))
						}
						if ipVersion == 6 {
							Expect(addrsCali1).To(ConsistOf("fe80::179/128"))
							Expect(addrsCali2).NotTo(ContainElement("fe80::179/128"))
						}
					})

					It("should have configured the interface for endpoint update", func() {
						epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
							Id: &wlEPID1,
							Endpoint: &proto.WorkloadEndpoint{
								State:    "active",
								Mac:      "01:02:03:04:05:06",
								Name:     "cali1",
								Ipv4Nets: []string{"10.0.240.2/24"},
								Ipv6Nets: []string{"2001:db8:2::2/128"},
							},
						})
						epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
							Id: &wlEPID2,
							Endpoint: &proto.WorkloadEndpoint{
								State:        "active",
								Mac:          "01:02:03:04:05:06",
								Name:         "cali2",
								Ipv4Nets:     []string{"10.0.240.3/24"},
								Ipv6Nets:     []string{"2001:db8:2::3/128"},
								LocalBgpPeer: &proto.LocalBGPPeer{BgpPeerName: "global-peer"},
							},
						})
						epMgr.OnUpdate(&proto.GlobalBGPConfigUpdate{
							LocalWorkloadPeeringIpV4: "169.254.0.179",
							LocalWorkloadPeeringIpV6: "fe80::179",
						})
						applyUpdates(epMgr)

						err := epMgr.linkAddrsMgr.Apply()
						Expect(err).NotTo(HaveOccurred())

						addrsCali1 := listLinkAddrs(nl, linkCali1)
						addrsCali2 := listLinkAddrs(nl, linkCali2)
						if ipVersion == 4 {
							Expect(addrsCali2).To(ConsistOf("169.254.0.179/32"))
							Expect(addrsCali1).NotTo(ContainElement("169.254.0.179/32"))
						}
						if ipVersion == 6 {
							Expect(addrsCali2).To(ConsistOf("fe80::179/128"))
							Expect(addrsCali1).NotTo(ContainElement("fe80::179/128"))
						}
					})

					It("should have configured the interface on peer ip update", func() {
						epMgr.OnUpdate(&proto.GlobalBGPConfigUpdate{
							LocalWorkloadPeeringIpV4: "169.254.0.178",
							LocalWorkloadPeeringIpV6: "fe80::178",
						})
						applyUpdates(epMgr)

						err := epMgr.linkAddrsMgr.Apply()
						Expect(err).NotTo(HaveOccurred())

						addrsCali1 := listLinkAddrs(nl, linkCali1)
						if ipVersion == 4 {
							Expect(addrsCali1).To(ConsistOf("169.254.0.178/32"))
						}
						if ipVersion == 6 {
							Expect(addrsCali1).To(ConsistOf("fe80::178/128"))
						}
					})
				})
			})
		})

		Describe("policy grouping tests", func() {
			var (
				// Define expected policy IDs for easier reference.
				polA1      = "gnp/polA1"
				polA2      = "gnp/polA2"
				polB1      = "gnp/polB1"
				polB2      = "gnp/polB2"
				polC1      = "gnp/polC1"
				tier2PolA1 = "gnp/tier2.polA1"
				tier2PolA2 = "gnp/tier2.polA2"
				tier2PolB1 = "gnp/tier2.polB1"
			)

			JustBeforeEach(func() {
				// Add some policies to the endpoint manager in the default tier.
				epMgr.OnUpdate(&proto.ActivePolicyUpdate{
					Id:     &proto.PolicyID{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
					Policy: &proto.Policy{Tier: "default", OriginalSelector: "has(a)"},
				})
				epMgr.OnUpdate(&proto.ActivePolicyUpdate{
					Id:     &proto.PolicyID{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
					Policy: &proto.Policy{Tier: "default", OriginalSelector: "has(a)"},
				})
				epMgr.OnUpdate(&proto.ActivePolicyUpdate{
					Id:     &proto.PolicyID{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
					Policy: &proto.Policy{Tier: "default", OriginalSelector: "has(b)"},
				})
				epMgr.OnUpdate(&proto.ActivePolicyUpdate{
					Id:     &proto.PolicyID{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
					Policy: &proto.Policy{Tier: "default", OriginalSelector: "has(b)"},
				})
				epMgr.OnUpdate(&proto.ActivePolicyUpdate{
					Id:     &proto.PolicyID{Name: "polC1", Kind: v3.KindGlobalNetworkPolicy},
					Policy: &proto.Policy{Tier: "default", OriginalSelector: "has(c)"},
				})

				// Also add policies in another tier. Note that names are prefixed with tier name
				// so that they don't clash with the default tier policies.
				epMgr.OnUpdate(&proto.ActivePolicyUpdate{
					Id:     &proto.PolicyID{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
					Policy: &proto.Policy{Tier: "tier2", OriginalSelector: "has(a)"},
				})
				epMgr.OnUpdate(&proto.ActivePolicyUpdate{
					Id:     &proto.PolicyID{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
					Policy: &proto.Policy{Tier: "tier2", OriginalSelector: "has(a)"},
				})
				epMgr.OnUpdate(&proto.ActivePolicyUpdate{
					Id:     &proto.PolicyID{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
					Policy: &proto.Policy{Tier: "tier2", OriginalSelector: "has(b)"},
				})
				epMgr.OnUpdate(&proto.ActivePolicyUpdate{
					Id:     &proto.PolicyID{Name: "tier2.polB2", Kind: v3.KindGlobalNetworkPolicy},
					Policy: &proto.Policy{Tier: "tier2", OriginalSelector: "has(b)"},
				})
			})

			It("should 'group' a single policy", func() {
				Expect(epMgr.groupPolicies(
					[]*proto.PolicyID{{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy}},
					rules.PolicyDirectionInbound,
				)).To(Equal([]*rules.PolicyGroup{
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(a)",
					},
				}))
			})
			It("should 'group' a pair of policies same selector", func() {
				Expect(epMgr.groupPolicies(
					[]*proto.PolicyID{{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "polA2", Kind: v3.KindGlobalNetworkPolicy}},
					rules.PolicyDirectionInbound,
				)).To(Equal([]*rules.PolicyGroup{
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "polA2", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(a)",
					},
				}))
			})
			It("should 'group' a pair of policies different selector", func() {
				Expect(epMgr.groupPolicies(
					[]*proto.PolicyID{{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "polB1", Kind: v3.KindGlobalNetworkPolicy}},
					rules.PolicyDirectionInbound,
				)).To(Equal([]*rules.PolicyGroup{
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(a)",
					},
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(b)",
					},
				}))
			})
			It("should 'group' two pairs", func() {
				Expect(epMgr.groupPolicies(
					[]*proto.PolicyID{
						{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
						{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
						{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
						{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
					},
					rules.PolicyDirectionInbound,
				)).To(Equal([]*rules.PolicyGroup{
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "polA2", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(a)",
					},
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "polB2", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(b)",
					},
				}))
			})
			It("should 'group' mixed", func() {
				Expect(epMgr.groupPolicies(
					[]*proto.PolicyID{
						{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
						{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
						{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
						{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
					},
					rules.PolicyDirectionInbound,
				)).To(Equal([]*rules.PolicyGroup{
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(a)",
					},
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "polB2", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(b)",
					},
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(a)",
					},
				}))
			})

			It("should 'group' non-default tier", func() {
				Expect(epMgr.groupPolicies(
					[]*proto.PolicyID{
						{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
						{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
						{Name: "tier2.polB2", Kind: v3.KindGlobalNetworkPolicy},
						{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
					},
					rules.PolicyDirectionInbound,
				)).To(Equal([]*rules.PolicyGroup{
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(a)",
					},
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy}, {Name: "tier2.polB2", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(b)",
					},
					{
						Direction: rules.PolicyDirectionInbound,
						Policies:  []*types.PolicyID{{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy}},
						Selector:  "has(a)",
					},
				}))
			})

			Describe("policy grouping tests", func() {
				var (
					table              *mockTable
					ep1IngressChain    string
					ep1EgressChain     string
					ep2IngressChain    string
					ep2EgressChain     string
					deleteEP1          func()
					deleteEP2          func()
					removeAPolsFromEp1 func()
				)

				BeforeEach(func() {
					// Zero out shared vars to avoid test cross-talk.
					table = nil
					ep1IngressChain = ""
					ep1EgressChain = ""
					ep2IngressChain = ""
					ep2EgressChain = ""
					deleteEP1 = nil
					deleteEP2 = nil
					removeAPolsFromEp1 = nil
				})

				defineIngressPolicyGroupingTests := func() {
					It("should get the expected policy group chains (ingress)", func() {
						ingressNamesEP1, groupsEP1 := extractGroups(table.currentChains, ep1IngressChain)
						Expect(groupsEP1).To(Equal([][]string{
							{polA1, polA2},
							{polB1, polB2},
							{tier2PolA1, tier2PolA2},
						}))

						namesEP2, groupsEP2 := extractGroups(table.currentChains, ep2IngressChain)
						Expect(groupsEP2).To(Equal([][]string{
							{
								polB1,
								polB2,
							},
							{
								polC1,
							},
							{
								tier2PolA1,
								tier2PolA2,
							},
						}))

						Expect(ingressNamesEP1[1]).NotTo(Equal(""), "Policy B group shouldn't be inlined")
						Expect(ingressNamesEP1[1]).To(Equal(namesEP2[0]), "EPs should share the policy B group")
						Expect(namesEP2[1]).To(Equal(""), "Group C should be inlined")
					})

					It("should handle a change of selector", func() {
						// Start as with the above test...
						ingressNamesEP1, groupsEP1 := extractGroups(table.currentChains, ep1IngressChain)
						Expect(groupsEP1).To(Equal([][]string{
							{
								polA1,
								polA2,
							},
							{
								polB1,
								polB2,
							},
							{
								tier2PolA1,
								tier2PolA2,
							},
						}))
						_, groupsEP2 := extractGroups(table.currentChains, ep2IngressChain)
						Expect(groupsEP2).To(Equal([][]string{
							{
								polB1,
								polB2,
							},
							{
								polC1,
							},
							{
								tier2PolA1,
								tier2PolA2,
							},
						}))

						// Then move polA2 to the B group...
						epMgr.OnUpdate(&proto.ActivePolicyUpdate{
							Id:     &proto.PolicyID{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
							Policy: &proto.Policy{Tier: "default", OriginalSelector: "has(b)"}, // :-O
						})
						applyUpdates(epMgr)

						_, groupsEP1Post := extractGroups(table.currentChains, ep1IngressChain)
						Expect(groupsEP1Post).To(Equal([][]string{
							{
								polA1,
							},
							{
								polA2,
								polB1,
								polB2,
							},
							{
								tier2PolA1,
								tier2PolA2,
							},
						}))

						_, groupsEP2Post := extractGroups(table.currentChains, ep2IngressChain)
						Expect(groupsEP2Post).To(Equal([][]string{
							{
								polB1,
								polB2,
							},
							{
								polC1,
							},
							// {"tier2.polA1", "tier2.polA2"},
							{
								tier2PolA1,
								tier2PolA2,
							},
						}))

						Expect(table.currentChains).NotTo(HaveKey(ingressNamesEP1[0]), "Old polA group should be cleaned up")
					})

					It("should clean up group chain that is no longer used (EP deleted)", func() {
						namesEP1, _ := extractGroups(table.currentChains, ep1IngressChain)
						polAGroup := namesEP1[0]
						polBGroup := namesEP1[1]
						tier2Group := namesEP1[2]
						Expect(table.currentChains).To(HaveKey(polAGroup))
						deleteEP1()
						applyUpdates(epMgr)
						Expect(table.currentChains).NotTo(HaveKey(polAGroup),
							"Policy A group should be cleaned up")
						Expect(table.currentChains).To(HaveKey(polBGroup),
							"Policy B group chain should still be present, it is shared with the second endpoint")
						Expect(table.currentChains).To(HaveKey(tier2Group),
							"Tier 2 group chain should still be present, it is shared with the second endpoint")
						deleteEP2()
						applyUpdates(epMgr)
						Expect(table.currentChains).NotTo(HaveKey(polBGroup),
							"Policy B group should be cleaned up")
						Expect(table.currentChains).NotTo(HaveKey(tier2Group),
							"Tier 2 group should be cleaned up")
					})

					It("should clean up group chain that is no longer used (EP updated)", func() {
						namesEP1, _ := extractGroups(table.currentChains, ep1IngressChain)
						polAGroup := namesEP1[0]
						polBGroup := namesEP1[1]
						Expect(table.currentChains).To(HaveKey(polAGroup))
						removeAPolsFromEp1()
						applyUpdates(epMgr)
						_, groupsEP1 := extractGroups(table.currentChains, ep1IngressChain)
						Expect(groupsEP1).To(Equal([][]string{
							// {"polB1", "polB2"},
							{
								polB1,
								polB2,
							},
						}))
						Expect(table.currentChains).NotTo(HaveKey(polAGroup), "Policy A group should be cleaned up")
						Expect(table.currentChains).To(HaveKey(polBGroup), "Policy B group chain should still be present, it is shared with the second endpoint")
					})
				}

				defineEgressPolicyGroupingTests := func() {
					It("should get the expected policy group chains (egress)", func() {
						namesEP1, groupsEP1 := extractGroups(table.currentChains, ep1EgressChain)
						Expect(groupsEP1).To(Equal([][]string{
							{polA1},
							{polB1, polB2},
							{tier2PolA1},
							{tier2PolB1},
						}))
						namesEP2In, _ := extractGroups(table.currentChains, ep2IngressChain)
						namesEP2, groupsEP2 := extractGroups(table.currentChains, ep2EgressChain)
						Expect(groupsEP2).To(Equal([][]string{
							{polB1, polB2},
							{tier2PolA1},
							{tier2PolB1},
						}))
						Expect(namesEP1[0]).To(Equal(""), "Group A should be inlined")
						Expect(namesEP1[1]).NotTo(Equal(""), "Policy B group shouldn't be inlined")
						Expect(namesEP1[1]).To(Equal(namesEP2[0]), "EPs should share the policy B group")
						Expect(namesEP2In[0]).NotTo(Equal(namesEP2[0]), "Ingress/Egress group names should differ")
					})
				}

				Describe("with two workload endpoints", func() {
					JustBeforeEach(func() {
						table = filterTable
						ep1IngressChain = "cali-tw-cali12345-ab"
						ep1EgressChain = "cali-fw-cali12345-ab"
						ep2IngressChain = "cali-tw-cali12345-ac"
						ep2EgressChain = "cali-fw-cali12345-ac"

						epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
							Id: &wlEPID1,
							Endpoint: &proto.WorkloadEndpoint{
								State:      "active",
								Mac:        "01:02:03:04:05:06",
								Name:       "cali12345-ab",
								ProfileIds: []string{},
								Tiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
								Ipv4Nets: []string{"10.0.240.2/24"},
								Ipv6Nets: []string{"2001:db8:2::2/128"},
							},
						})
						epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
							Id: &wlEPID2,
							Endpoint: &proto.WorkloadEndpoint{
								State:      "active",
								Mac:        "01:02:03:04:05:07",
								Name:       "cali12345-ac",
								ProfileIds: []string{},
								Tiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polC1", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
								Ipv4Nets: []string{"10.0.240.2/24"},
								Ipv6Nets: []string{"2001:db8:2::3/128"},
							},
						})
						applyUpdates(epMgr)

						deleteEP1 = func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
								Id: &wlEPID1,
							})
						}
						deleteEP2 = func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
								Id: &wlEPID2,
							})
						}

						removeAPolsFromEp1 = func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
								Id: &wlEPID1,
								Endpoint: &proto.WorkloadEndpoint{
									State:      "active",
									Mac:        "01:02:03:04:05:06",
									Name:       "cali12345-ab",
									ProfileIds: []string{},
									Tiers: []*proto.TierInfo{
										{
											Name: "default",
											IngressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
											EgressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
										{
											Name: "tier2",
											EgressPolicies: []*proto.PolicyID{
												{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
									},
									Ipv4Nets: []string{"10.0.240.2/24"},
									Ipv6Nets: []string{"2001:db8:2::2/128"},
								},
							})
						}
					})

					defineIngressPolicyGroupingTests()
					defineEgressPolicyGroupingTests()
				})

				Describe("with a workload and host endpoint (normal policy)", func() {
					JustBeforeEach(func() {
						table = filterTable
						ep1IngressChain = "cali-tw-cali12345-ab"
						ep1EgressChain = "cali-fw-cali12345-ab"
						ep2IngressChain = "cali-fh-eth1"
						ep2EgressChain = "cali-th-eth1"

						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth1",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth1",
							Addrs: eth1Addrs,
						})

						epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
							Id: &wlEPID1,
							Endpoint: &proto.WorkloadEndpoint{
								State:      "active",
								Mac:        "01:02:03:04:05:06",
								Name:       "cali12345-ab",
								ProfileIds: []string{},
								Tiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
								Ipv4Nets: []string{"10.0.240.2/24"},
								Ipv6Nets: []string{"2001:db8:2::2/128"},
							},
						})
						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth1",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth1",
								ProfileIds: []string{},
								Tiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polC1", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						applyUpdates(epMgr)

						deleteEP1 = func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
								Id: &wlEPID1,
							})
						}
						deleteEP2 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth1",
								},
							})
						}

						removeAPolsFromEp1 = func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
								Id: &wlEPID1,
								Endpoint: &proto.WorkloadEndpoint{
									State:      "active",
									Mac:        "01:02:03:04:05:06",
									Name:       "cali12345-ab",
									ProfileIds: []string{},
									Tiers: []*proto.TierInfo{
										{
											Name: "default",
											IngressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
											EgressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
										{
											Name: "tier2",
											EgressPolicies: []*proto.PolicyID{
												{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
									},
									Ipv4Nets: []string{"10.0.240.2/24"},
									Ipv6Nets: []string{"2001:db8:2::2/128"},
								},
							})
						}
					})

					defineIngressPolicyGroupingTests()
					defineEgressPolicyGroupingTests()
				})

				Describe("with a host and workload endpoint (normal policy)", func() {
					JustBeforeEach(func() {
						table = filterTable
						ep1IngressChain = "cali-fh-eth0"
						ep1EgressChain = "cali-th-eth0"
						ep2IngressChain = "cali-tw-cali12345-ac"
						ep2EgressChain = "cali-fw-cali12345-ac"

						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth0",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth0",
							Addrs: eth1Addrs,
						})

						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth0",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth0",
								ProfileIds: []string{},
								Tiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						epMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
							Id: &wlEPID2,
							Endpoint: &proto.WorkloadEndpoint{
								State:      "active",
								Mac:        "01:02:03:04:05:07",
								Name:       "cali12345-ac",
								ProfileIds: []string{},
								Tiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polC1", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
								Ipv4Nets: []string{"10.0.240.2/24"},
								Ipv6Nets: []string{"2001:db8:2::3/128"},
							},
						})
						applyUpdates(epMgr)

						deleteEP1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
							})
						}
						deleteEP2 = func() {
							epMgr.OnUpdate(&proto.WorkloadEndpointRemove{
								Id: &wlEPID2,
							})
						}

						removeAPolsFromEp1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointUpdate{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
								Endpoint: &proto.HostEndpoint{
									Name:       "eth0",
									ProfileIds: []string{},
									Tiers: []*proto.TierInfo{
										{
											Name: "default",
											IngressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
											EgressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
										{
											Name: "tier2",
											EgressPolicies: []*proto.PolicyID{
												{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
									},
								},
							})
						}
					})

					defineIngressPolicyGroupingTests()
					defineEgressPolicyGroupingTests()
				})

				Describe("with two host endpoints (normal policy)", func() {
					JustBeforeEach(func() {
						table = filterTable
						ep1IngressChain = "cali-fh-eth0"
						ep1EgressChain = "cali-th-eth0"
						ep2IngressChain = "cali-fh-eth1"
						ep2EgressChain = "cali-th-eth1"

						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth0",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth0",
							Addrs: eth0Addrs,
						})
						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth1",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth1",
							Addrs: eth1Addrs,
						})

						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth0",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth0",
								ProfileIds: []string{},
								Tiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth1",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth1",
								ProfileIds: []string{},
								Tiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polC1", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						applyUpdates(epMgr)

						deleteEP1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
							})
						}
						deleteEP2 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth1",
								},
							})
						}

						removeAPolsFromEp1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointUpdate{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
								Endpoint: &proto.HostEndpoint{
									Name:       "eth0",
									ProfileIds: []string{},
									Tiers: []*proto.TierInfo{
										{
											Name: "default",
											IngressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
											EgressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
										{
											Name: "tier2",
											EgressPolicies: []*proto.PolicyID{
												{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
									},
								},
							})
						}
					})

					defineIngressPolicyGroupingTests()
					defineEgressPolicyGroupingTests()
				})

				Describe("with two host endpoints (pre-DNAT policy)", func() {
					JustBeforeEach(func() {
						table = mangleTable
						ep1IngressChain = "cali-fh-eth0"
						ep1EgressChain = "cali-th-eth0"
						ep2IngressChain = "cali-fh-eth1"
						ep2EgressChain = "cali-th-eth1"

						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth0",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth0",
							Addrs: eth0Addrs,
						})
						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth1",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth1",
							Addrs: eth1Addrs,
						})

						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth0",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth0",
								ProfileIds: []string{},
								PreDnatTiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth1",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth1",
								ProfileIds: []string{},
								PreDnatTiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polC1", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						applyUpdates(epMgr)

						deleteEP1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
							})
						}
						deleteEP2 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth1",
								},
							})
						}

						removeAPolsFromEp1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointUpdate{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
								Endpoint: &proto.HostEndpoint{
									Name:       "eth0",
									ProfileIds: []string{},
									PreDnatTiers: []*proto.TierInfo{
										{
											Name: "default",
											IngressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
											EgressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
										{
											Name: "tier2",
											EgressPolicies: []*proto.PolicyID{
												{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
									},
								},
							})
						}
					})

					defineIngressPolicyGroupingTests()
				})

				Describe("with two host endpoints (apply-on-forward policy)", func() {
					JustBeforeEach(func() {
						format.MaxLength = 100000000
						table = filterTable
						ep1IngressChain = "cali-fhfw-eth0"
						ep1EgressChain = "cali-thfw-eth0"
						ep2IngressChain = "cali-fhfw-eth1"
						ep2EgressChain = "cali-thfw-eth1"

						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth0",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth0",
							Addrs: eth0Addrs,
						})
						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth1",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth1",
							Addrs: eth1Addrs,
						})

						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth0",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth0",
								ProfileIds: []string{},
								ForwardTiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth1",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth1",
								ProfileIds: []string{},
								ForwardTiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polC1", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						applyUpdates(epMgr)

						deleteEP1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
							})
						}
						deleteEP2 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth1",
								},
							})
						}

						removeAPolsFromEp1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointUpdate{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
								Endpoint: &proto.HostEndpoint{
									Name:       "eth0",
									ProfileIds: []string{},
									ForwardTiers: []*proto.TierInfo{
										{
											Name: "default",
											IngressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
											EgressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
										{
											Name: "tier2",
											EgressPolicies: []*proto.PolicyID{
												{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
									},
								},
							})
						}
					})

					defineIngressPolicyGroupingTests()
					defineEgressPolicyGroupingTests()
				})

				Describe("with two host endpoints no-track policy)", func() {
					JustBeforeEach(func() {
						table = rawTable
						ep1IngressChain = "cali-fh-eth0"
						ep1EgressChain = "cali-th-eth0"
						ep2IngressChain = "cali-fh-eth1"
						ep2EgressChain = "cali-th-eth1"

						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth0",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth0",
							Addrs: eth0Addrs,
						})
						epMgr.OnUpdate(&ifaceStateUpdate{
							Name:  "eth1",
							State: "up",
						})
						epMgr.OnUpdate(&ifaceAddrsUpdate{
							Name:  "eth1",
							Addrs: eth1Addrs,
						})

						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth0",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth0",
								ProfileIds: []string{},
								UntrackedTiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polA2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						epMgr.OnUpdate(&proto.HostEndpointUpdate{
							Id: &proto.HostEndpointID{
								EndpointId: "eth1",
							},
							Endpoint: &proto.HostEndpoint{
								Name:       "eth1",
								ProfileIds: []string{},
								UntrackedTiers: []*proto.TierInfo{
									{
										Name: "default",
										IngressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polC1", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
									{
										Name: "tier2",
										IngressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polA2", Kind: v3.KindGlobalNetworkPolicy},
										},
										EgressPolicies: []*proto.PolicyID{
											{Name: "tier2.polA1", Kind: v3.KindGlobalNetworkPolicy},
											{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
										},
									},
								},
							},
						})
						applyUpdates(epMgr)

						deleteEP1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
							})
						}
						deleteEP2 = func() {
							epMgr.OnUpdate(&proto.HostEndpointRemove{
								Id: &proto.HostEndpointID{
									EndpointId: "eth1",
								},
							})
						}

						removeAPolsFromEp1 = func() {
							epMgr.OnUpdate(&proto.HostEndpointUpdate{
								Id: &proto.HostEndpointID{
									EndpointId: "eth0",
								},
								Endpoint: &proto.HostEndpoint{
									Name:       "eth0",
									ProfileIds: []string{},
									UntrackedTiers: []*proto.TierInfo{
										{
											Name: "default",
											IngressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
											EgressPolicies: []*proto.PolicyID{
												{Name: "polB1", Kind: v3.KindGlobalNetworkPolicy},
												{Name: "polB2", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
										{
											Name: "tier2",
											EgressPolicies: []*proto.PolicyID{
												{Name: "tier2.polB1", Kind: v3.KindGlobalNetworkPolicy},
											},
										},
									},
								},
							})
						}
					})

					defineIngressPolicyGroupingTests()
					defineEgressPolicyGroupingTests()
				})
			})
		})

		It("should check the correct path", func() {
			mockProcSys.pathsThatExist[fmt.Sprintf("/proc/sys/net/ipv%d/conf/cali1234", ipVersion)] = true
			Expect(epMgr.interfaceExistsInProcSys("cali1234")).To(BeTrue())
			Expect(epMgr.interfaceExistsInProcSys("cali3456")).To(BeFalse())
		})
	}
}

// extractGroups loosely parses the given chain (which should be a "to/from
// endpoint" chain) to extract the policy group chains that it jumps to (along
// with any inline policy jumps).  the returned slices have the same length;
// a group chain is represented by the name of the group chain in
// groupChainNames and a slice of policy names in the groups slice. An
// inline policy jump is represented by "" in the groupChainNames slice and
// single-entry slice containing the policy name in the groups slice.
//
// Policy chain names in the default tier are stripped of the default/ prefix.
// this makes it easier to share tests with OS.
func extractGroups(dpChains map[string]*generictables.Chain, epChainName string) (groupChainNames []string, groups [][]string) {
	Expect(dpChains).To(HaveKey(epChainName))
	epChain := dpChains[epChainName]
	for _, r := range epChain.Rules {
		if ja, ok := r.Action.(iptables.JumpAction); ok {
			if strings.HasPrefix(ja.Target, rules.PolicyGroupInboundPrefix) ||
				strings.HasPrefix(ja.Target, rules.PolicyGroupOutboundPrefix) {
				// Found jump to group.
				groupChainNames = append(groupChainNames, ja.Target)
				groups = append(groups, extractPolicyNamesFromJumps(dpChains[ja.Target]))
			} else if strings.HasPrefix(ja.Target, string(rules.PolicyInboundPfx)) ||
				strings.HasPrefix(ja.Target, string(rules.PolicyOutboundPfx)) {
				// Found jump to policy.
				groupChainNames = append(groupChainNames, "")
				groups = append(groups, []string{removePolChainNamePrefix(ja.Target)})
			}
		}
	}
	return
}

func extractPolicyNamesFromJumps(chain *generictables.Chain) (pols []string) {
	for _, r := range chain.Rules {
		if ja, ok := r.Action.(iptables.JumpAction); ok {
			pols = append(pols, removePolChainNamePrefix(ja.Target))
		}
	}
	return
}

func removePolChainNamePrefix(target string) string {
	if strings.HasPrefix(target, string(rules.PolicyInboundPfx)) {
		return target[len(rules.PolicyInboundPfx):]
	}
	if strings.HasPrefix(target, string(rules.PolicyOutboundPfx)) {
		return target[len(rules.PolicyOutboundPfx):]
	}
	log.WithField("chainName", target).Panic("Not a policy chain name.")
	panic("Not a policy chain name")
}

var _ = Describe("EndpointManager IPv4", endpointManagerTests(4, false))

var _ = Describe("EndpointManager IPv4 with flowlogs", endpointManagerTests(4, true))

var _ = Describe("EndpointManager IPv6", endpointManagerTests(6, false))

var _ = Describe("EndpointManager IPv6 with flowlogs", endpointManagerTests(6, true))

type testProcSys struct {
	lock           sync.Mutex
	state          map[string]string
	pathsThatExist map[string]bool
	Fail           bool
}

var errProcSysFail = errors.New("mock proc sys failure")

func (t *testProcSys) write(path, value string) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	log.WithFields(log.Fields{
		"path":  path,
		"value": value,
	}).Info("testProcSys writer")
	if t.Fail {
		return errProcSysFail
	}
	t.state[path] = value
	return nil
}

func (t *testProcSys) stat(path string) (os.FileInfo, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	exists := t.pathsThatExist[path]
	if exists {
		return nil, nil
	} else {
		return os.Stat("/file/that/does/not/exist")
	}
}

func (t *testProcSys) checkState(expected map[string]string) {
	t.lock.Lock()
	defer t.lock.Unlock()
	Expect(t.state).To(Equal(expected))
}

func (t *testProcSys) checkStateContains(expected map[string]string) {
	for k, v := range expected {
		actual, ok := t.state[k]
		Expect(ok).To(BeTrue())
		Expect(actual).To(Equal(v))
	}
}

type testHEPListener struct {
	state map[string]string
}

func (t *testHEPListener) OnHEPUpdate(hostIfaceToEpMap map[string]*proto.HostEndpoint) {
	log.Infof("OnHEPUpdate: %v", hostIfaceToEpMap)
	t.state = map[string]string{}

	stringifyPolicies := func(policies []*proto.PolicyID) string {
		var policyStrings []string
		for _, pol := range policies {
			policyStrings = append(policyStrings, pol.Name)
		}
		return strings.Join(policyStrings, ",")
	}

	stringify := func(tiers []*proto.TierInfo) string {
		var tierStrings []string
		for _, tier := range tiers {
			tierStrings = append(tierStrings,
				"I="+stringifyPolicies(tier.IngressPolicies)+
					",E="+stringifyPolicies(tier.EgressPolicies))
		}
		return strings.Join(tierStrings, "/")
	}

	for ifaceName, hep := range hostIfaceToEpMap {
		t.state[ifaceName] = "profiles=" + strings.Join(hep.ProfileIds, ",") +
			",normal=" + stringify(hep.Tiers) +
			",untracked=" + stringify(hep.UntrackedTiers) +
			",preDNAT=" + stringify(hep.PreDnatTiers) +
			",AoF=" + stringify(hep.ForwardTiers)
	}
}
