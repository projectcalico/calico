// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/rules"
	"github.com/projectcalico/felix/go/felix/set"
	"strings"
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
}

var hostDispatchEmpty = []*iptables.Chain{
	{
		Name:  "cali-to-host-endpoint",
		Rules: []iptables.Rule{},
	},
	{
		Name:  "cali-from-host-endpoint",
		Rules: []iptables.Rule{},
	},
}

func hostChainsForIfaces(ifaceTierNames []string) []*iptables.Chain {
	chains := []*iptables.Chain{}
	dispatchOut := []iptables.Rule{}
	dispatchIn := []iptables.Rule{}
	for _, ifaceTierName := range ifaceTierNames {
		var ifaceName, tierName string
		nameParts := strings.Split(ifaceTierName, "_")
		if len(nameParts) == 1 {
			ifaceName = nameParts[0]
			tierName = ""
		} else {
			ifaceName = nameParts[0]
			tierName = nameParts[1]
		}
		outRules := []iptables.Rule{
			{
				Match:  iptables.Match(),
				Action: iptables.JumpAction{Target: "cali-failsafe-out"},
			},
			{
				Match:  iptables.Match(),
				Action: iptables.ClearMarkAction{Mark: 8},
			},
		}
		if tierName != "" {
			outRules = append(outRules, []iptables.Rule{
				{
					Match:   iptables.Match(),
					Action:  iptables.ClearMarkAction{Mark: 16},
					Comment: "Start of tier " + tierName,
				},
				{
					Match:   iptables.Match().MarkClear(16),
					Action:  iptables.DropAction{},
					Comment: "Drop if no policies passed packet",
				},
			}...)
		}
		outRules = append(outRules, iptables.Rule{
			Match:   iptables.Match(),
			Action:  iptables.DropAction{},
			Comment: "Drop if no profiles matched",
		})
		inRules := []iptables.Rule{
			{
				Match:  iptables.Match(),
				Action: iptables.JumpAction{Target: "cali-failsafe-in"},
			},
			{
				Match:  iptables.Match(),
				Action: iptables.ClearMarkAction{Mark: 8},
			},
		}
		if tierName != "" {
			inRules = append(inRules, []iptables.Rule{
				{
					Match:   iptables.Match(),
					Action:  iptables.ClearMarkAction{Mark: 16},
					Comment: "Start of tier " + tierName,
				},
				{
					Match:   iptables.Match().MarkClear(16),
					Action:  iptables.DropAction{},
					Comment: "Drop if no policies passed packet",
				},
			}...)
		}
		inRules = append(inRules, iptables.Rule{
			Match:   iptables.Match(),
			Action:  iptables.DropAction{},
			Comment: "Drop if no profiles matched",
		})
		chains = append(chains,
			&iptables.Chain{
				Name:  "calith-" + ifaceName,
				Rules: outRules,
			},
			&iptables.Chain{
				Name:  "califh-" + ifaceName,
				Rules: inRules,
			},
		)
		dispatchOut = append(dispatchOut,
			iptables.Rule{
				Match:  iptables.Match().OutInterface(ifaceName),
				Action: iptables.GotoAction{Target: "calith-" + ifaceName},
			},
		)
		dispatchIn = append(dispatchIn,
			iptables.Rule{
				Match:  iptables.Match().InInterface(ifaceName),
				Action: iptables.GotoAction{Target: "califh-" + ifaceName},
			},
		)
	}
	chains = append(chains,
		&iptables.Chain{
			Name:  "cali-to-host-endpoint",
			Rules: dispatchOut,
		},
		&iptables.Chain{
			Name:  "cali-from-host-endpoint",
			Rules: dispatchIn,
		},
	)
	return chains
}

type hostEpSpec struct {
	id        string
	name      string
	ipv4Addrs []string
	ipv6Addrs []string
	tierName  string
}

var _ = Describe("EndpointManager testing", func() {
	const (
		ipv4     = "10.0.240.10"
		ipv4Eth1 = "10.0.240.30"
		ipv6     = "2001:db8::10.0.240.10"
	)
	var (
		epMgr          *endpointManager
		filterTable    *mockTable
		rrConfigNormal rules.Config
		ipVersion      int
		eth0Addrs      set.Set
		loAddrs        set.Set
		eth1Addrs      set.Set
	)

	BeforeEach(func() {
		rrConfigNormal = rules.Config{
			IPIPEnabled:          true,
			IPIPTunnelAddress:    nil,
			IPSetConfigV4:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			IptablesMarkAccept:   0x8,
			IptablesMarkNextTier: 0x10,
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
		filterTable = newMockTable()
		epMgr = newEndpointManager(
			filterTable,
			renderer,
			nil,
			uint8(ipVersion),
			[]string{"cali"},
			nil,
		)
	})

	for ipVersion = range []uint8{4, 6} {
		It("should be constructable", func() {
			Expect(epMgr).ToNot(BeNil())
		})

		configureHostEp := func(spec *hostEpSpec) func() {
			tiers := []*proto.TierInfo{}
			if spec.tierName != "" {
				tiers = append(tiers, &proto.TierInfo{Name: spec.tierName})
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
					hostChainsForIfaces(names),
				})
			}
		}

		expectEmptyChains := func() func() {
			return func() {
				filterTable.checkChains([][]*iptables.Chain{
					wlDispatchEmpty,
					hostDispatchEmpty,
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
				It("should have expected chains", expectChainsFor("eth0_tierA"))

				Context("with another host ep (>ID) that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp(&hostEpSpec{
						id:        "id2",
						ipv4Addrs: []string{ipv4},
						tierName:  "tierB",
					}))
					It("should have expected chains", expectChainsFor("eth0_tierA"))

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor("eth0_tierB"))

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
						tierName:  "tierB",
					}))
					It("should have expected chains", expectChainsFor("eth0_tierB"))

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor("eth0_tierB"))

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id0"))
							It("should have empty dispatch chains", expectEmptyChains())
						})
					})
				})
			})

			Describe("with host endpoint matching eth0", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:   "id1",
					name: "eth0",
				}))
				It("should have expected chains", expectChainsFor("eth0"))

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

					Context("with host ep matching eth1's IP", func() {
						JustBeforeEach(configureHostEp(&hostEpSpec{
							id:        "id22",
							ipv4Addrs: []string{ipv4Eth1},
						}))
						It("should have expected chains", expectChainsFor("eth0", "eth1"))
					})

					Context("with host ep matching eth1", func() {
						JustBeforeEach(configureHostEp(&hostEpSpec{
							id:   "id22",
							name: "eth1",
						}))
						It("should have expected chains", expectChainsFor("eth0", "eth1"))
					})
				})
			})

			Describe("with host endpoint matching non-existent interface", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:   "id3",
					name: "eth1",
				}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

			Describe("with host endpoint matching IPv4 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id4",
					ipv4Addrs: []string{ipv4},
				}))
				It("should have expected chains", expectChainsFor("eth0"))
			})

			Describe("with host endpoint matching IPv6 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id5",
					ipv6Addrs: []string{ipv6},
				}))
				It("should have expected chains", expectChainsFor("eth0"))
			})

			Describe("with host endpoint matching IPv4 address and correct interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth0",
					ipv4Addrs: []string{ipv4},
				}))
				It("should have expected chains", expectChainsFor("eth0"))
			})

			Describe("with host endpoint matching IPv6 address and correct interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth0",
					ipv6Addrs: []string{ipv6},
				}))
				It("should have expected chains", expectChainsFor("eth0"))
			})

			Describe("with host endpoint matching IPv4 address and wrong interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth1",
					ipv4Addrs: []string{ipv4},
				}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

			Describe("with host endpoint matching IPv6 address and wrong interface name", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id3",
					name:      "eth1",
					ipv6Addrs: []string{ipv6},
				}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

			Describe("with host endpoint with unmatched IPv4 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id4",
					ipv4Addrs: []string{"8.8.8.8"},
				}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

			Describe("with host endpoint with unmatched IPv6 address", func() {
				JustBeforeEach(configureHostEp(&hostEpSpec{
					id:        "id5",
					ipv6Addrs: []string{"fe08::2"},
				}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

		})

		Context("with host endpoint configured before interface signaled", func() {
			JustBeforeEach(configureHostEp(&hostEpSpec{
				id:   "id3",
				name: "eth0",
			}))
			It("should have empty dispatch chains", expectEmptyChains())

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
			})
		})
	}
})
