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
	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/rules"
	"github.com/projectcalico/felix/go/felix/set"
	"reflect"
)

type mockTable struct {
	currentChains  map[string]*iptables.Chain
	expectedChains map[string]*iptables.Chain
}

func newMockTable() *mockTable {
	return &mockTable{
		currentChains:  map[string]*iptables.Chain{},
		expectedChains: map[string]*iptables.Chain{},
	}
}

func logChains(message string, chains []*iptables.Chain) {
	if chains == nil {
		log.Debug(message, " with nil chains")
	} else {
		log.WithField("chains", chains).Debug(message)
		for _, chain := range chains {
			log.WithField("chain", *chain).Debug("")
		}
	}
}

func (t *mockTable) UpdateChains(chains []*iptables.Chain) {
	logChains("UpdateChains", chains)
	for _, chain := range chains {
		t.currentChains[chain.Name] = chain
	}
}

func (t *mockTable) RemoveChains(chains []*iptables.Chain) {
	logChains("RemoveChains", chains)
	for _, chain := range chains {
		_, prs := t.currentChains[chain.Name]
		Expect(prs).To(BeTrue())
		delete(t.currentChains, chain.Name)
	}
}

func (t *mockTable) checkChains(expected []*iptables.Chain) {
	t.expectedChains = map[string]*iptables.Chain{}
	for _, chain := range expected {
		t.expectedChains[chain.Name] = chain
	}
	t.checkChainsSameAsBefore()
}

func (t *mockTable) checkChainsSameAsBefore() {
	Expect(reflect.DeepEqual(t.currentChains, t.expectedChains)).To(BeTrue())
}

var wlDispatchEmpty = []*iptables.Chain{
	&iptables.Chain{
		Name: "cali-to-wl-dispatch",
		Rules: []iptables.Rule{
			{
				Match:   iptables.Match(),
				Action:  iptables.DropAction{},
				Comment: "Unknown interface",
			},
		},
	},
	&iptables.Chain{
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
	&iptables.Chain{
		Name:  "cali-to-host-endpoint",
		Rules: []iptables.Rule{},
	},
	&iptables.Chain{
		Name:  "cali-from-host-endpoint",
		Rules: []iptables.Rule{},
	},
}

func hostDispatchForIface(ifaceName string) []*iptables.Chain {
	return []*iptables.Chain{
		&iptables.Chain{
			Name: "calith-" + ifaceName,
			Rules: []iptables.Rule{
				{
					Match:  iptables.Match(),
					Action: iptables.JumpAction{Target: "cali-failsafe-out"},
				},
				{
					Match:  iptables.Match(),
					Action: iptables.ClearMarkAction{Mark: 8},
				},
				{
					Match:   iptables.Match(),
					Action:  iptables.DropAction{},
					Comment: "Drop if no profiles matched",
				},
			},
		},
		&iptables.Chain{
			Name: "califh-" + ifaceName,
			Rules: []iptables.Rule{
				{
					Match:  iptables.Match(),
					Action: iptables.JumpAction{Target: "cali-failsafe-in"},
				},
				{
					Match:  iptables.Match(),
					Action: iptables.ClearMarkAction{Mark: 8},
				},
				{
					Match:   iptables.Match(),
					Action:  iptables.DropAction{},
					Comment: "Drop if no profiles matched",
				},
			},
		},
		&iptables.Chain{
			Name: "cali-to-host-endpoint",
			Rules: []iptables.Rule{
				{
					Match:  iptables.Match().OutInterface(ifaceName),
					Action: iptables.GotoAction{Target: "calith-" + ifaceName},
				},
			},
		},
		&iptables.Chain{
			Name: "cali-from-host-endpoint",
			Rules: []iptables.Rule{
				{
					Match:  iptables.Match().InInterface(ifaceName),
					Action: iptables.GotoAction{Target: "califh-" + ifaceName},
				},
			},
		},
	}
}

var _ = FDescribe("EndpointManager testing", func() {
	const (
		ipv4 = "10.0.240.10"
		ipv6 = "2001:db8::10.0.240.10"
	)
	var (
		epMgr          *endpointManager
		filterTable    *mockTable
		rrConfigNormal rules.Config
		ipVersion      int
		eth0Addrs      set.Set
		loAddrs        set.Set
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

		configureHostEp := func(id string, name string, ipv4Addrs []string, ipv6Addrs []string) func() {
			return func() {
				epMgr.OnUpdate(&proto.HostEndpointUpdate{
					Id: &proto.HostEndpointID{
						EndpointId: id,
					},
					Endpoint: &proto.HostEndpoint{
						Name:              name,
						ProfileIds:        []string{},
						Tiers:             []*proto.TierInfo{},
						ExpectedIpv4Addrs: ipv4Addrs,
						ExpectedIpv6Addrs: ipv6Addrs,
					},
				})
				epMgr.CompleteDeferredWork()
			}
		}

		expectChainsFor := func(name string) func() {
			return func() {
				filterTable.checkChains(append(wlDispatchEmpty, hostDispatchForIface(name)...))
			}
		}

		expectEmptyChains := func() func() {
			return func() {
				filterTable.checkChains(append(wlDispatchEmpty, hostDispatchEmpty...))
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

			It("should have empty dispatch chains", func() {
				filterTable.checkChains(append(wlDispatchEmpty, hostDispatchEmpty...))
			})

			Describe("with host endpoint matching eth0", func() {
				JustBeforeEach(configureHostEp("id1", "eth0", []string{}, []string{}))
				It("should have expected chains", expectChainsFor("eth0"))

				Context("with another host ep that matches the IPv4 address", func() {
					JustBeforeEach(configureHostEp("id2", "", []string{ipv4}, []string{}))
					It("should have expected chains", expectChainsFor("eth0"))

					Context("with the first host ep removed", func() {
						JustBeforeEach(removeHostEp("id1"))
						It("should have expected chains", expectChainsFor("eth0"))

						Context("with both host eps removed", func() {
							JustBeforeEach(removeHostEp("id2"))
							It("should have empty dispatch chains", expectEmptyChains())
						})
					})
				})
			})

			Describe("with host endpoint matching non-existent interface", func() {
				JustBeforeEach(configureHostEp("id3", "eth1", []string{}, []string{}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

			Describe("with host endpoint matching IPv4 address", func() {
				JustBeforeEach(configureHostEp("id4", "", []string{ipv4}, []string{}))
				It("should have expected chains", expectChainsFor("eth0"))
			})

			Describe("with host endpoint matching IPv6 address", func() {
				JustBeforeEach(configureHostEp("id5", "", []string{}, []string{ipv6}))
				It("should have expected chains", expectChainsFor("eth0"))
			})

			Describe("with host endpoint matching IPv4 address and correct interface name", func() {
				JustBeforeEach(configureHostEp("id3", "eth0", []string{ipv4}, []string{}))
				It("should have expected chains", expectChainsFor("eth0"))
			})

			Describe("with host endpoint matching IPv6 address and correct interface name", func() {
				JustBeforeEach(configureHostEp("id3", "eth0", []string{}, []string{ipv6}))
				It("should have expected chains", expectChainsFor("eth0"))
			})

			Describe("with host endpoint matching IPv4 address and wrong interface name", func() {
				JustBeforeEach(configureHostEp("id3", "eth1", []string{ipv4}, []string{}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

			Describe("with host endpoint matching IPv6 address and wrong interface name", func() {
				JustBeforeEach(configureHostEp("id3", "eth1", []string{}, []string{ipv6}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

			Describe("with host endpoint with unmatched IPv4 address", func() {
				JustBeforeEach(configureHostEp("id4", "", []string{"8.8.8.8"}, []string{}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

			Describe("with host endpoint with unmatched IPv6 address", func() {
				JustBeforeEach(configureHostEp("id5", "", []string{}, []string{"fe08::2"}))
				It("should have empty dispatch chains", expectEmptyChains())
			})

		})

		Context("with host endpoint configured before interface signaled", func() {
			JustBeforeEach(configureHostEp("id3", "eth0", []string{}, []string{}))
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

		It("should process a workload endpoint update", func() {
		})
	}
})
