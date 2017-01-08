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

var _ = Describe("EndpointManager test", func() {

	var epMgr *endpointManager
	var filterTable *mockTable

	rrConfigNormal := rules.Config{
		IPIPEnabled:          true,
		IPIPTunnelAddress:    nil,
		IPSetConfigV4:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
		IPSetConfigV6:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
		IptablesMarkAccept:   0x8,
		IptablesMarkNextTier: 0x10,
	}

	for ip_version := range []uint8{4, 6} {
		BeforeEach(func() {
			renderer := rules.NewRenderer(rrConfigNormal)
			filterTable = newMockTable()
			epMgr = newEndpointManager(
				filterTable,
				renderer,
				nil,
				uint8(ip_version),
				[]string{"cali"},
				nil,
			)
		})

		It("should be constructable", func() {
			Expect(epMgr).ToNot(BeNil())
		})

		It("should process host endpoints", func() {

			log.Info("TEST: Define a host endpoint for a named interface")
			epMgr.OnUpdate(&proto.HostEndpointUpdate{
				Id: &proto.HostEndpointID{
					EndpointId: "endpoint-id-11",
				},
				Endpoint: &proto.HostEndpoint{
					Name:              "eth0",
					ProfileIds:        []string{},
					Tiers:             []*proto.TierInfo{},
					ExpectedIpv4Addrs: []string{},
					ExpectedIpv6Addrs: []string{},
				},
			})
			epMgr.CompleteDeferredWork()
			filterTable.checkChains(append(wlDispatchEmpty, hostDispatchEmpty...))

			log.Info("TEST: Signal that that interface exists")
			epMgr.OnUpdate(&ifaceUpdate{
				Name:  "eth0",
				State: "up",
			})
			addrs := set.New()
			epMgr.OnUpdate(&ifaceAddrsUpdate{
				Name:  "eth0",
				Addrs: addrs,
			})
			epMgr.CompleteDeferredWork()
			filterTable.checkChains(append(wlDispatchEmpty, hostDispatchForIface("eth0")...))

			log.Info("TEST: Add an address to the interface")
			addrs.Add("10.0.240.10")
			epMgr.OnUpdate(&ifaceAddrsUpdate{
				Name:  "eth0",
				Addrs: addrs,
			})
			epMgr.CompleteDeferredWork()
			filterTable.checkChainsSameAsBefore()

			log.Info("TEST: Change host endpoint to expect that address instead of a named interface")
			epMgr.OnUpdate(&proto.HostEndpointUpdate{
				Id: &proto.HostEndpointID{
					EndpointId: "endpoint-id-11",
				},
				Endpoint: &proto.HostEndpoint{
					ProfileIds:        []string{},
					Tiers:             []*proto.TierInfo{},
					ExpectedIpv4Addrs: []string{"10.0.240.10"},
					ExpectedIpv6Addrs: []string{},
				},
			})
			epMgr.CompleteDeferredWork()
			filterTable.checkChainsSameAsBefore()

			log.Info("TEST: Signal another host endpoint that also matches the IP address")
			epMgr.OnUpdate(&proto.HostEndpointUpdate{
				Id: &proto.HostEndpointID{
					EndpointId: "other-endpoint-id-55",
				},
				Endpoint: &proto.HostEndpoint{
					ProfileIds:        []string{},
					Tiers:             []*proto.TierInfo{},
					ExpectedIpv4Addrs: []string{"8.8.8.8", "10.0.240.10"},
					ExpectedIpv6Addrs: []string{},
				},
			})
			epMgr.CompleteDeferredWork()
			filterTable.checkChainsSameAsBefore()

			log.Info("TEST: Remove that other host endpoint again")
			epMgr.OnUpdate(&proto.HostEndpointRemove{
				Id: &proto.HostEndpointID{
					EndpointId: "other-endpoint-id-55",
				},
			})
			epMgr.CompleteDeferredWork()
			filterTable.checkChainsSameAsBefore()

			log.Info("TEST: Change host endpoint to expect a different address")
			epMgr.OnUpdate(&proto.HostEndpointUpdate{
				Id: &proto.HostEndpointID{
					EndpointId: "endpoint-id-11",
				},
				Endpoint: &proto.HostEndpoint{
					ProfileIds:        []string{},
					Tiers:             []*proto.TierInfo{},
					ExpectedIpv4Addrs: []string{"10.0.240.11"},
					ExpectedIpv6Addrs: []string{},
				},
			})
			epMgr.CompleteDeferredWork()
			filterTable.checkChains(append(wlDispatchEmpty, hostDispatchEmpty...))

			log.Info("TEST: Change host endpoint to be for an interface that doesn't exist yet")
			epMgr.OnUpdate(&proto.HostEndpointUpdate{
				Id: &proto.HostEndpointID{
					EndpointId: "endpoint-id-11",
				},
				Endpoint: &proto.HostEndpoint{
					Name:              "eth1",
					ProfileIds:        []string{},
					Tiers:             []*proto.TierInfo{},
					ExpectedIpv4Addrs: []string{},
					ExpectedIpv6Addrs: []string{},
				},
			})
			epMgr.CompleteDeferredWork()
			filterTable.checkChainsSameAsBefore()

			log.Info("TEST: Signal that interface")
			epMgr.OnUpdate(&ifaceUpdate{
				Name:  "eth1",
				State: "up",
			})
			addrs = set.New()
			epMgr.OnUpdate(&ifaceAddrsUpdate{
				Name:  "eth1",
				Addrs: addrs,
			})
			epMgr.CompleteDeferredWork()
			filterTable.checkChains(append(wlDispatchEmpty, hostDispatchForIface("eth1")...))
		})

		It("should process a workload endpoint update", func() {
		})
	}
})
