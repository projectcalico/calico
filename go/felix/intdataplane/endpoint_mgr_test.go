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
)

type mockTable struct {
}

func newMockTable() *mockTable {
	return &mockTable{}
}

func (*mockTable) UpdateChains(chains []*iptables.Chain) {
	log.WithField("chains", chains).Debug("UpdateChains")
	for _, chain := range chains {
		log.WithField("chain", *chain).Debug("")
	}
}

func (*mockTable) RemoveChains(chains []*iptables.Chain) {
	log.WithField("chains", chains).Debug("RemoveChains")
	for _, chain := range chains {
		log.WithField("chain", *chain).Debug("")
	}
}

var _ = Describe("EndpointManager test", func() {
	var epMgr4, epMgr6 *endpointManager
	BeforeEach(func() {
		rrConfigNormal := rules.Config{
			IPIPEnabled:          true,
			IPIPTunnelAddress:    nil,
			IPSetConfigV4:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:        ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			IptablesMarkAccept:   0x8,
			IptablesMarkNextTier: 0x10,
		}
		renderer := rules.NewRenderer(rrConfigNormal)
		filterTable := newMockTable()
		epMgr4 = newEndpointManager(
			filterTable,
			renderer,
			nil,
			4,
			[]string{"cali"},
			nil,
		)
		epMgr6 = newEndpointManager(
			filterTable,
			renderer,
			nil,
			6,
			[]string{"cali"},
			nil,
		)
	})

	It("should be constructable", func() {
		Expect(epMgr4).ToNot(BeNil())
		Expect(epMgr6).ToNot(BeNil())
	})

	It("should process a host endpoint update", func() {
		epMgr4.OnUpdate(&proto.HostEndpointUpdate{
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
		epMgr4.CompleteDeferredWork()
		epMgr4.OnUpdate(&ifaceUpdate{
			Name:  "eth0",
			State: "up",
		})
		epMgr4.OnUpdate(&ifaceAddrsUpdate{
			Name:  "eth0",
			Addrs: set.New(),
		})
		epMgr4.CompleteDeferredWork()
	})

	It("should process a workload endpoint update", func() {
		//		var dp = intdataplane.NewIntDataplaneDriver(dpConfig)
		//		dp.SendMessage(&proto.InSync{})
		//		dp.SendMessage(&proto.WorkloadEndpointUpdate{})
	})
})
