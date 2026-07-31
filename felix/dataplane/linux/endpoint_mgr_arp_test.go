// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

var _ = Describe("ARP chain programming", func() {
	var (
		epMgr    *endpointManager
		arpTable *mockTable
	)

	BeforeEach(func() {
		arpTable = newMockTable("arp")
		epMgr = &endpointManager{
			arpTable:        arpTable,
			activeARPChains: map[types.WorkloadEndpointID][]*generictables.Chain{},
		}
	})

	It("should program ARP chains when a workload is added", func() {
		id := types.ProtoToWorkloadEndpointID(&proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "pod-1",
			EndpointId:     "endpoint-id-1",
		})
		wl := &proto.WorkloadEndpoint{
			Name:     "cali12345-ab",
			Ipv4Nets: []string{"10.0.0.1/32"},
		}

		epMgr.updateWorkloadARPChains(id, wl)

		chainName := rules.EndpointChainName(rules.WorkloadARPPfx, "cali12345-ab", nftables.MaxChainNameLength)
		Expect(arpTable.currentChains).To(HaveKey(chainName))

		chain := arpTable.currentChains[chainName]
		Expect(chain.Rules).To(HaveLen(1))
		Expect(chain.Rules[0].Match.Render()).To(ContainSubstring("arp operation reply"))
		Expect(chain.Rules[0].Match.Render()).To(ContainSubstring("arp saddr ip 10.0.0.1"))
		Expect(chain.Rules[0].Match.Render()).To(ContainSubstring("oifname cali12345-ab"))
	})

	It("should program multiple drop rules for multiple IPs", func() {
		id := types.ProtoToWorkloadEndpointID(&proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "pod-2",
			EndpointId:     "endpoint-id-2",
		})
		wl := &proto.WorkloadEndpoint{
			Name:     "cali67890-cd",
			Ipv4Nets: []string{"10.0.0.1/32", "10.0.0.2/32"},
		}

		epMgr.updateWorkloadARPChains(id, wl)

		chainName := rules.EndpointChainName(rules.WorkloadARPPfx, "cali67890-cd", nftables.MaxChainNameLength)
		Expect(arpTable.currentChains).To(HaveKey(chainName))

		chain := arpTable.currentChains[chainName]
		Expect(chain.Rules).To(HaveLen(2))
		Expect(chain.Rules[0].Match.Render()).To(ContainSubstring("arp saddr ip 10.0.0.1"))
		Expect(chain.Rules[1].Match.Render()).To(ContainSubstring("arp saddr ip 10.0.0.2"))
	})

	It("should remove ARP chains when a workload is removed", func() {
		id := types.ProtoToWorkloadEndpointID(&proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "pod-3",
			EndpointId:     "endpoint-id-3",
		})
		wl := &proto.WorkloadEndpoint{
			Name:     "caliabcde-ef",
			Ipv4Nets: []string{"10.0.0.3/32"},
		}

		epMgr.updateWorkloadARPChains(id, wl)

		chainName := rules.EndpointChainName(rules.WorkloadARPPfx, "caliabcde-ef", nftables.MaxChainNameLength)
		Expect(arpTable.currentChains).To(HaveKey(chainName))

		epMgr.removeWorkloadARPChains(id)
		Expect(arpTable.currentChains).NotTo(HaveKey(chainName))
	})

	It("should not panic when arpTable is nil (IPv6)", func() {
		epMgr6 := &endpointManager{
			arpTable:        nil,
			activeARPChains: map[types.WorkloadEndpointID][]*generictables.Chain{},
		}

		id := types.ProtoToWorkloadEndpointID(&proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "pod-4",
			EndpointId:     "endpoint-id-4",
		})
		wl := &proto.WorkloadEndpoint{
			Name:     "cali11111-ab",
			Ipv4Nets: []string{"10.0.0.4/32"},
		}

		// Should not panic.
		epMgr6.updateWorkloadARPChains(id, wl)
		epMgr6.removeWorkloadARPChains(id)
	})
})
