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

package intdataplane

import (
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
	"reflect"
)

// A floating IP is an IP that can be used to reach a particular workload endpoint, but that the
// endpoint itself is not aware of.  The 'floating IP' terminology comes from OpenStack, but the
// concept can be useful with workload orchestration platforms more generally.  OpenStack
// installations use floating IPs for two reasons: (1) IP mobility, aka as a 'service IP' - i.e. to
// have an IP that can be moved from time to time to target a different workload, for example,
// depending on which of those workloads is currently the 'active' one for some HA service; (2) to
// allow a particular workload to be reachable (inbound) from the Internet, when the networking
// driver normally doesn't allow an Internet-routable IP to be assigned as a workload's primary IP.
// In Calico (2) is irrelevant, because a workload can have an Internet-routable IP as its primary
// IP, but the idea of service IP mobility is still useful, and floating IPs are one way of
// providing mobile service IPs.
//
// Implementation-wise, a floating IP is simply a destination IP address - the 'external' IP - that
// gets DNAT'd by the compute node to the workload's normal IP address - the 'internal' IP - on
// packets that are sent to the workload.
//
// There generally _isn't_ a corresponding SNAT for the other direction; in other words, packets
// sent _from_ a workload don't have their source address changing to a floating IP, if the workload
// has floating IPs associated with it.  This is because people don't expect floating IPs to do
// that, and its faster in the datapath to avoid NATs if we can, especially when sending to another
// workload nearby.  (And for sending outbound to the Internet, there will be an SNAT if needed at
// the data center's border gateway.)  However SNAT is needed in the loopback case where a workload
// sends to a floating IP that maps back to itself; for this case the datapath processing must be as
// follows:
//
// 1. Workload sends to <floating IP>, so packet has SRC=<workload IP> DST=<floating IP>.
//
// 2. Compute node does DNAT for the floating IP, so now packet has SRC=<workload IP> DST=<workload IP>.
//
// 3. Compute node does SNAT, so that packet has SRC=<floating IP> DST=<workload IP>.
//
// 4. Workload receives packet again, with SRC=<floating IP> DST=<workload IP>.
//
// If (3) was omitted, the workload would receive a packet from a non-loopback interface with
// SRC=<my own IP> DST=<my own IP>, and so would probably drop it.

// floatingIPManager programs the 'cali-fip-dnat' and 'cali-fip-snat' chains in the iptables 'nat'
// table with DNAT and SNAT rules for the floating IPs associated with local workload endpoints.
// The cali-fip-dnat chain is statically linked from cali-OUTPUT and cali-PREROUTING, and
// cali-fip-snat from cali-POSTROUTING.
type floatingIPManager struct {
	ipVersion uint8

	// Our dependencies.
	natTable     iptablesTable
	ruleRenderer rules.RuleRenderer

	// Internal state.
	activeDNATChains []*iptables.Chain
	activeSNATChains []*iptables.Chain
	natInfo          map[proto.WorkloadEndpointID][]*proto.NatInfo
	dirtyNATInfo     bool
}

func newFloatingIPManager(
	natTable iptablesTable,
	ruleRenderer rules.RuleRenderer,
	ipVersion uint8,
) *floatingIPManager {
	return &floatingIPManager{
		natTable:     natTable,
		ruleRenderer: ruleRenderer,
		ipVersion:    ipVersion,

		activeDNATChains: []*iptables.Chain{},
		activeSNATChains: []*iptables.Chain{},
		natInfo:          map[proto.WorkloadEndpointID][]*proto.NatInfo{},
		dirtyNATInfo:     true,
	}
}

func (m *floatingIPManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		if m.ipVersion == 4 {
			m.natInfo[*msg.Id] = msg.Endpoint.Ipv4Nat
		} else {
			m.natInfo[*msg.Id] = msg.Endpoint.Ipv6Nat
		}
		m.dirtyNATInfo = true
	case *proto.WorkloadEndpointRemove:
		delete(m.natInfo, *msg.Id)
		m.dirtyNATInfo = true
	}
}

func (m *floatingIPManager) CompleteDeferredWork() error {
	if m.dirtyNATInfo {
		// Collate required DNATs as a map from external IP to internal IP.
		dnats := map[string]string{}
		for _, natInfos := range m.natInfo {
			for _, natInfo := range natInfos {
				log.WithFields(log.Fields{
					"ExtIP": natInfo.ExtIp,
					"IntIP": natInfo.IntIp,
				}).Debug("NAT mapping")

				// We shouldn't ever have the same floating IP mapping to multiple
				// workload IPs, but if we do we'll program the mapping to the
				// alphabetically earlier one.
				existingIntIP := dnats[natInfo.ExtIp]
				if existingIntIP == "" || natInfo.IntIp < existingIntIP {
					log.Debug("Wanted NAT mapping")
					dnats[natInfo.ExtIp] = natInfo.IntIp
				}
			}
		}
		// Collate required SNATs as a map from internal IP to external IP.
		snats := map[string]string{}
		for extIP, intIP := range dnats {
			log.WithFields(log.Fields{
				"ExtIP": extIP,
				"IntIP": intIP,
			}).Debug("Reverse mapping")

			// For the reverse SNATs, if multiple floating IPs map to the same workload
			// IP, use the alphabetically earliest floating IP.
			existingExtIP := snats[intIP]
			if existingExtIP == "" || extIP < existingExtIP {
				log.Debug("Wanted reverse mapping")
				snats[intIP] = extIP
			}
		}
		// Render chains for those NATs.
		dnatChains := m.ruleRenderer.DNATsToIptablesChains(dnats)
		snatChains := m.ruleRenderer.SNATsToIptablesChains(snats)
		// Update iptables if they have changed.
		if !reflect.DeepEqual(m.activeDNATChains, dnatChains) {
			m.natTable.RemoveChains(m.activeDNATChains)
			m.natTable.UpdateChains(dnatChains)
			m.activeDNATChains = dnatChains
		}
		if !reflect.DeepEqual(m.activeSNATChains, snatChains) {
			m.natTable.RemoveChains(m.activeSNATChains)
			m.natTable.UpdateChains(snatChains)
			m.activeSNATChains = snatChains
		}
		m.dirtyNATInfo = false
	}
	return nil
}
