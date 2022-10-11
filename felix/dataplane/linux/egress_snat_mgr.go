// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.Address
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
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

// egressSNATManager manages the ipsets and iptables chains used to implement the "NAT outgoing" or
// "masquerade" feature.  The feature adds a boolean flag to each IPAM pool, which controls how
// outgoing traffic to non-Calico destinations is handled.  If the "masquerade" flag is set,
// outgoing traffic is source-NATted to appear to come from the host's IP address.
//
// The egressSNATManager maintains two CIDR IP sets: one contains the CIDRs for all Calico
// IPAM pools, the other contains only the NAT-enabled pools.
//
// When NAT-enabled pools are present, the egressSNATManager inserts the iptables masquerade rule
// to trigger NAT of outgoing packets from NAT-enabled pools.  Traffic to any Calico-owned
// pool is excluded.
type egressSNATManager struct {
	ipVersion        uint8
	natTable         iptablesTable
	activeSNATChains []*iptables.Chain
	egressSNATInfo   map[proto.WorkloadEndpointID][]*proto.NatInfo
	dirty            bool
	ruleRenderer     rules.RuleRenderer
	enabled          bool
	logCxt           *log.Entry
}

func newEgressSNATManager(
	natTable iptablesTable,
	ruleRenderer rules.RuleRenderer,
	ipVersion uint8,
	enabled bool,
) *egressSNATManager {
	return &egressSNATManager{
		ipVersion:        ipVersion,
		natTable:         natTable,
		activeSNATChains: []*iptables.Chain{},
		egressSNATInfo:   map[proto.WorkloadEndpointID][]*proto.NatInfo{},
		dirty:            true,
		ruleRenderer:     ruleRenderer,
		enabled:          enabled,
		logCxt:           log.WithField("ipVersion", ipVersion),
	}
}

func (m *egressSNATManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.WorkloadEndpointUpdate:
		// We only program NAT mappings if Egress SNAT feature is globally enabled.
		if m.enabled {
			if m.ipVersion == 4 {
				m.egressSNATInfo[*msg.Id] = msg.Endpoint.Ipv4Snat
			} else {
				m.egressSNATInfo[*msg.Id] = msg.Endpoint.Ipv6Snat
			}
		} else {
			delete(m.egressSNATInfo, *msg.Id)
		}
		m.dirty = true
	case *proto.WorkloadEndpointRemove:
		delete(m.egressSNATInfo, *msg.Id)
		m.dirty = true
	}
}

func (m *egressSNATManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}

	// Collate required SNATs as a map from internal IP to external IP.
	snats := map[string]string{}
	for _, egressSNATs := range m.egressSNATInfo {
		for _, egressSNAT := range egressSNATs {
			log.WithFields(log.Fields{
				"ExtIP": egressSNAT.ExtIp,
				"IntIP": egressSNAT.IntIp,
			}).Debug("Egress SNAT mapping")

			// For the egress SNATs, if multiple external IPs map to the same
			// workload IP, use the alphabetically earliest external IP.
			existingExtIP := snats[egressSNAT.IntIp]
			if existingExtIP == "" || egressSNAT.IntIp < existingExtIP {
				log.Debug("Wanted Egress SNAT mapping")
				snats[egressSNAT.IntIp] = egressSNAT.ExtIp
			}
		}
	}

	// Render chains for those NATs.
	snatChains := m.ruleRenderer.EgressSNATsToIptablesChains(snats, m.ipVersion)
	// Update iptables if they have changed.
	if !reflect.DeepEqual(m.activeSNATChains, snatChains) {
		m.natTable.RemoveChains(m.activeSNATChains)
		m.natTable.UpdateChains(snatChains)
		m.activeSNATChains = snatChains
	}
	m.dirty = false
	return nil
}
