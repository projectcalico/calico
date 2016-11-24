// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/felix/go/felix/ip"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/routetable"
	"github.com/projectcalico/felix/go/felix/rules"
	"reflect"
)

type endpointManager struct {
	ipVersion      int
	filterTable    *iptables.Table
	allEndpoints   map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	pendingUpdates map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	idToChains     map[proto.WorkloadEndpointID][]*iptables.Chain
	dispatchChains []*iptables.Chain
	ruleRenderer   rules.RuleRenderer
	routeTable     *routetable.RouteTable
}

func newEndpointManager(
	filterTable *iptables.Table,
	ruleRenderer rules.RuleRenderer,
	routeTable *routetable.RouteTable,
	ipVersion int,
) *endpointManager {
	return &endpointManager{
		ipVersion:      ipVersion,
		filterTable:    filterTable,
		allEndpoints:   map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		pendingUpdates: map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		idToChains:     map[proto.WorkloadEndpointID][]*iptables.Chain{},
		ruleRenderer:   ruleRenderer,
		routeTable:     routeTable,
	}
}

func (m *endpointManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		m.pendingUpdates[*msg.Id] = msg.Endpoint
	case *proto.WorkloadEndpointRemove:
		m.pendingUpdates[*msg.Id] = nil
	case *proto.HostEndpointUpdate:
		// TODO(smc) Host endpoint updates
		log.WithField("msg", msg).Warn("Message not implemented")
	case *proto.HostEndpointRemove:
		// TODO(smc) Host endpoint updates
		log.WithField("msg", msg).Warn("Message not implemented")
	}
}

func (m *endpointManager) CompleteDeferredWork() {
	// Rewrite the dispatch chains if they've changed.
	// TODO(smc) avoid re-rendering chains if nothing has changed.  (Slightly tricky because
	// the dispatch chains depend on the interface names and maybe later the IPs in the data.)
	newDispatchChains := m.ruleRenderer.WorkloadDispatchChains(m.allEndpoints)
	if !reflect.DeepEqual(newDispatchChains, m.dispatchChains) {
		log.Info("Workloads changed, updating dispatch chains.")
		m.filterTable.RemoveChains(m.dispatchChains)
		m.filterTable.UpdateChains(newDispatchChains)
		m.dispatchChains = newDispatchChains
	}

	// Update any dirty endpoints.
	for id, workload := range m.pendingUpdates {
		logCxt := log.WithField("id", id)
		oldWorkload := m.allEndpoints[id]
		if workload != nil {
			logCxt.Info("Updating per-endpoint chains.")
			chains := m.ruleRenderer.WorkloadEndpointToIptablesChains(&id, workload)
			m.filterTable.UpdateChains(chains)
			m.idToChains[id] = chains
			logCxt.Info("Updating endpoint routes.")
			var ipStrings []string
			if m.ipVersion == 4 {
				ipStrings = workload.Ipv4Nets
			} else {
				ipStrings = workload.Ipv6Nets
			}
			ipNets := make([]ip.CIDR, len(ipStrings))
			for i, s := range ipStrings {
				ipNets[i] = ip.MustParseCIDR(s)
			}
			if oldWorkload != nil && oldWorkload.Name != workload.Name {
				logCxt.Debug("Interface name changed, cleaning up old routes")
				m.routeTable.SetRoutes(oldWorkload.Name, nil)
			}
			m.routeTable.SetRoutes(workload.Name, ipNets)
		} else {
			logCxt.Info("Workload removed, deleting its chains.")
			m.filterTable.RemoveChains(m.idToChains[id])
			if oldWorkload := m.allEndpoints[id]; oldWorkload != nil {
				logCxt.Info("Workload removed, deleting its routes.")
				m.routeTable.SetRoutes(oldWorkload.Name, nil)
			}
		}
		delete(m.pendingUpdates, id)
	}
}
