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
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/rules"
	"github.com/projectcalico/felix/go/felix/set"
	"reflect"
)

type endpointManager struct {
	filterTable    *iptables.Table
	allEndpoints   map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	idToChains     map[proto.WorkloadEndpointID][]*iptables.Chain
	dispatchChains []*iptables.Chain
	dirtyEndpoints set.Set
	ruleRenderer   rules.RuleRenderer
}

func newEndpointManager(filterTable *iptables.Table, ruleRenderer rules.RuleRenderer) *endpointManager {
	return &endpointManager{
		filterTable:    filterTable,
		allEndpoints:   map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		idToChains:     map[proto.WorkloadEndpointID][]*iptables.Chain{},
		dirtyEndpoints: set.New(),
		ruleRenderer:   ruleRenderer,
	}
}

func (m *endpointManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.WorkloadEndpointUpdate:
		m.allEndpoints[*msg.Id] = msg.Endpoint
		m.dirtyEndpoints.Add(*msg.Id)
	case *proto.WorkloadEndpointRemove:
		delete(m.allEndpoints, *msg.Id)
		m.dirtyEndpoints.Add(*msg.Id)
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

	// Rewrite the chains of any dirty endpoints.
	m.dirtyEndpoints.Iter(func(item interface{}) error {
		id := item.(proto.WorkloadEndpointID)
		if workload := m.allEndpoints[id]; workload != nil {
			log.WithField("id", id).Info("Workload updated, updating its chains.")
			chains := m.ruleRenderer.WorkloadEndpointToIptablesChains(&id, workload)
			m.filterTable.UpdateChains(chains)
			m.idToChains[id] = chains
		} else {
			log.WithField("id", id).Info("Workload removed, deleting its chains.")
			m.filterTable.RemoveChains(m.idToChains[id])
		}
		return set.RemoveItem
	})
}
