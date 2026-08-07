// Copyright (c) 2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package intdataplane

import (
	"reflect"
	"strings"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

type lbNoEndpointsServiceID struct {
	namespace string
	name      string
}

// lbNoEndpointsManager maintains the policy-gated exceptions that allow packets
// for opted-in LoadBalancer VIPs to reach normal routing when kube-proxy has no
// local endpoint.
type lbNoEndpointsManager struct {
	ipVersion    uint8
	filterTable  Table
	ruleRenderer rules.RuleRenderer
	services     map[lbNoEndpointsServiceID]*proto.ServiceUpdate
	activeChains []*generictables.Chain
	dirty        bool
}

func newLBNoEndpointsManager(filterTable Table, ruleRenderer rules.RuleRenderer, ipVersion uint8) *lbNoEndpointsManager {
	return &lbNoEndpointsManager{
		ipVersion: ipVersion, filterTable: filterTable, ruleRenderer: ruleRenderer,
		services: map[lbNoEndpointsServiceID]*proto.ServiceUpdate{}, dirty: true,
	}
}

func (m *lbNoEndpointsManager) OnUpdate(msg any) {
	switch update := msg.(type) {
	case *proto.ServiceUpdate:
		id := lbNoEndpointsServiceID{namespace: update.GetNamespace(), name: update.GetName()}
		if strings.EqualFold(update.GetNoEndpointsAction(), "Forward") {
			m.services[id] = update
		} else {
			delete(m.services, id)
		}
		m.dirty = true
	case *proto.ServiceRemove:
		delete(m.services, lbNoEndpointsServiceID{namespace: update.GetNamespace(), name: update.GetName()})
		m.dirty = true
	}
}

func (m *lbNoEndpointsManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}
	services := make([]*proto.ServiceUpdate, 0, len(m.services))
	for _, service := range m.services {
		services = append(services, service)
	}
	chains := m.ruleRenderer.LBNoEndpointServicesToIptablesChains(services, m.ipVersion)
	if !reflect.DeepEqual(m.activeChains, chains) {
		m.filterTable.RemoveChains(m.activeChains)
		m.filterTable.UpdateChains(chains)
		m.activeChains = chains
	}
	m.dirty = false
	return nil
}
