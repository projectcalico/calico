// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

// The service loop manager maintains an iptables chain in the filter table whose purpose is to
// prevent forwarding to IPs within known service CIDRs.  Traffic that arrives on the node with such
// IPs is supposed to be DNAT'd to an endpoint pod IP:port by kube-proxy iptables or IPVS rules.  If
// that doesn't happen, it means that target service IP:port isn't actually in use; and in that case
// it's better for us to drop it, to avoid a possible routing loop between this node and this node's
// default gateway.  The specific loop-generating scenario is when Calico is configured to advertise
// service CIDRs and IPs over BGP: then the default gateway will have a route back to this node, for
// the service CIDR, and there could be a loop if we allowed nonexistent service traffic to be
// forwarded on from here.
type serviceLoopManager struct {
	ipVersion uint8

	// Our dependencies.
	filterTable  Table
	ruleRenderer rules.RuleRenderer

	// Internal state.
	activeFilterChains     []*generictables.Chain
	pendingGlobalBGPConfig *proto.GlobalBGPConfigUpdate
}

func newServiceLoopManager(
	filterTable Table,
	ruleRenderer rules.RuleRenderer,
	ipVersion uint8,
) *serviceLoopManager {
	return &serviceLoopManager{
		ipVersion:              ipVersion,
		filterTable:            filterTable,
		ruleRenderer:           ruleRenderer,
		activeFilterChains:     []*generictables.Chain{},
		pendingGlobalBGPConfig: &proto.GlobalBGPConfigUpdate{},
	}
}

func (m *serviceLoopManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.GlobalBGPConfigUpdate:
		m.pendingGlobalBGPConfig = msg
	}
}

func (m *serviceLoopManager) CompleteDeferredWork() error {
	if m.pendingGlobalBGPConfig != nil {
		blockedCIDRs := []string{}
		blockedCIDRs = append(blockedCIDRs, m.pendingGlobalBGPConfig.GetServiceClusterCidrs()...)
		blockedCIDRs = append(blockedCIDRs, m.pendingGlobalBGPConfig.GetServiceExternalCidrs()...)
		blockedCIDRs = append(blockedCIDRs, m.pendingGlobalBGPConfig.GetServiceLoadbalancerCidrs()...)

		// Render chains for those cluster CIDRs.
		newFilterChains := m.ruleRenderer.BlockedCIDRsToIptablesChains(blockedCIDRs, m.ipVersion)

		// Update iptables if they have changed.
		if !reflect.DeepEqual(m.activeFilterChains, newFilterChains) {
			m.filterTable.RemoveChains(m.activeFilterChains)
			m.filterTable.UpdateChains(newFilterChains)
			m.activeFilterChains = newFilterChains
		}
		m.pendingGlobalBGPConfig = nil
	}
	return nil
}
