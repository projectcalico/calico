// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
)

// policyManager simply renders policy/profile updates into iptables.Chain objects and sends
// them to the dataplane layer.
type policyManager struct {
	rawTable     iptablesTable
	mangleTable  iptablesTable
	filterTable  iptablesTable
	ruleRenderer policyRenderer
	ipVersion    uint8
}

type policyRenderer interface {
	PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*iptables.Chain
	ProfileToIptablesChains(profileID *proto.ProfileID, policy *proto.Profile, ipVersion uint8) []*iptables.Chain
}

func newPolicyManager(rawTable, mangleTable, filterTable iptablesTable, ruleRenderer policyRenderer, ipVersion uint8) *policyManager {
	return &policyManager{
		rawTable:     rawTable,
		mangleTable:  mangleTable,
		filterTable:  filterTable,
		ruleRenderer: ruleRenderer,
		ipVersion:    ipVersion,
	}
}

func (m *policyManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.ActivePolicyUpdate:
		log.WithField("id", msg.Id).Debug("Updating policy chains")
		chains := m.ruleRenderer.PolicyToIptablesChains(msg.Id, msg.Policy, m.ipVersion)
		m.rawTable.UpdateChains(chains)
		m.mangleTable.UpdateChains(chains)
		m.filterTable.UpdateChains(chains)
	case *proto.ActivePolicyRemove:
		log.WithField("id", msg.Id).Debug("Removing policy chains")
		inName := rules.PolicyChainName(rules.PolicyInboundPfx, msg.Id)
		outName := rules.PolicyChainName(rules.PolicyOutboundPfx, msg.Id)
		m.filterTable.RemoveChainByName(inName)
		m.filterTable.RemoveChainByName(outName)
		m.mangleTable.RemoveChainByName(inName)
		m.mangleTable.RemoveChainByName(outName)
		m.rawTable.RemoveChainByName(inName)
		m.rawTable.RemoveChainByName(outName)
	case *proto.ActiveProfileUpdate:
		log.WithField("id", msg.Id).Debug("Updating profile chains")
		chains := m.ruleRenderer.ProfileToIptablesChains(msg.Id, msg.Profile, m.ipVersion)
		m.filterTable.UpdateChains(chains)
	case *proto.ActiveProfileRemove:
		log.WithField("id", msg.Id).Debug("Removing profile chains")
		inName := rules.ProfileChainName(rules.ProfileInboundPfx, msg.Id)
		outName := rules.ProfileChainName(rules.ProfileOutboundPfx, msg.Id)
		m.filterTable.RemoveChainByName(inName)
		m.filterTable.RemoveChainByName(outName)
	}
}

func (m *policyManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
