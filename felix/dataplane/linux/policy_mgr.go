// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.
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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

// policyManager simply renders policy/profile updates into iptables.Chain objects and sends
// them to the dataplane layer.
type policyManager struct {
	rawTable       iptablesTable
	mangleTable    iptablesTable
	filterTable    iptablesTable
	ruleRenderer   policyRenderer
	ipVersion      uint8
	rawEgressOnly  bool
	neededIPSets   map[proto.PolicyID]set.Set[string]
	ipSetsCallback func(neededIPSets set.Set[string])
}

type policyRenderer interface {
	PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy, ipVersion uint8) []*iptables.Chain
	ProfileToIptablesChains(profileID *proto.ProfileID, policy *proto.Profile, ipVersion uint8) (inbound, outbound *iptables.Chain)
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

func newRawEgressPolicyManager(rawTable iptablesTable, ruleRenderer policyRenderer, ipVersion uint8,
	ipSetsCallback func(neededIPSets set.Set[string])) *policyManager {
	return &policyManager{
		rawTable:       rawTable,
		mangleTable:    &noopTable{},
		filterTable:    &noopTable{},
		ruleRenderer:   ruleRenderer,
		ipVersion:      ipVersion,
		rawEgressOnly:  true,
		neededIPSets:   make(map[proto.PolicyID]set.Set[string]),
		ipSetsCallback: ipSetsCallback,
	}
}

func (m *policyManager) mergeNeededIPSets(id *proto.PolicyID, neededIPSets set.Set[string]) {
	if neededIPSets != nil {
		m.neededIPSets[*id] = neededIPSets
	} else {
		delete(m.neededIPSets, *id)
	}
	merged := set.New[string]()
	for _, ipSets := range m.neededIPSets {
		ipSets.Iter(func(item string) error {
			merged.Add(item)
			return nil
		})
	}
	m.ipSetsCallback(merged)
}

func (m *policyManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.ActivePolicyUpdate:
		if m.rawEgressOnly && !msg.Policy.Untracked {
			log.WithField("id", msg.Id).Debug("Ignore non-untracked policy")
			return
		}
		log.WithField("id", msg.Id).Debug("Updating policy chains")
		chains := m.ruleRenderer.PolicyToIptablesChains(msg.Id, msg.Policy, m.ipVersion)
		if m.rawEgressOnly {
			neededIPSets := set.New[string]()
			filteredChains := []*iptables.Chain(nil)
			for _, chain := range chains {
				if strings.Contains(chain.Name, string(rules.PolicyOutboundPfx)) {
					filteredChains = append(filteredChains, chain)
					neededIPSets.AddAll(chain.IPSetNames())
				}
			}
			chains = filteredChains
			m.mergeNeededIPSets(msg.Id, neededIPSets)
		}
		// We can't easily tell whether the policy is in use in a particular table, and, if the policy
		// type gets changed it may move between tables.  Hence, we put the policy into all tables.
		// The iptables layer will avoid programming it if it is not actually used.
		m.rawTable.UpdateChains(chains)
		m.mangleTable.UpdateChains(chains)
		m.filterTable.UpdateChains(chains)
	case *proto.ActivePolicyRemove:
		log.WithField("id", msg.Id).Debug("Removing policy chains")
		if m.rawEgressOnly {
			m.mergeNeededIPSets(msg.Id, nil)
		}
		inName := rules.PolicyChainName(rules.PolicyInboundPfx, msg.Id)
		outName := rules.PolicyChainName(rules.PolicyOutboundPfx, msg.Id)
		// As above, we need to clean up in all the tables.
		m.filterTable.RemoveChainByName(inName)
		m.filterTable.RemoveChainByName(outName)
		m.mangleTable.RemoveChainByName(inName)
		m.mangleTable.RemoveChainByName(outName)
		m.rawTable.RemoveChainByName(inName)
		m.rawTable.RemoveChainByName(outName)
	case *proto.ActiveProfileUpdate:
		if m.rawEgressOnly {
			log.WithField("id", msg.Id).Debug("Ignore non-untracked profile")
			return
		}
		log.WithField("id", msg.Id).Debug("Updating profile chains")
		inbound, outbound := m.ruleRenderer.ProfileToIptablesChains(msg.Id, msg.Profile, m.ipVersion)
		m.filterTable.UpdateChains([]*iptables.Chain{inbound, outbound})
		m.mangleTable.UpdateChains([]*iptables.Chain{outbound})
	case *proto.ActiveProfileRemove:
		log.WithField("id", msg.Id).Debug("Removing profile chains")
		inName := rules.ProfileChainName(rules.ProfileInboundPfx, msg.Id)
		outName := rules.ProfileChainName(rules.ProfileOutboundPfx, msg.Id)
		m.filterTable.RemoveChainByName(inName)
		m.filterTable.RemoveChainByName(outName)
		m.mangleTable.RemoveChainByName(outName)
	}
}

func (m *policyManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}

// noopTable fulfils the iptablesTable interface but does nothing.
type noopTable struct{}

func (t *noopTable) UpdateChain(chain *iptables.Chain) {}
func (t *noopTable) UpdateChains([]*iptables.Chain)    {}
func (t *noopTable) RemoveChains([]*iptables.Chain)    {}
func (t *noopTable) RemoveChainByName(name string)     {}
