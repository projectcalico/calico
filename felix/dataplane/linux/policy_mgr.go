// Copyright (c) 2016-2023 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// policyManager simply renders policy/profile updates into generictables.Chain objects and sends
// them to the dataplane layer.
type policyManager struct {
	rawTable         Table
	mangleTable      Table
	filterTable      Table
	ruleRenderer     policyRenderer
	ipVersion        uint8
	rawEgressOnly    bool
	ipSetFilterDirty bool // Only used in "raw only" mode.
	neededIPSets     map[types.PolicyID]set.Set[string]
	ipSetsCallback   func(neededIPSets set.Set[string])
	nftablesEnabled  bool
}

type policyRenderer interface {
	PolicyToIptablesChains(policyID *types.PolicyID, policy *proto.Policy, ipVersion uint8) []*generictables.Chain
	ProfileToIptablesChains(profileID *types.ProfileID, policy *proto.Profile, ipVersion uint8) (inbound, outbound *generictables.Chain)
}

func newPolicyManager(rawTable, mangleTable, filterTable Table, ruleRenderer policyRenderer, ipVersion uint8, nft bool) *policyManager {
	return &policyManager{
		rawTable:        rawTable,
		mangleTable:     mangleTable,
		filterTable:     filterTable,
		ruleRenderer:    ruleRenderer,
		ipVersion:       ipVersion,
		nftablesEnabled: nft,
	}
}

func newRawEgressPolicyManager(rawTable Table, ruleRenderer policyRenderer, ipVersion uint8,
	ipSetsCallback func(neededIPSets set.Set[string]),
	nft bool,
) *policyManager {
	return &policyManager{
		rawTable:      rawTable,
		mangleTable:   generictables.NewNoopTable(),
		filterTable:   generictables.NewNoopTable(),
		ruleRenderer:  ruleRenderer,
		ipVersion:     ipVersion,
		rawEgressOnly: true,
		// Make sure we set the filter at start-of-day, even if there are no policies.
		ipSetFilterDirty: true,
		neededIPSets:     make(map[types.PolicyID]set.Set[string]),
		ipSetsCallback:   ipSetsCallback,
		nftablesEnabled:  nft,
	}
}

func (m *policyManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.ActivePolicyUpdate:
		id := types.ProtoToPolicyID(msg.GetId())
		if m.rawEgressOnly && !msg.Policy.Untracked {
			log.WithField("id", msg.Id).Debug("Clean up non-untracked policy.")
			m.cleanUpPolicy(&id)
			return
		}
		log.WithField("id", msg.Id).Debug("Updating policy chains")
		chains := m.ruleRenderer.PolicyToIptablesChains(&id, msg.Policy, m.ipVersion)
		if m.rawEgressOnly {
			neededIPSets := set.New[string]()
			filteredChains := []*generictables.Chain(nil)
			for _, chain := range chains {
				if strings.Contains(chain.Name, string(rules.PolicyOutboundPfx)) {
					filteredChains = append(filteredChains, chain)
					neededIPSets.AddAll(chain.IPSetNames())
				}
			}
			chains = filteredChains
			m.updateNeededIPSets(&id, neededIPSets)
		}
		// We can't easily tell whether the policy is in use in a particular table, and, if the policy
		// type gets changed it may move between tables.  Hence, we put the policy into all tables.
		// The iptables layer will avoid programming it if it is not actually used.
		m.rawTable.UpdateChains(chains)
		m.mangleTable.UpdateChains(chains)
		m.filterTable.UpdateChains(chains)
	case *proto.ActivePolicyRemove:
		log.WithField("id", msg.Id).Debug("Removing policy chains")
		id := types.ProtoToPolicyID(msg.GetId())
		m.cleanUpPolicy(&id)
	case *proto.ActiveProfileUpdate:
		id := types.ProtoToProfileID(msg.GetId())
		if m.rawEgressOnly {
			log.WithField("id", msg.Id).Debug("Ignore non-untracked profile")
			return
		}
		log.WithField("id", msg.Id).Debug("Updating profile chains")
		inbound, outbound := m.ruleRenderer.ProfileToIptablesChains(&id, msg.Profile, m.ipVersion)
		m.filterTable.UpdateChains([]*generictables.Chain{inbound, outbound})
		m.mangleTable.UpdateChains([]*generictables.Chain{outbound})
	case *proto.ActiveProfileRemove:
		log.WithField("id", msg.Id).Debug("Removing profile chains")
		id := types.ProtoToProfileID(msg.GetId())
		inName := rules.ProfileChainName(rules.ProfileInboundPfx, &id, m.nftablesEnabled)
		outName := rules.ProfileChainName(rules.ProfileOutboundPfx, &id, m.nftablesEnabled)
		m.filterTable.RemoveChainByName(inName)
		m.filterTable.RemoveChainByName(outName)
		m.mangleTable.RemoveChainByName(outName)
	}
}

func (m *policyManager) cleanUpPolicy(id *types.PolicyID) {
	if m.rawEgressOnly {
		m.updateNeededIPSets(id, nil)
	}
	inName := rules.PolicyChainName(rules.PolicyInboundPfx, id, m.nftablesEnabled)
	outName := rules.PolicyChainName(rules.PolicyOutboundPfx, id, m.nftablesEnabled)
	// As above, we need to clean up in all the tables.
	m.filterTable.RemoveChainByName(inName)
	m.filterTable.RemoveChainByName(outName)
	m.mangleTable.RemoveChainByName(inName)
	m.mangleTable.RemoveChainByName(outName)
	m.rawTable.RemoveChainByName(inName)
	m.rawTable.RemoveChainByName(outName)
}

func (m *policyManager) updateNeededIPSets(id *types.PolicyID, neededIPSets set.Set[string]) {
	if neededIPSets != nil {
		m.neededIPSets[*id] = neededIPSets
	} else {
		delete(m.neededIPSets, *id)
	}
	m.ipSetFilterDirty = true
}

func (m *policyManager) CompleteDeferredWork() error {
	if !m.rawEgressOnly {
		return nil
	}
	if !m.ipSetFilterDirty {
		return nil
	}
	m.ipSetFilterDirty = false

	merged := set.New[string]()
	for _, ipSets := range m.neededIPSets {
		ipSets.Iter(func(item string) error {
			merged.Add(item)
			return nil
		})
	}
	m.ipSetsCallback(merged)
	return nil
}
