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
	"github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/rules"
	"github.com/projectcalico/felix/go/felix/set"
	"strings"
)

type masqManager struct {
	ipVersion    uint8
	ipsets       *ipsets.IPSets
	natTable     *iptables.Table
	activePools  map[string]*proto.IPAMPool
	masqPools    set.Set
	dirty        bool
	ruleRenderer rules.RuleRenderer

	logCxt *log.Entry
}

func newMasqManager(
	ipsetsMgr *ipsets.IPSets,
	natTable *iptables.Table,
	ruleRenderer rules.RuleRenderer,
	maxIPSetSize int,
	ipVersion uint8,
) *masqManager {
	// Make sure our IP sets exist.  We set the contents to empty here
	// but the IPSets object will defer writing the IP sets until we're
	// in sync, by which point we'll have added all our CIDRs into the sets.
	ipsetsMgr.AddOrReplaceIPSet(ipsets.IPSetMetadata{
		MaxSize: maxIPSetSize,
		SetID:   rules.NATOutgoingAllIPsSetID,
		Type:    ipsets.IPSetTypeHashNet,
	}, []string{})
	ipsetsMgr.AddOrReplaceIPSet(ipsets.IPSetMetadata{
		MaxSize: maxIPSetSize,
		SetID:   rules.NATOutgoingMasqIPsSetID,
		Type:    ipsets.IPSetTypeHashNet,
	}, []string{})

	return &masqManager{
		ipVersion:    ipVersion,
		ipsets:       ipsetsMgr,
		natTable:     natTable,
		activePools:  map[string]*proto.IPAMPool{},
		masqPools:    set.New(),
		dirty:        true,
		ruleRenderer: ruleRenderer,
		logCxt:       log.WithField("ipVersion", ipVersion),
	}
}

func (d *masqManager) OnUpdate(msg interface{}) {
	var poolID string
	var newPool *proto.IPAMPool

	switch msg := msg.(type) {
	case *proto.IPAMPoolUpdate:
		d.logCxt.WithField("id", msg.Id).Debug("IPAM pool update/create")
		poolID = msg.Id
		newPool = msg.Pool
	case *proto.IPAMPoolRemove:
		d.logCxt.WithField("id", msg.Id).Debug("IPAM pool removed")
		poolID = msg.Id
	default:
		return
	}

	logCxt := d.logCxt.WithField("id", poolID)
	if oldPool := d.activePools[poolID]; oldPool != nil {
		// For simplicity (in case of an update to the CIDR, say) always
		// remove the old values from the IP sets.  The IPSets object
		// defers and coalesces the update so removing then adding the
		// same IP is a no-op anyway.
		logCxt.Debug("Removing old pool.")
		d.ipsets.RemoveMembers(rules.NATOutgoingAllIPsSetID, []string{oldPool.Cidr})
		if oldPool.Masquerade {
			logCxt.Debug("Masquerade was enabled on pool.")
			d.ipsets.RemoveMembers(rules.NATOutgoingMasqIPsSetID, []string{oldPool.Cidr})
		}
		delete(d.activePools, poolID)
		d.masqPools.Discard(poolID)
	}
	if newPool != nil {
		// An update/create.
		newPoolIsV6 := strings.Contains(newPool.Cidr, ":")
		weAreV6 := d.ipVersion == 6
		if newPoolIsV6 != weAreV6 {
			logCxt.Debug("Skipping IPAM pool of different version.")
			return
		}

		// Update the IP sets.
		logCxt.Debug("Adding IPAM pool to IP sets.")
		d.ipsets.AddMembers(rules.NATOutgoingAllIPsSetID, []string{newPool.Cidr})
		if newPool.Masquerade {
			logCxt.Debug("IPAM has masquerade enabled.")
			d.ipsets.AddMembers(rules.NATOutgoingMasqIPsSetID, []string{newPool.Cidr})
			d.masqPools.Add(poolID)
		}
		d.activePools[poolID] = newPool
	}
	d.dirty = true
}

func (m *masqManager) CompleteDeferredWork() error {
	if !m.dirty {
		return nil
	}

	// Refresh the chain in case we've gone from having no masq pools to
	// having some or vice-versa.
	m.logCxt.Info("IPAM pools updated, refreshing iptables rule")
	chain := m.ruleRenderer.NATOutgoingChain(m.masqPools.Len() > 0, m.ipVersion)
	m.natTable.UpdateChain(chain)
	m.dirty = false

	return nil
}
