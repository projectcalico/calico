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
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/felix/set"
)

// masqManager manages the ipsets and iptables chains used to implement the "NAT outgoing" or
// "masquerade" feature.  The feature adds a boolean flag to each IPAM pool, which controls how
// outgoing traffic to non-Calico destinations is handled.  If the "masquerade" flag is set,
// outgoing traffic is source-NATted to appear to come from the host's IP address.
//
// The masqManager maintains two CIDR IP sets: one contains the CIDRs for all Calico
// IPAM pools, the other contains only the NAT-enabled pools.
//
// When NAT-enabled pools are present, the masqManager inserts the iptables masquerade rule
// to trigger NAT of outgoing packets from NAT-enabled pools.  Traffic to any Calico-owned
// pool is excluded.
type masqManager struct {
	ipVersion       uint8
	ipsetsDataplane ipsetsDataplane
	natTable        iptablesTable
	activePools     map[string]*proto.IPAMPool
	masqPools       set.Set
	dirty           bool
	ruleRenderer    rules.RuleRenderer

	logCxt *log.Entry
}

func newMasqManager(
	ipsetsDataplane ipsetsDataplane,
	natTable iptablesTable,
	ruleRenderer rules.RuleRenderer,
	maxIPSetSize int,
	ipVersion uint8,
) *masqManager {
	// Make sure our IP sets exist.  We set the contents to empty here
	// but the IPSets object will defer writing the IP sets until we're
	// in sync, by which point we'll have added all our CIDRs into the sets.
	ipsetsDataplane.AddOrReplaceIPSet(ipsets.IPSetMetadata{
		MaxSize: maxIPSetSize,
		SetID:   rules.IPSetIDNATOutgoingAllPools,
		Type:    ipsets.IPSetTypeHashNet,
	}, []string{})
	ipsetsDataplane.AddOrReplaceIPSet(ipsets.IPSetMetadata{
		MaxSize: maxIPSetSize,
		SetID:   rules.IPSetIDNATOutgoingMasqPools,
		Type:    ipsets.IPSetTypeHashNet,
	}, []string{})

	return &masqManager{
		ipVersion:       ipVersion,
		ipsetsDataplane: ipsetsDataplane,
		natTable:        natTable,
		activePools:     map[string]*proto.IPAMPool{},
		masqPools:       set.New(),
		dirty:           true,
		ruleRenderer:    ruleRenderer,
		logCxt:          log.WithField("ipVersion", ipVersion),
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
		d.ipsetsDataplane.RemoveMembers(rules.IPSetIDNATOutgoingAllPools, []string{oldPool.Cidr})
		if oldPool.Masquerade {
			logCxt.Debug("Masquerade was enabled on pool.")
			d.ipsetsDataplane.RemoveMembers(rules.IPSetIDNATOutgoingMasqPools, []string{oldPool.Cidr})
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
		d.ipsetsDataplane.AddMembers(rules.IPSetIDNATOutgoingAllPools, []string{newPool.Cidr})
		if newPool.Masquerade {
			logCxt.Debug("IPAM has masquerade enabled.")
			d.ipsetsDataplane.AddMembers(rules.IPSetIDNATOutgoingMasqPools, []string{newPool.Cidr})
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
