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
	"reflect"
)

type Config struct {
	DisableIPv6          bool
	RuleRendererOverride rules.RuleRenderer
}

func StartIntDataplaneDriver(config Config) *internalDataplane {
	ruleRenderer := config.RuleRendererOverride
	if ruleRenderer == nil {
		ruleRenderer = rules.NewRenderer()
	}
	filterTableV4 := iptables.NewTable("filter", 4, rules.AllHistoricChainNamePrefixes, rules.RuleHashPrefix)
	dp := &internalDataplane{
		toDataplane:       make(chan interface{}, 100),
		fromDataplane:     make(chan interface{}, 100),
		filterTableV4:     filterTableV4,
		ipsetsV4:          ipsets.NewIPSets(ipsets.IPFamilyV4),
		ruleRenderer:      ruleRenderer,
		endpointManagerV4: newEndpointManager(filterTableV4, ruleRenderer),
	}
	if !config.DisableIPv6 {
		dp.filterTableV6 = iptables.NewTable("filter", 6, rules.AllHistoricChainNamePrefixes, rules.RuleHashPrefix)
		dp.ipsetsV6 = ipsets.NewIPSets(ipsets.IPFamilyV6)
		dp.endpointManagerV6 = newEndpointManager(dp.filterTableV6, ruleRenderer)
	}
	go dp.loopUpdatingDataplane()
	go dp.loopReportingStatus()
	return dp
}

type internalDataplane struct {
	toDataplane   chan interface{}
	fromDataplane chan interface{}

	filterTableV4 *iptables.Table
	filterTableV6 *iptables.Table

	ipsetsV4 *ipsets.IPSets
	ipsetsV6 *ipsets.IPSets

	endpointManagerV4 *endpointManager
	endpointManagerV6 *endpointManager

	ruleRenderer rules.RuleRenderer
}

func (d *internalDataplane) SendMessage(msg interface{}) error {
	d.toDataplane <- msg
	return nil
}

func (d *internalDataplane) RecvMessage() (interface{}, error) {
	return <-d.fromDataplane, nil
}

func (d *internalDataplane) loopUpdatingDataplane() {
	log.Info("Started internal iptables dataplane driver")
	inSync := false
	for msg := range d.toDataplane {
		log.WithField("msg", msg).Info("Received update from calculation graph")
		switch msg := msg.(type) {
		// IP set-related messages, these are extremely common.
		case *proto.IPSetDeltaUpdate:
			// TODO(smc) Feels ugly to do the fan-out here.
			d.ipsetsV4.AddIPsToIPSet(msg.Id, msg.AddedMembers)
			d.ipsetsV4.RemoveIPsFromIPSet(msg.Id, msg.RemovedMembers)
			d.ipsetsV6.AddIPsToIPSet(msg.Id, msg.AddedMembers)
			d.ipsetsV6.RemoveIPsFromIPSet(msg.Id, msg.RemovedMembers)
		case *proto.IPSetUpdate:
			d.ipsetsV4.CreateOrReplaceIPSet(ipsets.IPSetMetadata{
				Type:     ipsets.IPSetTypeHashIP,
				SetID:    msg.Id,
				IPFamily: ipsets.IPFamilyV4,
				MaxSize:  1024 * 1024,
			}, msg.Members)
			d.ipsetsV6.CreateOrReplaceIPSet(ipsets.IPSetMetadata{
				Type:     ipsets.IPSetTypeHashIP,
				SetID:    msg.Id,
				IPFamily: ipsets.IPFamilyV6,
				MaxSize:  1024 * 1024,
			}, msg.Members)
		case *proto.IPSetRemove:
			d.ipsetsV4.RemoveIPSet(msg.Id)
			d.ipsetsV6.RemoveIPSet(msg.Id)

		// Local workload updates.
		case *proto.WorkloadEndpointUpdate:
			d.endpointManagerV4.OnUpdate(msg)
			d.endpointManagerV6.OnUpdate(msg)
		case *proto.WorkloadEndpointRemove:
			d.endpointManagerV4.OnRemove(msg)
			d.endpointManagerV6.OnRemove(msg)

		// Local host endpoint updates.
		case *proto.HostEndpointUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.HostEndpointRemove:
			log.WithField("msg", msg).Warn("Message not implemented")

		// Local active policy updates.
		case *proto.ActivePolicyUpdate:
			chains := d.ruleRenderer.PolicyToIptablesChains(msg.Id, msg.Policy)
			d.filterTableV4.UpdateChains(chains)
			// TODO(smc) Distinct chains for v6 (need to filter on the IPVersion field)
			d.filterTableV6.UpdateChains(chains)
		case *proto.ActivePolicyRemove:
			inName := rules.PolicyChainName(rules.PolicyInboundPfx, msg.Id)
			outName := rules.PolicyChainName(rules.PolicyOutboundPfx, msg.Id)
			d.filterTableV4.RemoveChainByName(inName)
			d.filterTableV4.RemoveChainByName(outName)
			d.filterTableV6.RemoveChainByName(inName)
			d.filterTableV6.RemoveChainByName(outName)

		case *proto.ActiveProfileUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.ActiveProfileRemove:
			log.WithField("msg", msg).Warn("Message not implemented")

		// Less common cluster config updates.
		case *proto.HostMetadataUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.HostMetadataRemove:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.IPAMPoolUpdate:
			log.WithField("msg", msg).Warn("Message not implemented")
		case *proto.IPAMPoolRemove:
			log.WithField("msg", msg).Warn("Message not implemented")

		case *proto.ConfigUpdate:
			// Since we're in-process, we get our config from the typed config object.
			log.Debug("Ignoring config update")
		case *proto.InSync:
			// TODO(smc) need to generate InSync message after each flush of the EventSequencer?
			log.Info("Datastore in sync, flushing the dataplane for the first time...")
			inSync = true
		default:
			log.WithField("msg", msg).Panic("Unknown message type")
		}

		if inSync {
			d.apply()
		}
	}
}

func (d *internalDataplane) apply() {
	d.ipsetsV4.ApplyUpdates()
	d.ipsetsV6.ApplyUpdates()

	d.endpointManagerV4.Apply()
	d.endpointManagerV6.Apply()

	d.filterTableV4.Apply()
	d.filterTableV6.Apply()

	d.ipsetsV4.ApplyDeletions()
	d.ipsetsV6.ApplyDeletions()
}

func (d *internalDataplane) loopReportingStatus() {
	log.Info("Started internal status report thread")
	// TODO(smc) Implement status reporting.
}

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

func (m *endpointManager) OnUpdate(msg *proto.WorkloadEndpointUpdate) {
	m.allEndpoints[*msg.Id] = msg.Endpoint
	m.dirtyEndpoints.Add(*msg.Id)
}

func (m *endpointManager) OnRemove(msg *proto.WorkloadEndpointRemove) {
	delete(m.allEndpoints, *msg.Id)
	m.dirtyEndpoints.Add(*msg.Id)
}

func (m *endpointManager) Apply() {
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
