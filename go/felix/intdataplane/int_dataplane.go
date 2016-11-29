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
	"github.com/projectcalico/felix/go/felix/ifacemonitor"
	"github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/routetable"
	"github.com/projectcalico/felix/go/felix/rules"
	"time"
)

type Config struct {
	DisableIPv6          bool
	RuleRendererOverride rules.RuleRenderer

	RulesConfig rules.Config
}

func NewIntDataplaneDriver(config Config) *InternalDataplane {
	ruleRenderer := config.RuleRendererOverride
	if ruleRenderer == nil {
		ruleRenderer = rules.NewRenderer(config.RulesConfig)
	}
	dp := &InternalDataplane{
		toDataplane:       make(chan interface{}, 100),
		fromDataplane:     make(chan interface{}, 100),
		ruleRenderer:      ruleRenderer,
		interfacePrefixes: config.RulesConfig.WorkloadIfacePrefixes,
		cleanupPending:    true,
		ifaceMonitor:      ifacemonitor.New(),
		ifaceUpdates:      make(chan *ifaceUpdate, 100),
	}

	dp.ifaceMonitor.Callback = dp.onIfaceStateChange

	natTableV4 := iptables.NewTable("nat", 4, rules.AllHistoricChainNamePrefixes, rules.RuleHashPrefix)
	rawTableV4 := iptables.NewTable("raw", 4, rules.AllHistoricChainNamePrefixes, rules.RuleHashPrefix)
	filterTableV4 := iptables.NewTable("filter", 4, rules.AllHistoricChainNamePrefixes, rules.RuleHashPrefix)
	ipSetsConfigV4 := config.RulesConfig.IPSetConfigV4
	ipSetsV4 := ipsets.NewIPSets(ipSetsConfigV4)
	dp.iptablesNATTables = append(dp.iptablesNATTables, natTableV4)
	dp.iptablesRawTables = append(dp.iptablesRawTables, rawTableV4)
	dp.iptablesFilterTables = append(dp.iptablesFilterTables, filterTableV4)
	dp.ipsetsWriters = append(dp.ipsetsWriters, ipSetsV4)

	routeTableV4 := routetable.New(config.RulesConfig.WorkloadIfacePrefixes, 4)
	dp.routeTables = append(dp.routeTables, routeTableV4)

	dp.RegisterManager(newIPSetsManager(ipSetsV4))
	dp.RegisterManager(newPolicyManager(filterTableV4, ruleRenderer, 4))
	dp.RegisterManager(newEndpointManager(
		filterTableV4,
		ruleRenderer,
		routeTableV4,
		4,
		config.RulesConfig.WorkloadIfacePrefixes))

	if !config.DisableIPv6 {
		natTableV6 := iptables.NewTable("nat", 6, rules.AllHistoricChainNamePrefixes, rules.RuleHashPrefix)
		rawTableV6 := iptables.NewTable("raw", 6, rules.AllHistoricChainNamePrefixes, rules.RuleHashPrefix)
		filterTableV6 := iptables.NewTable("filter", 6, rules.AllHistoricChainNamePrefixes, rules.RuleHashPrefix)

		ipSetsConfigV6 := config.RulesConfig.IPSetConfigV6
		ipSetsV6 := ipsets.NewIPSets(ipSetsConfigV6)
		dp.ipsetsWriters = append(dp.ipsetsWriters, ipSetsV6)
		dp.iptablesNATTables = append(dp.iptablesNATTables, natTableV6)
		dp.iptablesRawTables = append(dp.iptablesRawTables, rawTableV6)
		dp.iptablesFilterTables = append(dp.iptablesFilterTables, filterTableV6)

		routeTableV6 := routetable.New(config.RulesConfig.WorkloadIfacePrefixes, 6)
		dp.routeTables = append(dp.routeTables, routeTableV6)

		dp.RegisterManager(newIPSetsManager(ipSetsV6))
		dp.RegisterManager(newPolicyManager(filterTableV6, ruleRenderer, 6))
		dp.RegisterManager(newEndpointManager(
			filterTableV6,
			ruleRenderer,
			routeTableV6,
			6,
			config.RulesConfig.WorkloadIfacePrefixes))
	}
	return dp
}

type Manager interface {
	// TODO(smc) add machinery to send only the required messages to each Manager.

	// OnUpdate is called for each protobuf message from the datastore.  May either directly
	// send updates to the IPSets and iptables.Table objects (which will queue the updates
	// until the main loop instructs them to act) or (for efficiency) may wait until
	// a call to CompleteDeferredWork() to flush updates to the dataplane.
	OnUpdate(protoBufMsg interface{})
	// Called before the main loop flushes updates to the dataplane to allow for batched
	// work to be completed.
	CompleteDeferredWork() error
}

type InternalDataplane struct {
	toDataplane   chan interface{}
	fromDataplane chan interface{}

	iptablesNATTables    []*iptables.Table
	iptablesRawTables    []*iptables.Table
	iptablesFilterTables []*iptables.Table
	ipsetsWriters        []*ipsets.IPSets

	ifaceMonitor *ifacemonitor.InterfaceMonitor
	ifaceUpdates chan *ifaceUpdate

	allManagers []Manager

	ruleRenderer rules.RuleRenderer

	interfacePrefixes []string

	routeTables []*routetable.RouteTable

	dataplaneNeedsSync bool
	cleanupPending     bool
}

func (d *InternalDataplane) RegisterManager(mgr Manager) {
	d.allManagers = append(d.allManagers, mgr)
}

func (d *InternalDataplane) Start() {
	go d.loopUpdatingDataplane()
	go d.loopReportingStatus()
	go d.ifaceMonitor.MonitorInterfaces()
}

// onIfaceStateChange is our interface monitor callback.  It gets called from the monitor's thread.
func (d *InternalDataplane) onIfaceStateChange(ifaceName string, state ifacemonitor.State) {
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"state":     state,
	}).Info("Linux interface state changed.")
	d.ifaceUpdates <- &ifaceUpdate{
		Name:  ifaceName,
		State: state,
	}
}

type ifaceUpdate struct {
	Name  string
	State ifacemonitor.State
}

func (d *InternalDataplane) SendMessage(msg interface{}) error {
	d.toDataplane <- msg
	return nil
}

func (d *InternalDataplane) RecvMessage() (interface{}, error) {
	return <-d.fromDataplane, nil
}

func (d *InternalDataplane) loopUpdatingDataplane() {
	log.Info("Started internal iptables dataplane driver")

	// TODO Check global RPF value is sane (can't be "loose").

	// Endure that the default value of rp_filter is set to "strict" for newly-created
	// interfaces.  This is required to prevent a race between starting an interface and
	// Felix being able to configure it.
	writeProcSys("/proc/sys/net/ipv4/conf/default/rp_filter", "1")

	for _, t := range d.iptablesFilterTables {
		t.UpdateChains(d.ruleRenderer.StaticFilterTableChains())
		t.SetRuleInsertions("FORWARD", []iptables.Rule{{
			Action: iptables.JumpAction{rules.ForwardChainName},
		}})
	}

	// Retry any failed operations every 10s.
	retryTicker := time.NewTicker(10 * time.Second)

	datastoreInSync := false
	for {
		select {
		case msg := <-d.toDataplane:
			log.WithField("msg", msg).Info("Received update from calculation graph")
			for _, mgr := range d.allManagers {
				mgr.OnUpdate(msg)
			}

			switch msg := msg.(type) {

			case *proto.WorkloadEndpointUpdate:
				// TODO(smc) For now, report every workload endpoint as "UP".
				d.fromDataplane <- &proto.FromDataplane_WorkloadEndpointStatusUpdate{
					WorkloadEndpointStatusUpdate: &proto.WorkloadEndpointStatusUpdate{
						Id: msg.Id,
						Status: &proto.EndpointStatus{
							Status: "up",
						},
					},
				}
			case *proto.WorkloadEndpointRemove:
				// TODO(smc) For now, report every workload endpoint as "UP".
				d.fromDataplane <- &proto.FromDataplane_WorkloadEndpointStatusRemove{
					WorkloadEndpointStatusRemove: &proto.WorkloadEndpointStatusRemove{
						Id: msg.Id,
					},
				}
			case *proto.InSync:
				// TODO(smc) need to generate InSync message after each flush of the EventSequencer?
				log.Info("Datastore in sync, flushing the dataplane for the first time...")
				datastoreInSync = true
			}
			d.dataplaneNeedsSync = true
		case ifaceUpdate := <-d.ifaceUpdates:
			log.WithField("msg", ifaceUpdate).Info("Received interface update")
			for _, mgr := range d.allManagers {
				mgr.OnUpdate(ifaceUpdate)
			}
			d.dataplaneNeedsSync = true
		case <-retryTicker.C:
		}

		if datastoreInSync && d.dataplaneNeedsSync {
			d.apply()
		}
	}
}

func (d *InternalDataplane) apply() {
	// Update sequencing is important here because iptables rules have dependencies on ipsets.
	// Creating a rule that references an unknown IP set fails, as does deleting an IP set that
	// is in use.

	// Unset the needs-sync flag, we'll set it again if something fails.
	d.dataplaneNeedsSync = false

	// First, give the managers a chance to update IP sets and iptables.
	for _, mgr := range d.allManagers {
		err := mgr.CompleteDeferredWork()
		if err != nil {
			d.dataplaneNeedsSync = true
		}
	}

	// Next, create/update IP sets.  We defer deletions of IP sets until after we update
	// iptables.
	for _, w := range d.ipsetsWriters {
		w.ApplyUpdates()
	}

	// Update iptables, this should sever any references to now-unused IP sets.
	for _, t := range d.iptablesFilterTables {
		t.Apply()
	}
	for _, t := range d.iptablesNATTables {
		t.Apply()
	}
	for _, t := range d.iptablesRawTables {
		t.Apply()
	}

	// Update the routing table.
	for _, r := range d.routeTables {
		err := r.Apply()
		if err != nil {
			log.Warn("Failed to synchronize routing table, will retry...")
			d.dataplaneNeedsSync = true
		}
	}

	// Now clean up any left-over IP sets.
	for _, w := range d.ipsetsWriters {
		w.ApplyDeletions()
	}

	if d.cleanupPending {
		for _, w := range d.ipsetsWriters {
			w.AttemptCleanup()
		}
		d.cleanupPending = false
	}
}

func (d *InternalDataplane) loopReportingStatus() {
	log.Info("Started internal status report thread")
	// TODO(smc) Implement status reporting.
}
