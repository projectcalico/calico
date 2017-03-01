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
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/jitter"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/routetable"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/felix/set"
	"github.com/projectcalico/felix/throttle"
)

const (
	// msgPeekLimit is the maximum number of messages we'll try to grab from the to-dataplane
	// channel before we apply the changes.  Higher values allow us to batch up more work on
	// the channel for greater throughput when we're under load (at cost of higher latency).
	msgPeekLimit = 100
)

var (
	countDataplaneSyncErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_int_dataplane_failures",
		Help: "Number of times dataplane updates failed and will be retried.",
	})
	countMessages = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_int_dataplane_messages",
		Help: "Number dataplane messages by type.",
	}, []string{"type"})
	histApplyTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "felix_int_dataplane_apply_time_seconds",
		Help: "Time in seconds that it took to apply a dataplane update.",
		Buckets: []float64{
			0.02, 0.05, 0.1, 0.2, 0.5, 1.0,
		},
	})
	histBatchSize = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "felix_int_dataplane_msg_batch_size",
		Help: "Number of messages processed in each batch. Higher values indicate we're " +
			"doing more batching to try to keep up.",
		Buckets: []float64{
			1, 2, 5, 10, 20, 50,
		},
	})

	processStartTime time.Time
)

func init() {
	prometheus.MustRegister(countDataplaneSyncErrors)
	prometheus.MustRegister(histApplyTime)
	prometheus.MustRegister(countMessages)
	prometheus.MustRegister(histBatchSize)
	processStartTime = time.Now()
}

type Config struct {
	IPv6Enabled          bool
	RuleRendererOverride rules.RuleRenderer
	IPIPMTU              int
	IgnoreLooseRPF       bool

	MaxIPSetSize int

	IptablesRefreshInterval time.Duration
	IptablesInsertMode      string

	RulesConfig rules.Config

	StatusReportingInterval time.Duration
}

// InternalDataplane implements an in-process Felix dataplane driver based on iptables
// and ipsets.  It communicates with the datastore-facing part of Felix via the
// Send/RecvMessage methods, which operate on the protobuf-defined API objects.
//
// Architecture
//
// The internal dataplane driver is organised around a main event loop, which handles
// update events from the datastore and dataplane.
//
// Each pass around the main loop has two phases.  In the first phase, updates are fanned
// out to "manager" objects, which calculate the changes that are needed and pass them to
// the dataplane programming layer.  In the second phase, the dataplane layer applies the
// updates in a consistent sequence.  The second phase is skipped until the datastore is
// in sync; this ensures that the first update to the dataplane applies a consistent
// snapshot.
//
// Having the dataplane layer batch updates has several advantages.  It is much more
// efficient to batch updates, since each call to iptables/ipsets has a high fixed cost.
// In addition, it allows for different managers to make updates without having to
// coordinate on their sequencing.
//
// Requirements on the API
//
// The internal dataplane does not do consistency checks on the incoming data (as the
// old Python-based driver used to do).  It expects to be told about dependent resources
// before they are needed and for their lifetime to exceed that of the resources that
// depend on them.  For example, it is important the the datastore layer send an
// IP set create event before it sends a rule that references that IP set.
type InternalDataplane struct {
	toDataplane   chan interface{}
	fromDataplane chan interface{}

	allIptablesTables    []*iptables.Table
	iptablesNATTables    []*iptables.Table
	iptablesRawTables    []*iptables.Table
	iptablesFilterTables []*iptables.Table
	ipSets               []*ipsets.IPSets

	ipipManager *ipipManager

	ifaceMonitor     *ifacemonitor.InterfaceMonitor
	ifaceUpdates     chan *ifaceUpdate
	ifaceAddrUpdates chan *ifaceAddrsUpdate

	endpointStatusCombiner *endpointStatusCombiner

	allManagers []Manager

	ruleRenderer rules.RuleRenderer

	interfacePrefixes []string

	routeTables []*routetable.RouteTable

	dataplaneNeedsSync    bool
	forceDataplaneRefresh bool
	cleanupPending        bool

	reschedTimer *time.Timer
	reschedC     <-chan time.Time

	applyThrottle *throttle.Throttle

	config Config
}

func NewIntDataplaneDriver(config Config) *InternalDataplane {
	log.WithField("config", config).Info("Creating internal dataplane driver.")
	ruleRenderer := config.RuleRendererOverride
	if ruleRenderer == nil {
		ruleRenderer = rules.NewRenderer(config.RulesConfig)
	}
	dp := &InternalDataplane{
		toDataplane:       make(chan interface{}, msgPeekLimit),
		fromDataplane:     make(chan interface{}, 100),
		ruleRenderer:      ruleRenderer,
		interfacePrefixes: config.RulesConfig.WorkloadIfacePrefixes,
		cleanupPending:    true,
		ifaceMonitor:      ifacemonitor.New(),
		ifaceUpdates:      make(chan *ifaceUpdate, 100),
		ifaceAddrUpdates:  make(chan *ifaceAddrsUpdate, 100),
		config:            config,
		applyThrottle:     throttle.New(10),
	}

	dp.ifaceMonitor.Callback = dp.onIfaceStateChange
	dp.ifaceMonitor.AddrCallback = dp.onIfaceAddrsChange

	natTableV4 := iptables.NewTable(
		"nat",
		4,
		rules.RuleHashPrefix,
		iptables.TableOptions{
			HistoricChainPrefixes:    rules.AllHistoricChainNamePrefixes,
			ExtraCleanupRegexPattern: rules.HistoricInsertedNATRuleRegex,
			InsertMode:               config.IptablesInsertMode,
			RefreshInterval:          config.IptablesRefreshInterval,
		},
	)
	rawTableV4 := iptables.NewTable(
		"raw",
		4,
		rules.RuleHashPrefix,
		iptables.TableOptions{
			HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
			InsertMode:            config.IptablesInsertMode,
			RefreshInterval:       config.IptablesRefreshInterval,
		})
	filterTableV4 := iptables.NewTable(
		"filter",
		4,
		rules.RuleHashPrefix,
		iptables.TableOptions{
			HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
			InsertMode:            config.IptablesInsertMode,
			RefreshInterval:       config.IptablesRefreshInterval,
		})
	ipSetsConfigV4 := config.RulesConfig.IPSetConfigV4
	ipSetsV4 := ipsets.NewIPSets(ipSetsConfigV4)
	dp.iptablesNATTables = append(dp.iptablesNATTables, natTableV4)
	dp.iptablesRawTables = append(dp.iptablesRawTables, rawTableV4)
	dp.iptablesFilterTables = append(dp.iptablesFilterTables, filterTableV4)
	dp.ipSets = append(dp.ipSets, ipSetsV4)

	routeTableV4 := routetable.New(config.RulesConfig.WorkloadIfacePrefixes, 4)
	dp.routeTables = append(dp.routeTables, routeTableV4)

	dp.endpointStatusCombiner = newEndpointStatusCombiner(dp.fromDataplane, config.IPv6Enabled)

	dp.RegisterManager(newIPSetsManager(ipSetsV4, config.MaxIPSetSize))
	dp.RegisterManager(newPolicyManager(rawTableV4, filterTableV4, ruleRenderer, 4))
	dp.RegisterManager(newEndpointManager(
		rawTableV4,
		filterTableV4,
		ruleRenderer,
		routeTableV4,
		4,
		config.RulesConfig.WorkloadIfacePrefixes,
		dp.endpointStatusCombiner.OnEndpointStatusUpdate))
	dp.RegisterManager(newFloatingIPManager(natTableV4, ruleRenderer, 4))
	dp.RegisterManager(newMasqManager(ipSetsV4, natTableV4, ruleRenderer, config.MaxIPSetSize, 4))
	if config.RulesConfig.IPIPEnabled {
		// Add a manger to keep the all-hosts IP set up to date.
		dp.ipipManager = newIPIPManager(ipSetsV4, config.MaxIPSetSize)
		dp.RegisterManager(dp.ipipManager) // IPv4-only
	}
	if config.IPv6Enabled {
		natTableV6 := iptables.NewTable(
			"nat",
			6,
			rules.RuleHashPrefix,
			iptables.TableOptions{
				HistoricChainPrefixes:    rules.AllHistoricChainNamePrefixes,
				ExtraCleanupRegexPattern: rules.HistoricInsertedNATRuleRegex,
				InsertMode:               config.IptablesInsertMode,
				RefreshInterval:          config.IptablesRefreshInterval,
			},
		)
		rawTableV6 := iptables.NewTable(
			"raw",
			6,
			rules.RuleHashPrefix,
			iptables.TableOptions{
				HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
				InsertMode:            config.IptablesInsertMode,
				RefreshInterval:       config.IptablesRefreshInterval,
			},
		)
		filterTableV6 := iptables.NewTable(
			"filter",
			6,
			rules.RuleHashPrefix,
			iptables.TableOptions{
				HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
				InsertMode:            config.IptablesInsertMode,
				RefreshInterval:       config.IptablesRefreshInterval,
			},
		)

		ipSetsConfigV6 := config.RulesConfig.IPSetConfigV6
		ipSetsV6 := ipsets.NewIPSets(ipSetsConfigV6)
		dp.ipSets = append(dp.ipSets, ipSetsV6)
		dp.iptablesNATTables = append(dp.iptablesNATTables, natTableV6)
		dp.iptablesRawTables = append(dp.iptablesRawTables, rawTableV6)
		dp.iptablesFilterTables = append(dp.iptablesFilterTables, filterTableV6)

		routeTableV6 := routetable.New(config.RulesConfig.WorkloadIfacePrefixes, 6)
		dp.routeTables = append(dp.routeTables, routeTableV6)

		dp.RegisterManager(newIPSetsManager(ipSetsV6, config.MaxIPSetSize))
		dp.RegisterManager(newPolicyManager(rawTableV6, filterTableV6, ruleRenderer, 6))
		dp.RegisterManager(newEndpointManager(
			rawTableV6,
			filterTableV6,
			ruleRenderer,
			routeTableV6,
			6,
			config.RulesConfig.WorkloadIfacePrefixes,
			dp.endpointStatusCombiner.OnEndpointStatusUpdate))
		dp.RegisterManager(newFloatingIPManager(natTableV6, ruleRenderer, 6))
		dp.RegisterManager(newMasqManager(ipSetsV6, natTableV6, ruleRenderer, config.MaxIPSetSize, 6))
	}

	for _, t := range dp.iptablesNATTables {
		dp.allIptablesTables = append(dp.allIptablesTables, t)
	}
	for _, t := range dp.iptablesFilterTables {
		dp.allIptablesTables = append(dp.allIptablesTables, t)
	}
	for _, t := range dp.iptablesRawTables {
		dp.allIptablesTables = append(dp.allIptablesTables, t)
	}

	return dp
}

type Manager interface {
	// OnUpdate is called for each protobuf message from the datastore.  May either directly
	// send updates to the IPSets and iptables.Table objects (which will queue the updates
	// until the main loop instructs them to act) or (for efficiency) may wait until
	// a call to CompleteDeferredWork() to flush updates to the dataplane.
	OnUpdate(protoBufMsg interface{})
	// Called before the main loop flushes updates to the dataplane to allow for batched
	// work to be completed.
	CompleteDeferredWork() error
}

func (d *InternalDataplane) RegisterManager(mgr Manager) {
	d.allManagers = append(d.allManagers, mgr)
}

func (d *InternalDataplane) Start() {
	// Do our start-of-day configuration.
	d.doStaticDataplaneConfig()

	// Then, start the worker threads.
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

// onIfaceAddrsChange is our interface address monitor callback.  It gets called
// from the monitor's thread.
func (d *InternalDataplane) onIfaceAddrsChange(ifaceName string, addrs set.Set) {
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"addrs":     addrs,
	}).Info("Linux interface addrs changed.")
	d.ifaceAddrUpdates <- &ifaceAddrsUpdate{
		Name:  ifaceName,
		Addrs: addrs,
	}
}

type ifaceAddrsUpdate struct {
	Name  string
	Addrs set.Set
}

func (d *InternalDataplane) SendMessage(msg interface{}) error {
	d.toDataplane <- msg
	return nil
}

func (d *InternalDataplane) RecvMessage() (interface{}, error) {
	return <-d.fromDataplane, nil
}

// doStaticDataplaneConfig sets up the kernel and our static iptables  chains.  Should be called
// once at start of day before starting the main loop.  The actual iptables programming is deferred
// to the main loop.
func (d *InternalDataplane) doStaticDataplaneConfig() {
	// Check/configure global kernel parameters.
	d.configureKernel()

	// Endure that the default value of rp_filter is set to "strict" for newly-created
	// interfaces.  This is required to prevent a race between starting an interface and
	// Felix being able to configure it.
	writeProcSys("/proc/sys/net/ipv4/conf/default/rp_filter", "1")

	for _, t := range d.iptablesRawTables {
		rawChains := d.ruleRenderer.StaticRawTableChains(t.IPVersion)
		t.UpdateChains(rawChains)
		t.SetRuleInsertions("PREROUTING", []iptables.Rule{{
			Action: iptables.JumpAction{Target: rules.ChainRawPrerouting},
		}})
		t.SetRuleInsertions("OUTPUT", []iptables.Rule{{
			Action: iptables.JumpAction{Target: rules.ChainRawOutput},
		}})
	}

	for _, t := range d.iptablesFilterTables {
		filterChains := d.ruleRenderer.StaticFilterTableChains(t.IPVersion)
		t.UpdateChains(filterChains)
		t.SetRuleInsertions("FORWARD", []iptables.Rule{{
			Action: iptables.JumpAction{Target: rules.ChainFilterForward},
		}})
		t.SetRuleInsertions("INPUT", []iptables.Rule{{
			Action: iptables.JumpAction{Target: rules.ChainFilterInput},
		}})
		t.SetRuleInsertions("OUTPUT", []iptables.Rule{{
			Action: iptables.JumpAction{Target: rules.ChainFilterOutput},
		}})
	}

	if d.config.RulesConfig.IPIPEnabled {
		log.Info("IPIP enabled, starting thread to keep tunnel configuration in sync.")
		go d.ipipManager.KeepIPIPDeviceInSync(
			d.config.IPIPMTU,
			d.config.RulesConfig.IPIPTunnelAddress,
		)
	} else {
		log.Info("IPIP disabled. Not starting tunnel update thread.")
	}

	for _, t := range d.iptablesNATTables {
		t.UpdateChains(d.ruleRenderer.StaticNATTableChains(t.IPVersion))
		t.SetRuleInsertions("PREROUTING", []iptables.Rule{{
			Action: iptables.JumpAction{Target: rules.ChainNATPrerouting},
		}})
		t.SetRuleInsertions("POSTROUTING", []iptables.Rule{{
			Action: iptables.JumpAction{Target: rules.ChainNATPostrouting},
		}})
		t.SetRuleInsertions("OUTPUT", []iptables.Rule{{
			Action: iptables.JumpAction{Target: rules.ChainNATOutput},
		}})
	}
}

func (d *InternalDataplane) loopUpdatingDataplane() {
	log.Info("Started internal iptables dataplane driver loop")

	// Retry any failed operations every 10s.
	retryTicker := time.NewTicker(10 * time.Second)
	var refreshC <-chan time.Time
	if d.config.IptablesRefreshInterval > 0 {
		refreshTicker := jitter.NewTicker(
			d.config.IptablesRefreshInterval,
			d.config.IptablesRefreshInterval/10,
		)
		refreshC = refreshTicker.C
	}

	// Fill the apply throttle leaky bucket.
	throttleC := jitter.NewTicker(100*time.Millisecond, 10*time.Millisecond).C
	beingThrottled := false

	datastoreInSync := false
	doneFirstApply := false

	processMsgFromCalcGraph := func(msg interface{}) {
		log.WithField("msg", msg).Infof("Received %T update from calculation graph", msg)
		d.recordMsgStat(msg)
		for _, mgr := range d.allManagers {
			mgr.OnUpdate(msg)
		}
		switch msg.(type) {
		case *proto.InSync:
			log.WithField("timeSinceStart", time.Since(processStartTime)).Info(
				"Datastore in sync, flushing the dataplane for the first time...")
			datastoreInSync = true
		}
	}

	for {
		select {
		case msg := <-d.toDataplane:
			// Process the message we received, then opportunistically process any other
			// pending messages.
			batchSize := 1
			processMsgFromCalcGraph(msg)
		msgLoop:
			for i := 0; i < msgPeekLimit; i++ {
				select {
				case msg := <-d.toDataplane:
					processMsgFromCalcGraph(msg)
					batchSize++
				default:
					// Channel blocked so we must be caught up.
					break msgLoop
				}
			}
			d.dataplaneNeedsSync = true
			histBatchSize.Observe(float64(batchSize))
		case ifaceUpdate := <-d.ifaceUpdates:
			log.WithField("msg", ifaceUpdate).Info("Received interface update")
			for _, mgr := range d.allManagers {
				mgr.OnUpdate(ifaceUpdate)
			}
			for _, routeTable := range d.routeTables {
				routeTable.OnIfaceStateChanged(ifaceUpdate.Name, ifaceUpdate.State)
			}
			d.dataplaneNeedsSync = true
		case ifaceAddrsUpdate := <-d.ifaceAddrUpdates:
			log.WithField("msg", ifaceAddrsUpdate).Info("Received interface addresses update")
			for _, mgr := range d.allManagers {
				mgr.OnUpdate(ifaceAddrsUpdate)
			}
			d.dataplaneNeedsSync = true
		case <-refreshC:
			log.Debug("Refreshing dataplane state")
			d.forceDataplaneRefresh = true
			d.dataplaneNeedsSync = true
		case <-d.reschedC:
			log.Debug("Reschedule kick received")
			d.dataplaneNeedsSync = true
			// nil out the channel to record that the timer is now inactive.
			d.reschedC = nil
		case <-throttleC:
			log.Debug("Throttle kick received")
			d.applyThrottle.Refill()
		case <-retryTicker.C:
		}

		if datastoreInSync && d.dataplaneNeedsSync {
			// Dataplane is out-of-sync, check if we're throttled.
			if d.applyThrottle.Admit() {
				if beingThrottled && d.applyThrottle.WouldAdmit() {
					log.Info("Dataplane updates no longer throttled")
					beingThrottled = false
				}
				log.Info("Applying dataplane updates")
				applyStart := time.Now()

				// Actually apply the changes to the dataplane.
				d.apply()

				// Record stats.
				applyTime := time.Since(applyStart)
				if applyTime > 0 {
					// Avoid a negative interval in case the clock jumps.
					histApplyTime.Observe(applyTime.Seconds())
				}

				if d.dataplaneNeedsSync {
					// Dataplane is still dirty, record an error.
					countDataplaneSyncErrors.Inc()
				}
				log.WithField("msecToApply", applyTime.Seconds()*1000.0).Info(
					"Finished applying updates to dataplane.")
			} else {
				if !beingThrottled {
					log.Info("Dataplane updates throttled")
					beingThrottled = true
				}
			}
			if !doneFirstApply {
				log.WithField("secsSinceStart", time.Since(processStartTime).Seconds()).Info(
					"Completed first update to dataplane.")
				doneFirstApply = true
			}
		}
	}
}

func (d *InternalDataplane) configureKernel() {
	// For IPv4, we rely on the kernel's reverse path filtering to prevent workloads from
	// spoofing their IP addresses.
	//
	// The RPF check for a particular interface is controlled by several sysctls:
	//
	//     - ipv4.conf.all.rp_filter is a global override
	//     - ipv4.conf.default.rp_filter controls the value that is set on a newly created
	//       interface
	//     - ipv4.conf.<interface>.rp_filter controls a particular interface.
	//
	// The algorithm for combining the global override and per-interface values is to take the
	// *numeric* maximum between the two.  The values are: 0=off, 1=strict, 2=loose.  "loose"
	// is not suitable for Calico since it would allow workloads to spoof packets from other
	// workloads on the same host.  Hence, we need the global override to be <=1 or it would
	// override the per-interface setting to "strict" that we require.
	//
	// Unless the IgnoreLooseRPF flag is set, we bail out rather than simply setting it
	// because setting 2, "loose", is unusual and it is likely to have been set deliberately.
	rpFilter, err := readRPFilter()
	if err != nil {
		logCxt := log.WithError(err)
		if d.config.IgnoreLooseRPF {
			logCxt.Error("Failed to read kernel's rp_filter value from /proc/sys. " +
				"Ignoring due to IgnoreLooseRPF setting.")
		} else {
			logCxt.Fatal("Failed to read kernel's rp_filter value from /proc/sys")
		}
	} else if rpFilter > 1 {
		if d.config.IgnoreLooseRPF {
			log.Warn("Kernel's RPF check is set to 'loose' and IgnoreLooseRPF " +
				"set to true.  Calico will not be able to prevent workloads " +
				"from spoofing their source IP.  Please ensure that some " +
				"other anti-spoofing mechanism is in place (such as running " +
				"only non-privileged containers).")
		} else {
			log.Fatal("Kernel's RPF check is set to 'loose'.  This would " +
				"allow endpoints to spoof their IP address.  Calico " +
				"requires net.ipv4.conf.all.rp_filter to be set to " +
				"0 or 1. If you require loose RPF and you are not concerned " +
				"about spoofing, this check can be disabled by setting the " +
				"IgnoreLooseRPF configuration parameter to 'true'.")
		}
	}

	// Make sure the default for new interfaces is set to strict checking so that there's no
	// race when a new interface is added and felix hasn't configured it yet.
	writeProcSys("/proc/sys/net/ipv4/conf/default/rp_filter", "1")
}

func readRPFilter() (value int64, err error) {
	f, err := os.Open("/proc/sys/net/ipv4/conf/all/rp_filter")
	if err != nil {
		return
	}
	rpFilterBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}
	value, err = strconv.ParseInt(strings.Trim(string(rpFilterBytes), "\n"), 10, 64)
	return
}

func (d *InternalDataplane) recordMsgStat(msg interface{}) {
	typeName := reflect.ValueOf(msg).Elem().Type().Name()
	countMessages.WithLabelValues(typeName).Inc()
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

	if d.forceDataplaneRefresh {
		// Refresh timer popped, ask the dataplane to resync as part of its update.
		for _, r := range d.routeTables {
			// Queue a resync on the next Apply().
			r.QueueResync()
		}
		for _, r := range d.ipSets {
			// Queue a resync on the next Apply().
			r.QueueResync()
		}
		d.forceDataplaneRefresh = false
	}

	// Next, create/update IP sets.  We defer deletions of IP sets until after we update
	// iptables.
	for _, w := range d.ipSets {
		w.ApplyUpdates()
	}

	// Update iptables, this should sever any references to now-unused IP sets.
	var reschedDelay time.Duration
	for _, t := range d.allIptablesTables {
		tableReschedAfter := t.Apply()
		if tableReschedAfter != 0 && (reschedDelay == 0 || tableReschedAfter < reschedDelay) {
			reschedDelay = tableReschedAfter
		}
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
	for _, w := range d.ipSets {
		w.ApplyDeletions()
	}

	// And publish and status updates.
	d.endpointStatusCombiner.Apply()

	// Set up any needed rescheduling kick.
	if d.reschedC != nil {
		// We have an active rescheduling timer, stop it so we can restart it with a
		// different timeout below if it is still needed.
		// This snippet comes from the docs for Timer.Stop().
		if !d.reschedTimer.Stop() {
			// Timer had already popped, drain its channel.
			<-d.reschedC
		}
		// Nil out our copy of the channel to record that the timer is inactive.
		d.reschedC = nil
	}
	if reschedDelay != 0 {
		// We need to reschedule.
		log.WithField("delay", reschedDelay).Debug("Asked to reschedule.")
		if d.reschedTimer == nil {
			// First time, create the timer.
			d.reschedTimer = time.NewTimer(reschedDelay)
		} else {
			// Have an existing timer, reset it.
			d.reschedTimer.Reset(reschedDelay)
		}
		d.reschedC = d.reschedTimer.C
	}
}

func (d *InternalDataplane) loopReportingStatus() {
	log.Info("Started internal status report thread")
	if d.config.StatusReportingInterval <= 0 {
		log.Info("Process status reports disabled")
		return
	}
	start := time.Now()
	// Wait before first report so that we don't check in if we're in a tight cyclic restart.
	time.Sleep(10 * time.Second)
	for {
		now := time.Now()
		uptimeNanos := float64(now.Sub(start))
		uptimeSecs := uptimeNanos / 1000000000
		d.fromDataplane <- &proto.ProcessStatusUpdate{
			IsoTimestamp: now.UTC().Format(time.RFC3339),
			Uptime:       uptimeSecs,
		}
		time.Sleep(d.config.StatusReportingInterval)
	}
}

// iptablesTable is a shim interface for iptables.Table.
type iptablesTable interface {
	UpdateChain(chain *iptables.Chain)
	UpdateChains([]*iptables.Chain)
	RemoveChains([]*iptables.Chain)
	RemoveChainByName(name string)
}
