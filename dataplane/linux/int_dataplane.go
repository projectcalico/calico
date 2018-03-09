// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/jitter"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/routetable"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/felix/throttle"
	"github.com/projectcalico/libcalico-go/lib/health"
	"github.com/projectcalico/libcalico-go/lib/set"
)

const (
	// msgPeekLimit is the maximum number of messages we'll try to grab from the to-dataplane
	// channel before we apply the changes.  Higher values allow us to batch up more work on
	// the channel for greater throughput when we're under load (at cost of higher latency).
	msgPeekLimit = 100

	// Interface name used by kube-proxy to bind service ips.
	KubeIPVSInterface = "kube-ipvs0"
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
	summaryApplyTime = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_apply_time_seconds",
		Help: "Time in seconds that it took to apply a dataplane update.",
	})
	summaryBatchSize = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_msg_batch_size",
		Help: "Number of messages processed in each batch. Higher values indicate we're " +
			"doing more batching to try to keep up.",
	})
	summaryIfaceBatchSize = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_iface_msg_batch_size",
		Help: "Number of interface state messages processed in each batch. Higher " +
			"values indicate we're doing more batching to try to keep up.",
	})
	summaryAddrBatchSize = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_addr_msg_batch_size",
		Help: "Number of interface address messages processed in each batch. Higher " +
			"values indicate we're doing more batching to try to keep up.",
	})

	processStartTime time.Time
)

func init() {
	prometheus.MustRegister(countDataplaneSyncErrors)
	prometheus.MustRegister(summaryApplyTime)
	prometheus.MustRegister(countMessages)
	prometheus.MustRegister(summaryBatchSize)
	prometheus.MustRegister(summaryIfaceBatchSize)
	prometheus.MustRegister(summaryAddrBatchSize)
	processStartTime = time.Now()
}

type Config struct {
	IPv6Enabled          bool
	RuleRendererOverride rules.RuleRenderer
	IPIPMTU              int
	IgnoreLooseRPF       bool

	MaxIPSetSize int

	IPSetsRefreshInterval          time.Duration
	RouteRefreshInterval           time.Duration
	IptablesRefreshInterval        time.Duration
	IptablesPostWriteCheckInterval time.Duration
	IptablesInsertMode             string
	IptablesLockFilePath           string
	IptablesLockTimeout            time.Duration
	IptablesLockProbeInterval      time.Duration

	NetlinkTimeout time.Duration

	RulesConfig rules.Config

	IfaceMonitorConfig ifacemonitor.Config

	StatusReportingInterval time.Duration

	ConfigChangedRestartCallback func()

	PostInSyncCallback func()
	HealthAggregator   *health.HealthAggregator

	DebugSimulateDataplaneHangAfter time.Duration
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
	iptablesMangleTables []*iptables.Table
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

	// dataplaneNeedsSync is set if the dataplane is dirty in some way, i.e. we need to
	// call apply().
	dataplaneNeedsSync bool
	// forceIPSetsRefresh is set by the IP sets refresh timer to indicate that we should
	// check the IP sets in the dataplane.
	forceIPSetsRefresh bool
	// forceRouteRefresh is set by the route refresh timer to indicate that we should
	// check the routes in the dataplane.
	forceRouteRefresh bool
	// doneFirstApply is set after we finish the first update to the dataplane. It indicates
	// that the dataplane should now be in sync.
	doneFirstApply bool

	reschedTimer *time.Timer
	reschedC     <-chan time.Time

	applyThrottle *throttle.Throttle

	config Config

	debugHangC <-chan time.Time
}

const (
	healthName     = "int_dataplane"
	healthInterval = 10 * time.Second
)

func NewIntDataplaneDriver(config Config) *InternalDataplane {
	log.WithField("config", config).Info("Creating internal dataplane driver.")
	ruleRenderer := config.RuleRendererOverride
	if ruleRenderer == nil {
		ruleRenderer = rules.NewRenderer(config.RulesConfig)
	}
	epMarkMapper := rules.NewEndpointMarkMapper(
		config.RulesConfig.IptablesMarkEndpoint,
		config.RulesConfig.IptablesMarkNonCaliEndpoint)

	dp := &InternalDataplane{
		toDataplane:       make(chan interface{}, msgPeekLimit),
		fromDataplane:     make(chan interface{}, 100),
		ruleRenderer:      ruleRenderer,
		interfacePrefixes: config.RulesConfig.WorkloadIfacePrefixes,
		ifaceMonitor:      ifacemonitor.New(config.IfaceMonitorConfig),
		ifaceUpdates:      make(chan *ifaceUpdate, 100),
		ifaceAddrUpdates:  make(chan *ifaceAddrsUpdate, 100),
		config:            config,
		applyThrottle:     throttle.New(10),
	}
	dp.applyThrottle.Refill() // Allow the first apply() immediately.

	dp.ifaceMonitor.Callback = dp.onIfaceStateChange
	dp.ifaceMonitor.AddrCallback = dp.onIfaceAddrsChange

	// Most iptables tables need the same options.
	iptablesOptions := iptables.TableOptions{
		HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
		InsertMode:            config.IptablesInsertMode,
		RefreshInterval:       config.IptablesRefreshInterval,
		PostWriteInterval:     config.IptablesPostWriteCheckInterval,
	}

	// However, the NAT tables need an extra cleanup regex.
	iptablesNATOptions := iptablesOptions
	iptablesNATOptions.ExtraCleanupRegexPattern = rules.HistoricInsertedNATRuleRegex

	var iptablesLock sync.Locker
	if config.IptablesLockTimeout <= 0 {
		log.Info("iptables lock disabled.")
		iptablesLock = dummyLock{}
	} else {
		// Create the shared iptables lock.  This allows us to block other processes from
		// manipulating iptables while we make our updates.  We use a shared lock because we
		// actually do multiple updates in parallel (but to different tables), which is safe.
		log.WithField("timeout", config.IptablesLockTimeout).Info(
			"iptables lock enabled")
		iptablesLock = iptables.NewSharedLock(
			config.IptablesLockFilePath,
			config.IptablesLockTimeout,
			config.IptablesLockProbeInterval,
		)
	}

	mangleTableV4 := iptables.NewTable(
		"mangle",
		4,
		rules.RuleHashPrefix,
		iptablesLock,
		iptablesOptions)
	natTableV4 := iptables.NewTable(
		"nat",
		4,
		rules.RuleHashPrefix,
		iptablesLock,
		iptablesNATOptions,
	)
	rawTableV4 := iptables.NewTable(
		"raw",
		4,
		rules.RuleHashPrefix,
		iptablesLock,
		iptablesOptions)
	filterTableV4 := iptables.NewTable(
		"filter",
		4,
		rules.RuleHashPrefix,
		iptablesLock,
		iptablesOptions)
	ipSetsConfigV4 := config.RulesConfig.IPSetConfigV4
	ipSetsV4 := ipsets.NewIPSets(ipSetsConfigV4)
	dp.iptablesNATTables = append(dp.iptablesNATTables, natTableV4)
	dp.iptablesRawTables = append(dp.iptablesRawTables, rawTableV4)
	dp.iptablesMangleTables = append(dp.iptablesMangleTables, mangleTableV4)
	dp.iptablesFilterTables = append(dp.iptablesFilterTables, filterTableV4)
	dp.ipSets = append(dp.ipSets, ipSetsV4)

	routeTableV4 := routetable.New(config.RulesConfig.WorkloadIfacePrefixes, 4, config.NetlinkTimeout)
	dp.routeTables = append(dp.routeTables, routeTableV4)

	dp.endpointStatusCombiner = newEndpointStatusCombiner(dp.fromDataplane, config.IPv6Enabled)

	dp.RegisterManager(newIPSetsManager(ipSetsV4, config.MaxIPSetSize))
	dp.RegisterManager(newHostIPManager(
		config.RulesConfig.WorkloadIfacePrefixes,
		rules.IPSetIDThisHostIPs,
		ipSetsV4,
		config.MaxIPSetSize))
	dp.RegisterManager(newPolicyManager(rawTableV4, mangleTableV4, filterTableV4, ruleRenderer, 4))
	dp.RegisterManager(newEndpointManager(
		rawTableV4,
		mangleTableV4,
		filterTableV4,
		ruleRenderer,
		routeTableV4,
		4,
		epMarkMapper,
		config.RulesConfig.KubeIPVSSupportEnabled,
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
		mangleTableV6 := iptables.NewTable(
			"mangle",
			6,
			rules.RuleHashPrefix,
			iptablesLock,
			iptablesOptions,
		)
		natTableV6 := iptables.NewTable(
			"nat",
			6,
			rules.RuleHashPrefix,
			iptablesLock,
			iptablesNATOptions,
		)
		rawTableV6 := iptables.NewTable(
			"raw",
			6,
			rules.RuleHashPrefix,
			iptablesLock,
			iptablesOptions,
		)
		filterTableV6 := iptables.NewTable(
			"filter",
			6,
			rules.RuleHashPrefix,
			iptablesLock,
			iptablesOptions,
		)

		ipSetsConfigV6 := config.RulesConfig.IPSetConfigV6
		ipSetsV6 := ipsets.NewIPSets(ipSetsConfigV6)
		dp.ipSets = append(dp.ipSets, ipSetsV6)
		dp.iptablesNATTables = append(dp.iptablesNATTables, natTableV6)
		dp.iptablesRawTables = append(dp.iptablesRawTables, rawTableV6)
		dp.iptablesMangleTables = append(dp.iptablesMangleTables, mangleTableV6)
		dp.iptablesFilterTables = append(dp.iptablesFilterTables, filterTableV6)

		routeTableV6 := routetable.New(config.RulesConfig.WorkloadIfacePrefixes, 6, config.NetlinkTimeout)
		dp.routeTables = append(dp.routeTables, routeTableV6)

		dp.RegisterManager(newIPSetsManager(ipSetsV6, config.MaxIPSetSize))
		dp.RegisterManager(newHostIPManager(
			config.RulesConfig.WorkloadIfacePrefixes,
			rules.IPSetIDThisHostIPs,
			ipSetsV6,
			config.MaxIPSetSize))
		dp.RegisterManager(newPolicyManager(rawTableV6, mangleTableV6, filterTableV6, ruleRenderer, 6))
		dp.RegisterManager(newEndpointManager(
			rawTableV6,
			mangleTableV6,
			filterTableV6,
			ruleRenderer,
			routeTableV6,
			6,
			epMarkMapper,
			config.RulesConfig.KubeIPVSSupportEnabled,
			config.RulesConfig.WorkloadIfacePrefixes,
			dp.endpointStatusCombiner.OnEndpointStatusUpdate))
		dp.RegisterManager(newFloatingIPManager(natTableV6, ruleRenderer, 6))
		dp.RegisterManager(newMasqManager(ipSetsV6, natTableV6, ruleRenderer, config.MaxIPSetSize, 6))
	}

	for _, t := range dp.iptablesMangleTables {
		dp.allIptablesTables = append(dp.allIptablesTables, t)
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

	// Register that we will report liveness and readiness.
	if config.HealthAggregator != nil {
		log.Info("Registering to report health.")
		config.HealthAggregator.RegisterReporter(
			healthName,
			&health.HealthReport{Live: true, Ready: true},
			healthInterval*2,
		)
	}

	if config.DebugSimulateDataplaneHangAfter != 0 {
		log.WithField("delay", config.DebugSimulateDataplaneHangAfter).Warn(
			"Simulating a dataplane hang.")
		dp.debugHangC = time.After(config.DebugSimulateDataplaneHangAfter)
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

// Check if current felix ipvs config is correct when felix gets an kube-ipvs0 interface update.
// If KubeIPVSInterface is UP and felix ipvs support is disabled (kube-proxy switched from iptables to ipvs mode),
// or if KubeIPVSInterface is DOWN and felix ipvs support is enabled (kube-proxy switched from ipvs to iptables mode),
// restart felix to pick up correct ipvs support mode.
func (d *InternalDataplane) checkIPVSConfigOnStateUpdate(state ifacemonitor.State) {
	if (!d.config.RulesConfig.KubeIPVSSupportEnabled && state == ifacemonitor.StateUp) ||
		(d.config.RulesConfig.KubeIPVSSupportEnabled && state == ifacemonitor.StateDown) {
		log.WithFields(log.Fields{
			"ipvsIfaceState": state,
			"ipvsSupport":    d.config.RulesConfig.KubeIPVSSupportEnabled,
		}).Info("kube-proxy mode changed. Restart felix.")
		d.config.ConfigChangedRestartCallback()
	}
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

	for _, t := range d.iptablesMangleTables {
		t.UpdateChains(d.ruleRenderer.StaticMangleTableChains(t.IPVersion))
		t.SetRuleInsertions("PREROUTING", []iptables.Rule{{
			Action: iptables.JumpAction{Target: rules.ChainManglePrerouting},
		}})
	}
}

func (d *InternalDataplane) loopUpdatingDataplane() {
	log.Info("Started internal iptables dataplane driver loop")
	healthTicks := time.NewTicker(healthInterval).C
	d.reportHealth()

	// Retry any failed operations every 10s.
	retryTicker := time.NewTicker(10 * time.Second)

	// If configured, start tickers to refresh the IP sets and routing table entries.
	var ipSetsRefreshC <-chan time.Time
	if d.config.IPSetsRefreshInterval > 0 {
		log.WithField("interval", d.config.IptablesRefreshInterval).Info(
			"Will refresh IP sets on timer")
		refreshTicker := jitter.NewTicker(
			d.config.IPSetsRefreshInterval,
			d.config.IPSetsRefreshInterval/10,
		)
		ipSetsRefreshC = refreshTicker.C
	}
	var routeRefreshC <-chan time.Time
	if d.config.RouteRefreshInterval > 0 {
		log.WithField("interval", d.config.RouteRefreshInterval).Info(
			"Will refresh routes on timer")
		refreshTicker := jitter.NewTicker(
			d.config.RouteRefreshInterval,
			d.config.RouteRefreshInterval/10,
		)
		routeRefreshC = refreshTicker.C
	}

	// Fill the apply throttle leaky bucket.
	throttleC := jitter.NewTicker(100*time.Millisecond, 10*time.Millisecond).C
	beingThrottled := false

	datastoreInSync := false

	processMsgFromCalcGraph := func(msg interface{}) {
		log.WithField("msg", proto.MsgStringer{Msg: msg}).Infof(
			"Received %T update from calculation graph", msg)
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

	processIfaceUpdate := func(ifaceUpdate *ifaceUpdate) {
		log.WithField("msg", ifaceUpdate).Info("Received interface update")
		if ifaceUpdate.Name == KubeIPVSInterface {
			d.checkIPVSConfigOnStateUpdate(ifaceUpdate.State)
			return
		}

		for _, mgr := range d.allManagers {
			mgr.OnUpdate(ifaceUpdate)
		}
		for _, routeTable := range d.routeTables {
			routeTable.OnIfaceStateChanged(ifaceUpdate.Name, ifaceUpdate.State)
		}
	}

	processAddrsUpdate := func(ifaceAddrsUpdate *ifaceAddrsUpdate) {
		log.WithField("msg", ifaceAddrsUpdate).Info("Received interface addresses update")
		for _, mgr := range d.allManagers {
			mgr.OnUpdate(ifaceAddrsUpdate)
		}
	}

	for {
		select {
		case msg := <-d.toDataplane:
			// Process the message we received, then opportunistically process any other
			// pending messages.
			batchSize := 1
			processMsgFromCalcGraph(msg)
		msgLoop1:
			for i := 0; i < msgPeekLimit; i++ {
				select {
				case msg := <-d.toDataplane:
					processMsgFromCalcGraph(msg)
					batchSize++
				default:
					// Channel blocked so we must be caught up.
					break msgLoop1
				}
			}
			d.dataplaneNeedsSync = true
			summaryBatchSize.Observe(float64(batchSize))
		case ifaceUpdate := <-d.ifaceUpdates:
			// Process the message we received, then opportunistically process any other
			// pending messages.
			batchSize := 1
			processIfaceUpdate(ifaceUpdate)
		msgLoop2:
			for i := 0; i < msgPeekLimit; i++ {
				select {
				case ifaceUpdate := <-d.ifaceUpdates:
					processIfaceUpdate(ifaceUpdate)
					batchSize++
				default:
					// Channel blocked so we must be caught up.
					break msgLoop2
				}
			}
			d.dataplaneNeedsSync = true
			summaryIfaceBatchSize.Observe(float64(batchSize))
		case ifaceAddrsUpdate := <-d.ifaceAddrUpdates:
			batchSize := 1
			processAddrsUpdate(ifaceAddrsUpdate)
		msgLoop3:
			for i := 0; i < msgPeekLimit; i++ {
				select {
				case ifaceAddrsUpdate := <-d.ifaceAddrUpdates:
					processAddrsUpdate(ifaceAddrsUpdate)
					batchSize++
				default:
					// Channel blocked so we must be caught up.
					break msgLoop3
				}
			}
			summaryAddrBatchSize.Observe(float64(batchSize))
			d.dataplaneNeedsSync = true
		case <-ipSetsRefreshC:
			log.Debug("Refreshing IP sets state")
			d.forceIPSetsRefresh = true
			d.dataplaneNeedsSync = true
		case <-routeRefreshC:
			log.Debug("Refreshing routes")
			d.forceRouteRefresh = true
			d.dataplaneNeedsSync = true
		case <-d.reschedC:
			log.Debug("Reschedule kick received")
			d.dataplaneNeedsSync = true
			// nil out the channel to record that the timer is now inactive.
			d.reschedC = nil
		case <-throttleC:
			log.Debug("Throttle kick received")
			d.applyThrottle.Refill()
		case <-healthTicks:
			d.reportHealth()
		case <-retryTicker.C:
		case <-d.debugHangC:
			log.Warning("Debug hang simulation timer popped, hanging the dataplane!!")
			time.Sleep(1 * time.Hour)
			log.Panic("Woke up after 1 hour, something's probably wrong with the test.")
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
				summaryApplyTime.Observe(applyTime.Seconds())

				if d.dataplaneNeedsSync {
					// Dataplane is still dirty, record an error.
					countDataplaneSyncErrors.Inc()
				}
				log.WithField("msecToApply", applyTime.Seconds()*1000.0).Info(
					"Finished applying updates to dataplane.")

				if !d.doneFirstApply {
					log.WithField(
						"secsSinceStart", time.Since(processStartTime).Seconds(),
					).Info("Completed first update to dataplane.")
					d.doneFirstApply = true
					if d.config.PostInSyncCallback != nil {
						d.config.PostInSyncCallback()
					}
				}
				d.reportHealth()
			} else {
				if !beingThrottled {
					log.Info("Dataplane updates throttled")
					beingThrottled = true
				}
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

	if d.forceRouteRefresh {
		// Refresh timer popped.
		for _, r := range d.routeTables {
			// Queue a resync on the next Apply().
			r.QueueResync()
		}
		d.forceRouteRefresh = false
	}

	if d.forceIPSetsRefresh {
		// Refresh timer popped.
		for _, r := range d.ipSets {
			// Queue a resync on the next Apply().
			r.QueueResync()
		}
		d.forceIPSetsRefresh = false
	}

	// Next, create/update IP sets.  We defer deletions of IP sets until after we update
	// iptables.
	var ipSetsWG sync.WaitGroup
	for _, ipSets := range d.ipSets {
		ipSetsWG.Add(1)
		go func(ipSets *ipsets.IPSets) {
			ipSets.ApplyUpdates()
			ipSetsWG.Done()
		}(ipSets)
	}

	// Update the routing table in parallel with the other updates.  We'll wait for it to finish
	// before we return.
	var routesWG sync.WaitGroup
	for _, r := range d.routeTables {
		routesWG.Add(1)
		go func(r *routetable.RouteTable) {
			err := r.Apply()
			if err != nil {
				log.Warn("Failed to synchronize routing table, will retry...")
				d.dataplaneNeedsSync = true
			}
			routesWG.Done()
		}(r)
	}

	// Wait for the IP sets update to finish.  We can't update iptables until it has.
	ipSetsWG.Wait()

	// Update iptables, this should sever any references to now-unused IP sets.
	var reschedDelayMutex sync.Mutex
	var reschedDelay time.Duration
	var iptablesWG sync.WaitGroup
	for _, t := range d.allIptablesTables {
		iptablesWG.Add(1)
		go func(t *iptables.Table) {
			tableReschedAfter := t.Apply()

			reschedDelayMutex.Lock()
			defer reschedDelayMutex.Unlock()
			if tableReschedAfter != 0 && (reschedDelay == 0 || tableReschedAfter < reschedDelay) {
				reschedDelay = tableReschedAfter
			}
			iptablesWG.Done()
		}(t)
	}
	iptablesWG.Wait()

	// Now clean up any left-over IP sets.
	for _, ipSets := range d.ipSets {
		ipSetsWG.Add(1)
		go func(s *ipsets.IPSets) {
			s.ApplyDeletions()
			ipSetsWG.Done()
		}(ipSets)
	}
	ipSetsWG.Wait()

	// Wait for the route updates to finish.
	routesWG.Wait()

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
	// Wait before first report so that we don't check in if we're in a tight cyclic restart.
	time.Sleep(10 * time.Second)
	for {
		uptimeSecs := time.Since(processStartTime).Seconds()
		d.fromDataplane <- &proto.ProcessStatusUpdate{
			IsoTimestamp: time.Now().UTC().Format(time.RFC3339),
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

func (d *InternalDataplane) reportHealth() {
	if d.config.HealthAggregator != nil {
		d.config.HealthAggregator.Report(
			healthName,
			&health.HealthReport{Live: true, Ready: d.doneFirstApply},
		)
	}
}

type dummyLock struct{}

func (d dummyLock) Lock() {

}

func (d dummyLock) Unlock() {

}
