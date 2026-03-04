// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	bpfconntrack "github.com/projectcalico/calico/felix/bpf/conntrack"
	bpftimeouts "github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/events"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	bpfifstate "github.com/projectcalico/calico/felix/bpf/ifstate"
	bpfipsets "github.com/projectcalico/calico/felix/bpf/ipsets"
	bpfmaps "github.com/projectcalico/calico/felix/bpf/maps"
	bpfnat "github.com/projectcalico/calico/felix/bpf/nat"
	bpfproxy "github.com/projectcalico/calico/felix/bpf/proxy"
	bpfroutes "github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/bpf/tc"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	bpfutils "github.com/projectcalico/calico/felix/bpf/utils"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector"
	collectortypes "github.com/projectcalico/calico/felix/collector/types"
	felixconfig "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dataplane/common"
	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/iptables/cmdshim"
	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/linkaddrs"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routerule"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/routetable/ownershippol"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/throttle"
	"github.com/projectcalico/calico/felix/vxlanfdb"
	"github.com/projectcalico/calico/felix/wireguard"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	lclogutils "github.com/projectcalico/calico/libcalico-go/lib/logutils"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// msgPeekLimit is the maximum number of messages we'll try to grab from our channels
	// before we apply the changes.  Higher values allow us to batch up more work on
	// the channel for greater throughput when we're under load (at cost of higher latency).
	msgPeekLimit = 100

	// Interface name used by kube-proxy to bind service ips.
	KubeIPVSInterface = "kube-ipvs0"

	// Route cleanup grace period. Used for workload routes only.
	routeCleanupGracePeriod = 10 * time.Second
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
	gaugeInitialResyncApplyTime = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_int_dataplane_initial_resync_time_seconds",
		Help: "Time in seconds that it took to do the initial resync with " +
			"the dataplane and bring the dataplane into sync for the first time.",
	})
	summaryApplyTime = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_apply_time_seconds",
		Help: "Time in seconds for each incremental update to the dataplane " +
			"(after the initial resync).",
	})
	summaryBatchSize = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_msg_batch_size",
		Help: "Number of messages processed in each batch. Higher values indicate we're " +
			"doing more batching to try to keep up.",
	})
	summaryIfaceBatchSize = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_iface_msg_batch_size",
		Help: "Number of interface state messages processed in each batch. Higher " +
			"values indicate we're doing more batching to try to keep up.",
	})
	summaryAddrBatchSize = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_int_dataplane_addr_msg_batch_size",
		Help: "Number of interface address messages processed in each batch. Higher " +
			"values indicate we're doing more batching to try to keep up.",
	})

	processStartTime time.Time
	zeroKey          = wgtypes.Key{}

	maxCleanupRetries = 5
)

func init() {
	prometheus.MustRegister(countDataplaneSyncErrors)
	prometheus.MustRegister(gaugeInitialResyncApplyTime)
	prometheus.MustRegister(summaryApplyTime)
	prometheus.MustRegister(countMessages)
	prometheus.MustRegister(summaryBatchSize)
	prometheus.MustRegister(summaryIfaceBatchSize)
	prometheus.MustRegister(summaryAddrBatchSize)
	processStartTime = time.Now()
}

type Config struct {
	Hostname             string
	NodeZone             string
	IPv6Enabled          bool
	RuleRendererOverride rules.RuleRenderer
	IPIPMTU              int
	VXLANMTU             int
	VXLANMTUV6           int
	VXLANPort            int

	MaxIPSetSize int

	RouteSyncDisabled              bool
	IptablesBackend                string
	IPSetsRefreshInterval          time.Duration
	RouteRefreshInterval           time.Duration
	DeviceRouteSourceAddress       net.IP
	DeviceRouteSourceAddressIPv6   net.IP
	DeviceRouteProtocol            netlink.RouteProtocol
	RemoveExternalRoutes           bool
	ProgramClusterRoutes           bool
	IPForwarding                   string
	TableRefreshInterval           time.Duration
	IptablesPostWriteCheckInterval time.Duration
	IptablesInsertMode             string
	IptablesLockTimeout            time.Duration
	IptablesLockProbeInterval      time.Duration
	XDPRefreshInterval             time.Duration

	FloatingIPsEnabled bool

	Wireguard wireguard.Config

	NetlinkTimeout time.Duration

	RulesConfig rules.Config

	IfaceMonitorConfig ifacemonitor.Config

	StatusReportingInterval time.Duration

	ConfigChangedRestartCallback func()
	FatalErrorRestartCallback    func(error)

	PostInSyncCallback  func()
	HealthAggregator    *health.HealthAggregator
	WatchdogTimeout     time.Duration
	RouteTableManager   *idalloc.IndexAllocator
	bpfProxyHealthCheck bpfproxy.Healthcheck

	DebugSimulateDataplaneHangAfter  time.Duration
	DebugSimulateDataplaneApplyDelay time.Duration

	ExternalNodesCidrs []string

	BPFEnabled                         bool
	BPFPolicyDebugEnabled              bool
	BPFDisableUnprivileged             bool
	BPFJITHardening                    string
	BPFKubeProxyIptablesCleanupEnabled bool
	BPFLogLevel                        string
	BPFConntrackLogLevel               string
	BPFLogFilters                      map[string]string
	BPFCTLBLogFilter                   string
	BPFExtToServiceConnmark            int
	BPFDataIfacePattern                *regexp.Regexp
	BPFL3IfacePattern                  *regexp.Regexp
	XDPEnabled                         bool
	XDPAllowGeneric                    bool
	BPFConntrackCleanupMode            apiv3.BPFConntrackMode
	BPFConntrackTimeouts               bpftimeouts.Timeouts
	BPFCgroupV2                        string
	BPFConnTimeLBEnabled               bool
	BPFConnTimeLB                      string
	BPFHostNetworkedNAT                string
	BPFNodePortDSREnabled              bool
	BPFDSROptoutCIDRs                  []string
	BPFPSNATPorts                      numorstring.Port
	BPFMapSizeRoute                    int
	BPFMapSizeConntrack                int
	BPFMapSizePerCPUConntrack          int
	BPFMapSizeConntrackScaling         string
	BPFMapSizeConntrackCleanupQueue    int
	BPFMapSizeNATFrontend              int
	BPFMapSizeNATBackend               int
	BPFMapSizeNATAffinity              int
	BPFMapSizeIPSets                   int
	BPFMapSizeIfState                  int
	BPFMapSizeMaglev                   int
	BPFMaglevLUTSize                   int
	BPFIpv6Enabled                     bool
	BPFHostConntrackBypass             bool
	BPFEnforceRPF                      string
	BPFDisableGROForIfaces             *regexp.Regexp
	BPFExcludeCIDRsFromNAT             []string
	BPFExportBufferSizeMB              int
	BPFRedirectToPeer                  string
	BPFAttachType                      apiv3.BPFAttachOption

	BPFProfiling               string
	KubeProxyMinSyncPeriod     time.Duration
	KubeProxyHealtzPort        int
	SidecarAccelerationEnabled bool

	// Flow logs related fields.
	NfNetlinkBufSize int
	Collector        collector.Collector
	LookupsCache     *calc.LookupsCache
	FlowLogsEnabled  bool

	ServiceLoopPrevention string

	LookPathOverride func(file string) (string, error)

	KubeClientSet *kubernetes.Clientset

	FeatureDetectOverrides map[string]string
	FeatureGates           map[string]string

	// Populated with the smallest host MTU based on auto-detection.
	hostMTU         int
	MTUIfacePattern *regexp.Regexp
	RequireMTUFile  bool

	RouteSource string

	KubernetesProvider felixconfig.Provider

	// For testing purposes - allows unit tests to mock out the creation of the nftables dataplane.
	NewNftablesDataplane nftables.NewNftablesDataplaneFn
}

type UpdateBatchResolver interface {
	// Opportunity for a manager component to resolve state that depends jointly on the updates
	// that it has seen since the preceding CompleteDeferredWork call.  Processing here can
	// include passing resolved state to other managers.  It should not include any actual
	// dataplane updates yet.  (Those should be actioned in CompleteDeferredWork.)
	ResolveUpdateBatch() error
}

// InternalDataplane implements an in-process Felix dataplane driver based on iptables
// and ipsets.  It communicates with the datastore-facing part of Felix via the
// Send/RecvMessage methods, which operate on the protobuf-defined API objects.
//
// # Architecture
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
// # Requirements on the API
//
// The internal dataplane does not do consistency checks on the incoming data (as the
// old Python-based driver used to do).  It expects to be told about dependent resources
// before they are needed and for their lifetime to exceed that of the resources that
// depend on them. For example, it is important that the datastore layer sends an IP set
// create event before it sends a rule that references that IP set.
type InternalDataplane struct {
	toDataplane             chan any
	fromDataplane           chan any
	sendDataplaneInSyncOnce sync.Once

	mainRouteTables []routetable.SyncerInterface
	allTables       []generictables.Table
	mangleTables    []generictables.Table
	natTables       []generictables.Table
	rawTables       []generictables.Table
	filterTables    []generictables.Table
	ipSets          []dpsets.IPSetsDataplane

	ipipParentIfaceC chan string
	ipipManager      *ipipManager

	noEncapManager        *noEncapManager
	noEncapManagerV6      *noEncapManager
	noEncapParentIfaceC   chan string
	noEncapParentIfaceCV6 chan string

	vxlanParentIfaceC   chan string
	vxlanParentIfaceCV6 chan string
	vxlanManager        *vxlanManager
	vxlanManagerV6      *vxlanManager
	vxlanFDBs           []*vxlanfdb.VXLANFDB

	linkAddrsManagers []*linkaddrs.LinkAddrsManager

	wireguardManager   *wireguardManager
	wireguardManagerV6 *wireguardManager

	ifaceMonitor *ifacemonitor.InterfaceMonitor
	ifaceUpdates chan any

	endpointStatusCombiner *endpointStatusCombiner

	allManagers             []Manager
	managersWithRouteTables []ManagerWithRouteTables
	managersWithRouteRules  []ManagerWithRouteRules
	ruleRenderer            rules.RuleRenderer

	// datastoreInSync is set to true after we receive the "in sync" message from the datastore.
	// We delay programming of the dataplane until we're in sync with the datastore.
	datastoreInSync bool
	// ifaceMonitorInSync is set to true after the interface monitor reports that it is in sync.
	// As above, we block dataplane updates until we get that message.
	ifaceMonitorInSync bool

	// dataplaneNeedsSync is set if the dataplane is dirty in some way, i.e. we need to
	// call apply().
	dataplaneNeedsSync bool
	// forceIPSetsRefresh is set by the IP sets refresh timer to indicate that we should
	// check the IP sets in the dataplane.
	forceIPSetsRefresh bool
	// forceRouteRefresh is set by the route refresh timer to indicate that we should
	// check the routes in the dataplane.
	forceRouteRefresh bool
	// forceXDPRefresh is set by the XDP refresh timer to indicate that we should
	// check the XDP state in the dataplane.
	forceXDPRefresh bool
	// doneFirstApply is set after we finish the first update to the dataplane. It indicates
	// that the dataplane should now be in sync, though it is possible that an error occurred
	// necessitating a re-apply.
	doneFirstApply bool

	reschedTimer *time.Timer
	reschedC     <-chan time.Time

	applyThrottle *throttle.Throttle

	config Config

	debugHangC <-chan time.Time

	xdpState          *xdpState
	sockmapState      *sockmapState
	endpointsSourceV4 endpointsSource
	ipsetsSourceV4    ipsetsSource
	callbacks         *common.Callbacks

	loopSummarizer *logutils.Summarizer

	// Fields used to accumulate counts of messages of various types before we report them to
	// prometheus.
	datastoreBatchSize   int
	linkUpdateBatchSize  int
	addrsUpdateBatchSize int

	actions  generictables.ActionFactory
	newMatch func() generictables.MatchCriteria

	// nftablesEnabled tracks whether we are using nftables on this node.
	nftablesEnabled bool

	// kubeProxyNftablesEnabled tracks whether kube-proxy is running in nftables mode on this node.
	kubeProxyNftablesEnabled bool

	// getKubeProxyNftablesEnabled is a function that can be called to re-check whether kube-proxy
	// is running in nftables mode.
	getKubeProxyNftablesEnabled func() (bool, error)
}

const (
	healthName     = "InternalDataplaneMainLoop"
	healthInterval = 10 * time.Second

	ipipMTUOverhead        = 20
	vxlanMTUOverhead       = 50
	vxlanV6MTUOverhead     = 70
	wireguardMTUOverhead   = 60
	wireguardV6MTUOverhead = 80
	aksMTUOverhead         = 100
)

func NewIntDataplaneDriver(config Config) *InternalDataplane {
	if config.BPFLogLevel == "info" {
		config.BPFLogLevel = "off"
	}

	log.WithField("config", config).Info("Creating internal dataplane driver.")

	// Decide whether to use nftables or iptables based on configuration and kube-proxy mode.
	detectKubeProxyNftablesMode := nftables.KubeProxyNftablesEnabledFn(config.NewNftablesDataplane)
	kubeProxyNftablesEnabled, err := detectKubeProxyNftablesMode()
	if err != nil {
		log.WithError(err).Panic("Unable to detect kube-proxy nftables mode, shutting down")
	}
	nftablesEnabled := useNftables(config.RulesConfig.NFTablesMode, kubeProxyNftablesEnabled)

	ruleRenderer := config.RuleRendererOverride
	if ruleRenderer == nil {
		ruleRenderer = rules.NewRenderer(config.RulesConfig, nftablesEnabled)
	}
	epMarkMapper := rules.NewEndpointMarkMapper(
		config.RulesConfig.MarkEndpoint,
		config.RulesConfig.MarkNonCaliEndpoint)

	// Auto-detect host MTU.
	hostMTU, err := findHostMTU(config.MTUIfacePattern)
	if err != nil {
		log.WithError(err).Panic("Unable to detect host MTU, shutting down")
		return nil
	}
	ConfigureDefaultMTUs(hostMTU, &config)
	podMTU := determinePodMTU(config)
	if err := writeMTUFile(podMTU); err != nil {
		// Fail early if RequireMTUFile is true
		if config.RequireMTUFile {
			log.WithError(err).Error("Failed to write MTU file shutting, down")
			return nil
		}
		log.WithError(err).Error("Failed to write MTU file, pod MTU may not be properly set")
	}

	featureDetector := environment.NewFeatureDetector(
		config.FeatureDetectOverrides,
		environment.WithFeatureGates(config.FeatureGates),
	)

	// Determine the action set and new match function based on the underlying generictables implementation.
	actionSet := iptables.Actions()
	newMatchFn := iptables.Match
	if nftablesEnabled {
		actionSet = nftables.Actions()
		newMatchFn = nftables.Match
	}

	dp := &InternalDataplane{
		toDataplane:                 make(chan any, msgPeekLimit),
		fromDataplane:               make(chan any, 100),
		ruleRenderer:                ruleRenderer,
		ifaceMonitor:                ifacemonitor.New(config.IfaceMonitorConfig, featureDetector, config.FatalErrorRestartCallback),
		ifaceUpdates:                make(chan any, 100),
		config:                      config,
		applyThrottle:               throttle.New(10),
		loopSummarizer:              logutils.NewSummarizer("dataplane reconciliation loops"),
		actions:                     actionSet,
		newMatch:                    newMatchFn,
		nftablesEnabled:             nftablesEnabled,
		kubeProxyNftablesEnabled:    kubeProxyNftablesEnabled,
		getKubeProxyNftablesEnabled: detectKubeProxyNftablesMode,
	}
	dp.applyThrottle.Refill() // Allow the first apply() immediately.
	dp.ifaceMonitor.StateCallback = dp.onIfaceStateChange
	dp.ifaceMonitor.AddrCallback = dp.onIfaceAddrsChange
	dp.ifaceMonitor.InSyncCallback = dp.onIfaceInSync

	backendMode := environment.DetectBackend(config.LookPathOverride, cmdshim.NewRealCmd, config.IptablesBackend)

	// Most tables need the same options.
	iptablesOptions := iptables.TableOptions{
		HistoricChainPrefixes: rules.AllHistoricChainNamePrefixes,
		InsertMode:            config.IptablesInsertMode,
		RefreshInterval:       config.TableRefreshInterval,
		PostWriteInterval:     config.IptablesPostWriteCheckInterval,
		LockProbeInterval:     config.IptablesLockProbeInterval,
		BackendMode:           backendMode,
		LookPathOverride:      config.LookPathOverride,
		OnStillAlive:          dp.reportHealth,
		OpRecorder:            dp.loopSummarizer,
	}
	nftablesOptions := nftables.TableOptions{
		RefreshInterval:  config.TableRefreshInterval,
		LookPathOverride: config.LookPathOverride,
		OnStillAlive:     dp.reportHealth,
		OpRecorder:       dp.loopSummarizer,
		Disabled:         !nftablesEnabled,
		NewDataplane:     config.NewNftablesDataplane,
	}

	var cleanupTables []generictables.Table
	if config.BPFEnabled && config.BPFKubeProxyIptablesCleanupEnabled {
		// If BPF-mode is enabled, clean up kube-proxy's rules too.
		log.Info("BPF enabled, configuring iptables/nftables layer to clean up kube-proxy's rules.")
		iptablesOptions.ExtraCleanupRegexPattern = rules.KubeProxyInsertRuleRegex
		iptablesOptions.HistoricChainPrefixes = append(iptablesOptions.HistoricChainPrefixes, rules.KubeProxyChainPrefixes...)
		// Delete the ip kube-proxy and ip6 kube-proxy tables in nftables.
		nftablesKPOptions := nftablesOptions
		nftablesKPOptions.Disabled = true
		kubeProxyTableV4NFT := nftables.NewTable("kube-proxy", 4, rules.RuleHashPrefix, featureDetector, nftablesKPOptions, nftablesEnabled)
		cleanupTables = append(cleanupTables, kubeProxyTableV4NFT)
		if config.IPv6Enabled {
			kubeProxyTableV6NFT := nftables.NewTable("kube-proxy", 6, rules.RuleHashPrefix, featureDetector, nftablesKPOptions, nftablesEnabled)
			cleanupTables = append(cleanupTables, kubeProxyTableV6NFT)
		}
	}

	if config.BPFEnabled && !config.BPFPolicyDebugEnabled {
		err := os.RemoveAll(bpf.RuntimePolDir)
		if err != nil && !os.IsNotExist(err) {
			log.WithError(err).Info("Policy debug disabled but failed to remove the debug directory.  Ignoring.")
		}
	}

	// However, the NAT tables need an extra cleanup regex.
	iptablesNATOptions := iptablesOptions
	if iptablesNATOptions.ExtraCleanupRegexPattern == "" {
		iptablesNATOptions.ExtraCleanupRegexPattern = rules.HistoricInsertedNATRuleRegex
	} else {
		iptablesNATOptions.ExtraCleanupRegexPattern += "|" + rules.HistoricInsertedNATRuleRegex
	}

	// iptables and nftables implementations.
	var mangleTableV4NFT, natTableV4NFT, rawTableV4NFT, filterTableV4NFT generictables.Table
	var mangleTableV4IPT, natTableV4IPT, rawTableV4IPT, filterTableV4IPT generictables.Table

	// This is required when nftables mode is configured; but also useful for cleanup in other modes.
	nftablesV4RootTable := nftables.NewTable("calico", 4, rules.RuleHashPrefix, featureDetector, nftablesOptions, nftablesEnabled)

	if nftablesEnabled {
		// Create nftables Table implementations.
		mangleTableV4NFT = nftables.NewTableLayer("mangle", nftablesV4RootTable)
		natTableV4NFT = nftables.NewTableLayer("nat", nftablesV4RootTable)
		rawTableV4NFT = nftables.NewTableLayer("raw", nftablesV4RootTable)
		filterTableV4NFT = nftables.NewTableLayer("filter", nftablesV4RootTable)
	}

	// Create iptables table implementations.
	mangleTableV4IPT = iptables.NewTable("mangle", 4, rules.RuleHashPrefix, featureDetector, iptablesOptions)
	natTableV4IPT = iptables.NewTable("nat", 4, rules.RuleHashPrefix, featureDetector, iptablesNATOptions)
	rawTableV4IPT = iptables.NewTable("raw", 4, rules.RuleHashPrefix, featureDetector, iptablesOptions)
	filterTableV4IPT = iptables.NewTable("filter", 4, rules.RuleHashPrefix, featureDetector, iptablesOptions)

	// Based on configuration, some of the above tables should be active and others not.
	var mangleTableV4, natTableV4, rawTableV4, filterTableV4 generictables.Table
	var ipSetsV4 dpsets.IPSetsDataplane
	var cleanupIPSets []dpsets.IPSetsDataplane
	if nftablesEnabled {
		// Enable nftables.
		mangleTableV4 = mangleTableV4NFT
		natTableV4 = natTableV4NFT
		rawTableV4 = rawTableV4NFT
		filterTableV4 = filterTableV4NFT
		ipSetsV4 = nftablesV4RootTable

		// Cleanup iptables.
		cleanupTables = append(cleanupTables,
			mangleTableV4IPT,
			natTableV4IPT,
			rawTableV4IPT,
			filterTableV4IPT,
		)
		cleanupIPSets = append(cleanupIPSets, ipsets.NewIPSets(config.RulesConfig.IPSetConfigV4, dp.loopSummarizer))
	} else {
		// Enable iptables.
		mangleTableV4 = mangleTableV4IPT
		natTableV4 = natTableV4IPT
		rawTableV4 = rawTableV4IPT
		filterTableV4 = filterTableV4IPT
		ipSetsV4 = ipsets.NewIPSets(config.RulesConfig.IPSetConfigV4, dp.loopSummarizer)

		if nftablesV4RootTable != nil {
			// Cleanup nftables - we can simply add the root table here, Since
			// all the other tables / ipsets / maps are handled by the root table.
			cleanupTables = append(cleanupTables, nftablesV4RootTable)
		}
	}

	dp.natTables = append(dp.natTables, natTableV4)
	dp.rawTables = append(dp.rawTables, rawTableV4)
	dp.mangleTables = append(dp.mangleTables, mangleTableV4)
	dp.filterTables = append(dp.filterTables, filterTableV4)

	dp.ipSets = append(dp.ipSets, ipSetsV4)

	var routeTableV4 routetable.Interface
	var routeTableV6 routetable.Interface

	if !config.RouteSyncDisabled {
		log.Debug("Route management is enabled.")
		routeTableV4 = routetable.New(
			ownershippol.NewMainTable(
				dataplanedefs.VXLANIfaceNameV4,
				config.DeviceRouteProtocol,
				config.RulesConfig.WorkloadIfacePrefixes,
				config.RemoveExternalRoutes,
			),
			4,
			config.NetlinkTimeout,
			config.DeviceRouteSourceAddress,
			config.DeviceRouteProtocol,
			config.RemoveExternalRoutes,
			unix.RT_TABLE_MAIN,
			dp.loopSummarizer,
			featureDetector,
			routetable.WithStaticARPEntries(true),
			routetable.WithLivenessCB(dp.reportHealth),
			routetable.WithRouteCleanupGracePeriod(routeCleanupGracePeriod),
		)
		if config.IPv6Enabled {
			routeTableV6 = routetable.New(
				ownershippol.NewMainTable(
					dataplanedefs.VXLANIfaceNameV6,
					config.DeviceRouteProtocol,
					config.RulesConfig.WorkloadIfacePrefixes,
					config.RemoveExternalRoutes,
				),
				6,
				config.NetlinkTimeout,
				config.DeviceRouteSourceAddressIPv6,
				config.DeviceRouteProtocol,
				config.RemoveExternalRoutes,
				unix.RT_TABLE_MAIN,
				dp.loopSummarizer,
				featureDetector,
				// Note: deliberately not including:
				// - Static neighbor entries: we've never supported these for IPv6;
				//   we let the kernel populate them.
				routetable.WithLivenessCB(dp.reportHealth),
				routetable.WithRouteCleanupGracePeriod(routeCleanupGracePeriod),
			)
		}
	} else {
		log.Info("Route management is disabled, using DummyTables.")
		routeTableV4 = &routetable.DummyTable{}
		if config.IPv6Enabled {
			routeTableV6 = &routetable.DummyTable{}
		}
	}
	dp.mainRouteTables = append(dp.mainRouteTables, routeTableV4)
	if routeTableV6 != nil {
		dp.mainRouteTables = append(dp.mainRouteTables, routeTableV6)
	}

	// If no overlay is enabled, and Felix is responsible for programming routes, starts a manager to
	// program no encapsulation routes.
	if config.ProgramClusterRoutes {
		if !config.RulesConfig.VXLANEnabled && !config.RulesConfig.IPIPEnabled && !config.RulesConfig.WireguardEnabled {
			log.Info("Unencapsulated IPv4 route programming enabled, starting thread to keep no encapsulation routes in sync.")
			// Add a manager to keep the all-hosts IP set up to date.
			dp.noEncapManager = newNoEncapManager(
				routeTableV4,
				4,
				config,
				dp.loopSummarizer,
			)
			dp.noEncapParentIfaceC = make(chan string, 1)
			go dp.noEncapManager.monitorParentDevice(
				context.Background(),
				time.Second*10,
				dp.noEncapParentIfaceC,
			)
			dp.RegisterManager(dp.noEncapManager)
		}

		if config.IPv6Enabled &&
			!config.RulesConfig.VXLANEnabledV6 && !config.RulesConfig.WireguardEnabledV6 {
			log.Info("Unencapsulated IPv6 route programming enabled, starting thread to keep no encapsulation routes in sync.")
			// Add a manager to keep the all-hosts IP set up to date.
			dp.noEncapManagerV6 = newNoEncapManager(
				routeTableV6,
				6,
				config,
				dp.loopSummarizer,
			)
			dp.noEncapParentIfaceCV6 = make(chan string, 1)
			go dp.noEncapManagerV6.monitorParentDevice(
				context.Background(),
				time.Second*10,
				dp.noEncapParentIfaceCV6,
			)
			dp.RegisterManager(dp.noEncapManagerV6)
		}
	}

	dataplaneFeatures := featureDetector.GetFeatures()
	if config.RulesConfig.VXLANEnabled {
		var fdbOpts []vxlanfdb.Option
		if config.BPFEnabled && bpfutils.BTFEnabled {
			fdbOpts = append(fdbOpts, vxlanfdb.WithNeighUpdatesOnly())
		}
		vxlanFDB := vxlanfdb.New(netlink.FAMILY_V4, dataplanedefs.VXLANIfaceNameV4, featureDetector, config.NetlinkTimeout, fdbOpts...)
		dp.vxlanFDBs = append(dp.vxlanFDBs, vxlanFDB)

		dp.vxlanManager = newVXLANManager(
			ipSetsV4,
			routeTableV4,
			vxlanFDB,
			dataplanedefs.VXLANIfaceNameV4,
			4,
			config.VXLANMTU,
			config,
			dp.loopSummarizer,
		)
		dp.vxlanParentIfaceC = make(chan string, 1)
		vxlanMTU := config.VXLANMTU
		if config.BPFEnabled && bpfutils.BTFEnabled {
			vxlanMTU = 0
		}
		go dp.vxlanManager.keepVXLANDeviceInSync(
			context.Background(),
			vxlanMTU,
			dataplaneFeatures.ChecksumOffloadBroken,
			10*time.Second,
			dp.vxlanParentIfaceC,
		)
		dp.RegisterManager(dp.vxlanManager)
	} else {
		// Start a cleanup goroutine not to block felix if it needs to retry
		go cleanUpVXLANDevice(dataplanedefs.VXLANIfaceNameV4)
	}

	dp.endpointStatusCombiner = newEndpointStatusCombiner(dp.fromDataplane, config.IPv6Enabled)

	callbacks := common.NewCallbacks()
	dp.callbacks = callbacks
	if config.XDPEnabled {
		if err := bpf.SupportsXDP(); err != nil {
			log.WithError(err).Warn("Can't enable XDP acceleration.")
			config.XDPEnabled = false
		} else if !config.BPFEnabled {
			st, err := NewXDPState(config.XDPAllowGeneric)
			if err != nil {
				log.WithError(err).Warn("Can't enable XDP acceleration.")
			} else {
				dp.xdpState = st
				dp.xdpState.PopulateCallbacks(callbacks)
				dp.RegisterManager(st)
				log.Info("XDP acceleration enabled.")
			}
		}
	} else {
		log.Info("XDP acceleration disabled.")
	}

	// TODO Support cleaning up non-BPF XDP state from a previous Felix run, when BPF mode has just been enabled.
	if !config.BPFEnabled && dp.xdpState == nil {
		xdpState, err := NewXDPState(config.XDPAllowGeneric)
		if err == nil {
			if err := xdpState.WipeXDP(); err != nil {
				log.WithError(err).Warn("Failed to cleanup preexisting XDP state")
			}
		}
		// if we can't create an XDP state it means we couldn't get a working
		// bpffs so there's nothing to clean up
	}

	if config.SidecarAccelerationEnabled {
		if err := bpf.SupportsSockmap(); err != nil {
			log.WithError(err).Warn("Can't enable Sockmap acceleration.")
		} else {
			st, err := NewSockmapState()
			if err != nil {
				log.WithError(err).Warn("Can't enable Sockmap acceleration.")
			} else {
				dp.sockmapState = st
				dp.sockmapState.PopulateCallbacks(callbacks)

				if err := dp.sockmapState.SetupSockmapAcceleration(); err != nil {
					dp.sockmapState = nil
					log.WithError(err).Warn("Failed to set up Sockmap acceleration")
				} else {
					log.Info("Sockmap acceleration enabled.")
				}
			}
		}
	}

	if dp.sockmapState == nil {
		st, err := NewSockmapState()
		if err == nil {
			st.WipeSockmap(bpf.FindInBPFFSOnly)
		}
		// if we can't create a sockmap state it means we couldn't get a working
		// bpffs so there's nothing to clean up
	}

	ipsetsManager := dpsets.NewIPSetsManager("ipv4", ipSetsV4, config.MaxIPSetSize)
	ipsetsManagerV6 := dpsets.NewIPSetsManager("ipv6", nil, config.MaxIPSetSize)

	// iptables / nftables specific filter Table implementations for IPv6.
	var filterTableV6NFT, filterTableV6IPT generictables.Table

	// Create nftables Table implementations for IPv6.
	nftablesV6RootTable := nftables.NewTable("calico", 6, rules.RuleHashPrefix, featureDetector, nftablesOptions, nftablesEnabled)
	filterTableV6NFT = nftables.NewTableLayer("filter", nftablesV6RootTable)

	// Create iptables Table implementations for IPv6.
	filterTableV6IPT = iptables.NewTable("filter", 6, rules.RuleHashPrefix, featureDetector, iptablesOptions)

	// Select the correct table implementation based on whether we're using nftables or iptables.
	var filterTableV6 generictables.Table
	if nftablesEnabled {
		filterTableV6 = filterTableV6NFT
	} else {
		filterTableV6 = filterTableV6IPT
	}

	dp.RegisterManager(ipsetsManager)

	if !config.BPFEnabled {
		// BPF mode disabled, create the iptables/nftables-only managers.
		dp.ipsetsSourceV4 = ipsetsManager
		// TODO Connect host IP manager to BPF
		dp.RegisterManager(newHostIPManager(
			config.RulesConfig.WorkloadIfacePrefixes,
			rules.IPSetIDThisHostIPs,
			ipSetsV4,
			config.MaxIPSetSize))
		dp.RegisterManager(newPolicyManager(rawTableV4, mangleTableV4, filterTableV4, ruleRenderer, 4, nftablesEnabled))

		// Clean up any leftover BPF state.
		err := bpfnat.RemoveConnectTimeLoadBalancer(true, "")
		if err != nil {
			log.WithError(err).Info("Failed to remove BPF connect-time load balancer, ignoring.")
		}
		tc.CleanUpProgramsAndPins()
		bpfutils.RemoveBPFSpecialDevices()
	} else {
		// In BPF mode we still use iptables for raw egress policy.
		dp.RegisterManager(newRawEgressPolicyManager(rawTableV4, ruleRenderer, 4, ipSetsV4.SetFilter, nftablesEnabled))
	}

	interfaceRegexes := make([]string, len(config.RulesConfig.WorkloadIfacePrefixes))
	for i, r := range config.RulesConfig.WorkloadIfacePrefixes {
		interfaceRegexes[i] = "^" + r + ".*"
	}

	defaultRPFilter, err := os.ReadFile("/proc/sys/net/ipv4/conf/default/rp_filter")
	if err != nil {
		log.Warn("could not determine default rp_filter setting, defaulting to strict")
		defaultRPFilter = []byte{'1'}
	}

	bpfMapSizeConntrack := config.BPFMapSizeConntrack
	if config.BPFMapSizePerCPUConntrack > 0 {
		bpfMapSizeConntrack = config.BPFMapSizePerCPUConntrack * bpfmaps.NumPossibleCPUs()
	}

	bpfMapSizeConntrackResizeSize, _ := conntrackMapSizeFromFile()
	if bpfMapSizeConntrackResizeSize > bpfMapSizeConntrack {
		log.Infof("Overriding bpfMapSizeConntrack (%d) with map size growth (%d)",
			bpfMapSizeConntrack, bpfMapSizeConntrackResizeSize)
		bpfMapSizeConntrack = bpfMapSizeConntrackResizeSize
	}

	bpfipsets.SetMapSize(config.BPFMapSizeIPSets)
	bpfnat.SetMapSizes(config.BPFMapSizeNATFrontend, config.BPFMapSizeNATBackend, config.BPFMapSizeNATAffinity, config.BPFMapSizeMaglev)
	bpfroutes.SetMapSize(config.BPFMapSizeRoute)
	bpfconntrack.SetMapSize(bpfMapSizeConntrack)
	bpfconntrack.SetCleanupMapSize(config.BPFMapSizeConntrackCleanupQueue)
	bpfifstate.SetMapSize(config.BPFMapSizeIfState)

	var (
		bpfEndpointManager *bpfEndpointManager
		bpfEvnt            events.Events
		bpfEventPoller     *bpfEventPoller

		collectorPacketInfoReader    collectortypes.PacketInfoReader
		collectorConntrackInfoReader collectortypes.ConntrackInfoReader
	)

	// Initialisation needed for bpf.
	if config.BPFEnabled && config.FlowLogsEnabled {
		var err error
		// convert buffer size to bytes.
		ringSize := config.BPFExportBufferSizeMB * 1024 * 1024
		bpfEvnt, err = events.New(events.SourcePerfEvents, ringSize)
		if err != nil {
			log.WithError(err).Error("Failed to create perf event")
		} else {
			bpfEventPoller = newBpfEventPoller(bpfEvnt)
		}
	}

	if config.BPFEnabled {
		log.Info("BPF enabled, starting BPF endpoint manager and map manager.")

		bpfMaps, err := bpfmap.CreateBPFMaps(config.BPFIpv6Enabled)
		if err != nil {
			log.WithError(err).Panic("error creating bpf maps")
		}

		// Register map managers first since they create the maps that will be used by the endpoint manager.
		// Important that we create the maps before we load a BPF program with TC since we make sure the map
		// metadata name is set whereas TC doesn't set that field.
		var conntrackScannerV4, conntrackScannerV6 *bpfconntrack.Scanner
		var workloadRemoveChanV4, workloadRemoveChanV6 chan string
		var ipSetIDAllocatorV4, ipSetIDAllocatorV6 *idalloc.IDAllocator
		ipSetIDAllocatorV4 = idalloc.New()

		// Start IPv4 BPF dataplane components
		conntrackScannerV4, workloadRemoveChanV4 = startBPFDataplaneComponents(proto.IPVersion_IPV4, bpfMaps.V4, ipSetIDAllocatorV4, &config, ipsetsManager, dp)
		if config.BPFIpv6Enabled {
			// Start IPv6 BPF dataplane components
			ipSetIDAllocatorV6 = idalloc.New()
			conntrackScannerV6, workloadRemoveChanV6 = startBPFDataplaneComponents(proto.IPVersion_IPV6, bpfMaps.V6, ipSetIDAllocatorV6, &config, ipsetsManagerV6, dp)
		}

		workloadIfaceRegex := regexp.MustCompile(strings.Join(interfaceRegexes, "|"))

		if config.BPFConnTimeLB == string(apiv3.BPFConnectTimeLBDisabled) &&
			config.BPFHostNetworkedNAT == string(apiv3.BPFHostNetworkedNATDisabled) {
			log.Warn("Host-networked access to services from host networked process won't work properly " +
				"- BPFHostNetworkedNAT is disabled.")
		}

		if config.LookupsCache != nil {
			config.LookupsCache.EnableID64()
		}

		// Forwarding into an IPIP tunnel fails silently because IPIP tunnels are L3 devices and support for
		// L3 devices in BPF is not available yet.  Disable the FIB lookup in that case.
		bpfEndpointManager, err = NewBPFEndpointManager(
			nil,
			&config,
			bpfMaps,
			workloadIfaceRegex,
			ipSetIDAllocatorV4,
			ipSetIDAllocatorV6,
			ruleRenderer,
			filterTableV4,
			filterTableV6,
			dp.reportHealth,
			dp.loopSummarizer,
			routeTableV4,
			routeTableV6,
			config.LookupsCache,
			config.HealthAggregator,
			dataplaneFeatures,
			podMTU,
			workloadRemoveChanV4,
			workloadRemoveChanV6,
		)
		if err != nil {
			log.WithError(err).Panic("Failed to create BPF endpoint manager.")
		}

		dp.RegisterManager(bpfEndpointManager)

		// HostNetworkedNAT is Enabled and CTLB enabled.
		// HostNetworkedNAT is Disabled and CTLB is either disabled/TCP.
		// The above cases are invalid configuration. Revert to CTLB enabled.
		if config.BPFHostNetworkedNAT == string(apiv3.BPFHostNetworkedNATEnabled) {
			if config.BPFConnTimeLB == string(apiv3.BPFConnectTimeLBEnabled) {
				log.Warn("Both BPFConnectTimeLoadBalancing and BPFHostNetworkedNATWithoutCTLB are enabled. " +
					"Disabling BPFHostNetworkedNATWithoutCTLB. " +
					"Set BPFConnectTimeLoadBalancing=TCP if you want disable it for other protocols.")
				config.BPFHostNetworkedNAT = string(apiv3.BPFHostNetworkedNATDisabled)
			}
		} else {
			if config.BPFConnTimeLB != string(apiv3.BPFConnectTimeLBEnabled) {
				if config.BPFHostNetworkedNAT == string(apiv3.BPFHostNetworkedNATDisabled) {
					log.Warnf("Access to (some) services from host may not work properly because "+
						"BPFConnectTimeLoadBalancing is %s and BPFHostNetworkedNATWithoutCTLB is disabled",
						config.BPFConnTimeLB)
				}
			}
		}

		if config.BPFConnTimeLB != string(apiv3.BPFConnectTimeLBDisabled) {
			excludeUDP := false
			if config.BPFConnTimeLB == string(apiv3.BPFConnectTimeLBTCP) && config.BPFHostNetworkedNAT == string(apiv3.BPFHostNetworkedNATEnabled) {
				excludeUDP = true
			}
			logLevel := strings.ToLower(config.BPFLogLevel)
			if config.BPFLogFilters != nil {
				if logLevel != "off" && config.BPFCTLBLogFilter != "all" {
					logLevel = "off"
				}
			}

			// Activate the connect-time load balancer.
			err = bpfnat.InstallConnectTimeLoadBalancer(true, config.BPFIpv6Enabled,
				config.BPFCgroupV2, logLevel, config.BPFConntrackTimeouts.UDPTimeout, excludeUDP, bpfMaps.CommonMaps.CTLBProgramsMaps)
			if err != nil {
				log.WithError(err).Panic("BPFConnTimeLBEnabled but failed to attach connect-time load balancer, bailing out.")
			}
			log.Infof("Connect time load balancer enabled: %s", config.BPFConnTimeLB)
		} else {
			// Deactivate the connect-time load balancer.
			err = bpfnat.RemoveConnectTimeLoadBalancer(true, config.BPFCgroupV2)
			if err != nil {
				log.WithError(err).Warn("Failed to detach connect-time load balancer. Ignoring.")
			}
		}

		if config.Collector != nil && bpfEventPoller != nil {
			policyEventListener := events.NewCollectorPolicyListener(config.LookupsCache)
			bpfEventPoller.Register(events.TypePolicyVerdict, policyEventListener.EventHandler)
			if config.BPFIpv6Enabled {
				bpfEventPoller.Register(events.TypePolicyVerdictV6, policyEventListener.EventHandler)
			}
			log.Info("BPF: Registered events sink for TypePolicyVerdict")

			collectorPacketInfoReader = policyEventListener

			collectorCtInfoReader := bpfconntrack.NewCollectorCtInfoReader()
			// We must add the collectorConntrackInfoReader before
			// conntrack.LivenessScanner as we want to see expired connections and the
			// liveness scanner would remove them for us.
			if conntrackScannerV4 != nil {
				conntrackInfoReaderV4 := bpfconntrack.NewInfoReader(
					config.BPFConntrackTimeouts,
					config.BPFNodePortDSREnabled,
					nil,
					collectorCtInfoReader,
				)
				conntrackScannerV4.AddFirstUnlocked(conntrackInfoReaderV4)
			}
			if conntrackScannerV6 != nil {
				conntrackInfoReaderV6 := bpfconntrack.NewInfoReader(
					config.BPFConntrackTimeouts,
					config.BPFNodePortDSREnabled,
					nil,
					collectorCtInfoReader,
				)
				conntrackScannerV6.AddFirstUnlocked(conntrackInfoReaderV6)
			}

			log.Info("BPF: ConntrackInfoReader added to conntrackScanner")
			collectorConntrackInfoReader = collectorCtInfoReader
		}

		if conntrackScannerV4 != nil {
			conntrackScannerV4.Start()
		}
		if conntrackScannerV6 != nil {
			conntrackScannerV6.Start()
		}

		log.Info("conntrackScanner started")
	}

	var filterMaps nftables.MapsDataplane
	if nftablesEnabled {
		filterMaps = filterTableV4.(nftables.MapsDataplane)
	}

	linkAddrsManagerV4 := linkaddrs.New(4, config.RulesConfig.WorkloadIfacePrefixes, featureDetector, config.NetlinkTimeout)
	dp.linkAddrsManagers = append(dp.linkAddrsManagers, linkAddrsManagerV4)

	epManager := newEndpointManager(
		rawTableV4,
		mangleTableV4,
		filterTableV4,
		ruleRenderer,
		routeTableV4,
		4,
		epMarkMapper,
		config.RulesConfig.KubeIPVSSupportEnabled,
		config.RulesConfig.WorkloadIfacePrefixes,
		dp.endpointStatusCombiner.OnEndpointStatusUpdate,
		string(defaultRPFilter),
		filterMaps,
		config.BPFEnabled,
		config.BPFAttachType,
		bpfEndpointManager,
		callbacks,
		config.FloatingIPsEnabled,
		nftablesEnabled,
		linkAddrsManagerV4,
	)
	dp.RegisterManager(epManager)
	dp.endpointsSourceV4 = epManager
	dp.RegisterManager(newFloatingIPManager(natTableV4, ruleRenderer, 4, config.FloatingIPsEnabled))
	dp.RegisterManager(newMasqManager(ipSetsV4, natTableV4, ruleRenderer, config.MaxIPSetSize, 4))

	if config.RulesConfig.IPIPEnabled ||
		config.RulesConfig.NATOutgoingExclusions == string(apiv3.NATOutgoingExclusionsIPPoolsAndHostIPs) {
		dp.RegisterManager(newHostsIPSetManager(ipSetsV4, 4, config))
	}

	if !config.BPFEnabled {
		dp.RegisterManager(newDSCPManager(ipSetsV4, mangleTableV4, ruleRenderer, 4, config))
	}

	if config.RulesConfig.IPIPEnabled {
		log.Info("IPIP enabled, starting thread to keep tunnel configuration in sync.")
		// Add a manager to keep the all-hosts IP set up to date.
		dp.ipipManager = newIPIPManager(
			routeTableV4,
			dataplanedefs.IPIPIfaceName,
			4,
			config.IPIPMTU,
			config,
			dp.loopSummarizer,
		)
		dp.ipipParentIfaceC = make(chan string, 1)
		go dp.ipipManager.keepIPIPDeviceInSync(
			context.Background(),
			config.IPIPMTU,
			dataplaneFeatures.ChecksumOffloadBroken,
			time.Second*10,
			dp.ipipParentIfaceC,
		)
		dp.RegisterManager(dp.ipipManager)
	} else {
		// Only clean up IPIP addresses if IPIP is implicitly disabled (no IPIP pools and not explicitly set in FelixConfig)
		if config.RulesConfig.FelixConfigIPIPEnabled == nil {
			// Start a cleanup goroutine not to block felix if it needs to retry
			go cleanUpIPIPAddrs()
		}
	}

	// Add a manager for IPv4 wireguard configuration. This is added irrespective of whether wireguard is actually enabled
	// because it may need to tidy up some of the routing rules when disabled.
	cryptoRouteTableWireguard := wireguard.New(config.Hostname, &config.Wireguard, 4, config.NetlinkTimeout,
		config.DeviceRouteProtocol, func(publicKey wgtypes.Key) error {
			if publicKey == zeroKey {
				dp.fromDataplane <- &proto.WireguardStatusUpdate{PublicKey: "", IpVersion: 4}
			} else {
				dp.fromDataplane <- &proto.WireguardStatusUpdate{PublicKey: publicKey.String(), IpVersion: 4}
			}
			return nil
		},
		dp.loopSummarizer,
		featureDetector,
	)
	dp.wireguardManager = newWireguardManager(cryptoRouteTableWireguard, config, 4)
	dp.RegisterManager(dp.wireguardManager) // IPv4

	dp.RegisterManager(newServiceLoopManager(filterTableV4, ruleRenderer, 4))

	if config.IPv6Enabled {
		// Build out both iptables and nftables implementations for IPv6.
		var mangleTableV6NFT, natTableV6NFT, rawTableV6NFT generictables.Table
		var mangleTableV6IPT, natTableV6IPT, rawTableV6IPT generictables.Table

		if nftablesEnabled {
			// Define nftables table implementations for IPv6.
			mangleTableV6NFT = nftables.NewTableLayer("mangle", nftablesV6RootTable)
			natTableV6NFT = nftables.NewTableLayer("nat", nftablesV6RootTable)
			rawTableV6NFT = nftables.NewTableLayer("raw", nftablesV6RootTable)
		}

		// Define iptables table implementations for IPv6.
		mangleTableV6IPT = iptables.NewTable("mangle", 6, rules.RuleHashPrefix, featureDetector, iptablesOptions)
		natTableV6IPT = iptables.NewTable("nat", 6, rules.RuleHashPrefix, featureDetector, iptablesNATOptions)
		rawTableV6IPT = iptables.NewTable("raw", 6, rules.RuleHashPrefix, featureDetector, iptablesOptions)

		// Select the correct table implementation based on whether we're using nftables or iptables.
		var mangleTableV6, natTableV6, rawTableV6 generictables.Table
		var ipSetsV6 dpsets.IPSetsDataplane
		if nftablesEnabled {
			// Enable nftables.
			mangleTableV6 = mangleTableV6NFT
			natTableV6 = natTableV6NFT
			rawTableV6 = rawTableV6NFT
			ipSetsV6 = nftablesV6RootTable

			// Cleanup iptables.
			cleanupTables = append(cleanupTables,
				mangleTableV6IPT,
				natTableV6IPT,
				rawTableV6IPT,
				filterTableV6IPT,
			)
			cleanupIPSets = append(cleanupIPSets, ipsets.NewIPSets(config.RulesConfig.IPSetConfigV6, dp.loopSummarizer))
		} else {
			// Enable iptables.
			mangleTableV6 = mangleTableV6IPT
			natTableV6 = natTableV6IPT
			rawTableV6 = rawTableV6IPT
			ipSetsV6 = ipsets.NewIPSets(config.RulesConfig.IPSetConfigV6, dp.loopSummarizer)

			if nftablesV6RootTable != nil {
				// Cleanup nftables - we can simply add the root table here, Since
				// all the other tables / ipsets / maps are handled by the root table.
				cleanupTables = append(cleanupTables, nftablesV6RootTable)
			}
		}

		dp.ipSets = append(dp.ipSets, ipSetsV6)
		dp.natTables = append(dp.natTables, natTableV6)
		dp.rawTables = append(dp.rawTables, rawTableV6)
		dp.mangleTables = append(dp.mangleTables, mangleTableV6)
		dp.filterTables = append(dp.filterTables, filterTableV6)

		if config.RulesConfig.VXLANEnabledV6 {
			vxlanName := dataplanedefs.VXLANIfaceNameV6

			var (
				fdbOpts     []vxlanfdb.Option
				vxlanMgrOps []vxlanMgrOption
			)
			if config.BPFEnabled && bpfutils.BTFEnabled {
				// BPF mode uses the same device for both V4 and V6
				vxlanName = dataplanedefs.VXLANIfaceNameV4
				if dp.vxlanManager != nil {
					vxlanMgrOps = append(vxlanMgrOps, vxlanMgrWithDualStack())
				}
				fdbOpts = append(fdbOpts, vxlanfdb.WithNeighUpdatesOnly())
				go cleanUpVXLANDevice(dataplanedefs.VXLANIfaceNameV6)
			}
			vxlanFDBV6 := vxlanfdb.New(netlink.FAMILY_V6, vxlanName, featureDetector, config.NetlinkTimeout, fdbOpts...)
			dp.vxlanFDBs = append(dp.vxlanFDBs, vxlanFDBV6)

			dp.vxlanManagerV6 = newVXLANManager(
				ipSetsV6,
				routeTableV6,
				vxlanFDBV6,
				vxlanName,
				6,
				config.VXLANMTUV6,
				config,
				dp.loopSummarizer,
				vxlanMgrOps...,
			)
			dp.vxlanParentIfaceCV6 = make(chan string, 1)
			vxlanMTU := config.VXLANMTUV6
			if config.BPFEnabled && bpfutils.BTFEnabled {
				vxlanMTU = 0
			}
			go dp.vxlanManagerV6.keepVXLANDeviceInSync(
				context.Background(),
				vxlanMTU,
				dataplaneFeatures.ChecksumOffloadBroken,
				10*time.Second,
				dp.vxlanParentIfaceCV6,
			)
			dp.RegisterManager(dp.vxlanManagerV6)
		} else {
			// Start a cleanup goroutine not to block felix if it needs to retry
			go cleanUpVXLANDevice(dataplanedefs.VXLANIfaceNameV6)
		}

		ipsetsManagerV6.AddDataplane(ipSetsV6)
		dp.RegisterManager(ipsetsManagerV6)
		if !config.BPFEnabled {
			dp.RegisterManager(newHostIPManager(
				config.RulesConfig.WorkloadIfacePrefixes,
				rules.IPSetIDThisHostIPs,
				ipSetsV6,
				config.MaxIPSetSize))
			dp.RegisterManager(newPolicyManager(rawTableV6, mangleTableV6, filterTableV6, ruleRenderer, 6, nftablesEnabled))
		} else {
			dp.RegisterManager(newRawEgressPolicyManager(rawTableV6, ruleRenderer, 6, ipSetsV6.SetFilter, nftablesEnabled))
		}

		var filterMapsV6 nftables.MapsDataplane
		if nftablesEnabled {
			filterMapsV6 = filterTableV6.(nftables.MapsDataplane)
		}

		linkAddrsManagerV6 := linkaddrs.New(6, config.RulesConfig.WorkloadIfacePrefixes, featureDetector, config.NetlinkTimeout)
		dp.linkAddrsManagers = append(dp.linkAddrsManagers, linkAddrsManagerV6)

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
			dp.endpointStatusCombiner.OnEndpointStatusUpdate,
			"",
			filterMapsV6,
			config.BPFEnabled,
			config.BPFAttachType,
			nil,
			callbacks,
			config.FloatingIPsEnabled,
			nftablesEnabled,
			linkAddrsManagerV6,
		))
		dp.RegisterManager(newFloatingIPManager(natTableV6, ruleRenderer, 6, config.FloatingIPsEnabled))
		dp.RegisterManager(newMasqManager(ipSetsV6, natTableV6, ruleRenderer, config.MaxIPSetSize, 6))
		dp.RegisterManager(newServiceLoopManager(filterTableV6, ruleRenderer, 6))

		if config.RulesConfig.NATOutgoingExclusions == string(apiv3.NATOutgoingExclusionsIPPoolsAndHostIPs) {
			dp.RegisterManager(newHostsIPSetManager(ipSetsV6, 6, config))
		}

		if !config.BPFEnabled {
			dp.RegisterManager(newDSCPManager(ipSetsV6, mangleTableV6, ruleRenderer, 6, config))
		}

		// Add a manager for IPv6 wireguard configuration. This is added irrespective of whether wireguard is actually enabled
		// because it may need to tidy up some of the routing rules when disabled.
		cryptoRouteTableWireguardV6 := wireguard.New(config.Hostname, &config.Wireguard, 6, config.NetlinkTimeout,
			config.DeviceRouteProtocol, func(publicKey wgtypes.Key) error {
				if publicKey == zeroKey {
					dp.fromDataplane <- &proto.WireguardStatusUpdate{PublicKey: "", IpVersion: 6}
				} else {
					dp.fromDataplane <- &proto.WireguardStatusUpdate{PublicKey: publicKey.String(), IpVersion: 6}
				}
				return nil
			},
			dp.loopSummarizer,
			featureDetector)
		dp.wireguardManagerV6 = newWireguardManager(cryptoRouteTableWireguardV6, config, 6)
		dp.RegisterManager(dp.wireguardManagerV6)
	}

	if nftablesEnabled {
		// In nftables mode, we use a single underlying table to implement all tables. Only add the base table here
		// to avoid duplicating Apply() calls.
		dp.allTables = append(dp.allTables, nftablesV4RootTable)
		if config.IPv6Enabled {
			dp.allTables = append(dp.allTables, nftablesV6RootTable)
		}
	} else {
		dp.allTables = append(dp.allTables, dp.mangleTables...)
		dp.allTables = append(dp.allTables, dp.natTables...)
		dp.allTables = append(dp.allTables, dp.filterTables...)
		dp.allTables = append(dp.allTables, dp.rawTables...)
	}

	// Include cleanup tables in allTables so that they are cleaned up.
	dp.allTables = append(dp.allTables, cleanupTables...)
	dp.ipSets = append(dp.ipSets, cleanupIPSets...)

	// Register that we will report liveness and readiness.
	if config.HealthAggregator != nil {
		log.Info("Registering to report health.")
		timeout := config.WatchdogTimeout
		if timeout < healthInterval*2 {
			log.Warnf("Dataplane watchdog timeout (%v) too low, defaulting to %v", timeout, healthInterval*2)
			timeout = healthInterval * 2
		}
		config.HealthAggregator.RegisterReporter(
			healthName,
			&health.HealthReport{Live: true, Ready: true},
			timeout,
		)
	}

	if config.DebugSimulateDataplaneHangAfter != 0 {
		log.WithField("delay", config.DebugSimulateDataplaneHangAfter).Warn(
			"Simulating a dataplane hang.")
		dp.debugHangC = time.After(config.DebugSimulateDataplaneHangAfter)
	}

	// If required, subscribe to NFLog collection.
	if config.Collector != nil {
		if !config.BPFEnabled {
			log.Debug("Stats collection is required, create nflog reader")
			nflogrd := collector.NewNFLogReader(config.LookupsCache, 1, 2,
				config.NfNetlinkBufSize, true)
			collectorPacketInfoReader = nflogrd
			log.Debug("Stats collection is required, create conntrack reader")
			ctrd := collector.NewNetLinkConntrackReader(felixconfig.DefaultConntrackPollingInterval)
			collectorConntrackInfoReader = ctrd
		}

		config.Collector.SetPacketInfoReader(collectorPacketInfoReader)
		log.Info("PacketInfoReader added to collector")
		config.Collector.SetConntrackInfoReader(collectorConntrackInfoReader)
		log.Info("ConntrackInfoReader added to collector")
	}

	if bpfEventPoller != nil {
		log.Info("Starting BPF event poller")
		if err := bpfEventPoller.Start(); err != nil {
			log.WithError(err).Info("Stopping bpf event poller")
			err := bpfEvnt.Close()
			if err != nil {
				log.WithError(err).Info("Error from closing bpf event source.")
			}
		}
	}

	return dp
}

// useNftables determines whether to use nftables based on the FelixConfig setting and
// kube-proxy mode.
func useNftables(mode string, proxyEnabled bool) bool {
	use := false

	switch mode {
	case "Auto":
		// Detect based on kube-proxy mode.
		use = proxyEnabled
	case "Enabled":
		use = true
	}

	log.WithFields(log.Fields{
		"kubeProxyEnabled": proxyEnabled,
		"calicoMode":       mode,
		"useNftables":      use,
	}).Info("Determined whether or not to use nftables")
	return use
}

// findHostMTU auto-detects the smallest host interface MTU.
func findHostMTU(matchRegex *regexp.Regexp) (int, error) {
	// Find all the interfaces on the host.

	nlHandle, err := netlinkshim.NewRealNetlink()
	if err != nil {
		log.WithError(err).Error("Failed to create netlink handle. Unable to auto-detect MTU.")
		return 0, err
	}

	defer nlHandle.Delete()
	links, err := nlHandle.LinkList()
	if err != nil {
		log.WithError(err).Error("Failed to list interfaces. Unable to auto-detect MTU.")
		return 0, err
	}

	// Iterate through them, keeping track of the lowest MTU.
	smallest := 0
	for _, l := range links {
		// Skip links that we know are not external interfaces.
		fields := log.Fields{"mtu": l.Attrs().MTU, "name": l.Attrs().Name}
		if matchRegex == nil || !matchRegex.MatchString(l.Attrs().Name) {
			log.WithFields(fields).Debug("Skipping interface for MTU detection")
			continue
		}
		if !ifacemonitor.LinkIsOperUp(l) {
			log.WithFields(fields).Debug("Skipping down interface for MTU detection")
			continue
		}
		log.WithFields(fields).Debug("Examining link for MTU calculation")
		if l.Attrs().MTU < smallest || smallest == 0 {
			smallest = l.Attrs().MTU
		}
	}

	if smallest == 0 {
		// We failed to find a usable interface. Default the MTU of the host
		// to 1460 - the smallest among common cloud providers.
		log.Warn("Failed to auto-detect host MTU - no interfaces matched the MTU interface pattern. To use auto-MTU, set mtuIfacePattern to match your host's interfaces")
		return 1460, nil
	}
	return smallest, nil
}

// writeMTUFile writes the smallest MTU among enabled encapsulation types to disk
// for use by other components (e.g., CNI plugin).
func writeMTUFile(mtu int) error {
	// Make sure directory exists.
	if err := os.MkdirAll("/var/lib/calico", os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory /var/lib/calico: %s", err)
	}

	// Write the smallest MTU to disk so other components can rely on this calculation consistently.
	filename := "/var/lib/calico/mtu"
	log.Debugf("Writing %d to "+filename, mtu)
	if err := os.WriteFile(filename, fmt.Appendf(nil, "%d", mtu), 0o644); err != nil {
		log.WithError(err).Error("Unable to write to " + filename)
		return err
	}
	return nil
}

// determinePodMTU looks at the configured MTUs and enabled encapsulations to determine which
// value for MTU should be used for pod interfaces.
func determinePodMTU(config Config) int {
	// Determine the smallest MTU among enabled encap methods. If none of the encap methods are
	// enabled, we'll just use the host's MTU.
	mtu := 0
	type mtuState struct {
		mtu     int
		enabled bool
	}
	for _, s := range []mtuState{
		{config.IPIPMTU, config.RulesConfig.IPIPEnabled},
		{config.VXLANMTU, config.RulesConfig.VXLANEnabled},
		{config.VXLANMTUV6, config.RulesConfig.VXLANEnabledV6},
		{config.Wireguard.MTU, config.Wireguard.Enabled},
		{config.Wireguard.MTUV6, config.Wireguard.EnabledV6},
	} {
		if s.enabled && s.mtu != 0 && (s.mtu < mtu || mtu == 0) {
			mtu = s.mtu
		}
	}

	if mtu == 0 {
		// No enabled encapsulation. Just use the host MTU.
		mtu = config.hostMTU
	} else if mtu > config.hostMTU {
		fields := log.Fields{"mtu": mtu, "hostMTU": config.hostMTU}
		log.WithFields(fields).Warn("Configured MTU is larger than detected host interface MTU")
	}
	log.WithField("mtu", mtu).Info("Determined pod MTU")
	return mtu
}

// ConfigureDefaultMTUs defaults any MTU configurations that have not been set.
// We default the values even if the encap is not enabled, in order to match behavior from earlier versions of Calico.
// However, they MTU will only be considered for allocation to pod interfaces if the encap is enabled.
func ConfigureDefaultMTUs(hostMTU int, c *Config) {
	c.hostMTU = hostMTU
	if c.IPIPMTU == 0 {
		log.Debug("Defaulting IPIP MTU based on host")
		c.IPIPMTU = hostMTU - ipipMTUOverhead
	}
	if c.VXLANMTU == 0 {
		log.Debug("Defaulting IPv4 VXLAN MTU based on host")
		c.VXLANMTU = hostMTU - vxlanMTUOverhead
	}
	if c.VXLANMTUV6 == 0 {
		log.Debug("Defaulting IPv6 VXLAN MTU based on host")
		c.VXLANMTUV6 = hostMTU - vxlanV6MTUOverhead
	}
	if c.Wireguard.MTU == 0 {
		if c.KubernetesProvider == felixconfig.ProviderAKS && c.Wireguard.EncryptHostTraffic {
			// The default MTU on Azure is 1500, but the underlying network stack will fragment packets at 1400 bytes,
			// see https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-tcpip-performance-tuning#azure-and-vm-mtu
			// for details.
			// Additionally, Wireguard sets the DF bit on its packets, and so if the MTU is set too high large packets
			// will be dropped. Therefore it is necessary to allow for the difference between the MTU of the host and
			// the underlying network.
			log.Debug("Defaulting IPv4 Wireguard MTU based on host and AKS with WorkloadIPs")
			c.Wireguard.MTU = hostMTU - aksMTUOverhead - wireguardMTUOverhead
		} else {
			log.Debug("Defaulting IPv4 Wireguard MTU based on host")
			c.Wireguard.MTU = hostMTU - wireguardMTUOverhead
		}
	}
	if c.Wireguard.MTUV6 == 0 {
		if c.KubernetesProvider == felixconfig.ProviderAKS && c.Wireguard.EncryptHostTraffic {
			// The default MTU on Azure is 1500, but the underlying network stack will fragment packets at 1400 bytes,
			// see https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-tcpip-performance-tuning#azure-and-vm-mtu
			// for details.
			// Additionally, Wireguard sets the DF bit on its packets, and so if the MTU is set too high large packets
			// will be dropped. Therefore it is necessary to allow for the difference between the MTU of the host and
			// the underlying network.
			log.Debug("Defaulting IPv6 Wireguard MTU based on host and AKS with WorkloadIPs")
			c.Wireguard.MTUV6 = hostMTU - aksMTUOverhead - wireguardV6MTUOverhead
		} else {
			log.Debug("Defaulting IPv6 Wireguard MTU based on host")
			c.Wireguard.MTUV6 = hostMTU - wireguardV6MTUOverhead
		}
	}
}

func cleanUpIPIPAddrs() {
	// If IPIP is not enabled, check to see if there is are addresses in the IPIP device and delete them if there are.
	log.Debug("Checking if we need to clean up the IPIP device")

	var errFound bool

cleanupRetry:
	for i := 0; i <= maxCleanupRetries; i++ {
		errFound = false
		if i > 0 {
			log.Debugf("Retrying %v/%v times", i, maxCleanupRetries)
		}
		link, err := netlink.LinkByName(dataplanedefs.IPIPIfaceName)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				log.Debug("IPIP disabled and no IPIP device found")
				return
			}
			log.WithError(err).Warn("IPIP disabled and failed to query IPIP device.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			log.WithError(err).Warn("IPIP disabled and failed to list addresses, will be unable to remove any old addresses from the device should they exist.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}

		for _, oldAddr := range addrs {
			if err := netlink.AddrDel(link, &oldAddr); err != nil {
				log.WithError(err).Errorf("IPIP disabled and failed to delete unwanted IPIP address %s.", oldAddr.IPNet)
				errFound = true

				// Sleep for 1 second before retrying
				time.Sleep(1 * time.Second)
				continue cleanupRetry
			}
		}
	}
	if errFound {
		log.Warnf("Giving up trying to clean up IPIP addresses after retrying %v times", maxCleanupRetries)
	}
}

func cleanUpVXLANDevice(deviceName string) {
	// If VXLAN is not enabled, check to see if there is a VXLAN device and delete it if there is.
	log.Debug("Checking if we need to clean up the VXLAN device")

	var errFound bool
	for i := 0; i <= maxCleanupRetries; i++ {
		errFound = false
		if i > 0 {
			log.Debugf("Retrying %v/%v times", i, maxCleanupRetries)
		}
		link, err := netlink.LinkByName(deviceName)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				log.Debug("VXLAN disabled and no VXLAN device found")
				return
			}
			log.WithError(err).Warn("VXLAN disabled and failed to query VXLAN device.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}
		if err = netlink.LinkDel(link); err != nil {
			log.WithError(err).Error("VXLAN disabled and failed to delete unwanted VXLAN device.")
			errFound = true

			// Sleep for 1 second before retrying
			time.Sleep(1 * time.Second)
			continue
		}
	}
	if errFound {
		log.Warnf("Giving up trying to clean up VXLAN device after retrying %v times", maxCleanupRetries)
	}
}

type Manager interface {
	// OnUpdate is called for each protobuf message from the datastore.  May either directly
	// send updates to the IPSets and generictables.Table objects (which will queue the updates
	// until the main loop instructs them to act) or (for efficiency) may wait until
	// a call to CompleteDeferredWork() to flush updates to the dataplane.
	OnUpdate(protoBufMsg any)
	// Called before the main loop flushes updates to the dataplane to allow for batched
	// work to be completed.
	CompleteDeferredWork() error
}

type ManagerWithRouteTables interface {
	Manager
	GetRouteTableSyncers() []routetable.SyncerInterface
}

type ManagerWithRouteRules interface {
	Manager
	GetRouteRules() []routeRules
}

type routeRules interface {
	SetRule(rule *routerule.Rule)
	RemoveRule(rule *routerule.Rule)
	QueueResync()
	Apply() error
}

func (d *InternalDataplane) routeTableSyncers() []routetable.SyncerInterface {
	rts := d.mainRouteTables
	for _, mrts := range d.managersWithRouteTables {
		rts = append(rts, mrts.GetRouteTableSyncers()...)
	}
	return rts
}

func (d *InternalDataplane) routeRules() []routeRules {
	var rrs []routeRules
	for _, mrrs := range d.managersWithRouteRules {
		rrs = append(rrs, mrrs.GetRouteRules()...)
	}

	return rrs
}

func (d *InternalDataplane) RegisterManager(mgr Manager) {
	tableMgr, ok := mgr.(ManagerWithRouteTables)
	if ok {
		// Used to log the whole manager out here but if we do that then we cause races if the manager has
		// other threads or locks.
		log.WithField("manager", reflect.TypeOf(mgr).Name()).Debug("registering ManagerWithRouteTables")
		d.managersWithRouteTables = append(d.managersWithRouteTables, tableMgr)
	}

	rulesMgr, ok := mgr.(ManagerWithRouteRules)
	if ok {
		log.WithField("manager", mgr).Debug("registering ManagerWithRouteRules")
		d.managersWithRouteRules = append(d.managersWithRouteRules, rulesMgr)
	}
	d.allManagers = append(d.allManagers, mgr)
}

func (d *InternalDataplane) Start() {
	// Do our start-of-day configuration.
	d.doStaticDataplaneConfig()

	// Then, start the worker threads.
	go d.loopUpdatingDataplane()
	go d.loopReportingStatus()
	go d.ifaceMonitor.MonitorInterfaces()
	go d.monitorHostMTU()
	go d.monitorKubeProxyNftablesMode()
}

// onIfaceInSync is used as a callback from the interface monitor.  We use it to send a message back to
// the main goroutine via a channel.
func (d *InternalDataplane) onIfaceInSync() {
	d.ifaceUpdates <- &ifaceInSync{}
}

type ifaceInSync struct{}

// onIfaceStateChange is our interface monitor callback.  It gets called from the monitor's thread.
func (d *InternalDataplane) onIfaceStateChange(ifaceName string, state ifacemonitor.State, ifIndex int) {
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"ifIndex":   ifIndex,
		"state":     state,
	}).Info("Linux interface state changed.")
	d.ifaceUpdates <- &ifaceStateUpdate{
		Name:  ifaceName,
		State: state,
		Index: ifIndex,
	}
}

type ifaceStateUpdate struct {
	Name  string
	State ifacemonitor.State
	Index int
}

func NewIfaceStateUpdate(name string, state ifacemonitor.State, index int) any {
	return &ifaceStateUpdate{
		Name:  name,
		State: state,
		Index: index,
	}
}

// Check if current felix ipvs config is correct when felix gets a kube-ipvs0 interface update.
// If KubeIPVSInterface is UP and felix ipvs support is disabled (kube-proxy switched from iptables to ipvs mode),
// or if KubeIPVSInterface is DOWN and felix ipvs support is enabled (kube-proxy switched from ipvs to iptables mode),
// restart felix to pick up correct ipvs support mode.
func (d *InternalDataplane) checkIPVSConfigOnStateUpdate(state ifacemonitor.State) {
	ipvsIfacePresent := state != ifacemonitor.StateNotPresent
	ipvsSupportEnabled := d.config.RulesConfig.KubeIPVSSupportEnabled
	if ipvsSupportEnabled != ipvsIfacePresent {
		log.WithFields(log.Fields{
			"ipvsIfaceState": state,
			"ipvsSupport":    ipvsSupportEnabled,
		}).Info("kube-proxy mode changed. Restart felix.")
		d.config.ConfigChangedRestartCallback()
	}
}

// monitorKubeProxyNftablesMode monitors kube-proxy's nftables mode has changed and
// triggers a Felix restart if it has. This is only active if the nftables mode is set to "Auto".
func (d *InternalDataplane) monitorKubeProxyNftablesMode() {
	if d.config.RulesConfig.NFTablesMode != "Auto" {
		// We can skip this check if nftables is not configured to Auto.
		log.Debug("Skipping kube-proxy nftables mode monitoring as NFTablesMode is not set to Auto.")
		return
	}
	if d.getKubeProxyNftablesEnabled == nil {
		log.Panic("BUG: kube-proxy nftables mode check function is nil")
	}

	// Loop forever, checking kube proxy status at intervals.
	t := time.Tick(15 * time.Second)
	for range t {
		previous := d.kubeProxyNftablesEnabled
		current, err := d.getKubeProxyNftablesEnabled()
		if err != nil {
			log.WithError(err).Warn("Failed to detect kube-proxy nftables mode.")
			continue
		}

		if previous != current {
			log.WithFields(log.Fields{
				"previous": previous,
				"current":  current,
			}).Info("kube-proxy nftables mode changed. Restart felix.")
			d.config.ConfigChangedRestartCallback()
		}
	}
}

// onIfaceAddrsChange is our interface address monitor callback.  It gets called
// from the monitor's thread.
func (d *InternalDataplane) onIfaceAddrsChange(ifaceName string, addrs set.Set[string]) {
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"addrs":     addrs,
	}).Info("Linux interface addrs changed.")
	d.ifaceUpdates <- &ifaceAddrsUpdate{
		Name:  ifaceName,
		Addrs: addrs,
	}
}

type ifaceAddrsUpdate struct {
	Name  string
	Addrs set.Set[string]
}

func NewIfaceAddrsUpdate(name string, ips ...string) any {
	return &ifaceAddrsUpdate{
		Name:  name,
		Addrs: set.FromArray[string](ips),
	}
}

func (d *InternalDataplane) SendMessage(msg any) error {
	d.toDataplane <- msg
	return nil
}

func (d *InternalDataplane) RecvMessage() (any, error) {
	return <-d.fromDataplane, nil
}

func (d *InternalDataplane) monitorHostMTU() {
	for {
		mtu, err := findHostMTU(d.config.MTUIfacePattern)
		if err != nil {
			log.WithError(err).Error("Error detecting host MTU")
		} else if d.config.hostMTU != mtu {
			// Since log writing is done a background thread, we set the force-flush flag on this log to ensure that
			// all the in-flight logs get written before we exit.
			log.WithFields(log.Fields{lclogutils.FieldForceFlush: true}).Info("Host MTU changed")
			d.config.ConfigChangedRestartCallback()
		}
		time.Sleep(30 * time.Second)
	}
}

// doStaticDataplaneConfig sets up the kernel and our static iptables  chains.  Should be called
// once at start of day before starting the main loop.  The actual iptables programming is deferred
// to the main loop.
func (d *InternalDataplane) doStaticDataplaneConfig() {
	// Check/configure global kernel parameters.
	d.configureKernel()

	if d.config.BPFEnabled {
		d.setUpIptablesBPFEarly()
		d.setUpIptablesBPF()
	} else {
		d.setUpIptablesNormal()
	}
}

func (d *InternalDataplane) bpfMarkPreestablishedFlowsRules() []generictables.Rule {
	return []generictables.Rule{{
		Match:   d.newMatch().ConntrackState("ESTABLISHED,RELATED"),
		Comment: []string{"Mark pre-established flows."},
		Action: d.actions.SetMaskedMark(
			tcdefs.MarkLinuxConntrackEstablished,
			tcdefs.MarkLinuxConntrackEstablishedMask,
		),
	}}
}

func (d *InternalDataplane) setUpIptablesBPF() {
	// Wildcard matching varies based on iptables vs nftables.
	wildcard := iptables.Wildcard
	if d.nftablesEnabled {
		wildcard = nftables.Wildcard
	}

	rulesConfig := d.config.RulesConfig
	for _, t := range d.filterTables {
		fwdRules := []generictables.Rule{
			{
				// Bypass is a strong signal from the BPF program, it means that the flow is approved
				// by the program at both ingress and egress.
				Comment: []string{"Pre-approved by BPF programs."},
				Match:   d.newMatch().MarkMatchesWithMask(tcdefs.MarkSeenBypass, tcdefs.MarkSeenBypassMask),
				Action:  d.actions.Allow(),
			},
		}

		var inputRules, outputRules []generictables.Rule

		// Handle packets for flows that pre-date the BPF programs.  The BPF program doesn't have any conntrack
		// state for these so it allows them to fall through to iptables with a mark set.
		inputRules = append(inputRules,
			generictables.Rule{
				Match: d.newMatch().
					MarkMatchesWithMask(tcdefs.MarkSeenFallThrough, tcdefs.MarkSeenFallThroughMask).
					ConntrackState("ESTABLISHED,RELATED"),
				Comment: []string{"Accept packets from flows that pre-date BPF."},
				Action:  d.actions.Allow(),
			},
			generictables.Rule{
				Match: d.newMatch().
					MarkMatchesWithMask(tcdefs.MarkSeenFallThrough, tcdefs.MarkSeenFallThroughMask).
					Protocol("tcp"),
				Comment: []string{"REJECT/rst packets from unknown TCP flows."},
				Action:  d.actions.Reject("tcp-reset"),
			},
			generictables.Rule{
				Match:   d.newMatch().MarkMatchesWithMask(tcdefs.MarkSeenFallThrough, tcdefs.MarkSeenFallThroughMask),
				Comment: []string{fmt.Sprintf("%s packets from unknown non-TCP flows.", d.ruleRenderer.IptablesFilterDenyAction())},
				Action:  d.ruleRenderer.IptablesFilterDenyAction(),
			},
		)

		// Mark traffic leaving the host that already has an established linux conntrack entry.
		outputRules = append(outputRules, d.bpfMarkPreestablishedFlowsRules()...)

		for _, prefix := range rulesConfig.WorkloadIfacePrefixes {
			fwdRules = append(fwdRules,
				// Drop/reject packets that have come from a workload but have not been through our BPF program.
				generictables.Rule{
					Match:   d.newMatch().InInterface(prefix+wildcard).NotMarkMatchesWithMask(tcdefs.MarkSeen, tcdefs.MarkSeenMask),
					Action:  d.ruleRenderer.IptablesFilterDenyAction(),
					Comment: []string{"From workload without BPF seen mark"},
				},
			)

			if rulesConfig.EndpointToHostAction == "ACCEPT" {
				// Only need to worry about ACCEPT here.  Drop gets compiled into the BPF program and
				// RETURN would be a no-op since there's nothing to RETURN from.
				inputRules = append(inputRules, generictables.Rule{
					Match:  d.newMatch().InInterface(prefix+wildcard).MarkMatchesWithMask(tcdefs.MarkSeen, tcdefs.MarkSeenMask),
					Action: d.actions.Allow(),
				})
			}

			// Catch any workload to host packets that haven't been through the BPF program.
			inputRules = append(inputRules, generictables.Rule{
				Match:  d.newMatch().InInterface(prefix+wildcard).NotMarkMatchesWithMask(tcdefs.MarkSeen, tcdefs.MarkSeenMask),
				Action: d.ruleRenderer.IptablesFilterDenyAction(),
			})
		}

		if rulesConfig.EndpointToHostAction != "ACCEPT" {
			// We must accept WG traffic that goes towards the host. By this time, it is a
			// SEEN traffic, so it was policed and accepted at a HEP. If the default INPUT
			// chain policy was DROP, it would get dropped now, therefore an explicit accept
			// is needed.
			inputRules = append(inputRules, d.ruleRenderer.FilterInputChainAllowWG(t.IPVersion(), rulesConfig, d.actions.Allow())...)
		}

		if t.IPVersion() == 6 {
			if !d.config.BPFIpv6Enabled {
				for _, prefix := range rulesConfig.WorkloadIfacePrefixes {
					// In BPF ipv4 mode, drop ipv6 packets to pods.
					fwdRules = append(fwdRules, generictables.Rule{
						Match:   d.newMatch().OutInterface(prefix + wildcard),
						Action:  d.ruleRenderer.IptablesFilterDenyAction(),
						Comment: []string{"To workload, drop IPv6."},
					})
				}
			} else {
				// ICMPv6 for router/neighbor soliciting are allowed towards the
				// host, but the bpf programs cannot easily make sure that they
				// only go to the host. Make sure that they are not forwarded.
				fwdRules = append(fwdRules, d.ruleRenderer.ICMPv6Filter(d.ruleRenderer.IptablesFilterDenyAction())...)
			}
		}

		if t.IPVersion() == 4 || d.config.BPFIpv6Enabled {
			// Let the BPF programs know if Linux conntrack knows about the flow.
			fwdRules = append(fwdRules, d.bpfMarkPreestablishedFlowsRules()...)
			// The packet may be about to go to a local workload.  However, the local workload may not have a BPF
			// program attached (yet).  To catch that case, we send the packet through a dispatch chain.  We only
			// add interfaces to the dispatch chain if the BPF program is in place.
			for _, prefix := range rulesConfig.WorkloadIfacePrefixes {
				// Make sure iptables rules don't drop packets that we're about to process through BPF.
				fwdRules = append(fwdRules,
					generictables.Rule{
						Match:   d.newMatch().OutInterface(prefix + wildcard),
						Action:  d.actions.Jump(rules.ChainToWorkloadDispatch),
						Comment: []string{"To workload, check workload is known."},
					},
				)
			}
			// Need a final rule to accept traffic that is from a workload and going somewhere else.
			// Otherwise, if iptables has a DROP policy on the forward chain, the packet will get dropped.
			// This rule must come after the to-workload jump rules above to ensure that we don't accept too
			// early before the destination is checked.
			for _, prefix := range rulesConfig.WorkloadIfacePrefixes {
				// Make sure iptables rules don't drop packets that we're about to process through BPF.
				fwdRules = append(fwdRules,
					generictables.Rule{
						Match:   d.newMatch().InInterface(prefix + wildcard),
						Action:  d.actions.Allow(),
						Comment: []string{"To workload, mark has already been verified."},
					},
				)
			}
			fwdRules = append(fwdRules,
				generictables.Rule{
					Match:   d.newMatch().InInterface(dataplanedefs.BPFOutDev),
					Action:  d.actions.Allow(),
					Comment: []string{"From ", dataplanedefs.BPFOutDev, " device, mark verified, accept."},
				},
			)
		}

		t.InsertOrAppendRules("INPUT", inputRules)
		t.InsertOrAppendRules("FORWARD", fwdRules)
		t.InsertOrAppendRules("OUTPUT", outputRules)
	}

	for _, t := range d.natTables {
		t.UpdateChains(d.ruleRenderer.StaticNATPostroutingChains(t.IPVersion()))
		t.InsertOrAppendRules("POSTROUTING", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainNATPostrouting),
		}})
	}

	for _, t := range d.rawTables {
		t.UpdateChains(d.ruleRenderer.StaticBPFModeRawChains(t.IPVersion(),
			d.config.Wireguard.EncryptHostTraffic, d.config.BPFHostConntrackBypass,
		))
		t.InsertOrAppendRules("PREROUTING", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainRawPrerouting),
		}})
		t.InsertOrAppendRules("OUTPUT", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainRawOutput),
		}})
	}

	if d.config.BPFExtToServiceConnmark != 0 {
		mark := uint32(d.config.BPFExtToServiceConnmark)
		for _, t := range d.mangleTables {
			t.InsertOrAppendRules("PREROUTING", []generictables.Rule{{
				Match: d.newMatch().MarkMatchesWithMask(
					tcdefs.MarkSeen|mark,
					tcdefs.MarkSeenMask|mark,
				),
				Comment: []string{"Mark connections with ExtToServiceConnmark"},
				Action:  d.actions.SetConnmark(mark, mark),
			}})
		}
	}
}

// setUpIptablesBPFEarly that need to be written asap
func (d *InternalDataplane) setUpIptablesBPFEarly() {
	rules := d.bpfMarkPreestablishedFlowsRules()

	for _, t := range d.filterTables {
		// We want to prevent inserting the rules over and over again if something later
		// crashed. We do not expect that we would insert just a part of the batch as that
		// should be handled by the iptables-restore transaction.  Never the less if we
		// see that unexpected case, perhaps due to an upgrade, we skip over updating the
		// iptables now and will wait for the full resync. That could be temporarily
		// disrupting.
		if present := t.CheckRulesPresent("FORWARD", rules); present != nil {
			if len(present) != len(rules) {
				log.WithField("presentRules", present).
					Warn("Some early rules on filter FORWARD, skipping adding other, full resync will resolve it.")
			}
		} else {
			if err := t.InsertRulesNow("FORWARD", rules); err != nil {
				log.WithError(err).
					Warn("Failed inserting some early rules to filter FORWARD, some flows may get temporarily disrupted.")
			}
		}
		if present := t.CheckRulesPresent("OUTPUT", rules); present != nil {
			if len(present) != len(rules) {
				log.WithField("presentRules", present).
					Warn("Some early rules on filter OUTPUT, skipping adding other, full resync will resolve it.")
			}
		} else {
			if err := t.InsertRulesNow("OUTPUT", rules); err != nil {
				log.WithError(err).
					Warn("Failed inserting some early rules to filter OUTPUT, some flows may get temporarily disrupted.")
			}
		}
	}
}

func (d *InternalDataplane) setUpIptablesNormal() {
	for _, t := range d.rawTables {
		rawChains := d.ruleRenderer.StaticRawTableChains(t.IPVersion())
		t.UpdateChains(rawChains)
		t.InsertOrAppendRules("PREROUTING", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainRawPrerouting),
		}})
		t.InsertOrAppendRules("OUTPUT", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainRawOutput),
		}})
	}
	for _, t := range d.filterTables {
		filterChains := d.ruleRenderer.StaticFilterTableChains(t.IPVersion())
		t.UpdateChains(filterChains)
		t.InsertOrAppendRules("FORWARD", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainFilterForward),
		}})
		t.InsertOrAppendRules("INPUT", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainFilterInput),
		}})
		t.InsertOrAppendRules("OUTPUT", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainFilterOutput),
		}})

		// Include rules which should be appended to the filter table forward chain.
		t.AppendRules("FORWARD", d.ruleRenderer.StaticFilterForwardAppendRules())
	}
	for _, t := range d.natTables {
		t.UpdateChains(d.ruleRenderer.StaticNATTableChains(t.IPVersion()))
		t.InsertOrAppendRules("PREROUTING", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainNATPrerouting),
		}})
		// We must go last to avoid a conflict if both kube-proxy and Calico
		// decide to MASQ the traffic.
		//
		// This is because kube-proxy uses a mark bit to trigger its MASQ and
		// we need the mark bit to get cleared by kube-proxy's chain.  If we
		// go first, our MASQ rule terminates further processing, and the
		// mark bit remains set on the packet.
		//
		// Leaving the mark set on the packet is a problem when the packet
		// gets encapped because the mark is copied to the outer encap packet.
		// The outer packet then gets MASQed by kube-proxy's rule.  In turn,
		// that MASQ triggers a checksum offload bug in the kernel resulting
		// in corrupted packets.
		//
		// N.B. ChainFIPSnat does not do MASQ, but does not collide with k8s
		// service, namely nodeports.
		t.AppendRules("POSTROUTING", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainNATPostrouting),
		}})
		t.InsertOrAppendRules("OUTPUT", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainNATOutput),
		}})
	}
	for _, t := range d.mangleTables {
		t.UpdateChains(d.ruleRenderer.StaticMangleTableChains(t.IPVersion()))
		t.InsertOrAppendRules("PREROUTING", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainManglePrerouting),
		}})
		t.InsertOrAppendRules("POSTROUTING", []generictables.Rule{{
			Match:  d.newMatch(),
			Action: d.actions.Jump(rules.ChainManglePostrouting),
		}})
	}
	if d.xdpState != nil {
		if err := d.setXDPFailsafePorts(); err != nil {
			log.Warnf("failed to set XDP failsafe ports, disabling XDP: %v", err)
			if err := d.shutdownXDPCompletely(); err != nil {
				log.Warnf("failed to disable XDP: %v, will proceed anyway.", err)
			}
		}
	}
}

func stringToProtocol(protocol string) (ipsetmember.Protocol, error) {
	switch protocol {
	case "tcp":
		return ipsetmember.ProtocolTCP, nil
	case "udp":
		return ipsetmember.ProtocolUDP, nil
	case "sctp":
		return ipsetmember.ProtocolSCTP, nil
	}
	return ipsetmember.ProtocolNone, fmt.Errorf("unknown protocol %q", protocol)
}

func (d *InternalDataplane) setXDPFailsafePorts() error {
	inboundPorts := d.config.RulesConfig.FailsafeInboundHostPorts

	if _, err := d.xdpState.common.bpfLib.NewFailsafeMap(); err != nil {
		return err
	}

	for _, p := range inboundPorts {
		proto, err := stringToProtocol(p.Protocol)
		if err != nil {
			return err
		}

		if err := d.xdpState.common.bpfLib.UpdateFailsafeMap(uint8(proto), p.Port); err != nil {
			return err
		}
	}

	log.Infof("Set XDP failsafe ports: %+v", inboundPorts)
	return nil
}

// shutdownXDPCompletely attempts to disable XDP state.  This could fail in cases where XDP isn't working properly.
func (d *InternalDataplane) shutdownXDPCompletely() error {
	if d.xdpState == nil {
		return nil
	}
	if d.callbacks != nil {
		d.xdpState.DepopulateCallbacks(d.callbacks)
	}
	// spend 1 second attempting to wipe XDP, in case of a hiccup.
	maxTries := 10
	waitInterval := 100 * time.Millisecond
	var err error
	for i := range maxTries {
		err = d.xdpState.WipeXDP()
		if err == nil {
			d.xdpState = nil
			return nil
		}
		log.WithError(err).WithField("try", i).Warn("failed to wipe the XDP state")
		time.Sleep(waitInterval)
	}
	return fmt.Errorf("failed to wipe the XDP state after %v tries over %v seconds: Error %v", maxTries, waitInterval, err)
}

func (d *InternalDataplane) loopUpdatingDataplane() {
	log.Info("Started internal iptables dataplane driver loop")
	healthTicks := time.NewTicker(healthInterval).C
	d.reportHealth()

	// Retry any failed operations every 10s.
	retryTicker := time.NewTicker(10 * time.Second)

	// If configured, start tickers to refresh the IP sets and routing table entries.
	ipSetsRefreshC := newRefreshTicker("IP sets", d.config.IPSetsRefreshInterval)
	routeRefreshC := newRefreshTicker("routes", d.config.RouteRefreshInterval)
	var xdpRefreshC <-chan time.Time
	if d.xdpState != nil {
		xdpRefreshC = newRefreshTicker("XDP state", d.config.XDPRefreshInterval)
	}

	// Implement a simple leaky bucket throttle to control how often we refresh the dataplane.
	// This makes sure that we tend to favour processing updates from the datastore if we're
	// under load.
	throttleC := jitter.NewTicker(100*time.Millisecond, 10*time.Millisecond).Channel()
	beingThrottled := false

	for {
		select {
		case msg := <-d.toDataplane:
			d.onDatastoreMessage(msg)
		case ifaceUpdate := <-d.ifaceUpdates:
			d.onIfaceMonitorMessage(ifaceUpdate)
		case name := <-d.ipipParentIfaceC:
			d.ipipManager.routeMgr.OnParentDeviceUpdate(name)
		case name := <-d.noEncapParentIfaceC:
			d.noEncapManager.routeMgr.OnParentDeviceUpdate(name)
		case name := <-d.noEncapParentIfaceCV6:
			d.noEncapManagerV6.routeMgr.OnParentDeviceUpdate(name)
		case name := <-d.vxlanParentIfaceC:
			d.vxlanManager.routeMgr.OnParentDeviceUpdate(name)
		case name := <-d.vxlanParentIfaceCV6:
			d.vxlanManagerV6.routeMgr.OnParentDeviceUpdate(name)
		case <-ipSetsRefreshC:
			log.Debug("Refreshing IP sets state")
			d.forceIPSetsRefresh = true
			d.dataplaneNeedsSync = true
		case <-routeRefreshC:
			log.Debug("Refreshing routes")
			d.forceRouteRefresh = true
			d.dataplaneNeedsSync = true
		case <-xdpRefreshC:
			log.Debug("Refreshing XDP")
			d.forceXDPRefresh = true
			d.dataplaneNeedsSync = true
		case <-d.reschedC:
			log.Debug("Reschedule kick received")
			d.dataplaneNeedsSync = true
			// nil out the channel to record that the timer is now inactive.
			d.reschedC = nil
		case <-throttleC:
			d.applyThrottle.Refill()
		case <-healthTicks:
			d.reportHealth()
		case <-retryTicker.C:
		case <-d.debugHangC:
			log.Warning("Debug hang simulation timer popped, hanging the dataplane!!")
			time.Sleep(1 * time.Hour)
			log.Panic("Woke up after 1 hour, something's probably wrong with the test.")
		}

		if d.datastoreInSync && d.ifaceMonitorInSync && d.dataplaneNeedsSync {
			// Dataplane is out-of-sync, check if we're throttled.
			if d.applyThrottle.Admit() {
				if beingThrottled && d.applyThrottle.WouldAdmit() {
					log.Info("Dataplane updates no longer throttled")
					beingThrottled = false
				}
				log.Debug("Applying dataplane updates")
				applyStart := time.Now()

				if d.config.DebugSimulateDataplaneApplyDelay > 0 {
					log.WithField("delay", d.config.DebugSimulateDataplaneApplyDelay).Debug("Simulating a dataplane-apply delay")
					time.Sleep(d.config.DebugSimulateDataplaneApplyDelay)
				}
				// Actually apply the changes to the dataplane.
				d.apply()
				applyTime := time.Since(applyStart)

				if d.dataplaneNeedsSync {
					// Dataplane is still dirty, record an error.
					countDataplaneSyncErrors.Inc()
				} else {
					d.sendDataplaneInSyncOnce.Do(func() {
						d.fromDataplane <- &proto.DataplaneInSync{}
					})
				}

				d.loopSummarizer.EndOfIteration(applyTime)

				if !d.doneFirstApply {
					log.WithField(
						"secsSinceStart", time.Since(processStartTime).Seconds(),
					).Info("Completed first update to dataplane.")
					d.loopSummarizer.RecordOperation("first-update")
					d.doneFirstApply = true
					if d.config.PostInSyncCallback != nil {
						d.config.PostInSyncCallback()
					}
					// Record a dedicated stat for the initial resync.
					gaugeInitialResyncApplyTime.Set(applyTime.Seconds())
				} else {
					// Don't record the initial resync in the summary stat. On
					// a quiet cluster it can skew the stat for a long time.
					summaryApplyTime.Observe(applyTime.Seconds())
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

func newRefreshTicker(name string, interval time.Duration) <-chan time.Time {
	if interval <= 0 {
		log.Infof("Refresh of %s on timer disabled", name)
		return nil
	}
	log.WithField("interval", interval).Infof("Will refresh %s on timer", name)
	refreshTicker := jitter.NewTicker(interval, interval/10)
	return refreshTicker.Channel()
}

// onDatastoreMessage is called when we get a message from the calculation graph
// it opportunistically processes a match of messages from its channel.
func (d *InternalDataplane) onDatastoreMessage(msg any) {
	d.datastoreBatchSize = 1

	// Process the message we received, then opportunistically process any other
	// pending messages.  This helps to avoid doing two dataplane updates in quick
	// succession (and hence increasing latency) if we're _not_ being throttled.
	d.processMsgFromCalcGraph(msg)
	drainChan(d.toDataplane, d.processMsgFromCalcGraph)

	summaryBatchSize.Observe(float64(d.datastoreBatchSize))
}

func (d *InternalDataplane) processMsgFromCalcGraph(msg any) {
	if log.IsLevelEnabled(log.InfoLevel) {
		log.Infof("Received %T update from calculation graph. msg=%s", msg, proto.MsgStringer{Msg: msg}.String())
	}
	d.datastoreBatchSize++
	d.dataplaneNeedsSync = true
	d.recordMsgStat(msg)
	for _, mgr := range d.allManagers {
		mgr.OnUpdate(msg)
	}
	switch msg.(type) {
	case *proto.InSync:
		log.WithField("timeSinceStart", time.Since(processStartTime)).Info(
			"Datastore in sync, flushing the dataplane for the first time...")
		d.datastoreInSync = true
	}
}

// onIfaceMonitorMessage is called when we get a message from the interface monitor
// it opportunistically processes a match of messages from its channel.
func (d *InternalDataplane) onIfaceMonitorMessage(ifaceUpdate any) {
	// Separate stats for historic reasons: there use to be two channels.
	d.linkUpdateBatchSize = 0
	d.addrsUpdateBatchSize = 0

	// As for datastore messages, the interface monitor can send many messages in one go, so we
	// opportunistically process a batch even if we're not being throttled.
	d.processIfaceUpdate(ifaceUpdate)
	drainChan(d.ifaceUpdates, d.processIfaceUpdate)

	d.dataplaneNeedsSync = true
	if d.linkUpdateBatchSize > 0 {
		summaryIfaceBatchSize.Observe(float64(d.linkUpdateBatchSize))
	}
	if d.addrsUpdateBatchSize > 0 {
		summaryAddrBatchSize.Observe(float64(d.addrsUpdateBatchSize))
	}
}

func (d *InternalDataplane) processIfaceUpdate(ifaceUpdate any) {
	switch ifaceUpdateMsg := ifaceUpdate.(type) {
	case *ifaceStateUpdate:
		d.processIfaceStateUpdate(ifaceUpdateMsg)
	case *ifaceAddrsUpdate:
		d.processIfaceAddrsUpdate(ifaceUpdateMsg)
	case *ifaceInSync:
		d.processIfaceInSync()
	}
}

func (d *InternalDataplane) processIfaceInSync() {
	if d.ifaceMonitorInSync {
		return
	}
	log.Info("Interface monitor now in sync.")
	d.ifaceMonitorInSync = true
	d.dataplaneNeedsSync = true
}

func (d *InternalDataplane) processIfaceStateUpdate(ifaceUpdate *ifaceStateUpdate) {
	log.WithField("msg", ifaceUpdate).Info("Received interface update")
	d.dataplaneNeedsSync = true
	d.linkUpdateBatchSize++
	if ifaceUpdate.Name == KubeIPVSInterface {
		d.checkIPVSConfigOnStateUpdate(ifaceUpdate.State)
		return
	}

	for _, mgr := range d.allManagers {
		mgr.OnUpdate(ifaceUpdate)
	}

	for _, fdb := range d.vxlanFDBs {
		fdb.OnIfaceStateChanged(ifaceUpdate.Name, ifaceUpdate.State)
	}

	for _, rt := range d.mainRouteTables {
		rt.OnIfaceStateChanged(ifaceUpdate.Name, ifaceUpdate.Index, ifaceUpdate.State)
	}
	for _, mgr := range d.managersWithRouteTables {
		for _, routeTable := range mgr.GetRouteTableSyncers() {
			routeTable.OnIfaceStateChanged(ifaceUpdate.Name, ifaceUpdate.Index, ifaceUpdate.State)
		}
	}
}

func (d *InternalDataplane) processIfaceAddrsUpdate(ifaceAddrsUpdate *ifaceAddrsUpdate) {
	log.WithField("msg", ifaceAddrsUpdate).Info("Received interface addresses update")
	d.dataplaneNeedsSync = true
	d.addrsUpdateBatchSize++
	for _, mgr := range d.allManagers {
		mgr.OnUpdate(ifaceAddrsUpdate)
	}
}

func drainChan[T any](c <-chan T, f func(T)) {
	for range msgPeekLimit {
		select {
		case v := <-c:
			f(v)
		default:
			return
		}
	}
}

func (d *InternalDataplane) configureKernel() {
	// Attempt to modprobe nf_conntrack_proto_sctp.  In some kernels this is a
	// module that needs to be loaded, otherwise all SCTP packets are marked
	// INVALID by conntrack and dropped by Calico's rules.  However, some kernels
	// (confirmed in Ubuntu 19.10's build of 5.3.0-24-generic) include this
	// conntrack without it being a kernel module, and so modprobe will fail.
	// Log result at INFO level for troubleshooting, but otherwise ignore any
	// failed modprobe calls.
	mp := newModProbe(moduleConntrackSCTP, newRealCmd)
	out, err := mp.Exec()
	log.WithError(err).WithField("output", out).Infof("attempted to modprobe %s", moduleConntrackSCTP)

	if d.config.IPForwarding == "Enabled" {
		log.Info("Making sure IPv4 forwarding is enabled.")
		err = writeProcSys("/proc/sys/net/ipv4/ip_forward", "1")
		if err != nil {
			log.WithError(err).Error("Failed to set IPv4 forwarding sysctl")
		}

		if d.config.IPv6Enabled {
			log.Info("Making sure IPv6 forwarding is enabled.")
			err = writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", "1")
			if err != nil {
				log.WithError(err).Error("Failed to set IPv6 forwarding sysctl")
			}
		}
	} else {
		log.Info("IPv4 forwarding disabled by config, leaving sysctls untouched.")
	}

	// Enable conntrack packet and byte accounting.
	err = writeProcSys("/proc/sys/net/netfilter/nf_conntrack_acct", "1")
	if err != nil {
		log.Warnf("failed to set enable conntrack packet and byte accounting: %v\n", err)
	}

	if d.config.BPFEnabled && d.config.BPFDisableUnprivileged {
		log.Info("BPF enabled, disabling unprivileged BPF usage.")
		err := writeProcSys("/proc/sys/kernel/unprivileged_bpf_disabled", "1")
		if err != nil {
			log.WithError(err).Error("Failed to set unprivileged_bpf_disabled sysctl")
		}
	}
	if d.config.Wireguard.Enabled || d.config.Wireguard.EnabledV6 {
		// wireguard module is available in linux kernel >= 5.6
		mpwg := newModProbe(moduleWireguard, newRealCmd)
		out, err = mpwg.Exec()
		log.WithError(err).WithField("output", out).Infof("attempted to modprobe %s", moduleWireguard)
	}
}

func (d *InternalDataplane) recordMsgStat(msg any) {
	typeName := reflect.ValueOf(msg).Elem().Type().Name()
	countMessages.WithLabelValues(typeName).Inc()
}

func (d *InternalDataplane) apply() {
	// Update sequencing is important here because iptables rules have dependencies on ipsets.
	// Creating a rule that references an unknown IP set fails, as does deleting an IP set that
	// is in use.

	// Unset the needs-sync flag, we'll set it again if something fails.
	d.dataplaneNeedsSync = false

	// First, give the managers a chance to resolve any state based on the preceding batch of
	// updates.  In some cases, e.g. EndpointManager, this can result in an update to another
	// manager (BPFEndpointManager.OnHEPUpdate) that must happen before either of those managers
	// begins its dataplane programming updates.
	for _, mgr := range d.allManagers {
		if handler, ok := mgr.(UpdateBatchResolver); ok {
			err := handler.ResolveUpdateBatch()
			if err != nil {
				log.WithField("manager", reflect.TypeOf(mgr).Name()).WithError(err).Debug(
					"couldn't resolve update batch for manager, will try again later")
				d.dataplaneNeedsSync = true
			}
			d.reportHealth()
		}
	}

	// Now allow managers to complete the dataplane programming updates that they need.
	for _, mgr := range d.allManagers {
		err := mgr.CompleteDeferredWork()
		if err != nil {
			log.WithField("manager", reflect.TypeOf(mgr).Name()).WithError(err).Debug(
				"couldn't complete deferred work for manager, will try again later")
			d.dataplaneNeedsSync = true
		}
		d.reportHealth()
	}

	if d.xdpState != nil {
		if d.forceXDPRefresh {
			// Refresh timer popped.
			d.xdpState.QueueResync()
			d.forceXDPRefresh = false
		}

		var applyXDPError error
		d.xdpState.ProcessPendingDiffState(d.endpointsSourceV4)
		if err := d.applyXDPActions(); err != nil {
			applyXDPError = err
		} else {
			err := d.xdpState.ProcessMemberUpdates()
			d.xdpState.DropPendingDiffState()
			if err != nil {
				log.WithError(err).Warning("Failed to process XDP member updates, will resync later...")
				if err := d.applyXDPActions(); err != nil {
					applyXDPError = err
				}
			}
			d.xdpState.UpdateState()
		}
		if applyXDPError != nil {
			log.WithError(applyXDPError).Info("Applying XDP actions did not succeed, disabling XDP")
			if err := d.shutdownXDPCompletely(); err != nil {
				log.Warnf("failed to disable XDP: %v, will proceed anyway.", err)
			}
		}
	}
	d.reportHealth()

	if d.forceRouteRefresh {
		// Refresh timer popped.
		for _, r := range d.routeTableSyncers() {
			// Queue a resync on the next Apply().
			r.QueueResync()
		}
		for _, r := range d.routeRules() {
			// Queue a resync on the next Apply().
			r.QueueResync()
		}
		for _, fdb := range d.vxlanFDBs {
			fdb.QueueResync()
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

	// Next, create/update IP sets.  We defer deletions of IP sets until after we update tables.
	var ipSetsWG sync.WaitGroup
	for _, ipSets := range d.ipSets {
		ipSetsWG.Add(1)
		go func(ipSets dpsets.IPSetsDataplane) {
			ipSets.ApplyUpdates(nil)
			d.reportHealth()
			ipSetsWG.Done()
		}(ipSets)
	}

	// Update any VXLAN FDB entries.
	for _, fdb := range d.vxlanFDBs {
		err := fdb.Apply()
		if err != nil {
			var lnf netlink.LinkNotFoundError
			if errors.As(err, &lnf) || errors.Is(err, vxlanfdb.ErrLinkDown) {
				log.Debug("VXLAN interface not ready yet, can't sync FDB entries.")
			} else {
				log.WithError(err).Warn("Failed to synchronize VXLAN FDB entries, will retry...")
				d.dataplaneNeedsSync = true
			}
		}
	}

	// Update any linkAddrs entries.
	for _, la := range d.linkAddrsManagers {
		err := la.Apply()
		if err != nil {
			log.WithError(err).Warn("Failed to synchronize link addr entries, will retry...")
			d.dataplaneNeedsSync = true
		}
	}

	// Update the routing table in parallel with the other updates.  We'll wait for it to finish
	// before we return.
	var routesWG sync.WaitGroup
	var numBackgroundProblems atomic.Uint64
	for _, r := range d.routeTableSyncers() {
		routesWG.Add(1)
		go func(r routetable.SyncerInterface) {
			err := r.Apply()
			if err != nil {
				log.Warn("Failed to synchronize routing table, will retry...")
				numBackgroundProblems.Add(1)
			}
			d.reportHealth()
			routesWG.Done()
		}(r)
	}

	// Update the routing rules in parallel with the other updates.  We'll wait for it to finish
	// before we return.
	var rulesWG sync.WaitGroup
	for _, r := range d.routeRules() {
		rulesWG.Add(1)
		go func(r routeRules) {
			err := r.Apply()
			if err != nil {
				log.Warn("Failed to synchronize routing rules, will retry...")
				numBackgroundProblems.Add(1)
			}
			d.reportHealth()
			rulesWG.Done()
		}(r)
	}

	// Wait for the IP sets update to finish.  We can't update iptables until it has.
	ipSetsWG.Wait()

	// Update tables, this should sever any references to now-unused IP sets.
	var reschedDelayMutex sync.Mutex
	var reschedDelay time.Duration
	var iptablesWG sync.WaitGroup
	for _, t := range d.allTables {
		iptablesWG.Add(1)
		go func(t generictables.Table) {
			tableReschedAfter := t.Apply()

			reschedDelayMutex.Lock()
			defer reschedDelayMutex.Unlock()
			if tableReschedAfter != 0 && (reschedDelay == 0 || tableReschedAfter < reschedDelay) {
				reschedDelay = tableReschedAfter
			}
			d.reportHealth()
			iptablesWG.Done()
		}(t)
	}
	iptablesWG.Wait()

	// Now clean up any left-over IP sets.
	var ipSetsNeedsReschedule atomic.Bool
	for _, ipSets := range d.ipSets {
		ipSetsWG.Add(1)
		go func(s dpsets.IPSetsDataplane) {
			defer ipSetsWG.Done()
			reschedule := s.ApplyDeletions()
			if reschedule {
				ipSetsNeedsReschedule.Store(true)
			}
			d.reportHealth()
		}(ipSets)
	}
	ipSetsWG.Wait()
	if ipSetsNeedsReschedule.Load() {
		if reschedDelay == 0 || reschedDelay > 100*time.Millisecond {
			reschedDelay = 100 * time.Millisecond
		}
	}

	// Wait for the route updates to finish.
	routesWG.Wait()

	// Wait for the rule updates to finish.
	rulesWG.Wait()

	if numBackgroundProblems.Load() > 0 {
		d.dataplaneNeedsSync = true
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

func (d *InternalDataplane) applyXDPActions() error {
	var err error = nil
	for range 10 {
		err = d.xdpState.ResyncIfNeeded(d.ipsetsSourceV4)
		if err != nil {
			return err
		}
		if err = d.xdpState.ApplyBPFActions(d.ipsetsSourceV4); err == nil {
			return nil
		} else {
			log.WithError(err).Info("Applying XDP BPF actions did not succeed, will retry with resync...")
		}
	}
	return err
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

// Table is a shim interface for generictables.Table.
type Table interface {
	UpdateChain(chain *generictables.Chain)
	UpdateChains([]*generictables.Chain)
	RemoveChains([]*generictables.Chain)
	RemoveChainByName(name string)
}

func (d *InternalDataplane) reportHealth() {
	if d.config.HealthAggregator != nil {
		d.config.HealthAggregator.Report(
			healthName,
			&health.HealthReport{Live: true, Ready: d.doneFirstApply && d.ifaceMonitorInSync},
		)
	}
}

func startBPFDataplaneComponents(
	ipFamily proto.IPVersion,
	maps *bpfmap.IPMaps,
	ipSetIDAllocator *idalloc.IDAllocator,
	config *Config,
	ipSetsMgr *dpsets.IPSetsManager,
	dp *InternalDataplane,
) (*bpfconntrack.Scanner, chan string) {
	ipSetConfig := config.RulesConfig.IPSetConfigV4
	ipSetEntry := bpfipsets.IPSetEntryFromBytes
	ipSetProtoEntry := bpfipsets.ProtoIPSetMemberToBPFEntry

	failSafesKeyFromSlice := failsafes.KeyFromSlice
	failSafesKey := failsafes.MakeKey

	ctKey := bpfconntrack.KeyFromBytes
	ctVal := bpfconntrack.ValueFromBytes

	if config.bpfProxyHealthCheck == nil && config.KubeProxyHealtzPort != 0 {
		var err error
		config.bpfProxyHealthCheck, err = bpfproxy.NewHealthCheck(
			config.KubeClientSet,
			config.Hostname,
			config.KubeProxyHealtzPort,
			config.KubeProxyMinSyncPeriod,
		)
		if err != nil {
			log.WithError(err).Error("Failed to initialize BPF kube-proxy health check")
		}
	}

	bpfproxyOpts := []bpfproxy.Option{
		bpfproxy.WithMinSyncPeriod(config.KubeProxyMinSyncPeriod),
		bpfproxy.WithMaglevLUTSize(config.BPFMaglevLUTSize),
	}

	if config.bpfProxyHealthCheck != nil {
		bpfproxyOpts = append(bpfproxyOpts, bpfproxy.WithHealthCheck(config.bpfProxyHealthCheck))
	} else {
		log.Info("No healthz server configured for BPF kube-proxy.")
	}

	if config.BPFNodePortDSREnabled {
		bpfproxyOpts = append(bpfproxyOpts, bpfproxy.WithDSREnabled())
	}

	if len(config.NodeZone) != 0 {
		bpfproxyOpts = append(bpfproxyOpts, bpfproxy.WithTopologyNodeZone(config.NodeZone))
	}

	if len(config.BPFExcludeCIDRsFromNAT) > 0 {
		bpfproxyOpts = append(bpfproxyOpts, bpfproxy.WithExcludedCIDRs(config.BPFExcludeCIDRsFromNAT))
	}

	if ipFamily == proto.IPVersion_IPV6 {
		ipSetConfig = config.RulesConfig.IPSetConfigV6
		ipSetEntry = bpfipsets.IPSetEntryV6FromBytes
		ipSetProtoEntry = bpfipsets.ProtoIPSetMemberToBPFEntryV6

		failSafesKeyFromSlice = failsafes.KeyV6FromSlice
		failSafesKey = failsafes.MakeKeyV6

		ctKey = bpfconntrack.KeyV6FromBytes
		ctVal = bpfconntrack.ValueV6FromBytes

		bpfproxyOpts = append(bpfproxyOpts, bpfproxy.WithIPFamily(6))
	}

	ipSets := bpfipsets.NewBPFIPSets(ipSetConfig, ipSetIDAllocator, maps.IpsetsMap, ipSetEntry, ipSetProtoEntry, dp.loopSummarizer)
	dp.ipSets = append(dp.ipSets, ipSets)
	ipSetsMgr.AddDataplane(ipSets)

	failsafeMgr := failsafes.NewManager(
		maps.FailsafesMap,
		config.RulesConfig.FailsafeInboundHostPorts,
		config.RulesConfig.FailsafeOutboundHostPorts,
		dp.loopSummarizer,
		ipFamily,
		failSafesKeyFromSlice,
		failSafesKey,
	)
	dp.RegisterManager(failsafeMgr)

	bpfRTMgr := newBPFRouteManager(config, maps, ipFamily, dp.loopSummarizer)
	dp.RegisterManager(bpfRTMgr)

	livenessScanner := bpfconntrack.NewLivenessScanner(config.BPFConntrackTimeouts, config.BPFNodePortDSREnabled)
	ctLogLevel := bpfconntrack.BPFLogLevelNone
	if config.BPFConntrackLogLevel == "debug" {
		ctLogLevel = bpfconntrack.BPFLogLevelDebug
	}

	bpfCleaner, err := bpfconntrack.NewBPFProgCleaner(int(ipFamily), config.BPFConntrackTimeouts, ctLogLevel)
	if err != nil {
		log.Errorf("error creating the bpf cleaner %v", err)
	}

	workloadRemoveChan := make(chan string, 1000)
	conntrackScanner := bpfconntrack.NewScanner(maps.CtMap, ctKey, ctVal,
		config.ConfigChangedRestartCallback,
		config.BPFMapSizeConntrackScaling, maps.CtCleanupMap.(bpfmaps.MapWithExistsCheck),
		int(ipFamily),
		bpfCleaner,
		livenessScanner, bpfconntrack.NewWorkloadRemoveScannerTCP(workloadRemoveChan))

	// Before we start, scan for all finished / timed out connections to
	// free up the conntrack table asap as it may take time to sync up the
	// proxy and kick off the first full cleaner scan.
	conntrackScanner.Scan()

	if config.KubeClientSet != nil {
		kp, err := bpfproxy.StartKubeProxy(
			config.KubeClientSet,
			config.Hostname,
			maps,
			bpfproxyOpts...,
		)
		if err != nil {
			log.WithError(err).Panic("Failed to start kube-proxy.")
		}

		// Register KP itself as a manager, in order to collect host metadata.
		// Kube-proxy already interfaces with the dataplane via manager callbacks to receive information
		// that is already at-hand in those managers. But, when it comes to batching raw host information,
		// we might-as-well just funnel it directly from the calc-graph.
		dp.RegisterManager(kp)

		bpfRTMgr.setHostIPUpdatesCallBack(kp.OnHostIPsUpdate)
		bpfRTMgr.setRoutesCallBacks(kp.OnRouteUpdate, kp.OnRouteDelete)
		conntrackScanner.AddUnlocked(bpfconntrack.NewStaleNATScanner(kp))
	} else {
		log.Info("BPF enabled but no Kubernetes client available, unable to run kube-proxy module.")
	}
	return conntrackScanner, workloadRemoveChan
}

func conntrackMapSizeFromFile() (int, error) {
	filename := "/var/lib/calico/bpf_ct_map_size"
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return zero.
			log.Infof("File %s does not exist", filename)
			return 0, nil
		}
		log.WithError(err).Errorf("Failed to read %s", filename)
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}
