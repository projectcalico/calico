//go:build !windows

// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"path"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
	k8sv1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/felix/bpf"
	bpfarp "github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/filter"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/legacy"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/qos"
	"github.com/projectcalico/calico/felix/bpf/tc"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/bpf/xdp"
	"github.com/projectcalico/calico/felix/cachingmap"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ethtool"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	logutilslc "github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	bpfEPManagerHealthName = "BPFEndpointManager"
)

var (
	bpfEndpointsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_dataplane_endpoints",
		Help: "Number of BPF endpoints managed in the dataplane.",
	})
	bpfDirtyEndpointsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_dirty_dataplane_endpoints",
		Help: "Number of BPF endpoints managed in the dataplane that are left dirty after a failure.",
	})
	bpfHappyEndpointsGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_bpf_happy_dataplane_endpoints",
		Help: "Number of BPF endpoints that are successfully programmed.",
	})
	errApplyingPolicy = errors.New("error applying policy")
)

var (
	jumpMapV4PolicyKey = make([]byte, 4)
	jumpMapV6PolicyKey = make([]byte, 4)
)

type XDPMode int

const (
	XDPModeAll XDPMode = iota
	XDPModeOnly
	XDPModeNone
)

func init() {
	prometheus.MustRegister(bpfEndpointsGauge)
	prometheus.MustRegister(bpfDirtyEndpointsGauge)
	prometheus.MustRegister(bpfHappyEndpointsGauge)

	binary.LittleEndian.PutUint32(jumpMapV4PolicyKey, uint32(tcdefs.ProgIndexPolicy))
	binary.LittleEndian.PutUint32(jumpMapV6PolicyKey, uint32(tcdefs.ProgIndexPolicy))
}

type IfaceType int32

const (
	IfaceTypeData IfaceType = iota
	IfaceTypeWireguard
	IfaceTypeIPIP
	IfaceTypeVXLAN
	IfaceTypeL3
	IfaceTypeBond
	IfaceTypeBondSlave
	IfaceTypeUnknown
)

type attachPoint interface {
	IfaceName() string
	IfaceIndex() int
	HookName() hook.Hook
	AttachProgram() error
	DetachProgram() error
	Log() *logrus.Entry
	LogVal() string
	PolicyJmp(proto.IPVersion) int
}

type attachPointWithPolicyJumps interface {
	attachPoint
	PolicyAllowJumpIdx(int) int
	PolicyDenyJumpIdx(int) int
}

type fileDescriptor interface {
	FD() uint32
	Close() error
}

type bpfDataplane interface {
	ensureStarted()
	ensureProgramAttached(attachPoint) error
	ensureProgramLoaded(ap attachPoint, ipFamily proto.IPVersion) error
	ensureNoProgram(attachPoint) error
	ensureQdisc(iface string) (bool, error)
	ensureBPFDevices() error
	configureBPFDevices() error
	updatePolicyProgram(rules polprog.Rules, polDir string, ap attachPoint, ipFamily proto.IPVersion) error
	removePolicyProgram(ap attachPoint, ipFamily proto.IPVersion) error
	setAcceptLocal(iface string, val bool) error
	setRPFilter(iface string, val int) error
	setRoute(ip.CIDR)
	delRoute(ip.CIDR)
	ruleMatchID(dir rules.RuleDir, action string, owner rules.RuleOwnerType, idx int, id types.IDMaker) polprog.RuleMatchID
	loadDefaultPolicies(hk hook.Hook) error
	loadTCLogFilter(ap *tc.AttachPoint) (fileDescriptor, int, error)
	interfaceByIndex(int) (*net.Interface, error)
	queryClassifier(string, string) bool
	getIfaceLink(string) (netlink.Link, error)
}

type hasLoadPolicyProgram interface {
	loadPolicyProgram(
		progName string,
		ipFamily proto.IPVersion,
		rules polprog.Rules,
		staticProgsMap maps.Map,
		polProgsMap maps.Map,
		attachType uint32,
		opts ...polprog.Option,
	) ([]fileDescriptor, []asm.Insns, error)
}

type bpfInterface struct {
	// info contains the information about the interface sent to us from external sources. For example,
	// the ID of the controlling workload interface and our current expectation of its "oper state".
	// When the info changes, we mark the interface dirty and refresh its dataplane state.
	info bpfInterfaceInfo
	// dpState contains the dataplane state that we've derived locally.  It caches the result of updating
	// the interface (so changes to dpState don't cause the interface to be marked dirty).
	dpState bpfInterfaceState
}

func (i *bpfInterfaceState) clearJumps() {
	i.v4.clearJumps()
	i.v6.clearJumps()
	i.filterIdx = [hook.Count]int{-1, -1, -1}
}

var zeroIface bpfInterface = func() bpfInterface {
	var i bpfInterface
	i.dpState.clearJumps()
	return i
}()

type bpfIfaceNode struct {
	name        string
	index       int
	masterIndex int
	parentIface *bpfIfaceNode
	children    map[int]*bpfIfaceNode
}

type bpfIfaceTrees map[int]*bpfIfaceNode

type bpfInterfaceInfo struct {
	ifIndex       int
	isUP          bool
	endpointID    *types.WorkloadEndpointID
	ifaceType     IfaceType
	masterIfIndex int
}

func (i bpfInterfaceInfo) ifaceIsUp() bool {
	return i.isUP
}

type ifaceReadiness int

const (
	ifaceNotReady ifaceReadiness = iota
	ifaceIsReady
	// We know it was ready at some point in time and we
	// assume it still is, but we need to reassure ourselves.
	ifaceIsReadyNotAssured
)

type bpfInterfaceState struct {
	v4          bpfInterfaceJumpIndices
	v6          bpfInterfaceJumpIndices
	filterIdx   [hook.Count]int
	v4Readiness ifaceReadiness
	v6Readiness ifaceReadiness
}

type bpfInterfaceJumpIndices struct {
	policyIdx [hook.Count]int
}

func (d *bpfInterfaceJumpIndices) clearJumps() {
	d.policyIdx = [hook.Count]int{-1, -1, -1}
}

type hostNetworkedNATMode int

const (
	hostNetworkedNATDisabled = iota
	hostNetworkedNATEnabled
	hostNetworkedNATUDPOnly
)

type bpfEndpointManager struct {
	initAttaches      map[string]bpf.EPAttachInfo
	initUnknownIfaces set.Set[string]

	// Main store of information about interfaces; indexed on interface name.
	ifacesLock  sync.Mutex
	nameToIface map[string]bpfInterface

	allWEPs        map[types.WorkloadEndpointID]*proto.WorkloadEndpoint
	happyWEPs      map[types.WorkloadEndpointID]*proto.WorkloadEndpoint
	happyWEPsDirty bool
	policies       map[types.PolicyID]*proto.Policy
	profiles       map[types.ProfileID]*proto.Profile

	// Indexes
	policiesToWorkloads map[types.PolicyID]set.Set[any]  /* FIXME types.WorkloadEndpointID or string (for a HEP) */
	profilesToWorkloads map[types.ProfileID]set.Set[any] /* FIXME types.WorkloadEndpointID or string (for a HEP) */

	dirtyIfaceNames set.Set[string]

	logFilters              map[string]string
	bpfLogLevel             string
	hostname                string
	dataIfaceRegex          *regexp.Regexp
	l3IfaceRegex            *regexp.Regexp
	workloadIfaceRegex      *regexp.Regexp
	epToHostAction          string
	vxlanMTU                int
	vxlanPort               uint16
	wgPort                  uint16
	wg6Port                 uint16
	dsrEnabled              bool
	dsrOptoutCidrs          bool
	bpfExtToServiceConnmark int
	psnatPorts              numorstring.Port
	commonMaps              *bpfmap.CommonMaps
	ifStateMap              *cachingmap.CachingMap[ifstate.Key, ifstate.Value]
	removeOldJumps          bool
	legacyCleanUp           bool
	hostIfaceTrees          bpfIfaceTrees

	jumpMapAllocIngress *jumpMapAlloc
	jumpMapAllocEgress  *jumpMapAlloc
	xdpJumpMapAlloc     *jumpMapAlloc
	policyTcAllowFDs    [2]bpf.ProgFD
	policyTcDenyFDs     [2]bpf.ProgFD

	ruleRenderer bpfAllowChainRenderer

	startupOnce   sync.Once
	copyDeltaOnce sync.Once

	// onStillAlive is called from loops to reset the watchdog.
	onStillAlive func()

	loadPolicyProgramFn func(
		progName string,
		ipFamily proto.IPVersion,
		rules polprog.Rules,
		staticProgsMap maps.Map,
		polProgsMap maps.Map,
		attachType uint32,
		opts ...polprog.Option,
	) ([]fileDescriptor, []asm.Insns, error)
	updatePolicyProgramFn func(rules polprog.Rules, polDir string, ap attachPoint, ipFamily proto.IPVersion) error

	// HEP processing.
	hostIfaceToEpMap     map[string]*proto.HostEndpoint
	wildcardHostEndpoint *proto.HostEndpoint
	wildcardExists       bool

	// UT-able BPF dataplane interface.
	dp bpfDataplane

	opReporter logutils.OpRecorder

	// XDP
	xdpModes []bpf.XDPMode

	// IPv6 Support
	ipv6Enabled bool

	// Detected features
	features *environment.Features

	// RPF mode
	rpfEnforceOption string

	// BPF Disable GRO ifaces map
	bpfDisableGROForIfaces *regexp.Regexp

	// Service routes
	hostNetworkedNATMode hostNetworkedNATMode

	bpfPolicyDebugEnabled  bool
	bpfRedirectToPeer      string
	bpfAttachType          apiv3.BPFAttachOption
	policyTrampolineStride atomic.Int32

	routeTableV4     *routetable.ClassView
	routeTableV6     *routetable.ClassView
	services         map[serviceKey][]ip.CIDR
	dirtyServices    set.Set[serviceKey]
	natExcludedCIDRs *ip.CIDRTrie
	profiling        string

	// Maps for policy rule counters
	polNameToMatchIDs map[string]set.Set[polprog.RuleMatchID]
	dirtyRules        set.Set[polprog.RuleMatchID]

	natInIdx    int
	natOutIdx   int
	bpfIfaceMTU int

	overlayTunnelID uint32

	natOutgoingExclusions string

	// Flow logs related fields.
	lookupsCache *calc.LookupsCache

	v4 *bpfEndpointManagerDataplane
	v6 *bpfEndpointManagerDataplane

	healthAggregator     *health.HealthAggregator
	updateRateLimitedLog *logutilslc.RateLimitedLogger

	QoSMap        maps.MapWithUpdateWithFlags
	maglevLUTSize int
}

type bpfEndpointManagerDataplane struct {
	*bpfmap.IPMaps
	ipFamily proto.IPVersion
	hostIP   net.IP
	mgr      *bpfEndpointManager

	ifaceToIpMap map[string]net.IP

	// IP of the tunnel / overlay device
	tunnelIP            net.IP
	iptablesFilterTable Table
	ipSetIDAlloc        *idalloc.IDAllocator
}

type serviceKey struct {
	name      string
	namespace string
}

type bpfAllowChainRenderer interface {
	WorkloadInterfaceAllowChains(endpoints map[types.WorkloadEndpointID]*proto.WorkloadEndpoint) []*generictables.Chain
}

type ManagerWithHEPUpdate interface {
	Manager
	OnHEPUpdate(hostIfaceToEpMap map[string]*proto.HostEndpoint)
}

func NewBPFEndpointManager(
	dp bpfDataplane,
	config *Config,
	bpfmaps *bpfmap.Maps,
	workloadIfaceRegex *regexp.Regexp,
	ipSetIDAllocV4 *idalloc.IDAllocator,
	ipSetIDAllocV6 *idalloc.IDAllocator,
	iptablesRuleRenderer bpfAllowChainRenderer,
	iptablesFilterTableV4 Table,
	iptablesFilterTableV6 Table,
	livenessCallback func(),
	opReporter logutils.OpRecorder,
	mainRouteTableV4 routetable.Interface,
	mainRouteTableV6 routetable.Interface,
	lookupsCache *calc.LookupsCache,
	healthAggregator *health.HealthAggregator,
	dataplanefeatures *environment.Features,
	bpfIfaceMTU int,
) (*bpfEndpointManager, error) {
	if livenessCallback == nil {
		livenessCallback = func() {}
	}

	m := &bpfEndpointManager{
		initUnknownIfaces:       set.New[string](),
		dp:                      dp,
		allWEPs:                 map[types.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		happyWEPs:               map[types.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		happyWEPsDirty:          true,
		policies:                map[types.PolicyID]*proto.Policy{},
		profiles:                map[types.ProfileID]*proto.Profile{},
		nameToIface:             map[string]bpfInterface{},
		policiesToWorkloads:     map[types.PolicyID]set.Set[any]{},
		profilesToWorkloads:     map[types.ProfileID]set.Set[any]{},
		dirtyIfaceNames:         set.New[string](),
		hostIfaceTrees:          make(bpfIfaceTrees),
		bpfLogLevel:             config.BPFLogLevel,
		logFilters:              config.BPFLogFilters,
		hostname:                config.Hostname,
		l3IfaceRegex:            config.BPFL3IfacePattern,
		workloadIfaceRegex:      workloadIfaceRegex,
		epToHostAction:          config.RulesConfig.EndpointToHostAction,
		vxlanMTU:                config.VXLANMTU,
		vxlanPort:               uint16(config.VXLANPort),
		overlayTunnelID:         uint32(config.RulesConfig.VXLANVNI),
		wgPort:                  uint16(config.Wireguard.ListeningPort),
		wg6Port:                 uint16(config.Wireguard.ListeningPortV6),
		dsrEnabled:              config.BPFNodePortDSREnabled,
		dsrOptoutCidrs:          len(config.BPFDSROptoutCIDRs) > 0,
		bpfExtToServiceConnmark: config.BPFExtToServiceConnmark,
		psnatPorts:              config.BPFPSNATPorts,
		commonMaps:              bpfmaps.CommonMaps,
		ifStateMap: cachingmap.New[ifstate.Key, ifstate.Value](ifstate.MapParams.Name,
			maps.NewTypedMap[ifstate.Key, ifstate.Value](
				bpfmaps.CommonMaps.IfStateMap.(maps.MapWithExistsCheck), ifstate.KeyFromBytes, ifstate.ValueFromBytes,
			)),

		// Note: the allocators only allocate a fraction of the map, the
		// rest is reserved for sub-programs generated if a single program
		// would be too large.
		jumpMapAllocIngress: newJumpMapAlloc(jump.TCMaxEntryPoints),
		jumpMapAllocEgress:  newJumpMapAlloc(jump.TCMaxEntryPoints),
		xdpJumpMapAlloc:     newJumpMapAlloc(jump.XDPMaxEntryPoints),
		ruleRenderer:        iptablesRuleRenderer,
		onStillAlive:        livenessCallback,
		lookupsCache:        lookupsCache,
		hostIfaceToEpMap:    map[string]*proto.HostEndpoint{},
		opReporter:          opReporter,
		// ipv6Enabled Should be set to config.Ipv6Enabled, but for now it is better
		// to set it to BPFIpv6Enabled which is a dedicated flag for development of IPv6.
		// TODO: set ipv6Enabled to config.Ipv6Enabled when IPv6 support is complete
		ipv6Enabled:            config.BPFIpv6Enabled,
		rpfEnforceOption:       config.BPFEnforceRPF,
		bpfDisableGROForIfaces: config.BPFDisableGROForIfaces,
		bpfPolicyDebugEnabled:  config.BPFPolicyDebugEnabled,
		bpfRedirectToPeer:      config.BPFRedirectToPeer,
		polNameToMatchIDs:      map[string]set.Set[polprog.RuleMatchID]{},
		dirtyRules:             set.New[polprog.RuleMatchID](),

		natOutgoingExclusions: config.RulesConfig.NATOutgoingExclusions,

		healthAggregator: healthAggregator,
		features:         dataplanefeatures,
		profiling:        config.BPFProfiling,
		bpfAttachType:    config.BPFAttachType,

		QoSMap:        bpfmaps.CommonMaps.QoSMap,
		maglevLUTSize: config.BPFMaglevLUTSize,
	}

	m.policyTrampolineStride.Store(int32(asm.TrampolineStrideDefault))

	specialInterfaces := []string{"egress.calico"}
	if config.RulesConfig.IPIPEnabled {
		specialInterfaces = append(specialInterfaces, dataplanedefs.IPIPIfaceName)
	}
	if config.RulesConfig.VXLANEnabled {
		specialInterfaces = append(specialInterfaces, dataplanedefs.VXLANIfaceNameV4)
	}
	if config.RulesConfig.VXLANEnabledV6 {
		specialInterfaces = append(specialInterfaces, dataplanedefs.VXLANIfaceNameV6)
	}
	if config.RulesConfig.WireguardEnabled {
		specialInterfaces = append(specialInterfaces, config.RulesConfig.WireguardInterfaceName)
	}
	if config.RulesConfig.WireguardEnabledV6 {
		specialInterfaces = append(specialInterfaces, config.RulesConfig.WireguardInterfaceNameV6)
	}

	if config.RulesConfig.IPIPEnabled || config.RulesConfig.WireguardEnabled || config.RulesConfig.WireguardEnabledV6 {
		m.overlayTunnelID = 1
	}

	for i, d := range specialInterfaces {
		specialInterfaces[i] = "^" + regexp.QuoteMeta(d) + "$"
	}
	exp := "(" + config.BPFDataIfacePattern.String() + "|" + strings.Join(specialInterfaces, "|") + ")"

	logrus.WithField("dataIfaceRegex", exp).Debug("final dataIfaceRegex")
	m.dataIfaceRegex = regexp.MustCompile(exp)

	if healthAggregator != nil {
		healthAggregator.RegisterReporter(bpfEPManagerHealthName, &health.HealthReport{
			Ready: true,
			Live:  false,
		}, 0)
		healthAggregator.Report(bpfEPManagerHealthName, &health.HealthReport{
			Ready:  false,
			Detail: "Not yet synced.",
		})
	}

	m.updateRateLimitedLog = logutilslc.NewRateLimitedLogger(
		logutilslc.OptInterval(30*time.Second),
		logutilslc.OptBurst(10),
	)

	// Calculate allowed XDP attachment modes.  Note, in BPF mode untracked ingress policy is
	// _only_ implemented by XDP, so we _should_ fall back to XDPGeneric if necessary in order
	// to preserve the semantics of untracked ingress policy.  (Therefore we are also saying
	// here that the GenericXDPEnabled config setting, like XDPEnabled, is only relevant when
	// BPFEnabled is false.)
	m.xdpModes = []bpf.XDPMode{
		bpf.XDPOffload,
		bpf.XDPDriver,
		bpf.XDPGeneric,
	}

	// Normally this endpoint manager uses its own dataplane implementation, but we have an
	// indirection here so that UT can simulate the dataplane and test how it's called.
	if m.dp == nil {
		m.dp = m
	}

	if config.BPFConnTimeLB == string(apiv3.BPFConnectTimeLBTCP) {
		m.hostNetworkedNATMode = hostNetworkedNATUDPOnly
	} else if config.BPFHostNetworkedNAT == string(apiv3.BPFHostNetworkedNATEnabled) {
		m.hostNetworkedNATMode = hostNetworkedNATEnabled
	}

	if m.bpfAttachType == apiv3.BPFAttachOptionTCX {
		if !tc.IsTcxSupported() {
			logrus.Infof("tcx is not supported. Falling back to tc")
			m.bpfAttachType = apiv3.BPFAttachOptionTC
		}
	}
	m.v4 = newBPFEndpointManagerDataplane(proto.IPVersion_IPV4, bpfmaps.V4, iptablesFilterTableV4, ipSetIDAllocV4, m)

	if m.ipv6Enabled {
		m.v6 = newBPFEndpointManagerDataplane(proto.IPVersion_IPV6, bpfmaps.V6, iptablesFilterTableV6, ipSetIDAllocV6, m)
	}

	if m.hostNetworkedNATMode != hostNetworkedNATDisabled {
		logrus.Infof("HostNetworkedNATMode is %d", m.hostNetworkedNATMode)
		m.routeTableV4 = routetable.NewClassView(routetable.RouteClassBPFSpecial, mainRouteTableV4)
		m.routeTableV6 = routetable.NewClassView(routetable.RouteClassBPFSpecial, mainRouteTableV6)
		m.services = make(map[serviceKey][]ip.CIDR)
		m.dirtyServices = set.New[serviceKey]()
		m.natExcludedCIDRs = ip.NewCIDRTrie()

		excludeCIDRsMatch := 1

		for _, c := range config.BPFExcludeCIDRsFromNAT {
			cidr, err := ip.CIDRFromString(c)
			if err != nil {
				logrus.WithError(err).Warnf("Bad %s CIDR to exclude from NAT", c)
			}

			if (cidr.Version() == 6) != m.ipv6Enabled {
				continue
			}

			m.natExcludedCIDRs.Update(cidr, &excludeCIDRsMatch)
		}

		// Anything else would prevent packets being accepted from the special
		// service veth. It does not create a security hole since BPF does the RPF
		// on its own.
		if m.v4 != nil {
			if err := m.dp.setRPFilter("all", 0); err != nil {
				return nil, fmt.Errorf("setting rp_filter for all: %w", err)
			}
		}

		m.bpfIfaceMTU = bpfIfaceMTU
		if err := m.dp.ensureBPFDevices(); err != nil {
			return nil, fmt.Errorf("ensure BPF devices: %w", err)
		} else {
			logrus.Infof("Created %s:%s veth pair.", dataplanedefs.BPFInDev, dataplanedefs.BPFOutDev)
		}
	}

	if m.bpfPolicyDebugEnabled {
		err := m.commonMaps.RuleCountersMap.Iter(func(k, v []byte) maps.IteratorAction {
			return maps.IterDelete
		})
		if err != nil {
			logrus.WithError(err).Warn("Failed to iterate over policy counters map")
		}
	}

	// If not running in test
	if m.dp == m {
		// Repin jump maps to a different path so that existing programs keep working
		// as if nothing has changed. We keep those maps as long as we have dirty
		// devices.
		//
		// Since we are restarting, we reload programs for all the devices, the
		// generic sets and the preables and then we can just remove the old maps.
		// We never copy from the old maps to the new ones.
		if err := m.repinJumpMaps(); err != nil {
			return nil, err
		}
		m.removeOldJumps = true
		// Make sure that we eventually clean up after previous versions.
		m.legacyCleanUp = true
	}

	m.updatePolicyProgramFn = m.dp.updatePolicyProgram

	if x, ok := m.dp.(hasLoadPolicyProgram); ok {
		m.loadPolicyProgramFn = x.loadPolicyProgram
		m.updatePolicyProgramFn = m.updatePolicyProgram
	}

	if config.BPFJITHardening == "Auto" {
		if v, err := m.getJITHardening(); err == nil && v == 2 {
			err := m.setJITHardening(1)
			if err != nil {
				logrus.WithError(err).Warn("Failed to set jit hardening to 1, continuing with 2 - performance may be degraded")
			}
		}
	}

	return m, nil
}

func newBPFEndpointManagerDataplane(
	ipFamily proto.IPVersion,
	ipMaps *bpfmap.IPMaps,
	iptablesFilterTable Table,
	ipSetIDAlloc *idalloc.IDAllocator,
	epMgr *bpfEndpointManager,
) *bpfEndpointManagerDataplane {
	return &bpfEndpointManagerDataplane{
		ipFamily:            ipFamily,
		ifaceToIpMap:        map[string]net.IP{},
		mgr:                 epMgr,
		IPMaps:              ipMaps,
		iptablesFilterTable: iptablesFilterTable,
		ipSetIDAlloc:        ipSetIDAlloc,
	}
}

var _ hasLoadPolicyProgram = (*bpfEndpointManager)(nil)

func (m *bpfEndpointManager) repinJumpMaps() error {
	oldBase := path.Join(bpfdefs.GlobalPinDir, "old_jumps")
	err := os.Mkdir(oldBase, 0o700)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("cannot create %s: %w", oldBase, err)
	}

	tmp, err := os.MkdirTemp(oldBase, "")
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("cannot create temp dir in %s: %w", oldBase, err)
	}

	mps := []maps.Map{
		m.commonMaps.XDPProgramsMap,
		m.commonMaps.XDPJumpMap,
	}

	for _, mp := range m.commonMaps.JumpMaps {
		mps = append(mps, mp)
	}
	mps = append(mps, m.commonMaps.ProgramsMaps...)
	for _, mp := range mps {
		pin := path.Join(tmp, mp.GetName())
		if err := libbpf.ObjPin(int(mp.MapFD()), pin); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("failed to repin %s to %s: %w", mp.GetName(), pin, err)
		}
	}

	for _, mp := range mps {
		if err := mp.Close(); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("failed to close %s: %w", mp.Path(), err)
		}
		if err := os.Remove(mp.Path()); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("failed to remove %s from %s: %w", mp.GetName(), mp.Path(), err)
		}
	}

	for _, mp := range mps {
		if err := mp.EnsureExists(); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("failed to recreate %s: %w", mp.Path(), err)
		}
	}

	return nil
}

// withIface handles the bookkeeping for working with a particular bpfInterface value.  It
// * creates the value if needed
// * calls the giving callback with the value so it can be edited
// * if the bpfInterface's info field changes, it marks it as dirty
// * if the bpfInterface is now empty (no info or state), it cleans it up.
func (m *bpfEndpointManager) withIface(ifaceName string, fn func(iface *bpfInterface) (forceDirty bool)) {
	iface, ok := m.nameToIface[ifaceName]
	if !ok {
		iface = zeroIface
	}
	ifaceCopy := iface
	dirty := fn(&iface)
	logCtx := logrus.WithField("name", ifaceName)

	if reflect.DeepEqual(iface, zeroIface) {
		logCtx.Debug("Interface info is now empty.")
		delete(m.nameToIface, ifaceName)
	} else {
		// Always store the result (rather than checking the dirty flag) because dirty only covers the info..
		m.nameToIface[ifaceName] = iface
	}

	dirty = dirty || iface.info != ifaceCopy.info

	if !dirty {
		return
	}

	logCtx.Debug("Marking iface dirty.")
	m.dirtyIfaceNames.Add(ifaceName)
}

func (m *bpfEndpointManager) updateHostIP(ipAddr string, ipFamily int) {
	ip, _, err := net.ParseCIDR(ipAddr)
	if err != nil {
		ip = net.ParseIP(ipAddr)
	}
	if ip != nil {
		if ipFamily == 4 {
			if m.v4.hostIP.Equal(ip) {
				return
			}
			m.v4.hostIP = ip
		} else {
			if m.v6.hostIP.Equal(ip) {
				return
			}
			m.v6.hostIP = ip
		}
		// Should be safe without the lock since there shouldn't be any active background threads
		// but taking it now makes us robust to refactoring.
		m.ifacesLock.Lock()
		for ifaceName := range m.nameToIface {
			m.withIface(ifaceName, func(iface *bpfInterface) (forceDirty bool) {
				iface.dpState.v4Readiness = ifaceNotReady
				iface.dpState.v6Readiness = ifaceNotReady
				return true
			})
		}
		m.ifacesLock.Unlock()
		// We use host IP as the source when routing service for the ctlb workaround. We
		// need to update those routes, so make them all dirty.
		for svc := range m.services {
			m.dirtyServices.Add(svc)
		}
	} else {
		logrus.Warn("Cannot parse hostip, no change applied")
	}
}

func (m *bpfEndpointManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// Updates from the dataplane:

	// Interface updates.
	case *ifaceStateUpdate:
		m.onInterfaceUpdate(msg)
	case *ifaceAddrsUpdate:
		m.onInterfaceAddrsUpdate(msg)
	// Updates from the datamodel:

	// Workloads.
	case *proto.WorkloadEndpointUpdate:
		m.onWorkloadEndpointUpdate(msg)
	case *proto.WorkloadEndpointRemove:
		m.onWorkloadEndpointRemove(msg)
	// Policies.
	case *proto.ActivePolicyUpdate:
		m.onPolicyUpdate(msg)
	case *proto.ActivePolicyRemove:
		m.onPolicyRemove(msg)
	// Profiles.
	case *proto.ActiveProfileUpdate:
		m.onProfileUpdate(msg)
	case *proto.ActiveProfileRemove:
		m.onProfileRemove(msg)

	case *proto.HostMetadataUpdate:
		if m.v4 != nil && msg.Hostname == m.hostname {
			logrus.WithField("HostMetadataUpdate", msg).Infof("Host IP changed: %s", msg.Ipv4Addr)
			m.updateHostIP(msg.Ipv4Addr, 4)
		}
	case *proto.HostMetadataV6Update:
		if m.v6 != nil && msg.Hostname == m.hostname {
			logrus.WithField("HostMetadataV6Update", msg).Infof("Host IPv6 changed: %s", msg.Ipv6Addr)
			m.updateHostIP(msg.Ipv6Addr, 6)
		}
	case *proto.HostMetadataV4V6Update:
		if msg.Hostname != m.hostname {
			break
		}
		if m.v4 != nil {
			logrus.WithField("HostMetadataV4V6Update", msg).Infof("Host IP changed: %s", msg.Ipv4Addr)
			m.updateHostIP(msg.Ipv4Addr, 4)
		}
		if m.v6 != nil {
			logrus.WithField("HostMetadataV4V6Update", msg).Infof("Host IPv6 changed: %s", msg.Ipv6Addr)
			m.updateHostIP(msg.Ipv6Addr, 6)
		}
	case *proto.ServiceUpdate:
		m.onServiceUpdate(msg)
	case *proto.ServiceRemove:
		m.onServiceRemove(msg)
	case *proto.RouteUpdate:
		m.onRouteUpdate(msg)
	}
}

func (m *bpfEndpointManager) onRouteUpdate(update *proto.RouteUpdate) {
	if update.Types&proto.RouteType_LOCAL_TUNNEL == proto.RouteType_LOCAL_TUNNEL {
		ip, _, err := net.ParseCIDR(update.Dst)
		if err != nil {
			logrus.WithField("local tunnel cidr", update.Dst).WithError(err).Warn("not parsable")
			return
		}
		if m.v6 != nil {
			if ip.To4() == nil {
				m.v6.tunnelIP = ip
			}
		}
		if m.v4 != nil {
			if ip.To4() != nil {
				m.v4.tunnelIP = ip
			}
		}
		logrus.WithField("ip", update.Dst).Info("host tunnel")
		m.dirtyIfaceNames.Add(dataplanedefs.BPFOutDev)
	}
}

func (m *bpfEndpointManager) onInterfaceAddrsUpdate(update *ifaceAddrsUpdate) {
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	var v6AddrsUpdate, v4AddrsUpdate bool
	if m.v4 != nil {
		v4AddrsUpdate = m.v4.updateIfaceIP(update)
	}
	if m.v6 != nil {
		v6AddrsUpdate = m.v6.updateIfaceIP(update)
	}
	if v4AddrsUpdate || v6AddrsUpdate {
		m.dirtyIfaceNames.Add(update.Name)
	}
}

func (d *bpfEndpointManagerDataplane) updateIfaceIP(update *ifaceAddrsUpdate) bool {
	var ipAddrs []net.IP
	isDirty := false
	if update.Addrs != nil && update.Addrs.Len() > 0 {
		logrus.Debugf("Interface %+v received address update %+v", update.Name, update.Addrs)
		for item := range update.Addrs.All() {
			ip := net.ParseIP(item)
			if d.ipFamily == proto.IPVersion_IPV6 {
				if ip.To4() == nil && !ip.IsLinkLocalUnicast() {
					ipAddrs = append(ipAddrs, ip)
				}
			} else if ip.To4() != nil {
				ipAddrs = append(ipAddrs, ip)
			}
		}
		sort.Slice(ipAddrs, func(i, j int) bool {
			return bytes.Compare(ipAddrs[i], ipAddrs[j]) < 0
		})
		if len(ipAddrs) > 0 {
			ip, ok := d.ifaceToIpMap[update.Name]
			if !ok || !ip.Equal(ipAddrs[0]) {
				d.ifaceToIpMap[update.Name] = ipAddrs[0]
				isDirty = true
			}
		}
	} else {
		_, ok := d.ifaceToIpMap[update.Name]
		if ok {
			delete(d.ifaceToIpMap, update.Name)
			isDirty = true
		}
	}
	return isDirty
}

func (m *bpfEndpointManager) reclaimPolicyIdx(name string, ipFamily int, iface *bpfInterface) {
	idx := &iface.dpState.v4
	if ipFamily == 6 {
		idx = &iface.dpState.v6
	}
	for _, attachHook := range []hook.Hook{hook.XDP, hook.Ingress, hook.Egress} {
		if err := m.jumpMapDelete(attachHook, idx.policyIdx[attachHook]); err != nil {
			logrus.WithError(err).Warn("Policy program may leak.")
		}
		if attachHook != hook.XDP {
			if attachHook == hook.Ingress {
				if err := m.jumpMapAllocIngress.Put(idx.policyIdx[attachHook], name); err != nil {
					logrus.WithError(err).Errorf("Policy family %d, hook %s", ipFamily, attachHook)
				}
			} else {
				if err := m.jumpMapAllocEgress.Put(idx.policyIdx[attachHook], name); err != nil {
					logrus.WithError(err).Errorf("Policy family %d, hook %s", ipFamily, attachHook)
				}
			}
		} else {
			if err := m.xdpJumpMapAlloc.Put(idx.policyIdx[attachHook], name); err != nil {
				logrus.WithError(err).Error(attachHook.String())
			}
		}
	}
}

func (m *bpfEndpointManager) reclaimFilterIdx(name string, iface *bpfInterface) {
	for _, attachHook := range []hook.Hook{hook.Ingress, hook.Egress} {
		if err := m.jumpMapDelete(attachHook, iface.dpState.filterIdx[attachHook]); err != nil {
			logrus.WithError(err).Warn("Filter program may leak.")
		}
		if attachHook == hook.Ingress {
			if err := m.jumpMapAllocIngress.Put(iface.dpState.filterIdx[attachHook], name); err != nil {
				logrus.WithError(err).Errorf("Filter hook %s", attachHook)
			}
		} else {
			if err := m.jumpMapAllocEgress.Put(iface.dpState.filterIdx[attachHook], name); err != nil {
				logrus.WithError(err).Errorf("Filter hook %s", attachHook)
			}
		}
		iface.dpState.filterIdx[attachHook] = -1
	}
}

func (m *bpfEndpointManager) getIfTypeFlags(name string, ifaceType IfaceType) uint32 {
	flags := uint32(0)
	if m.isWorkloadIface(name) {
		flags |= ifstate.FlgWEP
	} else {
		switch ifaceType {
		case IfaceTypeData:
			flags |= ifstate.FlgHEP
		case IfaceTypeBond:
			flags |= ifstate.FlgBond
		case IfaceTypeBondSlave:
			flags |= ifstate.FlgBondSlave
		case IfaceTypeL3:
			flags |= ifstate.FlgL3
		case IfaceTypeWireguard:
			flags |= ifstate.FlgWireguard
		case IfaceTypeVXLAN:
			flags |= ifstate.FlgVxlan
		case IfaceTypeIPIP:
			flags |= ifstate.FlgIPIP
		}
	}
	return flags
}

func (m *bpfEndpointManager) addIgnoredHostIfaceToIfState(name string, ifIndex int) {
	k := ifstate.NewKey(uint32(ifIndex))
	flags := ifstate.FlgNotManaged
	v := ifstate.NewValue(flags, name, -1, -1, -1, -1, -1, -1, -1, -1)
	m.ifStateMap.Desired().Set(k, v)
}

func (m *bpfEndpointManager) deleteIgnoredHostIfaceFromIfState(ifIndex int) {
	k := ifstate.NewKey(uint32(ifIndex))
	m.ifStateMap.Desired().Delete(k)
}

func (m *bpfEndpointManager) updateIfaceStateMap(name string, iface *bpfInterface) {
	k := ifstate.NewKey(uint32(iface.info.ifIndex))
	if iface.info.ifaceIsUp() {
		flags := m.getIfTypeFlags(name, iface.info.ifaceType)
		if iface.dpState.v4Readiness != ifaceNotReady {
			flags |= ifstate.FlgIPv4Ready
		}
		if iface.dpState.v6Readiness != ifaceNotReady {
			flags |= ifstate.FlgIPv6Ready
		}

		v := ifstate.NewValue(flags, name,
			iface.dpState.v4.policyIdx[hook.XDP],
			iface.dpState.v4.policyIdx[hook.Ingress],
			iface.dpState.v4.policyIdx[hook.Egress],
			iface.dpState.v6.policyIdx[hook.XDP],
			iface.dpState.v6.policyIdx[hook.Ingress],
			iface.dpState.v6.policyIdx[hook.Egress],
			iface.dpState.filterIdx[hook.Ingress],
			iface.dpState.filterIdx[hook.Egress],
		)
		m.ifStateMap.Desired().Set(k, v)
	} else {
		if m.v4 != nil {
			m.reclaimPolicyIdx(name, 4, iface)
		}
		if m.v6 != nil {
			m.reclaimPolicyIdx(name, 6, iface)
		}
		m.reclaimFilterIdx(name, iface)
		m.ifStateMap.Desired().Delete(k)
		iface.dpState.clearJumps()
	}
}

func (m *bpfEndpointManager) deleteIfaceCounters(name string, ifindex int) {
	err := m.commonMaps.CountersMap.Delete(counters.NewKey(ifindex, hook.Ingress).AsBytes())
	if err != nil && !maps.IsNotExists(err) {
		logrus.WithError(err).Warnf("Failed to remove  ingress counters for dev %s ifindex %d.", name, ifindex)
	}
	err = m.commonMaps.CountersMap.Delete(counters.NewKey(ifindex, hook.Egress).AsBytes())
	if err != nil && !maps.IsNotExists(err) {
		logrus.WithError(err).Warnf("Failed to remove  egress counters for dev %s ifindex %d.", name, ifindex)
	}
	err = m.commonMaps.CountersMap.Delete(counters.NewKey(ifindex, hook.XDP).AsBytes())
	if err != nil && !maps.IsNotExists(err) {
		logrus.WithError(err).Warnf("Failed to remove  XDP counters for dev %s ifindex %d.", name, ifindex)
	}
	logrus.Debugf("Deleted counters for dev %s ifindex %d.", name, ifindex)
}

func (m *bpfEndpointManager) cleanupOldXDPAttach(iface string) error {
	ap := xdp.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			Iface: iface,
			Hook:  hook.XDP,
		},
		Modes: []bpf.XDPMode{bpf.XDPGeneric, bpf.XDPDriver, bpf.XDPOffload},
	}
	if err := m.dp.ensureNoProgram(&ap); err != nil {
		return fmt.Errorf("xdp: %w", err)
	}
	return nil
}

func cleanupTcxPins(iface string) {
	for _, attachHook := range []hook.Hook{hook.Ingress, hook.Egress} {
		ap := tc.AttachPoint{
			AttachPoint: bpf.AttachPoint{
				Iface: iface,
				Hook:  attachHook,
			},
		}
		os.Remove(ap.ProgPinPath())
	}
}

func (m *bpfEndpointManager) cleanupOldTcAttach(iface string) error {
	ap := tc.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			Iface: iface,
		},
	}

	for _, attachHook := range []hook.Hook{hook.Ingress, hook.Egress} {
		ap.Hook = attachHook
		if err := m.dp.ensureNoProgram(&ap); err != nil {
			return fmt.Errorf("tc %s: %w", attachHook, err)
		}
	}
	return nil
}

func (m *bpfEndpointManager) cleanupOldAttach(iface string, ai bpf.EPAttachInfo) error {
	if ai.XDP != 0 {
		return m.cleanupOldXDPAttach(iface)
	}
	if ai.Ingress != 0 || ai.Egress != 0 {
		return m.cleanupOldTcAttach(iface)
	}

	return nil
}

func (m *bpfEndpointManager) onInterfaceUpdate(update *ifaceStateUpdate) {
	logrus.Debugf("Interface update for %v, state %v", update.Name, update.State)

	if !m.isDataIface(update.Name) && !m.isWorkloadIface(update.Name) && !m.isL3Iface(update.Name) {
		if update.State == ifacemonitor.StateUp {
			if ai, ok := m.initAttaches[update.Name]; ok {
				if err := m.cleanupOldAttach(update.Name, ai); err != nil {
					logrus.WithError(err).Warnf("Failed to detach old programs from now unused device '%s'", update.Name)
				} else {
					delete(m.initAttaches, update.Name)
				}
			}
			if update.Name == dataplanedefs.BPFInDev {
				m.ifacesLock.Lock()
				if err := m.reconcileBPFDevices(dataplanedefs.BPFInDev); err != nil {
					logrus.WithError(err).Fatal("Failed to configure BPF devices")
				}
				m.ifacesLock.Unlock()
			}
		}

		// Add host interface not managed by calico to the ifstate map,
		// so that packets from workload are not dropped.
		if update.Name != dataplanedefs.BPFInDev {
			if update.State == ifacemonitor.StateNotPresent {
				m.deleteIgnoredHostIfaceFromIfState(update.Index)
			} else {
				m.addIgnoredHostIfaceToIfState(update.Name, update.Index)
			}
		}

		if m.initUnknownIfaces != nil {
			m.initUnknownIfaces.Add(update.Name)
		}
		logrus.WithField("update", update).Debug("Ignoring interface that's neither data nor workload nor L3.")
		return
	}

	if update.State == ifacemonitor.StateNotPresent && m.bpfAttachType == apiv3.BPFAttachOptionTCX {
		// Delete the tcx pins if the interface is gone.
		// Check if the interface still exists, as we might get events out of order.
		_, err := m.dp.getIfaceLink(update.Name)
		if err != nil {
			cleanupTcxPins(update.Name)
		}
	}
	// Should be safe without the lock since there shouldn't be any active background threads
	// but taking it now makes us robust to refactoring.
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()
	masterIfIndex := 0
	curIfaceType := IfaceTypeUnknown
	if !m.isWorkloadIface(update.Name) {
		if update.State != ifacemonitor.StateNotPresent {
			// Determine the type of interface.
			// These include host, bond, slave, ipip, wireguard, l3.
			// update the ifaceType, master ifindex if bond slave.
			link, err := m.dp.getIfaceLink(update.Name)
			if err != nil {
				logrus.Errorf("Failed to get interface information via netlink '%s'", update.Name)
				curIfaceType = IfaceTypeL3
				if m.isDataIface(update.Name) {
					curIfaceType = IfaceTypeData
				}
			} else {
				m.hostIfaceTrees.addIface(link)
				curIfaceType = m.getIfaceTypeFromLink(link)
				masterIfIndex = link.Attrs().MasterIndex
				// Mark all the interfaces in the tree dirty, so that program can be attached/removed.
				m.dirtyIfaceNames.AddSet(m.getAllIfacesInTree(update.Name))
			}
		} else {
			allIfaces := m.getAllIfacesInTree(update.Name)
			// Mark all the interfaces in the tree dirty, so that program can be attached/removed.
			allIfaces.Discard(update.Name)
			m.hostIfaceTrees.deleteIface(update.Name)
			m.dirtyIfaceNames.AddSet(allIfaces)
		}
	}

	m.withIface(update.Name, func(iface *bpfInterface) (forceDirty bool) {
		ifaceIsUp := update.State == ifacemonitor.StateUp
		iface.info.masterIfIndex = masterIfIndex
		iface.info.ifaceType = curIfaceType
		// Note, only need to handle the mapping and unmapping of the host-* endpoint here.
		// For specific host endpoints OnHEPUpdate doesn't depend on iface state, and has
		// already stored and mapped as needed.
		if ifaceIsUp {
			delete(m.initAttaches, update.Name)
			// We require host interfaces to be in non-strict RPF mode so that
			// packets can return straight to host for services bypassing CTLB.
			switch update.Name {
			case dataplanedefs.BPFOutDev:
				if err := m.reconcileBPFDevices(update.Name); err != nil {
					logrus.WithError(err).Fatal("Failed to configure BPF devices")
				}
			default:
				if m.v4 != nil {
					if err := m.dp.setRPFilter(update.Name, 2); err != nil {
						logrus.WithError(err).Warnf("Failed to set rp_filter for %s.", update.Name)
					}
				}
			}

			if m.v4 != nil {
				_ = m.dp.setAcceptLocal(update.Name, true)
			}

			if _, hostEpConfigured := m.hostIfaceToEpMap[update.Name]; m.wildcardExists && !hostEpConfigured {
				logrus.Debugf("Map host-* endpoint for %v", update.Name)
				m.addHEPToIndexes(update.Name, m.wildcardHostEndpoint)
				m.hostIfaceToEpMap[update.Name] = m.wildcardHostEndpoint
			}
			iface.info.ifIndex = update.Index
			iface.info.isUP = true
			m.updateIfaceStateMap(update.Name, iface)
		} else {
			if m.wildcardExists && reflect.DeepEqual(m.hostIfaceToEpMap[update.Name], m.wildcardHostEndpoint) {
				logrus.Debugf("Unmap host-* endpoint for %v", update.Name)
				m.removeHEPFromIndexes(update.Name, m.wildcardHostEndpoint)
				delete(m.hostIfaceToEpMap, update.Name)
			}
			m.deleteIfaceCounters(update.Name, iface.info.ifIndex)
			iface.dpState.v4Readiness = ifaceNotReady
			iface.dpState.v6Readiness = ifaceNotReady
			iface.info.isUP = false
			m.updateIfaceStateMap(update.Name, iface)
			iface.info.ifIndex = 0
			iface.info.masterIfIndex = 0
			iface.info.ifaceType = 0
		}
		return true // Force interface to be marked dirty in case we missed a transition during a resync.
	})
}

// onWorkloadEndpointUpdate adds/updates the workload in the cache along with the index from active policy to
// workloads using that policy.
func (m *bpfEndpointManager) onWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate) {
	logrus.WithField("wep", msg.Endpoint).Debug("Workload endpoint update")
	wlID := types.ProtoToWorkloadEndpointID(msg.GetId())
	oldWEP := m.allWEPs[wlID]
	m.removeWEPFromIndexes(wlID, oldWEP)

	wl := msg.Endpoint
	m.allWEPs[wlID] = wl
	m.addWEPToIndexes(wlID, wl)
	m.withIface(wl.Name, func(iface *bpfInterface) bool {
		iface.info.endpointID = &wlID
		return true // Force interface to be marked dirty in case policies changed.
	})
}

// onWorkloadEndpointRemove removes the workload from the cache and the index, which maps from policy to workload.
func (m *bpfEndpointManager) onWorkloadEndpointRemove(msg *proto.WorkloadEndpointRemove) {
	wlID := types.ProtoToWorkloadEndpointID(msg.GetId())
	logrus.WithField("id", wlID).Debug("Workload endpoint removed")
	oldWEP := m.allWEPs[wlID]
	m.removeWEPFromIndexes(wlID, oldWEP)
	delete(m.allWEPs, wlID)

	if m.happyWEPs[wlID] != nil {
		delete(m.happyWEPs, wlID)
		m.happyWEPsDirty = true
	}

	m.withIface(oldWEP.Name, func(iface *bpfInterface) bool {
		iface.info.endpointID = nil
		return false
	})
	// Remove policy debug info if any
	m.removeIfaceAllPolicyDebugInfo(oldWEP.Name)
}

// onPolicyUpdate stores the policy in the cache and marks any endpoints using it dirty.
func (m *bpfEndpointManager) onPolicyUpdate(msg *proto.ActivePolicyUpdate) {
	polID := types.ProtoToPolicyID(msg.GetId())
	logrus.WithField("id", polID).Debug("Policy update")
	m.policies[polID] = msg.Policy
	// Note, polID includes the tier name as well as the policy name.
	m.markEndpointsDirty(m.policiesToWorkloads[polID], "policy")
	if m.bpfPolicyDebugEnabled {
		m.updatePolicyCache(polID, m.policies[polID].InboundRules, m.policies[polID].OutboundRules)
	}
}

// onPolicyRemove removes the policy from the cache and marks any endpoints using it dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onPolicyRemove(msg *proto.ActivePolicyRemove) {
	polID := types.ProtoToPolicyID(msg.GetId())
	logrus.WithField("id", polID).Debug("Policy removed")
	// Note, polID includes the tier name as well as the policy name.
	m.markEndpointsDirty(m.policiesToWorkloads[polID], "policy")
	delete(m.policies, polID)
	delete(m.policiesToWorkloads, polID)
	if m.bpfPolicyDebugEnabled {
		m.dirtyRules.AddSet(m.polNameToMatchIDs[polID.ID()])
		delete(m.polNameToMatchIDs, polID.ID())
	}
}

// onProfileUpdate stores the profile in the cache and marks any endpoints that use it as dirty.
func (m *bpfEndpointManager) onProfileUpdate(msg *proto.ActiveProfileUpdate) {
	profID := types.ProtoToProfileID(msg.GetId())
	logrus.WithField("id", profID).Debug("Profile update")
	m.profiles[profID] = msg.Profile
	m.markEndpointsDirty(m.profilesToWorkloads[profID], "profile")
	if m.bpfPolicyDebugEnabled {
		m.updatePolicyCacheProfile(profID, m.profiles[profID].InboundRules, m.profiles[profID].OutboundRules)
	}
}

// onProfileRemove removes the profile from the cache and marks any endpoints that were using it as dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onProfileRemove(msg *proto.ActiveProfileRemove) {
	profID := types.ProtoToProfileID(msg.GetId())
	logrus.WithField("id", profID).Debug("Profile removed")
	m.markEndpointsDirty(m.profilesToWorkloads[profID], "profile")
	delete(m.profiles, profID)
	delete(m.profilesToWorkloads, profID)
	if m.bpfPolicyDebugEnabled {
		m.dirtyRules.AddSet(m.polNameToMatchIDs[profID.ID()])
		delete(m.polNameToMatchIDs, profID.ID())
	}
}

func (m *bpfEndpointManager) removeDirtyPolicies() {
	b := make([]byte, 8)
	for item := range m.dirtyRules.All() {
		binary.LittleEndian.PutUint64(b, item)
		logrus.WithField("ruleId", item).Debug("deleting entry")
		err := m.commonMaps.RuleCountersMap.Delete(b)
		if err != nil && !maps.IsNotExists(err) {
			logrus.WithField("ruleId", item).Info("error deleting entry")
		}

		m.dirtyRules.Discard(item)
	}
}

func (m *bpfEndpointManager) markEndpointsDirty(ids set.Set[any], kind string) {
	if ids == nil {
		// Hear about the policy/profile before the endpoint.
		return
	}
	for item := range ids.All() {
		switch id := item.(type) {
		case types.WorkloadEndpointID:
			m.markExistingWEPDirty(id, kind)
		case string:
			if id == allInterfaces {
				for ifaceName := range m.nameToIface {
					if m.isWorkloadIface(ifaceName) {
						logrus.Debugf("Mark WEP iface dirty, for host-* endpoint %v change", kind)
						m.dirtyIfaceNames.Add(ifaceName)
					}
				}
			} else {
				logrus.Debugf("Mark host iface dirty %v, for host %v change", id, kind)
				m.dirtyIfaceNames.Add(id)
				m.dirtyIfaceNames.AddAll(m.hostIfaceTrees.getPhyDevices(id))
			}
		}
	}
}

func (m *bpfEndpointManager) markExistingWEPDirty(wlID types.WorkloadEndpointID, mapping string) {
	wep := m.allWEPs[wlID]
	if wep == nil {
		logrus.WithField("wlID", wlID).Panicf(
			"BUG: %s mapping points to unknown workload.", mapping)
	} else {
		m.dirtyIfaceNames.Add(wep.Name)
	}
}

func jumpMapDeleteEntry(m maps.Map, idx, stride int) error {
	for subProg := 0; subProg < jump.MaxSubPrograms; subProg++ {
		if err := m.Delete(jump.Key(polprog.SubProgramJumpIdx(idx, subProg, stride))); err != nil {
			if maps.IsNotExists(err) {
				logrus.WithError(err).WithField("idx", idx).Debug(
					"Policy program already gone from map.")
				return nil
			} else {
				logrus.WithError(err).Warn("Failed to delete policy program from map; policy program may leak.")
				return err
			}
		}
	}

	return nil
}

func (m *bpfEndpointManager) interfaceByIndex(ifindex int) (*net.Interface, error) {
	return net.InterfaceByIndex(ifindex)
}

func (m *bpfEndpointManager) syncIfStateMap() {
	tcSeenIndexes := set.New[int]()
	xdpSeenIndexes := set.New[int]()

	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	m.ifStateMap.Dataplane().Iter(func(k ifstate.Key, v ifstate.Value) {
		ifindex := int(k.IfIndex())
		netiface, err := m.dp.interfaceByIndex(ifindex)
		if err != nil {
			// "net" does not export the strings or err types :(
			if strings.Contains(err.Error(), "no such network interface") {
				m.ifStateMap.Desired().Delete(k)
				// Device does not exist anymore so delete all associated policies we know
				// about as we will not hear about that device again.
				for _, fn := range []func() int{
					v.XDPPolicyV4,
					v.XDPPolicyV6,
				} {
					if idx := fn(); idx != -1 {
						_ = jumpMapDeleteEntry(m.commonMaps.XDPJumpMap, idx, jump.XDPMaxEntryPoints)
					}
				}
				for _, fn := range []func() int{
					v.IngressPolicyV4,
					v.IngressPolicyV6,
					v.TcIngressFilter,
				} {
					if idx := fn(); idx != -1 {
						_ = jumpMapDeleteEntry(m.commonMaps.JumpMaps[hook.Ingress], idx, jump.TCMaxEntryPoints)
					}
				}
				for _, fn := range []func() int{
					v.EgressPolicyV4,
					v.EgressPolicyV6,
					v.TcEgressFilter,
				} {
					if idx := fn(); idx != -1 {
						_ = jumpMapDeleteEntry(m.commonMaps.JumpMaps[hook.Egress], idx, jump.TCMaxEntryPoints)
					}
				}
			} else {
				// It will get deleted by the first CompleteDeferredWork() if we
				// do not get any state update on that interface.
				logrus.WithError(err).Warnf("Failed to sync ifstate for iface %d, deferring it.", ifindex)
			}
		} else if m.isDataIface(netiface.Name) || m.isWorkloadIface(netiface.Name) || m.isL3Iface(netiface.Name) {
			// We only add iface that we still manage as configuration could have changed.

			m.ifStateMap.Desired().Set(k, v)

			m.withIface(netiface.Name, func(iface *bpfInterface) bool {
				if netiface.Flags&net.FlagUp != 0 {
					iface.info.ifIndex = netiface.Index
					iface.info.isUP = true
					if v.Flags()&ifstate.FlgIPv4Ready != 0 {
						iface.dpState.v4Readiness = ifaceIsReadyNotAssured
					}
					if v.Flags()&ifstate.FlgIPv6Ready != 0 {
						iface.dpState.v6Readiness = ifaceIsReadyNotAssured
					}
				}
				checkAndReclaimIdx := func(idx int, h hook.Hook, indexMap []int) {
					if idx < 0 {
						return
					}
					var alloc *jumpMapAlloc
					var seenIndexes set.Set[int]
					if h == hook.XDP {
						alloc = m.xdpJumpMapAlloc
						seenIndexes = xdpSeenIndexes
					} else {
						if h == hook.Ingress {
							alloc = m.jumpMapAllocIngress
						} else {
							alloc = m.jumpMapAllocEgress
						}
						seenIndexes = tcSeenIndexes
					}
					if err := alloc.Assign(idx, netiface.Name); err != nil {
						// Conflict with another program; need to alloc a new index.
						logrus.WithError(err).Error("Start of day resync found invalid jump map index, " +
							"allocate a fresh one.")
						idx = -1
					} else {
						seenIndexes.Add(idx)
					}
					indexMap[h] = idx
				}

				if m.v4 != nil {
					checkAndReclaimIdx(v.IngressPolicyV4(), hook.Ingress, iface.dpState.v4.policyIdx[:])
					checkAndReclaimIdx(v.EgressPolicyV4(), hook.Egress, iface.dpState.v4.policyIdx[:])
					if !m.isWorkloadIface(netiface.Name) {
						// We don't use XDP for WEPs so any ID we read back must be a mistake.
						checkAndReclaimIdx(v.XDPPolicyV4(), hook.XDP, iface.dpState.v4.policyIdx[:])
					}
				}
				if m.v6 != nil {
					checkAndReclaimIdx(v.IngressPolicyV6(), hook.Ingress, iface.dpState.v6.policyIdx[:])
					checkAndReclaimIdx(v.EgressPolicyV6(), hook.Egress, iface.dpState.v6.policyIdx[:])
					if !m.isWorkloadIface(netiface.Name) {
						checkAndReclaimIdx(v.XDPPolicyV6(), hook.XDP, iface.dpState.v6.policyIdx[:])
					}
				}
				checkAndReclaimIdx(v.TcIngressFilter(), hook.Ingress, iface.dpState.filterIdx[:])
				checkAndReclaimIdx(v.TcEgressFilter(), hook.Egress, iface.dpState.filterIdx[:])

				// Mark all interfaces that we knew about, that we still manage and
				// that exist as dirty. Since they exist, we either have to deal
				// with them sooner or later or they will disappear and we get
				// notified about that. Either way they won't be dirty anymore.
				//
				// The first time we see that we have no dirty ifaces, we can
				// release old jump maps because we know that all the ifaces now use
				// the new jump maps!
				return true
			})
		} else {
			// We no longer manage this device
			m.ifStateMap.Desired().Delete(k)
		}
	})
}

func (m *bpfEndpointManager) syncIfaceProperties() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("cannot list interfaces: %w", err)
	}

	// Update Generic Receive Offload [GRO] if configured.
	if m.bpfDisableGROForIfaces != nil {
		expr := m.bpfDisableGROForIfaces.String()
		if len(expr) > 0 {
			config := map[string]bool{
				ethtool.EthtoolRxGRO: false,
			}

			for _, entry := range ifaces {
				iface := entry.Name
				if m.bpfDisableGROForIfaces.MatchString(iface) {
					logrus.WithField(expr, iface).Debug("BPF Disable GRO iface match")
					err = ethtool.EthtoolChangeImpl(iface, config)
					if err == nil {
						logrus.WithField(iface, config).Debug("ethtool.Change() succeeded")
					}
				}
			}
		}
	}

	exists := set.New[int]()
	for i := range ifaces {
		exists.Add(ifaces[i].Index)
	}

	err = m.commonMaps.CountersMap.Iter(func(k, v []byte) maps.IteratorAction {
		var key counters.Key
		copy(key[:], k)

		if !exists.Contains(key.IfIndex()) {
			return maps.IterDelete
		}

		return maps.IterNone
	})
	if err != nil {
		return fmt.Errorf("iterating over counters map failed")
	}

	return nil
}

// loadDefaultPolicies loads the default allow and deny policy programs for the given hook
// and not policy direction.
func (m *bpfEndpointManager) loadDefaultPolicies(hk hook.Hook) error {
	file := path.Join(bpfdefs.ObjectDir, fmt.Sprintf("policy_default_%s.o", hk))
	obj, err := libbpf.OpenObject(file)
	if err != nil {
		return fmt.Errorf("file %s: %w", file, err)
	}

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		mapName := m.Name()
		if strings.HasPrefix(mapName, ".rodata") {
			continue
		}
		if size := maps.Size(mapName); size != 0 {
			if err := m.SetSize(size); err != nil {
				return fmt.Errorf("error resizing map %s: %w", mapName, err)
			}
		}
		if err := m.SetPinPath(path.Join(bpfdefs.GlobalPinDir, mapName)); err != nil {
			return fmt.Errorf("error pinning map %s: %w", mapName, err)
		}
	}

	if m.bpfAttachType == apiv3.BPFAttachOptionTCX {
		for p, err := obj.FirstProgram(); p != nil && err == nil; p, err = p.NextProgram() {
			attachType := libbpf.AttachTypeTcxEgress
			if hk == hook.Ingress {
				attachType = libbpf.AttachTypeTcxIngress
			}
			if err := obj.SetAttachType(p.Name(), attachType); err != nil {
				return fmt.Errorf("error setting attach type for program %s: %w", p.Name(), err)
			}
		}
	}

	if err := obj.Load(); err != nil {
		return fmt.Errorf("default policies: %w", err)
	}

	fd, err := obj.ProgramFD("calico_tc_deny")
	if err != nil {
		return fmt.Errorf("failed to load default deny policy program: %w", err)
	}
	m.policyTcDenyFDs[hk] = bpf.ProgFD(fd)

	fd, err = obj.ProgramFD("calico_tc_allow")
	if err != nil {
		return fmt.Errorf("failed to load default allow policy program: %w", err)
	}
	m.policyTcAllowFDs[hk] = bpf.ProgFD(fd)

	return nil
}

func (m *bpfEndpointManager) CompleteDeferredWork() error {
	defer func() {
		logrus.Debug("CompleteDeferredWork done.")
	}()

	// Do one-off initialisation.
	m.startupOnce.Do(func() {
		m.dp.ensureStarted()

		if err := m.ifStateMap.LoadCacheFromDataplane(); err != nil {
			logrus.WithError(err).Fatal("Cannot load interface state map - essential for consistent operation.")
		}

		for iface := range m.initUnknownIfaces.All() {
			if ai, ok := m.initAttaches[iface]; ok {
				if err := m.cleanupOldAttach(iface, ai); err != nil {
					logrus.WithError(err).Warnf("Failed to detach old programs from now unused device '%s'", iface)
				} else {
					delete(m.initAttaches, iface)
					m.initUnknownIfaces.Discard(iface)
				}
			}
		}

		// Makes sure that we delete entries for non-existing devices and preserve entries
		// for those that exists until we can make sure that they did (not) change.
		m.syncIfStateMap()
		logrus.Info("BPF Interface state map synced.")

		for _, hk := range []hook.Hook{hook.Ingress, hook.Egress} {
			if err := m.dp.loadDefaultPolicies(hk); err != nil {
				logrus.WithError(err).Warn("Failed to load default policies, some programs may default to DENY.")
			}
		}
		logrus.Info("Default BPF policy programs loaded.")

		m.initUnknownIfaces = nil

		if err := m.syncIfaceProperties(); err != nil {
			logrus.WithError(err).Warn("Failed to sync counters map with existing interfaces - some counters may have leaked.")
		}
		logrus.Info("BPF counters synced.")
	})

	m.applyProgramsToDirtyDataInterfaces()
	m.updateWEPsInDataplane()
	if m.bpfPolicyDebugEnabled {
		m.removeDirtyPolicies()
	}

	bpfEndpointsGauge.Set(float64(len(m.nameToIface)))
	bpfDirtyEndpointsGauge.Set(float64(m.dirtyIfaceNames.Len()))

	if m.hostNetworkedNATMode != hostNetworkedNATDisabled {
		// Update all existing IPs of dirty services
		for svc := range m.dirtyServices.All() {
			for _, ip := range m.services[svc] {
				m.dp.setRoute(ip)
			}
			m.dirtyServices.Discard(svc)
		}
	}

	if err := m.ifStateMap.ApplyAllChanges(); err != nil {
		logrus.WithError(err).Warn("Failed to write updates to ifstate BPF map.")
		m.reportHealth(false, "Failed to update interface state map.")
		return err
	}

	if m.happyWEPsDirty {
		chains := m.ruleRenderer.WorkloadInterfaceAllowChains(m.happyWEPs)
		if m.v4 != nil {
			m.v4.iptablesFilterTable.UpdateChains(chains)
		}
		if m.v6 != nil {
			m.v6.iptablesFilterTable.UpdateChains(chains)
		}
		m.happyWEPsDirty = false
	}
	bpfHappyEndpointsGauge.Set(float64(len(m.happyWEPs)))
	// Copy data from old map to the new map
	m.copyDeltaOnce.Do(func() {
		logrus.Info("Copy delta entries from old map to the new map")
		var err error
		if m.v6 != nil {
			err = m.v6.CtMap.CopyDeltaFromOldMap()
		}
		if m.v4 != nil {
			err = m.v4.CtMap.CopyDeltaFromOldMap()
		}
		if err != nil {
			logrus.WithError(err).Debugf("Failed to copy data from old conntrack map %s", err)
		}
	})

	if m.dirtyIfaceNames.Len() == 0 {
		if m.removeOldJumps {
			oldBase := path.Join(bpfdefs.GlobalPinDir, "old_jumps")
			if err := os.RemoveAll(oldBase); err != nil && os.IsNotExist(err) {
				m.reportHealth(false, "Failed to clean up old jump maps.")
				return fmt.Errorf("failed to remove %s: %w", oldBase, err)
			}
			m.removeOldJumps = false
		}
		if m.legacyCleanUp {
			legacy.CleanUpMaps()
			m.legacyCleanUp = false
		}
		m.reportHealth(true, "")
	} else {
		for iface := range m.dirtyIfaceNames.All() {
			m.updateRateLimitedLog.WithField("name", iface).Info("Interface remains dirty.")
		}
		m.reportHealth(false, "Failed to configure some interfaces.")
	}

	return nil
}

func (m *bpfEndpointManager) reportHealth(ready bool, detail string) {
	if m.healthAggregator == nil {
		return
	}
	m.healthAggregator.Report(bpfEPManagerHealthName, &health.HealthReport{
		Ready:  ready,
		Detail: detail,
	})
}

func (m *bpfEndpointManager) doApplyPolicyToDataIface(iface, masterIface string, xdpMode XDPMode) (bpfInterfaceState, error) {
	var (
		err     error
		up      bool
		ifIndex int
		state   bpfInterfaceState
	)

	m.ifacesLock.Lock()
	m.withIface(iface, func(iface *bpfInterface) bool {
		up = iface.info.ifaceIsUp()
		ifIndex = iface.info.ifIndex
		state = iface.dpState
		return false
	})
	m.ifacesLock.Unlock()
	if !up {
		logrus.WithField("iface", iface).Debug("Ignoring interface that is down")
		return state, nil
	}

	hepIface := iface
	if xdpMode != XDPModeOnly {
		_, err = m.dp.ensureQdisc(iface)
		if err != nil {
			return state, err
		}
	} else {
		hepIface = masterIface
	}

	var hepPtr *proto.HostEndpoint
	if hep, hepExists := m.hostIfaceToEpMap[hepIface]; hepExists {
		hepPtr = hep
	}

	var parallelWG sync.WaitGroup
	var ingressErr, xdpErr, err4, err6 error
	var ingressAP4, egressAP4 *tc.AttachPoint
	var ingressAP6, egressAP6 *tc.AttachPoint
	var xdpAP4, xdpAP6 *xdp.AttachPoint

	tcAttachPoint := m.calculateTCAttachPoint(iface)
	if err := m.dataIfaceStateFillJumps(tcAttachPoint, xdpMode, &state); err != nil {
		return state, err
	}
	tcAttachPoint.IfIndex = ifIndex

	xdpAttachPoint := &xdp.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			IfIndex:  ifIndex,
			Hook:     hook.XDP,
			Iface:    iface,
			LogLevel: m.bpfLogLevel,
		},
		Modes: m.xdpModes,
	}

	if m.v6 != nil {
		parallelWG.Add(1)
		go func() {
			defer parallelWG.Done()
			ingressAP6, egressAP6, xdpAP6, err6 = m.v6.applyPolicyToDataIface(iface, hepPtr, &state,
				tcAttachPoint, xdpAttachPoint, xdpMode)
		}()
	}
	if m.v4 != nil {
		ingressAP4, egressAP4, xdpAP4, err4 = m.v4.applyPolicyToDataIface(iface, hepPtr, &state,
			tcAttachPoint, xdpAttachPoint, xdpMode)
	}

	parallelWG.Wait()

	// Attach ingress program.
	parallelWG.Add(1)
	go func() {
		defer parallelWG.Done()
		ingressAP := mergeAttachPoints(ingressAP4, ingressAP6)
		if ingressAP != nil {
			m.loadFilterProgram(ingressAP)
			ingressErr = m.dp.ensureProgramAttached(ingressAP)
		}
	}()

	// Attach xdp program.
	parallelWG.Add(1)
	go func() {
		defer parallelWG.Done()
		xdpAP := mergeAttachPoints(xdpAP4, xdpAP6)
		if xdpAP != nil {
			if hepPtr != nil && len(hepPtr.UntrackedTiers) == 1 {
				xdpErr = m.dp.ensureProgramAttached(xdpAP)
			} else {
				xdpErr = m.dp.ensureNoProgram(xdpAP)
			}
		}
	}()

	// Attach egress program.
	egressAP := mergeAttachPoints(egressAP4, egressAP6)
	if egressAP != nil {
		m.loadFilterProgram(egressAP)
		err = m.dp.ensureProgramAttached(egressAP)
	}

	parallelWG.Wait()
	if err != nil {
		return state, err
	}
	if ingressErr != nil {
		return state, ingressErr
	}
	if xdpErr != nil {
		return state, xdpErr
	}

	if err4 != nil && err6 != nil {
		// This covers the case when we don't have hostIP on both paths.
		return state, errors.Join(err4, err6)
	}

	if m.v6 != nil {
		if err6 == nil {
			state.v6Readiness = ifaceIsReady
		}
		if m.v6.hostIP == nil {
			// If we do not have host IP for the IP version, we certainly error.
			// But that should not prevent the other IP version path from
			// working correctly.
			err6 = nil
		}
	}

	if m.v4 != nil {
		if err4 == nil {
			state.v4Readiness = ifaceIsReady
		}
		if m.v4.hostIP == nil {
			// If we do not have host IP for the IP version, we certainly error.
			// But that should not prevent the other IP version path from
			// working correctly.
			err4 = nil
		}
	}

	return state, errors.Join(err4, err6)
}

func (m *bpfEndpointManager) applyProgramsToDirtyDataInterfaces() {
	var mutex sync.Mutex
	errs := map[string]error{}
	var wg sync.WaitGroup
	for iface := range m.dirtyIfaceNames.All() {
		if !m.isDataIface(iface) && !m.isL3Iface(iface) {
			logrus.WithField("iface", iface).Debug(
				"Ignoring interface that doesn't match the host data/l3 interface regex")
			if !m.isWorkloadIface(iface) {
				logrus.WithField("iface", iface).Debug(
					"Removing interface that doesn't match the host data/l3 interface and is not workload interface")
				m.dirtyIfaceNames.Discard(iface)
			}
			continue
		}
		xdpMode := XDPModeAll
		attachTc := true
		masterName := ""

		/* If the interface is not found either in netlink or the host iface tree, attach Tc and XDP.
		 * If the interface is a root interface, and not a leaf interface, attach only Tc and cleanup XDP.
		 * If the interface is both a root and leaf interface, attach both Tc and XDP.
		 * If the interface is a leaf interface, attach only XDP and cleanup Tc.
		 * If the interface is neither a root nor a leaf, cleanup both Tc and XDP.
		 */
		link, err := m.dp.getIfaceLink(iface)
		if err != nil {
			logrus.WithField("iface", iface).Debug(
				"Error getting link")
		} else {
			hostIf := m.hostIfaceTrees.findIfaceByIndex(link.Attrs().Index)
			if hostIf == nil {
				logrus.WithField("iface", iface).Debug(
					"Host Iface not found in tree")
			} else {
				isRoot := isRootIface(hostIf)
				isLeaf := isLeafIface(hostIf)
				if isRoot {
					// Root interface and not a leaf. Attach only Tc.
					// set xdp mode to None and remove any previously attached
					// xdp programs.
					if !isLeaf {
						xdpMode = XDPModeNone
					}
					// Root and leaf. Single interface tree. Attach both Tc and XDP.
				} else if isLeaf {
					masterIfa := getRootInterface(hostIf)
					if err != nil {
						logrus.Warnf("Failed to get master interface details for '%s'. Continuing to attach program", iface)
					} else {
						masterName = masterIfa.name
						if !m.isDataIface(masterName) {
							logrus.Warnf("Master interface '%s' ignored. Add it to the bpfDataIfacePattern config", masterName)
						} else {
							logrus.WithField("iface", iface).Debug(
								"Attaching xdp only")
							xdpMode = XDPModeOnly
							attachTc = false
						}
					}
				} else {
					xdpMode = XDPModeNone
					attachTc = false
				}
			}
		}

		if !attachTc {
			// Remove any previously attached Tc program.
			err := m.cleanupOldTcAttach(iface)
			if err != nil {
				logrus.Warnf("error removing old Tc program from '%s'.", iface)
			}
		}

		if xdpMode == XDPModeNone {
			logrus.Debugf("Attaching only Tc programs to %s", iface)
			// Remove any previously attached XDP program.
			err = m.cleanupOldXDPAttach(iface)
			if err != nil {
				logrus.Warnf("error removing old xdp program from '%s'.", iface)
			}
		}

		m.opReporter.RecordOperation("update-data-iface")

		wg.Add(1)
		go func(ifaceName string) {
			var state bpfInterfaceState
			var err error
			defer wg.Done()
			if xdpMode != XDPModeNone || attachTc {
				state, err = m.doApplyPolicyToDataIface(ifaceName, masterName, xdpMode)
				m.ifacesLock.Lock()
				m.withIface(ifaceName, func(bpfIface *bpfInterface) bool {
					bpfIface.dpState = state
					return false
				})
				m.ifacesLock.Unlock()
			}
			if err == nil {
				// This is required to allow NodePort forwarding with
				// encapsulation with the host's IP as the source address
				if m.v4 != nil {
					_ = m.dp.setAcceptLocal(iface, true)
				}
			}
			mutex.Lock()
			errs[iface] = err
			mutex.Unlock()
		}(iface)
	}
	wg.Wait()

	// We can hold the lock for the whole iteration below because nothing else
	// is running now. We hold it pretty much to make race detector happy.
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	for iface, err := range errs {
		m.withIface(iface, func(i *bpfInterface) bool {
			m.updateIfaceStateMap(iface, i)
			return false // no need to enforce dirty
		})
		if err == nil {
			logrus.WithField("id", iface).Info("Applied program to host interface")
			m.dirtyIfaceNames.Discard(iface)
		} else {
			if isLinkNotFoundError(err) {
				logrus.WithField("iface", iface).Debug(
					"Tried to apply BPF program to interface but the interface wasn't present.  " +
						"Will retry if it shows up.")
				m.dirtyIfaceNames.Discard(iface)
			} else {
				logrus.WithField("iface", iface).WithError(err).Warn("Failed to apply policy to interface, will retry")
			}
		}
	}
}

func (m *bpfEndpointManager) updateWEPsInDataplane() {
	var mutex sync.Mutex
	errs := map[string]error{}
	var wg sync.WaitGroup

	// Limit the number of parallel workers.  Without this, all the workers vie for CPU and complete slowly.
	// On a constrained system, we can end up taking too long and going non-ready.
	maxWorkers := runtime.GOMAXPROCS(0)
	sem := semaphore.NewWeighted(int64(maxWorkers))

	for ifaceName := range m.dirtyIfaceNames.All() {
		if !m.isWorkloadIface(ifaceName) {
			continue
		}

		m.opReporter.RecordOperation("update-workload-iface")

		if err := sem.Acquire(context.Background(), 1); err != nil {
			// Should only happen if the context finishes.
			logrus.WithError(err).Panic("Failed to acquire semaphore")
		}
		m.onStillAlive()

		wg.Add(1)
		go func(ifaceName string) {
			defer wg.Done()
			defer sem.Release(1)
			err := m.applyPolicy(ifaceName)
			if err == nil {
				if m.v4 != nil {
					_ = m.dp.setAcceptLocal(ifaceName, true)
				}
			}
			mutex.Lock()
			errs[ifaceName] = err
			mutex.Unlock()
		}(ifaceName)
	}
	wg.Wait()

	for ifaceName, err := range errs {
		var wlID *types.WorkloadEndpointID

		m.withIface(ifaceName, func(iface *bpfInterface) bool {
			wlID = iface.info.endpointID
			m.updateIfaceStateMap(ifaceName, iface)
			return false // no need to enforce dirty
		})

		if err == nil {
			logrus.WithField("iface", ifaceName).Info("Updated workload interface.")
			if wlID != nil && m.allWEPs[*wlID] != nil {
				if m.happyWEPs[*wlID] == nil {
					logrus.WithFields(logrus.Fields{
						"id":    wlID,
						"iface": ifaceName,
					}).Info("Adding workload interface to iptables allow list.")
				}
				m.happyWEPs[*wlID] = m.allWEPs[*wlID]
				m.happyWEPsDirty = true
			}
			m.dirtyIfaceNames.Discard(ifaceName)
		} else {
			if wlID != nil && m.happyWEPs[*wlID] != nil {
				if !isLinkNotFoundError(err) {
					logrus.WithField("id", *wlID).WithError(err).Warning(
						"Failed to add policy to workload, removing from iptables allow list")
				}
				delete(m.happyWEPs, *wlID)
				m.happyWEPsDirty = true
			}

			if isLinkNotFoundError(err) {
				logrus.WithField("wep", wlID).Debug(
					"Tried to apply BPF program to interface but the interface wasn't present.  " +
						"Will retry if it shows up.")
				m.dirtyIfaceNames.Discard(ifaceName)
			} else {
				logrus.WithError(err).WithFields(logrus.Fields{
					"wepID": wlID,
					"name":  ifaceName,
				}).Warn("Failed to apply policy to endpoint, leaving it dirty")
			}
		}
	}
}

func (m *bpfEndpointManager) allocJumpIndicesForWEP(ifaceName string, idx *bpfInterfaceJumpIndices) error {
	var err error
	if idx.policyIdx[hook.Ingress] == -1 {
		idx.policyIdx[hook.Ingress], err = m.jumpMapAllocIngress.Get(ifaceName)
		if err != nil {
			return err
		}
	}

	if idx.policyIdx[hook.Egress] == -1 {
		idx.policyIdx[hook.Egress], err = m.jumpMapAllocEgress.Get(ifaceName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *bpfEndpointManager) allocJumpIndicesForDataIface(ifaceName string, xdpMode XDPMode, idx *bpfInterfaceJumpIndices) error {
	var err error
	if xdpMode != XDPModeOnly {
		if idx.policyIdx[hook.Ingress] == -1 {
			idx.policyIdx[hook.Ingress], err = m.jumpMapAllocIngress.Get(ifaceName)
			if err != nil {
				return err
			}
		}

		if idx.policyIdx[hook.Egress] == -1 {
			idx.policyIdx[hook.Egress], err = m.jumpMapAllocEgress.Get(ifaceName)
			if err != nil {
				return err
			}
		}
	}

	if xdpMode != XDPModeNone && idx.policyIdx[hook.XDP] == -1 {
		idx.policyIdx[hook.XDP], err = m.xdpJumpMapAlloc.Get(ifaceName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *bpfEndpointManager) wepStateFillJumps(ap *tc.AttachPoint, state *bpfInterfaceState) error {
	var err error

	// Allocate indices for IPv4
	if m.v4 != nil {
		err = m.allocJumpIndicesForWEP(ap.IfaceName(), &state.v4)
		if err != nil {
			return err
		}
	}

	// Allocate indices for IPv6
	if m.v6 != nil {
		err = m.allocJumpIndicesForWEP(ap.IfaceName(), &state.v6)
		if err != nil {
			return err
		}
	}

	if ap.LogLevel == "debug" {
		if state.filterIdx[hook.Ingress] == -1 {
			state.filterIdx[hook.Ingress], err = m.jumpMapAllocIngress.Get(ap.IfaceName())
			if err != nil {
				return err
			}
		}
		if state.filterIdx[hook.Egress] == -1 {
			state.filterIdx[hook.Egress], err = m.jumpMapAllocEgress.Get(ap.IfaceName())
			if err != nil {
				return err
			}
		}
	} else {
		for _, attachHook := range []hook.Hook{hook.Ingress, hook.Egress} {
			if err := m.jumpMapDelete(attachHook, state.filterIdx[attachHook]); err != nil {
				logrus.WithError(err).Warn("Filter program may leak.")
			}
			if attachHook == hook.Ingress {
				if err := m.jumpMapAllocIngress.Put(state.filterIdx[attachHook], ap.IfaceName()); err != nil {
					logrus.WithError(err).Errorf("Filter hook %s", attachHook)
				}
			} else {
				if err := m.jumpMapAllocEgress.Put(state.filterIdx[attachHook], ap.IfaceName()); err != nil {
					logrus.WithError(err).Errorf("Filter hook %s", attachHook)
				}
			}
			state.filterIdx[attachHook] = -1
		}
	}

	return nil
}

func (m *bpfEndpointManager) dataIfaceStateFillJumps(ap *tc.AttachPoint, xdpMode XDPMode, state *bpfInterfaceState) error {
	var err error
	if m.v4 != nil {
		err = m.allocJumpIndicesForDataIface(ap.IfaceName(), xdpMode, &state.v4)
		if err != nil {
			return err
		}
	}

	if m.v6 != nil {
		err = m.allocJumpIndicesForDataIface(ap.IfaceName(), xdpMode, &state.v6)
		if err != nil {
			return err
		}
	}

	if ap.LogLevel == "debug" {
		if state.filterIdx[hook.Ingress] == -1 {
			state.filterIdx[hook.Ingress], err = m.jumpMapAllocIngress.Get(ap.IfaceName())
			if err != nil {
				return err
			}
		}
		if state.filterIdx[hook.Egress] == -1 {
			state.filterIdx[hook.Egress], err = m.jumpMapAllocEgress.Get(ap.IfaceName())
			if err != nil {
				return err
			}
		}
	} else {
		for _, attachHook := range []hook.Hook{hook.Ingress, hook.Egress} {
			if err := m.jumpMapDelete(attachHook, state.filterIdx[attachHook]); err != nil {
				logrus.WithError(err).Warn("Filter program may leak.")
			}
			if attachHook == hook.Ingress {
				if err := m.jumpMapAllocIngress.Put(state.filterIdx[attachHook], ap.IfaceName()); err != nil {
					logrus.WithError(err).Errorf("Filter hook %s", attachHook)
				}
			} else {
				if err := m.jumpMapAllocEgress.Put(state.filterIdx[attachHook], ap.IfaceName()); err != nil {
					logrus.WithError(err).Errorf("Filter hook %s", attachHook)
				}
			}
			state.filterIdx[attachHook] = -1
		}
	}
	return nil
}

func (m *bpfEndpointManager) queryClassifier(ifaceName, tcHook string) bool {
	tcProgs, err := tc.ListAttachedPrograms(ifaceName, tcHook, false)
	if err != nil || len(tcProgs) == 0 {
		return false
	}
	return true
}

func (m *bpfEndpointManager) doApplyPolicy(ifaceName string) (bpfInterfaceState, error) {
	startTime := time.Now()

	var (
		state      bpfInterfaceState
		endpointID *types.WorkloadEndpointID
		ifaceUp    bool
		ifindex    int
	)

	// Other threads might be filling in jump map FDs in the map so take the lock.
	m.ifacesLock.Lock()
	m.withIface(ifaceName, func(iface *bpfInterface) (forceDirty bool) {
		ifaceUp = iface.info.ifaceIsUp()
		ifindex = iface.info.ifIndex
		endpointID = iface.info.endpointID
		state = iface.dpState
		return false
	})
	m.ifacesLock.Unlock()

	if !ifaceUp {
		// Interface is gone, nothing to do.
		logrus.WithField("ifaceName", ifaceName).Debug(
			"Ignoring request to program interface that is not present.")
		return state, nil
	}

	// Otherwise, the interface appears to be present but we may or may not have an endpoint from the
	// datastore.  If we don't have an endpoint then we'll attach a program to block traffic and we'll
	// get the jump map ready to insert the policy if the endpoint shows up.

	// Attach the qdisc first; it is shared between the directions.
	existed, err := m.dp.ensureQdisc(ifaceName)
	if err != nil {
		if isLinkNotFoundError(err) {
			// Interface is gone, nothing to do.
			logrus.WithField("ifaceName", ifaceName).Debug(
				"Ignoring request to program interface that is not present.")
			return state, nil
		}
		return state, err
	}
	if !existed {
		// Cannot be ready if the qdisc is not there so no program can be
		// attached. Do the full attach!
		state.v4Readiness = ifaceNotReady
		state.v6Readiness = ifaceNotReady
	}

	var (
		ingressErr, egressErr error
		err4, err6            error
		ingressAP4, egressAP4 *tc.AttachPoint
		ingressAP6, egressAP6 *tc.AttachPoint
		wg                    sync.WaitGroup
		wep                   *proto.WorkloadEndpoint
	)

	if endpointID != nil {
		wep = m.allWEPs[*endpointID]
	}

	v4Readiness := state.v4Readiness
	v6Readiness := state.v6Readiness

	if v4Readiness == ifaceIsReady || v6Readiness == ifaceIsReady {
		if !m.dp.queryClassifier(ifaceName, hook.Ingress.String()) {
			v4Readiness = ifaceNotReady
			v6Readiness = ifaceNotReady
		}
		if !m.dp.queryClassifier(ifaceName, hook.Egress.String()) {
			v4Readiness = ifaceNotReady
			v6Readiness = ifaceNotReady
		}
	}

	ap := m.calculateTCAttachPoint(ifaceName)
	ap.IfIndex = ifindex
	if wep != nil && wep.QosControls != nil {
		// QoSControls are present, update state

		if wep.QosControls.EgressBandwidth > 0 {
			ap.SkipEgressRedirect = true
		}

		if wep.QosControls.IngressPacketRate > 0 {
			// Ingress packet rate is configured
			ap.IngressPacketRateConfigured = true

			qosKey := qos.NewKey(uint32(ifindex), 1) // ingress=1
			qosValBytes, err := m.QoSMap.Get(qosKey.AsBytes())
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				logrus.WithField("ifindex", ifindex).WithError(err).Debug("Error retrieving ingress entry from QoS map.")
				return state, err
			}
			qosVal := qos.ValueFromBytes(qosValBytes)
			qosPacketRate := qosVal.PacketRate()
			qosPacketBurst := qosVal.PacketBurst()
			qosTokens := qosVal.PacketRateTokens()
			qosLastUpdate := qosVal.PacketRateLastUpdate()
			// Reset state if config changed. Safe to cast to int16 since the maximum value is 10000
			if qosVal.PacketRate() != int16(wep.QosControls.IngressPacketRate) || qosVal.PacketBurst() != int16(wep.QosControls.IngressPacketBurst) {
				qosPacketRate = int16(wep.QosControls.IngressPacketRate)
				qosPacketBurst = int16(wep.QosControls.IngressPacketBurst)
				qosTokens = int16(-1)
				qosLastUpdate = uint64(0)
			}

			qosVal = qos.NewValue(qosPacketRate, qosPacketBurst, qosTokens, qosLastUpdate)

			if err := m.QoSMap.UpdateWithFlags(qosKey.AsBytes(), qosVal.AsBytes(), unix.BPF_F_LOCK); err != nil {
				logrus.WithField("ifindex", ifindex).WithError(err).Debug("Error updating ingress entry in QoS map.")
				return state, fmt.Errorf("failed to update QoS map. err=%w", err)
			}
		} else {
			// Ingress packet rate not configured, clean up existing state if present
			qosKey := qos.NewKey(uint32(ifindex), 1) // ingress=1
			err = m.QoSMap.Delete(qosKey.AsBytes())
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				logrus.WithField("ifindex", ifindex).WithError(err).Debug("Error removing ingress entry from QoS map.")
				return state, err
			}
		}
		if wep.QosControls.EgressPacketRate > 0 {
			// Egress packet rate is configured
			ap.EgressPacketRateConfigured = true

			qosKey := qos.NewKey(uint32(ifindex), 0) // ingress=0
			qosValBytes, err := m.QoSMap.Get(qosKey.AsBytes())
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				logrus.WithField("ifindex", ifindex).WithError(err).Debug("Error retrieving egress entry from QoS map.")
				return state, err
			}
			qosVal := qos.ValueFromBytes(qosValBytes)
			qosPacketRate := qosVal.PacketRate()
			qosPacketBurst := qosVal.PacketBurst()
			qosTokens := qosVal.PacketRateTokens()
			qosLastUpdate := qosVal.PacketRateLastUpdate()
			// Reset state if config changed
			if qosVal.PacketRate() != int16(wep.QosControls.EgressPacketRate) || qosVal.PacketBurst() != int16(wep.QosControls.EgressPacketBurst) {
				// Safe to cast to int16 since the maximum value is 10000
				qosPacketRate = int16(wep.QosControls.EgressPacketRate)
				qosPacketBurst = int16(wep.QosControls.EgressPacketBurst)
				qosTokens = int16(-1)
				qosLastUpdate = uint64(0)
			}

			qosVal = qos.NewValue(qosPacketRate, qosPacketBurst, qosTokens, qosLastUpdate)

			if err := m.QoSMap.UpdateWithFlags(qosKey.AsBytes(), qosVal.AsBytes(), unix.BPF_F_LOCK); err != nil {
				logrus.WithField("ifindex", ifindex).WithError(err).Debug("Error updating egress entry in QoS map.")
				return state, fmt.Errorf("failed to update QoS map. err=%w", err)
			}
		} else {
			// Egress packet rate not configured, clean up existing state if present
			qosKey := qos.NewKey(uint32(ifindex), 0) // ingress=0
			err = m.QoSMap.Delete(qosKey.AsBytes())
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				logrus.WithField("ifindex", ifindex).WithError(err).Debug("Error removing egress entry from QoS map.")
				return state, err
			}
		}
	} else {
		// Either the workload endpoint or QoSControls were removed, clean up both ingress and egress state from map
		qosIngressKey := qos.NewKey(uint32(ifindex), 1) // ingress=1
		err = m.QoSMap.Delete(qosIngressKey.AsBytes())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			logrus.WithField("ifindex", ifindex).WithError(err).Debug("Error removing ingress entry from QoS map.")
			return state, err
		}
		qosEgressKey := qos.NewKey(uint32(ifindex), 0) // ingress=0
		err = m.QoSMap.Delete(qosEgressKey.AsBytes())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			logrus.WithField("ifindex", ifindex).WithError(err).Debug("Error removing egress entry from QoS map.")
			return state, err
		}
	}

	ap.DSCP = -1
	if wep != nil && len(wep.QosPolicies) > 0 {
		// Only one QoS policy is supported at the moment.
		dscp := int8(wep.QosPolicies[0].Dscp)
		if dscp < 0 || dscp > 63 {
			logrus.WithField("wep", wep.Name).Errorf("Invalid DSCP value %v - Skipping.", dscp)
		} else {
			ap.DSCP = dscp
		}
	}

	if err := m.wepStateFillJumps(ap, &state); err != nil {
		return state, err
	}

	if m.v6 != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ingressAP6, egressAP6, err6 = m.v6.applyPolicyToWeps(v6Readiness, ifaceName, &state, wep, ap)
		}()
	}

	if m.v4 != nil {
		ingressAP4, egressAP4, err4 = m.v4.applyPolicyToWeps(v4Readiness, ifaceName, &state, wep, ap)
	}

	wg.Wait()

	attachPreamble := false
	if m.v6 != nil {
		attachPreamble = v6Readiness != ifaceIsReady
	}
	if m.v4 != nil {
		attachPreamble = v4Readiness != ifaceIsReady
	}

	// Attach preamble TC program
	if attachPreamble {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ingressAP := mergeAttachPoints(ingressAP4, ingressAP6)
			if ingressAP != nil {
				m.loadFilterProgram(ingressAP)
				ingressErr = m.dp.ensureProgramAttached(ingressAP)
			}
		}()
		egressAP := mergeAttachPoints(egressAP4, egressAP6)
		if egressAP != nil {
			m.loadFilterProgram(egressAP)
			egressErr = m.dp.ensureProgramAttached(egressAP)
		}
		wg.Wait()
	}

	if ingressErr != nil {
		return state, ingressErr
	}

	if egressErr != nil {
		return state, egressErr
	}

	if err4 != nil && err6 != nil {
		// This covers the case when we don't have hostIP on both paths.
		return state, errors.Join(err4, err6)
	}

	if m.v6 != nil {
		if err6 == nil {
			state.v6Readiness = ifaceIsReady
		}
		if m.v6.hostIP == nil {
			// If we do not have host IP for the IP version, we certainly error.
			// But that should not prevent the other IP version path from
			// working correctly.
			err6 = nil
		}
	}

	if m.v4 != nil {
		if err4 == nil {
			state.v4Readiness = ifaceIsReady
		}
		if m.v4.hostIP == nil {
			// If we do not have host IP for the IP version, we certainly error.
			// But that should not prevent the other IP version path from
			// working correctly.
			err4 = nil
		}
	}

	if errors.Join(err4, err6) != nil {
		return state, errors.Join(err4, err6)
	}

	applyTime := time.Since(startTime)
	logrus.WithFields(logrus.Fields{"timeTaken": applyTime, "ifaceName": ifaceName}).
		Info("Finished applying BPF programs for workload")
	return state, nil
}

func (m *bpfEndpointManager) ensureProgramAttached(ap attachPoint) error {
	if err := counters.EnsureExists(m.commonMaps.CountersMap, ap.IfaceIndex(), ap.HookName()); err != nil {
		return err
	}

	return ap.AttachProgram()
}

// applyPolicy actually applies the policy to the given workload.
func (m *bpfEndpointManager) applyPolicy(ifaceName string) error {
	state, err := m.doApplyPolicy(ifaceName)

	m.ifacesLock.Lock()
	m.withIface(ifaceName, func(iface *bpfInterface) (forceDirty bool) {
		iface.dpState = state
		return false // already dirty
	})
	m.ifacesLock.Unlock()

	return err
}

func mergeAttachPoints(ap4, ap6 attachPoint) attachPoint {
	if aptcV4, v4ok := ap4.(*tc.AttachPoint); v4ok {
		if aptcV6, v6ok := ap6.(*tc.AttachPoint); v6ok {
			if aptcV4 != nil && aptcV6 == nil {
				return aptcV4
			} else if aptcV6 != nil && aptcV4 == nil {
				return aptcV6
			} else if aptcV4 != nil && aptcV6 != nil {
				aptcV4.HostIPv6 = aptcV6.HostIPv6
				aptcV4.IntfIPv6 = aptcV6.IntfIPv6
				aptcV4.HostTunnelIPv6 = aptcV6.HostTunnelIPv6
				aptcV4.HookLayoutV6 = aptcV6.HookLayoutV6
				aptcV4.PolicyIdxV6 = aptcV6.PolicyIdxV6
				return aptcV4
			}
		}
	} else if apxdpV4, v4ok := ap4.(*xdp.AttachPoint); v4ok {
		apxdpV6, _ := ap6.(*xdp.AttachPoint)
		if apxdpV4 != nil && apxdpV6 == nil {
			return apxdpV4
		} else if apxdpV6 != nil && apxdpV4 == nil {
			return apxdpV6
		} else if apxdpV6 != nil && apxdpV4 != nil {
			apxdpV4.PolicyIdxV6 = apxdpV6.PolicyIdxV6
			apxdpV4.HookLayoutV6 = apxdpV6.HookLayoutV6
			return apxdpV4
		}
	}
	return nil
}

func isLinkNotFoundError(err error) bool {
	if errors.Is(err, tc.ErrDeviceNotFound) { // From the tc package.
		return true
	}
	if err.Error() == "Link not found" { // From netlink and friends.
		return true
	}
	return false
}

var calicoRouterIP = net.IPv4(169, 254, 1, 1).To4()

func (d *bpfEndpointManagerDataplane) wepTCAttachPoint(ap *tc.AttachPoint, policyIdx, filterIdx int,
	polDirection PolDirection,
) *tc.AttachPoint {
	ap = d.configureTCAttachPoint(polDirection, ap, false)
	ifaceName := ap.IfaceName()
	if d.ipFamily == proto.IPVersion_IPV6 {
		ip, err := d.getInterfaceIP(ifaceName)
		if err != nil {
			logrus.Debugf("Error getting IP for interface %+v: %+v", ifaceName, err)
			ap.IntfIPv6 = d.hostIP
		} else {
			ap.IntfIPv6 = *ip
		}
		ap.HostIPv6 = d.hostIP
		ap.PolicyIdxV6 = policyIdx
	} else {
		ap.IntfIPv4 = calicoRouterIP
		ap.HostIPv4 = d.hostIP
		ap.PolicyIdxV4 = policyIdx
	}
	ap.LogFilterIdx = filterIdx

	return ap
}

func (d *bpfEndpointManagerDataplane) wepApplyPolicyToDirection(readiness ifaceReadiness, state *bpfInterfaceState,
	endpoint *proto.WorkloadEndpoint, polDirection PolDirection, ap *tc.AttachPoint,
) (*tc.AttachPoint, error) {
	var policyIdx, filterIdx int
	if d.hostIP == nil {
		// Do not bother and wait
		return nil, fmt.Errorf("unknown host IP")
	}

	indices := state.v4
	if d.ipFamily == proto.IPVersion_IPV6 {
		indices = state.v6
	}

	attachHook := hook.Ingress
	if polDirection == PolDirnEgress {
		attachHook = hook.Egress
	}
	policyIdx = indices.policyIdx[attachHook]
	filterIdx = state.filterIdx[attachHook]

	ap = d.wepTCAttachPoint(ap, policyIdx, filterIdx, polDirection)

	logrus.WithField("iface", ap.IfaceName()).Debugf("readiness: %d", readiness)
	if readiness != ifaceIsReady {
		err := d.mgr.loadPrograms(ap, d.ipFamily)
		if err != nil {
			return nil, fmt.Errorf("attaching program to wep: %w", err)
		}
		ap.Log().Info("Attached programs to the WEP")
	}

	if err := d.wepApplyPolicy(ap, endpoint, polDirection); err != nil {
		return ap, errApplyingPolicy
	}

	return ap, nil
}

func (m *bpfEndpointManager) loadPrograms(ap *tc.AttachPoint, ipFamily proto.IPVersion) error {
	err := m.dp.ensureProgramLoaded(ap, ipFamily)
	if err != nil {
		return err
	}
	return nil
}

func (m *bpfEndpointManager) loadFilterProgram(ap attachPoint) {
	if ap.LogVal() == "debug" {
		if err := m.updateLogFilter(ap); err != nil {
			ap.Log().WithError(err).Warn("Failed to update logging filter, logging may be incorrect.")
		}
	}
}

func (d *bpfEndpointManagerDataplane) wepApplyPolicy(ap *tc.AttachPoint,
	endpoint *proto.WorkloadEndpoint, polDirection PolDirection,
) error {
	var profileIDs []string
	var tiers []*proto.TierInfo
	if endpoint != nil {
		profileIDs = endpoint.ProfileIds
		tiers = endpoint.Tiers
	} else {
		logrus.WithField("name", ap.IfaceName()).Debug(
			"Workload interface with no endpoint in datastore, installing default-drop program.")
	}

	m := d.mgr
	// If tier or profileIDs is nil, this will return an empty set of rules but updatePolicyProgram appends a
	// drop rule, giving us default drop behaviour in that case.
	rules := m.extractRules(tiers, profileIDs, polDirection)

	// If host-* endpoint is configured, add in its policy.
	if m.wildcardExists {
		m.addHostPolicy(&rules, d.mgr.wildcardHostEndpoint, polDirection.Inverse())
	}

	// Intentionally leaving this code here until the *-hep takes precedence.
	wildcardEPPolicyAppliesToWEPs := false
	if wildcardEPPolicyAppliesToWEPs {
		// If workload egress and DefaultEndpointToHostAction is ACCEPT or DROP, suppress the normal
		// host-* endpoint policy. If it does not exist, suppress it as well, not to
		// create deny due to the fact that there are not profiles or tiers etc.
		if polDirection == PolDirnEgress && (m.epToHostAction != "RETURN" || !m.wildcardExists) {
			rules.SuppressNormalHostPolicy = true
		}
	} else {
		rules.SuppressNormalHostPolicy = true
	}

	// If host -> workload, always suppress the normal host-* endpoint policy.
	if polDirection == PolDirnIngress {
		rules.SuppressNormalHostPolicy = true
	}

	return m.updatePolicyProgramFn(rules, polDirection.RuleDir().String(), ap, d.ipFamily)
}

func (m *bpfEndpointManager) addHostPolicy(rules *polprog.Rules, hostEndpoint *proto.HostEndpoint, polDirection PolDirection) {
	// When there is applicable pre-DNAT policy that does not explicitly Allow or Deny traffic,
	// we continue on to subsequent tiers and normal or AoF policy.
	rules.HostPreDnatTiers = m.extractTiers(hostEndpoint.PreDnatTiers, polDirection, NoEndTierDrop)

	// When there is applicable apply-on-forward policy that does not explicitly Allow or Deny
	// traffic, traffic is dropped.
	rules.HostForwardTiers = m.extractTiers(hostEndpoint.ForwardTiers, polDirection, EndTierDrop)

	// When there is applicable normal policy that does not explicitly Allow or Deny traffic,
	// traffic is dropped.
	rules.HostNormalTiers = m.extractTiers(hostEndpoint.Tiers, polDirection, EndTierDrop)
	rules.HostProfiles = m.extractProfiles(hostEndpoint.ProfileIds, polDirection)
}

func (d *bpfEndpointManagerDataplane) applyPolicyToWeps(
	readiness ifaceReadiness,
	ifaceName string,
	state *bpfInterfaceState,
	endpoint *proto.WorkloadEndpoint,
	ap *tc.AttachPoint,
) (*tc.AttachPoint, *tc.AttachPoint, error) {
	ingressAttachPoint := *ap
	egressAttachPoint := *ap

	var parallelWG sync.WaitGroup
	var ingressAP *tc.AttachPoint
	var ingressErr error

	parallelWG.Add(1)
	go func() {
		defer parallelWG.Done()
		ingressAP, ingressErr = d.wepApplyPolicyToDirection(readiness,
			state, endpoint, PolDirnIngress, &ingressAttachPoint)
	}()

	egressAP, egressErr := d.wepApplyPolicyToDirection(readiness,
		state, endpoint, PolDirnEgress, &egressAttachPoint)
	parallelWG.Wait()

	return ingressAP, egressAP, errors.Join(ingressErr, egressErr)
}

func (d *bpfEndpointManagerDataplane) applyPolicyToDataIface(
	ifaceName string,
	ep *proto.HostEndpoint,
	state *bpfInterfaceState,
	ap *tc.AttachPoint,
	apxdp *xdp.AttachPoint,
	xdpMode XDPMode,
) (*tc.AttachPoint, *tc.AttachPoint, *xdp.AttachPoint, error) {
	ingressAttachPoint := *ap
	egressAttachPoint := *ap
	xdpAttachPoint := *apxdp

	var parallelWG sync.WaitGroup
	var ingressAP, egressAP *tc.AttachPoint
	var xdpAP *xdp.AttachPoint
	var ingressErr, egressErr, xdpErr error

	if xdpMode != XDPModeNone {
		parallelWG.Add(1)
		go func() {
			defer parallelWG.Done()
			xdpAP, xdpErr = d.attachXDPProgram(&xdpAttachPoint, ep, state)
		}()
	}

	if xdpMode != XDPModeOnly {
		parallelWG.Add(1)
		go func() {
			defer parallelWG.Done()
			ingressAP, ingressErr = d.attachDataIfaceProgram(ifaceName, ep, PolDirnIngress, state, &ingressAttachPoint)
		}()

		egressAP, egressErr = d.attachDataIfaceProgram(ifaceName, ep, PolDirnEgress, state, &egressAttachPoint)
	}
	parallelWG.Wait()
	return ingressAP, egressAP, xdpAP, errors.Join(ingressErr, egressErr, xdpErr)
}

func (d *bpfEndpointManagerDataplane) attachDataIfaceProgram(
	ifaceName string,
	ep *proto.HostEndpoint,
	polDirection PolDirection,
	state *bpfInterfaceState,
	ap *tc.AttachPoint,
) (*tc.AttachPoint, error) {
	if d.hostIP == nil {
		// Do not bother and wait
		return nil, fmt.Errorf("unknown host IP")
	}

	ap = d.configureTCAttachPoint(polDirection, ap, true)

	ip, err := d.getInterfaceIP(ifaceName)
	if err != nil {
		logrus.Debugf("Error getting IP for interface %+v: %+v", ifaceName, err)
	}

	indices := state.v4
	if d.ipFamily == proto.IPVersion_IPV6 {
		indices = state.v6
	}

	attachHook := hook.Ingress
	if polDirection == PolDirnEgress {
		attachHook = hook.Egress
	}

	policyIdx := indices.policyIdx[attachHook]
	filterIdx := state.filterIdx[attachHook]

	if d.ipFamily == proto.IPVersion_IPV6 {
		ap.HostIPv6 = d.hostIP
		if ip != nil {
			ap.IntfIPv6 = *ip
		} else {
			ap.IntfIPv6 = d.hostIP
		}
		ap.PolicyIdxV6 = policyIdx
	} else {
		ap.HostIPv4 = d.hostIP
		if ip != nil {
			ap.IntfIPv4 = *ip
		} else {
			ap.IntfIPv4 = d.hostIP
		}
		ap.PolicyIdxV4 = policyIdx
	}
	ap.LogFilterIdx = filterIdx

	m := d.mgr

	if err := m.loadPrograms(ap, d.ipFamily); err != nil {
		return nil, err
	}

	ap.DSCP = -1
	if ep != nil && len(ep.QosPolicies) > 0 {
		// Only one QoS policy is supported at the moment.
		dscp := int8(ep.QosPolicies[0].Dscp)
		if dscp < 0 || dscp > 63 {
			logrus.WithField("hep", ep.Name).Errorf("Invalid DSCP value %v - Skipping.", dscp)
		} else {
			ap.DSCP = dscp
		}
	}

	if ep != nil {
		rules := polprog.Rules{
			ForHostInterface: true,
		}
		m.addHostPolicy(&rules, ep, polDirection)
		if err := m.updatePolicyProgramFn(rules, polDirection.RuleDir().String(), ap, d.ipFamily); err != nil {
			return ap, err
		}
	} else {
		if err := m.dp.removePolicyProgram(ap, d.ipFamily); err != nil {
			return ap, err
		}
	}
	return ap, nil
}

func (d *bpfEndpointManagerDataplane) attachXDPProgram(ap *xdp.AttachPoint, ep *proto.HostEndpoint, state *bpfInterfaceState) (*xdp.AttachPoint, error) {
	if d.ipFamily == proto.IPVersion_IPV6 {
		ap.PolicyIdxV6 = state.v6.policyIdx[hook.XDP]
	} else {
		ap.PolicyIdxV4 = state.v4.policyIdx[hook.XDP]
	}

	m := d.mgr
	if ep != nil && len(ep.UntrackedTiers) == 1 {
		err := m.dp.ensureProgramLoaded(ap, d.ipFamily)
		if err != nil {
			return nil, err
		}

		ap.Log().Infof("Building program for untracked policy hep=%v, family=%v", ep.Name, d.ipFamily)
		rules := polprog.Rules{
			ForHostInterface: true,
			HostNormalTiers:  m.extractTiers(ep.UntrackedTiers, PolDirnIngress, false),
			ForXDP:           true,
		}
		ap.Log().Infof("Rules: %v", rules)
		err = m.updatePolicyProgramFn(rules, "xdp", ap, d.ipFamily)
		ap.Log().WithError(err).Debugf("Applied untracked policy hep=%v", ep.Name)
		return ap, err
	}
	return ap, nil
}

// PolDirection is the Calico datamodel direction of policy.  On a host endpoint, ingress is towards the host.
// On a workload endpoint, ingress is towards the workload.
type PolDirection int

const (
	PolDirnIngress PolDirection = iota
	PolDirnEgress
)

func (polDirection PolDirection) RuleDir() rules.RuleDir {
	if polDirection == PolDirnIngress {
		return rules.RuleDirIngress
	}
	return rules.RuleDirEgress
}

func (polDirection PolDirection) Inverse() PolDirection {
	if polDirection == PolDirnIngress {
		return PolDirnEgress
	}
	return PolDirnIngress
}

func (m *bpfEndpointManager) apLogFilter(ap *tc.AttachPoint, iface string) (string, string) {
	if len(m.logFilters) == 0 {
		return m.bpfLogLevel, ""
	}

	if m.bpfLogLevel != "debug" {
		return m.bpfLogLevel, ""
	}

	exp, ok := m.logFilters[iface]
	if !ok {
		if ap.Type == tcdefs.EpTypeWorkload {
			if exp, ok := m.logFilters["weps"]; ok {
				logrus.WithField("iface", iface).Debugf("Log filter for weps: %s", exp)
				return m.bpfLogLevel, exp
			}
		}
		if ap.Type == tcdefs.EpTypeHost {
			if exp, ok := m.logFilters["heps"]; ok {
				logrus.WithField("iface", iface).Debugf("Log filter for heps: %s", exp)
				return m.bpfLogLevel, exp
			}
		}
		if exp, ok := m.logFilters["all"]; ok {
			logrus.WithField("iface", iface).Debugf("Log filter for all: %s", exp)
			return m.bpfLogLevel, exp
		}

		logrus.WithField("iface", iface).Debug("No log filter")
		return "off", ""
	}

	logrus.WithField("iface", iface).Debugf("Log filter:  %s", exp)
	return m.bpfLogLevel, exp
}

func (m *bpfEndpointManager) getEndpointType(ifaceName string) tcdefs.EndpointType {
	if m.isWorkloadIface(ifaceName) {
		return tcdefs.EpTypeWorkload
	}
	m.ifacesLock.Lock()
	ifaceType := m.nameToIface[ifaceName].info.ifaceType
	m.ifacesLock.Unlock()
	switch ifaceType {
	case IfaceTypeData, IfaceTypeVXLAN, IfaceTypeBond, IfaceTypeBondSlave:
		if ifaceName == "vxlan.calico" || ifaceName == "vxlan-v6.calico" {
			return tcdefs.EpTypeVXLAN
		}
		if ifaceName == "lo" {
			return tcdefs.EpTypeLO
		}
		if ifaceName == dataplanedefs.BPFInDev || ifaceName == dataplanedefs.BPFOutDev {
			return tcdefs.EpTypeNAT
		}
		return tcdefs.EpTypeHost
	case IfaceTypeWireguard, IfaceTypeL3:
		return tcdefs.EpTypeL3Device
	case IfaceTypeIPIP:
		if m.features.IPIPDeviceIsL3 {
			return tcdefs.EpTypeL3Device
		}
		return tcdefs.EpTypeIPIP
	default:
		logrus.Panicf("Unsupported ifaceName %v", ifaceName)
	}
	return tcdefs.EpTypeHost
}

func (m *bpfEndpointManager) calculateTCAttachPoint(ifaceName string) *tc.AttachPoint {
	ap := &tc.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			Iface: ifaceName,
		},
		MaglevLUTSize: uint32(m.maglevLUTSize),
	}

	ap.Type = m.getEndpointType(ifaceName)

	if ap.Type == tcdefs.EpTypeLO && m.hostNetworkedNATMode == hostNetworkedNATUDPOnly {
		ap.UDPOnly = true
	}
	if ap.Type != tcdefs.EpTypeWorkload {
		ap.WgPort = m.wgPort
		ap.Wg6Port = m.wg6Port
		ap.NATin = uint32(m.natInIdx)
		ap.NATout = uint32(m.natOutIdx)

	} else {
		ap.ExtToServiceConnmark = uint32(m.bpfExtToServiceConnmark)
	}

	if m.natOutgoingExclusions == string(apiv3.NATOutgoingExclusionsIPPoolsAndHostIPs) {
		ap.NATOutgoingExcludeHosts = true
	}

	ap.ToHostDrop = (m.epToHostAction == "DROP")
	ap.DSR = m.dsrEnabled
	ap.DSROptoutCIDRs = m.dsrOptoutCidrs
	ap.LogLevel, ap.LogFilter = m.apLogFilter(ap, ifaceName)
	ap.VXLANPort = m.vxlanPort
	ap.PSNATStart = m.psnatPorts.MinPort
	ap.PSNATEnd = m.psnatPorts.MaxPort
	ap.TunnelMTU = uint16(m.vxlanMTU)
	ap.Profiling = m.profiling
	ap.OverlayTunnelID = m.overlayTunnelID
	ap.AttachType = m.bpfAttachType
	ap.RedirectPeer = true
	if m.bpfRedirectToPeer == "Disabled" {
		ap.RedirectPeer = false
	} else if (ap.Type == tcdefs.EpTypeIPIP || ap.Type == tcdefs.EpTypeL3Device) && m.bpfRedirectToPeer == "L2Only" {
		ap.RedirectPeer = false
	}

	switch m.rpfEnforceOption {
	case "Strict":
		ap.RPFEnforceOption = tcdefs.RPFEnforceOptionStrict
	case "Loose":
		ap.RPFEnforceOption = tcdefs.RPFEnforceOptionLoose
	default:
		ap.RPFEnforceOption = tcdefs.RPFEnforceOptionDisabled
	}
	return ap
}

func (d *bpfEndpointManagerDataplane) configureTCAttachPoint(policyDirection PolDirection, ap *tc.AttachPoint, isDataIface bool) *tc.AttachPoint {
	if ap.Type == tcdefs.EpTypeLO || ap.Type == tcdefs.EpTypeNAT || isDataIface {
		if d.ipFamily == proto.IPVersion_IPV6 {
			ap.HostTunnelIPv6 = d.tunnelIP
		} else {
			ap.HostTunnelIPv4 = d.tunnelIP
		}
		logrus.Debugf("Setting tunnel ip %s on ap %s", d.tunnelIP, ap.IfaceName())
	}

	if ap.Type == tcdefs.EpTypeWorkload {
		// Policy direction is relative to the workload so, from the host namespace it's flipped.
		if policyDirection == PolDirnIngress {
			ap.Hook = hook.Egress
		} else {
			ap.Hook = hook.Ingress
		}
	} else {
		// Host endpoints have the natural relationship between policy direction and hook.
		if policyDirection == PolDirnIngress {
			ap.Hook = hook.Ingress
		} else {
			ap.Hook = hook.Egress
		}
	}

	ap.ProgramsMap = d.mgr.commonMaps.ProgramsMaps[hook.Ingress]
	if ap.Hook == hook.Egress {
		ap.ProgramsMap = d.mgr.commonMaps.ProgramsMaps[hook.Egress]
	}

	if d.mgr.FlowLogsEnabled() {
		ap.FlowLogsEnabled = true
	}

	var toOrFrom tcdefs.ToOrFromEp
	if ap.Hook == hook.Ingress {
		toOrFrom = tcdefs.FromEp
	} else {
		toOrFrom = tcdefs.ToEp
	}

	ap.ToOrFrom = toOrFrom
	return ap
}

const (
	EndTierDrop   = true
	NoEndTierDrop = false
)

// Given a slice of TierInfo - as present on workload and host endpoints - that actually consists
// only of tier and policy NAMEs, build and return a slice of tier data that includes all of the
// implied policy rules as well.
func (m *bpfEndpointManager) extractTiers(tiers []*proto.TierInfo, direction PolDirection, endTierDrop bool) (rTiers []polprog.Tier) {
	dir := direction.RuleDir()
	for _, tier := range tiers {
		directionalPols := tier.IngressPolicies
		if direction == PolDirnEgress {
			directionalPols = tier.EgressPolicies
		}

		if len(directionalPols) > 0 {
			stagedOnly := true

			polTier := polprog.Tier{
				Name:     tier.Name,
				Policies: make([]polprog.Policy, len(directionalPols)),
			}

			for i, polID := range directionalPols {
				if model.KindIsStaged(polID.Kind) {
					logrus.Debugf("Skipping staged policy %v", polID)
					continue
				}
				stagedOnly = false

				pol := m.policies[types.ProtoToPolicyID(polID)]
				if pol == nil {
					logrus.WithField("tier", tier).Warn("Tier refers to unknown policy!")
					continue
				}
				var prules []*proto.Rule
				if direction == PolDirnIngress {
					prules = pol.InboundRules
				} else {
					prules = pol.OutboundRules
				}
				policy := polprog.Policy{
					Name:      polID.Name,
					Namespace: polID.Namespace,
					Kind:      polID.Kind,
					Rules:     make([]polprog.Rule, len(prules)),
				}

				for ri, r := range prules {
					policy.Rules[ri] = polprog.Rule{
						Rule:    r,
						MatchID: m.ruleMatchID(dir, r.Action, rules.RuleOwnerTypePolicy, ri, types.ProtoToPolicyID(polID)),
					}
				}

				polTier.Policies[i] = policy
			}

			if endTierDrop && !stagedOnly && tier.DefaultAction != string(apiv3.Pass) {
				polTier.EndRuleID = m.endOfTierDropID(dir, tier.Name)
				polTier.EndAction = polprog.TierEndDeny
			} else {
				polTier.EndRuleID = m.endOfTierPassID(dir, tier.Name)
				polTier.EndAction = polprog.TierEndPass
			}

			rTiers = append(rTiers, polTier)
		}
	}
	return
}

func (m *bpfEndpointManager) extractProfiles(profileNames []string, direction PolDirection) (rProfiles []polprog.Profile) {
	dir := direction.RuleDir()
	if count := len(profileNames); count > 0 {
		rProfiles = make([]polprog.Profile, count)

		for i, profName := range profileNames {
			prof := m.profiles[types.ProfileID{Name: profName}]
			var prules []*proto.Rule
			if direction == PolDirnIngress {
				prules = prof.InboundRules
			} else {
				prules = prof.OutboundRules
			}
			profile := polprog.Profile{
				Name:  profName,
				Rules: make([]polprog.Rule, len(prules)),
			}

			for ri, r := range prules {
				profile.Rules[ri] = polprog.Rule{
					Rule:    r,
					MatchID: m.ruleMatchID(dir, r.Action, rules.RuleOwnerTypeProfile, ri, &types.ProfileID{Name: profName}),
				}
			}

			rProfiles[i] = profile
		}
	}
	return
}

func (m *bpfEndpointManager) extractRules(tiers []*proto.TierInfo, profileNames []string, direction PolDirection) polprog.Rules {
	var r polprog.Rules
	// When there is applicable normal policy that does not explicitly Allow or Deny traffic,
	// traffic is dropped.
	r.Tiers = m.extractTiers(tiers, direction, EndTierDrop)
	r.Profiles = m.extractProfiles(profileNames, direction)
	return r
}

func strToByte64(s string) [64]byte {
	var bytes [64]byte
	copy(bytes[:], []byte(s))
	return bytes
}

func (m *bpfEndpointManager) ruleMatchIDFromNFLOGPrefix(nflogPrefix string) polprog.RuleMatchID {
	if m.FlowLogsEnabled() {
		return m.lookupsCache.GetID64FromNFLOGPrefix(strToByte64(nflogPrefix))
	}
	// Lookup cache is not available, so generate an ID out of provided prefix.
	h := fnv.New64a()
	h.Write([]byte(nflogPrefix))
	return h.Sum64()
}

func (m *bpfEndpointManager) endOfTierPassID(dir rules.RuleDir, tier string) polprog.RuleMatchID {
	return m.ruleMatchIDFromNFLOGPrefix(rules.CalculateEndOfTierPassNFLOGPrefixStr(dir, tier))
}

func (m *bpfEndpointManager) endOfTierDropID(dir rules.RuleDir, tier string) polprog.RuleMatchID {
	return m.ruleMatchIDFromNFLOGPrefix(rules.CalculateEndOfTierDropNFLOGPrefixStr(dir, tier))
}

func (m *bpfEndpointManager) isWorkloadIface(iface string) bool {
	return m.workloadIfaceRegex.MatchString(iface)
}

func (m *bpfEndpointManager) isDataIface(iface string) bool {
	return m.dataIfaceRegex.MatchString(iface) ||
		(m.hostNetworkedNATMode != hostNetworkedNATDisabled && (iface == dataplanedefs.BPFOutDev || iface == "lo"))
}

func (m *bpfEndpointManager) FlowLogsEnabled() bool {
	return m.lookupsCache != nil
}

func (m *bpfEndpointManager) isL3Iface(iface string) bool {
	if m.l3IfaceRegex == nil {
		return false
	}
	return m.l3IfaceRegex.MatchString(iface)
}

func (m *bpfEndpointManager) addWEPToIndexes(wlID types.WorkloadEndpointID, wl *proto.WorkloadEndpoint) {
	for _, t := range wl.Tiers {
		m.addPolicyToEPMappings(t.Name, t.IngressPolicies, wlID)
		m.addPolicyToEPMappings(t.Name, t.EgressPolicies, wlID)
	}
	m.addProfileToEPMappings(wl.ProfileIds, wlID)
}

func (m *bpfEndpointManager) addPolicyToEPMappings(tier string, policies []*proto.PolicyID, id interface{}) {
	for _, p := range policies {
		polID := types.ProtoToPolicyID(p)
		if m.policiesToWorkloads[polID] == nil {
			m.policiesToWorkloads[polID] = set.New[any]()
		}
		m.policiesToWorkloads[polID].Add(id)
	}
}

func (m *bpfEndpointManager) addProfileToEPMappings(profileIds []string, id interface{}) {
	for _, profName := range profileIds {
		profID := types.ProfileID{Name: profName}
		profSet := m.profilesToWorkloads[profID]
		if profSet == nil {
			profSet = set.New[any]()
			m.profilesToWorkloads[profID] = profSet
		}
		profSet.Add(id)
	}
}

func (m *bpfEndpointManager) removeWEPFromIndexes(wlID types.WorkloadEndpointID, wep *proto.WorkloadEndpoint) {
	if wep == nil {
		return
	}

	for _, t := range wep.Tiers {
		m.removePolicyToEPMappings(t.Name, t.IngressPolicies, wlID)
		m.removePolicyToEPMappings(t.Name, t.EgressPolicies, wlID)
	}

	m.removeProfileToEPMappings(wep.ProfileIds, wlID)

	m.withIface(wep.Name, func(iface *bpfInterface) bool {
		iface.info.endpointID = nil
		return false
	})
}

func (m *bpfEndpointManager) removePolicyToEPMappings(tier string, policies []*proto.PolicyID, id interface{}) {
	for _, pol := range policies {
		polID := types.ProtoToPolicyID(pol)
		polSet := m.policiesToWorkloads[polID]
		if polSet == nil {
			continue
		}
		polSet.Discard(id)
		if polSet.Len() == 0 {
			// Defensive; we also clean up when the profile is removed.
			delete(m.policiesToWorkloads, polID)
		}
	}
}

func (m *bpfEndpointManager) removeProfileToEPMappings(profileIds []string, id any) {
	for _, profName := range profileIds {
		profID := types.ProfileID{Name: profName}
		profSet := m.profilesToWorkloads[profID]
		if profSet == nil {
			continue
		}
		profSet.Discard(id)
		if profSet.Len() == 0 {
			// Defensive; we also clean up when the policy is removed.
			delete(m.profilesToWorkloads, profID)
		}
	}
}

func (m *bpfEndpointManager) OnHEPUpdate(hostIfaceToEpMap map[string]*proto.HostEndpoint) {
	if m == nil {
		return
	}

	logrus.Debugf("HEP update from generic endpoint manager: %v", hostIfaceToEpMap)

	// Pre-process the map for the host-* endpoint: if there is a host-* endpoint, any host
	// interface without its own HEP should use the host-* endpoint's policy.
	wildcardHostEndpoint, wildcardExists := hostIfaceToEpMap[allInterfaces]
	if wildcardExists {
		logrus.Info("Host-* endpoint is configured")
		for ifaceName := range m.nameToIface {
			if _, specificExists := hostIfaceToEpMap[ifaceName]; (m.isDataIface(ifaceName) || m.isL3Iface(ifaceName)) && !specificExists {
				logrus.Infof("Use host-* endpoint policy for %v", ifaceName)
				hostIfaceToEpMap[ifaceName] = wildcardHostEndpoint
			}
		}
		delete(hostIfaceToEpMap, allInterfaces)
	}

	// If there are parts of proto.HostEndpoint that do not affect us, we could mask those out
	// here so that they can't cause spurious updates - at the cost of having different
	// proto.HostEndpoint data here than elsewhere.  For example, the ExpectedIpv4Addrs and
	// ExpectedIpv6Addrs fields.  But currently there are no fields that are sufficiently likely
	// to change as to make this worthwhile.

	// If the host-* endpoint is changing, mark all workload interfaces as dirty.
	if (wildcardExists != m.wildcardExists) || !reflect.DeepEqual(wildcardHostEndpoint, m.wildcardHostEndpoint) {
		logrus.Infof("Host-* endpoint is changing; was %v, now %v", m.wildcardHostEndpoint, wildcardHostEndpoint)
		m.removeHEPFromIndexes(allInterfaces, m.wildcardHostEndpoint)
		m.wildcardHostEndpoint = wildcardHostEndpoint
		m.wildcardExists = wildcardExists
		m.addHEPToIndexes(allInterfaces, wildcardHostEndpoint)
		for ifaceName := range m.nameToIface {
			if m.isWorkloadIface(ifaceName) {
				logrus.Info("Mark WEP iface dirty, for host-* endpoint change")
				m.dirtyIfaceNames.Add(ifaceName)
			}
		}
	}

	// Loop through existing host endpoints, in case they are changing or disappearing.
	for ifaceName, existingEp := range m.hostIfaceToEpMap {
		newEp, stillExists := hostIfaceToEpMap[ifaceName]
		if stillExists && reflect.DeepEqual(newEp, existingEp) {
			logrus.Debugf("No change to host endpoint for ifaceName=%v", ifaceName)
		} else {
			m.removeHEPFromIndexes(ifaceName, existingEp)
			if stillExists {
				logrus.Infof("Host endpoint changing for ifaceName=%v", ifaceName)
				m.addHEPToIndexes(ifaceName, newEp)
				m.hostIfaceToEpMap[ifaceName] = newEp
			} else {
				logrus.Infof("Host endpoint deleted for ifaceName=%v", ifaceName)
				delete(m.hostIfaceToEpMap, ifaceName)
			}
			m.dirtyIfaceNames.Add(ifaceName)
			m.dirtyIfaceNames.AddAll(m.hostIfaceTrees.getPhyDevices(ifaceName))
		}
		delete(hostIfaceToEpMap, ifaceName)
	}

	// Now anything remaining in hostIfaceToEpMap must be a new host endpoint.
	for ifaceName, newEp := range hostIfaceToEpMap {
		if !m.isDataIface(ifaceName) && !m.isL3Iface(ifaceName) {
			logrus.Warningf("Host endpoint configured for ifaceName=%v, but that doesn't match BPFDataIfacePattern/BPFL3IfacePattern; ignoring", ifaceName)
			continue
		}
		logrus.Infof("Host endpoint added for ifaceName=%v", ifaceName)
		m.addHEPToIndexes(ifaceName, newEp)
		m.hostIfaceToEpMap[ifaceName] = newEp
		m.dirtyIfaceNames.Add(ifaceName)
		m.dirtyIfaceNames.AddAll(m.hostIfaceTrees.getPhyDevices(ifaceName))
	}
}

func (m *bpfEndpointManager) addHEPToIndexes(ifaceName string, ep *proto.HostEndpoint) {
	if ep == nil {
		return
	}
	for _, tiers := range [][]*proto.TierInfo{ep.Tiers, ep.UntrackedTiers, ep.PreDnatTiers, ep.ForwardTiers} {
		for _, t := range tiers {
			m.addPolicyToEPMappings(t.Name, t.IngressPolicies, ifaceName)
			m.addPolicyToEPMappings(t.Name, t.EgressPolicies, ifaceName)
		}
	}
	m.addProfileToEPMappings(ep.ProfileIds, ifaceName)
}

func (m *bpfEndpointManager) removeHEPFromIndexes(ifaceName string, ep *proto.HostEndpoint) {
	if ep == nil {
		return
	}
	for _, tiers := range [][]*proto.TierInfo{ep.Tiers, ep.UntrackedTiers, ep.PreDnatTiers, ep.ForwardTiers} {
		for _, t := range tiers {
			m.removePolicyToEPMappings(t.Name, t.IngressPolicies, ifaceName)
			m.removePolicyToEPMappings(t.Name, t.EgressPolicies, ifaceName)
		}
	}

	m.removeProfileToEPMappings(ep.GetProfileIds(), ifaceName)
}

// Dataplane code.
//
// We don't yet have an enforced dividing line between the "manager" and "dataplane" parts of the
// BPF endpoint manager.  But we do have an indirection (the `dp` field) that allows us to UT the
// "manager" logic on its own, and it's useful to keep a separation in mind so that we can continue
// to UT in that way.
//
// As a small help for that, all of the "dataplane" code comes after this point in the file, and all
// of the "manager" code above.

func (m *bpfEndpointManager) setAcceptLocal(iface string, val bool) error {
	numval := "0"
	if val {
		numval = "1"
	}

	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/accept_local", iface)
	err := writeProcSys(path, numval)
	if err != nil {
		if _, errif := net.InterfaceByName(iface); errif == nil {
			logrus.WithField("err", err).Errorf("Failed to set %s to %s", path, numval)
			return err
		}
		logrus.Debugf("%s not set to %s - iface does not exist.", path, numval)
		return nil
	}

	logrus.Infof("%s set to %s", path, numval)
	return nil
}

func (m *bpfEndpointManager) setRPFilter(iface string, val int) error {
	// We only support IPv4 for now.
	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iface)
	numval := strconv.Itoa(val)
	err := writeProcSys(path, numval)
	if err != nil {
		logrus.WithField("err", err).Errorf("Failed to  set %s to %s", path, numval)
		return err
	}

	logrus.Infof("%s set to %s", path, numval)
	return nil
}

const jitHardenPath = "/proc/sys/net/core/bpf_jit_harden"

func (m *bpfEndpointManager) setJITHardening(val int) error {
	numval := strconv.Itoa(val)
	err := writeProcSys(jitHardenPath, numval)
	if err != nil {
		logrus.WithField("err", err).Errorf("Failed to set %s to %s", jitHardenPath, numval)
		return err
	}

	logrus.Infof("%s set to %s", jitHardenPath, numval)
	return nil
}

func (m *bpfEndpointManager) getJITHardening() (int, error) {
	data, err := os.ReadFile(jitHardenPath)
	if err != nil {
		return 0, err
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return val, nil
}

func (m *bpfEndpointManager) ensureStarted() {
	logrus.Info("Starting map cleanup runner.")

	var err error

	m.initAttaches, err = bpf.ListCalicoAttached()
	if err != nil {
		logrus.WithError(err).Warn("Failed to list previously attached programs. We may not clean up some.")
	}
}

func (m *bpfEndpointManager) reconcileBPFDevices(iface string) error {
	if m.hostNetworkedNATMode == hostNetworkedNATDisabled {
		return nil
	}

	vethPeer := dataplanedefs.BPFInDev
	if iface == dataplanedefs.BPFInDev {
		vethPeer = dataplanedefs.BPFOutDev
	}

	// Wait for both bpfin.cali and bpfout.cali to become oper UP
	// before configuring arp and rp_filter.
	intf, ok := m.nameToIface[vethPeer]
	if !ok || !intf.info.ifaceIsUp() {
		return nil
	}
	return m.dp.configureBPFDevices()
}

func (m *bpfEndpointManager) configureBPFDevices() error {
	bpfin, err := netlink.LinkByName(dataplanedefs.BPFInDev)
	if err != nil {
		return fmt.Errorf("missing %s after add: %w", dataplanedefs.BPFInDev, err)
	}

	bpfout, err := netlink.LinkByName(dataplanedefs.BPFOutDev)
	if err != nil {
		return fmt.Errorf("missing %s after add: %w", dataplanedefs.BPFOutDev, err)
	}

	if m.v6 != nil {
		anyV6, _ := ip.CIDRFromString("::/128")
		err = m.v6.ArpMap.Update(
			bpfarp.NewKeyV6(anyV6.Addr().AsNetIP(), uint32(m.natInIdx)).AsBytes(),
			bpfarp.NewValue(bpfin.Attrs().HardwareAddr, bpfout.Attrs().HardwareAddr).AsBytes(),
		)
	}
	if m.v4 != nil {
		anyV4, _ := ip.CIDRFromString("0.0.0.0/0")
		err = m.v4.ArpMap.Update(
			bpfarp.NewKey(anyV4.Addr().AsNetIP(), uint32(m.natInIdx)).AsBytes(),
			bpfarp.NewValue(bpfin.Attrs().HardwareAddr, bpfout.Attrs().HardwareAddr).AsBytes(),
		)
	}

	if err != nil {
		return fmt.Errorf("failed to program arp for natif: %w", err)
	}

	// Add a permanent ARP entry to point to the other side of the veth to avoid
	// ARP requests that would not be proxied if .all.rp_filter == 1
	arp := &netlink.Neigh{
		State:        netlink.NUD_PERMANENT,
		HardwareAddr: bpfout.Attrs().HardwareAddr,
		LinkIndex:    bpfin.Attrs().Index,
	}

	ipFamilies := []int{}
	if m.v4 != nil {
		ipFamilies = append(ipFamilies, netlink.FAMILY_V4)
	}
	if m.v6 != nil {
		ipFamilies = append(ipFamilies, netlink.FAMILY_V6)
	}

	for _, ipFamily := range ipFamilies {
		arp.Family = ipFamily
		arp.IP = bpfnatGW
		if ipFamily == netlink.FAMILY_V6 {
			arp.IP = bpfnatGWv6
		}
		retries := 10
		i := retries
		for {
			if err := netlink.NeighAdd(arp); err != nil && err != syscall.EEXIST {
				logrus.WithError(err).Warnf("Failed to update neigh for %s (arp %#v), retrying.", dataplanedefs.BPFOutDev, arp)
				i--
				if i > 0 {
					time.Sleep(250 * time.Millisecond)
					continue
				} else {
					return fmt.Errorf("failed to update neigh for %s (arp %#v) after %d tries: %w",
						dataplanedefs.BPFOutDev, arp, retries, err)
				}
			}
			break
		}
	}
	logrus.Infof("Updated neigh for %s (arp %v)", dataplanedefs.BPFOutDev, arp)

	if m.v4 != nil {
		if err := configureProcSysForInterface(dataplanedefs.BPFInDev, 4, "0", writeProcSys); err != nil {
			return fmt.Errorf("failed to configure %s parameters: %w", dataplanedefs.BPFOutDev, err)
		}
		if err := configureProcSysForInterface(dataplanedefs.BPFOutDev, 4, "0", writeProcSys); err != nil {
			return fmt.Errorf("failed to configure %s parameters: %w", dataplanedefs.BPFOutDev, err)
		}
	}

	return nil
}

func (m *bpfEndpointManager) ensureBPFDevices() error {
	if m.hostNetworkedNATMode == hostNetworkedNATDisabled {
		return nil
	}

	var bpfout, bpfin netlink.Link

	bpfin, err := netlink.LinkByName(dataplanedefs.BPFInDev)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = dataplanedefs.BPFInDev
		la.MTU = m.bpfIfaceMTU
		nat := &netlink.Veth{
			LinkAttrs: la,
			PeerName:  dataplanedefs.BPFOutDev,
		}
		if err := netlink.LinkAdd(nat); err != nil {
			return fmt.Errorf("failed to add %s: %w", dataplanedefs.BPFInDev, err)
		}
		bpfin, err = netlink.LinkByName(dataplanedefs.BPFInDev)
		if err != nil {
			return fmt.Errorf("missing %s after add: %w", dataplanedefs.BPFInDev, err)
		}
	}

	if state := bpfin.Attrs().OperState; state != netlink.OperUp {
		logrus.WithField("state", state).Info(dataplanedefs.BPFInDev)
		if err := netlink.LinkSetUp(bpfin); err != nil {
			return fmt.Errorf("failed to set %s up: %w", dataplanedefs.BPFInDev, err)
		}
	}

	bpfout, err = netlink.LinkByName(dataplanedefs.BPFOutDev)
	if err != nil {
		return fmt.Errorf("missing %s after add: %w", dataplanedefs.BPFOutDev, err)
	}
	if state := bpfout.Attrs().OperState; state != netlink.OperUp {
		logrus.WithField("state", state).Info(dataplanedefs.BPFOutDev)
		if err := netlink.LinkSetUp(bpfout); err != nil {
			return fmt.Errorf("failed to set %s up: %w", dataplanedefs.BPFOutDev, err)
		}
	}

	err = netlink.LinkSetMTU(bpfin, m.bpfIfaceMTU)
	if err != nil {
		return fmt.Errorf("failed to set MTU to %d on %s: %w", m.bpfIfaceMTU, dataplanedefs.BPFInDev, err)
	}

	err = netlink.LinkSetMTU(bpfout, m.bpfIfaceMTU)
	if err != nil {
		return fmt.Errorf("failed to set MTU to %d on %s: %w", m.bpfIfaceMTU, dataplanedefs.BPFOutDev, err)
	}

	m.natInIdx = bpfin.Attrs().Index
	m.natOutIdx = bpfout.Attrs().Index

	_, err = m.ensureQdisc(dataplanedefs.BPFInDev)
	if err != nil {
		return fmt.Errorf("failed to set qdisc on %s: %w", dataplanedefs.BPFOutDev, err)
	}

	_, err = m.ensureQdisc("lo")
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to set qdisc on lo.")
	}

	// Setup a link local route to a nonexistent link local address that would
	// serve as a gateway to route services via bpfnat veth rather than having
	// link local routes for each service that would trigger ARP queries.
	if m.v4 != nil {
		m.routeTableV4.RouteUpdate(dataplanedefs.BPFInDev, routetable.Target{
			Type: routetable.TargetTypeLinkLocalUnicast,
			CIDR: bpfnatGWCIDR,
		})
	}
	if m.v6 != nil {
		m.routeTableV6.RouteUpdate(dataplanedefs.BPFInDev, routetable.Target{
			Type: routetable.TargetTypeLinkLocalUnicast,
			CIDR: bpfnatGWCIDRv6,
		})
	}

	return nil
}

func (m *bpfEndpointManager) ensureQdisc(iface string) (bool, error) {
	if m.bpfAttachType == apiv3.BPFAttachOptionTCX {
		return true, nil
	}
	return tc.EnsureQdisc(iface)
}

func (m *bpfEndpointManager) loadTCObj(at hook.AttachType, pm *hook.ProgramsMap) (hook.Layout, error) {
	layout, err := pm.LoadObj(at, string(m.bpfAttachType))
	if err != nil {
		return nil, err
	}

	if at.LogLevel != "debug" {
		return layout, nil
	}

	at.LogLevel = "off"
	layoutNoDebug, err := pm.LoadObj(at, string(m.bpfAttachType))
	if err != nil {
		return nil, err
	}

	return hook.MergeLayouts(layoutNoDebug, layout), nil
}

// Ensure TC/XDP program is attached to the specified interface.
func (m *bpfEndpointManager) ensureProgramLoaded(ap attachPoint, ipFamily proto.IPVersion) error {
	var err error

	if aptc, ok := ap.(*tc.AttachPoint); ok {
		at := hook.AttachType{
			Hook:       aptc.HookName(),
			Type:       aptc.Type,
			LogLevel:   aptc.LogLevel,
			ToHostDrop: aptc.ToHostDrop,
			DSR:        aptc.DSR,
		}

		at.Family = int(ipFamily)
		policyIdx := aptc.PolicyIdxV4
		ap.Log().Debugf("ensureProgramLoaded %d", ipFamily)
		if ipFamily == proto.IPVersion_IPV6 {
			if aptc.HookLayoutV6, err = m.loadTCObj(at, aptc.ProgramsMap.(*hook.ProgramsMap)); err != nil {
				return fmt.Errorf("loading generic v%d tc hook program: %w", ipFamily, err)
			}
			policyIdx = aptc.PolicyIdxV6
		} else {
			if aptc.HookLayoutV4, err = m.loadTCObj(at, aptc.ProgramsMap.(*hook.ProgramsMap)); err != nil {
				return fmt.Errorf("loading generic v%d tc hook program: %w", ipFamily, err)
			}
		}

		jmpMap := m.commonMaps.JumpMaps[aptc.Hook]
		// Load default policy before the real policy is created and loaded.
		switch at.DefaultPolicy() {
		case hook.DefPolicyAllow:
			err = maps.UpdateMapEntry(jmpMap.MapFD(),
				jump.Key(policyIdx), jump.Value(m.policyTcAllowFDs[aptc.Hook].FD()))
		case hook.DefPolicyDeny:
			err = maps.UpdateMapEntry(jmpMap.MapFD(),
				jump.Key(policyIdx), jump.Value(m.policyTcDenyFDs[aptc.Hook].FD()))
		}

		if err != nil {
			return fmt.Errorf("failed to set default policy: %w", err)
		}
	} else if apxdp, ok := ap.(*xdp.AttachPoint); ok {
		at := hook.AttachType{
			Hook:     hook.XDP,
			LogLevel: apxdp.LogLevel,
		}

		at.Family = int(ipFamily)
		pm := m.commonMaps.XDPProgramsMap.(*hook.ProgramsMap)
		if ipFamily == proto.IPVersion_IPV6 {
			if apxdp.HookLayoutV6, err = pm.LoadObj(at, ""); err != nil {
				return fmt.Errorf("loading generic xdp hook program: %w", err)
			}
		} else {
			if apxdp.HookLayoutV4, err = pm.LoadObj(at, ""); err != nil {
				return fmt.Errorf("loading generic xdp hook program: %w", err)
			}
		}
	} else {
		return fmt.Errorf("unknown attach type")
	}
	return nil
}

// Ensure that the specified attach point does not have our program.
func (m *bpfEndpointManager) ensureNoProgram(ap attachPoint) error {
	// Ensure interface does not have our program attached.
	err := ap.DetachProgram()
	var state bpfInterfaceState
	m.ifacesLock.Lock()
	m.withIface(ap.IfaceName(), func(iface *bpfInterface) bool {
		state = iface.dpState
		return false
	})
	m.ifacesLock.Unlock()

	if m.v4 != nil {
		if err := m.jumpMapDelete(ap.HookName(), state.v4.policyIdx[ap.HookName()]); err != nil {
			logrus.WithError(err).Warn("Policy program may leak.")
		}
		m.removePolicyDebugInfo(ap.IfaceName(), 4, ap.HookName())
	}
	// Forget the policy debug info
	if m.v6 != nil {
		if err := m.jumpMapDelete(ap.HookName(), state.v6.policyIdx[ap.HookName()]); err != nil {
			logrus.WithError(err).Warn("Policy program may leak.")
		}
		m.removePolicyDebugInfo(ap.IfaceName(), 6, ap.HookName())
	}

	// Clean up QoS map
	qosIngressKey := qos.NewKey(uint32(ap.IfaceIndex()), 1) // ingress=1
	qosErr := m.QoSMap.Delete(qosIngressKey.AsBytes())
	if qosErr != nil && !errors.Is(qosErr, os.ErrNotExist) {
		err = qosErr
		logrus.WithError(err).Warn("QoS map may leak.")
	}
	qosEgressKey := qos.NewKey(uint32(ap.IfaceIndex()), 0) // ingress=0
	qosErr = m.QoSMap.Delete(qosEgressKey.AsBytes())
	if qosErr != nil && !errors.Is(qosErr, os.ErrNotExist) {
		err = qosErr
		logrus.WithError(err).Warn("QoS map may leak.")
	}

	return err
}

func (m *bpfEndpointManager) removeIfaceAllPolicyDebugInfo(ifaceName string) {
	for _, ipFamily := range []proto.IPVersion{proto.IPVersion_IPV4, proto.IPVersion_IPV6} {
		for _, hook := range hook.All {
			m.removePolicyDebugInfo(ifaceName, ipFamily, hook)
		}
	}
}

func (m *bpfEndpointManager) removePolicyDebugInfo(ifaceName string, ipFamily proto.IPVersion, hook hook.Hook) {
	if !m.bpfPolicyDebugEnabled {
		return
	}
	filename := bpf.PolicyDebugJSONFileName(ifaceName, hook.String(), ipFamily)
	err := os.Remove(filename)
	if err != nil {
		logrus.WithError(err).Debugf("Failed to remove the policy debug file %v. Ignoring", filename)
	}
}

func (m *bpfEndpointManager) writePolicyDebugInfo(insns []asm.Insns, ifaceName string, ipFamily proto.IPVersion, polDir string, h hook.Hook, polErr error) error {
	if !m.bpfPolicyDebugEnabled {
		return nil
	}
	if err := os.MkdirAll(bpf.RuntimePolDir, 0o600); err != nil {
		return err
	}

	errStr := ""
	if polErr != nil {
		errStr = polErr.Error()
	}

	// We may have >1 sub-program; it seems to work reasonably well to just
	// concatenate the instructions.  The policy program builder writes
	// comments that delineate the programs.
	var combinedInsns asm.Insns
	if len(insns) > 0 {
		combinedInsns = insns[0]
		for _, ins := range insns[1:] {
			combinedInsns = append(combinedInsns, ins...)
		}
	}
	policyDebugInfo := bpf.PolicyDebugInfo{
		IfaceName:  ifaceName,
		Hook:       "tc " + h.String(),
		PolicyInfo: combinedInsns,
		Error:      errStr,
	}

	filename := bpf.PolicyDebugJSONFileName(ifaceName, strings.ToLower(polDir), ipFamily)
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	err := encoder.Encode(policyDebugInfo)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filename, buffer.Bytes(), 0o600); err != nil {
		return err
	}
	logrus.Debugf("Policy iface %s hook %s written to %s", ifaceName, h, filename)
	return nil
}

func (m *bpfEndpointManager) updatePolicyProgram(rules polprog.Rules, polDir string, ap attachPoint, ipFamily proto.IPVersion) error {
	progName := policyProgramName(ap.IfaceName(), polDir, proto.IPVersion(ipFamily))

	var opts []polprog.Option
	if apj, ok := ap.(attachPointWithPolicyJumps); ok {
		allow := apj.PolicyAllowJumpIdx(int(ipFamily))
		if allow == -1 {
			return fmt.Errorf("no allow jump index")
		}

		deny := apj.PolicyDenyJumpIdx(int(ipFamily))
		if deny == -1 {
			return fmt.Errorf("no deny jump index")
		}
		opts = append(opts, polprog.WithAllowDenyJumps(allow, deny))
	}
	insns, err := m.doUpdatePolicyProgram(
		ap,
		ap.HookName(),
		progName,
		ap.PolicyJmp(ipFamily),
		rules,
		ipFamily,
		opts...,
	)
	perr := m.writePolicyDebugInfo(insns, ap.IfaceName(), ipFamily, polDir, ap.HookName(), err)
	if perr != nil {
		logrus.WithError(perr).Warn("error writing policy debug information")
	}
	if err != nil {
		return fmt.Errorf("failed to update policy program v%d: %w", ipFamily, err)
	}

	return nil
}

func (m *bpfEndpointManager) loadTCLogFilter(ap *tc.AttachPoint) (fileDescriptor, int, error) {
	programsMapFD := ap.ProgramsMap.MapFD()
	logFilter, err := filter.New(ap.Type, 64, ap.LogFilter, programsMapFD, m.commonMaps.StateMap.MapFD())
	if err != nil {
		return nil, 0, err
	}

	attachType := uint32(0)
	if m.bpfAttachType == apiv3.BPFAttachOptionTCX {
		attachType = libbpf.AttachTypeTcxIngress
		if ap.Hook == hook.Egress {
			attachType = libbpf.AttachTypeTcxEgress
		}
	}
	fd, err := bpf.LoadBPFProgramFromInsnsWithAttachType(logFilter, "calico_log_filter",
		"Apache-2.0", uint32(unix.BPF_PROG_TYPE_SCHED_CLS), attachType)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to load BPF log filter program: %w", err)
	}

	return fd, ap.LogFilterIdx, nil
}

func (m *bpfEndpointManager) updateLogFilter(ap attachPoint) error {
	switch t := ap.(type) {
	case *tc.AttachPoint:
		fd, idx, err := m.dp.loadTCLogFilter(t)
		if err != nil {
			return err
		}
		defer fd.Close()
		if err := m.commonMaps.JumpMaps[t.Hook].Update(jump.Key(idx), jump.Value(fd.FD())); err != nil {
			return fmt.Errorf("failed to update %s policy jump map [%d]=%d: %w", ap.HookName(), idx, fd.FD(), err)
		}

		ap.Log().Debugf("Loaded filter at %d", idx)
	default:
		return fmt.Errorf("log filters not supported for %T attach points", ap)
	}

	return nil
}

func policyProgramName(iface, polDir string, ipFamily proto.IPVersion) string {
	version := "4"
	if ipFamily == proto.IPVersion_IPV6 {
		version = "6"
	}

	return fmt.Sprintf("p%v%c_%s", version, polDir[0], iface)
}

func (m *bpfEndpointManager) loadPolicyProgram(
	progName string,
	ipFamily proto.IPVersion,
	rules polprog.Rules,
	staticProgsMap maps.Map,
	polProgsMap maps.Map,
	attachType uint32,
	opts ...polprog.Option,
) (
	fd []fileDescriptor, insns []asm.Insns, err error,
) {
	logrus.WithFields(logrus.Fields{
		"progName": progName,
		"ipFamily": ipFamily,
	}).Debug("Generating policy program...")

	ipsetsMapFD := m.v4.IpsetsMap.MapFD()
	ipSetIDAlloc := m.v4.ipSetIDAlloc
	if ipFamily == proto.IPVersion_IPV6 {
		opts = append(opts, polprog.WithIPv6())
		ipsetsMapFD = m.v6.IpsetsMap.MapFD()
		ipSetIDAlloc = m.v6.ipSetIDAlloc
	}

	if m.FlowLogsEnabled() {
		opts = append(opts, polprog.WithFlowLogs())
	}

	pg := polprog.NewBuilder(
		ipSetIDAlloc,
		ipsetsMapFD,
		m.commonMaps.StateMap.MapFD(),
		staticProgsMap.MapFD(),
		polProgsMap.MapFD(),
		opts...,
	)
	programs, err := pg.Instructions(rules)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate policy bytecode v%v: %w", ipFamily, err)
	}
	progType := unix.BPF_PROG_TYPE_SCHED_CLS
	if rules.ForXDP {
		progType = unix.BPF_PROG_TYPE_XDP
	}

	progFDs := make([]fileDescriptor, 0, len(programs))
	success := false
	defer func() {
		if success {
			return
		}
		for _, progFD := range progFDs {
			if err := progFD.Close(); err != nil {
				logrus.WithError(err).Panic("Failed to close program FD.")
			}
		}
	}()
	for i, p := range programs {
		subProgName := progName
		if i > 0 {
			if len(subProgName) > 12 {
				subProgName = subProgName[:12]
			}
			subProgName = fmt.Sprintf("%s_%d", subProgName, i)
		}
		progFD, err := bpf.LoadBPFProgramFromInsnsWithAttachType(p, subProgName, "Apache-2.0", uint32(progType), attachType)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"name":       subProgName,
				"subProgram": i,
			}).Error("Failed to load BPF policy program")
			return nil, nil, fmt.Errorf("failed to load BPF policy program %v: %w", ipFamily, err)
		}
		progFDs = append(progFDs, progFD)
	}
	success = true
	return progFDs, programs, nil
}

func (m *bpfEndpointManager) doUpdatePolicyProgram(
	ap attachPoint,
	hk hook.Hook,
	progName string,
	polJumpMapIdx int,
	rules polprog.Rules,
	ipFamily proto.IPVersion,
	opts ...polprog.Option,
) ([]asm.Insns, error) {
	if m.bpfPolicyDebugEnabled {
		opts = append(opts, polprog.WithPolicyDebugEnabled())
	}

	staticProgsMap := m.commonMaps.XDPProgramsMap
	polProgsMap := m.commonMaps.XDPJumpMap
	attachType := uint32(0)
	if apTc, ok := ap.(*tc.AttachPoint); ok {
		staticProgsMap = apTc.ProgramsMap
		polProgsMap = m.commonMaps.JumpMaps[apTc.Hook]
		if m.bpfAttachType == apiv3.BPFAttachOptionTCX {
			attachType = libbpf.AttachTypeTcxIngress
			if apTc.Hook == hook.Egress {
				attachType = libbpf.AttachTypeTcxEgress
			}
		}
	}

	// If we have to break a program up into sub-programs to please the
	// verifier then we store the sub-programs at
	// polJumpMapIdx + subProgNo * stride.
	stride := jump.TCMaxEntryPoints
	if hk == hook.XDP {
		polProgsMap = m.commonMaps.XDPJumpMap
		stride = jump.XDPMaxEntryPoints
	}
	opts = append(opts, polprog.WithPolicyMapIndexAndStride(polJumpMapIdx, stride))

	tstrideOrig := int(m.policyTrampolineStride.Load())
	tstride := tstrideOrig

	var (
		progFDs []fileDescriptor
		insns   []asm.Insns
	)

	for {
		var err error

		options := append(opts, polprog.WithTrampolineStride(tstride))
		progFDs, insns, err = m.loadPolicyProgramFn(
			progName,
			ipFamily,
			rules,
			staticProgsMap,
			polProgsMap,
			attachType,
			options...,
		)
		if err != nil {
			if errors.Is(err, unix.ERANGE) {
				if tstride >= 1000 {
					tstride -= tstride / 4
					tmp := m.policyTrampolineStride.Load()
					if tmp < int32(tstride) {
						tstride = int(tmp)
					}
					logrus.Debugf("Reducing trampoline stride to %d and retrying", tstride)
					continue
				} else {
					return nil, fmt.Errorf("reducing trampoline stride below 1000 not practical")
				}
			} else {
				return nil, err
			}
		} else {
			break
		}
	}

	for tstride < tstrideOrig {
		if m.policyTrampolineStride.CompareAndSwap(int32(tstrideOrig), int32(tstride)) {
			logrus.Warnf("Reducing policy program trampoline stride to %d", tstride)
		} else {
			tstrideOrig = int(m.policyTrampolineStride.Load())
		}
	}

	defer func() {
		for _, progFD := range progFDs {
			// Once we've put the programs in the map, we don't need their FDs.
			if err := progFD.Close(); err != nil {
				logrus.WithError(err).Panic("Failed to close program FD.")
			}
		}
	}()

	for i, progFD := range progFDs {
		subProgIdx := polprog.SubProgramJumpIdx(polJumpMapIdx, i, stride)
		logrus.Debugf("Putting sub-program %d at position %d", i, subProgIdx)
		if err := polProgsMap.Update(jump.Key(subProgIdx), jump.Value(progFD.FD())); err != nil {
			return nil, fmt.Errorf("failed to update %s policy jump map [%d]=%d: %w", hk, subProgIdx, progFD, err)
		}
	}
	for i := len(progFDs); i < jump.MaxSubPrograms; i++ {
		subProgIdx := polprog.SubProgramJumpIdx(polJumpMapIdx, i, stride)
		if err := polProgsMap.Delete(jump.Key(subProgIdx)); err != nil {
			if os.IsNotExist(err) {
				break
			}
			logrus.WithError(err).Warn("Unexpected error while trying to clean up old policy programs.")
		}
	}

	return insns, nil
}

func (m *bpfEndpointManager) jumpMapDelete(h hook.Hook, idx int) error {
	if idx < 0 {
		return nil
	}

	jumpMap := m.commonMaps.XDPJumpMap
	stride := jump.XDPMaxEntryPoints
	if h != hook.XDP {
		jumpMap = m.commonMaps.JumpMaps[h]
		stride = jump.TCMaxEntryPoints
	}

	return jumpMapDeleteEntry(jumpMap, idx, stride)
}

func (m *bpfEndpointManager) removePolicyProgram(ap attachPoint, ipFamily proto.IPVersion) error {
	idx := ap.PolicyJmp(ipFamily)
	if idx == -1 {
		return fmt.Errorf("invalid policy jump map idx %d", idx)
	}

	var pm maps.Map
	var stride int
	if ap.HookName() == hook.XDP {
		stride = jump.XDPMaxEntryPoints
		pm = m.commonMaps.XDPJumpMap
	} else {
		stride = jump.TCMaxEntryPoints
		pm = m.commonMaps.JumpMaps[ap.HookName()]
	}

	if err := jumpMapDeleteEntry(pm, idx, stride); err != nil {
		return fmt.Errorf("removing policy iface %s hook %s: %w", ap.IfaceName(), ap.HookName(), err)
	}

	m.removePolicyDebugInfo(ap.IfaceName(), ipFamily, ap.HookName())
	return nil
}

func FindJumpMap(progID int, ifaceName string) (mapFD maps.FD, err error) {
	logCtx := logrus.WithField("progID", progID).WithField("iface", ifaceName)
	logCtx.Debugf("Looking up jump map")
	bpftool := exec.Command("bpftool", "prog", "show", "id",
		fmt.Sprintf("%d", progID), "--json")
	output, err := bpftool.Output()
	if err != nil {
		// We can hit this case if the interface was deleted underneath us; check that it's still there.
		if _, err := os.Stat(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s", ifaceName)); os.IsNotExist(err) {
			return 0, tc.ErrDeviceNotFound
		}
		return 0, fmt.Errorf("failed to get map metadata: %w out=\n%v", err, string(output))
	}
	var prog struct {
		MapIDs []int `json:"map_ids"`
	}
	err = json.Unmarshal(output, &prog)
	if err != nil {
		return 0, fmt.Errorf("failed to parse bpftool output: %w", err)
	}

	for _, mapID := range prog.MapIDs {
		mapFD, err := maps.GetMapFDByID(mapID)
		if err != nil {
			return 0, fmt.Errorf("failed to get map FD from ID: %w", err)
		}
		mapInfo, err := maps.GetMapInfo(mapFD)
		if err != nil {
			err = mapFD.Close()
			if err != nil {
				logrus.WithError(err).Panic("Failed to close FD.")
			}
			return 0, fmt.Errorf("failed to get map info: %w", err)
		}
		if mapInfo.Type == unix.BPF_MAP_TYPE_PROG_ARRAY {
			logCtx.WithField("fd", mapFD).Debug("Found jump map")
			return mapFD, nil
		}
		err = mapFD.Close()
		if err != nil {
			logrus.WithError(err).Panic("Failed to close FD.")
		}
	}

	return 0, fmt.Errorf("failed to find jump map for iface=%s progID=%d", ifaceName, progID)
}

func (d *bpfEndpointManagerDataplane) getInterfaceIP(ifaceName string) (*net.IP, error) {
	var ipAddrs []net.IP
	if ip, ok := d.ifaceToIpMap[ifaceName]; ok {
		return &ip, nil
	}
	intf, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}
	logrus.Debugf("Addrs for dev %s : %v", ifaceName, addrs)
	for _, addr := range addrs {
		switch t := addr.(type) {
		case *net.IPNet:
			ipAddrs = append(ipAddrs, t.IP)
		}
	}
	sort.Slice(ipAddrs, func(i, j int) bool {
		return bytes.Compare(ipAddrs[i], ipAddrs[j]) < 0
	})
	if len(ipAddrs) > 0 {
		return &ipAddrs[0], nil
	}
	return nil, errors.New("interface ip address not found")
}

func (m *bpfEndpointManager) onServiceUpdate(update *proto.ServiceUpdate) {
	if m.hostNetworkedNATMode == hostNetworkedNATDisabled {
		return
	}

	if m.hostNetworkedNATMode == hostNetworkedNATUDPOnly {
		hasUDP := false

		for _, port := range update.Ports {
			if port.Protocol == "UDP" {
				hasUDP = true
				break
			}
		}

		if !hasUDP {
			return // skip services that do not have UDP ports
		}
	}

	logrus.WithFields(logrus.Fields{
		"Name":      update.Name,
		"Namespace": update.Namespace,
	}).Info("Service Update")

	ipstr := make([]string, 0, 2)
	if len(update.ClusterIps) > 0 {
		ipstr = append(ipstr, update.ClusterIps...)
	}
	if update.LoadbalancerIp != "" {
		ipstr = append(ipstr, update.LoadbalancerIp)
	}

	key := serviceKey{name: update.Name, namespace: update.Namespace}

	ips := make([]ip.CIDR, 0, len(ipstr))
	for _, i := range ipstr {
		if i == k8sv1.ClusterIPNone {
			// Headless services have an explicit "None" value for ClusterIPs.
			continue
		}
		cidr, err := ip.ParseCIDROrIP(i)
		if err != nil {
			logrus.WithFields(logrus.Fields{"service": key, "ip": i}).Warn("Not a valid CIDR.")
		} else {
			_, v := m.natExcludedCIDRs.LPM(cidr)
			if v != nil {
				continue
			}
			if m.v6 != nil {
				if _, ok := cidr.(ip.V6CIDR); ok {
					ips = append(ips, cidr)
				}
			}
			if m.v4 != nil {
				if _, ok := cidr.(ip.V4CIDR); ok {
					ips = append(ips, cidr)
				}
			}
		}
	}

	// Check which IPs have been removed (no-op if we haven't seen it yet)
	for _, old := range m.services[key] {
		exists := false
		for _, svcIP := range ips {
			if old == svcIP {
				exists = true
				break
			}
		}
		if !exists {
			m.dp.delRoute(old)
		}
	}

	m.services[key] = ips
	m.dirtyServices.Add(key)
}

func (m *bpfEndpointManager) onServiceRemove(update *proto.ServiceRemove) {
	if m.hostNetworkedNATMode == hostNetworkedNATDisabled {
		return
	}

	logrus.WithFields(logrus.Fields{
		"Name":      update.Name,
		"Namespace": update.Namespace,
	}).Info("Service Remove")

	key := serviceKey{name: update.Name, namespace: update.Namespace}

	for _, svcIP := range m.services[key] {
		m.dp.delRoute(svcIP)
	}

	delete(m.services, key)
}

var (
	bpfnatGW       = net.ParseIP("169.254.1.1")
	bpfnatGWIP     = ip.FromNetIP(bpfnatGW)
	bpfnatGWCIDR   = ip.CIDRFromAddrAndPrefix(bpfnatGWIP, 32)
	bpfnatGWv6     = net.ParseIP("2001:db8::1")
	bpfnatGWIPv6   = ip.FromNetIP(bpfnatGWv6)
	bpfnatGWCIDRv6 = ip.CIDRFromAddrAndPrefix(bpfnatGWIPv6, 128)
)

func (m *bpfEndpointManager) setRoute(cidr ip.CIDR) {
	target := routetable.Target{
		Type: routetable.TargetTypeGlobalUnicast,
		CIDR: cidr,
	}

	if cidr.Version() == 6 {
		if m.v6 != nil && m.v6.hostIP != nil {
			target.GW = bpfnatGWIPv6
			target.Src = ip.FromNetIP(m.v6.hostIP)
			m.routeTableV6.RouteUpdate(dataplanedefs.BPFInDev, target)
		}
	} else if m.v4 != nil && m.v4.hostIP != nil {
		target.GW = bpfnatGWIP
		target.Src = ip.FromNetIP(m.v4.hostIP)
		m.routeTableV4.RouteUpdate(dataplanedefs.BPFInDev, target)
	}

	logrus.WithFields(logrus.Fields{
		"cidr": cidr,
	}).Debug("setRoute")
}

func (m *bpfEndpointManager) delRoute(cidr ip.CIDR) {
	if m.v6 != nil && cidr.Version() == 6 {
		m.routeTableV6.RouteRemove(dataplanedefs.BPFInDev, cidr)
	}
	if m.v4 != nil && cidr.Version() == 4 {
		m.routeTableV4.RouteRemove(dataplanedefs.BPFInDev, cidr)
	}
	logrus.WithFields(logrus.Fields{
		"cidr": cidr,
	}).Debug("delRoute")
}

func (m *bpfEndpointManager) updatePolicyCacheProfile(id types.ProfileID, inboundRules, outboundRules []*proto.Rule) {
	m.updateCache(id, id.Name, "Profile", inboundRules, outboundRules)
}

// updatePolicyCache modifies entries in the cache, adding new entries and marking old entries dirty.
func (m *bpfEndpointManager) updatePolicyCache(id types.PolicyID, inboundRules, outboundRules []*proto.Rule) {
	// Build a unique string name for the policy
	name := id.String()
	m.updateCache(id, name, "Policy", inboundRules, outboundRules)
}

func (m *bpfEndpointManager) updateCache(id types.IDMaker, name, owner string, inboundRules, outboundRules []*proto.Rule) {
	ruleIds := set.New[polprog.RuleMatchID]()
	if val, ok := m.polNameToMatchIDs[id.ID()]; ok {
		// If the policy name exists, it means the policy is updated. There are cases where both inbound,
		// outbound rules are updated or any one.
		// Mark all the entries as dirty.
		m.dirtyRules.AddSet(val)
	}
	// Now iterate through all the rules and if the ruleIds are already in the cache, it means the rule has not
	// changed as part of the update. Remove the dirty flag and add this entry back as non-dirty.
	for idx, rule := range inboundRules {
		ruleIds.Add(m.addRuleInfo(id, rule, idx, owner, PolDirnIngress, name))
	}
	for idx, rule := range outboundRules {
		ruleIds.Add(m.addRuleInfo(id, rule, idx, owner, PolDirnEgress, name))
	}
	m.polNameToMatchIDs[id.ID()] = ruleIds
}

func (m *bpfEndpointManager) addRuleInfo(id types.IDMaker, rule *proto.Rule, idx int, owner string, direction PolDirection, polName string) polprog.RuleMatchID {
	ruleOwner := rules.RuleOwnerTypePolicy
	if owner == "Profile" {
		ruleOwner = rules.RuleOwnerTypeProfile
	}
	matchID := m.dp.ruleMatchID(direction.RuleDir(), rule.Action, ruleOwner, idx, id)
	m.dirtyRules.Discard(matchID)

	return matchID
}

func (m *bpfEndpointManager) ruleMatchID(
	dir rules.RuleDir,
	action string,
	owner rules.RuleOwnerType,
	idx int,
	id types.IDMaker,
) polprog.RuleMatchID {
	var a rules.RuleAction
	switch action {
	case "", "allow":
		a = rules.RuleActionAllow
	case "next-tier", "pass":
		a = rules.RuleActionPass
	case "deny":
		a = rules.RuleActionDeny
	case "log":
		// If we get it here, we dont know what to do about that, 0 means
		// invalid, but does not break anything.
		return 0
	default:
		logrus.WithField("action", action).Panic("Unknown rule action")
	}

	return m.ruleMatchIDFromNFLOGPrefix(rules.CalculateNFLOGPrefixStr(a, owner, dir, idx, id))
}

func (m *bpfEndpointManager) getIfaceLink(name string) (netlink.Link, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	return link, nil
}

func (m *bpfEndpointManager) getNumEPs() int {
	return len(m.nameToIface)
}

func (m *bpfEndpointManager) getIfaceTypeFromLink(link netlink.Link) IfaceType {
	attrs := link.Attrs()
	if attrs.Slave != nil && attrs.Slave.SlaveType() == "bond" {
		return IfaceTypeBondSlave
	}

	switch link.Type() {
	case "ipip":
		return IfaceTypeIPIP
	case "wireguard":
		return IfaceTypeWireguard
	case "vxlan":
		return IfaceTypeVXLAN
	case "bond":
		return IfaceTypeBond
	case "tuntap":
		if link.(*netlink.Tuntap).Mode == netlink.TUNTAP_MODE_TUN {
			return IfaceTypeL3
		}
	default:
		// Loopback device.
		if attrs.Flags&net.FlagLoopback > 0 {
			return IfaceTypeData
		}

		ifa, err := net.InterfaceByName(attrs.Name)
		if err == nil {
			addrs, err := ifa.Addrs()
			if err == nil {
				if len(attrs.HardwareAddr) == 0 && len(addrs) > 0 {
					return IfaceTypeL3
				}
			}
		}
		if m.isL3Iface(attrs.Name) {
			return IfaceTypeL3
		}
	}
	return IfaceTypeData
}

func (trees bpfIfaceTrees) getPhyDevices(masterIfName string) []string {
	hostIf := trees.findIfaceByName(masterIfName)
	if hostIf == nil {
		logrus.Errorf("error finding interface %s", masterIfName)
		return []string{}
	}

	if len(hostIf.children) > 0 {
		return getLeafNodes(hostIf)
	}
	return []string{}
}

func (trees bpfIfaceTrees) addIfaceStandAlone(intf *bpfIfaceNode) {
	// Check if the interface already exists in the tree.
	val := trees.findIfaceByIndex(intf.index)
	if val != nil {
		// If the interface had a master and now it has an update
		// as a standalone interface, it means the interface is moving
		// away, e.g. out of bond. Delete the interface, and add the interface
		// as a standalone one.
		if val.masterIndex != 0 {
			trees.deleteIface(intf.name)
		} else {
			// We might have created this interface.
			// Hence just update the name of the interface, without overwriting the
			// child information. Since we add the parent interface to the tree when
			// adding the child to the tree, its important that we don't overwrite the
			// child information.
			val.name = intf.name
			return
		}
	}
	trees[intf.index] = intf
}

// addIfaceWithMaster handles adding slave interface to the tree.
func (trees bpfIfaceTrees) addIfaceWithMaster(intf *bpfIfaceNode, masterIndex int) {
	// If the interface is already in the correct position in the tree,
	// don't add it.
	val := trees.findIfaceByIndex(intf.index)
	if val != nil {
		if val.parentIface != nil && val.parentIface.index == masterIndex {
			return
		}
	}
	// Now the interface is a slave interface, perhaps with a different master.
	// So delete the interface and add it again.
	trees.deleteIface(intf.name)
	// Master interface is already there in the tree. Add the slave interface as a child.
	masterIface := trees.findIfaceByIndex(masterIndex)
	if masterIface != nil {
		masterIface.children[intf.index] = intf
	} else {
		// If the master interface is not there in the tree. Add the master interface to the
		// tree and the slave interface as its child.
		masterIface = &bpfIfaceNode{index: masterIndex, children: make(map[int]*bpfIfaceNode)}
	}
	intf.parentIface = masterIface
	masterIface.children[intf.index] = intf
	trees[masterIndex] = masterIface
}

// addIfaceWithChild add in-tree parent of the childIdx interface.
func (trees bpfIfaceTrees) addIfaceWithChild(intf *bpfIfaceNode, childIdx int) {
	// Check if the interface with childIdx is in the tree. If so,
	// add this interface as a parent.
	val := trees.findIfaceByIndex(childIdx)
	if val != nil {
		val.parentIface = intf
		intf.children[val.index] = val
		delete(trees, childIdx)
	} else {
		// If the child interface is not in the tree, add a new interface with
		// childIdx as a child of intf.
		intf.children[childIdx] = &bpfIfaceNode{
			index:       childIdx,
			parentIface: intf,
			children:    make(map[int]*bpfIfaceNode),
		}
	}
	trees[intf.index] = intf
}

// addHostIface adds host interface to hostIfaceTrees tree.
func (trees bpfIfaceTrees) addIface(link netlink.Link) {
	attrs := link.Attrs()
	intf := &bpfIfaceNode{
		name:        attrs.Name,
		index:       attrs.Index,
		masterIndex: attrs.MasterIndex,
		children:    make(map[int]*bpfIfaceNode),
	}

	if attrs.MasterIndex == 0 && attrs.ParentIndex == 0 {
		trees.addIfaceStandAlone(intf)
	} else if attrs.MasterIndex != 0 {
		trees.addIfaceWithMaster(intf, attrs.MasterIndex)
	} else if attrs.ParentIndex != 0 {
		trees.addIfaceWithChild(intf, attrs.ParentIndex)
	}
}

func (trees bpfIfaceTrees) deleteIface(name string) {
	// Interface not in the tree.
	node := trees.findIfaceByName(name)
	if node == nil {
		return
	}

	// Interface is a root interface.
	if node.parentIface == nil {
		for _, child := range node.children {
			child.parentIface = nil
			trees[child.index] = child
		}
		delete(trees, node.index)
	} else {
		// Interface is not a root and not a leaf. Add each child node
		// as a separate tree and delete this tree.
		if len(node.children) > 0 {
			for _, child := range node.children {
				child.parentIface = nil
				trees[child.index] = child
			}
			delete(trees, node.parentIface.index)
		} else {
			// Interface is a leaf.
			delete(node.parentIface.children, node.index)
		}
	}
}

// findIfaceByIndex returns the bpfIfaceNode if present matching the index.
func (trees bpfIfaceTrees) findIfaceByIndex(index int) *bpfIfaceNode {
	for _, tree := range trees {
		if node := tree.findIfaceByIndex(index); node != nil {
			return node
		}
	}
	return nil
}

// findIfaceByName returns the bpfIfaceNode if present matching the name.
func (trees bpfIfaceTrees) findIfaceByName(name string) *bpfIfaceNode {
	for _, tree := range trees {
		if node := tree.findIfaceByName(name); node != nil {
			return node
		}
	}
	return nil
}

func (n *bpfIfaceNode) findIfaceByIndex(index int) *bpfIfaceNode {
	if n.index == index {
		return n
	}
	for _, child := range n.children {
		if child.index == index {
			return child
		}
		if node := child.findIfaceByIndex(index); node != nil {
			return node
		}
	}
	return nil
}

func (n *bpfIfaceNode) findIfaceByName(name string) *bpfIfaceNode {
	if n.name == name {
		return n
	}
	for _, child := range n.children {
		if child.name == name {
			return child
		}
		if node := child.findIfaceByName(name); node != nil {
			return node
		}
	}
	return nil
}

func (n *bpfIfaceNode) getIfacesInTree() []string {
	nodes := []string{n.name}
	for _, child := range n.children {
		nodes = append(nodes, child.getIfacesInTree()...)
	}
	return nodes
}

func getRootInterface(hostIf *bpfIfaceNode) *bpfIfaceNode {
	temp := hostIf
	for {
		if temp.parentIface == nil {
			return temp
		}
		temp = temp.parentIface
	}
}

// getAllIfacesInTree returns all the interface names in the tree as a slice.
func (m *bpfEndpointManager) getAllIfacesInTree(name string) set.Set[string] {
	allIfaces := set.New[string]()
	hostIf := m.hostIfaceTrees.findIfaceByName(name)
	if hostIf == nil {
		return allIfaces
	}
	root := getRootInterface(hostIf)
	if root == nil {
		return allIfaces
	}
	allIfaces.AddAll(root.getIfacesInTree())
	return allIfaces
}

// isLeafIface returns if the interface does not have a valid child.
// This can be as simple as return len(hostIf.children) == 0.
// However, the main interfaces may have a parent in a different namespace, like a veth,
// and we are not going to see and update from that parent.
func isLeafIface(hostIf *bpfIfaceNode) bool {
	for _, child := range hostIf.children {
		if child.name != "" {
			return false
		}
	}
	return true
}

// isRootIface returns if the interface is root or not.
func isRootIface(hostIf *bpfIfaceNode) bool {
	return hostIf.parentIface == nil
}

// getLeafNodes returns the list of leaf nodes, given
// any node in the tree.
func getLeafNodes(intf *bpfIfaceNode) []string {
	leaves := []string{}
	if intf == nil {
		return leaves
	}

	if len(intf.children) == 0 {
		leaves = append(leaves, intf.name)
	}
	for _, child := range intf.children {
		leaves = append(leaves, getLeafNodes(child)...)
	}
	return leaves
}

func newJumpMapAlloc(entryPoints int) *jumpMapAlloc {
	a := &jumpMapAlloc{
		max:       entryPoints,
		free:      set.New[int](),
		freeStack: make([]int, entryPoints),
		inUse:     map[int]string{},
	}
	for i := 0; i < entryPoints; i++ {
		a.free.Add(i)
		a.freeStack[entryPoints-1-i] = i
	}
	return a
}

type jumpMapAlloc struct {
	lock sync.Mutex
	max  int

	free      set.Set[int]
	freeStack []int
	inUse     map[int]string
}

func (pa *jumpMapAlloc) Get(owner string) (int, error) {
	pa.lock.Lock()
	defer pa.lock.Unlock()

	if len(pa.freeStack) == 0 {
		return -1, errors.New("jumpMapAlloc: ran out of policy map indexes")
	}
	idx := pa.freeStack[len(pa.freeStack)-1]
	pa.freeStack = pa.freeStack[:len(pa.freeStack)-1]
	pa.free.Discard(idx)
	pa.inUse[idx] = owner

	logrus.WithFields(logrus.Fields{"owner": owner, "index": idx}).Debug("jumpMapAlloc: Allocated policy map index")
	pa.checkFreeLockHeld(idx)
	return idx, nil
}

// Assign explicitly assigns ownership of a specific free index to the given
// owner.  Used at start-of-day to re-establish existing ownerships.
func (pa *jumpMapAlloc) Assign(idx int, owner string) error {
	if idx < 0 || idx >= pa.max {
		return fmt.Errorf("index %d out of jump map range", idx)
	}

	pa.lock.Lock()
	defer pa.lock.Unlock()

	if recordedOwner, ok := pa.inUse[idx]; ok {
		err := fmt.Errorf("jumpMapAlloc: trying to set owner of %d to %q but it is owned by %q", idx, owner, recordedOwner)
		return err
	}

	pa.free.Discard(idx)
	pa.inUse[idx] = owner
	// Iterate backwards because it's most likely that the previously-used
	// item came from the lower indexes (which start life at the end of
	// the stack slice).
	for i := len(pa.freeStack) - 1; i >= 0; i-- {
		if pa.freeStack[i] == idx {
			pa.freeStack[i] = pa.freeStack[len(pa.freeStack)-1]
			pa.freeStack = pa.freeStack[:len(pa.freeStack)-1]
			break
		}
	}
	pa.checkFreeLockHeld(idx)
	return nil
}

// Put puts an index into the free pool.  The recorded owner must match the
// given owner.
func (pa *jumpMapAlloc) Put(idx int, owner string) error {
	if idx < 0 || idx >= pa.max {
		return nil // ignore, especially if an index is -1 aka unused
	}

	pa.lock.Lock()
	defer pa.lock.Unlock()

	if recordedOwner, ok := pa.inUse[idx]; !ok || recordedOwner != owner {
		err := fmt.Errorf("jumpMapAlloc: %q trying to free index %d but it is owned by %q", owner, idx, recordedOwner)
		return err
	}
	logrus.WithFields(logrus.Fields{"owner": owner, "index": idx}).Debug("jumpMapAlloc: Released policy map index")
	delete(pa.inUse, idx)
	pa.free.Add(idx)
	pa.freeStack = append(pa.freeStack, idx)
	pa.checkFreeLockHeld(idx)
	return nil
}

func (pa *jumpMapAlloc) checkFreeLockHeld(idx int) {
	if len(pa.freeStack) != pa.free.Len() {
		logrus.WithFields(logrus.Fields{
			"assigning": idx,
			"set":       pa.free,
			"stack":     pa.freeStack,
		}).Panic("jumpMapAlloc: Free set and free stack got out of sync")
	}
}
