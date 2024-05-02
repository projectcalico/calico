//go:build !windows

// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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
	"syscall"
	"time"

	"github.com/projectcalico/calico/felix/ethtool"
	"github.com/projectcalico/calico/libcalico-go/lib/health"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/rules"

	logutilslc "github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/api/pkg/lib/numorstring"

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
	"github.com/projectcalico/calico/felix/bpf/tc"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/bpf/xdp"
	"github.com/projectcalico/calico/felix/cachingmap"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
)

const (
	bpfInDev  = "bpfin.cali"
	bpfOutDev = "bpfout.cali"

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

func init() {
	prometheus.MustRegister(bpfEndpointsGauge)
	prometheus.MustRegister(bpfDirtyEndpointsGauge)
	prometheus.MustRegister(bpfHappyEndpointsGauge)

	binary.LittleEndian.PutUint32(jumpMapV4PolicyKey, uint32(tcdefs.ProgIndexPolicy))
	binary.LittleEndian.PutUint32(jumpMapV6PolicyKey, uint32(tcdefs.ProgIndexPolicy))
}

type attachPoint interface {
	IfaceName() string
	HookName() hook.Hook
	IsAttached() (bool, error)
	AttachProgram() (bpf.AttachResult, error)
	DetachProgram() error
	Log() *log.Entry
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
	ensureProgramAttached(attachPoint) (qDiscInfo, error)
	ensureProgramLoaded(ap attachPoint, ipFamily proto.IPVersion) error
	ensureNoProgram(attachPoint) error
	ensureQdisc(iface string) (bool, error)
	ensureBPFDevices() error
	updatePolicyProgram(rules polprog.Rules, polDir string, ap attachPoint, ipFamily proto.IPVersion) error
	removePolicyProgram(ap attachPoint, ipFamily proto.IPVersion) error
	setAcceptLocal(iface string, val bool) error
	setRPFilter(iface string, val int) error
	setRoute(ip.CIDR)
	delRoute(ip.CIDR)
	ruleMatchID(dir, action, owner, name string, idx int) polprog.RuleMatchID
	loadDefaultPolicies() error
	loadTCLogFilter(ap *tc.AttachPoint) (fileDescriptor, int, error)
	interfaceByIndex(int) (*net.Interface, error)
	queryClassifier(int, int, int, bool) (int, error)
}

type hasLoadPolicyProgram interface {
	loadPolicyProgram(
		progName string,
		ipFamily proto.IPVersion,
		rules polprog.Rules,
		staticProgsMap maps.Map,
		polProgsMap maps.Map,
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

type bpfInterfaceInfo struct {
	ifIndex    int
	isUP       bool
	endpointID *proto.WorkloadEndpointID
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
	qdisc       qDiscInfo
}

type bpfInterfaceJumpIndices struct {
	policyIdx [hook.Count]int
}

func (d *bpfInterfaceJumpIndices) clearJumps() {
	d.policyIdx = [hook.Count]int{-1, -1, -1}
}

type qDiscInfo struct {
	valid  bool
	prio   int
	handle int
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

	allWEPs        map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	happyWEPs      map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	happyWEPsDirty bool
	policies       map[proto.PolicyID]*proto.Policy
	profiles       map[proto.ProfileID]*proto.Profile

	// Indexes
	policiesToWorkloads map[proto.PolicyID]set.Set[any]  /* FIXME proto.WorkloadEndpointID or string (for a HEP) */
	profilesToWorkloads map[proto.ProfileID]set.Set[any] /* FIXME proto.WorkloadEndpointID or string (for a HEP) */

	dirtyIfaceNames set.Set[string]

	logFilters              map[string]string
	bpfLogLevel             string
	hostname                string
	fibLookupEnabled        bool
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

	jumpMapAlloc     *jumpMapAlloc
	xdpJumpMapAlloc  *jumpMapAlloc
	policyDefaultObj *libbpf.Obj
	policyTcAllowFD  bpf.ProgFD
	policyTcDenyFD   bpf.ProgFD

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
		opts ...polprog.Option,
	) ([]fileDescriptor, []asm.Insns, error)
	updatePolicyProgramFn func(rules polprog.Rules, polDir string, ap attachPoint, ipFamily proto.IPVersion) error

	// HEP processing.
	hostIfaceToEpMap     map[string]proto.HostEndpoint
	wildcardHostEndpoint proto.HostEndpoint
	wildcardExists       bool

	// UT-able BPF dataplane interface.
	dp bpfDataplane

	//ifaceToIpMap map[string]net.IP
	opReporter logutils.OpRecorder

	// XDP
	xdpModes []bpf.XDPMode

	// IPv6 Support
	ipv6Enabled bool

	// Detected features
	Features *environment.Features

	// RPF mode
	rpfEnforceOption string

	// BPF Disable GRO ifaces map
	bpfDisableGROForIfaces *regexp.Regexp

	// Service routes
	hostNetworkedNATMode hostNetworkedNATMode

	bpfPolicyDebugEnabled bool

	routeTableV4     routetable.RouteTableInterface
	routeTableV6     routetable.RouteTableInterface
	services         map[serviceKey][]ip.CIDR
	dirtyServices    set.Set[serviceKey]
	natExcludedCIDRs *ip.CIDRTrie

	// Maps for policy rule counters
	polNameToMatchIDs map[string]set.Set[polprog.RuleMatchID]
	dirtyRules        set.Set[polprog.RuleMatchID]

	natInIdx  int
	natOutIdx int

	v4 *bpfEndpointManagerDataplane
	v6 *bpfEndpointManagerDataplane

	healthAggregator     *health.HealthAggregator
	updateRateLimitedLog *logutilslc.RateLimitedLogger
}

type bpfEndpointManagerDataplane struct {
	*bpfmap.IPMaps
	ipFamily proto.IPVersion
	hostIP   net.IP
	mgr      *bpfEndpointManager

	ifaceToIpMap map[string]net.IP

	// IP of the tunnel / overlay device
	tunnelIP            net.IP
	iptablesFilterTable IptablesTable
	ipSetIDAlloc        *idalloc.IDAllocator
}

type serviceKey struct {
	name      string
	namespace string
}

type bpfAllowChainRenderer interface {
	WorkloadInterfaceAllowChains(endpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint) []*iptables.Chain
}

type ManagerWithHEPUpdate interface {
	Manager
	OnHEPUpdate(hostIfaceToEpMap map[string]proto.HostEndpoint)
}

func NewTestEpMgr(
	config *Config,
	bpfmaps *bpfmap.Maps,
	workloadIfaceRegex *regexp.Regexp,
) (ManagerWithHEPUpdate, error) {
	return newBPFEndpointManager(nil, config, bpfmaps, true, workloadIfaceRegex, idalloc.New(), idalloc.New(),
		rules.NewRenderer(rules.Config{
			BPFEnabled:                  true,
			IPIPEnabled:                 true,
			IPIPTunnelAddress:           nil,
			IPSetConfigV4:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			IptablesMarkAccept:          0x8,
			IptablesMarkPass:            0x10,
			IptablesMarkScratch0:        0x20,
			IptablesMarkScratch1:        0x40,
			IptablesMarkEndpoint:        0xff00,
			IptablesMarkNonCaliEndpoint: 0x0100,
			KubeIPVSSupportEnabled:      true,
			WorkloadIfacePrefixes:       []string{"cali", "tap"},
			VXLANPort:                   4789,
			VXLANVNI:                    4096,
		}),
		iptables.NewNoopTable(),
		iptables.NewNoopTable(),
		nil,
		logutils.NewSummarizer("test"),
		new(environment.FakeFeatureDetector),
		nil,
	)
}

func newBPFEndpointManager(
	dp bpfDataplane,
	config *Config,
	bpfmaps *bpfmap.Maps,
	fibLookupEnabled bool,
	workloadIfaceRegex *regexp.Regexp,
	ipSetIDAllocV4 *idalloc.IDAllocator,
	ipSetIDAllocV6 *idalloc.IDAllocator,
	iptablesRuleRenderer bpfAllowChainRenderer,
	iptablesFilterTableV4 IptablesTable,
	iptablesFilterTableV6 IptablesTable,
	livenessCallback func(),
	opReporter logutils.OpRecorder,
	featureDetector environment.FeatureDetectorIface,
	healthAggregator *health.HealthAggregator,
) (*bpfEndpointManager, error) {
	if livenessCallback == nil {
		livenessCallback = func() {}
	}

	m := &bpfEndpointManager{
		initUnknownIfaces:       set.New[string](),
		dp:                      dp,
		allWEPs:                 map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		happyWEPs:               map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		happyWEPsDirty:          true,
		policies:                map[proto.PolicyID]*proto.Policy{},
		profiles:                map[proto.ProfileID]*proto.Profile{},
		nameToIface:             map[string]bpfInterface{},
		policiesToWorkloads:     map[proto.PolicyID]set.Set[any]{},
		profilesToWorkloads:     map[proto.ProfileID]set.Set[any]{},
		dirtyIfaceNames:         set.New[string](),
		bpfLogLevel:             config.BPFLogLevel,
		hostname:                config.Hostname,
		fibLookupEnabled:        fibLookupEnabled,
		dataIfaceRegex:          config.BPFDataIfacePattern,
		l3IfaceRegex:            config.BPFL3IfacePattern,
		workloadIfaceRegex:      workloadIfaceRegex,
		epToHostAction:          config.RulesConfig.EndpointToHostAction,
		vxlanMTU:                config.VXLANMTU,
		vxlanPort:               uint16(config.VXLANPort),
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
		jumpMapAlloc:     newJumpMapAlloc(jump.TCMaxEntryPoints),
		xdpJumpMapAlloc:  newJumpMapAlloc(jump.XDPMaxEntryPoints),
		ruleRenderer:     iptablesRuleRenderer,
		onStillAlive:     livenessCallback,
		hostIfaceToEpMap: map[string]proto.HostEndpoint{},
		opReporter:       opReporter,
		// ipv6Enabled Should be set to config.Ipv6Enabled, but for now it is better
		// to set it to BPFIpv6Enabled which is a dedicated flag for development of IPv6.
		// TODO: set ipv6Enabled to config.Ipv6Enabled when IPv6 support is complete
		ipv6Enabled:            config.BPFIpv6Enabled,
		rpfEnforceOption:       config.BPFEnforceRPF,
		bpfDisableGROForIfaces: config.BPFDisableGROForIfaces,
		bpfPolicyDebugEnabled:  config.BPFPolicyDebugEnabled,
		polNameToMatchIDs:      map[string]set.Set[polprog.RuleMatchID]{},
		dirtyRules:             set.New[polprog.RuleMatchID](),

		healthAggregator: healthAggregator,
	}

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

	// Clean all the files under /var/run/calico/bpf/prog to remove any information from the
	// previous execution of the bpf dataplane, and make sure the directory exists.
	bpf.CleanAttachedProgDir()

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

	m.v4 = newBPFEndpointManagerDataplane(proto.IPVersion_IPV4, bpfmaps.V4, iptablesFilterTableV4, ipSetIDAllocV4, m)

	if m.ipv6Enabled {
		m.v6 = newBPFEndpointManagerDataplane(proto.IPVersion_IPV6, bpfmaps.V6, iptablesFilterTableV6, ipSetIDAllocV6, m)
	}

	if m.hostNetworkedNATMode != hostNetworkedNATDisabled {
		log.Infof("HostNetworkedNATMode is %d", m.hostNetworkedNATMode)
		if m.v4 != nil {
			m.routeTableV4 = routetable.New(
				[]string{bpfInDev},
				uint8(4),
				config.NetlinkTimeout,
				nil, // deviceRouteSourceAddress
				config.DeviceRouteProtocol,
				true, // removeExternalRoutes
				unix.RT_TABLE_MAIN,
				opReporter,
				featureDetector,
			)
		}
		if m.v6 != nil {
			m.routeTableV6 = routetable.New(
				[]string{bpfInDev},
				uint8(6),
				config.NetlinkTimeout,
				nil, // deviceRouteSourceAddress
				config.DeviceRouteProtocol,
				true, // removeExternalRoutes
				unix.RT_TABLE_MAIN,
				opReporter,
				featureDetector,
			)
		}

		m.services = make(map[serviceKey][]ip.CIDR)
		m.dirtyServices = set.New[serviceKey]()
		m.natExcludedCIDRs = ip.NewCIDRTrie()

		var excludeCIDRsMatch = 1

		for _, c := range config.BPFExcludeCIDRsFromNAT {
			cidr, err := ip.CIDRFromString(c)
			if err != nil {
				log.WithError(err).Warnf("Bad %s CIDR to exclude from NAT", c)
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

		if err := m.dp.ensureBPFDevices(); err != nil {
			return nil, fmt.Errorf("ensure BPF devices: %w", err)
		} else {
			log.Infof("Created %s:%s veth pair.", bpfInDev, bpfOutDev)
		}
	}

	if m.bpfPolicyDebugEnabled {
		err := m.commonMaps.RuleCountersMap.Iter(func(k, v []byte) maps.IteratorAction {
			return maps.IterDelete
		})
		if err != nil {
			log.WithError(err).Warn("Failed to iterate over policy counters map")
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

	return m, nil
}

func newBPFEndpointManagerDataplane(
	ipFamily proto.IPVersion,
	ipMaps *bpfmap.IPMaps,
	iptablesFilterTable IptablesTable,
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
	err := os.Mkdir(oldBase, 0700)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("cannot create %s: %w", oldBase, err)
	}

	tmp, err := os.MkdirTemp(oldBase, "")
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("cannot create temp dir in %s: %w", oldBase, err)
	}

	mps := []maps.Map{
		m.commonMaps.ProgramsMap,
		m.commonMaps.JumpMap,
		m.commonMaps.XDPProgramsMap,
		m.commonMaps.XDPJumpMap,
	}

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
	logCtx := log.WithField("name", ifaceName)

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

func (m *bpfEndpointManager) updateHostIP(ip net.IP, ipFamily int) {
	if ip != nil {
		if ipFamily == 4 {
			m.v4.hostIP = ip
		} else {
			m.v6.hostIP = ip
		}
		// Should be safe without the lock since there shouldn't be any active background threads
		// but taking it now makes us robust to refactoring.
		m.ifacesLock.Lock()
		for ifaceName := range m.nameToIface {
			m.dirtyIfaceNames.Add(ifaceName)
		}
		m.ifacesLock.Unlock()

		// We use host IP as the source when routing service for the ctlb workaround. We
		// need to update those routes, so make them all dirty.
		for svc := range m.services {
			m.dirtyServices.Add(svc)
		}
	} else {
		log.Warn("Cannot parse hostip, no change applied")
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
			log.WithField("HostMetadataUpdate", msg).Infof("Host IP changed: %s", msg.Ipv4Addr)
			m.updateHostIP(net.ParseIP(msg.Ipv4Addr), 4)
		}
	case *proto.HostMetadataV6Update:
		if m.v6 != nil && msg.Hostname == m.hostname {
			log.WithField("HostMetadataV6Update", msg).Infof("Host IPv6 changed: %s", msg.Ipv6Addr)
			m.updateHostIP(net.ParseIP(msg.Ipv6Addr), 6)
		}
	case *proto.HostMetadataV4V6Update:
		if msg.Hostname != m.hostname {
			break
		}
		if m.v4 != nil {
			log.WithField("HostMetadataV4V6Update", msg).Infof("Host IP changed: %s", msg.Ipv4Addr)
			m.updateHostIP(net.ParseIP(msg.Ipv4Addr), 4)
		}
		if m.v6 != nil {
			log.WithField("HostMetadataV4V6Update", msg).Infof("Host IPv6 changed: %s", msg.Ipv6Addr)
			m.updateHostIP(net.ParseIP(msg.Ipv6Addr), 6)
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
	if update.Type == proto.RouteType_LOCAL_TUNNEL {
		ip, _, err := net.ParseCIDR(update.Dst)
		if err != nil {
			log.WithField("local tunnel cird", update.Dst).WithError(err).Warn("not parsable")
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
		log.WithField("ip", update.Dst).Info("host tunnel")
		m.dirtyIfaceNames.Add(bpfOutDev)
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
		log.Debugf("Interface %+v received address update %+v", update.Name, update.Addrs)
		update.Addrs.Iter(func(item string) error {
			ip := net.ParseIP(item)
			if d.ipFamily == proto.IPVersion_IPV6 {
				if ip.To4() == nil && !ip.IsLinkLocalUnicast() {
					ipAddrs = append(ipAddrs, ip)
				}
			} else if ip.To4() != nil {
				ipAddrs = append(ipAddrs, ip)
			}
			return nil
		})
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
			log.WithError(err).Warn("Policy program may leak.")
		}
		if attachHook != hook.XDP {
			if err := m.jumpMapAlloc.Put(idx.policyIdx[attachHook], name); err != nil {
				log.WithError(err).Errorf("Policy family %d, hook %s", ipFamily, attachHook)
			}
		} else {
			if err := m.xdpJumpMapAlloc.Put(idx.policyIdx[attachHook], name); err != nil {
				log.WithError(err).Error(attachHook.String())
			}
		}
	}
}

func (m *bpfEndpointManager) reclaimFilterIdx(name string, iface *bpfInterface) {
	for _, attachHook := range []hook.Hook{hook.Ingress, hook.Egress} {
		if err := m.jumpMapDelete(attachHook, iface.dpState.filterIdx[attachHook]); err != nil {
			log.WithError(err).Warn("Filter program may leak.")
		}
		if err := m.jumpMapAlloc.Put(iface.dpState.filterIdx[attachHook], name); err != nil {
			log.WithError(err).Errorf("Filter hook %s", attachHook)
		}
	}
}

func (m *bpfEndpointManager) updateIfaceStateMap(name string, iface *bpfInterface) {
	k := ifstate.NewKey(uint32(iface.info.ifIndex))
	if iface.info.ifaceIsUp() {
		flags := uint32(0)
		if m.isWorkloadIface(name) {
			flags |= ifstate.FlgWEP
		}
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
		log.WithError(err).Warnf("Failed to remove  ingress counters for dev %s ifindex %d.", name, ifindex)
	}
	err = m.commonMaps.CountersMap.Delete(counters.NewKey(ifindex, hook.Egress).AsBytes())
	if err != nil && !maps.IsNotExists(err) {
		log.WithError(err).Warnf("Failed to remove  egress counters for dev %s ifindex %d.", name, ifindex)
	}
	err = m.commonMaps.CountersMap.Delete(counters.NewKey(ifindex, hook.XDP).AsBytes())
	if err != nil && !maps.IsNotExists(err) {
		log.WithError(err).Warnf("Failed to remove  XDP counters for dev %s ifindex %d.", name, ifindex)
	}
	log.Debugf("Deleted counters for dev %s ifindex %d.", name, ifindex)
}

func (m *bpfEndpointManager) cleanupOldAttach(iface string, ai bpf.EPAttachInfo) error {
	if ai.XDP != 0 {
		ap := xdp.AttachPoint{
			AttachPoint: bpf.AttachPoint{
				Iface: iface,
				Hook:  hook.XDP,
			},
			// Try all modes in this order
			Modes: []bpf.XDPMode{bpf.XDPGeneric, bpf.XDPDriver, bpf.XDPOffload},
		}

		if err := m.dp.ensureNoProgram(&ap); err != nil {
			return fmt.Errorf("xdp: %w", err)
		}
	}
	if ai.Ingress != 0 || ai.Egress != 0 {
		ap := tc.AttachPoint{
			AttachPoint: bpf.AttachPoint{
				Iface: iface,
				Hook:  hook.Egress,
			},
		}

		if err := m.dp.ensureNoProgram(&ap); err != nil {
			return fmt.Errorf("tc egress: %w", err)
		}

		ap.Hook = hook.Ingress

		if err := m.dp.ensureNoProgram(&ap); err != nil {
			return fmt.Errorf("tc ingress: %w", err)
		}
	}

	return nil
}

func (m *bpfEndpointManager) onInterfaceUpdate(update *ifaceStateUpdate) {
	log.Debugf("Interface update for %v, state %v", update.Name, update.State)
	// Should be safe without the lock since there shouldn't be any active background threads
	// but taking it now makes us robust to refactoring.
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	if update.State == ifacemonitor.StateNotPresent {
		if err := bpf.ForgetIfaceAttachedProg(update.Name); err != nil {
			log.WithError(err).Errorf("Error in removing interface %s json file. err=%v", update.Name, err)
		}
	}

	if !m.isDataIface(update.Name) && !m.isWorkloadIface(update.Name) && !m.isL3Iface(update.Name) {
		if update.State == ifacemonitor.StateUp {
			if ai, ok := m.initAttaches[update.Name]; ok {
				if err := m.cleanupOldAttach(update.Name, ai); err != nil {
					log.WithError(err).Warnf("Failed to detach old programs from now unused device '%s'", update.Name)
				} else {
					delete(m.initAttaches, update.Name)
				}
			}
		}
		if m.initUnknownIfaces != nil {
			m.initUnknownIfaces.Add(update.Name)
		}
		log.WithField("update", update).Debug("Ignoring interface that's neither data nor workload nor L3.")
		return
	}

	m.withIface(update.Name, func(iface *bpfInterface) (forceDirty bool) {
		ifaceIsUp := update.State == ifacemonitor.StateUp
		// Note, only need to handle the mapping and unmapping of the host-* endpoint here.
		// For specific host endpoints OnHEPUpdate doesn't depend on iface state, and has
		// already stored and mapped as needed.
		if ifaceIsUp {
			delete(m.initAttaches, update.Name)
			// We require host interfaces to be in non-strict RPF mode so that
			// packets can return straight to host for services bypassing CTLB.
			switch update.Name {
			case bpfInDev, bpfOutDev:
				// do nothing
			default:
				if m.v4 != nil {
					if err := m.dp.setRPFilter(update.Name, 2); err != nil {
						log.WithError(err).Warnf("Failed to set rp_filter for %s.", update.Name)
					}
				}
			}

			if m.v4 != nil {
				_ = m.dp.setAcceptLocal(update.Name, true)
			}

			if _, hostEpConfigured := m.hostIfaceToEpMap[update.Name]; m.wildcardExists && !hostEpConfigured {
				log.Debugf("Map host-* endpoint for %v", update.Name)
				m.addHEPToIndexes(update.Name, &m.wildcardHostEndpoint)
				m.hostIfaceToEpMap[update.Name] = m.wildcardHostEndpoint
			}
			iface.info.ifIndex = update.Index
			iface.info.isUP = true
			m.updateIfaceStateMap(update.Name, iface)
		} else {
			if m.wildcardExists && reflect.DeepEqual(m.hostIfaceToEpMap[update.Name], m.wildcardHostEndpoint) {
				log.Debugf("Unmap host-* endpoint for %v", update.Name)
				m.removeHEPFromIndexes(update.Name, &m.wildcardHostEndpoint)
				delete(m.hostIfaceToEpMap, update.Name)
			}
			m.deleteIfaceCounters(update.Name, iface.info.ifIndex)
			iface.dpState.v4Readiness = ifaceNotReady
			iface.dpState.v6Readiness = ifaceNotReady
			iface.info.isUP = false
			m.updateIfaceStateMap(update.Name, iface)
			iface.info.ifIndex = 0
		}
		return true // Force interface to be marked dirty in case we missed a transition during a resync.
	})
}

// onWorkloadEndpointUpdate adds/updates the workload in the cache along with the index from active policy to
// workloads using that policy.
func (m *bpfEndpointManager) onWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate) {
	log.WithField("wep", msg.Endpoint).Debug("Workload endpoint update")
	wlID := *msg.Id
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
	wlID := *msg.Id
	log.WithField("id", wlID).Debug("Workload endpoint removed")
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
	polID := *msg.Id
	log.WithField("id", polID).Debug("Policy update")
	m.policies[polID] = msg.Policy
	m.markEndpointsDirty(m.policiesToWorkloads[polID], "policy")
	if m.bpfPolicyDebugEnabled {
		m.updatePolicyCache(polID.Name, "Policy", m.policies[polID].InboundRules, m.policies[polID].OutboundRules)
	}
}

// onPolicyRemove removes the policy from the cache and marks any endpoints using it dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onPolicyRemove(msg *proto.ActivePolicyRemove) {
	polID := *msg.Id
	log.WithField("id", polID).Debug("Policy removed")
	m.markEndpointsDirty(m.policiesToWorkloads[polID], "policy")
	delete(m.policies, polID)
	delete(m.policiesToWorkloads, polID)
	if m.bpfPolicyDebugEnabled {
		m.dirtyRules.AddSet(m.polNameToMatchIDs[polID.Name])
		delete(m.polNameToMatchIDs, polID.Name)
	}
}

// onProfileUpdate stores the profile in the cache and marks any endpoints that use it as dirty.
func (m *bpfEndpointManager) onProfileUpdate(msg *proto.ActiveProfileUpdate) {
	profID := *msg.Id
	log.WithField("id", profID).Debug("Profile update")
	m.profiles[profID] = msg.Profile
	m.markEndpointsDirty(m.profilesToWorkloads[profID], "profile")
	if m.bpfPolicyDebugEnabled {
		m.updatePolicyCache(profID.Name, "Profile", m.profiles[profID].InboundRules, m.profiles[profID].OutboundRules)
	}
}

// onProfileRemove removes the profile from the cache and marks any endpoints that were using it as dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onProfileRemove(msg *proto.ActiveProfileRemove) {
	profID := *msg.Id
	log.WithField("id", profID).Debug("Profile removed")
	m.markEndpointsDirty(m.profilesToWorkloads[profID], "profile")
	delete(m.profiles, profID)
	delete(m.profilesToWorkloads, profID)
	if m.bpfPolicyDebugEnabled {
		m.dirtyRules.AddSet(m.polNameToMatchIDs[profID.Name])
		delete(m.polNameToMatchIDs, profID.Name)
	}
}

func (m *bpfEndpointManager) removeDirtyPolicies() {
	b := make([]byte, 8)
	m.dirtyRules.Iter(func(item polprog.RuleMatchID) error {
		binary.LittleEndian.PutUint64(b, item)
		log.WithField("ruleId", item).Debug("deleting entry")
		err := m.commonMaps.RuleCountersMap.Delete(b)
		if err != nil && !maps.IsNotExists(err) {
			log.WithField("ruleId", item).Info("error deleting entry")
		}

		return set.RemoveItem
	})
}

func (m *bpfEndpointManager) markEndpointsDirty(ids set.Set[any], kind string) {
	if ids == nil {
		// Hear about the policy/profile before the endpoint.
		return
	}
	ids.Iter(func(item any) error {
		switch id := item.(type) {
		case proto.WorkloadEndpointID:
			m.markExistingWEPDirty(id, kind)
		case string:
			if id == allInterfaces {
				for ifaceName := range m.nameToIface {
					if m.isWorkloadIface(ifaceName) {
						log.Debugf("Mark WEP iface dirty, for host-* endpoint %v change", kind)
						m.dirtyIfaceNames.Add(ifaceName)
					}
				}
			} else {
				log.Debugf("Mark host iface dirty, for host %v change", kind)
				m.dirtyIfaceNames.Add(id)
			}
		}
		return nil
	})
}

func (m *bpfEndpointManager) markExistingWEPDirty(wlID proto.WorkloadEndpointID, mapping string) {
	wep := m.allWEPs[wlID]
	if wep == nil {
		log.WithField("wlID", wlID).Panicf(
			"BUG: %s mapping points to unknown workload.", mapping)
	} else {
		m.dirtyIfaceNames.Add(wep.Name)
	}
}

func jumpMapDeleteEntry(m maps.Map, idx, stride int) error {
	for subProg := 0; subProg < jump.MaxSubPrograms; subProg++ {
		if err := m.Delete(jump.Key(polprog.SubProgramJumpIdx(idx, subProg, stride))); err != nil {
			if maps.IsNotExists(err) {
				log.WithError(err).WithField("idx", idx).Debug(
					"Policy program already gone from map.")
				return nil
			} else {
				log.WithError(err).Warn("Failed to delete policy program from map; policy program may leak.")
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
					v.EgressPolicyV4,
					v.IngressPolicyV6,
					v.EgressPolicyV6,
					v.TcIngressFilter,
					v.TcEgressFilter,
				} {
					if idx := fn(); idx != -1 {
						_ = jumpMapDeleteEntry(m.commonMaps.JumpMap, idx, jump.TCMaxEntryPoints)
					}
				}
			} else {
				// It will get deleted by the first CompleteDeferredWork() if we
				// do not get any state update on that interface.
				log.WithError(err).Warnf("Failed to sync ifstate for iface %d, deferring it.", ifindex)
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
						alloc = m.jumpMapAlloc
						seenIndexes = tcSeenIndexes
					}
					if err := alloc.Assign(idx, netiface.Name); err != nil {
						// Conflict with another program; need to alloc a new index.
						log.WithError(err).Error("Start of day resync found invalid jump map index, " +
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
			var config = map[string]bool{
				ethtool.EthtoolRxGRO: false,
			}

			for _, entry := range ifaces {
				iface := entry.Name
				if m.bpfDisableGROForIfaces.MatchString(iface) {
					log.WithField(expr, iface).Debug("BPF Disable GRO iface match")
					err = ethtool.EthtoolChangeImpl(iface, config)
					if err == nil {
						log.WithField(iface, config).Debug("ethtool.Change() succeeded")
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

func (m *bpfEndpointManager) loadDefaultPolicies() error {
	file := path.Join(bpfdefs.ObjectDir, "policy_default.o")
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

	if err := obj.Load(); err != nil {
		return fmt.Errorf("default policies: %w", err)
	}

	m.policyDefaultObj = obj

	fd, err := obj.ProgramFD("calico_tc_deny")
	if err != nil {
		return fmt.Errorf("failed to load default deny policy program: %w", err)
	}
	m.policyTcDenyFD = bpf.ProgFD(fd)

	fd, err = obj.ProgramFD("calico_tc_allow")
	if err != nil {
		return fmt.Errorf("failed to load default allow policy program: %w", err)
	}
	m.policyTcAllowFD = bpf.ProgFD(fd)
	return nil
}

func (m *bpfEndpointManager) CompleteDeferredWork() error {
	defer func() {
		log.Debug("CompleteDeferredWork done.")
	}()

	// Do one-off initialisation.
	m.startupOnce.Do(func() {
		m.dp.ensureStarted()

		if err := m.ifStateMap.LoadCacheFromDataplane(); err != nil {
			log.WithError(err).Fatal("Cannot load interface state map - essential for consistent operation.")
		}

		m.initUnknownIfaces.Iter(func(iface string) error {
			if ai, ok := m.initAttaches[iface]; ok {
				if err := m.cleanupOldAttach(iface, ai); err != nil {
					log.WithError(err).Warnf("Failed to detach old programs from now unused device '%s'", iface)
				} else {
					delete(m.initAttaches, iface)
					return set.RemoveItem
				}
			}
			return nil
		})

		// Makes sure that we delete entries for non-existing devices and preserve entries
		// for those that exists until we can make sure that they did (not) change.
		m.syncIfStateMap()
		log.Info("BPF Interface state map synced.")

		if err := m.dp.loadDefaultPolicies(); err != nil {
			log.WithError(err).Warn("Failed to load default policies, some programs may default to DENY.")
		}
		log.Info("Default BPF policy programs loaded.")

		m.initUnknownIfaces = nil

		if err := m.syncIfaceProperties(); err != nil {
			log.WithError(err).Warn("Failed to sync counters map with existing interfaces - some counters may have leaked.")
		}
		log.Info("BPF counters synced.")
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
		m.dirtyServices.Iter(func(svc serviceKey) error {
			for _, ip := range m.services[svc] {
				m.dp.setRoute(ip)
			}
			return set.RemoveItem
		})
	}

	if err := m.ifStateMap.ApplyAllChanges(); err != nil {
		log.WithError(err).Warn("Failed to write updates to ifstate BPF map.")
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
		log.Info("Copy delta entries from old map to the new map")
		var err error
		if m.v6 != nil {
			err = m.v6.CtMap.CopyDeltaFromOldMap()
		} else {
			err = m.v4.CtMap.CopyDeltaFromOldMap()
		}
		if err != nil {
			log.WithError(err).Debugf("Failed to copy data from old conntrack map %s", err)
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
		m.dirtyIfaceNames.Iter(func(iface string) error {
			m.updateRateLimitedLog.WithField("name", iface).Info("Interface remains dirty.")
			return nil
		})
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

func (m *bpfEndpointManager) doApplyPolicyToDataIface(iface string) (bpfInterfaceState, error) {

	var (
		err   error
		up    bool
		state bpfInterfaceState
	)

	m.ifacesLock.Lock()
	ifaceName := iface
	m.withIface(iface, func(iface *bpfInterface) bool {
		up = iface.info.ifaceIsUp()
		state = iface.dpState
		return false
	})
	m.ifacesLock.Unlock()
	if !up {
		log.WithField("iface", iface).Debug("Ignoring interface that is down")
		return state, nil
	}
	if err := m.dataIfaceStateFillJumps(ifaceName, &state); err != nil {
		return state, err
	}

	_, err = m.dp.ensureQdisc(iface)
	if err != nil {
		return state, err
	}
	var hepPtr *proto.HostEndpoint
	if hep, hepExists := m.hostIfaceToEpMap[iface]; hepExists {
		hepPtr = &hep
	}

	var parallelWG sync.WaitGroup
	var ingressErr, xdpErr, err4, err6 error
	var ingressAP4, egressAP4 *tc.AttachPoint
	var ingressAP6, egressAP6 *tc.AttachPoint
	var xdpAP4, xdpAP6 *xdp.AttachPoint

	tcAttachPoint := m.calculateTCAttachPoint(iface)
	xdpAttachPoint := &xdp.AttachPoint{
		AttachPoint: bpf.AttachPoint{
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
				tcAttachPoint, xdpAttachPoint)
		}()
	}
	if m.v4 != nil {
		ingressAP4, egressAP4, xdpAP4, err4 = m.v4.applyPolicyToDataIface(iface, hepPtr, &state,
			tcAttachPoint, xdpAttachPoint)
	}

	parallelWG.Wait()

	// Attach ingress program.
	parallelWG.Add(1)
	go func() {
		defer parallelWG.Done()
		ingressAP := mergeAttachPoints(ingressAP4, ingressAP6)
		if ingressAP != nil {
			m.loadFilterProgram(ingressAP)
			_, ingressErr = m.dp.ensureProgramAttached(ingressAP)
		}
	}()

	// Attach xdp program.
	parallelWG.Add(1)
	go func() {
		defer parallelWG.Done()
		xdpAP := mergeAttachPoints(xdpAP4, xdpAP6)
		if hepPtr != nil && len(hepPtr.UntrackedTiers) == 1 && xdpAP != nil {
			_, xdpErr = m.dp.ensureProgramAttached(xdpAP)
		} else {
			xdpErr = m.dp.ensureNoProgram(xdpAP)
		}
	}()

	// Attach egress program.
	egressAP := mergeAttachPoints(egressAP4, egressAP6)
	if egressAP != nil {
		m.loadFilterProgram(egressAP)
		_, err = m.dp.ensureProgramAttached(egressAP)
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
	m.dirtyIfaceNames.Iter(func(iface string) error {
		if !m.isDataIface(iface) && !m.isL3Iface(iface) {
			log.WithField("iface", iface).Debug(
				"Ignoring interface that doesn't match the host data/l3 interface regex")
			if !m.isWorkloadIface(iface) {
				log.WithField("iface", iface).Debug(
					"Removing interface that doesn't match the host data/l3 interface and is not workload interface")
				return set.RemoveItem
			}
			return nil
		}

		m.opReporter.RecordOperation("update-data-iface")

		wg.Add(1)
		go func(ifaceName string) {
			defer wg.Done()
			state, err := m.doApplyPolicyToDataIface(ifaceName)
			m.ifacesLock.Lock()
			m.withIface(ifaceName, func(bpfIface *bpfInterface) bool {
				bpfIface.dpState = state
				return false
			})
			m.ifacesLock.Unlock()
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
		return nil
	})
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
			log.WithField("id", iface).Info("Applied program to host interface")
			m.dirtyIfaceNames.Discard(iface)
		} else {
			if isLinkNotFoundError(err) {
				log.WithField("iface", iface).Debug(
					"Tried to apply BPF program to interface but the interface wasn't present.  " +
						"Will retry if it shows up.")
				m.dirtyIfaceNames.Discard(iface)
			} else {
				log.WithField("iface", iface).WithError(err).Warn("Failed to apply policy to interface, will retry")
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

	m.dirtyIfaceNames.Iter(func(ifaceName string) error {
		if !m.isWorkloadIface(ifaceName) {
			return nil
		}

		m.opReporter.RecordOperation("update-workload-iface")

		if err := sem.Acquire(context.Background(), 1); err != nil {
			// Should only happen if the context finishes.
			log.WithError(err).Panic("Failed to acquire semaphore")
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
		return nil
	})
	wg.Wait()

	for ifaceName, err := range errs {
		var wlID *proto.WorkloadEndpointID

		m.withIface(ifaceName, func(iface *bpfInterface) bool {
			wlID = iface.info.endpointID
			m.updateIfaceStateMap(ifaceName, iface)
			return false // no need to enforce dirty
		})

		if err == nil {
			log.WithField("iface", ifaceName).Info("Updated workload interface.")
			if wlID != nil && m.allWEPs[*wlID] != nil {
				if m.happyWEPs[*wlID] == nil {
					log.WithFields(log.Fields{
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
					log.WithField("id", *wlID).WithError(err).Warning(
						"Failed to add policy to workload, removing from iptables allow list")
				}
				delete(m.happyWEPs, *wlID)
				m.happyWEPsDirty = true
			}

			if isLinkNotFoundError(err) {
				log.WithField("wep", wlID).Debug(
					"Tried to apply BPF program to interface but the interface wasn't present.  " +
						"Will retry if it shows up.")
				m.dirtyIfaceNames.Discard(ifaceName)
			} else {
				log.WithError(err).WithFields(log.Fields{
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
		idx.policyIdx[hook.Ingress], err = m.jumpMapAlloc.Get(ifaceName)
		if err != nil {
			return err
		}
	}

	if idx.policyIdx[hook.Egress] == -1 {
		idx.policyIdx[hook.Egress], err = m.jumpMapAlloc.Get(ifaceName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *bpfEndpointManager) allocJumpIndicesForDataIface(ifaceName string, idx *bpfInterfaceJumpIndices) error {
	var err error
	if idx.policyIdx[hook.Ingress] == -1 {
		idx.policyIdx[hook.Ingress], err = m.jumpMapAlloc.Get(ifaceName)
		if err != nil {
			return err
		}
	}

	if idx.policyIdx[hook.Egress] == -1 {
		idx.policyIdx[hook.Egress], err = m.jumpMapAlloc.Get(ifaceName)
		if err != nil {
			return err
		}
	}

	if idx.policyIdx[hook.XDP] == -1 {
		idx.policyIdx[hook.XDP], err = m.xdpJumpMapAlloc.Get(ifaceName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *bpfEndpointManager) wepStateFillJumps(ifaceName string, state *bpfInterfaceState) error {
	var err error

	// Allocate indices for IPv4
	if m.v4 != nil {
		err = m.allocJumpIndicesForWEP(ifaceName, &state.v4)
		if err != nil {
			return err
		}
	}

	// Allocate indices for IPv6
	if m.v6 != nil {
		err = m.allocJumpIndicesForWEP(ifaceName, &state.v6)
		if err != nil {
			return err
		}
	}

	if m.bpfLogLevel == "debug" {
		if state.filterIdx[hook.Ingress] == -1 {
			state.filterIdx[hook.Ingress], err = m.jumpMapAlloc.Get(ifaceName)
			if err != nil {
				return err
			}
		}
		if state.filterIdx[hook.Egress] == -1 {
			state.filterIdx[hook.Egress], err = m.jumpMapAlloc.Get(ifaceName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *bpfEndpointManager) dataIfaceStateFillJumps(ifaceName string, state *bpfInterfaceState) error {
	var err error

	if m.v4 != nil {
		err = m.allocJumpIndicesForDataIface(ifaceName, &state.v4)
		if err != nil {
			return err
		}
	}

	if m.v6 != nil {
		err = m.allocJumpIndicesForDataIface(ifaceName, &state.v6)
		if err != nil {
			return err
		}
	}

	if m.bpfLogLevel == "debug" {
		if state.filterIdx[hook.Ingress] == -1 {
			state.filterIdx[hook.Ingress], err = m.jumpMapAlloc.Get(ifaceName)
			if err != nil {
				return err
			}
		}
		if state.filterIdx[hook.Egress] == -1 {
			state.filterIdx[hook.Egress], err = m.jumpMapAlloc.Get(ifaceName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *bpfEndpointManager) queryClassifier(ifindex, handle, prio int, ingress bool) (int, error) {
	return libbpf.QueryClassifier(ifindex, handle, prio, ingress)
}

func (m *bpfEndpointManager) doApplyPolicy(ifaceName string) (bpfInterfaceState, error) {
	startTime := time.Now()

	var (
		state      bpfInterfaceState
		endpointID *proto.WorkloadEndpointID
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
		log.WithField("ifaceName", ifaceName).Debug(
			"Ignoring request to program interface that is not present.")
		return state, nil
	}

	if err := m.wepStateFillJumps(ifaceName, &state); err != nil {
		return state, err
	}

	// Otherwise, the interface appears to be present but we may or may not have an endpoint from the
	// datastore.  If we don't have an endpoint then we'll attach a program to block traffic and we'll
	// get the jump map ready to insert the policy if the endpoint shows up.

	// Attach the qdisc first; it is shared between the directions.
	existed, err := m.dp.ensureQdisc(ifaceName)
	if err != nil {
		if isLinkNotFoundError(err) {
			// Interface is gone, nothing to do.
			log.WithField("ifaceName", ifaceName).Debug(
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
		ingressErr, egressErr     error
		err4, err6                error
		ingressQdisc, egressQdisc qDiscInfo
		ingressAP4, egressAP4     *tc.AttachPoint
		ingressAP6, egressAP6     *tc.AttachPoint
		wg                        sync.WaitGroup
		wep                       *proto.WorkloadEndpoint
	)

	if endpointID != nil {
		wep = m.allWEPs[*endpointID]
	}

	v4Readiness := state.v4Readiness
	v6Readiness := state.v6Readiness
	if v4Readiness == ifaceIsReady || v6Readiness == ifaceIsReady {
		if _, err := m.dp.queryClassifier(ifindex, state.qdisc.handle, state.qdisc.prio, true); err != nil {
			v4Readiness = ifaceNotReady
			v6Readiness = ifaceNotReady
		}
	}

	ap := m.calculateTCAttachPoint(ifaceName)

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

	//Attach preamble TC program
	if attachPreamble {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ingressAP := mergeAttachPoints(ingressAP4, ingressAP6)
			if ingressAP != nil {
				m.loadFilterProgram(ingressAP)
				ingressQdisc, ingressErr = m.dp.ensureProgramAttached(ingressAP)
			}
		}()
		egressAP := mergeAttachPoints(egressAP4, egressAP6)
		if egressAP != nil {
			m.loadFilterProgram(egressAP)
			egressQdisc, egressErr = m.dp.ensureProgramAttached(egressAP)
		}
		wg.Wait()
	}

	if ingressErr != nil {
		return state, ingressErr
	}

	if egressErr != nil {
		return state, egressErr
	}

	if egressQdisc != ingressQdisc {
		return state, fmt.Errorf("ingress qdisc info (%v) does not equal egress qdisc info (%v)",
			ingressQdisc, egressQdisc)
	}
	state.qdisc = ingressQdisc

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
	log.WithFields(log.Fields{"timeTaken": applyTime, "ifaceName": ifaceName}).
		Info("Finished applying BPF programs for workload")
	return state, nil
}

func (m *bpfEndpointManager) ensureProgramAttached(ap attachPoint) (qDiscInfo, error) {
	var qdisc qDiscInfo
	res, err := ap.AttachProgram()
	if err != nil {
		return qdisc, err
	}
	if tcRes, ok := res.(*tc.AttachResult); ok {
		qdisc.valid = true
		qdisc.prio = tcRes.Prio()
		qdisc.handle = tcRes.Handle()
	}
	return qdisc, nil
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
	polDirection PolDirection) *tc.AttachPoint {

	ap = d.configureTCAttachPoint(polDirection, ap, false)
	ifaceName := ap.IfaceName()
	if d.ipFamily == proto.IPVersion_IPV6 {
		ip, err := d.getInterfaceIP(ifaceName)
		if err != nil {
			log.Debugf("Error getting IP for interface %+v: %+v", ifaceName, err)
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
	endpoint *proto.WorkloadEndpoint, polDirection PolDirection, ap *tc.AttachPoint) (*tc.AttachPoint, error) {

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

	log.WithField("iface", ap.IfaceName()).Debugf("readiness: %d", readiness)
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
	endpoint *proto.WorkloadEndpoint, polDirection PolDirection) error {

	var profileIDs []string
	var tier *proto.TierInfo
	if endpoint != nil {
		profileIDs = endpoint.ProfileIds
		if len(endpoint.Tiers) != 0 {
			tier = endpoint.Tiers[0]
		}
	} else {
		log.WithField("name", ap.IfaceName()).Debug(
			"Workload interface with no endpoint in datastore, installing default-drop program.")
	}

	m := d.mgr
	// If tier or profileIDs is nil, this will return an empty set of rules but updatePolicyProgram appends a
	// drop rule, giving us default drop behaviour in that case.
	rules := m.extractRules(tier, profileIDs, polDirection)

	// If host-* endpoint is configured, add in its policy.
	if m.wildcardExists {
		m.addHostPolicy(&rules, &d.mgr.wildcardHostEndpoint, polDirection.Inverse())
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

	return m.updatePolicyProgramFn(rules, polDirection.RuleDir(), ap, d.ipFamily)
}

func (m *bpfEndpointManager) addHostPolicy(rules *polprog.Rules, hostEndpoint *proto.HostEndpoint, polDirection PolDirection) {

	// When there is applicable pre-DNAT policy that does not explicitly Allow or Deny traffic,
	// we continue on to subsequent tiers and normal or AoF policy.
	if len(hostEndpoint.PreDnatTiers) == 1 {
		rules.HostPreDnatTiers = m.extractTiers(hostEndpoint.PreDnatTiers[0], polDirection, NoEndTierDrop)
	}

	// When there is applicable apply-on-forward policy that does not explicitly Allow or Deny
	// traffic, traffic is dropped.
	if len(hostEndpoint.ForwardTiers) == 1 {
		rules.HostForwardTiers = m.extractTiers(hostEndpoint.ForwardTiers[0], polDirection, EndTierDrop)
	}

	// When there is applicable normal policy that does not explicitly Allow or Deny traffic,
	// traffic is dropped.
	if len(hostEndpoint.Tiers) == 1 {
		rules.HostNormalTiers = m.extractTiers(hostEndpoint.Tiers[0], polDirection, EndTierDrop)
	}
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
) (*tc.AttachPoint, *tc.AttachPoint, *xdp.AttachPoint, error) {

	ingressAttachPoint := *ap
	egressAttachPoint := *ap
	xdpAttachPoint := *apxdp

	var parallelWG sync.WaitGroup
	var ingressAP, egressAP *tc.AttachPoint
	var xdpAP *xdp.AttachPoint
	var ingressErr, egressErr, xdpErr error

	parallelWG.Add(2)
	go func() {
		defer parallelWG.Done()
		ingressAP, ingressErr = d.attachDataIfaceProgram(ifaceName, ep, PolDirnIngress, state, &ingressAttachPoint)
	}()

	go func() {
		defer parallelWG.Done()
		xdpAP, xdpErr = d.attachXDPProgram(&xdpAttachPoint, ep, state)
	}()

	egressAP, egressErr = d.attachDataIfaceProgram(ifaceName, ep, PolDirnEgress, state, &egressAttachPoint)
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
		log.Debugf("Error getting IP for interface %+v: %+v", ifaceName, err)
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

	if ep != nil {
		rules := polprog.Rules{
			ForHostInterface: true,
		}
		m.addHostPolicy(&rules, ep, polDirection)
		if err := m.updatePolicyProgramFn(rules, polDirection.RuleDir(), ap, d.ipFamily); err != nil {
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
			HostNormalTiers:  m.extractTiers(ep.UntrackedTiers[0], PolDirnIngress, false),
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

func (polDirection PolDirection) RuleDir() string {
	if polDirection == PolDirnIngress {
		return "Ingress"
	}
	return "Egress"
}

const (
	PolDirnIngress PolDirection = iota
	PolDirnEgress
)

func (polDirection PolDirection) Inverse() PolDirection {
	if polDirection == PolDirnIngress {
		return PolDirnEgress
	}
	return PolDirnIngress
}

func (m *bpfEndpointManager) apLogFilter(ap *tc.AttachPoint, iface string) (string, string) {
	if m.logFilters == nil {
		return m.bpfLogLevel, ""
	}

	exp, ok := m.logFilters[iface]
	if !ok {
		if ap.Type == tcdefs.EpTypeWorkload {
			if exp, ok := m.logFilters["weps"]; ok {
				return m.bpfLogLevel, exp
			}
		}
		if ap.Type == tcdefs.EpTypeHost {
			if exp, ok := m.logFilters["heps"]; ok {
				return m.bpfLogLevel, exp
			}
		}
		if exp, ok := m.logFilters["all"]; ok {
			return m.bpfLogLevel, exp
		}

		return "off", ""
	}

	return m.bpfLogLevel, exp
}

func (m *bpfEndpointManager) calculateTCAttachPoint(ifaceName string) *tc.AttachPoint {
	ap := &tc.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			Iface: ifaceName,
		},
	}

	var endpointType tcdefs.EndpointType

	// Determine endpoint type.
	if m.isWorkloadIface(ifaceName) {
		endpointType = tcdefs.EpTypeWorkload
	} else if ifaceName == "lo" {
		endpointType = tcdefs.EpTypeLO
		if m.hostNetworkedNATMode == hostNetworkedNATUDPOnly {
			ap.UDPOnly = true
		}
	} else if ifaceName == "tunl0" {
		if m.Features.IPIPDeviceIsL3 {
			endpointType = tcdefs.EpTypeL3Device
		} else {
			endpointType = tcdefs.EpTypeTunnel
		}
	} else if ifaceName == "wireguard.cali" || ifaceName == "wg-v6.cali" || m.isL3Iface(ifaceName) {
		endpointType = tcdefs.EpTypeL3Device
	} else if ifaceName == bpfInDev || ifaceName == bpfOutDev {
		endpointType = tcdefs.EpTypeNAT
	} else if m.isDataIface(ifaceName) {
		endpointType = tcdefs.EpTypeHost
		ap.NATin = uint32(m.natInIdx)
		ap.NATout = uint32(m.natOutIdx)
	} else {
		log.Panicf("Unsupported ifaceName %v", ifaceName)
	}
	ap.Type = endpointType
	if ap.Type != tcdefs.EpTypeWorkload {
		ap.WgPort = m.wgPort
		ap.Wg6Port = m.wg6Port
		ap.NATin = uint32(m.natInIdx)
		ap.NATout = uint32(m.natOutIdx)
	} else {
		ap.ExtToServiceConnmark = uint32(m.bpfExtToServiceConnmark)
	}

	ap.ToHostDrop = (m.epToHostAction == "DROP")
	ap.FIB = m.fibLookupEnabled
	ap.DSR = m.dsrEnabled
	ap.DSROptoutCIDRs = m.dsrOptoutCidrs
	ap.LogLevel, ap.LogFilter = m.apLogFilter(ap, ifaceName)
	ap.VXLANPort = m.vxlanPort
	ap.PSNATStart = m.psnatPorts.MinPort
	ap.PSNATEnd = m.psnatPorts.MaxPort
	ap.TunnelMTU = uint16(m.vxlanMTU)

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
		log.Debugf("Setting tunnel ip %s on ap %s", d.tunnelIP, ap.IfaceName())
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

	var toOrFrom tcdefs.ToOrFromEp
	if ap.Hook == hook.Ingress {
		toOrFrom = tcdefs.FromEp
	} else {
		toOrFrom = tcdefs.ToEp
	}

	ap.ToOrFrom = toOrFrom
	return ap
}

const EndTierDrop = true
const NoEndTierDrop = false

func (m *bpfEndpointManager) extractTiers(tier *proto.TierInfo, direction PolDirection, endTierDrop bool) (rTiers []polprog.Tier) {
	dir := direction.RuleDir()
	if tier == nil {
		return
	}

	directionalPols := tier.IngressPolicies
	if direction == PolDirnEgress {
		directionalPols = tier.EgressPolicies
	}

	if len(directionalPols) > 0 {
		polTier := polprog.Tier{
			Name:     tier.Name,
			Policies: make([]polprog.Policy, len(directionalPols)),
		}

		for i, polName := range directionalPols {
			pol := m.policies[proto.PolicyID{Tier: tier.Name, Name: polName}]
			if pol == nil {
				log.WithField("tier", tier).Warn("Tier refers to unknown policy!")
				continue
			}
			var prules []*proto.Rule
			if direction == PolDirnIngress {
				prules = pol.InboundRules
			} else {
				prules = pol.OutboundRules
			}
			policy := polprog.Policy{
				Name:  polName,
				Rules: make([]polprog.Rule, len(prules)),
			}

			for ri, r := range prules {
				policy.Rules[ri] = polprog.Rule{
					Rule:    r,
					MatchID: m.ruleMatchID(dir, r.Action, "Policy", polName, ri),
				}
			}

			polTier.Policies[i] = policy
		}

		if endTierDrop {
			polTier.EndAction = polprog.TierEndDeny
		} else {
			polTier.EndAction = polprog.TierEndPass
		}

		rTiers = append(rTiers, polTier)
	}
	return
}

func (m *bpfEndpointManager) extractProfiles(profileNames []string, direction PolDirection) (rProfiles []polprog.Profile) {
	dir := direction.RuleDir()
	if count := len(profileNames); count > 0 {
		rProfiles = make([]polprog.Profile, count)

		for i, profName := range profileNames {
			prof := m.profiles[proto.ProfileID{Name: profName}]
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
					MatchID: m.ruleMatchID(dir, r.Action, "Profile", profName, ri),
				}
			}

			rProfiles[i] = profile
		}
	}
	return
}

func (m *bpfEndpointManager) extractRules(tier *proto.TierInfo, profileNames []string, direction PolDirection) polprog.Rules {
	var r polprog.Rules

	// When there is applicable normal policy that does not explicitly Allow or Deny traffic,
	// traffic is dropped.
	r.Tiers = m.extractTiers(tier, direction, EndTierDrop)

	r.Profiles = m.extractProfiles(profileNames, direction)

	return r
}

func (m *bpfEndpointManager) isWorkloadIface(iface string) bool {
	return m.workloadIfaceRegex.MatchString(iface)
}

func (m *bpfEndpointManager) isDataIface(iface string) bool {
	return m.dataIfaceRegex.MatchString(iface) ||
		(m.hostNetworkedNATMode != hostNetworkedNATDisabled && (iface == bpfOutDev || iface == "lo"))
}

func (m *bpfEndpointManager) isL3Iface(iface string) bool {
	if m.l3IfaceRegex == nil {
		return false
	}
	return m.l3IfaceRegex.MatchString(iface)
}

func (m *bpfEndpointManager) addWEPToIndexes(wlID proto.WorkloadEndpointID, wl *proto.WorkloadEndpoint) {
	for _, t := range wl.Tiers {
		m.addPolicyToEPMappings(t.IngressPolicies, wlID)
		m.addPolicyToEPMappings(t.EgressPolicies, wlID)
	}
	m.addProfileToEPMappings(wl.ProfileIds, wlID)
}

func (m *bpfEndpointManager) addPolicyToEPMappings(polNames []string, id interface{}) {
	for _, pol := range polNames {
		polID := proto.PolicyID{
			Tier: "default",
			Name: pol,
		}
		if m.policiesToWorkloads[polID] == nil {
			m.policiesToWorkloads[polID] = set.New[any]()
		}
		m.policiesToWorkloads[polID].Add(id)
	}
}

func (m *bpfEndpointManager) addProfileToEPMappings(profileIds []string, id interface{}) {
	for _, profName := range profileIds {
		profID := proto.ProfileID{Name: profName}
		profSet := m.profilesToWorkloads[profID]
		if profSet == nil {
			profSet = set.New[any]()
			m.profilesToWorkloads[profID] = profSet
		}
		profSet.Add(id)
	}
}

func (m *bpfEndpointManager) removeWEPFromIndexes(wlID proto.WorkloadEndpointID, wep *proto.WorkloadEndpoint) {
	if wep == nil {
		return
	}

	for _, t := range wep.Tiers {
		m.removePolicyToEPMappings(t.IngressPolicies, wlID)
		m.removePolicyToEPMappings(t.EgressPolicies, wlID)
	}

	m.removeProfileToEPMappings(wep.ProfileIds, wlID)

	m.withIface(wep.Name, func(iface *bpfInterface) bool {
		iface.info.endpointID = nil
		return false
	})
}

func (m *bpfEndpointManager) removePolicyToEPMappings(polNames []string, id interface{}) {
	for _, pol := range polNames {
		polID := proto.PolicyID{
			Tier: "default",
			Name: pol,
		}
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
		profID := proto.ProfileID{Name: profName}
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

func (m *bpfEndpointManager) OnHEPUpdate(hostIfaceToEpMap map[string]proto.HostEndpoint) {
	if m == nil {
		return
	}

	log.Debugf("HEP update from generic endpoint manager: %v", hostIfaceToEpMap)

	// Pre-process the map for the host-* endpoint: if there is a host-* endpoint, any host
	// interface without its own HEP should use the host-* endpoint's policy.
	wildcardHostEndpoint, wildcardExists := hostIfaceToEpMap[allInterfaces]
	if wildcardExists {
		log.Info("Host-* endpoint is configured")
		for ifaceName := range m.nameToIface {
			if _, specificExists := hostIfaceToEpMap[ifaceName]; (m.isDataIface(ifaceName) || m.isL3Iface(ifaceName)) && !specificExists {
				log.Infof("Use host-* endpoint policy for %v", ifaceName)
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
		log.Infof("Host-* endpoint is changing; was %v, now %v", m.wildcardHostEndpoint, wildcardHostEndpoint)
		m.removeHEPFromIndexes(allInterfaces, &m.wildcardHostEndpoint)
		m.wildcardHostEndpoint = wildcardHostEndpoint
		m.wildcardExists = wildcardExists
		m.addHEPToIndexes(allInterfaces, &wildcardHostEndpoint)
		for ifaceName := range m.nameToIface {
			if m.isWorkloadIface(ifaceName) {
				log.Info("Mark WEP iface dirty, for host-* endpoint change")
				m.dirtyIfaceNames.Add(ifaceName)
			}
		}
	}

	// Loop through existing host endpoints, in case they are changing or disappearing.
	for ifaceName, existingEp := range m.hostIfaceToEpMap {
		newEp, stillExists := hostIfaceToEpMap[ifaceName]
		if stillExists && reflect.DeepEqual(newEp, existingEp) {
			log.Debugf("No change to host endpoint for ifaceName=%v", ifaceName)
		} else {
			m.removeHEPFromIndexes(ifaceName, &existingEp)
			if stillExists {
				log.Infof("Host endpoint changing for ifaceName=%v", ifaceName)
				m.addHEPToIndexes(ifaceName, &newEp)
				m.hostIfaceToEpMap[ifaceName] = newEp
			} else {
				log.Infof("Host endpoint deleted for ifaceName=%v", ifaceName)
				delete(m.hostIfaceToEpMap, ifaceName)
			}
			m.dirtyIfaceNames.Add(ifaceName)
		}
		delete(hostIfaceToEpMap, ifaceName)
	}

	// Now anything remaining in hostIfaceToEpMap must be a new host endpoint.
	for ifaceName, newEp := range hostIfaceToEpMap {
		if !m.isDataIface(ifaceName) && !m.isL3Iface(ifaceName) {
			log.Warningf("Host endpoint configured for ifaceName=%v, but that doesn't match BPFDataIfacePattern/BPFL3IfacePattern; ignoring", ifaceName)
			continue
		}
		log.Infof("Host endpoint added for ifaceName=%v", ifaceName)
		m.addHEPToIndexes(ifaceName, &newEp)
		m.hostIfaceToEpMap[ifaceName] = newEp
		m.dirtyIfaceNames.Add(ifaceName)
	}
}

func (m *bpfEndpointManager) addHEPToIndexes(ifaceName string, ep *proto.HostEndpoint) {
	for _, tiers := range [][]*proto.TierInfo{ep.Tiers, ep.UntrackedTiers, ep.PreDnatTiers, ep.ForwardTiers} {
		for _, t := range tiers {
			m.addPolicyToEPMappings(t.IngressPolicies, ifaceName)
			m.addPolicyToEPMappings(t.EgressPolicies, ifaceName)
		}
	}
	m.addProfileToEPMappings(ep.ProfileIds, ifaceName)
}

func (m *bpfEndpointManager) removeHEPFromIndexes(ifaceName string, ep *proto.HostEndpoint) {
	for _, tiers := range [][]*proto.TierInfo{ep.Tiers, ep.UntrackedTiers, ep.PreDnatTiers, ep.ForwardTiers} {
		for _, t := range tiers {
			m.removePolicyToEPMappings(t.IngressPolicies, ifaceName)
			m.removePolicyToEPMappings(t.EgressPolicies, ifaceName)
		}
	}

	m.removeProfileToEPMappings(ep.ProfileIds, ifaceName)
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
			log.WithField("err", err).Errorf("Failed to set %s to %s", path, numval)
			return err
		}
		log.Debugf("%s not set to %s - iface does not exist.", path, numval)
		return nil
	}

	log.Infof("%s set to %s", path, numval)
	return nil
}

func (m *bpfEndpointManager) setRPFilter(iface string, val int) error {
	// We only support IPv4 for now.
	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iface)
	numval := strconv.Itoa(val)
	err := writeProcSys(path, numval)
	if err != nil {
		log.WithField("err", err).Errorf("Failed to  set %s to %s", path, numval)
		return err
	}

	log.Infof("%s set to %s", path, numval)
	return nil
}

func (m *bpfEndpointManager) ensureStarted() {
	log.Info("Starting map cleanup runner.")

	var err error

	m.initAttaches, err = bpf.ListCalicoAttached()
	if err != nil {
		log.WithError(err).Warn("Failed to list previously attached programs. We may not clean up some.")
	}
}

func (m *bpfEndpointManager) ensureBPFDevices() error {
	if m.hostNetworkedNATMode == hostNetworkedNATDisabled {
		return nil
	}

	var bpfout, bpfin netlink.Link

	bpfin, err := netlink.LinkByName(bpfInDev)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = bpfInDev
		nat := &netlink.Veth{
			LinkAttrs: la,
			PeerName:  bpfOutDev,
		}
		if err := netlink.LinkAdd(nat); err != nil {
			return fmt.Errorf("failed to add %s: %w", bpfInDev, err)
		}
		bpfin, err = netlink.LinkByName(bpfInDev)
		if err != nil {
			return fmt.Errorf("missing %s after add: %w", bpfInDev, err)
		}
	}
	if state := bpfin.Attrs().OperState; state != netlink.OperUp {
		log.WithField("state", state).Info(bpfInDev)
		if err := netlink.LinkSetUp(bpfin); err != nil {
			return fmt.Errorf("failed to set %s up: %w", bpfInDev, err)
		}
	}
	bpfout, err = netlink.LinkByName(bpfOutDev)
	if err != nil {
		return fmt.Errorf("missing %s after add: %w", bpfOutDev, err)
	}
	if state := bpfout.Attrs().OperState; state != netlink.OperUp {
		log.WithField("state", state).Info(bpfOutDev)
		if err := netlink.LinkSetUp(bpfout); err != nil {
			return fmt.Errorf("failed to set %s up: %w", bpfOutDev, err)
		}
	}

	m.natInIdx = bpfin.Attrs().Index
	m.natOutIdx = bpfout.Attrs().Index

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
				log.WithError(err).Warnf("Failed to update neigh for %s (arp %#v), retrying.", bpfOutDev, arp)
				i--
				if i > 0 {
					time.Sleep(250 * time.Millisecond)
					continue
				} else {
					return fmt.Errorf("failed to update neigh for %s (arp %#v) after %d tries: %w",
						bpfOutDev, arp, retries, err)
				}
			}
			break
		}
	}
	log.Infof("Updated neigh for %s (arp %v)", bpfOutDev, arp)

	if m.v4 != nil {
		if err := configureInterface(bpfInDev, 4, "0", writeProcSys); err != nil {
			return fmt.Errorf("failed to configure %s parameters: %w", bpfOutDev, err)
		}
		if err := configureInterface(bpfOutDev, 4, "0", writeProcSys); err != nil {
			return fmt.Errorf("failed to configure %s parameters: %w", bpfOutDev, err)
		}
	}

	_, err = m.ensureQdisc(bpfInDev)
	if err != nil {
		return fmt.Errorf("failed to set qdisc on %s: %w", bpfOutDev, err)
	}

	_, err = m.ensureQdisc("lo")
	if err != nil {
		log.WithError(err).Fatalf("Failed to set qdisc on lo.")
	}

	// Setup a link local route to a nonexistent link local address that would
	// serve as a gateway to route services via bpfnat veth rather than having
	// link local routes for each service that would trigger ARP queries.
	if m.v4 != nil {
		m.routeTableV4.RouteUpdate(bpfInDev, routetable.Target{
			Type: routetable.TargetTypeLinkLocalUnicast,
			CIDR: bpfnatGWCIDR,
		})
	}
	if m.v6 != nil {
		m.routeTableV6.RouteUpdate(bpfInDev, routetable.Target{
			Type: routetable.TargetTypeLinkLocalUnicast,
			CIDR: bpfnatGWCIDRv6,
		})
	}

	return nil
}

func (m *bpfEndpointManager) ensureQdisc(iface string) (bool, error) {
	return tc.EnsureQdisc(iface)
}

func (m *bpfEndpointManager) loadTCObj(at hook.AttachType) (hook.Layout, error) {
	pm := m.commonMaps.ProgramsMap.(*hook.ProgramsMap)

	layout, err := pm.LoadObj(at)
	if err != nil {
		return nil, err
	}

	if at.LogLevel != "debug" {
		return layout, nil
	}

	at.LogLevel = "off"
	layoutNoDebug, err := pm.LoadObj(at)
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
			FIB:        aptc.FIB,
			ToHostDrop: aptc.ToHostDrop,
			DSR:        aptc.DSR,
		}

		at.Family = int(ipFamily)
		policyIdx := aptc.PolicyIdxV4
		ap.Log().Debugf("ensureProgramLoaded %d", ipFamily)
		if ipFamily == proto.IPVersion_IPV6 {
			if aptc.HookLayoutV6, err = m.loadTCObj(at); err != nil {
				return fmt.Errorf("loading generic v%d tc hook program: %w", ipFamily, err)
			}
			policyIdx = aptc.PolicyIdxV6
		} else {
			if aptc.HookLayoutV4, err = m.loadTCObj(at); err != nil {
				return fmt.Errorf("loading generic v%d tc hook program: %w", ipFamily, err)
			}
		}

		// Load default policy before the real policy is created and loaded.
		switch at.DefaultPolicy() {
		case hook.DefPolicyAllow:
			err = maps.UpdateMapEntry(m.commonMaps.JumpMap.MapFD(),
				jump.Key(policyIdx), jump.Value(m.policyTcAllowFD.FD()))
		case hook.DefPolicyDeny:
			err = maps.UpdateMapEntry(m.commonMaps.JumpMap.MapFD(),
				jump.Key(policyIdx), jump.Value(m.policyTcDenyFD.FD()))
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
			if apxdp.HookLayoutV6, err = pm.LoadObj(at); err != nil {
				return fmt.Errorf("loading generic xdp hook program: %w", err)
			}
		} else {
			if apxdp.HookLayoutV4, err = pm.LoadObj(at); err != nil {
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

	if m.v4 != nil {
		if err := m.jumpMapDelete(ap.HookName(), ap.PolicyJmp(proto.IPVersion_IPV4)); err != nil {
			log.WithError(err).Warn("Policy program may leak.")
		}
		m.removePolicyDebugInfo(ap.IfaceName(), 4, ap.HookName())
	}
	// Forget the policy debug info
	if m.v6 != nil {
		if err := m.jumpMapDelete(ap.HookName(), ap.PolicyJmp(proto.IPVersion_IPV6)); err != nil {
			log.WithError(err).Warn("Policy program may leak.")
		}
		m.removePolicyDebugInfo(ap.IfaceName(), 6, ap.HookName())
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
		log.WithError(err).Debugf("Failed to remove the policy debug file %v. Ignoring", filename)
	}
}

func (m *bpfEndpointManager) writePolicyDebugInfo(insns []asm.Insns, ifaceName string, ipFamily proto.IPVersion, polDir string, h hook.Hook, polErr error) error {
	if !m.bpfPolicyDebugEnabled {
		return nil
	}
	if err := os.MkdirAll(bpf.RuntimePolDir, 0600); err != nil {
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

	if err := os.WriteFile(filename, buffer.Bytes(), 0600); err != nil {
		return err
	}
	log.Debugf("Policy iface %s hook %s written to %s", ifaceName, h, filename)
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
		ap.HookName(),
		progName,
		ap.PolicyJmp(ipFamily),
		rules,
		ipFamily,
		opts...,
	)
	perr := m.writePolicyDebugInfo(insns, ap.IfaceName(), ipFamily, polDir, ap.HookName(), err)
	if perr != nil {
		log.WithError(perr).Warn("error writing policy debug information")
	}
	if err != nil {
		return fmt.Errorf("failed to update policy program v%d: %w", ipFamily, err)
	}

	return nil
}

func (m *bpfEndpointManager) loadTCLogFilter(ap *tc.AttachPoint) (fileDescriptor, int, error) {
	logFilter, err := filter.New(ap.Type, 64, ap.LogFilter, m.commonMaps.ProgramsMap.MapFD())
	if err != nil {
		return nil, 0, err
	}

	fd, err := bpf.LoadBPFProgramFromInsns(logFilter, "calico_log_filter",
		"Apache-2.0", uint32(unix.BPF_PROG_TYPE_SCHED_CLS))

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
		if err := m.commonMaps.JumpMap.Update(jump.Key(idx), jump.Value(fd.FD())); err != nil {
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
	opts ...polprog.Option,
) (
	fd []fileDescriptor, insns []asm.Insns, err error,
) {
	log.WithFields(log.Fields{
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
				log.WithError(err).Panic("Failed to close program FD.")
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
		progFD, err := bpf.LoadBPFProgramFromInsns(p, subProgName, "Apache-2.0", uint32(progType))
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
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

	staticProgsMap := m.commonMaps.ProgramsMap
	if hk == hook.XDP {
		staticProgsMap = m.commonMaps.XDPProgramsMap
	}

	// If we have to break a program up into sub-programs to please the
	// verifier then we store the sub-programs at
	// polJumpMapIdx + subProgNo * stride.
	polProgsMap := m.commonMaps.JumpMap
	stride := jump.TCMaxEntryPoints
	if hk == hook.XDP {
		polProgsMap = m.commonMaps.XDPJumpMap
		stride = jump.XDPMaxEntryPoints
	}
	opts = append(opts, polprog.WithPolicyMapIndexAndStride(polJumpMapIdx, stride))
	progFDs, insns, err := m.loadPolicyProgramFn(
		progName,
		ipFamily,
		rules,
		staticProgsMap,
		polProgsMap,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	defer func() {
		for _, progFD := range progFDs {
			// Once we've put the programs in the map, we don't need their FDs.
			if err := progFD.Close(); err != nil {
				log.WithError(err).Panic("Failed to close program FD.")
			}
		}
	}()

	for i, progFD := range progFDs {
		subProgIdx := polprog.SubProgramJumpIdx(polJumpMapIdx, i, stride)
		log.Debugf("Putting sub-program %d at position %d", i, subProgIdx)
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
			log.WithError(err).Warn("Unexpected error while trying to clean up old policy programs.")
		}
	}

	return insns, nil
}

func (m *bpfEndpointManager) jumpMapDelete(h hook.Hook, idx int) error {
	if idx < 0 {
		return nil
	}

	jumpMap := m.commonMaps.JumpMap
	stride := jump.TCMaxEntryPoints
	if h == hook.XDP {
		jumpMap = m.commonMaps.XDPJumpMap
		stride = jump.XDPMaxEntryPoints
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
		pm = m.commonMaps.JumpMap
	}

	if err := jumpMapDeleteEntry(pm, idx, stride); err != nil {
		return fmt.Errorf("removing policy iface %s hook %s: %w", ap.IfaceName(), ap.HookName(), err)
	}

	m.removePolicyDebugInfo(ap.IfaceName(), ipFamily, ap.HookName())
	return nil
}

func FindJumpMap(progID int, ifaceName string) (mapFD maps.FD, err error) {
	logCtx := log.WithField("progID", progID).WithField("iface", ifaceName)
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
				log.WithError(err).Panic("Failed to close FD.")
			}
			return 0, fmt.Errorf("failed to get map info: %w", err)
		}
		if mapInfo.Type == unix.BPF_MAP_TYPE_PROG_ARRAY {
			logCtx.WithField("fd", mapFD).Debug("Found jump map")
			return mapFD, nil
		}
		err = mapFD.Close()
		if err != nil {
			log.WithError(err).Panic("Failed to close FD.")
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
	log.Debugf("Addrs for dev %s : %v", ifaceName, addrs)
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

	log.WithFields(log.Fields{
		"Name":      update.Name,
		"Namespace": update.Namespace,
	}).Info("Service Update")

	ipstr := make([]string, 0, 2)
	if update.ClusterIp != "" {
		ipstr = append(ipstr, update.ClusterIp)
	}
	if update.LoadbalancerIp != "" {
		ipstr = append(ipstr, update.LoadbalancerIp)
	}

	key := serviceKey{name: update.Name, namespace: update.Namespace}

	ips := make([]ip.CIDR, 0, len(ipstr))
	for _, i := range ipstr {
		cidr, err := ip.ParseCIDROrIP(i)
		if err != nil {
			log.WithFields(log.Fields{"service": key, "ip": i}).Warn("Not a valid CIDR.")
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

	log.WithFields(log.Fields{
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
			m.routeTableV6.RouteUpdate(bpfInDev, target)
		}
	} else if m.v4 != nil && m.v4.hostIP != nil {
		target.GW = bpfnatGWIP
		target.Src = ip.FromNetIP(m.v4.hostIP)
		m.routeTableV4.RouteUpdate(bpfInDev, target)
	}

	log.WithFields(log.Fields{
		"cidr": cidr,
	}).Debug("setRoute")
}

func (m *bpfEndpointManager) delRoute(cidr ip.CIDR) {
	if m.v6 != nil && cidr.Version() == 6 {
		m.routeTableV6.RouteRemove(bpfInDev, cidr)
	}
	if m.v4 != nil && cidr.Version() == 4 {
		m.routeTableV4.RouteRemove(bpfInDev, cidr)
	}
	log.WithFields(log.Fields{
		"cidr": cidr,
	}).Debug("delRoute")
}

func (m *bpfEndpointManager) GetRouteTableSyncers() []routetable.RouteTableSyncer {
	if m.hostNetworkedNATMode == hostNetworkedNATDisabled {
		return nil
	}

	tables := []routetable.RouteTableSyncer{}
	if m.v4 != nil {
		tables = append(tables, m.routeTableV4)
	}
	if m.v6 != nil {
		tables = append(tables, m.routeTableV6)
	}

	return tables
}

// updatePolicyCache modifies entries in the cache, adding new entries and marking old entries dirty.
func (m *bpfEndpointManager) updatePolicyCache(name string, owner string, inboundRules, outboundRules []*proto.Rule) {
	ruleIds := set.New[polprog.RuleMatchID]()
	if val, ok := m.polNameToMatchIDs[name]; ok {
		// If the policy name exists, it means the policy is updated. There are cases where both inbound,
		// outbound rules are updated or any one.
		// Mark all the entries as dirty.
		m.dirtyRules.AddSet(val)
	}
	// Now iterate through all the rules and if the ruleIds are already in the cache, it means the rule has not
	// changed as part of the update. Remove the dirty flag and add this entry back as non-dirty.
	for idx, rule := range inboundRules {
		ruleIds.Add(m.addRuleInfo(rule, idx, owner, PolDirnIngress, name))
	}
	for idx, rule := range outboundRules {
		ruleIds.Add(m.addRuleInfo(rule, idx, owner, PolDirnEgress, name))
	}
	m.polNameToMatchIDs[name] = ruleIds
}

func (m *bpfEndpointManager) addRuleInfo(rule *proto.Rule, idx int,
	owner string, direction PolDirection, polName string) polprog.RuleMatchID {

	matchID := m.dp.ruleMatchID(direction.RuleDir(), rule.Action, owner, polName, idx)
	m.dirtyRules.Discard(matchID)

	return matchID
}

func (m *bpfEndpointManager) ruleMatchID(dir, action, owner, name string, idx int) polprog.RuleMatchID {
	h := fnv.New64a()
	h.Write([]byte(action + owner + dir + strconv.Itoa(idx) + name))
	return h.Sum64()
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

	log.WithFields(log.Fields{"owner": owner, "index": idx}).Debug("jumpMapAlloc: Allocated policy map index")
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
	log.WithFields(log.Fields{"owner": owner, "index": idx}).Debug("jumpMapAlloc: Released policy map index")
	delete(pa.inUse, idx)
	pa.free.Add(idx)
	pa.freeStack = append(pa.freeStack, idx)
	pa.checkFreeLockHeld(idx)
	return nil
}

func (pa *jumpMapAlloc) checkFreeLockHeld(idx int) {
	if len(pa.freeStack) != pa.free.Len() {
		log.WithFields(log.Fields{
			"assigning": idx,
			"set":       pa.free,
			"stack":     pa.freeStack,
		}).Panic("jumpMapAlloc: Free set and free stack got out of sync")
	}
}
