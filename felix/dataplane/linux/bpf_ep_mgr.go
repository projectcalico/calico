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

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/rules"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/bpf"
	bpfarp "github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
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
	binary.LittleEndian.PutUint32(jumpMapV6PolicyKey, uint32(tcdefs.ProgIndexV6Policy))
}

type attachPoint interface {
	IfaceName() string
	HookName() hook.Hook
	IsAttached() (bool, error)
	AttachProgram() (int, error)
	DetachProgram() error
	Log() *log.Entry
	PolicyIdx(int) int
}

type attachPointWithPolicyJumps interface {
	attachPoint
	PolicyAllowJumpIdx(int) int
	PolicyDenyJumpIdx(int) int
}

type bpfDataplane interface {
	ensureStarted()
	ensureProgramAttached(ap attachPoint) error
	ensureNoProgram(ap attachPoint) error
	ensureQdisc(iface string) error
	ensureBPFDevices() error
	updatePolicyProgram(rules polprog.Rules, polDir string, ap attachPoint) error
	removePolicyProgram(ap attachPoint) error
	setAcceptLocal(iface string, val bool) error
	setRPFilter(iface string, val int) error
	setRoute(ip.V4CIDR)
	delRoute(ip.V4CIDR)
	ruleMatchID(dir, action, owner, name string, idx int) polprog.RuleMatchID
	loadDefaultPolicies() error
}

type hasLoadPolicyProgram interface {
	loadPolicyProgram(progName string,
		ipFamily proto.IPVersion, rules polprog.Rules, progsMap maps.Map, opts ...polprog.Option) (
		bpf.ProgFD, asm.Insns, error)
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

func (i *bpfInterfaceState) clearPolicies() {
	i.policyIdx = [hook.Count]int{-1, -1, -1}
}

var zeroIface bpfInterface = func() bpfInterface {
	var i bpfInterface
	i.dpState.clearPolicies()
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

type bpfInterfaceState struct {
	policyIdx [hook.Count]int
	isReady   bool
}

type ctlbWorkaroundMode int

const (
	ctlbWorkaroundDisabled = iota
	ctlbWorkaroundEnabled
	ctlbWorkaroundUDPOnly
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

	bpfLogLevel             string
	hostname                string
	hostIP                  net.IP
	fibLookupEnabled        bool
	dataIfaceRegex          *regexp.Regexp
	l3IfaceRegex            *regexp.Regexp
	workloadIfaceRegex      *regexp.Regexp
	ipSetIDAlloc            *idalloc.IDAllocator
	epToHostAction          string
	vxlanMTU                int
	vxlanPort               uint16
	wgPort                  uint16
	dsrEnabled              bool
	dsrOptoutCidrs          bool
	bpfExtToServiceConnmark int
	psnatPorts              numorstring.Port
	bpfmaps                 *bpfmap.Maps
	ifStateMap              *cachingmap.CachingMap[ifstate.Key, ifstate.Value]
	removeOldJumps          bool
	legacyCleanUp           bool

	policyMapAlloc    *policyMapAlloc
	xdpPolicyMapAlloc *policyMapAlloc
	policyDefaultObj  *libbpf.Obj
	policyTcAllowFD   bpf.ProgFD
	policyTcDenyFD    bpf.ProgFD

	ruleRenderer        bpfAllowChainRenderer
	iptablesFilterTable IptablesTable

	startupOnce   sync.Once
	copyDeltaOnce sync.Once

	// onStillAlive is called from loops to reset the watchdog.
	onStillAlive func()

	loadPolicyProgramFn func(progName string,
		ipFamily proto.IPVersion, rules polprog.Rules, progsMap maps.Map, opts ...polprog.Option) (
		bpf.ProgFD, asm.Insns, error)
	updatePolicyProgramFn func(rules polprog.Rules, polDir string, ap attachPoint) error

	// HEP processing.
	hostIfaceToEpMap     map[string]proto.HostEndpoint
	wildcardHostEndpoint proto.HostEndpoint
	wildcardExists       bool

	// UT-able BPF dataplane interface.
	dp bpfDataplane

	ifaceToIpMap map[string]net.IP
	opReporter   logutils.OpRecorder

	// XDP
	xdpModes []bpf.XDPMode

	// IPv6 Support
	ipv6Enabled bool

	// IP of the tunnel / overlay device
	tunnelIP net.IP

	// Detected features
	Features *environment.Features

	// RPF mode
	rpfEnforceOption string

	// Service routes
	ctlbWorkaroundMode ctlbWorkaroundMode

	bpfPolicyDebugEnabled bool

	routeTable    routetable.RouteTableInterface
	services      map[serviceKey][]ip.V4CIDR
	dirtyServices set.Set[serviceKey]

	// Maps for policy rule counters
	polNameToMatchIDs map[string]set.Set[polprog.RuleMatchID]
	dirtyRules        set.Set[polprog.RuleMatchID]

	natInIdx  int
	natOutIdx int

	arpMap maps.Map
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

func NewTestEpMgr(config *Config, bpfmaps *bpfmap.Maps, workloadIfaceRegex *regexp.Regexp) (ManagerWithHEPUpdate, error) {
	return newBPFEndpointManager(nil, config, bpfmaps, true, workloadIfaceRegex, idalloc.New(),
		rules.NewRenderer(rules.Config{
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
		nil,
		logutils.NewSummarizer("test"),
		new(environment.FakeFeatureDetector),
	)
}

func newBPFEndpointManager(
	dp bpfDataplane,
	config *Config,
	bpfmaps *bpfmap.Maps,
	fibLookupEnabled bool,
	workloadIfaceRegex *regexp.Regexp,
	ipSetIDAlloc *idalloc.IDAllocator,
	iptablesRuleRenderer bpfAllowChainRenderer,
	iptablesFilterTable IptablesTable,
	livenessCallback func(),
	opReporter logutils.OpRecorder,
	featureDetector environment.FeatureDetectorIface,
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
		ipSetIDAlloc:            ipSetIDAlloc,
		epToHostAction:          config.RulesConfig.EndpointToHostAction,
		vxlanMTU:                config.VXLANMTU,
		vxlanPort:               uint16(config.VXLANPort),
		wgPort:                  uint16(config.Wireguard.ListeningPort),
		dsrEnabled:              config.BPFNodePortDSREnabled,
		dsrOptoutCidrs:          len(config.BPFDSROptoutCIDRs) > 0,
		bpfExtToServiceConnmark: config.BPFExtToServiceConnmark,
		psnatPorts:              config.BPFPSNATPorts,
		bpfmaps:                 bpfmaps,
		ifStateMap: cachingmap.New[ifstate.Key, ifstate.Value](ifstate.MapParams.Name,
			maps.NewTypedMap[ifstate.Key, ifstate.Value](
				bpfmaps.IfStateMap.(maps.MapWithExistsCheck), ifstate.KeyFromBytes, ifstate.ValueFromBytes,
			)),
		policyMapAlloc: &policyMapAlloc{
			max:  polprog.MaxEntries,
			free: make(chan int, polprog.MaxEntries),
		},
		xdpPolicyMapAlloc: &policyMapAlloc{
			max:  polprog.XDPMaxEntries,
			free: make(chan int, polprog.XDPMaxEntries),
		},
		ruleRenderer:        iptablesRuleRenderer,
		iptablesFilterTable: iptablesFilterTable,
		onStillAlive:        livenessCallback,
		hostIfaceToEpMap:    map[string]proto.HostEndpoint{},
		ifaceToIpMap:        map[string]net.IP{},
		opReporter:          opReporter,
		// ipv6Enabled Should be set to config.Ipv6Enabled, but for now it is better
		// to set it to BPFIpv6Enabled which is a dedicated flag for development of IPv6.
		// TODO: set ipv6Enabled to config.Ipv6Enabled when IPv6 support is complete
		ipv6Enabled:           config.BPFIpv6Enabled,
		rpfEnforceOption:      config.BPFEnforceRPF,
		bpfPolicyDebugEnabled: config.BPFPolicyDebugEnabled,
		polNameToMatchIDs:     map[string]set.Set[polprog.RuleMatchID]{},
		dirtyRules:            set.New[polprog.RuleMatchID](),
		arpMap:                bpfmaps.ArpMap,
	}

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

	if config.FeatureGates != nil {
		switch config.FeatureGates["BPFConnectTimeLoadBalancingWorkaround"] {
		case "enabled":
			m.ctlbWorkaroundMode = ctlbWorkaroundEnabled
		case "udp":
			m.ctlbWorkaroundMode = ctlbWorkaroundUDPOnly
		}
	}

	if m.ctlbWorkaroundMode != ctlbWorkaroundDisabled {
		log.Infof("BPFConnectTimeLoadBalancingWorkaround is %d", m.ctlbWorkaroundMode)
		m.routeTable = routetable.New(
			[]string{bpfInDev},
			4,
			false, // vxlan
			config.NetlinkTimeout,
			nil, // deviceRouteSourceAddress
			config.DeviceRouteProtocol,
			true, // removeExternalRoutes
			unix.RT_TABLE_MAIN,
			opReporter,
			featureDetector,
		)
		m.services = make(map[serviceKey][]ip.V4CIDR)
		m.dirtyServices = set.New[serviceKey]()

		// Anything else would prevent packets being accepted from the special
		// service veth. It does not create a security hole since BPF does the RPF
		// on its own.
		if err := m.dp.setRPFilter("all", 0); err != nil {
			return nil, fmt.Errorf("setting rp_filter for all: %w", err)
		}

		if err := m.dp.ensureBPFDevices(); err != nil {
			return nil, fmt.Errorf("ensure BPF devices: %w", err)
		} else {
			log.Infof("Created %s:%s veth pair.", bpfInDev, bpfOutDev)
		}
	}

	if m.bpfPolicyDebugEnabled {
		err := m.bpfmaps.RuleCountersMap.Iter(func(k, v []byte) maps.IteratorAction {
			return maps.IterDelete
		})
		if err != nil {
			log.WithError(err).Warn("Failed to iterate over policy counters map")
		}
	}

	// If not running in test
	if m.dp == m {
		// Repin jump maps to a differnt path so that existing programs keep working
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
		// Make sure that we envetually clean up after previous versions.
		m.legacyCleanUp = true
	}

	m.updatePolicyProgramFn = m.dp.updatePolicyProgram

	if x, ok := m.dp.(hasLoadPolicyProgram); ok {
		m.loadPolicyProgramFn = x.loadPolicyProgram
		m.updatePolicyProgramFn = m.updatePolicyProgram
	}

	return m, nil
}

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
		m.bpfmaps.ProgramsMap,
		m.bpfmaps.PolicyMap,
		m.bpfmaps.XDPProgramsMap,
		m.bpfmaps.XDPPolicyMap,
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
		m.onWorkloadEnpdointRemove(msg)
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
		if msg.Hostname == m.hostname {
			log.WithField("HostMetadataUpdate", msg).Info("Host IP changed")
			ip := net.ParseIP(msg.Ipv4Addr)
			if ip != nil {
				m.hostIP = ip
				// Should be safe without the lock since there shouldn't be any active background threads
				// but taking it now makes us robust to refactoring.
				m.ifacesLock.Lock()
				for ifaceName := range m.nameToIface {
					m.dirtyIfaceNames.Add(ifaceName)
				}
				m.ifacesLock.Unlock()
			} else {
				log.WithField("HostMetadataUpdate", msg).Warn("Cannot parse IP, no change applied")
			}
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
		m.tunnelIP = ip
		log.WithField("ip", update.Dst).Info("host tunnel")
		m.dirtyIfaceNames.Add(bpfOutDev)
	}
}

func (m *bpfEndpointManager) onInterfaceAddrsUpdate(update *ifaceAddrsUpdate) {
	var ipAddrs []net.IP
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	if update.Addrs != nil && update.Addrs.Len() > 0 {
		log.Debugf("Interface %+v received address update %+v", update.Name, update.Addrs)
		update.Addrs.Iter(func(item string) error {
			ip := net.ParseIP(item)
			if ip.To4() != nil {
				ipAddrs = append(ipAddrs, ip)
			}
			return nil
		})
		sort.Slice(ipAddrs, func(i, j int) bool {
			return bytes.Compare(ipAddrs[i], ipAddrs[j]) < 0
		})
		if len(ipAddrs) > 0 {
			ip, ok := m.ifaceToIpMap[update.Name]
			if !ok || !ip.Equal(ipAddrs[0]) {
				m.ifaceToIpMap[update.Name] = ipAddrs[0]
				m.dirtyIfaceNames.Add(update.Name)
			}

		}
	} else {
		_, ok := m.ifaceToIpMap[update.Name]
		if ok {
			delete(m.ifaceToIpMap, update.Name)
			m.dirtyIfaceNames.Add(update.Name)
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
		if iface.dpState.isReady {
			flags |= ifstate.FlgReady
		}
		v := ifstate.NewValue(flags, name,
			iface.dpState.policyIdx[hook.XDP],
			iface.dpState.policyIdx[hook.Ingress],
			iface.dpState.policyIdx[hook.Egress])
		m.ifStateMap.SetDesired(k, v)
	} else {
		if err := m.policyMapDelete(hook.XDP, iface.dpState.policyIdx[hook.XDP]); err != nil {
			log.WithError(err).Warn("Policy program may leak.")
		}
		if err := m.xdpPolicyMapAlloc.Put(iface.dpState.policyIdx[hook.XDP]); err != nil {
			log.WithError(err).Error("XDP")
		}

		if err := m.policyMapDelete(hook.Ingress, iface.dpState.policyIdx[hook.Ingress]); err != nil {
			log.WithError(err).Warn("Policy program may leak.")
		}
		if err := m.policyMapAlloc.Put(iface.dpState.policyIdx[hook.Ingress]); err != nil {
			log.WithError(err).Error("Ingress")
		}

		if err := m.policyMapDelete(hook.Egress, iface.dpState.policyIdx[hook.Egress]); err != nil {
			log.WithError(err).Warn("Policy program may leak.")
		}
		if err := m.policyMapAlloc.Put(iface.dpState.policyIdx[hook.Egress]); err != nil {
			log.WithError(err).Error("Ingress")
		}

		m.ifStateMap.DeleteDesired(k)
		iface.dpState.clearPolicies()
	}
}

func (m *bpfEndpointManager) deleteIfaceCounters(name string, ifindex int) {
	err := m.bpfmaps.CountersMap.Delete(counters.NewKey(ifindex, hook.Ingress).AsBytes())
	if err != nil && !maps.IsNotExists(err) {
		log.WithError(err).Warnf("Failed to remove  ingress counters for dev %s ifindex %d.", name, ifindex)
	}
	err = m.bpfmaps.CountersMap.Delete(counters.NewKey(ifindex, hook.Egress).AsBytes())
	if err != nil && !maps.IsNotExists(err) {
		log.WithError(err).Warnf("Failed to remove  egress counters for dev %s ifindex %d.", name, ifindex)
	}
	err = m.bpfmaps.CountersMap.Delete(counters.NewKey(ifindex, hook.XDP).AsBytes())
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
				if err := m.dp.setRPFilter(update.Name, 2); err != nil {
					log.WithError(err).Warnf("Failed to set rp_filter for %s.", update.Name)
				}
			}
			_ = m.dp.setAcceptLocal(update.Name, true)
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
			iface.dpState.isReady = false
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
func (m *bpfEndpointManager) onWorkloadEnpdointRemove(msg *proto.WorkloadEndpointRemove) {
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
		err := m.bpfmaps.RuleCountersMap.Delete(b)
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

func policyMapDeleteEntry(m maps.Map, idx int) error {
	if err := m.Delete(polprog.Key(idx)); err != nil {
		if maps.IsNotExists(err) {
			log.WithError(err).WithField("idx", idx).
				Warn("Policy program already not in table - inconsistency fixed!")
			return nil
		} else {
			log.WithError(err).Warn("Policy program may leak.")
			return err
		}
	}

	return nil
}

func (m *bpfEndpointManager) syncIfStateMap() {
	palloc := set.New[int]()
	xdpPalloc := set.New[int]()

	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	m.ifStateMap.IterDataplaneCache(func(k ifstate.Key, v ifstate.Value) {
		ifindex := int(k.IfIndex())
		netiface, err := net.InterfaceByIndex(ifindex)
		if err != nil {
			// "net" does not export the strings or err types :(
			if strings.Contains(err.Error(), "no such network interface") {
				m.ifStateMap.DeleteDesired(k)
				// Device does not exist anymore so delete all associated policies we know
				// about as we will not hear about that device again.
				if idx := v.XDPPolicy(); idx != -1 {
					_ = policyMapDeleteEntry(m.bpfmaps.XDPPolicyMap, idx)
				}
				if idx := v.IngressPolicy(); idx != -1 {
					_ = policyMapDeleteEntry(m.bpfmaps.PolicyMap, idx)
				}
				if idx := v.EgressPolicy(); idx != -1 {
					_ = policyMapDeleteEntry(m.bpfmaps.PolicyMap, idx)
				}
			} else {
				// It will get deleted by the first CompleteDeferredWork() if we
				// do not get any state update on that interface.
				log.WithError(err).Warnf("Failed to sync ifstate for iface %d, deffering it.", ifindex)
			}
		} else if m.isDataIface(netiface.Name) || m.isWorkloadIface(netiface.Name) || m.isL3Iface(netiface.Name) {
			// We only add iface that we still manage as configuration could have changed.

			m.ifStateMap.SetDesired(k, v)

			m.withIface(netiface.Name, func(iface *bpfInterface) bool {
				if netiface.Flags&net.FlagUp != 0 {
					iface.info.ifIndex = netiface.Index
					iface.info.isUP = true
					if v.Flags()&ifstate.FlgReady != 0 {
						iface.dpState.isReady = true
					}
				}

				var idx int

				if idx = v.XDPPolicy(); idx != -1 {
					xdpPalloc.Add(idx)
				}
				iface.dpState.policyIdx[hook.XDP] = idx

				if idx = v.IngressPolicy(); idx != -1 {
					palloc.Add(idx)
				}
				iface.dpState.policyIdx[hook.Ingress] = idx

				if idx = v.EgressPolicy(); idx != -1 {
					palloc.Add(idx)
				}
				iface.dpState.policyIdx[hook.Egress] = idx

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
			m.ifStateMap.DeleteDesired(k)
		}
	})

	// Fill unallocated indexes.
	for i := 0; i < polprog.MaxEntries; i++ {
		if !palloc.Contains(i) {
			_ = m.policyMapAlloc.Put(i)
		}
	}
	for i := 0; i < polprog.XDPMaxEntries; i++ {
		if !xdpPalloc.Contains(i) {
			_ = m.xdpPolicyMapAlloc.Put(i)
		}
	}
}

func (m *bpfEndpointManager) syncIfaceCounters() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("cannot list interfaces: %w", err)
	}

	exists := set.New[int]()
	for i := range ifaces {
		exists.Add(ifaces[i].Index)
	}

	err = m.bpfmaps.CountersMap.Iter(func(k, v []byte) maps.IteratorAction {
		var key counters.Key
		copy(key[:], k)

		if !exists.Contains(key.IfIndex()) {
			return maps.IterDelete
		}

		return maps.IterNone
	})

	if err != nil {
		return fmt.Errorf("iterating over countrs map failed")
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
		if size := maps.Size(m.Name()); size != 0 {
			if err := m.SetSize(size); err != nil {
				return fmt.Errorf("error resizing map %s: %w", m.Name(), err)
			}
		}
		if err := m.SetPinPath(path.Join(bpfdefs.GlobalPinDir, m.Name())); err != nil {
			return fmt.Errorf("error pinning map %s: %w", m.Name(), err)
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

		if err := m.dp.loadDefaultPolicies(); err != nil {
			log.WithError(err).Warn("Failed to load default policies, some programs may default to DENY.")
		}

		m.initUnknownIfaces = nil

		if err := m.syncIfaceCounters(); err != nil {
			log.WithError(err).Warn("Failed to sync counters map with existing interfaces - some counters may have leaked.")
		}
	})

	m.applyProgramsToDirtyDataInterfaces()
	m.updateWEPsInDataplane()
	if m.bpfPolicyDebugEnabled {
		m.removeDirtyPolicies()
	}

	bpfEndpointsGauge.Set(float64(len(m.nameToIface)))
	bpfDirtyEndpointsGauge.Set(float64(m.dirtyIfaceNames.Len()))

	if m.ctlbWorkaroundMode != ctlbWorkaroundDisabled {
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
		return err
	}

	if m.happyWEPsDirty {
		chains := m.ruleRenderer.WorkloadInterfaceAllowChains(m.happyWEPs)
		m.iptablesFilterTable.UpdateChains(chains)
		m.happyWEPsDirty = false
	}
	bpfHappyEndpointsGauge.Set(float64(len(m.happyWEPs)))
	// Copy data from old map to the new map
	m.copyDeltaOnce.Do(func() {
		log.Info("Copy delta entries from old map to the new map")
		err := m.bpfmaps.CtMap.CopyDeltaFromOldMap()
		if err != nil {
			log.WithError(err).Debugf("Failed to copy data from old conntrack map %s", err)
		}
	})

	if m.dirtyIfaceNames.Len() == 0 {
		if m.removeOldJumps {
			oldBase := path.Join(bpfdefs.GlobalPinDir, "old_jumps")
			if err := os.RemoveAll(oldBase); err != nil && os.IsNotExist(err) {
				return fmt.Errorf("failed to remove %s: %w", oldBase, err)
			}
			m.removeOldJumps = false
		}
		if m.legacyCleanUp {
			legacy.CleanUpMaps()
			m.legacyCleanUp = false
		}
	}

	return nil
}

func (m *bpfEndpointManager) applyProgramsToDirtyDataInterfaces() {
	var mutex sync.Mutex
	errs := map[string]error{}
	var wg sync.WaitGroup
	m.dirtyIfaceNames.Iter(func(iface string) error {
		if !m.isDataIface(iface) && !m.isL3Iface(iface) {
			log.WithField("iface", iface).Debug(
				"Ignoring interface that doesn't match the host data/l3 interface regex")
			return nil
		}

		var (
			err                           error
			up                            bool
			xdpIdx, ingressIdx, egressIdx int
		)

		m.ifacesLock.Lock()
		defer m.ifacesLock.Unlock()
		m.withIface(iface, func(iface *bpfInterface) bool {
			up = iface.info.ifaceIsUp()

			if xdpIdx = iface.dpState.policyIdx[hook.XDP]; xdpIdx == -1 {
				if xdpIdx, err = m.xdpPolicyMapAlloc.Get(); err != nil {
					return false
				}
			}
			iface.dpState.policyIdx[hook.XDP] = xdpIdx

			if ingressIdx = iface.dpState.policyIdx[hook.Ingress]; ingressIdx == -1 {
				if ingressIdx, err = m.policyMapAlloc.Get(); err != nil {
					return false
				}
			}
			iface.dpState.policyIdx[hook.Ingress] = ingressIdx

			if egressIdx = iface.dpState.policyIdx[hook.Egress]; egressIdx == -1 {
				if egressIdx, err = m.policyMapAlloc.Get(); err != nil {
					return false
				}
			}
			iface.dpState.policyIdx[hook.Egress] = egressIdx

			return false
		})

		if err != nil {
			errs[iface] = err
			return nil
		}

		if !up {
			log.WithField("iface", iface).Debug("Ignoring interface that is down")
			return set.RemoveItem
		}

		m.opReporter.RecordOperation("update-data-iface")

		wg.Add(1)
		go func() {
			defer wg.Done()

			// Attach the qdisc first; it is shared between the directions.
			err := m.dp.ensureQdisc(iface)
			if err != nil {
				mutex.Lock()
				errs[iface] = err
				mutex.Unlock()
				return
			}

			var hepPtr *proto.HostEndpoint
			if hep, hepExists := m.hostIfaceToEpMap[iface]; hepExists {
				hepPtr = &hep
			}

			var parallelWG sync.WaitGroup
			var ingressErr, xdpErr error
			parallelWG.Add(1)
			go func() {
				defer parallelWG.Done()
				ingressErr = m.attachDataIfaceProgram(iface, hepPtr, PolDirnIngress, ingressIdx)
			}()
			parallelWG.Add(1)
			go func() {
				defer parallelWG.Done()
				xdpErr = m.attachXDPProgram(iface, hepPtr, xdpIdx)
			}()

			err = m.attachDataIfaceProgram(iface, hepPtr, PolDirnEgress, egressIdx)
			parallelWG.Wait()
			if err == nil {
				err = ingressErr
			}
			if err == nil {
				err = xdpErr
			}
			if err == nil {
				// This is required to allow NodePort forwarding with
				// encapsulation with the host's IP as the source address
				_ = m.dp.setAcceptLocal(iface, true)
			}
			mutex.Lock()
			errs[iface] = err
			mutex.Unlock()
		}()
		return nil
	})
	wg.Wait()

	// We can hold the lock for the whole iteration below because nothing else
	// is running now. We hold it pretty much to make race detector happy.
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	for iface, err := range errs {
		isReady := true
		if err == nil {
			log.WithField("id", iface).Info("Applied program to host interface")
			m.dirtyIfaceNames.Discard(iface)
		} else {
			isReady = false
			if isLinkNotFoundError(err) {
				log.WithField("iface", iface).Debug(
					"Tried to apply BPF program to interface but the interface wasn't present.  " +
						"Will retry if it shows up.")
				m.dirtyIfaceNames.Discard(iface)
			} else {
				log.WithField("iface", iface).WithError(err).Warn("Failed to apply policy to interface, will retry")
			}
		}

		m.withIface(iface, func(i *bpfInterface) bool {
			i.dpState.isReady = isReady
			m.updateIfaceStateMap(iface, i)
			return false // no need to enforce dirty
		})
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
				_ = m.dp.setAcceptLocal(ifaceName, true)
			}
			mutex.Lock()
			errs[ifaceName] = err
			mutex.Unlock()
		}(ifaceName)
		return nil
	})
	wg.Wait()

	for ifaceName, err := range errs {
		iface := m.nameToIface[ifaceName]
		wlID := iface.info.endpointID

		m.updateIfaceStateMap(ifaceName, &iface)

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

func (m *bpfEndpointManager) doApplyPolicy(ifaceName string) (bpfInterfaceState, error) {
	startTime := time.Now()

	var state bpfInterfaceState

	// Other threads might be filling in jump map FDs in the map so take the lock.
	m.ifacesLock.Lock()
	var endpointID *proto.WorkloadEndpointID
	var ifaceUp bool
	m.withIface(ifaceName, func(iface *bpfInterface) (forceDirty bool) {
		ifaceUp = iface.info.ifaceIsUp()
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

	var err error

	if state.policyIdx[hook.Ingress] == -1 {
		state.policyIdx[hook.Ingress], err = m.policyMapAlloc.Get()
		if err != nil {
			return state, err
		}
	}

	if state.policyIdx[hook.Egress] == -1 {
		state.policyIdx[hook.Egress], err = m.policyMapAlloc.Get()
		if err != nil {
			return state, err
		}
	}

	// Otherwise, the interface appears to be present but we may or may not have an endpoint from the
	// datastore.  If we don't have an endpoint then we'll attach a program to block traffic and we'll
	// get the jump map ready to insert the policy if the endpoint shows up.

	// Attach the qdisc first; it is shared between the directions.
	err = m.dp.ensureQdisc(ifaceName)
	if err != nil {
		if isLinkNotFoundError(err) {
			// Interface is gone, nothing to do.
			log.WithField("ifaceName", ifaceName).Debug(
				"Ignoring request to program interface that is not present.")
			return state, nil
		}
		return state, err
	}

	var ingressErr, egressErr error
	var wg sync.WaitGroup
	var wep *proto.WorkloadEndpoint
	if endpointID != nil {
		wep = m.allWEPs[*endpointID]
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		ingressErr = m.attachWorkloadProgram(ifaceName, state.policyIdx[hook.Ingress], wep, PolDirnIngress)
	}()
	go func() {
		defer wg.Done()
		egressErr = m.attachWorkloadProgram(ifaceName, state.policyIdx[hook.Egress], wep, PolDirnEgress)
	}()
	wg.Wait()

	if ingressErr != nil {
		return state, ingressErr
	}
	if egressErr != nil {
		return state, egressErr
	}

	applyTime := time.Since(startTime)
	log.WithFields(log.Fields{"timeTaken": applyTime, "ifaceName": ifaceName}).
		Info("Finished applying BPF programs for workload")

	state.isReady = true

	return state, nil
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

func (m *bpfEndpointManager) attachWorkloadProgram(ifaceName string, jumpIdx int,
	endpoint *proto.WorkloadEndpoint, polDirection PolDirection) error {

	if m.hostIP == nil {
		// Do not bother and wait
		return fmt.Errorf("unknown host IP")
	}

	ap := m.calculateTCAttachPoint(polDirection, ifaceName)
	ap.HostIP = m.hostIP
	// * Since we don't pass packet length when doing fib lookup, MTU check is skipped.
	// * Hence it is safe to set the tunnel mtu same as veth mtu
	ap.TunnelMTU = uint16(m.vxlanMTU)
	ap.IntfIP = calicoRouterIP
	ap.ExtToServiceConnmark = uint32(m.bpfExtToServiceConnmark)
	ap.PolicyIdx4 = jumpIdx

	err := m.dp.ensureProgramAttached(ap)
	if err != nil {
		return err
	}

	var profileIDs []string
	var tier *proto.TierInfo
	if endpoint != nil {
		profileIDs = endpoint.ProfileIds
		if len(endpoint.Tiers) != 0 {
			tier = endpoint.Tiers[0]
		}
	} else {
		log.WithField("name", ifaceName).Debug(
			"Workload interface with no endpoint in datastore, installing default-drop program.")
	}

	// If tier or profileIDs is nil, this will return an empty set of rules but updatePolicyProgram appends a
	// drop rule, giving us default drop behaviour in that case.
	rules := m.extractRules(tier, profileIDs, polDirection)

	// If host-* endpoint is configured, add in its policy.
	if m.wildcardExists {
		m.addHostPolicy(&rules, &m.wildcardHostEndpoint, polDirection.Inverse())
	}

	// If workload egress and DefaultEndpointToHostAction is ACCEPT or DROP, suppress the normal
	// host-* endpoint policy.
	if polDirection == PolDirnEgress && m.epToHostAction != "RETURN" {
		rules.SuppressNormalHostPolicy = true
	}

	// If host -> workload, always suppress the normal host-* endpoint policy.
	if polDirection == PolDirnIngress {
		rules.SuppressNormalHostPolicy = true
	}

	return m.updatePolicyProgramFn(rules, polDirection.RuleDir(), ap)
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

func (m *bpfEndpointManager) attachDataIfaceProgram(ifaceName string, ep *proto.HostEndpoint,
	polDirection PolDirection, jumpIdx int) error {

	if m.hostIP == nil {
		// Do not bother and wait
		return fmt.Errorf("unknown host IP")
	}

	ap := m.calculateTCAttachPoint(polDirection, ifaceName)
	ap.HostIP = m.hostIP
	ap.TunnelMTU = uint16(m.vxlanMTU)
	ap.ExtToServiceConnmark = uint32(m.bpfExtToServiceConnmark)
	ip, err := m.getInterfaceIP(ifaceName)
	if err != nil {
		log.Debugf("Error getting IP for interface %+v: %+v", ifaceName, err)
		ap.IntfIP = m.hostIP
	} else {
		ap.IntfIP = *ip
	}
	ap.NATin = uint32(m.natInIdx)
	ap.NATout = uint32(m.natOutIdx)
	ap.PolicyIdx4 = jumpIdx

	if err := m.dp.ensureProgramAttached(ap); err != nil {
		return err
	}

	if ep != nil {
		rules := polprog.Rules{
			ForHostInterface: true,
		}
		m.addHostPolicy(&rules, ep, polDirection)
		return m.updatePolicyProgramFn(rules, polDirection.RuleDir(), ap)
	}

	if err := m.dp.removePolicyProgram(ap); err != nil {
		return err
	}
	return nil
}

func (m *bpfEndpointManager) attachXDPProgram(ifaceName string, ep *proto.HostEndpoint, jumpIdx int) error {
	ap := &xdp.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			Hook:       hook.XDP,
			Iface:      ifaceName,
			LogLevel:   m.bpfLogLevel,
			PolicyIdx4: jumpIdx,
		},
		Modes: m.xdpModes,
	}

	if ep != nil && len(ep.UntrackedTiers) == 1 {
		err := m.dp.ensureProgramAttached(ap)
		if err != nil {
			return err
		}

		ap.Log().Debugf("Building program for untracked policy hep=%v", ep.Name)
		rules := polprog.Rules{
			ForHostInterface: true,
			HostNormalTiers:  m.extractTiers(ep.UntrackedTiers[0], PolDirnIngress, false),
			ForXDP:           true,
		}
		ap.Log().Debugf("Rules: %v", rules)
		return m.updatePolicyProgramFn(rules, "xdp", ap)
	} else {
		return m.dp.ensureNoProgram(ap)
	}
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

func (m *bpfEndpointManager) calculateTCAttachPoint(policyDirection PolDirection, ifaceName string) *tc.AttachPoint {
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
		ap.HostTunnelIP = m.tunnelIP
		log.Debugf("Setting tunnel ip %s on ap %s", m.tunnelIP, ifaceName)
	} else if ifaceName == "tunl0" {
		if m.Features.IPIPDeviceIsL3 {
			endpointType = tcdefs.EpTypeL3Device
		} else {
			endpointType = tcdefs.EpTypeTunnel
		}
	} else if ifaceName == "wireguard.cali" || m.isL3Iface(ifaceName) {
		endpointType = tcdefs.EpTypeL3Device
	} else if ifaceName == bpfInDev || ifaceName == bpfOutDev {
		endpointType = tcdefs.EpTypeNAT
		ap.HostTunnelIP = m.tunnelIP
		log.Debugf("Setting tunnel ip %s on ap %s", m.tunnelIP, ifaceName)
	} else if m.isDataIface(ifaceName) {
		endpointType = tcdefs.EpTypeHost
		ap.HostTunnelIP = m.tunnelIP
		log.Debugf("Setting tunnel ip %s on ap %s", m.tunnelIP, ifaceName)
	} else {
		log.Panicf("Unsupported ifaceName %v", ifaceName)
	}

	if endpointType == tcdefs.EpTypeWorkload {
		// Policy direction is relative to the workload so, from the host namespace it's flipped.
		if policyDirection == PolDirnIngress {
			ap.Hook = hook.Egress
		} else {
			ap.Hook = hook.Ingress
		}
	} else {
		ap.WgPort = m.wgPort
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

	ap.Type = endpointType
	ap.ToOrFrom = toOrFrom
	ap.ToHostDrop = (m.epToHostAction == "DROP")
	ap.FIB = m.fibLookupEnabled
	ap.DSR = m.dsrEnabled
	ap.DSROptoutCIDRs = m.dsrOptoutCidrs
	ap.LogLevel = m.bpfLogLevel
	ap.VXLANPort = m.vxlanPort
	ap.PSNATStart = m.psnatPorts.MinPort
	ap.PSNATEnd = m.psnatPorts.MaxPort
	ap.IPv6Enabled = m.ipv6Enabled

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
					MatchID: m.dp.ruleMatchID(dir, r.Action, "Policy", polName, ri),
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
					MatchID: m.dp.ruleMatchID(dir, r.Action, "Profile", profName, ri),
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
		(m.ctlbWorkaroundMode != ctlbWorkaroundDisabled && (iface == bpfOutDev || iface == "lo"))
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
			m.policiesToWorkloads[polID] = set.NewBoxed[any]()
		}
		m.policiesToWorkloads[polID].Add(id)
	}
}

func (m *bpfEndpointManager) addProfileToEPMappings(profileIds []string, id interface{}) {
	for _, profName := range profileIds {
		profID := proto.ProfileID{Name: profName}
		profSet := m.profilesToWorkloads[profID]
		if profSet == nil {
			profSet = set.NewBoxed[any]()
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
		log.WithField("err", err).Errorf("Failed to  set %s to %s", path, numval)
		return err
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

	if err := m.ifStateMap.LoadCacheFromDataplane(); err != nil {
		log.WithError(err).Fatal("Cannot load interface state map - essential for consistent operation.")
	}
}

func (m *bpfEndpointManager) ensureBPFDevices() error {
	if m.ctlbWorkaroundMode == ctlbWorkaroundDisabled {
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

	anyV4, _ := ip.CIDRFromString("0.0.0.0/0")
	_ = m.arpMap.Update(
		bpfarp.NewKey(anyV4.Addr().AsNetIP(), uint32(m.natInIdx)).AsBytes(),
		bpfarp.NewValue(bpfin.Attrs().HardwareAddr, bpfout.Attrs().HardwareAddr).AsBytes(),
	)

	// Add a permanent ARP entry to point to the other side of the veth to avoid
	// ARP requests that would not be proxied if .all.rp_filter == 1
	arp := &netlink.Neigh{
		State:        netlink.NUD_PERMANENT,
		IP:           net.IPv4(169, 254, 1, 1),
		HardwareAddr: bpfout.Attrs().HardwareAddr,
		LinkIndex:    bpfin.Attrs().Index,
	}
	if err := netlink.NeighAdd(arp); err != nil && err != syscall.EEXIST {
		return fmt.Errorf("failed to update neight for %s: %w", bpfOutDev, err)
	}

	if err := configureInterface(bpfInDev, 4, "0", writeProcSys); err != nil {
		return fmt.Errorf("failed to configure %s parameters: %w", bpfInDev, err)
	}
	if err := configureInterface(bpfOutDev, 4, "0", writeProcSys); err != nil {
		return fmt.Errorf("failed to configure %s parameters: %w", bpfOutDev, err)
	}

	err = m.ensureQdisc(bpfInDev)
	if err != nil {
		return fmt.Errorf("failed to set qdisc on %s: %w", bpfOutDev, err)
	}

	err = m.ensureQdisc("lo")
	if err != nil {
		log.WithError(err).Fatalf("Failed to set qdisc on lo.")
	}

	// Setup a link local route to a non-existent link local address that would
	// serve as a gateway to route services via bpfnat veth rather than having
	// link local routes for each service that would trigger ARP querries.
	cidr, _ := ip.CIDRFromString("169.254.1.1/32")

	m.routeTable.RouteUpdate(bpfInDev, routetable.Target{
		Type: routetable.TargetTypeLinkLocalUnicast,
		CIDR: cidr,
	})

	return nil
}

func (m *bpfEndpointManager) ensureQdisc(iface string) error {
	return tc.EnsureQdisc(iface)
}

// Ensure TC/XDP program is attached to the specified interface.
func (m *bpfEndpointManager) ensureProgramAttached(ap attachPoint) error {
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

		pm := m.bpfmaps.ProgramsMap.(*hook.ProgramsMap)

		at.Family = 4
		if aptc.HookLayout4, err = pm.LoadObj(at); err != nil {
			return fmt.Errorf("loading generic v4 tc hook program: %w", err)
		}

		// Load deafault policy before the real policy is created and loaded.
		switch at.DefaultPolicy() {
		case hook.DefPolicyAllow:
			err = maps.UpdateMapEntry(m.bpfmaps.PolicyMap.MapFD(),
				polprog.Key(ap.PolicyIdx(4)), polprog.Value(m.policyTcAllowFD))
		case hook.DefPolicyDeny:
			err = maps.UpdateMapEntry(m.bpfmaps.PolicyMap.MapFD(),
				polprog.Key(ap.PolicyIdx(4)), polprog.Value(m.policyTcDenyFD))
		}

		if err != nil {
			return fmt.Errorf("failed to set default policy: %w", err)
		}

		if aptc.IPv6Enabled {
			at.Family = 6
			if aptc.HookLayout6, err = pm.LoadObj(at); err != nil {
				return fmt.Errorf("loading generic v6 tc hook program: %w", err)
			}
		}

	} else if apxdp, ok := ap.(*xdp.AttachPoint); ok {
		at := hook.AttachType{
			Hook:     hook.XDP,
			LogLevel: apxdp.LogLevel,
		}

		pm := m.bpfmaps.XDPProgramsMap.(*hook.ProgramsMap)
		if apxdp.HookLayout, err = pm.LoadObj(at); err != nil {
			return fmt.Errorf("loading generic xdp hook program: %w", err)
		}
	} else {
		return fmt.Errorf("unknown attach type")
	}

	_, err = ap.AttachProgram()

	return err
}

// Ensure that the specified attach point does not have our program.
func (m *bpfEndpointManager) ensureNoProgram(ap attachPoint) error {
	// Ensure interface does not have our program attached.
	err := ap.DetachProgram()

	if err := m.policyMapDelete(ap.HookName(), ap.PolicyIdx(4)); err != nil {
		log.WithError(err).Warn("Policy program may leak.")
	}

	// Forget the policy debug info
	m.removePolicyDebugInfo(ap.IfaceName(), 4, ap.HookName())

	return err
}

func (m *bpfEndpointManager) removeIfaceAllPolicyDebugInfo(ifaceName string) {
	ipVersions := []proto.IPVersion{proto.IPVersion_IPV4}
	if m.ipv6Enabled {
		ipVersions = append(ipVersions, proto.IPVersion_IPV6)
	}

	for _, ipFamily := range ipVersions {
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

func (m *bpfEndpointManager) writePolicyDebugInfo(insns asm.Insns, ifaceName string, ipFamily proto.IPVersion, polDir string, h hook.Hook, polErr error) error {
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

	var policyDebugInfo = bpf.PolicyDebugInfo{
		IfaceName:  ifaceName,
		Hook:       "tc " + h.String(),
		PolicyInfo: insns,
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

func (m *bpfEndpointManager) updatePolicyProgram(rules polprog.Rules, polDir string, ap attachPoint) error {
	ipVersions := []proto.IPVersion{proto.IPVersion_IPV4}
	if m.ipv6Enabled {
		ipVersions = append(ipVersions, proto.IPVersion_IPV6)
	}

	for _, ipFamily := range ipVersions {
		progName := policyProgramName(ap.IfaceName(), polDir, ipFamily)
		insns, err := m.doUpdatePolicyProgram(ap, progName, rules, ipFamily)
		perr := m.writePolicyDebugInfo(insns, ap.IfaceName(), ipFamily, polDir, ap.HookName(), err)
		if perr != nil {
			log.WithError(perr).Warn("error writing policy debug information")
		}
		if err != nil {
			return fmt.Errorf("failed to update policy program v%d: %w", ipFamily, err)
		}
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

func (m *bpfEndpointManager) loadPolicyProgram(progName string,
	ipFamily proto.IPVersion, rules polprog.Rules, progsMap maps.Map, opts ...polprog.Option) (
	bpf.ProgFD, asm.Insns, error) {

	pg := polprog.NewBuilder(m.ipSetIDAlloc, m.bpfmaps.IpsetsMap.MapFD(),
		m.bpfmaps.StateMap.MapFD(), progsMap.MapFD(), opts...)
	if ipFamily == proto.IPVersion_IPV6 {
		pg.EnableIPv6Mode()
	}
	insns, err := pg.Instructions(rules)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to generate policy bytecode v%v: %w", ipFamily, err)
	}
	progType := unix.BPF_PROG_TYPE_SCHED_CLS
	if rules.ForXDP {
		progType = unix.BPF_PROG_TYPE_XDP
	}
	progFD, err := bpf.LoadBPFProgramFromInsns(insns, progName, "Apache-2.0", uint32(progType))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to load BPF policy program v%v: %w", ipFamily, err)
	}

	return progFD, insns, nil
}

func (m *bpfEndpointManager) doUpdatePolicyProgram(ap attachPoint, progName string, rules polprog.Rules,
	ipFamily proto.IPVersion) (asm.Insns, error) {

	opts := []polprog.Option{}
	if m.bpfPolicyDebugEnabled {
		opts = append(opts, polprog.WithPolicyDebugEnabled())
	}

	progsMap := m.bpfmaps.ProgramsMap
	if ap.HookName() == hook.XDP {
		progsMap = m.bpfmaps.XDPProgramsMap
	}

	if apj, ok := ap.(attachPointWithPolicyJumps); ok {
		allow := apj.PolicyAllowJumpIdx(int(ipFamily))
		if allow == -1 {
			return nil, fmt.Errorf("no allow jump index")
		}

		deny := apj.PolicyDenyJumpIdx(int(ipFamily))
		if deny == -1 {
			return nil, fmt.Errorf("no deny jump index")
		}

		opts = append(opts, polprog.WithAllowDenyJumps(allow, deny))
	}

	progFD, insns, err := m.loadPolicyProgramFn(progName, ipFamily, rules, progsMap, opts...)
	if err != nil {
		return nil, err
	}

	defer func() {
		// Once we've put the program in the map, we don't need its FD any more.
		err := progFD.Close()
		if err != nil {
			log.WithError(err).Panic("Failed to close program FD.")
		}
	}()

	if err := m.policyMapUpdate(ap, int(ipFamily), progFD); err != nil {
		return nil, err
	}

	return insns, nil
}

func (m *bpfEndpointManager) policyMapUpdate(ap attachPoint, family int, fd bpf.ProgFD) error {
	polMap := m.bpfmaps.PolicyMap
	if ap.HookName() == hook.XDP {
		polMap = m.bpfmaps.XDPPolicyMap
	}

	jumpIdx := ap.PolicyIdx(int(family))
	if err := polMap.Update(polprog.Key(jumpIdx), polprog.Value(fd)); err != nil {
		return fmt.Errorf("failed to update %s policy jump map [%d]=%d: %w", ap.HookName(), jumpIdx, fd, err)
	}

	return nil
}

func (m *bpfEndpointManager) policyMapDelete(h hook.Hook, idx int) error {
	if idx < 0 {
		return nil
	}

	polMap := m.bpfmaps.PolicyMap
	if h == hook.XDP {
		polMap = m.bpfmaps.XDPPolicyMap
	}

	return policyMapDeleteEntry(polMap, idx)
}

func (m *bpfEndpointManager) removePolicyProgram(ap attachPoint) error {
	ipVersions := []proto.IPVersion{proto.IPVersion_IPV4}
	if m.ipv6Enabled {
		ipVersions = append(ipVersions, proto.IPVersion_IPV6)
	}

	for _, ipFamily := range ipVersions {
		idx := ap.PolicyIdx(int(ipFamily))
		if idx == -1 {
			continue
		}

		var pm maps.Map

		if ap.HookName() == hook.XDP {
			pm = m.bpfmaps.PolicyMap
		} else {
			pm = m.bpfmaps.XDPPolicyMap
		}

		if err := policyMapDeleteEntry(pm, idx); err != nil {
			return fmt.Errorf("removing policy iface %s hook %s: %w", ap.IfaceName(), ap.HookName(), err)
		}

		m.removePolicyDebugInfo(ap.IfaceName(), ipFamily, ap.HookName())
	}

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

func (m *bpfEndpointManager) getInterfaceIP(ifaceName string) (*net.IP, error) {
	var ipAddrs []net.IP
	if ip, ok := m.ifaceToIpMap[ifaceName]; ok {
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
	for _, addr := range addrs {
		switch t := addr.(type) {
		case *net.IPNet:
			if t.IP.To4() != nil {
				ipAddrs = append(ipAddrs, t.IP)
			}
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
	if m.ctlbWorkaroundMode == ctlbWorkaroundDisabled {
		return
	}

	if m.ctlbWorkaroundMode == ctlbWorkaroundUDPOnly {
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

	ips := make([]string, 0, 2)
	if update.ClusterIp != "" {
		ips = append(ips, update.ClusterIp)
	}
	if update.LoadbalancerIp != "" {
		ips = append(ips, update.LoadbalancerIp)
	}

	key := serviceKey{name: update.Name, namespace: update.Namespace}

	ips4 := make([]ip.V4CIDR, 0, len(ips))
	for _, i := range ips {
		cidr, err := ip.ParseCIDROrIP(i)
		if err != nil {
			log.WithFields(log.Fields{"service": key, "ip": i}).Warn("Not a valid CIDR.")
		} else if cidrv4, ok := cidr.(ip.V4CIDR); !ok {
			log.WithFields(log.Fields{"service": key, "ip": i}).Debug("Not a valid V4 CIDR.")
		} else {
			ips4 = append(ips4, cidrv4)
		}
	}

	// Check which IPs have been removed (no-op if we haven't seen it yet)
	for _, old := range m.services[key] {
		exists := false
		for _, svcIP := range ips4 {
			if old == svcIP {
				exists = true
				break
			}
		}
		if !exists {
			m.dp.delRoute(old)
		}
	}

	m.services[key] = ips4
	m.dirtyServices.Add(key)
}

func (m *bpfEndpointManager) onServiceRemove(update *proto.ServiceRemove) {
	if m.ctlbWorkaroundMode == ctlbWorkaroundDisabled {
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

var bpfnatGW = ip.FromNetIP(net.IPv4(169, 254, 1, 1))

func (m *bpfEndpointManager) setRoute(cidr ip.V4CIDR) {
	m.routeTable.RouteUpdate(bpfInDev, routetable.Target{
		Type: routetable.TargetTypeGlobalUnicast,
		CIDR: cidr,
		GW:   bpfnatGW,
	})
	log.WithFields(log.Fields{
		"cidr": cidr,
	}).Debug("setRoute")
}

func (m *bpfEndpointManager) delRoute(cidr ip.V4CIDR) {
	m.routeTable.RouteRemove(bpfInDev, cidr)
	log.WithFields(log.Fields{
		"cidr": cidr,
	}).Debug("delRoute")
}

func (m *bpfEndpointManager) GetRouteTableSyncers() []routetable.RouteTableSyncer {
	if m.ctlbWorkaroundMode == ctlbWorkaroundDisabled {
		return nil
	}

	tables := []routetable.RouteTableSyncer{m.routeTable}

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

type policyMapAlloc struct {
	max  int
	free chan int
}

func (pa *policyMapAlloc) Get() (int, error) {
	select {
	case i := <-pa.free:
		return i, nil
	default:
		return -1, errors.New("ran out of policy map indexes")
	}
}

func (pa *policyMapAlloc) Put(i int) error {
	if i < 0 || i >= pa.max {
		return nil // ignore, expecially if an index is -1 aka unused
	}

	select {
	case pa.free <- i:
		return nil
	default:
		return errors.New("returning more policy indexes than previously allocated!")
	}
}
