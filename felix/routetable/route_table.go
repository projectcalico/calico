// Copyright (c) 2016-2023 Tigera, Inc. All rights reserved.
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

package routetable

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/projectcalico/calico/felix/conntrack"
	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/netlinkshim/handlemgr"
	"github.com/projectcalico/calico/felix/timeshim"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	GetFailed       = errors.New("netlink get operation failed")
	ConnectFailed   = errors.New("connect to netlink failed")
	ListFailed      = errors.New("netlink list operation failed")
	UpdateFailed    = errors.New("netlink update operation failed")
	IfaceNotPresent = errors.New("interface not present")
	IfaceDown       = errors.New("interface down")
	IfaceGrace      = errors.New("interface in cleanup grace period")

	ipV6LinkLocalCIDR = ip.MustParseCIDROrIP("fe80::/64")

	listAllRoutesTime = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_route_table_list_all_routes_seconds",
		Help: "Time taken to list all the routes during a resync.",
	})
)

func init() {
	prometheus.MustRegister(listAllRoutesTime)
}

const (
	// Use this for targets with no outbound interface.
	InterfaceNone = "*NoOIF*"
)

type TargetType string

const (
	TargetTypeLocal            TargetType = "local"
	TargetTypeVXLAN            TargetType = "vxlan"
	TargetTypeNoEncap          TargetType = "noencap"
	TargetTypeOnLink           TargetType = "onlink"
	TargetTypeGlobalUnicast    TargetType = "global-unicast"
	TargetTypeLinkLocalUnicast TargetType = "local-unicast"

	// The following target types should be used with InterfaceNone.
	TargetTypeBlackhole   TargetType = "blackhole"
	TargetTypeProhibit    TargetType = "prohibit"
	TargetTypeThrow       TargetType = "throw"
	TargetTypeUnreachable TargetType = "unreachable"
)

const (
	maxApplyRetries = 2
)

type L2Target struct {
	// For VXLAN targets, this is the node's real IP address.
	IP ip.Addr

	// For VXLAN targets, this is the MAC address of the remote VTEP.
	VTEPMAC net.HardwareAddr

	// For VXLAN targets, this is the IP address of the remote VTEP.
	GW ip.Addr
}

type Target struct {
	Type    TargetType
	CIDR    ip.CIDR
	GW      ip.Addr
	Src     ip.Addr
	DestMAC net.HardwareAddr
}

func (t Target) Equal(t2 Target) bool {
	return reflect.DeepEqual(t, t2)
}

func (t Target) RouteType() int {
	switch t.Type {
	case TargetTypeLocal:
		return unix.RTN_LOCAL
	case TargetTypeThrow:
		return unix.RTN_THROW
	case TargetTypeBlackhole:
		return unix.RTN_BLACKHOLE
	case TargetTypeProhibit:
		return unix.RTN_PROHIBIT
	case TargetTypeUnreachable:
		return unix.RTN_UNREACHABLE
	default:
		return unix.RTN_UNICAST
	}
}

func (t Target) RouteScope() netlink.Scope {
	switch t.Type {
	case TargetTypeLocal:
		return netlink.SCOPE_HOST
	case TargetTypeLinkLocalUnicast:
		return netlink.SCOPE_LINK
	case TargetTypeGlobalUnicast:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeNoEncap:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeVXLAN:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeThrow:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeBlackhole:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeProhibit:
		return netlink.SCOPE_UNIVERSE
	case TargetTypeOnLink:
		return netlink.SCOPE_LINK
	default:
		return netlink.SCOPE_LINK
	}
}

func (t Target) Flags() netlink.NextHopFlag {
	switch t.Type {
	case TargetTypeVXLAN, TargetTypeNoEncap, TargetTypeOnLink:
		return unix.RTNH_F_ONLINK
	default:
		return 0
	}
}

// kernelRouteKey represents the kernel's FIB key.  The kernel allows routes
// to coexist as long as they have different keys.
type kernelRouteKey struct {
	// Destination CIDR; route matches traffic to this destination.
	CIDR ip.CIDR
	// TOS is the Type-of-Service field.  For example, one app may mark its
	// packets as "high importance" and that will take a different route to
	// another app.
	//
	// Kernel uses the TOS=0 route if there isn't a more precise match.
	TOS int
	// Priority is the routing metric / distance.  Given two routes with the
	// same CIDR, the kernel prefers the route with the _lower_ priority.
	Priority int
}

// kernelRoute is our low-level representation of a route. It contains fields
// that we can easily read back from the kernel for comparison. In particular,
// we track the interface index instead of the interface name.  This means that
// when interface indexes change, we must trigger recalculation of the desired
// kernelRoute.
type kernelRoute struct {
	Type     int // unix.RTN_... constants.
	Scope    netlink.Scope
	GW       ip.Addr
	Src      ip.Addr
	Ifindex  int
	Protocol netlink.RouteProtocol
	OnLink   bool
	// FIXME Add ARP entries
}

func (r kernelRoute) GWAsNetIP() net.IP {
	if r.GW == nil {
		return nil
	}
	return r.GW.AsNetIP()
}

func (r kernelRoute) SrcAsNetIP() net.IP {
	if r.Src == nil {
		return nil
	}
	return r.Src.AsNetIP()
}

// RouteTable manages calico routes for a specific table. It reconciles the
// routes that we desire to have for calico managed devices with what is the
// current status in the dataplane. That is, it removes any routes that we do
// not desire and adds those that we do. It skips over devices that we do not
// manage not to interfere with other users of the route tables.
type RouteTable struct {
	logCxt        *log.Entry
	ipVersion     uint8
	netlinkFamily int

	// Interface update tracking.
	fullResync         bool
	ifacesToRescan     set.Set[string]
	ifacePrefixRegexp  *regexp.Regexp
	includeNoInterface bool

	// ifaceToRoutes and cidrToIfaces are our inputs, updated
	// eagerly when something in the manager layer tells us tp change the
	// routes.  The API to the manager layer is indexed on interface, but
	// there's a mismatch with the kernel, which is indexed on CIDR.  We
	// track both so that we can resolve conflicts.
	ifaceToRoutes map[string]map[ip.CIDR]Target
	cidrToIfaces  map[ip.CIDR]set.Set[string]

	// kernelRoutes tracks the relationship between the route that we want
	// to program for a given CIDR (i.e. the route selected after conflict
	// resolution if there are multiple routes) and the route that's actually
	// in the kernel.
	kernelRoutes *deltatracker.DeltaTracker[kernelRouteKey, kernelRoute]

	l2Targets            *deltatracker.DeltaTracker[string, []L2Target]
	ifaceNameToFirstSeen map[string]time.Time
	ifaceNameToIndex     map[string]int
	ifaceIndexToName     map[int]string

	pendingConntrackCleanups map[ip.Addr]chan struct{}

	// Whether this route table is managing vxlan routes.
	vxlan bool

	deviceRouteSourceAddress ip.Addr

	deviceRouteProtocol  netlink.RouteProtocol
	removeExternalRoutes bool

	nl *handlemgr.HandleManager

	// The routing table index.  This is defaulted to RT_TABLE_MAIN if not specified.
	tableIndex int

	// Testing shims, swapped with mock versions for UT
	addStaticARPEntry func(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error
	conntrack         conntrackIface
	time              timeshim.Interface

	opReporter       logutils.OpRecorder
	livenessCallback func()

	// The route deletion grace period.
	routeCleanupGracePeriod time.Duration
	featureDetector         environment.FeatureDetectorIface
}

type RouteTableOpt func(table *RouteTable)

func WithLivenessCB(cb func()) RouteTableOpt {
	return func(table *RouteTable) {
		table.livenessCallback = cb
	}
}

func WithRouteCleanupGracePeriod(routeCleanupGracePeriod time.Duration) RouteTableOpt {
	return func(table *RouteTable) {
		table.routeCleanupGracePeriod = routeCleanupGracePeriod
	}
}

func New(
	interfaceRegexes []string,
	ipVersion uint8,
	vxlan bool,
	netlinkTimeout time.Duration,
	deviceRouteSourceAddress net.IP,
	deviceRouteProtocol netlink.RouteProtocol,
	removeExternalRoutes bool,
	tableIndex int,
	opReporter logutils.OpRecorder,
	featureDetector environment.FeatureDetectorIface,
	opts ...RouteTableOpt,
) *RouteTable {
	return NewWithShims(
		interfaceRegexes,
		ipVersion,
		netlinkshim.NewRealNetlink,
		vxlan,
		netlinkTimeout,
		addStaticARPEntry,
		conntrack.New(),
		timeshim.RealTime(),
		deviceRouteSourceAddress,
		deviceRouteProtocol,
		removeExternalRoutes,
		tableIndex,
		opReporter,
		featureDetector,
		opts...,
	)
}

// NewWithShims is a test constructor, which allows netlink, arp and time to be replaced by shims.
func NewWithShims(
	interfaceRegexes []string,
	ipVersion uint8,
	newNetlinkHandle func() (netlinkshim.Interface, error),
	vxlan bool,
	netlinkTimeout time.Duration,
	addStaticARPEntry func(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error,
	conntrack conntrackIface,
	timeShim timeshim.Interface,
	deviceRouteSourceAddress net.IP,
	deviceRouteProtocol netlink.RouteProtocol,
	removeExternalRoutes bool,
	tableIndex int,
	opReporter logutils.OpRecorder,
	featureDetector environment.FeatureDetectorIface,
	opts ...RouteTableOpt,
) *RouteTable {
	var filteredRegexes []string
	includeNoOIF := false

	for _, interfaceRegex := range interfaceRegexes {
		if interfaceRegex == InterfaceNone {
			includeNoOIF = true
		} else {
			filteredRegexes = append(filteredRegexes, interfaceRegex)
		}
	}

	if tableIndex == 0 {
		// If we set route.Table to 0, what we actually get is a route in RT_TABLE_MAIN.  However,
		// RouteListFiltered is much more efficient if we give it the "real" table number.
		log.Debug("RouteTable created with unspecified table; defaulting to unix.RT_TABLE_MAIN.")
		tableIndex = unix.RT_TABLE_MAIN
	}

	logCxt := log.WithFields(log.Fields{
		"ipVersion":  ipVersion,
		"tableIndex": tableIndex,
	})

	// Create a regexp matching the interfaces this route table manages.
	var ifacePrefixRegexp *regexp.Regexp
	if len(filteredRegexes) == 0 && len(interfaceRegexes) > 0 {
		// All of the regexp parts were special matches for non-interface types. In this case don't match any
		// interfaces.
		logCxt.Info("No interface matches required for routetable")
	} else {
		// Either there were no regexp parts supplied (same as match all), or at least one real interface was included.
		// Compile the interface regex.
		ifaceNamePattern := strings.Join(filteredRegexes, "|")
		logCxt = logCxt.WithField("ifaceRegex", ifaceNamePattern)
		ifacePrefixRegexp = regexp.MustCompile(ifaceNamePattern)
		logCxt.Info("Calculated interface name regexp")
	}

	family := netlink.FAMILY_V4
	if ipVersion == 6 {
		family = netlink.FAMILY_V6
	} else if ipVersion != 4 {
		log.WithField("ipVersion", ipVersion).Panic("Unknown IP version")
	}

	rt := &RouteTable{
		logCxt:             logCxt,
		ipVersion:          ipVersion,
		netlinkFamily:      family,
		ifacePrefixRegexp:  ifacePrefixRegexp,
		includeNoInterface: includeNoOIF,

		ifaceToRoutes: map[string]map[ip.CIDR]Target{},
		cidrToIfaces:  map[ip.CIDR]set.Set[string]{},

		kernelRoutes: deltatracker.New[kernelRouteKey, kernelRoute](),
		l2Targets:    deltatracker.New[string, []L2Target](),

		ifaceNameToFirstSeen:     map[string]time.Time{},
		fullResync:               true,
		pendingConntrackCleanups: map[ip.Addr]chan struct{}{},
		addStaticARPEntry:        addStaticARPEntry,
		conntrack:                conntrack,
		time:                     timeShim,
		vxlan:                    vxlan,
		deviceRouteSourceAddress: ip.FromNetIP(deviceRouteSourceAddress), // FIXME use ip.Addr as input
		deviceRouteProtocol:      deviceRouteProtocol,
		removeExternalRoutes:     removeExternalRoutes,
		tableIndex:               tableIndex,
		opReporter:               opReporter,
		livenessCallback:         func() {},
		nl: handlemgr.NewHandleManager(
			family,
			featureDetector,
			handlemgr.WithNewHandleOverride(newNetlinkHandle),
			handlemgr.WithSocketTimeout(netlinkTimeout),
		),
		featureDetector: featureDetector,
	}

	for _, o := range opts {
		o(rt)
	}

	return rt
}

func (r *RouteTable) OnIfaceStateChanged(ifaceName string, ifIndex int, state ifacemonitor.State) {
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	if r.ifacePrefixRegexp == nil || !r.ifacePrefixRegexp.MatchString(ifaceName) {
		logCxt.Debug("Ignoring interface state change, not an interface managed by this routetable.")
		return
	}
	if state == ifacemonitor.StateNotPresent {
		// Interface explicitly deleted, if it shows up again then we'll give it
		// a new grace period.
		delete(r.ifaceNameToFirstSeen, ifaceName)
	} else {
		r.onIfaceSeen(ifaceName)
	}

	recalculate := false
	if state == ifacemonitor.StateNotPresent {
		// Interface deleted, clean up.
		oldIndex := r.ifaceNameToIndex[ifaceName]
		delete(r.ifaceIndexToName, oldIndex)
		delete(r.ifaceNameToIndex, ifaceName)
		recalculate = true
	} else if ifIndex != r.ifaceNameToIndex[ifaceName] {
		// Interface index new/updated.
		delete(r.ifaceIndexToName, r.ifaceNameToIndex[ifaceName])
		r.ifaceNameToIndex[ifaceName] = ifIndex
		r.ifaceIndexToName[ifIndex] = ifaceName
		recalculate = true
	}

	if state == ifacemonitor.StateUp {
		// When an interface goes down/up that can remove its routes, mark
		// all its routes as suspect.
		logCxt.Debug("Interface up, marking for route sync")
		r.ifacesToRescan.Add(ifaceName)
		recalculate = true
	}

	if recalculate {
		r.recalculateAllIfaceRoutes(ifaceName)
	}
}

func (r *RouteTable) onIfaceSeen(ifaceName string) {
	if _, ok := r.ifaceNameToFirstSeen[ifaceName]; ok {
		return
	}
	r.ifaceNameToFirstSeen[ifaceName] = r.time.Now()
}

// SetRoutes replaces the full set of targets for the specified interface.
func (r *RouteTable) SetRoutes(ifaceName string, targets []Target) {
	if ifaceName == InterfaceNone && !r.includeNoInterface {
		r.logCxt.Error("Setting route with no interface")
		return
	}

	// Figure out what has changed.
	oldTargetsToCleanUp := r.ifaceToRoutes[ifaceName]
	newTargets := map[ip.CIDR]Target{}
	for _, t := range targets {
		delete(oldTargetsToCleanUp, t.CIDR)
		newTargets[t.CIDR] = t
		r.addOwningIface(ifaceName, t.CIDR)
	}

	// Record the new desired state.
	if len(newTargets) == 0 {
		delete(r.ifaceToRoutes, ifaceName)
	} else {
		r.ifaceToRoutes[ifaceName] = newTargets
	}

	// Clean up the old CIDRs.
	for cidr := range oldTargetsToCleanUp {
		r.removeOwningIface(ifaceName, cidr)
		r.recalculateDesiredKernelRoute(cidr)
	}

	for cidr := range newTargets {
		r.recalculateDesiredKernelRoute(cidr)
	}
}

// RouteUpdate updates the route keyed off the target CIDR. These deltas will
// be applied to any routes set using SetRoute.
func (r *RouteTable) RouteUpdate(ifaceName string, target Target) {
	if ifaceName == InterfaceNone && !r.includeNoInterface {
		r.logCxt.Error("Updating route with no interface")
		return
	}

	r.ifaceToRoutes[ifaceName][target.CIDR] = target
	r.addOwningIface(ifaceName, target.CIDR)
}

// RouteRemove removes the route with the specified CIDR. These deltas will
// be applied to any routes set using SetRoute.
func (r *RouteTable) RouteRemove(ifaceName string, cidr ip.CIDR) {
	if ifaceName == InterfaceNone && !r.includeNoInterface {
		r.logCxt.Error("Removing route with no interface")
		return
	}

	delete(r.ifaceToRoutes[ifaceName], cidr)
	if len(r.ifaceToRoutes[ifaceName]) == 0 {
		delete(r.ifaceToRoutes, ifaceName)
	}
	r.removeOwningIface(ifaceName, cidr)
}

func (r *RouteTable) addOwningIface(ifaceName string, cidr ip.CIDR) {
	ifaceNames := r.cidrToIfaces[cidr]
	if ifaceNames == nil {
		ifaceNames = set.New[string]()
		r.cidrToIfaces[cidr] = ifaceNames
	}
	ifaceNames.Add(ifaceName)
	r.recalculateDesiredKernelRoute(cidr)
}

func (r *RouteTable) removeOwningIface(ifaceName string, cidr ip.CIDR) {
	ifaceNames := r.cidrToIfaces[cidr]
	ifaceNames.Discard(ifaceName)
	if ifaceNames.Len() == 0 {
		delete(r.cidrToIfaces, cidr)
	}
	r.recalculateDesiredKernelRoute(cidr)
}

func (r *RouteTable) recalculateAllIfaceRoutes(name string) {
	for cidr := range r.ifaceToRoutes[name] {
		r.recalculateDesiredKernelRoute(cidr)
	}
}

func (r *RouteTable) recalculateDesiredKernelRoute(cidr ip.CIDR) {
	// Start with a blank slate.  We don't currently use the TOS/Priority
	// for our routes so we leave those as 0 in the kernelRouteKey.
	kernKey := kernelRouteKey{CIDR: cidr}
	r.kernelRoutes.Desired().Delete(kernKey)

	ifaces := r.cidrToIfaces[cidr]
	if ifaces == nil {
		r.logCxt.WithField("cidr", cidr).Debug("CIDR no longer has associated routes.")
		return
	}
	var bestTarget Target
	bestIface := ""
	bestIfaceIdx := 0
	ifaces.Iter(func(ifaceName string) error {
		ifIndex := 0
		if ifaceName == InterfaceNone {
			if r.ipVersion == 6 {
				// IPv6 "special" routes use ifindex 1 (vs 0 for IPv4).
				ifIndex = 1
			}
		} else {
			ifIndex = r.ifaceNameToIndex[ifaceName]
			if ifIndex == 0 {
				r.logCxt.WithField("name", ifaceName).Debug("Skipping interface with unknown index.")
				return nil
			}
		}
		// Arbitrary tie-breaker.
		if ifaceName > bestIface {
			bestIface = ifaceName
			bestIfaceIdx = ifIndex
			bestTarget = r.ifaceToRoutes[ifaceName][cidr]
		}
		return nil
	})

	if bestIface == "" {
		r.logCxt.WithField("cidr", cidr).Debug("CIDR no longer has associated route (all candidate routes missing iface index).")
		return
	}

	src := r.deviceRouteSourceAddress
	if bestTarget.Src != nil {
		src = bestTarget.Src
	}
	kernRoute := kernelRoute{
		Type:     bestTarget.RouteType(),
		Scope:    bestTarget.RouteScope(),
		GW:       bestTarget.GW,
		Src:      src,
		Ifindex:  bestIfaceIdx,
		OnLink:   bestTarget.Flags()&unix.RTNH_F_ONLINK != 0, // FIXME handle other flags?
		Protocol: r.deviceRouteProtocol,
	}
	r.logCxt.WithField("kernelRoute", kernRoute).Debug("Calculated kernel route.")
	r.kernelRoutes.Desired().Set(kernKey, kernRoute)
}

func (r *RouteTable) SetL2Routes(ifaceName string, targets []L2Target) {
	if len(targets) > 0 {
		r.l2Targets.Desired().Set(ifaceName, targets)
	} else {
		r.l2Targets.Desired().Delete(ifaceName)
	}
}

func (r *RouteTable) QueueResync() {
	r.logCxt.Debug("Queueing a resync of routing table.")
	r.fullResync = true
}

func (r *RouteTable) Apply() error {
	if err := r.maybeResyncWithDataplane(); err != nil {
		return err
	}
	if err := r.applyUpdates(); err != nil {
		return err
	}
	return nil
}

func (r *RouteTable) maybeResyncWithDataplane() error {
	nl, err := r.nl.Handle()
	if err != nil {
		r.logCxt.WithError(err).Error("Failed to connect to netlink.")
		return ConnectFailed
	}

	if !r.fullResync {
		return r.resyncIndividualInterfaces(nl)
	}

	// About to rescan everything, don't need the individual rescan set.
	r.ifacesToRescan.Clear()

	return r.doFullResync(nl)
}

func (r *RouteTable) doFullResync(nl netlinkshim.Interface) error {
	r.opReporter.RecordOperation(fmt.Sprint("resync-routes-v", r.ipVersion))

	resyncStartTime := time.Now()

	// Load all the routes in the routing table.  If we're managing routes in
	// a shared table (such as the main table) this may include a lot of routes
	// that we're not managing.
	routeFilter := &netlink.Route{}
	routeFilterFlags := uint64(0)
	if r.tableIndex != 0 {
		routeFilterFlags |= netlink.RT_FILTER_TABLE
	}
	allRoutes, err := nl.RouteListFiltered(r.netlinkFamily, routeFilter, routeFilterFlags)
	if errors.Is(err, unix.ENOENT) {
		// In strict mode, get this if the routing table doesn't exist; it'll be auto-created
		// when we add the first route so just treat it as empty.
		log.WithError(err).Debug("Routing table doesn't exist (yet). Treating as empty.")
		err = nil
		allRoutes = nil
	}
	if err != nil {
		return fmt.Errorf("failed to list all routes for resync: %w", err)
	}

	err = r.kernelRoutes.Dataplane().ReplaceAllIter(func(f func(k kernelRouteKey, v kernelRoute)) error {
		for _, route := range allRoutes {
			kernKey, kernRoute, ok := r.netlinkRouteToKernelRoute(route)
			if !ok {
				continue
			}
			f(kernKey, kernRoute)
		}
		return nil
	})
	if err != nil {
		// Should be impossible unless we return an error from the iterator.
		return fmt.Errorf("failed to update delta tracker: %w", err)
	}

	r.fullResync = false
	listAllRoutesTime.Observe(r.time.Since(resyncStartTime).Seconds())
	return nil
}

func (r *RouteTable) resyncIndividualInterfaces(nl netlinkshim.Interface) error {
	r.ifacesToRescan.Iter(func(ifaceName string) error {
		ifIndex := 0
		if ifaceName == InterfaceNone {
			if r.ipVersion == 6 {
				ifIndex = 1
			}
		} else {
			ifIndex := r.ifaceNameToIndex[ifaceName]
			if ifIndex == 0 {
				r.logCxt.Debug("Ignoring rescan of unknown interface.")
				return set.RemoveItem
			}
		}
		routeFilter := &netlink.Route{
			Table:     r.tableIndex,
			LinkIndex: ifIndex,
		}
		routeFilterFlags := netlink.RT_FILTER_OIF | netlink.RT_FILTER_TABLE
		netlinkRoutes, err := nl.RouteListFiltered(r.netlinkFamily, routeFilter, routeFilterFlags)
		if errors.Is(err, unix.ENOENT) {
			// In strict mode, get this if the routing table doesn't exist; it'll be auto-created
			// when we add the first route so just treat it as empty.
			log.WithError(err).Debug("Routing table doesn't exist (yet). Treating as empty.")
			err = nil
			netlinkRoutes = nil
		}
		if err != nil {
			// Filter the error so that we don't spam errors if the interface is being torn
			// down.
			filteredErr := r.filterErrorByIfaceState(ifaceName, err, ListFailed, false)
			if errors.Is(filteredErr, ListFailed) {
				r.logCxt.WithError(err).WithFields(log.Fields{
					"iface":       ifaceName,
					"routeFilter": routeFilter,
					"flags":       routeFilterFlags,
				}).Error("Error listing routes")
				r.nl.CloseHandle() // Defensive: force a netlink reconnection next time.
				return set.RemoveItem
			} else {
				r.logCxt.WithError(filteredErr).WithField("iface", ifaceName).Debug(
					"Failed to list routes; interface down/gone.")
				return set.RemoveItem
			}
		}

		// Loaded the routes, now update our tracker.  First index the data
		// we loaded.
		kernRoutes := map[kernelRouteKey]kernelRoute{}
		for _, nlRoute := range netlinkRoutes {
			kernKey, kernRoute, ok := r.netlinkRouteToKernelRoute(nlRoute)
			if !ok {
				continue
			}
			kernRoutes[kernKey] = kernRoute
		}
		// Then look for routes that the tracker says are there but are actually
		// missing.
		for cidr := range r.ifaceToRoutes[ifaceName] {
			kernKey := kernelRouteKey{CIDR: cidr}
			desiredKernRoute, ok := r.kernelRoutes.Desired().Get(kernKey)
			if !ok || desiredKernRoute.Ifindex != ifIndex {
				// This route belongs to some other interface right now.
				continue
			}
			if _, ok := kernRoutes[kernKey]; ok {
				continue
			}
			r.kernelRoutes.Dataplane().Delete(kernKey)
		}
		// Update tracker with the routes that we did see.
		for kk, kr := range kernRoutes {
			r.kernelRoutes.Dataplane().Set(kk, kr)
		}

		return set.RemoveItem
	})
	return nil
}

func (r *RouteTable) netlinkRouteToKernelRoute(route netlink.Route) (kernKey kernelRouteKey, kernRoute kernelRoute, ok bool) {
	if r.ifacePrefixRegexp != nil {
		if routeIsSpecialNoIfRoute(route) && !r.includeNoInterface {
			return
		}
		if routeIsIPv6Bootstrap(route) {
			return
		}
		ifaceName := r.ifaceIndexToName[route.LinkIndex]
		if ifaceName == "" {
			// We don't know about this interface.  Either we're racing
			// with link creation, in which case we'll hear about the
			// interface soon and work out what to do, or we're seeing
			// a route for a just-deleted interface, in which case
			// we don't care.
			r.logCxt.WithField("ifIndex", route.LinkIndex).Debug(
				"Skipping resync of route for unknown iface")
			return
		}
		if !r.ifacePrefixRegexp.MatchString(ifaceName) {
			return
		}
	}
	if !r.removeExternalRoutes && route.Protocol != r.deviceRouteProtocol {
		r.logCxt.Debug("Ignoring non-Calico route.")
		return
	}
	kernKey = kernelRouteKey{
		CIDR:     ip.CIDRFromIPNet(route.Dst),
		Priority: route.Priority,
		TOS:      route.Tos,
	}
	kernRoute = kernelRoute{
		Type:     route.Type,
		Scope:    route.Scope,
		GW:       ip.FromNetIP(route.Gw),
		Src:      ip.FromNetIP(route.Src),
		Ifindex:  route.LinkIndex,
		OnLink:   route.Flags&unix.RTNH_F_ONLINK != 0,
		Protocol: route.Protocol,
	}
	ok = true
	return
}

func routeIsIPv6Bootstrap(route netlink.Route) bool {
	if route.Family != netlink.FAMILY_V6 {
		return false
	}
	return ip.CIDRFromIPNet(route.Dst) == ipV6LinkLocalCIDR
}

func routeIsSpecialNoIfRoute(route netlink.Route) bool {
	if route.LinkIndex > 1 {
		// Special routes either have 0 for the link index or 1 ('lo'),
		// depending on IP version.
		return false
	}
	switch route.Type {
	case unix.RTN_LOCAL, unix.RTN_THROW, unix.RTN_BLACKHOLE, unix.RTN_PROHIBIT, unix.RTN_UNREACHABLE:
		return true
	}
	return false
}

func (r *RouteTable) applyUpdates() error {
	nl, err := r.nl.Handle()
	if err != nil {
		r.logCxt.Debug("Failed to connect to netlink")
		return ConnectFailed
	}

	// First clean up any old routes.
	deletionErrs := map[kernelRouteKey]error{}
	r.kernelRoutes.PendingDeletions().Iter(func(kernKey kernelRouteKey) deltatracker.IterAction {
		// Any deleted route should have the corresponding conntrack entries removed.
		r.startConntrackDeletion(kernKey.CIDR.Addr())
		dst := kernKey.CIDR.ToIPNet()
		err := nl.RouteDel(&netlink.Route{
			Table:    r.tableIndex,
			Dst:      &dst,
			Tos:      kernKey.TOS,
			Priority: kernKey.Priority,
		})
		if errors.Is(err, unix.ESRCH) {
			r.logCxt.WithField("route", kernKey).Debug("Tried to delete route but it wasn't found.")
			err = nil // Already gone (we hope).
		}
		if err != nil {
			deletionErrs[kernKey] = err
			return deltatracker.IterActionNoOp
		}
		// Route is gone, clean up the dataplane side of the tracker.
		return deltatracker.IterActionUpdateDataplane
	})
	if len(deletionErrs) > 0 {
		log.WithField("errors", deletionErrs).Warn(
			"Encountered some errors when trying to delete old routes.")
	}

	updateErrs := map[kernelRouteKey]error{}
	r.kernelRoutes.PendingUpdates().Iter(func(kernKey kernelRouteKey, v kernelRoute) deltatracker.IterAction {
		dst := kernKey.CIDR.ToIPNet()
		flags := 0
		if v.OnLink {
			flags = unix.RTNH_F_ONLINK
		}

		r.waitForPendingConntrackDeletion(kernKey.CIDR.Addr())

		nlRoute := &netlink.Route{
			Table:    r.tableIndex,
			Dst:      &dst,
			Tos:      kernKey.TOS,
			Priority: kernKey.Priority,

			Type:      v.Type,
			Scope:     v.Scope,
			Gw:        v.GWAsNetIP(),
			Src:       v.SrcAsNetIP(),
			LinkIndex: v.Ifindex,
			Protocol:  v.Protocol,
			Flags:     flags,
		}
		err := nl.RouteReplace(nlRoute)
		if err != nil {
			updateErrs[kernKey] = err
			return deltatracker.IterActionNoOp
		}
		// Route is gone, clean up the dataplane side of the tracker.
		return deltatracker.IterActionUpdateDataplane
	})
	// TODO filter out interfaces that are gone
	if len(updateErrs) > 0 {
		log.WithField("errors", updateErrs).Warn(
			"Encountered some errors when trying to update routes.")
	}

	return nil // TODO
}

//
// // fullResyncRoutesForLink performs a full resync of the routes by first listing current routes and correlating against
// // the expected set. After correlation, it will create a set of routes to delete and update the delta routes to add
// // back any missing routes.
// func (r *RouteTable) fullResyncRoutesForLink(logCxt *log.Entry, ifaceName string, deletedConnCIDRs set.Set[ip.CIDR]) ([]netlink.Route, error) {
// 	programmedRoutes, err := r.readProgrammedRoutes(logCxt, ifaceName)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	var routesToDelete []netlink.Route
// 	expectedTargets := r.ifaceNameToTargets[ifaceName]
// 	pendingDeltaTargets := r.pendingIfaceNameToDeltaTargets[ifaceName]
// 	if pendingDeltaTargets == nil {
// 		pendingDeltaTargets = map[ip.CIDR]*Target{}
// 		r.pendingIfaceNameToDeltaTargets[ifaceName] = pendingDeltaTargets
// 	}
// 	alreadyCorrectCIDRs := set.New[ip.CIDR]()
// 	leaveDirty := false
// 	for _, route := range programmedRoutes {
// 		logCxt.Debugf("Processing route: %v %v %v", route.Table, route.LinkIndex, route.Dst)
// 		var dest ip.CIDR
// 		if route.Dst != nil {
// 			dest = ip.CIDRFromIPNet(route.Dst)
// 		}
// 		logCxt := logCxt.WithField("dest", dest)
// 		// Check if we should remove routes not added by us
// 		if !r.removeExternalRoutes && route.Protocol != r.deviceRouteProtocol {
// 			logCxt.Debug("Syncing routes: not removing route as it is not marked as Felix route")
// 			continue
// 		}
//
// 		expectedTarget, expectedTargetFound := expectedTargets[dest]
// 		routeExpected := expectedTargetFound || (r.ipVersion == 6 && dest == ipV6LinkLocalCIDR)
// 		var routeProblems []string
// 		if !routeExpected {
// 			routeProblems = append(routeProblems, "unexpected route")
// 		}
// 		if dest != ipV6LinkLocalCIDR {
// 			if !r.deviceRouteSourceAddress.Equal(route.Src) {
// 				routeProblems = append(routeProblems, "incorrect source address")
// 			}
// 			if r.deviceRouteProtocol != route.Protocol {
// 				routeProblems = append(routeProblems, "incorrect protocol")
// 			}
// 			if expectedTargetFound && expectedTarget.RouteType() != route.Type {
// 				routeProblems = append(routeProblems, "incorrect type")
// 			}
// 			if (route.Gw == nil && expectedTarget.GW != nil) ||
// 				(route.Gw != nil && expectedTarget.GW == nil) ||
// 				(route.Gw != nil && expectedTarget.GW != nil && !route.Gw.Equal(expectedTarget.GW.AsNetIP())) {
// 				routeProblems = append(routeProblems, "incorrect gateway")
// 			}
// 		}
// 		if len(routeProblems) == 0 {
// 			logCxt.Debug("Route is correct")
// 			alreadyCorrectCIDRs.Add(dest)
// 			continue
// 		}
// 		// In order to allow Calico to run without Felix in an emergency, the CNI plugin pre-adds
// 		// the route to the interface.  To avoid flapping the route when Felix sees the interface
// 		// before learning about the endpoint, we give each interface a grace period after we first
// 		// see it before we remove routes that we're not expecting.  Check whether the grace period
// 		// applies to this interface.
// 		ifaceInGracePeriod := r.time.Since(r.ifaceNameToFirstSeen[ifaceName]) < r.routeCleanupGracePeriod
// 		if ifaceInGracePeriod && !routeExpected {
// 			// Don't remove unexpected routes from interfaces created recently.
// 			logCxt.Info("Syncing routes: found unexpected route; ignoring due to grace period.")
// 			leaveDirty = true
// 			continue
// 		}
// 		logCxt.WithField("routeProblems", routeProblems).Info("Remove old route")
// 		routesToDelete = append(routesToDelete, route)
// 		if dest != nil {
// 			deletedConnCIDRs.Add(dest)
// 		}
// 	}
//
// 	// Now loop through the expected CIDRs to Target. Remove any that we did not find, and add them back into our
// 	// delta updates (unless the entry is superseded by another update).
// 	for cidr, target := range expectedTargets {
// 		if alreadyCorrectCIDRs.Contains(cidr) {
// 			continue
// 		}
// 		logCxt := logCxt.WithField("cidr", cidr)
// 		logCxt.Info("Deleting from expected targets")
// 		delete(expectedTargets, cidr)
//
// 		// If we do not have an update that supersedes this entry, then add it back in as an update so that we add
// 		// the route.
// 		if pendingTarget, ok := pendingDeltaTargets[cidr]; !ok {
// 			logCxt.Info("No pending target update, adding back in as an update")
// 			pendingDeltaTargets[cidr] = safeTargetPointer(target)
// 		} else if pendingTarget == nil {
// 			logCxt.Info("Pending target deletion, removing delete update")
// 			delete(pendingDeltaTargets, cidr)
// 		} else {
// 			logCxt.Info("Pending target update, no changes to deltas required")
// 		}
// 	}
//
// 	if leaveDirty {
// 		// Superfluous routes on a recently created interface.  We'll recheck later.
// 		return routesToDelete, IfaceGrace
// 	}
//
// 	return routesToDelete, nil
// }
//
// func (r *RouteTable) readProgrammedRoutes(logCxt *log.Entry, ifaceName string) ([]netlink.Route, error) {
// 	// Get the netlink client and the link attributes
// 	nl, err := r.nl.Handle()
// 	if err != nil {
// 		logCxt.Debug("Failed to connect to netlink")
// 		return nil, ConnectFailed
// 	}
// 	// Try to get the link.  This may fail if it's been deleted out from under us.
// 	linkAttrs, err := r.getLinkAttributes(ifaceName)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// Got the link; try to sync its routes.  Note: We used to check if the interface
// 	// was oper down before we tried to do the sync but that prevented us from removing
// 	// routes from an interface in some corner cases (such as being admin up but oper
// 	// down).
// 	routeFilter := &netlink.Route{
// 		Table: r.tableIndex,
// 	}
//
// 	routeFilterFlags := netlink.RT_FILTER_OIF
// 	if r.tableIndex != 0 {
// 		routeFilterFlags |= netlink.RT_FILTER_TABLE
// 	}
// 	if linkAttrs != nil {
// 		// Link attributes might be nil for the special "no-OIF" interface name.
// 		routeFilter.LinkIndex = linkAttrs.Index
// 	} else if r.ipVersion == 6 {
// 		// IPv6 no-OIF interfaces get corrected to lo, which is interface index 1.
// 		routeFilter.LinkIndex = 1
// 	}
// 	programmedRoutes, err := nl.RouteListFiltered(r.netlinkFamily, routeFilter, routeFilterFlags)
// 	if errors.Is(err, unix.ENOENT) {
// 		// In strict mode, get this if the routing table doesn't exist; it'll be auto-created
// 		// when we add the first route so just treat it as empty.
// 		log.WithError(err).Debug("Routing table doesn't exist (yet). Treating as empty.")
// 		err = nil
// 		programmedRoutes = nil
// 	}
// 	r.livenessCallback()
// 	if err != nil {
// 		// Filter the error so that we don't spam errors if the interface is being torn
// 		// down.
// 		filteredErr := r.filterErrorByIfaceState(ifaceName, err, ListFailed, false)
// 		if filteredErr == ListFailed {
// 			logCxt.WithError(err).WithFields(log.Fields{
// 				"routeFilter": routeFilter,
// 				"flags":       routeFilterFlags,
// 			}).Error("Error listing routes")
// 			r.nl.CloseHandle() // Defensive: force a netlink reconnection next time.
// 		} else {
// 			logCxt.WithError(err).Info("Failed to list routes; interface down/gone.")
// 		}
// 		return nil, filteredErr
// 	}
// 	return programmedRoutes, nil
// }
//
// func (r *RouteTable) syncL2RoutesForLink(ifaceName string) error {
// 	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
// 	logCxt.Debug("Syncing interface L2 routes")
// 	if updatedTargets, ok := r.pendingIfaceNameToL2Targets[ifaceName]; ok {
// 		logCxt.Debug("Have updated targets.")
// 		if updatedTargets == nil {
// 			delete(r.ifaceNameToL2Targets, ifaceName)
// 		} else {
// 			r.ifaceNameToL2Targets[ifaceName] = updatedTargets
// 		}
// 		delete(r.pendingIfaceNameToL2Targets, ifaceName)
// 	}
// 	expectedTargets := r.ifaceNameToL2Targets[ifaceName]
//
// 	// Try to get the link attributes.  This may fail if it's been deleted out from under us.
// 	linkAttrs, err := r.getLinkAttributes(ifaceName)
// 	if err != nil {
// 		r.logCxt.WithError(err).Error("Failed to get link attributes")
// 		return err
// 	}
//
// 	// Build a map of expected targets by hwaddr for easier lookup,
// 	// so we can compare the expected L2 targets against the programmed ones
// 	// for this link.
// 	expected := map[string]bool{}
// 	for _, target := range expectedTargets {
// 		expected[target.VTEPMAC.String()] = true
// 	}
//
// 	// Get the current set of neighbors on this interface.
// 	existingNeigh, err := netlink.NeighList(linkAttrs.Index, netlink.FAMILY_V4)
// 	if err != nil {
// 		return err
// 	}
//
// 	// For each existing neighbor, if we don't expect an entry for its MAC address to be programmed
// 	// on this link, then delete it.
// 	var updatesFailed bool
//
// 	for _, existing := range existingNeigh {
// 		if existing.HardwareAddr == nil {
// 			log.WithField("neighbor", existing).Debug("Ignoring existing ARP entry with no hardware addr")
// 			continue
// 		}
// 		if _, ok := expected[existing.HardwareAddr.String()]; !ok {
// 			logCxt.WithField("neighbor", existing).Debug("Neighbor should no longer be programmed")
//
// 			// Remove the FDB entry for this neighbor.
// 			n := netlink.Neigh{
// 				LinkIndex:    existing.LinkIndex,
// 				State:        netlink.NUD_PERMANENT,
// 				Family:       unix.AF_BRIDGE,
// 				Flags:        netlink.NTF_SELF,
// 				IP:           existing.IP,
// 				HardwareAddr: existing.HardwareAddr,
// 			}
// 			if err := netlink.NeighDel(&n); err != nil {
// 				if !strings.Contains(err.Error(), "no such file or directory") {
// 					logCxt.WithError(err).Warnf("Failed to delete neighbor FDB entry %+v", n)
// 					updatesFailed = true
// 				}
// 			} else {
// 				logCxt.WithField("neighbor", existing).Info("Removed old neighbor FDB entry")
// 			}
//
// 			// Delete the ARP entry.
// 			if err := netlink.NeighDel(&existing); err != nil {
// 				if !strings.Contains(err.Error(), "no such file or directory") {
// 					logCxt.WithError(err).Warnf("Failed to delete neighbor ARP entry %+v", existing)
// 					updatesFailed = true
// 				}
// 			} else {
// 				logCxt.WithField("neighbor", existing).Info("Removed old neighbor ARP entry")
// 			}
// 		}
// 	}
//
// 	// For each expected target, ensure that it is programmed. If the value has changed since last programming, this
// 	// will update it.
// 	for _, target := range expectedTargets {
// 		if err = r.ensureL2Dataplane(linkAttrs, target); err != nil {
// 			logCxt.WithError(err).Warnf("Failed to sync L2 dataplane for interface")
// 			updatesFailed = true
// 			continue
// 		}
// 	}
//
// 	if updatesFailed {
// 		r.nl.CloseHandle() // Defensive: force a netlink reconnection next time.
//
// 		// Recheck whether the interface exists so we don't produce spammy logs during
// 		// interface removal.
// 		return r.filterErrorByIfaceState(ifaceName, UpdateFailed, UpdateFailed, false)
// 	}
//
// 	return nil
// }

func (r *RouteTable) ensureL2Dataplane(linkAttrs *netlink.LinkAttrs, target L2Target) error {
	// For each L2 entry we need to program, program it.
	// Add a static ARP entry.
	a := &netlink.Neigh{
		LinkIndex:    linkAttrs.Index,
		State:        netlink.NUD_PERMANENT,
		Type:         unix.RTN_UNICAST,
		IP:           target.GW.AsNetIP(),
		HardwareAddr: target.VTEPMAC,
	}
	if err := netlink.NeighSet(a); err != nil {
		return err
	}
	log.WithField("entry", a).Debug("Programmed ARP")

	// Add a FDB entry for this neighbor.
	n := &netlink.Neigh{
		LinkIndex:    linkAttrs.Index,
		State:        netlink.NUD_PERMANENT,
		Family:       unix.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           target.IP.AsNetIP(),
		HardwareAddr: target.VTEPMAC,
	}
	if err := netlink.NeighSet(n); err != nil {
		return err
	}
	log.WithField("entry", n).Debug("Programmed FDB")
	return nil
}

// startConntrackDeletion starts the deletion of conntrack entries for the given CIDR in the background.  Pending
// deletions are tracked in the pendingConntrackCleanups map so we can block waiting for them later.
//
// It's important to do the conntrack deletions in the background because scanning the conntrack
// table is very slow if there are a lot of entries.  Previously, we did the deletion synchronously
// but that led to lengthy Apply() calls on the critical path.
func (r *RouteTable) startConntrackDeletion(ipAddr ip.Addr) {
	log.WithField("ip", ipAddr).Debug("Starting goroutine to delete conntrack entries")
	done := make(chan struct{})
	r.pendingConntrackCleanups[ipAddr] = done
	go func() {
		defer close(done)
		r.conntrack.RemoveConntrackFlows(r.ipVersion, ipAddr.AsNetIP())
		log.WithField("ip", ipAddr).Debug("Deleted conntrack entries")
	}()
}

// cleanUpPendingConntrackDeletions scans the pendingConntrackCleanups map for completed entries and removes them.
func (r *RouteTable) cleanUpPendingConntrackDeletions() {
	for ipAddr, c := range r.pendingConntrackCleanups {
		select {
		case <-c:
			log.WithField("ip", ipAddr).Debug(
				"Background goroutine finished deleting conntrack entries")
			delete(r.pendingConntrackCleanups, ipAddr)
		default:
			log.WithField("ip", ipAddr).Debug(
				"Background goroutine yet to finish deleting conntrack entries")
			continue
		}
	}
}

// waitForPendingConntrackDeletion waits for any pending conntrack deletions (if any) for the given IP to complete.
func (r *RouteTable) waitForPendingConntrackDeletion(ipAddr ip.Addr) {
	if c := r.pendingConntrackCleanups[ipAddr]; c != nil {
		log.WithField("ip", ipAddr).Info("Waiting for pending conntrack deletion to finish")
		<-c
		log.WithField("ip", ipAddr).Info("Done waiting for pending conntrack deletion to finish")
		delete(r.pendingConntrackCleanups, ipAddr)
	}
}

// filterErrorByIfaceState checks the current state of the interface; if it's down or gone, it
// returns IfaceDown or IfaceNotPresent, otherwise, it returns the given defaultErr.
func (r *RouteTable) filterErrorByIfaceState(ifaceName string, currentErr, defaultErr error, suppressExistsWarning bool) error {
	logCxt := r.logCxt.WithFields(log.Fields{"ifaceName": ifaceName, "error": currentErr})
	if ifaceName == InterfaceNone {
		// Short circuit the no-OIF interface name.
		logCxt.Info("No interface on route.")
		return defaultErr
	}

	if strings.Contains(currentErr.Error(), "not found") {
		// Current error already tells us that the link was not present.  If we re-check
		// the status in this case, we open a race where the interface gets created and
		// we log an error when we're about to re-trigger programming anyway.
		logCxt.Info("Failed to access interface because it doesn't exist.")
		return IfaceNotPresent
	}
	// If the current error wasn't clear, try to look up the interface to see if there's a
	// well-understood reason for the failure.
	nl, err := r.nl.Handle()
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"ifaceName":  ifaceName,
			"currentErr": currentErr,
		}).Error("Failed to (re)connect to netlink while processing another error")
		return ConnectFailed
	}
	if link, err := nl.LinkByName(ifaceName); err == nil {
		// Link still exists.  Check if it's up.
		logCxt.WithField("link", link).Debug("Interface still exists")
		if link.Attrs().Flags&net.FlagUp != 0 {
			// Link exists and it's up, no reason that we expect to fail.
			if suppressExistsWarning {
				logCxt.WithField("link", link).Debug(
					"Failed to access interface but it appears to be up; retrying...")
			} else {
				logCxt.WithField("link", link).Warning(
					"Failed to access interface but it appears to be up")
			}
			return defaultErr
		} else {
			// Special case: Link exists and it's down.  Assume that's the problem.
			logCxt.WithField("link", link).Debug("Interface is down")
			return IfaceDown
		}
	} else if strings.Contains(err.Error(), "not found") {
		// Special case: Link no longer exists.
		logCxt.Info("Interface was deleted during operation, filtering error")
		return IfaceNotPresent
	} else {
		// Failed to list routes, then failed to check if interface exists.
		logCxt.WithError(err).Error("Failed to access interface after a failure")
		return defaultErr
	}
}

// getLinkAttributes returns the link attributes for the specified link name. This method returns nil if the
// interface name is the special "no-OIF" name.
func (r *RouteTable) getLinkAttributes(ifaceName string) (*netlink.LinkAttrs, error) {
	if ifaceName == InterfaceNone {
		// Short circuit the no-OIF interface name.
		return nil, nil
	}

	// Try to get the link.  This may fail if it's been deleted out from under us.
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)

	nl, err := r.nl.Handle()
	if err != nil {
		r.logCxt.WithError(err).Error("Failed to connect to netlink, retrying...")
		return nil, ConnectFailed
	}

	link, err := nl.LinkByName(ifaceName)
	if err != nil {
		// Filter the error so that we don't spam errors if the interface is being torn
		// down.
		filteredErr := r.filterErrorByIfaceState(ifaceName, err, GetFailed, false)
		if filteredErr == GetFailed {
			logCxt.WithError(err).Error("Failed to get interface.")
			r.nl.CloseHandle() // Defensive: force a netlink reconnection next time.
		} else {
			logCxt.WithError(err).Info("Failed to get interface; it's down/gone.")
		}
		return nil, filteredErr
	}
	return link.Attrs(), nil
}

func (r *RouteTable) shouldDeleteConflictingRoutes() bool {
	gate := r.featureDetector.FeatureGate("DeleteConflictingRoutes")
	switch strings.ToLower(gate) {
	case "enabled", "": // Default is "enabled"
		return true
	}
	return false
}

// safeTargetPointer returns a pointer to a Target safely ensuring the pointer is unique.
func safeTargetPointer(target Target) *Target {
	return &target
}
