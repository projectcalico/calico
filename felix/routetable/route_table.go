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
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

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

// RouteTable manages the calico routes for a specific table. It reconciles the
// routes that we desire to have for calico managed devices with what is the
// current status in the dataplane. That is, it removes any routes that we do
// not desire and adds those that we do. It skips over devices that we do not
// manage not to interfere with other users of the route tables.
type RouteTable struct {
	logCxt        *log.Entry
	ipVersion     uint8
	netlinkFamily int
	// The routing table index.  This is defaulted to RT_TABLE_MAIN if not specified.
	tableIndex int

	deviceRouteSourceAddress ip.Addr
	deviceRouteProtocol      netlink.RouteProtocol
	routeMetric              RouteMetric
	removeExternalRoutes     bool
	ownershipPolicy          OwnershipPolicy

	// Interface update tracking.
	fullResyncNeeded  bool
	forceNetlinkClose bool
	ifacesToRescan    set.Set[string]
	makeARPEntries    bool

	// ifaceToRoutes and cidrToIfaces are our inputs, updated
	// eagerly when something in the manager layer tells us to change the
	// routes.
	ifaceToRoutes map[string]map[ip.CIDR]Target
	cidrToIfaces  map[ip.CIDR]set.Set[string]

	// kernelRoutes tracks the relationship between the route that we want
	// to program for a given CIDR (i.e. the route selected after conflict
	// resolution if there are multiple routes) and the route that's actually
	// in the kernel.
	kernelRoutes *deltatracker.DeltaTracker[kernelRouteKey, kernelRoute]
	pendingARPs  map[string]map[ip.Addr]net.HardwareAddr

	ifaceNameToIndex      map[string]int
	ifaceIndexToName      map[int]string
	ifaceIndexToState     map[int]ifacemonitor.State
	ifaceIndexToGraceInfo map[int]graceInfo

	conntrackCleanupEnabled bool
	// conntrackTracker is a RealConntrackTracker or a DummyConntrackTracker
	// Depending on whether conntrack cleanup is enabled or not.
	conntrackTracker ConntrackTracker

	nl *handlemgr.HandleManager

	opReporter       logutils.OpRecorder
	livenessCallback func()

	// The route deletion grace period.
	routeCleanupGracePeriod time.Duration
	lastGracePeriodCleanup  time.Time
	featureDetector         environment.FeatureDetectorIface

	conntrack        conntrackIface
	time             timeshim.Interface
	newNetlinkHandle func() (netlinkshim.Interface, error)
}

type graceInfo struct {
	FirstSeen    time.Time
	GraceExpired bool
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

func WithRouteMetric(metric RouteMetric) RouteTableOpt {
	return func(table *RouteTable) {
		table.routeMetric = metric
	}
}

func WithStaticARPEntries(b bool) RouteTableOpt {
	return func(table *RouteTable) {
		if table.ipVersion != 4 {
			log.Panic("Bug: ARP entries only supported for IPv4.")
		}
		table.makeARPEntries = b
	}
}

func WithConntrackCleanup(enabled bool) RouteTableOpt {
	return func(table *RouteTable) {
		table.conntrackCleanupEnabled = enabled
	}
}

func WithTimeShim(shim timeshim.Interface) RouteTableOpt {
	return func(table *RouteTable) {
		table.time = shim
	}
}

func WithConntrackShim(shim conntrackIface) RouteTableOpt {
	return func(table *RouteTable) {
		table.conntrack = shim
	}
}

func WithNetlinkHandleShim(newNetlinkHandle func() (netlinkshim.Interface, error)) RouteTableOpt {
	return func(table *RouteTable) {
		table.newNetlinkHandle = newNetlinkHandle
	}
}

// OwnershipPolicy is used to determine whether a given interface or route
// belongs to Calico.  Routes that are loaded from the kernel are checked
// against this policy to determine if they should be tracked.  The RouteTable
// cleans up tracked routes that don't match the current datastore state.
//
// The policy is also used to determine whether an interface should be tracked
// or not.  If an interface is not tracked then the RouteTable will not be
// able to program routes for it, and it will not respond to interface state
// updates.  This is mainly a performance optimisation for our non-main
// routing tables which tend to be used to manager routes for a single device.
type OwnershipPolicy interface {
	RouteIsOurs(ifaceName string, route *netlink.Route) bool

	IfaceIsOurs(ifaceName string) bool
	IfaceShouldHaveARPEntries(ifaceName string) bool
	IfaceShouldHaveGracePeriod(ifaceName string) bool
}

// FIXME Makes sure that VXLAN same-subnet routes don't get cleaned up until VXLAN manager is in sync.

func New(
	ownershipPolicy OwnershipPolicy,
	ipVersion uint8,
	netlinkTimeout time.Duration,
	deviceRouteSourceAddress net.IP,
	deviceRouteProtocol netlink.RouteProtocol,
	removeExternalRoutes bool,
	tableIndex int,
	opReporter logutils.OpRecorder,
	featureDetector environment.FeatureDetectorIface,
	opts ...RouteTableOpt,
) *RouteTable {
	if tableIndex == 0 {
		// If we set route.Table to 0, what we actually get is a route in RT_TABLE_MAIN.  However,
		// RouteListFiltered is much more efficient if we give it the "real" table number.
		log.Debug("RouteTable created with unspecified table; defaulting to unix.RT_TABLE_MAIN.")
		tableIndex = unix.RT_TABLE_MAIN
	}

	var logCxt *log.Entry
	description := fmt.Sprintf("IPv%d,%d", ipVersion, tableIndex)
	logCxt = log.WithFields(log.Fields{
		"table": description,
	})

	family := netlink.FAMILY_V4
	if ipVersion == 6 {
		family = netlink.FAMILY_V6
	} else if ipVersion != 4 {
		logCxt.WithField("ipVersion", ipVersion).Panic("Unknown IP version")
	}

	rt := &RouteTable{
		logCxt:        logCxt,
		ipVersion:     ipVersion,
		netlinkFamily: family,
		tableIndex:    tableIndex,

		deviceRouteSourceAddress: ip.FromNetIP(deviceRouteSourceAddress),
		deviceRouteProtocol:      deviceRouteProtocol,
		removeExternalRoutes:     removeExternalRoutes,

		fullResyncNeeded: true,
		ifacesToRescan:   set.New[string](),
		ownershipPolicy:  ownershipPolicy,

		ifaceToRoutes: map[string]map[ip.CIDR]Target{},
		cidrToIfaces:  map[ip.CIDR]set.Set[string]{},

		kernelRoutes: deltatracker.New[kernelRouteKey, kernelRoute](),
		pendingARPs:  map[string]map[ip.Addr]net.HardwareAddr{},

		ifaceIndexToGraceInfo: map[int]graceInfo{},
		ifaceNameToIndex:      map[string]int{},
		ifaceIndexToName:      map[int]string{},
		ifaceIndexToState:     map[int]ifacemonitor.State{},

		conntrackCleanupEnabled: true,

		opReporter:       opReporter,
		livenessCallback: func() {},
		featureDetector:  featureDetector,

		// Shims; may get overridden by options below.
		conntrack:        conntrack.New(),
		time:             timeshim.RealTime(),
		newNetlinkHandle: netlinkshim.NewRealNetlink,
	}

	for _, o := range opts {
		o(rt)
	}

	rt.nl = handlemgr.NewHandleManager(
		rt.featureDetector,
		handlemgr.WithNewHandleOverride(rt.newNetlinkHandle),
		handlemgr.WithSocketTimeout(netlinkTimeout),
	)

	if rt.conntrackCleanupEnabled {
		rt.conntrackTracker = NewRealConntrackTracker(ipVersion, rt.conntrack)
	} else {
		rt.conntrackTracker = NewDummyConntrackTracker()
	}

	return rt
}

func (r *RouteTable) OnIfaceStateChanged(ifaceName string, ifIndex int, state ifacemonitor.State) {
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	if !r.ownershipPolicy.IfaceIsOurs(ifaceName) {
		logCxt.Trace("Ignoring interface state change, not an interface managed by this routetable.")
		return
	}

	// There are a couple of interesting corner cases:
	//
	// * Interface gets renamed: same ifindex, new name.  The interface
	//   monitor deals with that by sending us a deletion for the old
	//   name, then a creation for the new name.
	// * Interface gets recreated: same name, new ifindex.  Again we
	//   should see a deletion and then an add.

	logCxt.WithFields(log.Fields{
		"ifIndex": ifIndex,
		"state":   state,
		"name":    ifaceName,
	}).Debug("Interface state update.")
	recheckRoutesOwnership := false
	if state == ifacemonitor.StateNotPresent {
		// Interface deleted, clean up.
		oldIndex := r.ifaceNameToIndex[ifaceName]
		delete(r.ifaceIndexToName, oldIndex)
		delete(r.ifaceIndexToState, oldIndex)
		delete(r.ifaceNameToIndex, ifaceName)
		r.ifacesToRescan.Discard(ifaceName)

		// This interface may have had some active routes that were shadowing
		// routes from another interface.  Make sure we rescan.
		recheckRoutesOwnership = true
	} else {
		// Interface exists, record its details.
		r.onIfaceSeen(ifIndex)
		r.ifaceIndexToState[ifIndex] = state
		oldIfIndex, ok := r.ifaceNameToIndex[ifaceName]
		if ok && oldIfIndex != ifIndex {
			// Interface renumbered.  For example, deleted and then recreated
			// with same name.  Clean up old number.
			delete(r.ifaceIndexToName, oldIfIndex)

			// The interface index is part of the route conflict tie-breaker,
			// so we need to check if the winner has changed.
			recheckRoutesOwnership = true
		} else if !ok {
			// New interface.
			recheckRoutesOwnership = true
		}
		r.ifaceNameToIndex[ifaceName] = ifIndex
		r.ifaceIndexToName[ifIndex] = ifaceName
	}

	if state == ifacemonitor.StateUp {
		// Interface transitioned to "up".  Force a rescan of its routes
		// because routes often get removed when the interface goes down
		// and its default route disappears.
		logCxt.Debug("Interface up, marking for route sync")
		r.ifacesToRescan.Add(ifaceName)
		recheckRoutesOwnership = true
	}

	if recheckRoutesOwnership {
		r.recheckRouteOwnershipsByIface(ifaceName)
	}
}

func (r *RouteTable) onIfaceSeen(ifIndex int) {
	if ifIndex <= 1 {
		// Ignore "no interface" routes.
		return
	}
	if _, ok := r.ifaceIndexToGraceInfo[ifIndex]; ok {
		return
	}
	r.ifaceIndexToGraceInfo[ifIndex] = graceInfo{
		FirstSeen: r.time.Now(),
	}
}

// SetRoutes replaces the full set of targets for the specified interface.
func (r *RouteTable) SetRoutes(ifaceName string, targets []Target) {
	if !r.ownershipPolicy.IfaceIsOurs(ifaceName) {
		r.logCxt.WithField("ifaceName", ifaceName).Error(
			"Cannot set route for interface not managed by this routetable.")
		return
	}
	r.logCxt.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"targets":   targets,
	}).Debug("SetRoutes called.")

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
		delete(r.pendingARPs, ifaceName)
	} else {
		r.ifaceToRoutes[ifaceName] = newTargets
		if r.makeARPEntries {
			r.pendingARPs[ifaceName] = map[ip.Addr]net.HardwareAddr{}
		}
	}

	// Clean up the old CIDRs.
	for cidr := range oldTargetsToCleanUp {
		r.removeOwningIface(ifaceName, cidr)
		r.recalculateDesiredKernelRoute(cidr)
	}

	for cidr, target := range newTargets {
		r.recalculateDesiredKernelRoute(cidr)
		if r.makeARPEntries && target.DestMAC != nil {
			r.pendingARPs[ifaceName][cidr.Addr()] = target.DestMAC
		} else {
			delete(r.pendingARPs[ifaceName], cidr.Addr())
		}
	}
}

// RouteUpdate updates the route keyed off the target CIDR. These deltas will
// be applied to any routes set using SetRoute.
func (r *RouteTable) RouteUpdate(ifaceName string, target Target) {
	if !r.ownershipPolicy.IfaceIsOurs(ifaceName) {
		r.logCxt.WithField("ifaceName", ifaceName).Error(
			"Cannot set route for interface not managed by this routetable.")
		return
	}

	routesByCIDR := r.ifaceToRoutes[ifaceName]
	if routesByCIDR == nil {
		routesByCIDR = map[ip.CIDR]Target{}
		r.ifaceToRoutes[ifaceName] = routesByCIDR
	}
	routesByCIDR[target.CIDR] = target
	r.addOwningIface(ifaceName, target.CIDR)
}

// RouteRemove removes the route with the specified CIDR. These deltas will
// be applied to any routes set using SetRoute.
func (r *RouteTable) RouteRemove(ifaceName string, cidr ip.CIDR) {
	if !r.ownershipPolicy.IfaceIsOurs(ifaceName) {
		r.logCxt.WithField("ifaceName", ifaceName).Error(
			"Cannot set route for interface not managed by this routetable.")
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
	ifaceNames, ok := r.cidrToIfaces[cidr]
	if !ok {
		return
	}
	ifaceNames.Discard(ifaceName)
	if ifaceNames.Len() == 0 {
		delete(r.cidrToIfaces, cidr)
	}
	r.recalculateDesiredKernelRoute(cidr)
}

// recheckRouteOwnershipsByIface reruns conflict resolution for all
// the interface's routes.
func (r *RouteTable) recheckRouteOwnershipsByIface(name string) {
	for cidr := range r.ifaceToRoutes[name] {
		r.recalculateDesiredKernelRoute(cidr)
	}
}

func (r *RouteTable) ifaceIndex(ifaceName string) (int, bool) {
	if ifaceName == InterfaceNone {
		if r.ipVersion == 6 {
			// IPv6 "special" routes use ifindex 1 (vs 0 for IPv4).
			return 1, true
		} else {
			// IPv4 uses 0.
			return 0, true
		}
	}

	idx, ok := r.ifaceNameToIndex[ifaceName]
	return idx, ok
}

func (r *RouteTable) recalculateDesiredKernelRoute(cidr ip.CIDR) {
	kernKey := r.routeKeyForCIDR(cidr)
	oldDesiredRoute, _ := r.kernelRoutes.Desired().Get(kernKey)

	cleanUpKernelRoutes := func() {
		r.kernelRoutes.Desired().Delete(kernKey)
		r.conntrackTracker.RemoveAllowedOwner(kernKey)
	}

	ifaces := r.cidrToIfaces[cidr]
	if ifaces == nil {
		// Keep the blank slate!
		r.logCxt.WithFields(log.Fields{
			"cidr":     cidr,
			"oldRoute": oldDesiredRoute,
		}).Debug("CIDR no longer has associated routes.")
		cleanUpKernelRoutes()
		return
	}

	// In case of conflicts (more than one route with the same CIDR), pick
	// one deterministically so that we don't churn the dataplane.
	var bestTarget Target
	bestIface := ""
	bestIfaceIdx := -1
	var candidates []string
	ifaces.Iter(func(ifaceName string) error {
		candidates = append(candidates, ifaceName)
		ifIndex, ok := r.ifaceIndex(ifaceName)
		if !ok {
			r.logCxt.Debug("Skipping route for missing interface.")
			return nil
		}

		// We've got some routes for this interface, force-expire its
		// grace period.
		if graceInf, ok := r.ifaceIndexToGraceInfo[ifIndex]; ok {
			graceInf.GraceExpired = true
			r.ifaceIndexToGraceInfo[ifIndex] = graceInf
		}

		if ifaceName != InterfaceNone && r.ifaceIndexToState[ifIndex] != ifacemonitor.StateUp {
			r.logCxt.Debug("Skipping route for down interface.")
			return nil
		}

		// This tie-breaker tends to prefer "real" routes over "no-interface"
		// special routes, and it tends to prefer newer interfaces (because
		// they typically have higher indexes).
		if ifIndex > bestIfaceIdx {
			bestIface = ifaceName
			bestIfaceIdx = ifIndex
			bestTarget = r.ifaceToRoutes[ifaceName][cidr]
		}
		return nil
	})

	if bestIfaceIdx == -1 {
		r.logCxt.WithFields(log.Fields{
			"cidr":       cidr,
			"candidates": candidates,
		}).Debug("No valid route for this CIDR (all candidate routes missing iface index).")
		cleanUpKernelRoutes()
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
		OnLink:   bestTarget.Flags()&unix.RTNH_F_ONLINK != 0,
		Protocol: r.deviceRouteProtocol,
	}
	if log.IsLevelEnabled(log.DebugLevel) && !reflect.DeepEqual(oldDesiredRoute, kernRoute) {
		r.logCxt.WithFields(log.Fields{
			"dst":      kernKey,
			"oldRoute": oldDesiredRoute,
			"newRoute": kernRoute,
			"iface":    bestIface,
		}).Debug("Preferred kernel route for this dest has changed.")
	} else if log.IsLevelEnabled(log.DebugLevel) {
		r.logCxt.WithFields(log.Fields{
			"dst":   kernKey,
			"route": kernRoute,
			"iface": bestIface,
		}).Debug("Preferred kernel route for this dest still the same.")
	}

	r.kernelRoutes.Desired().Set(kernKey, kernRoute)
	r.conntrackTracker.SetAllowedOwner(kernKey, bestIfaceIdx)
}

func (r *RouteTable) QueueResync() {
	r.logCxt.Debug("Queueing a resync of routing table.")
	r.fullResyncNeeded = true
}

func (r *RouteTable) Apply() (err error) {
	err = r.attemptApply()
	if err != nil {
		// Do one inline retry with a fresh netlink connection.
		r.logCxt.WithError(err).Warn("First attempt at updating routing table failed.  Retrying...")
		err = r.attemptApply()
		if err != nil {
			r.logCxt.WithError(err).Error("Second attempt at updating routing table failed. Will retry later.")
		} else {
			r.logCxt.WithError(err).Info("Retry was successful.")
		}
	}
	return err
}

func (r *RouteTable) attemptApply() (err error) {
	defer func() {
		if err != nil || r.forceNetlinkClose {
			r.nl.CloseHandle()
			r.forceNetlinkClose = false
		}
	}()
	if err = r.maybeResyncWithDataplane(); err != nil {
		return err
	}
	if err = r.applyUpdates(); err != nil {
		return err
	}
	r.maybeCleanUpGracePeriods()
	r.conntrackTracker.DoPeriodicCleanup()
	return nil
}

func (r *RouteTable) maybeCleanUpGracePeriods() {
	if time.Since(r.lastGracePeriodCleanup) < r.routeCleanupGracePeriod {
		return
	}
	for k, v := range r.ifaceIndexToGraceInfo {
		if time.Since(v.FirstSeen) < r.routeCleanupGracePeriod {
			continue
		}
		if _, ok := r.ifaceIndexToName[k]; ok {
			continue // Iface still exists, don't want to reset its grace period.
		}
		delete(r.ifaceIndexToGraceInfo, k)
	}
}

func (r *RouteTable) maybeResyncWithDataplane() error {
	nl, err := r.nl.Handle()
	if err != nil {
		r.logCxt.WithError(err).Error("Failed to connect to netlink.")
		return ConnectFailed
	}

	if r.fullResyncNeeded {
		return r.doFullResync(nl)
	}

	// Do any partial per-interface resyncs.
	return r.resyncIndividualInterfaces(nl)
}

func (r *RouteTable) doFullResync(nl netlinkshim.Interface) error {
	r.logCxt.Debug("Doing full resync.")
	r.opReporter.RecordOperation(fmt.Sprint("resync-routes-v", r.ipVersion))
	resyncStartTime := time.Now()

	// It's possible that we get out of sync with the interface monitor; for example, if the
	// RouteTable is created after start-of-day.  Do our own refresh of the list of links.
	if err := r.refreshAllIfaceStates(nl); err != nil {
		log.WithError(err).Error("Failed to list interfaces")
		return fmt.Errorf("failed to list interfaces during resync: %w", err)
	}

	// Load all the routes in the routing table.  If we're managing
	// routes in a shared table (such as the main table) this may include
	// routes that we're not managing.
	routeFilter := &netlink.Route{
		Table: r.tableIndex,
	}
	routeFilterFlags := netlink.RT_FILTER_TABLE
	allRoutes, err := nl.RouteListFiltered(r.netlinkFamily, routeFilter, routeFilterFlags)
	if errors.Is(err, unix.ENOENT) {
		// In strict mode, get this if the routing table doesn't exist; it'll be auto-created
		// when we add the first route so just treat it as empty.
		log.WithError(err).Debug("Routing table doesn't exist (yet). Treating as empty.")
		allRoutes = nil
		err = nil
	}
	if err != nil {
		return fmt.Errorf("failed to list all routes for resync: %w", err)
	}

	err = r.kernelRoutes.Dataplane().ReplaceAllIter(func(f func(k kernelRouteKey, v kernelRoute)) error {
		for _, route := range allRoutes {
			r.onIfaceSeen(route.LinkIndex)
			kernKey, kernRoute, ok := r.netlinkRouteToKernelRoute(route)
			if !ok {
				// Not a route that we're managing.
				continue
			}
			r.conntrackTracker.AddDataplaneOwner(kernKey, kernRoute.Ifindex)
			f(kernKey, kernRoute)
		}
		return nil
	})
	if err != nil {
		// Should be impossible unless we return an error from the iterator.
		return fmt.Errorf("failed to update delta tracker: %w", err)
	}

	// We're now in sync.
	r.ifacesToRescan.Clear()
	r.fullResyncNeeded = false
	listAllRoutesTime.Observe(r.time.Since(resyncStartTime).Seconds())
	return nil
}

func (r *RouteTable) resyncIndividualInterfaces(nl netlinkshim.Interface) error {
	r.ifacesToRescan.Iter(func(ifaceName string) error {
		// Defensive: we can be out of sync with the interface monitor if this
		// RouteTable was created after start-of-day.  Refresh the link.
		err := r.refreshIfaceStateBestEffort(nl, ifaceName)
		if err != nil {
			r.forceNetlinkClose = true
			return nil
		}

		ifIndex, ok := r.ifaceIndex(ifaceName)
		if !ok {
			r.logCxt.Debug("Ignoring rescan of unknown interface.")
			return set.RemoveItem
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
				r.forceNetlinkClose = true
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
				// Not a route that we're managing, so we don't want it to
				// be a candidate for us to delete.
				continue
			}
			r.conntrackTracker.AddDataplaneOwner(kernKey, kernRoute.Ifindex)
			kernRoutes[kernKey] = kernRoute
		}
		// Then look for routes that the tracker says are there but are actually
		// missing.
		for cidr := range r.ifaceToRoutes[ifaceName] {
			kernKey := r.routeKeyForCIDR(cidr)
			if _, ok := kernRoutes[kernKey]; ok {
				// Route still there; handled below.
				continue
			}
			desKernRoute, ok := r.kernelRoutes.Desired().Get(kernKey)
			if !ok || desKernRoute.Ifindex != ifIndex {
				// This interface doesn't "own" this route .
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

func (r *RouteTable) refreshAllIfaceStates(nl netlinkshim.Interface) error {
	debug := log.IsLevelEnabled(log.DebugLevel)

	links, err := nl.LinkList()
	if err != nil {
		return err
	}
	seenNames := set.New[string]()

	// First pass, simulate deletions of any interfaces that have been
	// renamed or renumbered.
	for _, link := range links {
		oldIdx, ok := r.ifaceNameToIndex[link.Attrs().Name]
		if ok && oldIdx != link.Attrs().Index {
			// Interface renumbered.  For example, deleted and then recreated.
			// Simulate a deletion of the old interface.
			log.WithFields(log.Fields{
				"ifaceName": link.Attrs().Name,
				"oldIdx":    oldIdx,
				"newIdx":    link.Attrs().Index,
			}).Debug("Spotted interface had changed index during resync.")
			r.OnIfaceStateChanged(link.Attrs().Name, oldIdx, ifacemonitor.StateNotPresent)
		}
		oldName, ok := r.ifaceIndexToName[link.Attrs().Index]
		if ok && oldName != link.Attrs().Name {
			// Interface renamed.  Simulate a deletion of the old interface.
			log.WithFields(log.Fields{
				"ifaceName": link.Attrs().Name,
				"oldName":   oldName,
				"newName":   link.Attrs().Name,
			}).Debug("Spotted interface had changed name during resync.")
			r.OnIfaceStateChanged(oldName, link.Attrs().Index, ifacemonitor.StateNotPresent)
		}
	}

	// Second pass, update the state of any changed interfaces.
	for _, link := range links {
		seenNames.Add(link.Attrs().Name)
		newState := ifacemonitor.StateDown
		if ifacemonitor.LinkIsOperUp(link) {
			newState = ifacemonitor.StateUp
		}
		oldState := r.ifaceIndexToState[link.Attrs().Index]
		log.WithFields(log.Fields{
			"ifaceName": link.Attrs().Name,
			"newState":  newState,
			"oldState":  oldState,
			"idx":       link.Attrs().Index,
		}).Debug("Checking interface state.")
		if newState != oldState {
			// Only call OnIfaceStateChanged if the state has actually changed
			// so that we avoid triggering it to re-do conflict resolution
			// (which will generate log spam if the interface hasn't changed).
			if debug {
				r.logCxt.WithFields(log.Fields{
					"ifaceName": link.Attrs().Name,
					"oldState":  oldState,
					"newState":  newState,
				}).Debug("Spotted interface had changed state during resync.")
			}
			r.OnIfaceStateChanged(link.Attrs().Name, link.Attrs().Index, newState)
		}
	}

	// Third pass, remove any interfaces that have disappeared.
	for name := range r.ifaceNameToIndex {
		if seenNames.Contains(name) {
			continue
		}
		if debug {
			r.logCxt.WithField("ifaceName", name).Debug("Spotted interface not present during full resync.  Cleaning up.")
		}
		r.OnIfaceStateChanged(name, 0, ifacemonitor.StateNotPresent)
	}
	return nil
}

func (r *RouteTable) refreshIfaceStateBestEffort(nl netlinkshim.Interface, ifaceName string) error {
	r.logCxt.WithField("name", ifaceName).Debug("Refreshing state of interface.")
	link, err := nl.LinkByName(ifaceName)
	var lnf netlink.LinkNotFoundError
	if errors.As(err, &lnf) {
		r.OnIfaceStateChanged(ifaceName, 0, ifacemonitor.StateNotPresent)
		return nil
	} else if err != nil {
		log.WithError(err).Warn("Failed to get link.")
		return fmt.Errorf("failed to look up interface: %w", err)
	}
	state := ifacemonitor.StateDown
	if ifacemonitor.LinkIsOperUp(link) {
		state = ifacemonitor.StateUp
	}
	r.OnIfaceStateChanged(link.Attrs().Name, link.Attrs().Index, state)
	return nil
}

func (r *RouteTable) routeKeyForCIDR(cidr ip.CIDR) kernelRouteKey {
	return kernelRouteKey{CIDR: cidr, Priority: r.routeMetric}
}

// netlinkRouteToKernelRoute converts (only) routes that we own back
// to our kernelRoute/Key structs (returning ok=true).  Other routes
// are ignored and returned with ok = false.
func (r *RouteTable) netlinkRouteToKernelRoute(route netlink.Route) (kernKey kernelRouteKey, kernRoute kernelRoute, ok bool) {
	// We're on the hot path, so it's worth avoiding the overheads of
	// WithField(s) if debug is disabled.
	debug := log.IsLevelEnabled(log.DebugLevel)
	logCxt := r.logCxt
	if debug {
		logCxt = logCxt.WithField("route", route)
	}
	ifaceName := ""
	if routeIsSpecialNoIfRoute(route) {
		ifaceName = InterfaceNone
	} else if routeIsIPv6Bootstrap(route) {
		logCxt.Debug("Ignoring IPv6 bootstrap route, kernel manages these.")
		return
	} else {
		ifaceName = r.ifaceIndexToName[route.LinkIndex]
		if ifaceName == "" {
			// We don't know about this interface.  Either we're racing
			// with link creation, in which case we'll hear about the
			// interface soon and work out what to do, or we're seeing
			// a route for a just-deleted interface, in which case
			// we don't care.
			logCxt.Debug("Ignoring route for unknown iface")
			return
		}
	}

	if !r.ownershipPolicy.RouteIsOurs(ifaceName, &route) {
		logCxt.Debug("Ignoring route (it doesn't belong to us).")
		return
	}

	kernKey = kernelRouteKey{
		CIDR:     ip.CIDRFromIPNet(route.Dst),
		Priority: RouteMetric(route.Priority),
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
	if debug {
		logCxt.WithFields(log.Fields{
			"kernRoute": kernRoute,
			"kernKey":   kernKey,
		}).Debug("Loaded route from kernel.")
	}
	ok = true
	return
}

func routeIsIPv6Bootstrap(route netlink.Route) bool {
	if route.Dst == nil {
		return false
	}
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
		kernRoute, _ := r.kernelRoutes.PendingDeletions().Get(kernKey)
		graceInf := r.ifaceIndexToGraceInfo[kernRoute.Ifindex]
		ifaceInGracePeriod := !graceInf.GraceExpired && r.time.Since(graceInf.FirstSeen) < r.routeCleanupGracePeriod
		if ifaceInGracePeriod {
			// Don't remove unexpected routes from interfaces created recently.
			r.logCxt.WithFields(log.Fields{
				"route": kernRoute,
				"dest":  kernKey,
			}).Debug("Found unexpected route; ignoring due to grace period.")
			return deltatracker.IterActionNoOp
		}

		err := r.deleteRoute(nl, kernKey)
		if err != nil {
			deletionErrs[kernKey] = err
			return deltatracker.IterActionNoOp
		}
		// Route is gone, clean up the dataplane side of the tracker.
		r.logCxt.WithField("route", kernKey).Debug("Deleted route.")
		return deltatracker.IterActionUpdateDataplane
	})

	// Start background conntrack deletions for routes that have been removed.
	// We only wait for these to finish one-by-one if we need to move the route
	// to a new interface.
	r.conntrackTracker.StartDeletionsForDeletedRoutes()
	// For routes that are moving to a new interface, delete the old route
	// synchronously and kick off conntrack deletions for the old interface.
	// This makes sure that we don't have a window where a new connection
	// can start using the old interface.
	r.conntrackTracker.IterMovedRoutesAndStartDeletions(func(kernKey kernelRouteKey, newOwners []int) {
		err := r.deleteRoute(nl, kernKey)
		if err != nil {
			deletionErrs[kernKey] = err
		} else {
			r.kernelRoutes.Dataplane().Delete(kernKey)
		}
	})

	updateErrs := map[kernelRouteKey]error{}
	r.kernelRoutes.PendingUpdates().Iter(func(kernKey kernelRouteKey, kRoute kernelRoute) deltatracker.IterAction {
		dst := kernKey.CIDR.ToIPNet()
		flags := 0
		if kRoute.OnLink {
			flags = unix.RTNH_F_ONLINK
		}

		r.conntrackTracker.WaitForPendingDeletion(kernKey.CIDR.Addr())
		r.conntrackTracker.SetSingleDataplaneOwner(kernKey, kRoute.Ifindex)

		nlRoute := &netlink.Route{
			Family: r.netlinkFamily,

			Table:    r.tableIndex,
			Dst:      &dst,
			Tos:      kernKey.TOS,
			Priority: int(kernKey.Priority),

			Type:      kRoute.Type,
			Scope:     kRoute.Scope,
			Gw:        kRoute.GWAsNetIP(),
			Src:       kRoute.SrcAsNetIP(),
			LinkIndex: kRoute.Ifindex,
			Protocol:  kRoute.Protocol,
			Flags:     flags,
		}
		r.logCxt.WithFields(log.Fields{
			"nlRoute":  nlRoute,
			"ourKey":   kernKey,
			"ourRoute": kRoute,
		}).Debug("Replacing route")
		err := nl.RouteReplace(nlRoute)
		if err != nil {
			updateErrs[kernKey] = err
			return deltatracker.IterActionNoOp
		}

		// Route is gone, clean up the dataplane side of the tracker.
		return deltatracker.IterActionUpdateDataplane
	})

	arpErrs := map[string]error{}
	for ifaceName, addrToMAC := range r.pendingARPs {
		// Add static ARP entries (for workload endpoints).  This may have been
		// needed at one point but it no longer seems to be required.  Leaving
		// it here for two reasons: (1) there may be an obscure scenario where
		// it is needed. (2) we have tests that monitor netlink, and they break
		// if it is removed because they see the ARP traffic.
		ifaceIdx, ok := r.ifaceIndex(ifaceName)
		if !ok {
			// Asked to add ARP entries but the interface isn't known (yet).
			// Leave them pending.  We'll clean up the pending set if the
			// datastore stops asking us to add ARP entries for this interface.
			continue
		}
		for addr, mac := range addrToMAC {
			err := r.addStaticARPEntry(nl, addr, mac, ifaceIdx)
			if err != nil {
				log.WithError(err).Debug("Failed to add neighbor entry.")
				arpErrs[fmt.Sprintf("%s/%s", ifaceName, addr)] = err
			} else {
				delete(addrToMAC, addr)
			}
		}
		if len(addrToMAC) == 0 {
			delete(r.pendingARPs, ifaceName)
		}
	}

	// TODO filter out errors from interfaces that have gone away.
	err = nil
	if len(deletionErrs) > 0 {
		r.logCxt.WithField("errors", deletionErrs).Warn(
			"Encountered some errors when trying to delete old routes.")
		err = UpdateFailed
	}
	if len(updateErrs) > 0 {
		r.logCxt.WithField("errors", updateErrs).Warn(
			"Encountered some errors when trying to update routes.  Will retry.")
		err = UpdateFailed
	}
	if len(arpErrs) > 0 {
		r.logCxt.WithField("errors", arpErrs).Warn(
			"Encountered some errors when trying to add static ARP entries.  Will retry.")
		err = UpdateFailed
	}

	return err
}

func (r *RouteTable) deleteRoute(nl netlinkshim.Interface, kernKey kernelRouteKey) error {
	// Template route for deletion.  The family, table, TOS, Priority uniquely
	// identify the route, but we also need to set some fields to their "wildcard"
	// values (found via code reading the kernel and running "ip route del" under
	// strace).
	dst := kernKey.CIDR.ToIPNet()
	nlRoute := &netlink.Route{
		Family: r.netlinkFamily,

		Table:    r.tableIndex,
		Dst:      &dst,
		Tos:      kernKey.TOS,
		Priority: int(kernKey.Priority),

		Protocol: unix.RTPROT_UNSPEC,    // Wildcard (but also zero value).
		Scope:    unix.RT_SCOPE_NOWHERE, // Wildcard.  Note: non-zero value!
		Type:     unix.RTN_UNSPEC,       // Wildcard (but also zero value).
	}
	err := nl.RouteDel(nlRoute)
	if errors.Is(err, unix.ESRCH) {
		r.logCxt.WithField("route", kernKey).Debug("Tried to delete route but it wasn't found.")
		err = nil // Already gone (we hope).
	}
	return err
}

// filterErrorByIfaceState checks the current state of the interface; if it's down or gone, it
// returns IfaceDown or IfaceNotPresent, otherwise, it returns the given defaultErr.
func (r *RouteTable) filterErrorByIfaceState(
	ifaceName string,
	currentErr, defaultErr error,
	suppressExistsWarning bool,
) error {
	if currentErr == nil {
		return nil
	}

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

func (r *RouteTable) addStaticARPEntry(
	nl netlinkshim.Interface,
	addr ip.Addr,
	mac net.HardwareAddr,
	ifindex int,
) error {
	a := &netlink.Neigh{
		Family:       unix.AF_INET,
		LinkIndex:    ifindex,
		State:        netlink.NUD_PERMANENT,
		Type:         unix.RTN_UNICAST,
		IP:           addr.AsNetIP(),
		HardwareAddr: mac,
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		r.logCxt.WithField("entry", a).Debug("Adding static ARP entry.")
	}
	return nl.NeighSet(a)
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
	Priority RouteMetric
}

func (k kernelRouteKey) String() string {
	return fmt.Sprintf("%s(tos=%x metric=%d)", k.CIDR.String(), k.TOS, k.Priority)
}

// kernelRoute is our low-level representation of the parts of a route that
// we care to program. It contains fields that we can easily read back from the
// kernel for comparison. In particular, we track the interface index instead
// of the interface name.  This means that if an interface is recreated, we
// must trigger recalculation of the desired kernelRoute.
type kernelRoute struct {
	Type     int // unix.RTN_... constants.
	Scope    netlink.Scope
	GW       ip.Addr
	Src      ip.Addr
	Ifindex  int
	Protocol netlink.RouteProtocol
	OnLink   bool
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

func (r kernelRoute) String() string {
	var zeroVal kernelRoute
	if r == zeroVal {
		return "<none>"
	}
	gwStr := "<nil>"
	if r.GW != nil {
		gwStr = r.GW.String()
	}
	srcStr := "<nil>"
	if r.Src != nil {
		srcStr = r.Src.String()
	}
	return fmt.Sprintf("kernelRoute{Type:%d, Scope=%d, GW=%s, Src=%s, Ifindex=%d, Protocol=%v, OnLink=%v}",
		r.Type, r.Scope, gwStr, srcStr, r.Ifindex, r.Protocol, r.OnLink)
}
