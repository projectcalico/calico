// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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

//go:build !windows

package routetable

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"syscall"
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

const (
	routeListFilterAttempts = 5
)

var (
	ipV6LinkLocalCIDR = ip.MustParseCIDROrIP("fe80::/64")

	resyncTimeSummary = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_route_table_resync_seconds",
		Help: "Time taken to list all the routes during a resync.",
	})
	partialResyncTimeSummary = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_route_table_partial_resync_seconds",
		Help: "Time taken to resync the routes of a single interface.",
	})
	conntrackBlockTimeSummary = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_route_table_conntrack_wait_seconds",
		Help: "Time waiting for conntrack cleanups to finish.",
	})
	gaugeVecNumRoutes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_route_table_num_routes",
		Help: "Number of routes that Felix is managing in the particular routing table.",
	}, []string{"table"})
	gaugeVecNumIfaces = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_route_table_num_ifaces",
		Help: "Number of interfaces that Felix is monitoring for the particular routing table.",
	}, []string{"table"})

	defaultCIDRv4, _ = ip.ParseCIDROrIP("0.0.0.0/0")
	defaultCIDRv6, _ = ip.ParseCIDROrIP("::/0")
)

func init() {
	prometheus.MustRegister(
		resyncTimeSummary,
		partialResyncTimeSummary,
		conntrackBlockTimeSummary,
		gaugeVecNumRoutes,
		gaugeVecNumIfaces,
	)
}

// RouteTable manages the Calico routes for a specific kernel routing table.
//
// There are several complicating factors to managing the routes and all of
// these have caused real problems in the past:
//
//   - There is more than one Felix subcomponent that needs to program routes,
//     often into the same table.  It is possible for different components to
//     try to program conflicting routes for the same CIDR (for example, if a
//     local and remote endpoint share the same IP address).  To deal with this
//     we assign a RouteClass to each potential source of routes and break
//     ties on that value.
//
//   - Most Calico components only deal with CIDRs and interfaces, but the
//     kernel routing table is indexed by CIDR, metric and ToS field.  To handle
//     this difference in indexing, we use a DeltaTracker indexed in a way that
//     matches the kernel's indexing.  That allows us to correctly clean up any
//     kernel routes that would alias if we only considered CIDR.
//
//   - We need to translate interface name to interface index and that mapping
//     can change over time.  Interfaces can be renamed, keeping the same index.
//     Interfaces can be recreated, keeping the same name but getting a new index.
//     We handle this by indexing the routes we've been told to create on interface
//     name and by listening for interface state changes.  When an interface
//     is updated, we re-calculate the routes that we want to program for it and
//     re-do conflict resolution.
//
//   - We can race with the interface monitor goroutine, being asked to program
//     a route before we've heard about the interface, or spotting a new
//     interface index when we do a read back of routes from the kernel.
//
//   - The CNI plugin also programs the same routes that we do, so we can race
//     with it as well.  We may see an interface pop up with a route before we
//     hear about the corresponding WorkloadEndpoint.  To deal with that, we
//     implement a grace period before deleting routes that belong to us but
//     that we don't know about yet.
//
//   - When IP addresses move from one interface to another (for example because
//     a workload has been terminated and a new workload now has the IP) we need
//     to clean up the conntrack entries from the old workload.  We delegate this
//     cleanup to the RouteOwnershipTracker; giving it callbacks when routes move.
//     We do that cleanup in the background to avoid holding up other route
//     programming.
type RouteTable struct {
	logCxt        *log.Entry
	ipVersion     uint8
	netlinkFamily int
	// The routing table index.  This is defaulted to RT_TABLE_MAIN if not specified.
	tableIndex int

	deviceRouteSourceAddress ip.Addr
	defaultRouteProtocol     netlink.RouteProtocol
	removeExternalRoutes     bool
	ownershipPolicy          OwnershipPolicy

	// Interface update tracking.
	fullResyncNeeded    bool
	ifacesToRescan      set.Set[string]
	makeARPEntries      bool
	haveMultiPathRoutes bool

	// ifaceToRoutes and cidrToIfaces are our inputs, updated
	// eagerly when something in the manager layer tells us to change the
	// routes.
	ifaceToRoutes map[RouteClass]map[string]map[ip.CIDR]Target
	cidrToIfaces  map[RouteClass]map[ip.CIDR]set.Set[string]

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
	// conntrackTracker is a ConntrackCleanupManager or a NoOpRouteTracker
	// Depending on whether conntrack cleanup is enabled or not.
	conntrackTracker RouteOwnershipTracker

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

	gaugeNumRoutes prometheus.Gauge
	gaugeNumIfaces prometheus.Gauge
}

type graceInfo struct {
	FirstSeen    time.Time
	GraceExpired bool
}

type Opt func(table *RouteTable)

func WithLivenessCB(cb func()) Opt {
	return func(table *RouteTable) {
		table.livenessCallback = cb
	}
}

func WithRouteCleanupGracePeriod(routeCleanupGracePeriod time.Duration) Opt {
	return func(table *RouteTable) {
		table.routeCleanupGracePeriod = routeCleanupGracePeriod
	}
}

func WithStaticARPEntries(b bool) Opt {
	return func(table *RouteTable) {
		if table.ipVersion != 4 {
			log.Panic("Bug: ARP entries only supported for IPv4.")
		}
		table.makeARPEntries = b
	}
}

func WithConntrackCleanup(enabled bool) Opt {
	return func(table *RouteTable) {
		table.conntrackCleanupEnabled = enabled
	}
}

func WithTimeShim(shim timeshim.Interface) Opt {
	return func(table *RouteTable) {
		table.time = shim
	}
}

func WithConntrackShim(shim conntrackIface) Opt {
	return func(table *RouteTable) {
		table.conntrack = shim
	}
}

func WithNetlinkHandleShim(newNetlinkHandle func() (netlinkshim.Interface, error)) Opt {
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
// routing tables which tend to be used to manage routes for a single device.
type OwnershipPolicy interface {
	RouteIsOurs(ifaceName string, route *netlink.Route) bool

	IfaceIsOurs(ifaceName string) bool
	IfaceShouldHaveARPEntries(ifaceName string) bool
	IfaceShouldHaveGracePeriod(ifaceName string) bool
}

func New(
	ownershipPolicy OwnershipPolicy,
	ipVersion uint8,
	netlinkTimeout time.Duration,
	deviceRouteSourceAddress net.IP,
	defaultRouteProtocol netlink.RouteProtocol,
	removeExternalRoutes bool,
	tableIndex int,
	opReporter logutils.OpRecorder,
	featureDetector environment.FeatureDetectorIface,
	opts ...Opt,
) *RouteTable {
	if ownershipPolicy == nil {
		log.Panic("Must provide an ownership policy.")
	}
	if tableIndex == 0 {
		// If we set route.Table to 0, what we actually get is a route in RT_TABLE_MAIN.  However,
		// RouteListFiltered is much more efficient if we give it the "real" table number.
		log.Debug("RouteTable created with unspecified table; defaulting to unix.RT_TABLE_MAIN.")
		tableIndex = unix.RT_TABLE_MAIN
	}

	var logCxt *log.Entry
	description := fmt.Sprintf("IPv%d:%d", ipVersion, tableIndex)
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
		defaultRouteProtocol:     defaultRouteProtocol,
		removeExternalRoutes:     removeExternalRoutes,

		fullResyncNeeded: true,
		ifacesToRescan:   set.New[string](),
		ownershipPolicy:  ownershipPolicy,

		ifaceToRoutes: map[RouteClass]map[string]map[ip.CIDR]Target{},
		cidrToIfaces:  map[RouteClass]map[ip.CIDR]set.Set[string]{},

		kernelRoutes: deltatracker.New[kernelRouteKey, kernelRoute](
			deltatracker.WithValuesEqualFn[kernelRouteKey, kernelRoute](func(a, b kernelRoute) bool {
				return a.Equals(b)
			}),
		),
		pendingARPs: map[string]map[ip.Addr]net.HardwareAddr{},

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

		gaugeNumRoutes: gaugeVecNumRoutes.WithLabelValues(description),
		gaugeNumIfaces: gaugeVecNumIfaces.WithLabelValues(description),
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
		rt.conntrackTracker = NewConntrackCleanupManager(ipVersion, rt.conntrack)
	} else {
		rt.conntrackTracker = NewNoOpRouteTracker()
	}

	return rt
}

func (r *RouteTable) Index() int {
	return r.tableIndex
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
	if state == ifacemonitor.StateNotPresent {
		// Interface deleted, clean up.
		oldIndex := r.ifaceNameToIndex[ifaceName]
		delete(r.ifaceIndexToName, oldIndex)
		delete(r.ifaceIndexToState, oldIndex)
		delete(r.ifaceNameToIndex, ifaceName)
		r.ifacesToRescan.Discard(ifaceName)
	} else {
		// Interface exists, record its details.
		r.onIfaceSeen(ifIndex)
		r.ifaceIndexToState[ifIndex] = state
		oldIfIndex, ok := r.ifaceNameToIndex[ifaceName]
		if ok && oldIfIndex != ifIndex {
			// Interface renumbered.  For example, deleted and then recreated
			// with same name.  Clean up old number.
			delete(r.ifaceIndexToName, oldIfIndex)
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
		if r.haveMultiPathRoutes {
			// The interface may be used by a next hop on a multi-path route.
			// so we need to recheck everything.   We only use multi-path
			// for EGW tunnels right now so this will only be a handful of
			// routes.
			logCxt.Debug("Interface up, rechecking all multi-path routes.")
			r.QueueResync()
		}
	}

	r.recheckRouteOwnershipsByIface(ifaceName)

	if r.haveMultiPathRoutes {
		// Re-check all potential multi-path routes.  We only use multi-path
		// for EGW tunnels right now so this will only be a handful of routes.
		logCxt.Debug("Rechecking all multi-path routes.")
		r.recheckRouteOwnershipsByIface(InterfaceNone)
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

func (r *RouteTable) QueueResyncIface(ifaceName string) {
	r.ifacesToRescan.Add(ifaceName)
}

// SetRoutes replaces the full set of targets for the specified interface.
func (r *RouteTable) SetRoutes(routeClass RouteClass, ifaceName string, targets []Target) {
	if !r.ownershipPolicy.IfaceIsOurs(ifaceName) {
		r.logCxt.WithField("ifaceName", ifaceName).Error(
			"Cannot set route for interface not managed by this routetable.")
		return
	}
	r.logCxt.WithFields(log.Fields{
		"routeClass": routeClass,
		"ifaceName":  ifaceName,
		"targets":    targets,
	}).Debug("SetRoutes called.")
	r.checkTargets(ifaceName, targets...)

	if r.ifaceToRoutes[routeClass] == nil {
		r.ifaceToRoutes[routeClass] = map[string]map[ip.CIDR]Target{}
	}

	// Figure out what has changed.
	oldTargetsToCleanUp := r.ifaceToRoutes[routeClass][ifaceName]
	newTargets := map[ip.CIDR]Target{}
	for _, t := range targets {
		delete(oldTargetsToCleanUp, t.CIDR)
		newTargets[t.CIDR] = t
	}

	// Record the new desired state.
	if len(newTargets) == 0 {
		r.logCxt.Debug("No routes for this interface, removing from map.")
		delete(r.ifaceToRoutes[routeClass], ifaceName)
	} else {
		r.ifaceToRoutes[routeClass][ifaceName] = newTargets
	}

	// Clean up the old CIDRs.
	for cidr := range oldTargetsToCleanUp {
		r.logCxt.WithField("cidr", cidr).Debug("Cleaning up old route.")
		// removeOwningIface() calls recalculateDesiredKernelRoute.
		r.removeOwningIface(routeClass, ifaceName, cidr)
	}

	// Clean out the pending ARP list, then recalculate it below.
	delete(r.pendingARPs, ifaceName)
	for cidr, target := range newTargets {
		// addOwningIface() calls recalculateDesiredKernelRoute.
		r.addOwningIface(routeClass, ifaceName, cidr)
		r.updatePendingARP(ifaceName, cidr.Addr(), target.DestMAC)
	}
}

// RouteUpdate updates the route keyed off the target CIDR. These deltas will
// be applied to any routes set using SetRoute.
func (r *RouteTable) RouteUpdate(routeClass RouteClass, ifaceName string, target Target) {
	if !r.ownershipPolicy.IfaceIsOurs(ifaceName) {
		r.logCxt.WithField("ifaceName", ifaceName).Error(
			"Cannot set route for interface not managed by this routetable.")
		return
	}
	r.checkTargets(ifaceName, target)

	if r.ifaceToRoutes[routeClass] == nil {
		r.ifaceToRoutes[routeClass] = map[string]map[ip.CIDR]Target{}
	}

	routesByCIDR := r.ifaceToRoutes[routeClass][ifaceName]
	if routesByCIDR == nil {
		routesByCIDR = map[ip.CIDR]Target{}
		r.ifaceToRoutes[routeClass][ifaceName] = routesByCIDR
	}
	routesByCIDR[target.CIDR] = target
	r.addOwningIface(routeClass, ifaceName, target.CIDR)
	r.updatePendingARP(ifaceName, target.CIDR.Addr(), target.DestMAC)
}

// RouteRemove removes the route with the specified CIDR. These deltas will
// be applied to any routes set using SetRoute.
func (r *RouteTable) RouteRemove(routeClass RouteClass, ifaceName string, cidr ip.CIDR) {
	if !r.ownershipPolicy.IfaceIsOurs(ifaceName) {
		r.logCxt.WithField("ifaceName", ifaceName).Error(
			"Cannot set route for interface not managed by this routetable.")
		return
	}

	delete(r.ifaceToRoutes[routeClass][ifaceName], cidr)
	if len(r.ifaceToRoutes[routeClass][ifaceName]) == 0 {
		delete(r.ifaceToRoutes[routeClass], ifaceName)
	}
	r.removeOwningIface(routeClass, ifaceName, cidr)
	r.removePendingARP(ifaceName, cidr.Addr())
}

func (r *RouteTable) updatePendingARP(ifaceName string, addr ip.Addr, mac net.HardwareAddr) {
	if !r.makeARPEntries {
		return
	}
	if len(mac) == 0 {
		r.removePendingARP(ifaceName, addr)
		return
	}
	r.logCxt.Debug("Adding pending ARP entry.")
	if r.pendingARPs[ifaceName] == nil {
		r.pendingARPs[ifaceName] = map[ip.Addr]net.HardwareAddr{}
	}
	r.pendingARPs[ifaceName][addr] = mac
}

func (r *RouteTable) removePendingARP(ifaceName string, addr ip.Addr) {
	if !r.makeARPEntries {
		return
	}
	if pending, ok := r.pendingARPs[ifaceName]; ok {
		delete(pending, addr)
		if len(pending) == 0 {
			delete(r.pendingARPs, ifaceName)
		}
	}
}

func (r *RouteTable) addOwningIface(class RouteClass, ifaceName string, cidr ip.CIDR) {
	if r.cidrToIfaces[class] == nil {
		r.cidrToIfaces[class] = map[ip.CIDR]set.Set[string]{}
	}
	ifaceNames := r.cidrToIfaces[class][cidr]
	if ifaceNames == nil {
		ifaceNames = set.New[string]()
		r.cidrToIfaces[class][cidr] = ifaceNames
	}
	ifaceNames.Add(ifaceName)
	r.recalculateDesiredKernelRoute(cidr)
}

func (r *RouteTable) removeOwningIface(class RouteClass, ifaceName string, cidr ip.CIDR) {
	ifaceNames, ok := r.cidrToIfaces[class][cidr]
	if !ok {
		return
	}
	ifaceNames.Discard(ifaceName)
	if ifaceNames.Len() == 0 {
		delete(r.cidrToIfaces[class], cidr)
	}
	r.recalculateDesiredKernelRoute(cidr)
}

// recheckRouteOwnershipsByIface reruns conflict resolution for all
// the interface's routes.
func (r *RouteTable) recheckRouteOwnershipsByIface(name string) {
	seen := set.New[ip.CIDR]()
	for _, ifaceToRoutes := range r.ifaceToRoutes {
		for cidr := range ifaceToRoutes[name] {
			if seen.Contains(cidr) {
				continue
			}
			r.recalculateDesiredKernelRoute(cidr)
			seen.Add(cidr)
		}
	}
}

func (r *RouteTable) ifaceIndexForName(ifaceName string) (int, bool) {
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

func (r *RouteTable) ifaceNameForIndex(ifindex int) (string, bool) {
	if ifindex <= 1 {
		return InterfaceNone, true
	}
	name, ok := r.ifaceIndexToName[ifindex]
	return name, ok
}

func (r *RouteTable) recalculateDesiredKernelRoute(cidr ip.CIDR) {
	defer r.updateGauges()
	kernKey := r.routeKeyForCIDR(cidr)
	oldDesiredRoute, _ := r.kernelRoutes.Desired().Get(kernKey)

	var bestTarget Target
	bestRouteClass := RouteClassMax
	bestIface := ""
	bestIfaceIdx := -1
	var candidates []string

	for routeClass, cidrToIface := range r.cidrToIfaces {
		ifaces := cidrToIface[cidr]
		if ifaces == nil {
			continue
		}

		// In case of conflicts (more than one route with the same CIDR), pick
		// one deterministically so that we don't churn the dataplane.

		ifaces.Iter(func(ifaceName string) error {
			candidates = append(candidates, ifaceName)
			ifIndex, ok := r.ifaceIndexForName(ifaceName)
			if !ok {
				r.logCxt.WithField("ifaceName", ifaceName).Debug("Skipping route for missing interface.")
				return nil
			}

			someUp := false
			target, ok := r.ifaceToRoutes[routeClass][ifaceName][cidr]
			if !ok {
				log.WithFields(log.Fields{
					"ifaceName": ifaceName,
					"cidr":      cidr,
				}).Warn("Bug? No route for iface/CIDR (recalculateDesiredKernelRoute called too early?).")
				return nil
			}
			for _, nh := range target.MultiPath {
				if ifIndex, ok := r.ifaceIndexForName(nh.IfaceName); !ok {
					r.logCxt.WithField("ifaceName", nh.IfaceName).Debug("Skipping multi-path route for missing interface.")
					return nil
				} else {
					if r.ifaceIndexToState[ifIndex] == ifacemonitor.StateUp {
						someUp = true
					}
				}
			}

			// We've got some routes for this interface, force-expire its
			// grace period.
			if graceInf, ok := r.ifaceIndexToGraceInfo[ifIndex]; ok {
				graceInf.GraceExpired = true
				r.ifaceIndexToGraceInfo[ifIndex] = graceInf
			}

			if ifaceName != InterfaceNone && r.ifaceIndexToState[ifIndex] != ifacemonitor.StateUp {
				r.logCxt.WithField("ifaceName", ifaceName).Debug("Skipping route for down interface.")
				return nil
			} else if len(target.MultiPath) > 0 && !someUp {
				// Multi-path routes require at least one interface to be up.
				r.logCxt.Debug("Skipping multi-path route; all interfaces down.")
				return nil
			}

			// Main tie-breaker is the RouteClass, which is prioritised
			// by the function of the routes.  For example, local workload routes
			// take precedence over VXLAN tunnel routes.
			if routeClass < bestRouteClass || (routeClass == bestRouteClass && ifIndex > bestIfaceIdx) {
				bestIface = ifaceName
				bestIfaceIdx = ifIndex
				bestRouteClass = routeClass
				bestTarget = target
			}
			return nil
		})
	}

	if bestIfaceIdx == -1 {
		if len(candidates) == 0 {
			r.logCxt.WithFields(log.Fields{
				"cidr": cidr,
			}).Debug("CIDR no longer has any associated routes.")
		} else {
			r.logCxt.WithFields(log.Fields{
				"cidr":       cidr,
				"candidates": candidates,
			}).Debug("No valid route for this CIDR (all candidate routes missing iface index).")
		}

		// Clean up the old entries.
		r.kernelRoutes.Desired().Delete(kernKey)
		r.conntrackTracker.RemoveCIDROwner(cidr)
		return
	}

	src := r.deviceRouteSourceAddress
	if bestTarget.Src != nil {
		src = bestTarget.Src
	}
	proto := r.defaultRouteProtocol
	if bestTarget.Protocol != 0 {
		proto = bestTarget.Protocol
	}
	kernRoute := kernelRoute{
		Type:     bestTarget.RouteType(),
		Scope:    bestTarget.RouteScope(),
		GW:       bestTarget.GW,
		Src:      src,
		Ifindex:  bestIfaceIdx,
		OnLink:   bestTarget.Flags()&unix.RTNH_F_ONLINK != 0,
		Protocol: proto,
	}
	if len(bestTarget.MultiPath) > 0 {
		for _, nh := range bestTarget.MultiPath {
			ifIndex, ok := r.ifaceIndexForName(nh.IfaceName)
			if !ok {
				log.Panic("Bug: multi-path route had missing interface after we already checked!")
			}
			kernRoute.NextHops = append(kernRoute.NextHops, kernelNextHop{
				GW:      nh.Gw,
				Ifindex: ifIndex,
			})
		}
	} else {
		kernRoute.GW = bestTarget.GW
		kernRoute.Ifindex = bestIfaceIdx
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
	r.conntrackTracker.UpdateCIDROwner(cidr, bestIfaceIdx, bestRouteClass)
}

func (r *RouteTable) QueueResync() {
	r.logCxt.Debug("Queueing a resync of routing table.")
	r.fullResyncNeeded = true
}

// ReadRoutesFromKernel offers partial support for reading back routes from the
// kernel.  In particular, it assumes that "onlink" routes are VXLAN routes,
// which is lossy.  Currently, this is only used in Enterprise, where the
// routes it needs to read are VXLAN routes.
func (r *RouteTable) ReadRoutesFromKernel(ifaceName string) ([]Target, error) {
	r.logCxt.WithField("ifaceName", ifaceName).Debug("Reading routing table from kernel.")
	r.ifacesToRescan.Add(ifaceName)
	err := r.maybeResyncWithDataplane()
	if err != nil {
		return nil, err
	}

	ifaceIndex, ok := r.ifaceIndexForName(ifaceName)
	if !ok {
		return nil, IfaceNotPresent
	}

	var allTargets []Target
	r.kernelRoutes.Dataplane().Iter(func(key kernelRouteKey, kernRoute kernelRoute) {
		if kernRoute.Ifindex != ifaceIndex {
			return
		}

		target := Target{
			CIDR:     key.CIDR,
			Src:      kernRoute.Src,
			Protocol: kernRoute.Protocol,
		}

		switch kernRoute.Type {
		case unix.RTN_LOCAL:
			target.Type = TargetTypeLocal
		case unix.RTN_THROW:
			target.Type = TargetTypeThrow
		case unix.RTN_UNREACHABLE:
			target.Type = TargetTypeUnreachable
		case unix.RTN_BLACKHOLE:
			target.Type = TargetTypeBlackhole
		case unix.RTN_PROHIBIT:
			target.Type = TargetTypeProhibit
		case unix.RTN_UNICAST:
			if kernRoute.Scope == unix.RT_SCOPE_LINK {
				target.Type = TargetTypeLinkLocalUnicast
			} else {
				if kernRoute.OnLink {
					// Ugh, this is a lossy reverse mapping.
					// TODO align TargetTypes with kernel types!
					target.Type = TargetTypeVXLAN
				} else {
					target.Type = TargetTypeGlobalUnicast
				}
			}
		}

		if len(kernRoute.NextHops) > 0 {
			// Multi-path route.
			for _, nh := range kernRoute.NextHops {
				ifaceName, ok := r.ifaceNameForIndex(nh.Ifindex)
				if !ok {
					r.logCxt.WithField("ifindex", nh.Ifindex).Warn("Next hop has unknown interface index.")
				}
				target.MultiPath = append(target.MultiPath, NextHop{
					Gw:        nh.GW,
					IfaceName: ifaceName,
				})
			}
		} else {
			// Single-path route.
			target.GW = kernRoute.GW
		}

		allTargets = append(allTargets, target)
	})
	return allTargets, nil
}

func (r *RouteTable) Apply() (err error) {
	err = r.attemptApply(0)
	if err != nil {
		// To avoid log spam, only log if there was an unexpected problem.
		r.logCxt.WithError(err).Warn("First attempt at updating routing table failed.  Retrying...")
	}
	if err != nil || r.ifacesToRescan.Len() > 0 {
		// Do one inline retry with a fresh netlink connection.
		err = r.attemptApply(1)
		if err != nil {
			r.logCxt.WithError(err).Error("Second attempt at updating routing table failed. Will retry later.")
		} else {
			r.logCxt.WithError(err).Info("Retry was successful.")
		}
	}
	if r.ifacesToRescan.Len() > 0 {
		// Make sure the dataplane reschedules us.
		return fmt.Errorf("some interfaces flapped during route update: %s", r.ifacesToRescan.String())
	}
	return err
}

func (r *RouteTable) attemptApply(attempt int) (err error) {
	defer func() {
		if err != nil {
			r.nl.MarkHandleForReopen()
		}
	}()
	if err = r.maybeResyncWithDataplane(); err != nil {
		return err
	}
	if err = r.applyUpdates(attempt); err != nil {
		return err
	}
	r.maybeCleanUpGracePeriods()
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

		r.livenessCallback()
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

	// Load all the routes in the routing table.  For the main routing table,
	// this will include non-Calico routes, which we'll filter out later.
	routeFilter := &netlink.Route{
		Table: r.tableIndex,
	}
	routeFilterFlags := netlink.RT_FILTER_TABLE

	var err error
	seenKeys := set.NewSize[kernelRouteKey](r.kernelRoutes.Dataplane().Len())
	for attempt := 0; attempt < routeListFilterAttempts; attempt++ {
		// Using the Iter version here saves allocating a large slice of netlink.Route,
		// which we immediately discard.
		var scratchRoute netlink.Route
		err = nl.RouteListFilteredIter(r.netlinkFamily, routeFilter, routeFilterFlags, func(route netlink.Route) bool {
			// This copy avoids an alloc per iteration.  We leak scratchRoute
			// once but avoid leaking the function parameter.
			scratchRoute = route
			r.onIfaceSeen(route.LinkIndex)

			if !r.routeIsOurs(&scratchRoute) {
				// Not a route that we're managing.
				return true
			}

			kernKey, kernRoute := r.netlinkRouteToKernelRoute(&scratchRoute)
			if oldRoute, ok := r.kernelRoutes.Dataplane().Get(kernKey); !ok || oldRoute.Equals(kernRoute) {
				r.kernelRoutes.Dataplane().Set(kernKey, kernRoute)
			}
			seenKeys.Add(kernKey)
			r.livenessCallback()
			return true
		})
		if errors.Is(err, unix.EINTR) {
			// Expected error if the routes got updated in kernel mid-dump.
			log.WithError(err).Debug("Interrupted while listing routes.")
			seenKeys.Clear()
			continue
		}
		break
	}

	if errors.Is(err, unix.ENOENT) {
		// In strict mode, get this if the routing table doesn't exist; it'll be auto-created
		// when we add the first route so just treat it as empty.
		log.WithError(err).Debug("Routing table doesn't exist (yet). Treating as empty.")
		err = nil
	}
	if err != nil {
		return fmt.Errorf("failed to list all routes for resync: %w", err)
	}

	r.kernelRoutes.Dataplane().Iter(func(kernKey kernelRouteKey, kernRoute kernelRoute) {
		if !seenKeys.Contains(kernKey) {
			r.kernelRoutes.Dataplane().Delete(kernKey)
			r.conntrackTracker.OnDataplaneRouteDeleted(kernKey.CIDR, kernRoute.Ifindex)
		}
		r.livenessCallback()
	})

	// We're now in sync.
	r.ifacesToRescan.Clear()
	r.fullResyncNeeded = false
	resyncTimeSummary.Observe(r.time.Since(resyncStartTime).Seconds())
	return nil
}

func (r *RouteTable) SetRemoveExternalRoutes(b bool) {
	r.removeExternalRoutes = b
}

func (r *RouteTable) resyncIndividualInterfaces(nl netlinkshim.Interface) error {
	if r.ifacesToRescan.Len() == 0 {
		return nil
	}
	r.opReporter.RecordOperation(fmt.Sprint("partial-resync-routes-v", r.ipVersion))
	r.ifacesToRescan.Iter(func(ifaceName string) error {
		r.livenessCallback()
		err := r.resyncIface(nl, ifaceName)
		if err != nil {
			r.nl.MarkHandleForReopen()
			return nil
		}
		return set.RemoveItem
	})
	return nil
}

// resyncIface checks the current state of a single interface and its routes.
// It updates the interface state and the dataplane side of the route
// DeltaTracker.  Note: this method can trigger route recalculation,
// so it shouldn't be called while iterating over the DeltaTracker.  For
// example, if the interface status check discovers the interface has gone
// down, that might trigger another route to become active, mutating the
// DeltaTracker.
func (r *RouteTable) resyncIface(nl netlinkshim.Interface, ifaceName string) error {
	// We can be out of sync with the interface monitor if this
	// RouteTable was created after start-of-day.  Refresh the link.
	startTime := time.Now()
	err := r.refreshIfaceStateBestEffort(nl, ifaceName)
	if err != nil {
		r.nl.MarkHandleForReopen()
		return err
	}

	ifIndex, ok := r.ifaceIndexForName(ifaceName)
	if !ok {
		r.logCxt.Debug("Ignoring rescan of unknown interface.")
		return nil
	}

	routeFilter := &netlink.Route{
		Table:     r.tableIndex,
		LinkIndex: ifIndex,
	}
	routeFilterFlags := netlink.RT_FILTER_OIF | netlink.RT_FILTER_TABLE

	seenRoutes := set.New[kernelRouteKey]()
	for attempt := 0; attempt < routeListFilterAttempts; attempt++ {
		// Using the Iter version here saves allocating a large slice of netlink.Route,
		// which we immediately discard.
		var scratchRoute netlink.Route
		err = nl.RouteListFilteredIter(r.netlinkFamily, routeFilter, routeFilterFlags, func(route netlink.Route) bool {
			// This copy avoids an alloc per iteration.  We leak scratchRoute
			// once but avoid leaking the function parameter.
			scratchRoute = route

			if !r.routeIsOurs(&scratchRoute) {
				// Not a route that we're managing.
				return true
			}

			kernKey, kernRoute := r.netlinkRouteToKernelRoute(&scratchRoute)
			if oldRoute, ok := r.kernelRoutes.Dataplane().Get(kernKey); !ok || oldRoute.Equals(kernRoute) {
				r.kernelRoutes.Dataplane().Set(kernKey, kernRoute)
			}
			seenRoutes.Add(kernKey)
			return true
		})
		if errors.Is(err, unix.EINTR) {
			// Expected error if the routes got updated in kernel mid-dump.
			log.WithError(err).Debug("Interrupted while listing routes.")
			seenRoutes.Clear()
			continue
		}
		break
	}

	if errors.Is(err, unix.ENOENT) {
		// In strict mode, get this if the routing table doesn't exist; it'll be auto-created
		// when we add the first route so just treat it as empty.
		log.WithError(err).Debug("Routing table doesn't exist (yet). Treating as empty.")
		err = nil
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
			r.nl.MarkHandleForReopen()
			return nil
		} else {
			r.logCxt.WithError(filteredErr).WithField("iface", ifaceName).Debug(
				"Failed to list routes; interface down/gone.")
			return nil
		}
	}

	// Look for routes that the tracker says are there but are actually missing.
	for _, ifaceToRoutes := range r.ifaceToRoutes {
		for cidr := range ifaceToRoutes[ifaceName] {
			kernKey := r.routeKeyForCIDR(cidr)
			if seenRoutes.Contains(kernKey) {
				// Route still there; handled above.
				continue
			}
			desKernRoute, ok := r.kernelRoutes.Desired().Get(kernKey)
			if !ok || desKernRoute.Ifindex != ifIndex {
				// The interface we're syncing doesn't own this route
				// so the fact that it's missing is expected.
				continue
			}
			r.kernelRoutes.Dataplane().Delete(kernKey)
		}
	}
	partialResyncTimeSummary.Observe(r.time.Since(startTime).Seconds())

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
			}).Info("Spotted interface had changed index during resync.")
			r.OnIfaceStateChanged(link.Attrs().Name, oldIdx, ifacemonitor.StateNotPresent)
		}
		oldName, ok := r.ifaceIndexToName[link.Attrs().Index]
		if ok && oldName != link.Attrs().Name {
			// Interface renamed.  Simulate a deletion of the old interface.
			log.WithFields(log.Fields{
				"ifaceName": link.Attrs().Name,
				"oldName":   oldName,
				"newName":   link.Attrs().Name,
			}).Info("Spotted interface had changed name during resync.")
			r.OnIfaceStateChanged(oldName, link.Attrs().Index, ifacemonitor.StateNotPresent)
		}
		r.livenessCallback()
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
		r.livenessCallback()
	}

	// Third pass, remove any interfaces that have disappeared.
	for name := range r.ifaceNameToIndex {
		if seenNames.Contains(name) {
			continue
		}
		if debug {
			r.logCxt.WithField("ifaceName", name).Info("Spotted interface not present during full resync.  Cleaning up.")
		}
		r.OnIfaceStateChanged(name, 0, ifacemonitor.StateNotPresent)
		r.livenessCallback()
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
	return kernelRouteKey{CIDR: cidr}
}

func (r *RouteTable) routeIsOurs(route *netlink.Route) bool {
	// We're on the hot path, so it's worth avoiding the overheads of
	// WithField(s) if debug is disabled.
	logCxt := r.logCxt
	if log.IsLevelEnabled(log.DebugLevel) {
		logCxt = logCxt.WithField("route", route)
	}
	ifaceName := ""
	if routeIsSpecialNoIfRoute(route) {
		ifaceName = InterfaceNone
	} else if routeIsIPv6Bootstrap(route) {
		logCxt.Debug("Ignoring IPv6 bootstrap route, kernel manages these.")
		return false
	} else {
		ifaceName = r.ifaceIndexToName[route.LinkIndex]
		if ifaceName == "" {
			// We don't know about this interface.  Either we're racing
			// with link creation, in which case we'll hear about the
			// interface soon and work out what to do, or we're seeing
			// a route for a just-deleted interface, in which case
			// we don't care.
			logCxt.Debug("Ignoring route for unknown iface")
			return false
		}
	}

	if !r.ownershipPolicy.RouteIsOurs(ifaceName, route) {
		logCxt.Debug("Ignoring route (it doesn't belong to us).")
		return false
	}
	return true
}

func (r *RouteTable) netlinkRouteToKernelRoute(route *netlink.Route) (kernKey kernelRouteKey, kernRoute kernelRoute) {
	// Defensive; recent versions of netlink always return a CIDR, but just
	// in case that gets regressed...
	cidr := ip.CIDRFromIPNet(route.Dst)
	if route.Dst == nil {
		if r.ipVersion == 4 {
			cidr = defaultCIDRv4
		} else {
			cidr = defaultCIDRv6
		}
	}

	kernKey = kernelRouteKey{
		CIDR:     cidr,
		Priority: route.Priority,
		TOS:      route.Tos,
	}
	kernRoute = kernelRoute{
		Type:     route.Type,
		Scope:    route.Scope,
		Src:      ip.FromNetIP(route.Src),
		OnLink:   route.Flags&unix.RTNH_F_ONLINK != 0,
		Protocol: route.Protocol,
	}

	if len(route.MultiPath) > 0 {
		// Multi-path route.
		for _, nh := range route.MultiPath {
			if nh.Flags&unix.RTNH_F_ONLINK != 0 {
				kernRoute.OnLink = true
			}
			kernRoute.NextHops = append(kernRoute.NextHops, kernelNextHop{
				GW:      ip.FromNetIP(nh.Gw),
				Ifindex: nh.LinkIndex,
			})
		}
	} else {
		// Single-path route.
		kernRoute.GW = ip.FromNetIP(route.Gw)
		kernRoute.Ifindex = route.LinkIndex
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		r.logCxt.WithFields(log.Fields{
			"kernRoute": kernRoute,
			"kernKey":   kernKey,
		}).Debug("Loaded route from kernel.")
	}
	return
}

func routeIsIPv6Bootstrap(route *netlink.Route) bool {
	if route.Dst == nil {
		return false
	}
	if route.Family != netlink.FAMILY_V6 {
		return false
	}
	return ip.CIDRFromIPNet(route.Dst) == ipV6LinkLocalCIDR
}

func routeIsSpecialNoIfRoute(route *netlink.Route) bool {
	if route.LinkIndex > 1 {
		// Special routes either have 0 for the link index or 1 ('lo'),
		// depending on IP version.
		return false
	}
	if len(route.MultiPath) > 0 {
		return true
	}
	switch route.Type {
	case unix.RTN_LOCAL, unix.RTN_THROW, unix.RTN_BLACKHOLE, unix.RTN_PROHIBIT, unix.RTN_UNREACHABLE:
		return true
	}
	return false
}

func (r *RouteTable) applyUpdates(attempt int) error {
	nl, err := r.nl.Handle()
	if err != nil {
		r.logCxt.Debug("Failed to connect to netlink")
		return ConnectFailed
	}

	// First clean up any old routes.
	deletionErrs := map[kernelRouteKey]error{}
	r.kernelRoutes.PendingDeletions().Iter(func(kernKey kernelRouteKey) deltatracker.IterAction {
		r.livenessCallback()
		kernRoute, _ := r.kernelRoutes.PendingDeletions().Get(kernKey)
		if r.ifaceInGracePeriod(kernRoute.Ifindex) {
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
		r.conntrackTracker.OnDataplaneRouteDeleted(kernKey.CIDR, kernRoute.Ifindex)

		// Route is gone, clean up the dataplane side of the tracker.
		r.logCxt.WithField("route", kernKey).Debug("Deleted route.")
		return deltatracker.IterActionUpdateDataplane
	})

	// Now do a first pass of the routes that we want to create/update and
	// trigger any necessary conntrack cleanups for moved routes.
	r.kernelRoutes.PendingUpdates().Iter(func(kernKey kernelRouteKey, kernRoute kernelRoute) deltatracker.IterAction {
		r.livenessCallback()
		cidr := kernKey.CIDR
		dataplaneRoute, dataplaneExists := r.kernelRoutes.Dataplane().Get(kernKey)
		if dataplaneExists && r.conntrackTracker.CIDRNeedsEarlyCleanup(cidr, dataplaneRoute.Ifindex) {
			err := r.deleteRoute(nl, kernKey)
			if err != nil {
				deletionErrs[kernKey] = err
				return deltatracker.IterActionNoOp
			}
			// This will queue the route for conntrack cleanup.
			r.conntrackTracker.OnDataplaneRouteDeleted(kernKey.CIDR, dataplaneRoute.Ifindex)
		}
		return deltatracker.IterActionNoOp
	})

	// Start any deferred conntrack cleanups and reset the tracking for next
	// time.
	r.conntrackTracker.StartConntrackCleanupAndReset()

	updateErrs := map[kernelRouteKey]error{}
	r.kernelRoutes.PendingUpdates().Iter(func(kernKey kernelRouteKey, kRoute kernelRoute) deltatracker.IterAction {
		r.livenessCallback()
		dst := kernKey.CIDR.ToIPNet()
		flags := 0
		if kRoute.OnLink {
			flags = unix.RTNH_F_ONLINK
		}

		// In case we're moving a route, wait for the cleanup to finish.
		r.conntrackTracker.WaitForPendingDeletion(kernKey.CIDR)

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
		for _, nh := range kRoute.NextHops {
			nlRoute.MultiPath = append(nlRoute.MultiPath, &netlink.NexthopInfo{
				LinkIndex: nh.Ifindex,
				Gw:        nh.GWAsNetIP(),
				Flags:     flags,
			})
		}
		r.logCxt.WithFields(log.Fields{
			"nlRoute":  nlRoute,
			"ourKey":   kernKey,
			"ourRoute": kRoute,
		}).Debug("Replacing route")
		err := nl.RouteReplace(nlRoute)
		if err != nil {
			name, ok := r.ifaceNameForIndex(kRoute.Ifindex)
			if ok {
				err = r.filterErrorByIfaceState(
					name,
					err,
					err,
					attempt == 0,
				)

				if errors.Is(err, IfaceDown) || errors.Is(err, IfaceNotPresent) {
					// Very common race: the interface was taken down/deleted
					// by the CNI plugin while we were trying to update it.
					// Mark for a lazy rescan so that we won't try to program
					// this route again next time (unless the interface shows
					// up).
					r.ifacesToRescan.Add(name)
					return deltatracker.IterActionNoOp
				}
				err = fmt.Errorf("%v(%s): %w", kRoute, name, err)
			}

			updateErrs[kernKey] = err
			return deltatracker.IterActionNoOp
		}

		// Route is updated, clean up the dataplane side of the tracker.
		return deltatracker.IterActionUpdateDataplane
	})

	arpErrs := map[string]error{}
	for ifaceName, addrToMAC := range r.pendingARPs {
		// Add static ARP entries (for workload endpoints).  This may have been
		// needed at one point but it no longer seems to be required.  Leaving
		// it here for two reasons: (1) there may be an obscure scenario where
		// it is needed. (2) we have tests that monitor netlink, and they break
		// if it is removed because they see the ARP traffic.
		ifaceIdx, ok := r.ifaceIndexForName(ifaceName)
		if !ok {
			// Asked to add ARP entries but the interface isn't known (yet).
			// Leave them pending.  We'll clean up the pending set if the
			// datastore stops asking us to add ARP entries for this interface.
			continue
		}
		for addr, mac := range addrToMAC {
			r.livenessCallback()
			err := r.addStaticARPEntry(nl, addr, mac, ifaceIdx)
			if err != nil {
				err = r.filterErrorByIfaceState(
					ifaceName,
					err,
					err,
					attempt == 0,
				)

				if errors.Is(err, IfaceDown) || errors.Is(err, IfaceNotPresent) {
					// Very common race: the interface was taken down/deleted
					// by the CNI plugin while we were trying to update it.
					// Mark for a lazy rescan so that we won't try to program
					// this route again next time (unless the interface shows
					// up).
					r.ifacesToRescan.Add(ifaceName)
					err = nil
				}
			}
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

	err = nil
	if len(deletionErrs) > 0 {
		r.logCxt.WithField("errors", formatErrMap(deletionErrs)).Warn(
			"Encountered some errors when trying to delete old routes.")
		err = UpdateFailed
	}
	if len(updateErrs) > 0 {
		r.logCxt.WithField("errors", formatErrMap(updateErrs)).Warn(
			"Encountered some errors when trying to update routes.  Will retry.")
		err = UpdateFailed
	}
	if len(arpErrs) > 0 {
		r.logCxt.WithField("errors", formatErrMap(arpErrs)).Warn(
			"Encountered some errors when trying to add static ARP entries.  Will retry.")
		err = UpdateFailed
	}

	return err
}

// formatErrMap formats a map of errors as a string, ensuring the error
// messages are included in the output.
func formatErrMap[K comparable](errs map[K]error) string {
	parts := make([]string, 0, len(errs))
	for k, v := range errs {
		parts = append(parts, fmt.Sprintf("%v: %s", k, v.Error()))
	}
	return strings.Join(parts, ", ")
}

func (r *RouteTable) ifaceInGracePeriod(ifindex int) bool {
	graceInf, ok := r.ifaceIndexToGraceInfo[ifindex]
	if !ok {
		return false
	}
	if graceInf.GraceExpired {
		return false
	}
	name, ok := r.ifaceNameForIndex(ifindex)
	if !ok {
		return false
	}
	if !r.ownershipPolicy.IfaceShouldHaveGracePeriod(name) {
		return false
	}
	return r.time.Since(graceInf.FirstSeen) < r.routeCleanupGracePeriod
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
		Priority: kernKey.Priority,

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
		logCxt.Debug("No interface on route.")
		return defaultErr
	}

	if isNotFoundError(currentErr) {
		// Current error already tells us that the link was not present.  If we re-check
		// the status in this case, we open a race where the interface gets created and
		// we log an error when we're about to re-trigger programming anyway.
		logCxt.Debug("Interface doesn't exist, perhaps workload is being torn down?")
		return IfaceNotPresent
	}

	if errors.Is(currentErr, syscall.ENETDOWN) {
		// Another clear error: interface is down.
		logCxt.Debug("Interface down, perhaps workload is being torn down?")
		return IfaceDown
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
					"Failed to access interface but it appears to be up?")
			}
			return defaultErr
		} else {
			// Special case: Link exists and it's down.  Assume that's the problem.
			logCxt.WithField("link", link).Debug("Interface is down")
			return IfaceDown
		}
	} else if isNotFoundError(err) {
		// Special case: Link no longer exists.
		logCxt.Info("Interface was deleted during operation, filtering error")
		return IfaceNotPresent
	} else {
		// Failed to list routes, then failed to check if interface exists.
		logCxt.WithError(err).Error("Failed to access interface after a failure")
		return defaultErr
	}
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	var lnf netlink.LinkNotFoundError
	if errors.As(err, &lnf) {
		return true
	}
	if errors.Is(err, unix.ENOENT) {
		return true
	}
	if strings.Contains(err.Error(), "not found") {
		return true
	}
	return false
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

func (r *RouteTable) updateGauges() {
	r.gaugeNumRoutes.Set(float64(r.kernelRoutes.Desired().Len()))
	r.gaugeNumIfaces.Set(float64(len(r.ifaceIndexToName)))
}

func (r *RouteTable) checkTargets(ifaceName string, targets ...Target) {
	for _, t := range targets {
		if len(t.MultiPath) > 0 {
			if t.GW != nil || ifaceName != InterfaceNone {
				log.Panic("MultiPath routes should have InterfaceNone and no GW")
			}
			r.haveMultiPathRoutes = true
			for _, nh := range t.MultiPath {
				if nh.Gw == nil {
					log.Panic("MultiPath route should have GW")
				}
				if nh.IfaceName == "" || nh.IfaceName == InterfaceNone {
					log.Panic("MultiPath route should have interface name")
				}
			}
		}
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
	Src      ip.Addr
	Protocol netlink.RouteProtocol
	OnLink   bool

	// Either GW and Ifindex should be specified (for a gateway route) or
	// NextHops should be specified (for a multi-path route).
	GW      ip.Addr
	Ifindex int

	NextHops []kernelNextHop
}

func (r kernelRoute) IsZero() bool {
	var zero kernelRoute
	return r.Equals(zero)
}

func (r kernelRoute) Equals(b kernelRoute) bool {
	if r.Type != b.Type {
		return false
	}
	if r.Scope != b.Scope {
		return false
	}
	if r.Src != b.Src {
		return false
	}
	if r.Protocol != b.Protocol {
		return false
	}
	if r.OnLink != b.OnLink {
		return false
	}
	if r.GW != b.GW {
		return false
	}
	if r.Ifindex != b.Ifindex {
		return false
	}
	if len(r.NextHops) != len(b.NextHops) {
		return false
	}
	for i := range r.NextHops {
		if r.NextHops[i].GW != b.NextHops[i].GW {
			return false
		}
		if r.NextHops[i].Ifindex != b.NextHops[i].Ifindex {
			return false
		}
	}
	return true
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
	if r.IsZero() {
		return "<none>"
	}
	srcStr := "<nil>"
	if r.Src != nil {
		srcStr = r.Src.String()
	}

	nextHopPart := ""
	if len(r.NextHops) > 0 {
		nextHopPart = fmt.Sprintf("NextHops=%v", r.NextHops)
	} else {
		gwStr := "<nil>"
		if r.GW != nil {
			gwStr = r.GW.String()
		}
		nextHopPart = fmt.Sprintf("GW=%s, Ifindex=%d", gwStr, r.Ifindex)
	}

	return fmt.Sprintf("kernelRoute{Type=%d, Scope=%d, Src=%s, Protocol=%v, OnLink=%v, %s}",
		r.Type, r.Scope, srcStr, r.Protocol, r.OnLink, nextHopPart)
}

type kernelNextHop struct {
	GW      ip.Addr
	Ifindex int
}

func (h kernelNextHop) GWAsNetIP() net.IP {
	if h.GW == nil {
		return nil
	}
	return h.GW.AsNetIP()
}
