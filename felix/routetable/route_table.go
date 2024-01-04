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

	// Interface update tracking.
	fullResyncNeeded   bool
	ifacesToRescan     set.Set[string]
	ifacePrefixRegexp  *regexp.Regexp
	includeNoInterface bool

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

	ifaceNameToFirstSeen map[string]time.Time
	ifaceNameToIndex     map[string]int
	ifaceIndexToName     map[int]string

	pendingConntrackCleanups map[ip.Addr]chan struct{}

	nl *handlemgr.HandleManager

	opReporter       logutils.OpRecorder
	livenessCallback func()

	// The route deletion grace period.
	routeCleanupGracePeriod time.Duration
	featureDetector         environment.FeatureDetectorIface

	// Testing shims, swapped with mock versions for UT
	addStaticARPEntry func(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error
	conntrack         conntrackIface
	time              timeshim.Interface
}

type RouteTableOpt func(table *RouteTable)

func WithLivenessCB(cb func()) RouteTableOpt {
	return func(table *RouteTable) {
		table.livenessCallback = cb
	}
}

func WithRouteCleanupGracePeriod(routeCleanupGracePeriod time.Duration) RouteTableOpt {
	return func(table *RouteTable) {
		// TODO route grace period
		table.routeCleanupGracePeriod = routeCleanupGracePeriod
	}
}

func WithRouteMetric(metric RouteMetric) RouteTableOpt {
	return func(table *RouteTable) {
		table.routeMetric = metric
	}
}

func New(
	interfaceRegexes []string,
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
	return NewWithShims(
		interfaceRegexes,
		ipVersion,
		netlinkshim.NewRealNetlink,
		netlinkTimeout,
		addStaticARPEntry, // FIXME add static ARP entries.
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
		logCxt:        logCxt,
		ipVersion:     ipVersion,
		netlinkFamily: family,
		tableIndex:    tableIndex,

		deviceRouteSourceAddress: ip.FromNetIP(deviceRouteSourceAddress), // FIXME use ip.Addr as input
		deviceRouteProtocol:      deviceRouteProtocol,
		removeExternalRoutes:     removeExternalRoutes,

		fullResyncNeeded:   true,
		ifacesToRescan:     set.New[string](),
		ifacePrefixRegexp:  ifacePrefixRegexp,
		includeNoInterface: includeNoOIF,

		ifaceToRoutes: map[string]map[ip.CIDR]Target{},
		cidrToIfaces:  map[ip.CIDR]set.Set[string]{},

		kernelRoutes: deltatracker.New[kernelRouteKey, kernelRoute](),

		ifaceNameToFirstSeen: map[string]time.Time{},
		ifaceNameToIndex:     map[string]int{},
		ifaceIndexToName:     map[int]string{},

		pendingConntrackCleanups: map[ip.Addr]chan struct{}{},

		opReporter:       opReporter,
		livenessCallback: func() {},
		nl:               handlemgr.NewHandleManager(featureDetector, handlemgr.WithNewHandleOverride(newNetlinkHandle), handlemgr.WithSocketTimeout(netlinkTimeout)),
		featureDetector:  featureDetector,

		addStaticARPEntry: addStaticARPEntry,
		conntrack:         conntrack,
		time:              timeShim,
	}

	for _, o := range opts {
		o(rt)
	}

	return rt
}

func (r *RouteTable) OnIfaceStateChanged(ifaceName string, ifIndex int, state ifacemonitor.State) {
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	if r.ifacePrefixRegexp == nil || !r.ifacePrefixRegexp.MatchString(ifaceName) {
		logCxt.Trace("Ignoring interface state change, not an interface managed by this routetable.")
		return
	}

	// There are a couple of interesting corner cases:
	//
	// * Interface gets renamed: same ifindex, new name.  The interface
	//   monitor deals with that by sending us a deletion for the old
	//   name, then a creation for the new name.
	// * Interface gets recreated: same name, new ifindex.  We should
	//   see a deletion and then an add.

	recheckInterfaceRoutes := false
	if state == ifacemonitor.StateNotPresent {
		// Interface deleted, clean up.
		oldIndex := r.ifaceNameToIndex[ifaceName]
		delete(r.ifaceIndexToName, oldIndex)
		delete(r.ifaceNameToFirstSeen, ifaceName)
		delete(r.ifaceNameToIndex, ifaceName)
		r.ifacesToRescan.Discard(ifaceName)

		// This interface may have had some active routes that were shadowing
		// routes from another interface.  Make sure we rescan.
		recheckInterfaceRoutes = true
	} else {
		// Interface exists, record its details.
		r.onIfaceSeen(ifaceName)
		oldIfIndex, ok := r.ifaceNameToIndex[ifaceName]
		if ok && oldIfIndex != ifIndex {
			// Interface renumbered.  For example, deleted and then recreated
			// with same name.  Clean up old number.
			delete(r.ifaceIndexToName, oldIfIndex)

			// The interface index is part of the route conflict tie-breaker,
			// so we need to check if the winner has changed.
			recheckInterfaceRoutes = true
		} else if !ok {
			// New interface.
			recheckInterfaceRoutes = true
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
		recheckInterfaceRoutes = true
	}

	if recheckInterfaceRoutes {
		r.recheckRouteOwnershipsByIface(ifaceName)
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

// recheckRouteOwnershipsByIface reruns conflict resolution for all
// the interface's routes.
func (r *RouteTable) recheckRouteOwnershipsByIface(name string) {
	for cidr := range r.ifaceToRoutes[name] {
		r.recalculateDesiredKernelRoute(cidr)
	}
}

func (r *RouteTable) lookupIfaceIndex(ifaceName string) (int, bool) {
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

	// Start with a blank slate.  The delta-tracker will efficiently prevent
	// dataplane churn if we add an identical route back again.
	r.kernelRoutes.Desired().Delete(kernKey)

	ifaces := r.cidrToIfaces[cidr]
	if ifaces == nil {
		// Keep the blank slate!
		r.logCxt.WithFields(log.Fields{
			"cidr":     cidr,
			"oldRoute": oldDesiredRoute,
		}).Debug("CIDR no longer has associated routes.")
		return
	}

	// In case of conflicts (more than one route with the same CIDR), pick
	// one deterministically so that we don't churn the dataplane.
	var bestTarget Target
	bestIface := ""
	bestIfaceIdx := -1
	ifaces.Iter(func(ifaceName string) error {
		ifIndex, ok := r.lookupIfaceIndex(ifaceName)
		if !ok {
			r.logCxt.Debug("Skipping route for missing interface.")
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
		r.logCxt.WithField("cidr", cidr).Debug("No valid route for this CIDR (all candidate routes missing iface index).")
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
		OnLink:   bestTarget.Flags()&unix.RTNH_F_ONLINK != 0, // FIXME handle (any?) other flags?
		Protocol: r.deviceRouteProtocol,
	}
	r.logCxt.WithFields(log.Fields{
		"cidr":     cidr,
		"oldRoute": oldDesiredRoute,
		"newRoute": kernRoute,
		"iface":    bestIface,
	}).Debug("Calculated kernel route.")
	r.kernelRoutes.Desired().Set(kernKey, kernRoute)
}

func (r *RouteTable) QueueResync() {
	r.logCxt.Debug("Queueing a resync of routing table.")
	r.fullResyncNeeded = true
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

	if r.fullResyncNeeded {
		return r.doFullResync(nl)
	}

	// Do any partial per-interface resyncs.
	return r.resyncIndividualInterfaces(nl)
}

func (r *RouteTable) doFullResync(nl netlinkshim.Interface) error {
	r.opReporter.RecordOperation(fmt.Sprint("resync-routes-v", r.ipVersion))
	resyncStartTime := time.Now()

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
	} else if err != nil {
		return fmt.Errorf("failed to list all routes for resync: %w", err)
	}

	err = r.kernelRoutes.Dataplane().ReplaceAllIter(func(f func(k kernelRouteKey, v kernelRoute)) error {
		for _, route := range allRoutes {
			kernKey, kernRoute, ok := r.netlinkRouteToKernelRoute(route)
			if !ok {
				// Not a route that we're managing.
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

	// We're now in sync.
	r.ifacesToRescan.Clear()
	r.fullResyncNeeded = false
	listAllRoutesTime.Observe(r.time.Since(resyncStartTime).Seconds())
	return nil
}

func (r *RouteTable) resyncIndividualInterfaces(nl netlinkshim.Interface) error {
	r.ifacesToRescan.Iter(func(ifaceName string) error {
		ifIndex, ok := r.lookupIfaceIndex(ifaceName)
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
				// Not a route that we're managing, so we don't want it to
				// be a candidate for us to delete.
				continue
			}
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
	if routeIsSpecialNoIfRoute(route) {
		if !r.includeNoInterface {
			logCxt.Debug("Ignoring no-interface route (we're not managing them)")
			return
		}
	} else if routeIsIPv6Bootstrap(route) {
		logCxt.Debug("Ignoring IPv6 bootstrap route, kernel manages these.")
		return
	} else if r.ifacePrefixRegexp == nil {
		logCxt.Debug("Ignoring normal route; we're only managing special routes.")
		return
	} else {
		ifaceName := r.ifaceIndexToName[route.LinkIndex]
		if ifaceName == "" {
			// We don't know about this interface.  Either we're racing
			// with link creation, in which case we'll hear about the
			// interface soon and work out what to do, or we're seeing
			// a route for a just-deleted interface, in which case
			// we don't care.
			logCxt.Debug("Ignoring route for unknown iface")
			return
		}
		if !r.ifacePrefixRegexp.MatchString(ifaceName) {
			if debug {
				logCxt.WithField("ifaceName", ifaceName).Debug("Ignoring route for non-Calico interface.")
			}
			return
		}
	}
	if !r.removeExternalRoutes && route.Protocol != r.deviceRouteProtocol {
		logCxt.Debug("Ignoring route (not our protocol).")
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
		// Any deleted route should have the corresponding conntrack entries removed.
		r.startConntrackDeletion(kernKey.CIDR.Addr())
		dst := kernKey.CIDR.ToIPNet()

		// Template route for deletion.  The family, table, TOS, Priority uniquely
		// identify the route, but we also need to set some fields to their "wildcard"
		// values (found via code reading the kernel and running "ip route del" under
		// strace).
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
		if err != nil {
			deletionErrs[kernKey] = err
			return deltatracker.IterActionNoOp
		}
		// Route is gone, clean up the dataplane side of the tracker.
		r.logCxt.WithField("route", kernKey).Debug("Deleted route.")
		return deltatracker.IterActionUpdateDataplane
	})
	if len(deletionErrs) > 0 {
		log.WithField("errors", deletionErrs).Warn(
			"Encountered some errors when trying to delete old routes.")
	}

	updateErrs := map[kernelRouteKey]error{}
	r.kernelRoutes.PendingUpdates().Iter(func(kernKey kernelRouteKey, kRoute kernelRoute) deltatracker.IterAction {
		dst := kernKey.CIDR.ToIPNet()
		flags := 0
		if kRoute.OnLink {
			flags = unix.RTNH_F_ONLINK
		}

		r.waitForPendingConntrackDeletion(kernKey.CIDR.Addr())

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
	// TODO filter out interfaces that are gone
	if len(updateErrs) > 0 {
		log.WithField("errors", updateErrs).Warn(
			"Encountered some errors when trying to update routes.")
	}

	return nil // TODO
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
