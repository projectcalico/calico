// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.
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
	"net"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/conntrack"
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/libcalico-go/lib/set"
)

const (
	cleanupGracePeriod = 10 * time.Second
	maxConnFailures    = 3
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

	listIfaceTime = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_route_table_list_seconds",
		Help: "Time taken to list all the interfaces during a resync.",
	})
	perIfaceSyncTime = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_route_table_per_iface_sync_seconds",
		Help: "Time taken to sync each interface",
	})
)

func init() {
	prometheus.MustRegister(listIfaceTime, perIfaceSyncTime)
}

type Target struct {
	CIDR    ip.CIDR
	DestMAC net.HardwareAddr
}

type RouteTable struct {
	logCxt *log.Entry

	ipVersion      uint8
	netlinkFamily  int
	netlinkTimeout time.Duration
	// numConsistentNetlinkFailures counts the number of repeated netlink connection failures.
	// reset on successful connection.
	numConsistentNetlinkFailures int
	// Current netlink handle, or nil if we need to reconnect.
	cachedNetlinkHandle HandleIface

	dirtyIfaces set.Set

	ifacePrefixes     set.Set
	ifacePrefixRegexp *regexp.Regexp

	ifaceNameToTargets        map[string][]Target
	ifaceNameToFirstSeen      map[string]time.Time
	pendingIfaceNameToTargets map[string][]Target

	pendingConntrackCleanups map[ip.Addr]chan struct{}

	inSync bool

	// Testing shims, swapped with mock versions for UT

	newNetlinkHandle  func() (HandleIface, error)
	addStaticARPEntry func(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error
	conntrack         conntrackIface
	time              timeIface
}

func New(interfacePrefixes []string, ipVersion uint8, netlinkTimeout time.Duration) *RouteTable {
	return NewWithShims(
		interfacePrefixes,
		ipVersion,
		newNetlinkHandle,
		netlinkTimeout,
		addStaticARPEntry,
		conntrack.New(),
		realTime{},
	)
}

// NewWithShims is a test constructor, which allows netlink, arp and time to be replaced by shims.
func NewWithShims(
	interfacePrefixes []string,
	ipVersion uint8,
	newNetlinkHandle func() (HandleIface, error),
	netlinkTimeout time.Duration,
	addStaticARPEntry func(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error,
	conntrack conntrackIface,
	timeShim timeIface,
) *RouteTable {
	prefixSet := set.New()
	regexpParts := []string{}
	for _, prefix := range interfacePrefixes {
		prefixSet.Add(prefix)
		regexpParts = append(regexpParts, "^"+prefix+".*")
	}

	ifaceNamePattern := strings.Join(regexpParts, "|")
	log.WithField("regex", ifaceNamePattern).Info("Calculated interface name regexp")

	family := netlink.FAMILY_V4
	if ipVersion == 6 {
		family = netlink.FAMILY_V6
	} else if ipVersion != 4 {
		log.WithField("ipVersion", ipVersion).Panic("Unknown IP version")
	}

	return &RouteTable{
		logCxt: log.WithFields(log.Fields{
			"ipVersion": ipVersion,
		}),
		ipVersion:                 ipVersion,
		netlinkFamily:             family,
		ifacePrefixes:             prefixSet,
		ifacePrefixRegexp:         regexp.MustCompile(ifaceNamePattern),
		ifaceNameToTargets:        map[string][]Target{},
		ifaceNameToFirstSeen:      map[string]time.Time{},
		pendingIfaceNameToTargets: map[string][]Target{},
		dirtyIfaces:               set.New(),
		pendingConntrackCleanups:  map[ip.Addr]chan struct{}{},
		newNetlinkHandle:          newNetlinkHandle,
		netlinkTimeout:            netlinkTimeout,
		addStaticARPEntry:         addStaticARPEntry,
		conntrack:                 conntrack,
		time:                      timeShim,
	}
}

func (r *RouteTable) OnIfaceStateChanged(ifaceName string, state ifacemonitor.State) {
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	if !r.ifacePrefixRegexp.MatchString(ifaceName) {
		logCxt.Debug("Ignoring interface state change, not a Calico interface.")
		return
	}
	if state == ifacemonitor.StateUp {
		logCxt.Debug("Interface up, marking for route sync")
		r.dirtyIfaces.Add(ifaceName)
		r.onIfaceSeen(ifaceName)
	}
}

func (r *RouteTable) onIfaceSeen(ifaceName string) {
	if _, ok := r.ifaceNameToFirstSeen[ifaceName]; ok {
		return
	}
	r.ifaceNameToFirstSeen[ifaceName] = r.time.Now()
}

func (r *RouteTable) SetRoutes(ifaceName string, targets []Target) {
	r.pendingIfaceNameToTargets[ifaceName] = targets
	r.dirtyIfaces.Add(ifaceName)
}

func (r *RouteTable) QueueResync() {
	r.logCxt.Info("Queueing a resync of routing table.")
	r.inSync = false
}

func (r *RouteTable) getNetlinkHandle() (HandleIface, error) {
	if r.cachedNetlinkHandle == nil {
		if r.numConsistentNetlinkFailures >= maxConnFailures {
			log.WithField("numFailures", r.numConsistentNetlinkFailures).Panic(
				"Repeatedly failed to connect to netlink.")
		}
		log.Info("Trying to connect to netlink")
		nlHandle, err := r.newNetlinkHandle()
		if err != nil {
			r.numConsistentNetlinkFailures++
			log.WithError(err).WithField("numFailures", r.numConsistentNetlinkFailures).Error(
				"Failed to connect to netlink")
			return nil, err
		}
		err = nlHandle.SetSocketTimeout(r.netlinkTimeout)
		if err != nil {
			r.numConsistentNetlinkFailures++
			log.WithError(err).WithField("numFailures", r.numConsistentNetlinkFailures).Error(
				"Failed to set netlink timeout")
			nlHandle.Delete()
			return nil, err
		}
		r.cachedNetlinkHandle = nlHandle
	}
	if r.numConsistentNetlinkFailures > 0 {
		log.WithField("numFailures", r.numConsistentNetlinkFailures).Info(
			"Connected to netlink after previous failures.")
		r.numConsistentNetlinkFailures = 0
	}
	return r.cachedNetlinkHandle, nil
}

func (r *RouteTable) closeNetlinkHandle() {
	if r.cachedNetlinkHandle == nil {
		return
	}
	r.cachedNetlinkHandle.Delete()
	r.cachedNetlinkHandle = nil
}

func (r *RouteTable) Apply() error {
	if !r.inSync {
		listStartTime := time.Now()

		nl, err := r.getNetlinkHandle()
		if err != nil {
			r.logCxt.WithError(err).Error("Failed to connect to netlink, retrying...")
			return ConnectFailed
		}
		links, err := nl.LinkList()
		if err != nil {
			r.logCxt.WithError(err).Error("Failed to list interfaces, retrying...")
			r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.
			return ListFailed
		}
		// Clear the dirty set; there's no point trying to update non-existent interfaces.
		r.dirtyIfaces = set.New()
		for _, link := range links {
			attrs := link.Attrs()
			if attrs == nil {
				continue
			}
			ifaceName := attrs.Name
			if r.ifacePrefixRegexp.MatchString(ifaceName) {
				r.logCxt.WithField("ifaceName", ifaceName).Debug(
					"Resync: found calico-owned interface")
				r.dirtyIfaces.Add(ifaceName)
				r.onIfaceSeen(ifaceName)
			}
		}
		// Clean up first-seen timestamps for old interfaces.
		// Resyncs happen periodically, so the amount of memory leaked to old
		// first seen timestamps is small.
		for name, firstSeen := range r.ifaceNameToFirstSeen {
			if r.dirtyIfaces.Contains(name) {
				// Interface still present.
				continue
			}
			if time.Since(firstSeen) < cleanupGracePeriod {
				// Interface first seen recently.
				continue
			}
			log.WithField("ifaceName", name).Debug(
				"Cleaning up timestamp for removed interface.")
			delete(r.ifaceNameToFirstSeen, name)
		}
		r.inSync = true

		listIfaceTime.Observe(time.Since(listStartTime).Seconds())
	}

	graceIfaces := 0
	r.dirtyIfaces.Iter(func(item interface{}) error {
		retries := 2
		ifaceName := item.(string)
		logCxt := r.logCxt.WithField("ifaceName", ifaceName)
		for retries > 0 {
			err := r.syncRoutesForLink(ifaceName)
			if err == IfaceNotPresent {
				logCxt.Info("Interface missing, will retry if it appears.")
				break
			} else if err == IfaceDown {
				logCxt.Info("Interface down, will retry if it goes up.")
				break
			} else if err == IfaceGrace {
				logCxt.Info("Interface in cleanup grace period, will retry after.")
				graceIfaces++
				return nil
			} else if err != nil {
				logCxt.WithError(err).Warn("Failed to syncronise routes.")
				retries--
				continue
			}
			logCxt.Debug("Synchronised routes on interface")
			break
		}
		if retries == 0 {
			// The interface might be flapping or being deleted.
			logCxt.Warn("Failed to sync routes to interface even after retries. " +
				"Leaving it dirty.")
			return nil
		}
		return set.RemoveItem
	})

	r.cleanUpPendingConntrackDeletions()

	// Don't return a failure if there are only interfaces in the cleanup grace period.
	// They'll be retried on the next invocation (the route refresh timer), and we mustn't
	// count them as Sync Errors.
	if r.dirtyIfaces.Len() > graceIfaces {
		r.logCxt.Warn("Some interfaces still out-of sync.")
		r.inSync = false
		return UpdateFailed
	}

	return nil
}

func (r *RouteTable) syncRoutesForLink(ifaceName string) error {
	startTime := time.Now()
	defer func() {
		perIfaceSyncTime.Observe(time.Since(startTime).Seconds())
	}()
	logCxt := r.logCxt.WithField("ifaceName", ifaceName)
	logCxt.Debug("Syncing interface routes")

	// In order to allow Calico to run without Felix in an emergency, the CNI plugin pre-adds
	// the route to the interface.  To avoid flapping the route when Felix sees the interface
	// before learning about the endpoint, we give each interface a grace period after we first
	// see it before we remove routes that we're not expecting.  Check whether the grace period
	// applies to this interface.
	inGracePeriod := r.time.Since(r.ifaceNameToFirstSeen[ifaceName]) < cleanupGracePeriod
	leaveDirty := false

	// If this is a modify or delete, grab a copy of the existing targets so we can clean up
	// conntrack entries even if the routes have been removed.  We'll remove any still-required
	// CIDRs from this set below.  We don't apply the grace period to this calculation because
	// it only removes routes that the datamodel previously said were there and then were
	// removed.  In that case, we know we're up to date.
	oldCIDRs := set.New()
	if updatedTargets, ok := r.pendingIfaceNameToTargets[ifaceName]; ok {
		logCxt.Debug("Have updated targets.")
		oldTargets := r.ifaceNameToTargets[ifaceName]
		if updatedTargets == nil {
			delete(r.ifaceNameToTargets, ifaceName)
		} else {
			r.ifaceNameToTargets[ifaceName] = updatedTargets
		}
		for _, target := range oldTargets {
			oldCIDRs.Add(target.CIDR)
		}
		delete(r.pendingIfaceNameToTargets, ifaceName)
	}

	expectedTargets := r.ifaceNameToTargets[ifaceName]
	expectedCIDRs := set.New()
	for _, t := range expectedTargets {
		expectedCIDRs.Add(t.CIDR)
		oldCIDRs.Discard(t.CIDR)
	}
	if r.ipVersion == 6 {
		expectedCIDRs.Add(ipV6LinkLocalCIDR)
		oldCIDRs.Discard(ipV6LinkLocalCIDR)
	}

	// The code below may add some more CIDRs to clean up before it is done, make sure we
	// remove conntrack entries in any case.
	defer oldCIDRs.Iter(func(item interface{}) error {
		// Remove and conntrack entries that should no longer be there.
		dest := item.(ip.CIDR)
		r.startConntrackDeletion(dest.Addr())
		return nil
	})

	// Try to get the link.  This may fail if it's been deleted out from under us.
	nl, err := r.getNetlinkHandle()
	if err != nil {
		r.logCxt.WithError(err).Error("Failed to connect to netlink, retrying...")
		return ConnectFailed
	}
	link, err := nl.LinkByName(ifaceName)
	if err != nil {
		// Filter the error so that we don't spam errors if the interface is being torn
		// down.
		filteredErr := r.filterErrorByIfaceState(ifaceName, err, GetFailed)
		if filteredErr == GetFailed {
			logCxt.WithError(err).Error("Failed to get interface.")
			r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.
		} else {
			logCxt.WithError(err).Info("Failed to get interface; it's down/gone.")
		}
		return filteredErr
	}

	// Got the link; try to sync its routes.  Note: We used to check if the interface
	// was oper down before we tried to do the sync but that prevented us from removing
	// routes from an interface in some corner cases (such as being admin up but oper
	// down).
	linkAttrs := link.Attrs()
	oldRoutes, err := nl.RouteList(link, r.netlinkFamily)
	if err != nil {
		// Filter the error so that we don't spam errors if the interface is being torn
		// down.
		filteredErr := r.filterErrorByIfaceState(ifaceName, err, ListFailed)
		if filteredErr == ListFailed {
			logCxt.WithError(err).Error("Error listing routes")
			r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.
		} else {
			logCxt.WithError(err).Info("Failed to list routes; interface down/gone.")
		}
		return filteredErr
	}

	seenCIDRs := set.New()
	updatesFailed := false
	for _, route := range oldRoutes {
		var dest ip.CIDR
		if route.Dst != nil {
			dest = ip.CIDRFromIPNet(route.Dst)
		}
		logCxt := logCxt.WithField("dest", dest)
		seenCIDRs.Add(dest)
		if expectedCIDRs.Contains(dest) {
			logCxt.Debug("Syncing routes: Found expected route.")
			continue
		}
		if inGracePeriod {
			// Don't remove routes from interfaces created recently.
			logCxt.Info("Syncing routes: found unexpected route; ignoring due to grace period.")
			leaveDirty = true
			continue
		}
		logCxt.Info("Syncing routes: removing old route.")
		if err := nl.RouteDel(&route); err != nil {
			// Probably a race with the interface being deleted.
			logCxt.WithError(err).Info(
				"Route deletion failed, assuming someone got there first.")
			updatesFailed = true
		}
		if dest != nil {
			// Collect any old route CIDRs that we find in the dataplane so we
			// can remove their conntrack entries later.
			oldCIDRs.Add(dest)
		}
	}
	for _, target := range expectedTargets {
		cidr := target.CIDR
		if !seenCIDRs.Contains(cidr) {
			logCxt := logCxt.WithField("targetCIDR", target.CIDR)
			logCxt.Info("Syncing routes: adding new route.")
			ipNet := cidr.ToIPNet()
			route := netlink.Route{
				LinkIndex: linkAttrs.Index,
				Dst:       &ipNet,
				Type:      syscall.RTN_UNICAST,
				Protocol:  syscall.RTPROT_BOOT,
				Scope:     netlink.SCOPE_LINK,
			}
			// In case this IP is being re-used, wait for any previous conntrack entry
			// to be cleaned up.  (No-op if there are no pending deletes.)
			r.waitForPendingConntrackDeletion(cidr.Addr())
			if err := nl.RouteAdd(&route); err != nil {
				logCxt.WithError(err).Warn("Failed to add route")
				updatesFailed = true
			}
		}
		if r.ipVersion == 4 && target.DestMAC != nil {
			// TODO(smc) clean up/sync old ARP entries
			err := r.addStaticARPEntry(cidr, target.DestMAC, ifaceName)
			if err != nil {
				logCxt.WithError(err).Warn("Failed to set ARP entry")
				updatesFailed = true
			}
		}
	}

	if updatesFailed {
		r.closeNetlinkHandle() // Defensive: force a netlink reconnection next time.

		// Recheck whether the interface exists so we don't produce spammy logs during
		// interface removal.
		return r.filterErrorByIfaceState(ifaceName, UpdateFailed, UpdateFailed)
	}

	if leaveDirty {
		// Superfluous routes on a recently created interface.  We'll recheck later.
		return IfaceGrace
	}

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
func (r *RouteTable) filterErrorByIfaceState(ifaceName string, currentErr, defaultErr error) error {
	logCxt := r.logCxt.WithFields(log.Fields{"ifaceName": ifaceName, "error": currentErr})
	if strings.Contains(currentErr.Error(), "not found") {
		// Current error already tells us that the link was not present.  If we re-check
		// the status in this case, we open a race where the interface gets created and
		// we log an error when we're about to re-trigger programming anyway.
		logCxt.Info("Failed to access interface because it doesn't exist.")
		return IfaceNotPresent
	}
	// If the current error wasn't clear, try to look up the interface to see if there's a
	// well-understood reason for the failure.
	nl, err := r.getNetlinkHandle()
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
			logCxt.WithField("link", link).Warning(
				"Failed to access interface but it now appears to be up")
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
