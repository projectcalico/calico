// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routetable

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type RouteOwnershipTracker interface {
	UpdateCIDROwner(addr ip.CIDR, ifaceIdx int, routeClass RouteClass)
	RemoveCIDROwner(addr ip.CIDR)

	CIDRNeedsEarlyCleanup(cidr ip.CIDR, oldIface int) bool
	OnDataplaneRouteDeleted(cidr ip.CIDR, ifindex int)
	StartConntrackCleanupAndReset()

	WaitForPendingDeletion(cidr ip.CIDR)
}

type conntrackOwner struct {
	ifaceIdx   int
	routeClass RouteClass
}

// ConntrackCleanupManager handles cleaning up conntrack entries on behalf of
// a RouteTable when routes are moved or deleted .  It:
//
//   - Uses a DeltaTracker to track which interfaces the RouteTable has
//     told us own which IP addresses.  We assume that the RouteTable only
//     allows one route per CIDR (even though it understands how to clean up
//     routes for other ToS and priority values).
//
//   - Expects a callback from the RouteTable when a route is deleted.
//
//   - Uses the interface index and route class on that callback to decide
//     if the route being deleted needs a conntrack cleanup.
//
//   - Provides a lookup function to check if an updated route needs a cleanup.
//
//   - Updates that don't change the interface index don't need cleanup.
//
//   - Updates from remote to remote don't need cleanup.  For example, a route
//     moving from VXLAN to VXLAN-same-subnet.
//
//   - Updates where there was no previous route don't need cleanup.
//
// A complicating factor is that the kernel keys routes using CIDR, ToS and
// priority whereas conntrack entries are keyed on 5-tuple only.  We sidestep
// that by assuming the RouteTable only allows one route per CIDR in its final
// state.  [Shaun] I tried to handle multiple routes per CIDR, but the
// complexity spiralled, and it wasn't clear what should be done in a lot of
// the corner cases.  I'm hoping that, should we add function that uses multiple
// ToSes or priorities, the right way to handle conflicts will be clear at that
// time!
type ConntrackCleanupManager struct {
	ipVersion uint8

	// addrOwners tracks which interfaces own which IP addresses.  We update
	// the Desired() side immediately as the RouteTable gives us update.  The
	// Dataplane() side is updated to record the "previous state" as soon as
	// we've started conntrack cleanups.
	addrOwners *deltatracker.DeltaTracker[ip.Addr, conntrackOwner]

	// addrsToCleanUp tracks which IP addresses need conntrack cleanup.  We
	// don't start the cleanup immediately in case there are multiple routes
	// with the same CIDR being deleted by the RouteTable.
	addrsToCleanUp set.Set[ip.Addr]

	// perIPDoneChans contains a channel for the most recent conntrack cleanup
	// for a given IP.  This allows us to block until the cleanup is done.
	perIPDoneChans map[ip.Addr]chan struct{}
	// cleanupDoneC is used to manage cleanup of the entries in perIPDoneChans.
	// The background goroutine sends the IP address that it cleaned up on this
	// channel after it closes its individual "done" channel.
	cleanupDoneC chan ip.Addr

	conntrack conntrackIface
}

var _ RouteOwnershipTracker = (*ConntrackCleanupManager)(nil)

func NewConntrackCleanupManager(ipVersion uint8, conntrack conntrackIface) *ConntrackCleanupManager {
	return &ConntrackCleanupManager{
		ipVersion: ipVersion,
		addrOwners: deltatracker.New[ip.Addr, conntrackOwner](
			deltatracker.WithValuesEqualFn[ip.Addr, conntrackOwner](func(a, b conntrackOwner) bool {
				return a == b
			}),
		),
		addrsToCleanUp: set.New[ip.Addr](),
		perIPDoneChans: map[ip.Addr]chan struct{}{},
		cleanupDoneC:   make(chan ip.Addr),
		conntrack:      conntrack,
	}
}

// UpdateCIDROwner is called when the new owner of a CIDR is calculated.
// It updates the "desired" next state, so multiple calls for the same CIDR
// are effectively coalesced; only the most recent update is remembered.
// the actual cleanup is triggered later by calls to OnDataplaneRouteDeleted and
// StartConntrackCleanupAndReset.
func (c *ConntrackCleanupManager) UpdateCIDROwner(cidr ip.CIDR, ifaceIdx int, routeClass RouteClass) {
	// We can't currently handle non-32-bit IPv4 or non-128-bit IPv6 CIDRs.
	// To do so, we'd need to handle longest-prefix match.
	if !cidr.IsSingleAddress() {
		return
	}
	c.addrOwners.Desired().Set(cidr.Addr(), conntrackOwner{ifaceIdx: ifaceIdx, routeClass: routeClass})
}

// RemoveCIDROwner is called when there is no longer an owner for the given
// CIDR.  Like UpdateCIDROwner, it updates the "desired" next state so
// a call to UpdateCIDROwner for the same CIDR before the cleanup is triggered
// will undo the removal.
func (c *ConntrackCleanupManager) RemoveCIDROwner(cidr ip.CIDR) {
	c.addrOwners.Desired().Delete(cidr.Addr())
}

// OnDataplaneRouteDeleted is called when the RouteTable tells us that a route
// has been removed from the dataplane on the given interface.  In most cases,
// this will queue the CIDR for conntrack cleanup at the next call to
// StartConntrackCleanupAndReset.
//
// No cleanup is triggered if there is a desired route for the given CIDR
// and that desired route is staying on this interface.
func (c *ConntrackCleanupManager) OnDataplaneRouteDeleted(cidr ip.CIDR, ifindex int) {
	if !cidr.IsSingleAddress() {
		return
	}
	addr := cidr.Addr()
	desiredRoute, desiredExists := c.addrOwners.Desired().Get(addr)

	if desiredExists {
		// RouteTable is going to replace this route with another one.
		if desiredRoute.ifaceIdx == ifindex {
			// Route isn't actually moving, just a ToS/priority update?
			logrus.WithField("ip", addr).Debug(
				"Route staying on same interface, ignoring.")
			return
		}
		previousRoute, _ := c.addrOwners.Dataplane().Get(addr)
		if previousRoute.ifaceIdx == desiredRoute.ifaceIdx {
			// We've already processed this route in a previous round so the
			// RouteTable must be deleting a stray newly added route.
			// Not safe to clean up conntrack entries.
			logrus.WithField("ip", addr).Info(
				"Route deleted but tracker shows we've already programmed correct route, ignoring.")
			return
		}
	}
	logrus.WithField("ip", addr).Debug("Route deleted, queueing conntrack deletion.")
	c.addrsToCleanUp.Add(addr)
}

// CIDRNeedsEarlyCleanup is called by the RouteTable to check if a route should
// be deleted early, to allow for conntrack cleanup to be properly sequenced.
func (c *ConntrackCleanupManager) CIDRNeedsEarlyCleanup(cidr ip.CIDR, oldIface int) bool {
	if !cidr.IsSingleAddress() {
		return false
	}
	addr := cidr.Addr()
	desiredRoute, desiredExists := c.addrOwners.Desired().Get(addr)
	dataplaneRoute, dataplaneExists := c.addrOwners.Dataplane().Get(addr)
	if dataplaneExists && desiredExists && desiredRoute.ifaceIdx == dataplaneRoute.ifaceIdx {
		// The desired route is already in place from a previous run so this
		// route must be some sort of stray route being cleaned up after the
		// fact.  We don't want to kill conntrack for the already-programmed
		// good route.
		logrus.WithField("ip", addr).Debug("Dataplane already has correct route, not cleaning up.")
		return false
	}
	if desiredExists && desiredRoute.ifaceIdx == oldIface {
		// Route isn't actually moving, just a ToS/priority update?
		logrus.WithField("ip", addr).Debug("Route staying on same iface, no need to clean up.")
		return false
	}
	if desiredRoute.routeClass.IsRemote() && dataplaneRoute.routeClass.IsRemote() {
		// Moving between different kinds of tunnel, not safe to clean up, it
		// may still be same remote workload.
		logrus.WithField("ip", addr).Debug("Route moving from remote->remote, skipping cleanup.")
		return false
	}
	logrus.WithField("ip", addr).Debug("Address needs cleanup.")
	return true
}

// StartConntrackCleanupAndReset starts all pending conntrack cleanups and
// resets the tracker to prepare for the next round of updates.
func (c *ConntrackCleanupManager) StartConntrackCleanupAndReset() {
	c.addrsToCleanUp.Iter(func(addr ip.Addr) error {
		c.startDeletion(addr)
		return set.RemoveItem
	})

	// Reset the tracker; we assume that the RouteTable has now implemented
	// its planned actions, and it'll tell us if any routes change.
	c.addrOwners.PendingDeletions().Iter(func(_ ip.Addr) deltatracker.IterAction {
		return deltatracker.IterActionUpdateDataplane
	})
	c.addrOwners.PendingUpdates().Iter(func(_ ip.Addr, _ conntrackOwner) deltatracker.IterAction {
		return deltatracker.IterActionUpdateDataplane
	})
	c.cleanUpStaleChannels()
}

// startDeletion starts the deletion of conntrack entries for the given CIDR in the background.  Pending
// deletions are tracked in the perIPDoneChans map so we can block waiting for them later.
//
// It's important to do the conntrack deletions in the background because scanning the conntrack
// table is very slow if there are a lot of entries.  Previously, we did the deletion synchronously
// but that led to lengthy Apply() calls on the critical path.
func (c *ConntrackCleanupManager) startDeletion(ipAddr ip.Addr) {
	logrus.WithField("ip", ipAddr).Debug("Starting goroutine to delete conntrack entries")
	done := make(chan struct{})
	c.perIPDoneChans[ipAddr] = done
	go func() {
		defer func() {
			c.cleanupDoneC <- ipAddr
		}()
		defer close(done)
		c.conntrack.RemoveConntrackFlows(c.ipVersion, ipAddr.AsNetIP())
		logrus.WithField("ip", ipAddr).Debug("Deleted conntrack entries")
	}()
}

// DoPeriodicCleanup scans the perIPDoneChans map for completed entries and removes them.
func (c *ConntrackCleanupManager) cleanUpStaleChannels() {
	for {
		select {
		case ipAddr := <-c.cleanupDoneC:
			c.cleanUpExpiredChan(ipAddr)
		default:
			return
		}
	}
}

func (c *ConntrackCleanupManager) cleanUpExpiredChan(ipAddr ip.Addr) {
	ch := c.perIPDoneChans[ipAddr]
	select {
	case <-ch:
		logrus.WithField("ip", ipAddr).Debug(
			"Background goroutine finished deleting conntrack entries")
		delete(c.perIPDoneChans, ipAddr)
	default:
		// Can get here if there was >1 deletion started for the same IP.
		logrus.WithField("ip", ipAddr).Debug(
			"Background goroutine yet to finish deleting conntrack entries")
	}
}

// WaitForPendingDeletion waits for any pending conntrack deletions (if any)
// for the given IP to complete. Returns immediately if there's no pending
// deletion.
func (c *ConntrackCleanupManager) WaitForPendingDeletion(cidr ip.CIDR) {
	if !cidr.IsSingleAddress() {
		return
	}
	ipAddr := cidr.Addr()
	ch, ok := c.perIPDoneChans[ipAddr]
	if !ok {
		conntrackBlockTimeSummary.Observe(0)
		return
	}
	// Do a non-blocking read first, to avoid logging a message if the deletion has already
	// completed.
	startTime := time.Now()
	select {
	case <-ch:
		goto done
	default:
		logrus.WithField("ip", ipAddr).Info("Need to wait for pending conntrack deletion to finish...")
	}
	for {
		select {
		case <-ch:
			logrus.WithFields(logrus.Fields{
				"ip":          ipAddr,
				"timeWaiting": time.Since(startTime),
			}).Info("Done waiting for pending conntrack deletion to finish")
			goto done
		case <-time.After(10 * time.Second):
			logrus.WithFields(logrus.Fields{
				"ip":          ipAddr,
				"timeWaiting": time.Since(startTime),
			}).Info("Still waiting for pending conntrack deletion to finish...")
		}
	}
done:
	delete(c.perIPDoneChans, ipAddr)
	conntrackBlockTimeSummary.Observe(time.Since(startTime).Seconds())
}

// NoOpRouteTracker is a dummy implementation of RouteOwnershipTracker that does nothing.
type NoOpRouteTracker struct {
}

func NewNoOpRouteTracker() NoOpRouteTracker {
	return NoOpRouteTracker{}
}

func (n NoOpRouteTracker) UpdateCIDROwner(addr ip.CIDR, ifaceIdx int, routeClass RouteClass) {}
func (n NoOpRouteTracker) RemoveCIDROwner(addr ip.CIDR)                                      {}
func (n NoOpRouteTracker) OnDataplaneRouteDeleted(cidr ip.CIDR, ifindex int)                 {}
func (n NoOpRouteTracker) CIDRNeedsEarlyCleanup(cidr ip.CIDR, ifindex int) bool              { return false }
func (n NoOpRouteTracker) StartConntrackCleanupAndReset()                                    {}
func (n NoOpRouteTracker) WaitForPendingDeletion(cidr ip.CIDR)                               {}

var _ RouteOwnershipTracker = (*NoOpRouteTracker)(nil)
