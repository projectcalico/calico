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
	"reflect"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/deltatracker"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/immutable"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type RouteOwnershipTracker interface {
	SetAllowedOwner(key kernelRouteKey, idx int)
	RemoveAllowedOwner(key kernelRouteKey)
	AddDataplaneOwner(kernKey kernelRouteKey, ifindex int)
	RemoveDataplaneOwners(kernKey kernelRouteKey)
	SetSingleDataplaneOwner(key kernelRouteKey, idx int)

	IterMovedRoutesAndStartCleanups(f func(kernKey kernelRouteKey))
	WaitForPendingDeletion(ipAddr ip.Addr)

	DoPeriodicCleanup()
	ClearAllDataplaneOwners()
}

// ConntrackCleanupManager handles cleaning up conntrack entries on behalf of
// a RouteTable when routes are moved or deleted .  It:
//
//   - Tracks which interfaces own which IP addresses; i.e. which interfaces
//     should be allowed to have conntrack entries for the given IP address.
//     This tracking affects the "Desired" side of a DeltaTracker but cleanup
//     is only triggered when IterMovedRoutesAndStartDeletions is called.
//   - Tracks which interfaces actually have routes programmed for the IP address.
//     this is tracked in the "Dataplane" side of a DeltaTracker.
//   - Initiates background cleanup of conntrack entries when an IP address was
//     assigned to one interface and then that assignment was removed.
//   - Blocks programming of new routes for the given IP address until the
//     cleanup is finished.  Since IPAM avoids re-using IPs right away, this
//     should be rare.
//
// A complicating factor is that the kernel keys routes using CIDR, ToS and
// priority, whereas conntrack only uses the CIDR part of the route.  To deal
// with that, we calculate the union of all the interfaces that have a route
// for a particular IP.  While we don't currently do anything with ToS, IPv6
// routes do typically have a non-0 priority so we do need to handle that
// (and in particular we want to avoid cleaning up conntrack if the IP stays on
// the same interface but the priority changes).
type ConntrackCleanupManager struct {
	ipVersion      uint8
	possibleOwners *deltatracker.DeltaTracker[ip.Addr, immutable.CopyingMap[kernelRouteKey, []int]]

	// perIPDoneChans contains a channel for the most recent conntrack cleanup
	// for a given IP.  This allows us to block until the cleanup is done.
	perIPDoneChans map[ip.Addr]chan struct{}
	// cleanupDoneC is used to manage cleanup of the entries in perIPDoneChans.
	// The background goroutine sends the IP address that it cleaned up on this
	// channel after it closes its individual "done" channel.
	cleanupDoneC     chan ip.Addr

	conntrack conntrackIface
}

func NewConntrackCleanupManager(ipVersion uint8, conntrack conntrackIface) *ConntrackCleanupManager {
	return &ConntrackCleanupManager{
		ipVersion:      ipVersion,
		possibleOwners: deltatracker.New[ip.Addr, immutable.CopyingMap[kernelRouteKey, []int]](),
		perIPDoneChans: map[ip.Addr]chan struct{}{},
		cleanupDoneC:   make(chan ip.Addr),
		conntrack:      conntrack,
	}
}

// SetAllowedOwner records that the given interface is the one that's allowed
// to own the given route.
func (c *ConntrackCleanupManager) SetAllowedOwner(kernKey kernelRouteKey, idx int) {
	addr := kernKey.CIDR.Addr()
	ipOwners, _ := c.possibleOwners.Desired().Get(addr)
	ipOwners = ipOwners.WithKey(kernKey, []int{idx})
	c.possibleOwners.Desired().Set(addr, ipOwners)
}

// RemoveAllowedOwner removes the given interface from the list of allowed owners for the given route.
func (c *ConntrackCleanupManager) RemoveAllowedOwner(kernKey kernelRouteKey) {
	addr := kernKey.CIDR.Addr()
	ipOwners, ok := c.possibleOwners.Desired().Get(addr)
	if !ok {
		return
	}
	ipOwners = ipOwners.WithKeyDeleted(kernKey)
	if ipOwners.Len() > 0 {
		c.possibleOwners.Desired().Set(addr, ipOwners)
	} else {
		c.possibleOwners.Desired().Delete(addr)
	}
}

// AddDataplaneOwner records that the given interface currently has a route for the
// given IP address.  For example, the RouteTable may have read back the routes
// and seen that this interface has a route for the given IP.
func (c *ConntrackCleanupManager) AddDataplaneOwner(kernKey kernelRouteKey, ifindex int) {
	addr := kernKey.CIDR.Addr()
	ipOwners, _ := c.possibleOwners.Dataplane().Get(addr)
	ifaces, _ := ipOwners.Get(kernKey)
	for _, o := range ifaces {
		if o == ifindex {
			return
		}
	}
	newOwners := make([]int, len(ifaces)+1)
	copy(newOwners, ifaces)
	newOwners[len(ifaces)] = ifindex
	ipOwners = ipOwners.WithKey(kernKey, newOwners)
	c.possibleOwners.Dataplane().Set(addr, ipOwners)
}

func (c *ConntrackCleanupManager) RemoveDataplaneOwners(kernKey kernelRouteKey) {
	addr := kernKey.CIDR.Addr()
	ipOwners, _ := c.possibleOwners.Dataplane().Get(addr)
	ipOwners = ipOwners.WithKeyDeleted(kernKey)
	if ipOwners.Len() > 0 {
		c.possibleOwners.Dataplane().Set(addr, ipOwners)
	} else {
		c.possibleOwners.Dataplane().Delete(addr)
	}
}

// SetSingleDataplaneOwner records that the given interface is now the sole
// owner of the route.  I.e. the RouteTable has removed all other copies of the
// route from other interfaces and there is now a single owner in the dataplane.
func (c *ConntrackCleanupManager) SetSingleDataplaneOwner(kernKey kernelRouteKey, idx int) {
	addr := kernKey.CIDR.Addr()
	ipOwners, _ := c.possibleOwners.Dataplane().Get(addr)
	ipOwners = ipOwners.WithKey(kernKey, []int{idx})
	c.possibleOwners.Dataplane().Set(addr, ipOwners)
}

func (c *ConntrackCleanupManager) ClearAllDataplaneOwners() {
	c.possibleOwners.Dataplane().ReplaceAllMap(nil)
}

// IterMovedRoutesAndStartCleanups iterates over routes that have moved to new
// owners and, after issuing each callback, it starts the deletion of conntrack
// entries for the old owners.
//
// The RouteTable is intended to delete the old routes from the dataplane
// within the callback function.
func (c *ConntrackCleanupManager) IterMovedRoutesAndStartCleanups(f func(kernKey kernelRouteKey)) {
	keysToCleanUp := set.New[kernelRouteKey]()
	c.possibleOwners.PendingUpdates().Iter(func(
		addr ip.Addr,
		desiredOwners immutable.CopyingMap[kernelRouteKey, []int],
	) deltatracker.IterAction {
		oldOwners, ok := c.possibleOwners.Dataplane().Get(addr)
		if !ok {
			// We don't have any owners recorded in the dataplane.  This is the
			// mainline case when we're adding a route for the first time (or
			// it has been long enough since the last time this CIDR was used
			// that the cleanup is all done).
			//
			// No need to call back, this isn't a moved route.
			return deltatracker.IterActionNoOp
		}

		// Figure out if the IP address has actually moved.  We look at each
		// TOS separately and examine the highest priority route for each TOS.
		// In practice, TOS-bearing routes can only come from outside Calico
		// so this loop is very likely to find only TOS 0 routes.
		allTOSes := set.New[int]()
		oldTOSToWinningRoute := map[int]kernelRouteKey{}
		oldOwners.Iter(func(k kernelRouteKey, _ []int) bool {
			bestSoFar, ok := oldTOSToWinningRoute[k.TOS]
			if !ok || bestSoFar.Priority < k.Priority {
				oldTOSToWinningRoute[k.TOS] = k
				allTOSes.Add(k.TOS)
			}
			return true
		})
		newTOSToWinningRoute := map[int]kernelRouteKey{}
		desiredOwners.Iter(func(k kernelRouteKey, _ []int) bool {
			bestSoFar, ok := newTOSToWinningRoute[k.TOS]
			if !ok || bestSoFar.Priority < k.Priority {
				newTOSToWinningRoute[k.TOS] = k
				allTOSes.Add(k.TOS)
			}
			return true
		})
		moveDetected := false
		allTOSes.Iter(func(tos int) error {
			oldKey := oldTOSToWinningRoute[tos]
			oldIfaces, _ := oldOwners.Get(oldKey)
			if len(oldIfaces) == 0 {
				// No old owners for this TOS so there should be nothing to
				// clean up.
				return nil
			}
			newKey := newTOSToWinningRoute[tos]
			newIfaces, _ := desiredOwners.Get(newKey)
			if reflect.DeepEqual(oldIfaces, newIfaces) {
				// No change for this TOS.
				return nil
			}

			// Otherwise, we have a move.
			logrus.WithFields(logrus.Fields{
				"addr":      addr,
				"TOS":       tos,
				"oldOwners": oldIfaces,
				"newOwners": newIfaces,
			}).Info("Conntrack owners updated, starting conntrack deletion.")
			moveDetected = true
			// Tell the RouteTable to remove all the old routes for this ToS.
			// In practice, probably only one route(!).  This should make
			// sure that we can't uncover an unexpected route and produce some
			// stray conntrack entries in the window before the RouteTable
			// inserts the new routes.
			oldOwners.Iter(func(k kernelRouteKey, _ []int) bool {
				if k.TOS != tos {
					return true
				}
				f(oldKey)
				keysToCleanUp.Add(oldKey)
				return true
			})
			return nil
		})

		if moveDetected {
			c.startDeletion(addr)
		}
		return deltatracker.IterActionNoOp
	})

	// Clean up the entries we removed after the iteration so that we don't
	// mutate values in the DeltaTracker while iterating.
	keysToCleanUp.Iter(func(key kernelRouteKey) error {
		c.RemoveDataplaneOwners(key)
		return nil
	})

	// Clean up any conntrack entries for routes that have been deleted.
	c.possibleOwners.PendingDeletions().Iter(func(addr ip.Addr) deltatracker.IterAction {
		logrus.WithField("addr", addr).Debug(
			"All routes for this IP deleted, starting conntrack deletion.")
		c.startDeletion(addr)
		return deltatracker.IterActionUpdateDataplane
	})
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
func (c *ConntrackCleanupManager) DoPeriodicCleanup() {
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

// WaitForPendingDeletion waits for any pending conntrack deletions (if any) for the given IP to complete.
func (c *ConntrackCleanupManager) WaitForPendingDeletion(ipAddr ip.Addr) {
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
		logrus.WithField("ip", ipAddr).Info("Waiting for pending conntrack deletion to finish")
	}
	for {
		select {
		case <-ch:
			logrus.WithField("ip", ipAddr).Info("Done waiting for pending conntrack deletion to finish")
			goto done
		case <-time.After(10 * time.Second):
			logrus.WithField("ip", ipAddr).Info("Still waiting for pending conntrack deletion to finish...")
		}
	}
done:
	delete(c.perIPDoneChans, ipAddr)
	conntrackBlockTimeSummary.Observe(time.Since(startTime).Seconds())
}

var _ RouteOwnershipTracker = (*ConntrackCleanupManager)(nil)

// NoOpRouteTracker is a dummy implementation of RouteOwnershipTracker that does nothing.
type NoOpRouteTracker struct {
}

func NewNoOpRouteTracker() NoOpRouteTracker {
	return NoOpRouteTracker{}
}

func (d NoOpRouteTracker) RemoveDataplaneOwners(kernKey kernelRouteKey) {}
func (d NoOpRouteTracker) AddDataplaneOwner(kernKey kernelRouteKey, ifindex int) {}
func (d NoOpRouteTracker) IterMovedRoutesAndStartCleanups(f func(kernKey kernelRouteKey)) {
}
func (d NoOpRouteTracker) WaitForPendingDeletion(ipAddr ip.Addr)           {}
func (d NoOpRouteTracker) RemoveAllowedOwner(_ kernelRouteKey)             {}
func (d NoOpRouteTracker) SetAllowedOwner(_ kernelRouteKey, _ int)         {}
func (d NoOpRouteTracker) SetSingleDataplaneOwner(_ kernelRouteKey, _ int) {}
func (d NoOpRouteTracker) DoPeriodicCleanup()                              {}
func (d NoOpRouteTracker) ClearAllDataplaneOwners()                        {}

var _ RouteOwnershipTracker = (*NoOpRouteTracker)(nil)
