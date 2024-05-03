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
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type ConntrackTracker interface {
	SetAllowedOwner(key kernelRouteKey, idx int)
	RemoveAllowedOwner(key kernelRouteKey)
	AddDataplaneOwner(kernKey kernelRouteKey, ifindex int)
	SetSingleDataplaneOwner(key kernelRouteKey, idx int)

	StartDeletionsForDeletedRoutes()
	IterMovedRoutesAndStartDeletions(f func(kernKey kernelRouteKey))
	WaitForPendingDeletion(ipAddr ip.Addr)

	DoPeriodicCleanup()
}

func NewRealConntrackTracker(ipVersion uint8, conntrack conntrackIface) *RealConntrackTracker {
	return &RealConntrackTracker{
		ipVersion:        ipVersion,
		possibleOwners:   deltatracker.New[ip.Addr, map[kernelRouteKey][]int](),
		cleanupDoneChans: map[ip.Addr]chan struct{}{},
		conntrack:        conntrack,
	}
}

type RealConntrackTracker struct {
	ipVersion      uint8
	possibleOwners *deltatracker.DeltaTracker[ip.Addr, map[kernelRouteKey][]int]

	cleanupDoneChans map[ip.Addr]chan struct{}
	conntrack        conntrackIface
}

// SetAllowedOwner records that the given interface is allowed to own the given route.
// I.e. it is one of hte interfaces that the datapstore says the IP should belong to.
func (c *RealConntrackTracker) SetAllowedOwner(kernKey kernelRouteKey, idx int) {
	addr := kernKey.CIDR.Addr()
	ipOwners, ok := c.possibleOwners.Desired().Get(addr)
	if !ok {
		ipOwners = map[kernelRouteKey][]int{}
	} else {
		// Delete to avoid mutating the map while still in the DeltaTracker.
		c.possibleOwners.Desired().Delete(addr)
	}
	ipOwners[kernKey] = []int{idx}

	c.possibleOwners.Desired().Set(addr, ipOwners)
}

// RemoveAllowedOwner removes the given interface from the list of allowed owners for the given route.
func (c *RealConntrackTracker) RemoveAllowedOwner(kernKey kernelRouteKey) {
	addr := kernKey.CIDR.Addr()
	ipOwners, ok := c.possibleOwners.Desired().Get(addr)
	if !ok {
		return
	}
	// Delete to avoid mutating the map while still in the DeltaTracker.
	c.possibleOwners.Desired().Delete(addr)
	delete(ipOwners, kernKey)
	if len(ipOwners) > 0 {
		c.possibleOwners.Desired().Set(addr, ipOwners)
	}
}

// AddDataplaneOwner records that the given interface currently has a route for the
// given IP address.  For example, the RouteTable may ahve read back the routes
// and seen that this interface has a route for the given IP.
func (c *RealConntrackTracker) AddDataplaneOwner(kernKey kernelRouteKey, ifindex int) {
	addr := kernKey.CIDR.Addr()
	owners, _ := c.possibleOwners.Dataplane().Get(addr)
	for _, o := range owners[kernKey] {
		if o == ifindex {
			return
		}
	}
	if owners == nil {
		owners = map[kernelRouteKey][]int{}
	} else {
		// Delete to avoid mutating the map while still in the DeltaTracker.
		c.possibleOwners.Dataplane().Delete(addr)
	}
	owners[kernKey] = append(owners[kernKey], ifindex)
	c.possibleOwners.Dataplane().Set(addr, owners)
}

// SetSingleDataplaneOwner records that the given interface is now the sole
// owner of the route.  I.e. the RouteTable has removed all other copies of the
// route from other interfaces and there is now a single owner in the dataplane.
func (c *RealConntrackTracker) SetSingleDataplaneOwner(kernKey kernelRouteKey, idx int) {
	addr := kernKey.CIDR.Addr()
	owners, ok := c.possibleOwners.Dataplane().Get(addr)
	if !ok {
		owners = map[kernelRouteKey][]int{}
	} else {
		// Delete to avoid mutating the map while still in the DeltaTracker.
		c.possibleOwners.Dataplane().Delete(addr)
	}
	owners[kernKey] = []int{idx}
	c.possibleOwners.Dataplane().Set(addr, owners)
}

// StartDeletionsForDeletedRoutes starts the deletion of conntrack entries for
// addresses that have been completely deleted from all routes. Conntrack
// cleanup happens in the background.
func (c *RealConntrackTracker) StartDeletionsForDeletedRoutes() {
	// Clean up any conntrack entries for routes that have been deleted.
	c.possibleOwners.PendingDeletions().Iter(func(addr ip.Addr) deltatracker.IterAction {
		logrus.WithField("addr", addr).Debug(
			"All routes for this IP deleted, starting conntrack deletion.")
		c.startDeletion(addr)
		return deltatracker.IterActionUpdateDataplane
	})
}

// IterMovedRoutesAndStartDeletions iterates over routes that have moved to new
// owners and starts the deletion of conntrack entries for the old owners.
// The RouteTable is intended to delete the old routes from the dataplane
// after it gets a callback from this function.
func (c *RealConntrackTracker) IterMovedRoutesAndStartDeletions(f func(kernKey kernelRouteKey)) {
	keysToCleanUp := set.New[kernelRouteKey]()
	c.possibleOwners.PendingUpdates().Iter(func(addr ip.Addr, desiredOwners map[kernelRouteKey][]int) deltatracker.IterAction {
		oldOwners, ok := c.possibleOwners.Dataplane().Get(addr)
		if !ok {
			// We don't have any owners recorded in the dataplane.  This is the
			// mainline case when we're adding a route for the first time (or
			// it has been long enough since the last time this CIDR was used
			// that the cleanup is all done).
			return deltatracker.IterActionNoOp
		}

		// Figure out if the IP address has actually moved.  We look at each
		// TOS separately and examine the highest priority route for each TOS.
		// In practice, TOS-bearing routes can only come from outside Calico
		// so this loop is very likely to find only TOS 0 routes.
		allTOSes := set.New[int]()
		oldTOSToWinningRoute := map[int]kernelRouteKey{}
		for k := range oldOwners {
			bestSoFar, ok := oldTOSToWinningRoute[k.TOS]
			if !ok || bestSoFar.Priority < k.Priority {
				oldTOSToWinningRoute[k.TOS] = k
				allTOSes.Add(k.TOS)
			}
		}
		newTOSToWinningRoute := map[int]kernelRouteKey{}
		for k := range desiredOwners {
			bestSoFar, ok := newTOSToWinningRoute[k.TOS]
			if !ok || bestSoFar.Priority < k.Priority {
				newTOSToWinningRoute[k.TOS] = k
				allTOSes.Add(k.TOS)
			}
		}
		moveDetected := false
		allTOSes.Iter(func(tos int) error {
			oldKey := oldTOSToWinningRoute[tos]
			oldIfaces := oldOwners[oldKey]
			if len(oldIfaces) == 0 {
				// No old owners for this TOS so there should be nothing to
				// clean up.
				return nil
			}
			newKey := newTOSToWinningRoute[tos]
			newIfaces := desiredOwners[newKey]
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
			// In practice, probably only one route(!) but this should make
			// sure that we can't uncover an unexpected route and produce some
			// stray conntrack entries in the window before the RouteTable
			// inserts the new routes.
			for k := range oldOwners {
				if k.TOS != tos {
					continue
				}
				f(oldKey)
				keysToCleanUp.Add(oldKey)
			}
			return nil
		})

		if moveDetected {
			c.startDeletion(addr)
		}
		return deltatracker.IterActionNoOp
	})

	// Clean up the entries we removed after the iteration so that we don't
	// mutate values in the DeltaTracker while iterating.
	keysToCleanUp.Iter(func(k kernelRouteKey) error {
		oldOwners, ok := c.possibleOwners.Dataplane().Get(k.CIDR.Addr())
		if !ok {
			return nil
		}
		c.possibleOwners.Dataplane().Delete(k.CIDR.Addr())
		delete(oldOwners, k)
		if len(oldOwners) > 0 {
			c.possibleOwners.Dataplane().Set(k.CIDR.Addr(), oldOwners)
		}
		return nil
	})
}

// startDeletion starts the deletion of conntrack entries for the given CIDR in the background.  Pending
// deletions are tracked in the cleanupDoneChans map so we can block waiting for them later.
//
// It's important to do the conntrack deletions in the background because scanning the conntrack
// table is very slow if there are a lot of entries.  Previously, we did the deletion synchronously
// but that led to lengthy Apply() calls on the critical path.
func (c *RealConntrackTracker) startDeletion(ipAddr ip.Addr) {
	logrus.WithField("ip", ipAddr).Debug("Starting goroutine to delete conntrack entries")
	done := make(chan struct{})
	c.cleanupDoneChans[ipAddr] = done
	go func() {
		defer close(done)
		c.conntrack.RemoveConntrackFlows(c.ipVersion, ipAddr.AsNetIP())
		logrus.WithField("ip", ipAddr).Debug("Deleted conntrack entries")
	}()
}

// DoPeriodicCleanup scans the cleanupDoneChans map for completed entries and removes them.
func (c *RealConntrackTracker) DoPeriodicCleanup() {
	for ipAddr, ch := range c.cleanupDoneChans {
		select {
		case <-ch:
			logrus.WithField("ip", ipAddr).Debug(
				"Background goroutine finished deleting conntrack entries")
			delete(c.cleanupDoneChans, ipAddr)
		default:
			logrus.WithField("ip", ipAddr).Debug(
				"Background goroutine yet to finish deleting conntrack entries")
			continue
		}
	}
}

// WaitForPendingDeletion waits for any pending conntrack deletions (if any) for the given IP to complete.
func (c *RealConntrackTracker) WaitForPendingDeletion(ipAddr ip.Addr) {
	ch, ok := c.cleanupDoneChans[ipAddr]
	if !ok {
		return
	}
	// Do a non-blocking read first, to avoid logging a message if the deletion has already
	// completed.
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
	delete(c.cleanupDoneChans, ipAddr)
}

var _ ConntrackTracker = (*RealConntrackTracker)(nil)

// DummyConntrackTracker is a dummy implementation of ConntrackTracker that does nothing.
type DummyConntrackTracker struct {
}

func NewDummyConntrackTracker() DummyConntrackTracker {
	return DummyConntrackTracker{}
}

func (d DummyConntrackTracker) AddDataplaneOwner(kernKey kernelRouteKey, ifindex int) {}
func (d DummyConntrackTracker) StartDeletionsForDeletedRoutes()                       {}
func (d DummyConntrackTracker) IterMovedRoutesAndStartDeletions(f func(kernKey kernelRouteKey)) {
}
func (d DummyConntrackTracker) WaitForPendingDeletion(ipAddr ip.Addr)           {}
func (d DummyConntrackTracker) RemoveAllowedOwner(_ kernelRouteKey)             {}
func (d DummyConntrackTracker) SetAllowedOwner(_ kernelRouteKey, _ int)         {}
func (d DummyConntrackTracker) SetSingleDataplaneOwner(_ kernelRouteKey, _ int) {}
func (d DummyConntrackTracker) DoPeriodicCleanup()                              {}

var _ ConntrackTracker = (*DummyConntrackTracker)(nil)
