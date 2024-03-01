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
)

type ConntrackTracker interface {
	SetAllowedOwner(key kernelRouteKey, idx int)
	RemoveAllowedOwner(key kernelRouteKey)
	AddDataplaneOwner(kernKey kernelRouteKey, ifindex int)
	SetSingleDataplaneOwner(key kernelRouteKey, idx int)

	StartDeletionsForDeletedRoutes()
	IterMovedRoutesAndStartDeletions(f func(kernKey kernelRouteKey, newOwners []int))
	WaitForPendingDeletion(ipAddr ip.Addr)

	DoPeriodicCleanup()
}

func NewRealConntrackTracker(ipVersion uint8, conntrack conntrackIface) *RealConntrackTracker {
	return &RealConntrackTracker{
		possibleOwners:  deltatracker.New[kernelRouteKey, []int](),
		pendingCleanups: map[ip.Addr]chan struct{}{},
		conntrack:       conntrack,
		ipVersion:       ipVersion,
	}
}

type RealConntrackTracker struct {
	// FIXME, this is not quite right for IPv6.  IPv6 naturally uses multiple metrics
	//  on its routes (systemd uses 512, 1024, 2048 for different preference levels
	//  that means that we end up removing and re-adding routes with different prefs
	//  and cleaning up the conntrack entries when we do so.  Really need to spot that
	//  CIDR is on the same interface and only clean up ifindex changes.
	possibleOwners  *deltatracker.DeltaTracker[kernelRouteKey, []int]
	pendingCleanups map[ip.Addr]chan struct{}

	conntrack conntrackIface
	ipVersion uint8
}

func (c *RealConntrackTracker) SetAllowedOwner(kernKey kernelRouteKey, idx int) {
	c.possibleOwners.Desired().Set(kernKey, []int{idx})
}

func (c *RealConntrackTracker) RemoveAllowedOwner(kernKey kernelRouteKey) {
	c.possibleOwners.Desired().Delete(kernKey)
}

func (c *RealConntrackTracker) AddDataplaneOwner(kernKey kernelRouteKey, ifindex int) {
	owners, _ := c.possibleOwners.Dataplane().Get(kernKey)
	for _, o := range owners {
		if o == ifindex {
			return
		}
	}
	owners = append(owners, ifindex)
	c.possibleOwners.Dataplane().Set(kernKey, owners)
}

func (c *RealConntrackTracker) SetSingleDataplaneOwner(kernKey kernelRouteKey, idx int) {
	c.possibleOwners.Dataplane().Set(kernKey, []int{idx})
}

func (c *RealConntrackTracker) StartDeletionsForDeletedRoutes() {
	// Clean up any conntrack entries for routes that have been deleted.
	c.possibleOwners.PendingDeletions().Iter(func(kernKey kernelRouteKey) deltatracker.IterAction {
		logrus.WithField("kernKey", kernKey).Debug("Route deleted, starting conntrack deletion.")
		c.startDeletion(kernKey.CIDR.Addr())
		return deltatracker.IterActionUpdateDataplane
	})
}

func (c *RealConntrackTracker) IterMovedRoutesAndStartDeletions(f func(kernKey kernelRouteKey, newOwners []int)) {
	c.possibleOwners.PendingUpdates().Iter(func(kernKey kernelRouteKey, newOwners []int) deltatracker.IterAction {
		old, ok := c.possibleOwners.Dataplane().Get(kernKey)
		if !ok {
			// We don't have any owners recorded in the dataplane.  This is the
			// mainline case when we're adding a route for the first time (or
			// it has been long enough since the last time this CIDR was used
			// that the cleanup is all done).
			return deltatracker.IterActionNoOp
		}
		logrus.WithFields(logrus.Fields{
			"kernKey":   kernKey,
			"oldOwners": old,
			"newOwners": newOwners,
		}).Info("Conntrack owners updated, starting conntrack deletion.")
		f(kernKey, newOwners)
		c.startDeletion(kernKey.CIDR.Addr())
		c.possibleOwners.Dataplane().Delete(kernKey)
		return deltatracker.IterActionNoOp
	})
}

// startDeletion starts the deletion of conntrack entries for the given CIDR in the background.  Pending
// deletions are tracked in the pendingCleanups map so we can block waiting for them later.
//
// It's important to do the conntrack deletions in the background because scanning the conntrack
// table is very slow if there are a lot of entries.  Previously, we did the deletion synchronously
// but that led to lengthy Apply() calls on the critical path.
func (c *RealConntrackTracker) startDeletion(ipAddr ip.Addr) {
	logrus.WithField("ip", ipAddr).Debug("Starting goroutine to delete conntrack entries")
	done := make(chan struct{})
	c.pendingCleanups[ipAddr] = done
	go func() {
		defer close(done)
		c.conntrack.RemoveConntrackFlows(c.ipVersion, ipAddr.AsNetIP())
		logrus.WithField("ip", ipAddr).Debug("Deleted conntrack entries")
	}()
}

// DoPeriodicCleanup scans the pendingCleanups map for completed entries and removes them.
func (c *RealConntrackTracker) DoPeriodicCleanup() {
	for ipAddr, ch := range c.pendingCleanups {
		select {
		case <-ch:
			logrus.WithField("ip", ipAddr).Debug(
				"Background goroutine finished deleting conntrack entries")
			delete(c.pendingCleanups, ipAddr)
		default:
			logrus.WithField("ip", ipAddr).Debug(
				"Background goroutine yet to finish deleting conntrack entries")
			continue
		}
	}
}

// WaitForPendingDeletion waits for any pending conntrack deletions (if any) for the given IP to complete.
func (c *RealConntrackTracker) WaitForPendingDeletion(ipAddr ip.Addr) {
	ch, ok := c.pendingCleanups[ipAddr]
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
	delete(c.pendingCleanups, ipAddr)
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
func (d DummyConntrackTracker) IterMovedRoutesAndStartDeletions(f func(kernKey kernelRouteKey, newOwners []int)) {
}
func (d DummyConntrackTracker) WaitForPendingDeletion(ipAddr ip.Addr)           {}
func (d DummyConntrackTracker) RemoveAllowedOwner(_ kernelRouteKey)             {}
func (d DummyConntrackTracker) SetAllowedOwner(_ kernelRouteKey, _ int)         {}
func (d DummyConntrackTracker) SetSingleDataplaneOwner(_ kernelRouteKey, _ int) {}
func (d DummyConntrackTracker) DoPeriodicCleanup()                              {}

var _ ConntrackTracker = (*DummyConntrackTracker)(nil)
