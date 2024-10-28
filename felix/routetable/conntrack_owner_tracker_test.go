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
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ip"
)

var (
	cidr1 = ip.MustParseCIDROrIP("10.0.0.1")
)

func TestConntrackCleanupManager_NewRoute(t *testing.T) {
	h := setupConntrackTrackerTest(t)

	// Call methods in the same order as the RouteTable would.

	// Set the new owner for a previously-unknown IP.
	h.ccm.UpdateCIDROwner(cidr1, 10, RouteClassLocalWorkload)

	h.ccm.StartConntrackCleanupAndReset()

	Consistently(h.conntrack.NumPendingRemovals, "10ms").Should(Equal(0))
	expectWaitForPendingDeletionToReturnImmediately(h.ccm, cidr1)

	expectInSyncAtEnd(h.ccm)
}

func TestConntrackCleanupManager_MovedRoute(t *testing.T) {
	h := setupConntrackTrackerTest(t)

	// Call methods in the same order as the RouteTable would.

	// Initially, the route is owned by interface 10.
	t.Log("Setting initial owner.")
	h.ccm.UpdateCIDROwner(cidr1, 10, RouteClassLocalWorkload)
	// Commit that change.
	h.ccm.StartConntrackCleanupAndReset()

	// Then, the exact same route moves to interface 11.
	t.Log("Setting new owner.")
	h.ccm.UpdateCIDROwner(cidr1, 11, RouteClassLocalWorkload)

	// RouteTable won't have any deletions to do, so move on to the first
	// pass over the updated routes.
	Expect(h.ccm.CIDRNeedsEarlyCleanup(cidr1, 10)).To(BeTrue(),
		"Moved CIDR should need cleanup.")
	// RouteTable tells us that it deleted the old route.
	h.ccm.OnDataplaneRouteDeleted(cidr1, 10)

	// Then, asks us to clean up conntrack.
	h.ccm.StartConntrackCleanupAndReset()
	Eventually(h.conntrack.NumPendingRemovals).Should(Equal(1),
		"Expected one pending removal after moving route.")
	expectWaitForPendingDeletionToDelay(h.ccm, h.conntrack, cidr1)

	expectInSyncAtEnd(h.ccm)
}
func TestConntrackCleanupManager_MovedRouteRemoteToRemote(t *testing.T) {
	h := setupConntrackTrackerTest(t)

	// Call methods in the same order as the RouteTable would.

	// Initially, the route is owned by interface 10.
	t.Log("Setting initial owner.")
	h.ccm.UpdateCIDROwner(cidr1, 10, RouteClassVXLANTunnel)
	// Commit that change.
	h.ccm.StartConntrackCleanupAndReset()

	// Then, the exact same route moves to interface 11.
	t.Log("Setting new owner.")
	h.ccm.UpdateCIDROwner(cidr1, 11, RouteClassVXLANSameSubnet)

	// RouteTable won't have any deletions to do, so move on to the first
	// pass over the updated routes.
	Expect(h.ccm.CIDRNeedsEarlyCleanup(cidr1, 10)).To(BeFalse(),
		"Remote to remote moves houldn't trigger cleanup.")

	h.ccm.StartConntrackCleanupAndReset()
	Consistently(h.conntrack.NumPendingRemovals, "10ms").Should(Equal(0))
	expectWaitForPendingDeletionToReturnImmediately(h.ccm, cidr1)

	expectInSyncAtEnd(h.ccm)
}

func TestConntrackCleanupManager_ChangeOfPrioritySameInterface(t *testing.T) {
	h := setupConntrackTrackerTest(t)

	// This mimics what happens if the CNI plugin adds a route with one priority
	// and then Felix updates it to a different priority.
	t.Log("Setting initial owner.")

	// RouteTable spots the p=100 route, but it just queues it up for deletion.
	// Meanwhile, it tells us about the route it wants to program.
	h.ccm.UpdateCIDROwner(cidr1, 10, RouteClassLocalWorkload)
	// Then the deletion.
	h.ccm.OnDataplaneRouteDeleted(cidr1, 10)
	// Which should be ignored due to the prior update to signal intent to
	// create that route.
	Expect(h.ccm.CIDRNeedsEarlyCleanup(cidr1, 10)).To(BeFalse(),
		"CIDR on same interface should not need cleanup.")

	h.ccm.StartConntrackCleanupAndReset()
	Consistently(h.conntrack.NumPendingRemovals, "10ms").Should(Equal(0))
	expectWaitForPendingDeletionToReturnImmediately(h.ccm, cidr1)

	expectInSyncAtEnd(h.ccm)
}

func TestConntrackCleanupManager_ChangeOfPriorityDifferentInterface(t *testing.T) {
	h := setupConntrackTrackerTest(t)

	// This mimics what happens if the CNI plugin adds a route with one priority
	// and then Felix updates it to a different priority.
	t.Log("Setting initial owner.")

	// RouteTable spots the p=100 route, but it just queues it up for deletion.
	// Meanwhile, it tells us about the route it wants to program.
	h.ccm.UpdateCIDROwner(cidr1, 10, RouteClassLocalWorkload)
	// Then the deletion on a different interface.
	h.ccm.OnDataplaneRouteDeleted(cidr1, 11)

	h.ccm.StartConntrackCleanupAndReset()
	Eventually(h.conntrack.NumPendingRemovals).Should(Equal(1))
	expectWaitForPendingDeletionToDelay(h.ccm, h.conntrack, cidr1)

	expectInSyncAtEnd(h.ccm)
}

func TestConntrackCleanupManager_DeletedRoute(t *testing.T) {
	h := setupConntrackTrackerTest(t)

	// Tell the CCM about the route.
	h.ccm.UpdateCIDROwner(cidr1, 10, RouteClassLocalWorkload)
	h.ccm.StartConntrackCleanupAndReset() // Commit to the delta tracker.
	Consistently(h.conntrack.NumPendingRemovals, "10ms").Should(Equal(0))

	// Then, the route is deleted.
	h.ccm.RemoveCIDROwner(cidr1)
	h.ccm.OnDataplaneRouteDeleted(cidr1, 10)
	h.ccm.StartConntrackCleanupAndReset()
	Eventually(h.conntrack.NumPendingRemovals).Should(Equal(1))
	expectWaitForPendingDeletionToDelay(h.ccm, h.conntrack, cidr1)
}

func TestConntrackCleanupManager_DeletedStaleRoute(t *testing.T) {
	h := setupConntrackTrackerTest(t)

	// Tell the CCM about the route.
	h.ccm.UpdateCIDROwner(cidr1, 10, RouteClassLocalWorkload)
	h.ccm.StartConntrackCleanupAndReset() // Commit to the delta tracker.
	Consistently(h.conntrack.NumPendingRemovals, "10ms").Should(Equal(0))

	// Then, the route is deleted from a different interface.
	h.ccm.OnDataplaneRouteDeleted(cidr1, 11)
	h.ccm.StartConntrackCleanupAndReset()
	Consistently(h.conntrack.NumPendingRemovals, "10ms").Should(Equal(0))
}

type conntrackTrackerHarness struct {
	ccm       *ConntrackCleanupManager
	conntrack *mockConntrack
}

func setupConntrackTrackerTest(t *testing.T) *conntrackTrackerHarness {
	RegisterTestingT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conntrack := newMockConntrack(ctx)
	ccm := NewConntrackCleanupManager(4, conntrack)
	t.Cleanup(cancel)
	return &conntrackTrackerHarness{ccm, conntrack}
}

func expectWaitForPendingDeletionToReturnImmediately(ccm *ConntrackCleanupManager, cidr ip.CIDR) {
	delStart := time.Now()
	ccm.WaitForPendingDeletion(cidr)
	ExpectWithOffset(1, time.Since(delStart)).To(BeNumerically("<", 10*time.Millisecond),
		fmt.Sprintf("WaitForPendingDeletion(%v) should return immediately.", cidr))
}

func expectWaitForPendingDeletionToDelay(ccm *ConntrackCleanupManager, conntrack *mockConntrack, cidr ip.CIDR) {
	delStart := time.Now()
	go func() {
		time.Sleep(10 * time.Millisecond)
		conntrack.SignalPendingDeletionComplete(cidr.Addr())
	}()
	ccm.WaitForPendingDeletion(cidr)
	delay := time.Since(delStart)
	ExpectWithOffset(1, delay).To(BeNumerically(">=", 10*time.Millisecond),
		fmt.Sprintf("WaitForPendingDeletion(%v) should return after 10ms.", cidr))
	ExpectWithOffset(1, delay).To(BeNumerically("<", 20*time.Millisecond),
		fmt.Sprintf("WaitForPendingDeletion(%v) should return before 20ms.", cidr))
}

func expectInSyncAtEnd(ccm *ConntrackCleanupManager) {
	ExpectWithOffset(1, ccm.addrOwners.InSync()).To(BeTrue(), "Expected delta tracker to be in sync at end of test.")
	ExpectWithOffset(1, ccm.addrsToCleanUp).To(BeEmpty(), "Leaked addresses in addrsToCleanUp?")
}

type mockConntrack struct {
	lock sync.Mutex

	pendingRemovals map[ip.Addr]context.CancelFunc
	baseCtx         context.Context
}

func newMockConntrack(baseCtx context.Context) *mockConntrack {
	return &mockConntrack{
		pendingRemovals: map[ip.Addr]context.CancelFunc{},
		baseCtx:         baseCtx,
	}
}

func (m *mockConntrack) NumPendingRemovals() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return len(m.pendingRemovals)
}

// RemoveConntrackFlows is a called by background goroutine.  It blocks until
// the foreground test code signals that the fake removal is complete.
func (m *mockConntrack) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {
	logCtx := logrus.WithFields(logrus.Fields{
		"ipVersion": ipVersion,
		"ipAddr":    ipAddr,
	})
	logCtx.Info("RemoveConntrackFlows called.")
	addr := ip.FromNetIP(ipAddr)
	ctx, cancel := context.WithCancel(m.baseCtx)
	m.lock.Lock()
	m.pendingRemovals[addr] = cancel
	m.lock.Unlock()

	logCtx.Info("RemoveConntrackFlows waiting for signal to return...")
	<-ctx.Done()
	logCtx.Info("RemoveConntrackFlows returning")
}

func (m *mockConntrack) SignalPendingDeletionComplete(addr ip.Addr) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.pendingRemovals[addr]()
	delete(m.pendingRemovals, addr)
}
