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

var (
	cidr1 = ip.MustParseCIDROrIP("10.0.0.1")
	key1 = kernelRouteKey{
		CIDR:     cidr1,
	}
)

func TestConntrackCleanupManager_NewRoute(t *testing.T) {
	ccm, conntrack, cancel := setup(t)
	defer cancel()

	// Call methods in the same order as the RouteTable would.

	// Set the new owner for a previously-unknown IP.
	ccm.SetAllowedOwner(key1, 10)

	// Do the apply steps in order; first trigger deletions (there are none to do)
	ccm.StartDeletionsForDeletedRoutes() // Should be no-op.
	Expect(conntrack.NumPendingRemovals()).To(Equal(0))
	// Then, iterate over mutations.
	ccm.IterMovedRoutesAndStartDeletions(func(kernKey kernelRouteKey) {
		t.Fatalf("Unexpected routereturned by IterMovedRoutesAndStartDeletions: %v", kernKey)
	})
	// If there's a deletion to do, wait for it (should not be one).
	addr := cidr1.Addr()
	expectWaitForPendingDeletionToReturnImmediately(ccm, addr)
	// Then tell the tracker that we have updated the dataplane.
	ccm.SetSingleDataplaneOwner(key1, 10)

	// On the next apply, there should still be nothing to do...
	ccm.StartDeletionsForDeletedRoutes() // Should be no-op.
	Expect(conntrack.NumPendingRemovals()).To(Equal(0))
	ccm.IterMovedRoutesAndStartDeletions(func(kernKey kernelRouteKey) {
		t.Fatalf("Unexpected routereturned by IterMovedRoutesAndStartDeletions: %v", kernKey)
	})
	expectWaitForPendingDeletionToReturnImmediately(ccm, addr)
}

func TestConntrackCleanupManager_DeletedRoute(t *testing.T) {
	ccm, conntrack, cancel := setup(t)
	defer cancel()

	// Call methods in the same order as the RouteTable would.

	// Tell the tracker that the route is there in the dataplane.
	ccm.SetAllowedOwner(key1, 10)
	ccm.SetSingleDataplaneOwner(key1, 10)

	// Then tell it that it is deleted.
	ccm.RemoveAllowedOwner(key1)

	// Do the apply steps in order; first trigger deletions
	ccm.StartDeletionsForDeletedRoutes()
	Eventually(conntrack.NumPendingRemovals).Should(Equal(1))
	// Then, iterate over mutations.
	ccm.IterMovedRoutesAndStartDeletions(func(kernKey kernelRouteKey) {
		t.Fatalf("Unexpected routereturned by IterMovedRoutesAndStartDeletions: %v", kernKey)
	})

	addr := cidr1.Addr()
	expectWaitForPendingDeletionToDelay(ccm, conntrack, addr)
}

func setup(t *testing.T) (*ConntrackCleanupManager, *mockConntrack, context.CancelFunc) {
	RegisterTestingT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conntrack := newMockConntrack(ctx)
	ccm := NewConntrackCleanupManager(4, conntrack)
	return ccm, conntrack, cancel
}

func expectWaitForPendingDeletionToReturnImmediately(ccm *ConntrackCleanupManager, addr ip.Addr) {
	delStart := time.Now()
	ccm.WaitForPendingDeletion(addr)
	ExpectWithOffset(1, time.Since(delStart)).To(BeNumerically("<", 10*time.Millisecond),
		fmt.Sprintf("WaitForPendingDeletion(%v) should return immediately.", addr))
}

func expectWaitForPendingDeletionToDelay(ccm *ConntrackCleanupManager, conntrack *mockConntrack, addr ip.Addr) {
	go func() {
		time.Sleep(10 * time.Millisecond)
		conntrack.SignalPendingDeletionComplete(addr)
	}()
	delStart := time.Now()
	ccm.WaitForPendingDeletion(addr)
	delay := time.Since(delStart)
	ExpectWithOffset(1, delay).To(BeNumerically(">=", 10*time.Millisecond),
		fmt.Sprintf("WaitForPendingDeletion(%v) should return after 10ms.", addr))
	ExpectWithOffset(1, delay).To(BeNumerically("<", 20*time.Millisecond),
		fmt.Sprintf("WaitForPendingDeletion(%v) should return before 20ms.", addr))
}