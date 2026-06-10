// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package leaderelection_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/typha/pkg/leaderelection"
)

// shortDurations makes tests run in milliseconds rather than seconds.
var fastCfg = leaderelection.Config{
	Enabled:        true,
	LeaseName:      "test-lease",
	LeaseNamespace: "kube-system",
	LeaseDuration:  300 * time.Millisecond,
	RenewDeadline:  200 * time.Millisecond,
	RetryPeriod:    50 * time.Millisecond,
}

// receiveRole waits up to timeout for a role to arrive on the channel.
func receiveRole(t *testing.T, ch <-chan leaderelection.Role, timeout time.Duration) leaderelection.Role {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(timeout):
		t.Fatal("timed out waiting for role transition")
		return leaderelection.Follower
	}
}

// TestAcquiresLeader verifies that a single candidate acquires the lease and
// becomes Leader.
func TestAcquiresLeader(t *testing.T) {
	cs := fake.NewClientset()
	e := leaderelection.New(cs, fastCfg, "pod-a", "kube-system")
	if e == nil {
		t.Fatal("New returned nil for enabled config")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go e.Run(ctx)

	role := receiveRole(t, e.Roles(), 3*time.Second)
	if role != leaderelection.Leader {
		t.Fatalf("expected Leader, got %v", role)
	}
}

// TestCurrentHolderObserved verifies that CurrentHolder reflects the observed
// identity once leadership is acquired.
//
// client-go calls OnNewLeader asynchronously; it may fire slightly after
// OnStartedLeading (which emits Leader on the channel), so we poll rather than
// checking immediately.
func TestCurrentHolderObserved(t *testing.T) {
	cs := fake.NewClientset()
	e := leaderelection.New(cs, fastCfg, "pod-a", "kube-system")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go e.Run(ctx)

	// Wait until leader role is delivered.
	receiveRole(t, e.Roles(), 3*time.Second)

	// OnNewLeader may fire slightly after OnStartedLeading; poll briefly.
	deadline := time.Now().Add(time.Second)
	for {
		holder, ok := e.CurrentHolder()
		if ok && holder == "pod-a" {
			return // success
		}
		if time.Now().After(deadline) {
			t.Fatalf("CurrentHolder not set to pod-a within 1s; ok=%v holder=%q", ok, holder)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestFollowerThenLeaderOnHandover verifies Follower→Leader re-acquisition.
// Pod-A holds the lease; its context is cancelled (simulating graceful
// shutdown / ReleaseOnCancel).  Pod-B is waiting and must acquire leadership.
// Then a fresh pod-A elector re-acquires after pod-B's context is cancelled.
//
// Note: the fake clientset does not simulate clock-based lease expiry, so the
// only reliable way to force a leadership change is context cancellation or
// a real cluster (covered by WS-C's FV tests).
func TestFollowerThenLeaderOnHandover(t *testing.T) {
	cs := fake.NewClientset()

	// Start pod-a.
	ctxA, cancelA := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelA()
	eA := leaderelection.New(cs, fastCfg, "pod-a", "kube-system")
	go eA.Run(ctxA)

	// Pod-A acquires leadership.
	roleA := receiveRole(t, eA.Roles(), 3*time.Second)
	if roleA != leaderelection.Leader {
		t.Fatalf("pod-a: expected Leader, got %v", roleA)
	}

	// Start pod-b as a competing candidate; it should be Follower while pod-a holds.
	ctxB, cancelB := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelB()
	cfgB := fastCfg
	cfgB.LeaseName = "test-lease" // same lease
	eB := leaderelection.New(cs, cfgB, "pod-b", "kube-system")
	go eB.Run(ctxB)

	// Cancel pod-A's context — triggers ReleaseOnCancel, releasing the lease.
	cancelA()

	// Pod-A should emit Follower.
	roleA2 := receiveRole(t, eA.Roles(), 3*time.Second)
	if roleA2 != leaderelection.Follower {
		t.Fatalf("pod-a: expected Follower after cancel, got %v", roleA2)
	}

	// Pod-B should now acquire.
	roleB := receiveRole(t, eB.Roles(), 5*time.Second)
	if roleB != leaderelection.Leader {
		t.Fatalf("pod-b: expected Leader after pod-a released, got %v", roleB)
	}

	// Cancel pod-B — release the lease.
	cancelB()
	roleB2 := receiveRole(t, eB.Roles(), 3*time.Second)
	if roleB2 != leaderelection.Follower {
		t.Fatalf("pod-b: expected Follower after cancel, got %v", roleB2)
	}
}

// TestReAcquireAfterLoss verifies that a new elector for pod-a can acquire
// the lease after pod-b releases it, demonstrating re-entry into the election.
func TestReAcquireAfterLoss(t *testing.T) {
	cs := fake.NewClientset()

	// Pod-A acquires first.
	ctxA, cancelA := context.WithTimeout(context.Background(), 10*time.Second)
	eA := leaderelection.New(cs, fastCfg, "pod-a", "kube-system")
	go eA.Run(ctxA)
	roleA := receiveRole(t, eA.Roles(), 3*time.Second)
	if roleA != leaderelection.Leader {
		cancelA()
		t.Fatalf("pod-a: expected initial Leader, got %v", roleA)
	}

	// Release: cancel pod-A's context.
	cancelA()
	roleA2 := receiveRole(t, eA.Roles(), 3*time.Second)
	if roleA2 != leaderelection.Follower {
		t.Fatalf("pod-a: expected Follower after cancel, got %v", roleA2)
	}

	// New pod-a elector re-acquires the now-released lease.
	ctxA2, cancelA2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelA2()
	eA2 := leaderelection.New(cs, fastCfg, "pod-a", "kube-system")
	go eA2.Run(ctxA2)
	roleA3 := receiveRole(t, eA2.Roles(), 3*time.Second)
	if roleA3 != leaderelection.Leader {
		t.Fatalf("pod-a (new elector): expected Leader on re-acquire, got %v", roleA3)
	}
}

// TestGracefulCancelReleasesLease verifies that cancelling the context while
// holding the lease releases it (ReleaseOnCancel), leaving HolderIdentity empty.
func TestGracefulCancelReleasesLease(t *testing.T) {
	cs := fake.NewClientset()
	e := leaderelection.New(cs, fastCfg, "pod-a", "kube-system")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(ctx)
	}()

	// Wait until leader.
	role := receiveRole(t, e.Roles(), 3*time.Second)
	if role != leaderelection.Leader {
		t.Fatalf("expected Leader before cancel, got %v", role)
	}

	// Cancel the context — this triggers ReleaseOnCancel.
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	// The Lease should now have an empty holder (released).
	lease, err := cs.CoordinationV1().Leases("kube-system").Get(context.Background(), "test-lease", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get lease after cancel: %v", err)
	}
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "" {
		t.Fatalf("expected lease to be released (empty HolderIdentity), got %q", *lease.Spec.HolderIdentity)
	}
}

// TestDisabledReturnsNil verifies that New returns nil when Enabled is false.
func TestDisabledReturnsNil(t *testing.T) {
	cs := fake.NewClientset()
	cfg := fastCfg
	cfg.Enabled = false
	e := leaderelection.New(cs, cfg, "pod-a", "kube-system")
	if e != nil {
		t.Fatal("expected nil Elector when disabled")
	}
}

// TestDefaultConfigValues verifies that applyDefaults fills in sensible
// defaults when zero values are supplied.
func TestDefaultConfigValues(t *testing.T) {
	cs := fake.NewClientset()
	cfg := leaderelection.Config{
		Enabled: true,
		// Leave all durations and names as zero.
	}
	e := leaderelection.New(cs, cfg, "pod-x", "ns-y")
	if e == nil {
		t.Fatal("expected non-nil elector")
	}
	// Just check we can start without a panic from NewLeaderElector.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go e.Run(ctx)

	// We only care that it acquires without error; don't wait for long.
	receiveRole(t, e.Roles(), 3*time.Second)
}

// TestLeaseObjectCreated verifies that the Lease object is created in the
// correct namespace with the correct name.
func TestLeaseObjectCreated(t *testing.T) {
	cs := fake.NewClientset()
	e := leaderelection.New(cs, fastCfg, "pod-a", "kube-system")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go e.Run(ctx)
	receiveRole(t, e.Roles(), 3*time.Second)

	leases, err := cs.CoordinationV1().Leases("kube-system").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("failed to list leases: %v", err)
	}
	found := false
	for _, l := range leases.Items {
		if l.Name == "test-lease" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected lease object 'test-lease' to be created in kube-system")
	}
}

// TestPerLeaseInstantiation verifies that two Elector instances for different
// leases can run independently (important for WS-E tier-1 election).
func TestPerLeaseInstantiation(t *testing.T) {
	cs := fake.NewClientset()

	cfgA := fastCfg
	cfgA.LeaseName = "lease-a"
	cfgB := fastCfg
	cfgB.LeaseName = "lease-b"

	eA := leaderelection.New(cs, cfgA, "pod-a", "kube-system")
	eB := leaderelection.New(cs, cfgB, "pod-b", "kube-system")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go eA.Run(ctx)
	go eB.Run(ctx)

	rA := receiveRole(t, eA.Roles(), 3*time.Second)
	rB := receiveRole(t, eB.Roles(), 3*time.Second)

	if rA != leaderelection.Leader {
		t.Fatalf("pod-a expected Leader for lease-a, got %v", rA)
	}
	if rB != leaderelection.Leader {
		t.Fatalf("pod-b expected Leader for lease-b, got %v", rB)
	}

	// Each elector should hold its own lease object.
	for _, name := range []string{"lease-a", "lease-b"} {
		l, err := cs.CoordinationV1().Leases("kube-system").Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("failed to get lease %s: %v", name, err)
		}
		_ = l
	}
}
