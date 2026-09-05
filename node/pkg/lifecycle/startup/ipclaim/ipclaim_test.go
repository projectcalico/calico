// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package ipclaim

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
)

// coordinationLeaseResource is the GroupResource fake API-error constructors
// need to build a realistic simulated apiserver error for a Lease.
func coordinationLeaseResource() schema.GroupResource {
	return coordinationv1.SchemeGroupVersion.WithResource("leases").GroupResource()
}

// withFastRetries shrinks claimRetryBackoff to something a test can afford to
// actually sleep through, and restores both retry knobs afterward.
func withFastRetries(t *testing.T, attempts int) {
	t.Helper()
	origAttempts, origBackoff := claimRetryAttempts, claimRetryBackoff
	claimRetryAttempts = attempts
	claimRetryBackoff = time.Millisecond
	t.Cleanup(func() {
		claimRetryAttempts, claimRetryBackoff = origAttempts, origBackoff
	})
}

func TestLeaseNameForIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want string
	}{
		{name: "IPv4", ip: "10.0.1.5", want: "calico-ip-10-0-1-5"},
		{name: "IPv6", ip: "fe80::1", want: "calico-ip-fe80--1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LeaseNameForIP(net.ParseIP(tc.ip))
			if got != tc.want {
				t.Errorf("LeaseNameForIP(%s) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

// TestLeaseNameForIPTrailingZeroCompression covers IPv6 addresses whose RFC
// 5952 canonical string ends in the "::" zero-compression marker. Left
// unguarded, the naive ":" -> "-" substitution produces a name ending in
// "-", which Kubernetes' DNS1123-subdomain validation rejects, so the Lease
// Create call would fail deterministically rather than racing cleanly. Each
// case is checked against the real k8s name validator, not just eyeballed,
// so this actually proves the fix works rather than just checking cosmetic
// properties of the returned string.
func TestLeaseNameForIPTrailingZeroCompression(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{name: "unspecified address", ip: "::"},
		{name: "address with trailing zero-compression", ip: "2001:db8:1::"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed := net.ParseIP(tc.ip)
			if parsed == nil {
				t.Fatalf("net.ParseIP(%q) returned nil", tc.ip)
			}
			got := LeaseNameForIP(parsed)
			if got == "" {
				t.Fatalf("LeaseNameForIP(%s) returned an empty name", tc.ip)
			}
			last := got[len(got)-1]
			if !(last >= 'a' && last <= 'z' || last >= '0' && last <= '9') {
				t.Fatalf("LeaseNameForIP(%s) = %q, does not end in an alphanumeric character", tc.ip, got)
			}
			if errs := validation.IsDNS1123Subdomain(got); len(errs) != 0 {
				t.Fatalf("LeaseNameForIP(%s) = %q is not a valid DNS1123 subdomain: %v", tc.ip, got, errs)
			}
		})
	}
}

func TestClaimNodeIPLease(t *testing.T) {
	ctx := context.Background()
	ip := net.ParseIP("10.0.1.5")
	nodeA := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a-uid")}}
	nodeB := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b", UID: types.UID("node-b-uid")}}

	t.Run("succeeds and owner-references the Node when no one else holds the IP", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()

		conflict, holder, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conflict {
			t.Fatalf("expected no conflict, got conflict with holder %q", holder)
		}
		if holder != "node-a" {
			t.Fatalf("holder = %q, want node-a", holder)
		}

		lease, err := clientset.CoordinationV1().Leases(LeaseNamespace).Get(ctx, "calico-ip-10-0-1-5", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("lease not found: %v", err)
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "node-a" {
			t.Fatalf("lease holder identity = %v, want node-a", lease.Spec.HolderIdentity)
		}
		if len(lease.OwnerReferences) != 1 || lease.OwnerReferences[0].UID != types.UID("node-a-uid") {
			t.Fatalf("unexpected owner references: %+v", lease.OwnerReferences)
		}
	})

	t.Run("is idempotent when the caller already holds the lease", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()

		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip); err != nil {
			t.Fatalf("first claim failed: %v", err)
		}
		conflict, holder, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip)
		if err != nil {
			t.Fatalf("second claim (re-claim by same holder) failed: %v", err)
		}
		if conflict {
			t.Fatalf("expected no conflict on re-claim by the same holder, got conflict with holder %q", holder)
		}
	})

	t.Run("reports a conflict when a different node already holds the IP", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()

		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip); err != nil {
			t.Fatalf("first claim failed: %v", err)
		}
		conflict, holder, err := ClaimNodeIPLease(ctx, clientset, nodeB, "node-b", ip)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !conflict {
			t.Fatalf("expected a conflict, got none")
		}
		if holder != "node-a" {
			t.Fatalf("holder = %q, want node-a (the original claimant)", holder)
		}
	})

	t.Run("repairs a stale owner reference when the lease is still held by us but the Node was recreated with a new UID", func(t *testing.T) {
		// Simulates a Node delete+re-register under the same name: the
		// Lease's HolderIdentity still names us, so this isn't a conflict,
		// but its OwnerReferences UID is now stale and would eventually be
		// reaped by Kubernetes GC as an orphan out from under a node that's
		// still alive and still holds the address.
		clientset := fake.NewSimpleClientset()
		nodeARecreated := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a-uid-2")}}

		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip); err != nil {
			t.Fatalf("first claim failed: %v", err)
		}

		conflict, holder, err := ClaimNodeIPLease(ctx, clientset, nodeARecreated, "node-a", ip)
		if err != nil {
			t.Fatalf("re-claim after Node recreation failed: %v", err)
		}
		if conflict {
			t.Fatalf("expected no conflict, got conflict with holder %q", holder)
		}

		lease, err := clientset.CoordinationV1().Leases(LeaseNamespace).Get(ctx, "calico-ip-10-0-1-5", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("lease not found: %v", err)
		}
		if len(lease.OwnerReferences) != 1 || lease.OwnerReferences[0].UID != types.UID("node-a-uid-2") {
			t.Fatalf("expected the owner reference to be repaired to the new UID, got: %+v", lease.OwnerReferences)
		}
	})

	t.Run("a stale owner reference repair failure is logged, not returned, since the claim itself already succeeded", func(t *testing.T) {
		// Simulates a benign race on the repair Update -- e.g. a concurrent
		// racer touching the same Lease during a rolling restart -- which
		// must not fail the claim: we already hold HolderIdentity by the
		// time the repair is attempted.
		clientset := fake.NewSimpleClientset()
		nodeARecreated := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a-uid-2")}}

		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip); err != nil {
			t.Fatalf("first claim failed: %v", err)
		}
		clientset.PrependReactor("update", "leases", func(action clientgotesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewConflict(coordinationLeaseResource(), "calico-ip-10-0-1-5", errors.New("simulated concurrent repair"))
		})

		conflict, holder, err := ClaimNodeIPLease(ctx, clientset, nodeARecreated, "node-a", ip)
		if err != nil {
			t.Fatalf("expected the repair failure to be non-fatal, got: %v", err)
		}
		if conflict {
			t.Fatalf("expected no conflict, got conflict with holder %q", holder)
		}
		if holder != "node-a" {
			t.Fatalf("holder = %q, want node-a", holder)
		}
	})

	t.Run("retries the Create when the AlreadyExists lease vanishes before the follow-up Get", func(t *testing.T) {
		// Simulates the blocking Lease's owning Node being deleted (and the
		// Lease GC'd) in the window between our failed Create and the
		// follow-up Get: the IP is free again, so the Create should be
		// retried rather than treated as a hard error.
		withFastRetries(t, 3)
		clientset := fake.NewSimpleClientset()
		var createCalls int
		clientset.PrependReactor("create", "leases", func(action clientgotesting.Action) (bool, runtime.Object, error) {
			createCalls++
			if createCalls == 1 {
				return true, nil, apierrors.NewAlreadyExists(coordinationLeaseResource(), "calico-ip-10-0-1-5")
			}
			return false, nil, nil // let the fake tracker actually create it.
		})
		var getCalls int
		clientset.PrependReactor("get", "leases", func(action clientgotesting.Action) (bool, runtime.Object, error) {
			getCalls++
			if getCalls == 1 {
				return true, nil, apierrors.NewNotFound(coordinationLeaseResource(), "calico-ip-10-0-1-5")
			}
			return false, nil, nil
		})

		conflict, holder, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip)
		if err != nil {
			t.Fatalf("expected the claim to eventually succeed, got: %v", err)
		}
		if conflict {
			t.Fatalf("expected no conflict, got conflict with holder %q", holder)
		}
		if createCalls != 2 {
			t.Fatalf("expected exactly 2 Create attempts (one AlreadyExists, one retry that succeeds), got %d", createCalls)
		}
	})

	t.Run("still claims the lease, without an owner reference, when no Kubernetes Node is available", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()

		conflict, holder, err := ClaimNodeIPLease(ctx, clientset, nil, "node-a", ip)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conflict {
			t.Fatalf("expected no conflict, got conflict with holder %q", holder)
		}

		lease, err := clientset.CoordinationV1().Leases(LeaseNamespace).Get(ctx, "calico-ip-10-0-1-5", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("lease not found: %v", err)
		}
		if len(lease.OwnerReferences) != 0 {
			t.Fatalf("expected no owner references, got %+v", lease.OwnerReferences)
		}
	})

	t.Run("retries a transient Create failure and succeeds once the apiserver recovers", func(t *testing.T) {
		withFastRetries(t, 3)
		clientset := fake.NewSimpleClientset()
		var calls int
		clientset.PrependReactor("create", "leases", func(action clientgotesting.Action) (bool, runtime.Object, error) {
			calls++
			if calls < 3 {
				return true, nil, apierrors.NewServerTimeout(coordinationLeaseResource(), "create", 1)
			}
			return false, nil, nil // let the fake tracker's default reactor actually create it.
		})

		conflict, holder, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip)
		if err != nil {
			t.Fatalf("expected the claim to eventually succeed, got: %v", err)
		}
		if conflict {
			t.Fatalf("expected no conflict, got conflict with holder %q", holder)
		}
		if calls != 3 {
			t.Fatalf("expected 3 Create attempts, got %d", calls)
		}
	})

	t.Run("gives up and returns the error after exhausting retries on a persistent transient failure", func(t *testing.T) {
		withFastRetries(t, 3)
		clientset := fake.NewSimpleClientset()
		var calls int
		clientset.PrependReactor("create", "leases", func(action clientgotesting.Action) (bool, runtime.Object, error) {
			calls++
			return true, nil, apierrors.NewServerTimeout(coordinationLeaseResource(), "create", 1)
		})

		_, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip)
		if err == nil {
			t.Fatalf("expected an error after exhausting retries, got nil")
		}
		if calls != 3 {
			t.Fatalf("expected exactly 3 Create attempts (claimRetryAttempts), got %d", calls)
		}
	})

	t.Run("never retries AlreadyExists -- it is a conclusive answer, not a transient failure", func(t *testing.T) {
		withFastRetries(t, 3)
		clientset := fake.NewSimpleClientset()
		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip); err != nil {
			t.Fatalf("first claim failed: %v", err)
		}

		var calls int
		clientset.PrependReactor("create", "leases", func(action clientgotesting.Action) (bool, runtime.Object, error) {
			calls++
			return false, nil, nil // fall through to the fake tracker, which returns AlreadyExists.
		})

		conflict, holder, err := ClaimNodeIPLease(ctx, clientset, nodeB, "node-b", ip)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !conflict {
			t.Fatalf("expected a conflict, got holder %q", holder)
		}
		if calls != 1 {
			t.Fatalf("expected exactly 1 Create attempt for a conclusive AlreadyExists, got %d", calls)
		}
	})
}

func TestReleaseNodeIPLease(t *testing.T) {
	ctx := context.Background()
	ip := net.ParseIP("10.0.1.5")
	nodeA := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a-uid")}}

	t.Run("deletes an existing lease still held by the caller", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()
		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip); err != nil {
			t.Fatalf("claim failed: %v", err)
		}

		if err := ReleaseNodeIPLease(ctx, clientset, "node-a", ip); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err := clientset.CoordinationV1().Leases(LeaseNamespace).Get(ctx, "calico-ip-10-0-1-5", metav1.GetOptions{})
		if err == nil {
			t.Fatalf("expected lease to be deleted, but it still exists")
		}
	})

	t.Run("is a no-op, not an error, when there is nothing to release", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()

		if err := ReleaseNodeIPLease(ctx, clientset, "node-a", ip); err != nil {
			t.Fatalf("unexpected error releasing a lease that was never claimed: %v", err)
		}
	})

	t.Run("does not delete another node's live claim on the same IP (stale release)", func(t *testing.T) {
		// Reproduces the scenario this ownership check exists to prevent:
		// node-a's own stored record of "the IP I used to hold" is stale --
		// node-a's original Lease was already reclaimed (e.g. its Node
		// object was replaced, GC'd the old Lease, and a different node,
		// node-b, has genuinely and cleanly claimed the same IP since). If
		// node-a releases by name alone, it deletes node-b's live claim and
		// the address is now unprotected for a third node to grab -- two
		// nodes sharing one IP, the exact outage the Lease claim exists to
		// prevent.
		clientset := fake.NewSimpleClientset()
		nodeB := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b", UID: types.UID("node-b-uid")}}
		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeB, "node-b", ip); err != nil {
			t.Fatalf("node-b's claim failed: %v", err)
		}

		// node-a, acting on stale information, tries to release the IP it
		// used to think it held.
		if err := ReleaseNodeIPLease(ctx, clientset, "node-a", ip); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		lease, err := clientset.CoordinationV1().Leases(LeaseNamespace).Get(ctx, LeaseNameForIP(ip), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected node-b's live claim to survive the stale release, but the lease is gone: %v", err)
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "node-b" {
			t.Fatalf("lease holder identity = %v, want node-b (unchanged)", lease.Spec.HolderIdentity)
		}
	})

	t.Run("skips the delete when a precondition-failing race loses to a concurrent replacement", func(t *testing.T) {
		// Simulates the Get-then-Delete race directly: between our Get and
		// our Delete, someone else's Delete+Create replaced the object, so
		// the apiserver would reject our Delete's UID/ResourceVersion
		// precondition with a Conflict. That must be treated the same as
		// "nothing of ours to release", not as an error.
		clientset := fake.NewSimpleClientset()
		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip); err != nil {
			t.Fatalf("claim failed: %v", err)
		}
		clientset.PrependReactor("delete", "leases", func(action clientgotesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewConflict(coordinationLeaseResource(), "calico-ip-10-0-1-5", errors.New("simulated precondition failure"))
		})

		if err := ReleaseNodeIPLease(ctx, clientset, "node-a", ip); err != nil {
			t.Fatalf("expected a precondition/Conflict failure to be treated as success, got: %v", err)
		}
	})

	t.Run("propagates a real error instead of swallowing it like NotFound or Conflict", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()
		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", ip); err != nil {
			t.Fatalf("claim failed: %v", err)
		}
		clientset.PrependReactor("delete", "leases", func(action clientgotesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("simulated apiserver failure"))
		})

		err := ReleaseNodeIPLease(ctx, clientset, "node-a", ip)
		if err == nil {
			t.Fatalf("expected the simulated failure to be returned, got nil")
		}
	})

	t.Run("supports the node-changed-IP scenario: claim a new address, release the old one", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()
		oldIP := net.ParseIP("10.0.1.5")
		newIP := net.ParseIP("10.0.1.9")

		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", oldIP); err != nil {
			t.Fatalf("claim of old IP failed: %v", err)
		}
		if _, _, err := ClaimNodeIPLease(ctx, clientset, nodeA, "node-a", newIP); err != nil {
			t.Fatalf("claim of new IP failed: %v", err)
		}
		if err := ReleaseNodeIPLease(ctx, clientset, "node-a", oldIP); err != nil {
			t.Fatalf("release of old IP failed: %v", err)
		}

		if _, err := clientset.CoordinationV1().Leases(LeaseNamespace).Get(ctx, LeaseNameForIP(oldIP), metav1.GetOptions{}); err == nil {
			t.Fatalf("expected the old IP's lease to be gone")
		}
		if _, err := clientset.CoordinationV1().Leases(LeaseNamespace).Get(ctx, LeaseNameForIP(newIP), metav1.GetOptions{}); err != nil {
			t.Fatalf("expected the new IP's lease to still exist: %v", err)
		}
	})
}

func TestForceLegacyScan(t *testing.T) {
	cases := []struct {
		name string
		val  string
		set  bool
		want bool
	}{
		{name: "unset", set: false, want: false},
		{name: "true", val: "true", set: true, want: true},
		{name: "false", val: "false", set: true, want: false},
		{name: "empty", val: "", set: true, want: false},
		{name: "wrong case not honored", val: "TRUE", set: true, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv(ForceLegacyScanEnvVar, c.val)
			}
			if got := ForceLegacyScan(); got != c.want {
				t.Errorf("ForceLegacyScan() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestRetryBackoffWithJitter proves retryBackoffWithJitter actually applies
// jitter -- reverting it to a fixed claimRetryBackoff sleep wouldn't fail any
// other test in this file, since the retry paths it's used from only assert
// on outcomes, not on the sleep duration.
func TestRetryBackoffWithJitter(t *testing.T) {
	origBackoff := claimRetryBackoff
	claimRetryBackoff = 100 * time.Millisecond
	t.Cleanup(func() { claimRetryBackoff = origBackoff })

	const samples = 20
	got := make([]time.Duration, samples)
	seenDistinct := false
	for i := 0; i < samples; i++ {
		d := retryBackoffWithJitter()
		if d < claimRetryBackoff {
			t.Fatalf("retryBackoffWithJitter() = %v, want >= claimRetryBackoff (%v)", d, claimRetryBackoff)
		}
		// Doc comment: "up to half again" -- so the upper bound is
		// claimRetryBackoff + claimRetryBackoff/2.
		if max := claimRetryBackoff + claimRetryBackoff/2; d > max {
			t.Fatalf("retryBackoffWithJitter() = %v, want <= %v (claimRetryBackoff plus up to half again)", d, max)
		}
		got[i] = d
		if i > 0 && d != got[0] {
			seenDistinct = true
		}
	}
	if !seenDistinct {
		t.Fatalf("expected at least two different values across %d calls, got the same value (%v) every time -- jitter does not appear to be applied", samples, got[0])
	}
}
