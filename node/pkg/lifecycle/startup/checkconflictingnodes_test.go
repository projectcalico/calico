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

package startup

import (
	"context"
	"fmt"
	stdnet "net"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	coordinationv1 "k8s.io/api/coordination/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup/ipclaim"
)

// coordinationLeaseResource is the GroupResource fake API-error constructors
// need to build a realistic simulated apiserver error for a Lease.
func coordinationLeaseResource() schema.GroupResource {
	return coordinationv1.SchemeGroupVersion.WithResource("leases").GroupResource()
}

// resetTestLeaseState clears the process-lifetime state checkConflictingNodes
// keeps (the memoized IP-claim clientset and the one-time backfill flag) so
// each subtest below observes a fresh process, not the tail end of whatever
// the previous subtest left behind.
func resetTestLeaseState(t *testing.T) {
	t.Helper()
	leaseBackfilled.Store(false)
	t.Cleanup(func() { leaseBackfilled.Store(false) })
}

// mustParseNodeIP parses a Node's BGP CIDR address string (e.g. "10.0.1.5/24")
// the same way checkConflictingNodes does, for building the Lease name a
// test expects a given address to have claimed.
func mustParseNodeIP(t *testing.T, cidr string) stdnet.IP {
	t.Helper()
	ip, _, err := cnet.ParseCIDROrIP(cidr)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", cidr, err)
	}
	return ip.IP
}

// TestCheckConflictingNodesLeaseWiring covers the gating/wiring logic in
// checkConflictingNodes: the datastore-type branch that picks Lease-based
// claim vs. the legacy list scan, the FORCE_NODE_IP_CHECK_LEGACY_SCAN
// override, the diagnostic Get used to detect a prior IP, its wiring into
// ReleaseNodeIPLease, the ordering between the v4 and v6 claim blocks, and
// the addressChanged gate: the legacy list scan only runs when addressChanged
// is true, while the Lease claim path runs regardless of addressChanged.
// None of this had unit coverage before: the Kubernetes clientset used for
// the Lease claim used to be built inline with winutils.BuildConfigFromFlags
// and kubernetes.NewForConfig, which made it impossible to inject a fake
// here. newIPClaimClientset (a package variable) and the narrower
// client.NodeInterface parameter exist specifically to make this
// reachable without a live etcd/Kubernetes backend, which the rest of this
// package's (ginkgo-based) test suite requires.
func TestCheckConflictingNodesLeaseWiring(t *testing.T) {
	ctx := context.Background()

	t.Run("etcd datastore type falls back to the legacy list scan", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "etcdv3")
		buildCalls := 0
		withFakeIPClaimClientset(t, fake.NewSimpleClientset(), &buildCalls)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.listCalls != 1 {
			t.Fatalf("expected the legacy list scan to run exactly once, got %d calls", nodes.listCalls)
		}
		if buildCalls != 0 {
			t.Fatalf("expected no attempt to build a Kubernetes clientset for an etcd-backed deployment, got %d", buildCalls)
		}
	})

	t.Run("FORCE_NODE_IP_CHECK_LEGACY_SCAN forces the legacy scan even under the Kubernetes datastore type", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		t.Setenv(ipclaim.ForceLegacyScanEnvVar, "true")
		buildCalls := 0
		withFakeIPClaimClientset(t, fake.NewSimpleClientset(), &buildCalls)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		_, _, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nodes.listCalls != 1 {
			t.Fatalf("expected the legacy list scan to run exactly once, got %d calls", nodes.listCalls)
		}
		if buildCalls != 0 {
			t.Fatalf("expected the forced legacy scan to skip building a Kubernetes clientset, got %d calls", buildCalls)
		}
	})

	t.Run("apiconfig.LoadClientConfig error falls back to the legacy list scan when the address changed", func(t *testing.T) {
		resetTestLeaseState(t)
		// CALICO_K8S_CLIENT_QPS is a float32 env var read by
		// envconfig.Process inside apiconfig.LoadClientConfigFromEnvironment;
		// an unparsable value makes LoadClientConfig itself fail, exercising
		// the cerr != nil branch without needing to fake apiconfig directly.
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		t.Setenv("CALICO_K8S_CLIENT_QPS", "not-a-number")
		buildCalls := 0
		withFakeIPClaimClientset(t, fake.NewSimpleClientset(), &buildCalls)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.listCalls != 1 {
			t.Fatalf("expected the legacy list scan to run exactly once, got %d calls", nodes.listCalls)
		}
		if buildCalls != 0 {
			t.Fatalf("expected no attempt to build a Kubernetes clientset when the datastore type can't be determined, got %d", buildCalls)
		}
	})

	t.Run("apiconfig.LoadClientConfig error skips the legacy list scan when the address hasn't changed", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		t.Setenv("CALICO_K8S_CLIENT_QPS", "not-a-number")
		buildCalls := 0
		withFakeIPClaimClientset(t, fake.NewSimpleClientset(), &buildCalls)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.listCalls != 0 {
			t.Fatalf("expected the legacy list scan to be skipped on an unchanged address, got %d calls", nodes.listCalls)
		}
		if buildCalls != 0 {
			t.Fatalf("expected no attempt to build a Kubernetes clientset, got %d", buildCalls)
		}
	})

	t.Run("newIPClaimClientset's own error is surfaced as a hard error", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		wantErr := fmt.Errorf("simulated credential failure")
		withFakeIPClaimClientsetErr(t, wantErr)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		_, _, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err == nil {
			t.Fatalf("expected the clientset build failure to surface as an error")
		}
	})

	// TestCheckConflictingNodesLeaseWiring/a-failed-clientset-build-is-retried
	// covers the CRITICAL fix: getIPClaimClientset used to memoize via
	// sync.Once, which runs its function exactly once per process regardless
	// of whether it errors -- so a single transient failure (e.g. credentials
	// not yet available at boot) would be cached forever, and every later
	// call, including from the periodic monitor-addresses goroutine that
	// Fatals the process on any returned error, would get the same cached
	// error with no chance to ever succeed. This proves a failed build is
	// retried on the next call (build count increases), and that once a
	// build succeeds it is memoized and not rebuilt again.
	t.Run("a failed clientset build is retried, not cached, while a successful build is memoized", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		origFn := newIPClaimClientset
		resetIPClaimClientsetMemo()
		t.Cleanup(func() {
			newIPClaimClientset = origFn
			resetIPClaimClientsetMemo()
		})

		buildCalls := 0
		wantErr := fmt.Errorf("simulated transient credential failure")
		newIPClaimClientset = func() (kubernetes.Interface, error) {
			buildCalls++
			return nil, wantErr
		}

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		// First call: the build fails and surfaces as a hard error.
		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, true); err == nil {
			t.Fatalf("expected the clientset build failure to surface as an error")
		}
		if buildCalls != 1 {
			t.Fatalf("expected exactly one build attempt, got %d", buildCalls)
		}

		// Second call: a sync.Once-based memoization would have cached the
		// error from the first call and never invoked newIPClaimClientset
		// again, keeping buildCalls at 1. The fix must retry instead.
		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, true); err == nil {
			t.Fatalf("expected the clientset build to still be failing")
		}
		if buildCalls != 2 {
			t.Fatalf("expected the failed build to be retried on the next call (build count to increase), got %d", buildCalls)
		}

		// Now let the build succeed.
		cs := fake.NewSimpleClientset()
		newIPClaimClientset = func() (kubernetes.Interface, error) {
			buildCalls++
			return cs, nil
		}
		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, true); err != nil {
			t.Fatalf("unexpected error on the successful build: %v", err)
		}
		if buildCalls != 3 {
			t.Fatalf("expected exactly one more build attempt for the successful build, got %d", buildCalls)
		}

		// A further call must not rebuild: the successful clientset is
		// memoized for the rest of the process.
		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if buildCalls != 3 {
			t.Fatalf("expected the successful build to be memoized (no further build attempts), got %d", buildCalls)
		}
	})

	t.Run("Kubernetes datastore type invokes the Lease claim path", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		buildCalls := 0
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, &buildCalls)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.listCalls != 0 {
			t.Fatalf("expected the legacy list scan not to run, got %d calls", nodes.listCalls)
		}
		if buildCalls != 1 {
			t.Fatalf("expected exactly one Kubernetes clientset build for the Lease claim, got %d", buildCalls)
		}
		lease, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv4Address)), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected the IPv4 Lease to have been claimed: %v", err)
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "node-a" {
			t.Fatalf("lease holder = %v, want node-a", lease.Spec.HolderIdentity)
		}
	})

	t.Run("invokes the Lease claim path with a real Node and sets the OwnerReference", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		k8sNode := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a-uid")}}
		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		if _, _, err := checkConflictingNodes(ctx, nodes, node, k8sNode, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		lease, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv4Address)), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected the IPv4 Lease to have been claimed: %v", err)
		}
		if len(lease.OwnerReferences) != 1 || lease.OwnerReferences[0].UID != types.UID("node-a-uid") || lease.OwnerReferences[0].Name != "node-a" {
			t.Fatalf("unexpected owner references: %+v", lease.OwnerReferences)
		}
	})

	t.Run("releases the stale lease for the previous IP once the new one is claimed", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		oldNode := makeNode("10.0.1.9/24", "")
		if _, _, err := ipclaim.ClaimNodeIPLease(ctx, cs, nil, "node-a", mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)); err != nil {
			t.Fatalf("failed to seed the previous IP's lease: %v", err)
		}

		nodes := &fakeNodeInterface{getNode: oldNode}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nodes.getCalls != 1 {
			t.Fatalf("expected the diagnostic prior-IP Get to run exactly once, got %d calls", nodes.getCalls)
		}

		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err != nil {
			t.Fatalf("expected the new IP's lease to exist: %v", err)
		}
		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err == nil {
			t.Fatalf("expected the previous IP's lease to have been released")
		}
	})

	// TestCheckConflictingNodesLeaseWiring/releases-the-stale-lease-for-the-previous-address-even-when-the-new-address-conflicts
	// closes the gap the two subtests above leave open: they only exercise a
	// release when the new address's own claim succeeds. releaseIPv4 is
	// computed purely from whether THIS node's own prior-vs-current address
	// changed, and must not be gated on whether the new address happens to
	// conflict with a different node's live claim -- if it were, a node
	// whose address changes into a genuine conflict would never release its
	// old Lease, which on an autodetected address then gets compounded by
	// the caller clearing this node's own stored address on a persistent
	// conflict, permanently losing the ability to compute which address to
	// release on any later run. Reverting to gating the release on
	// !v4conflict would fail this test.
	t.Run("releases the stale lease for the previous address even when the new address conflicts", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		oldNode := makeNode("10.0.1.9/24", "")
		if _, _, err := ipclaim.ClaimNodeIPLease(ctx, cs, nil, "node-a", mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)); err != nil {
			t.Fatalf("failed to seed the previous IP's lease: %v", err)
		}

		nodes := &fakeNodeInterface{getNode: oldNode}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		// A different node already holds our newly detected v4 address, so
		// the claim for it conflicts.
		if _, _, err := ipclaim.ClaimNodeIPLease(ctx, cs, nil, "node-other", mustParseNodeIP(t, node.Spec.BGP.IPv4Address)); err != nil {
			t.Fatalf("failed to seed the conflicting v4 lease: %v", err)
		}

		v4conflict, _, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err == nil {
			t.Fatalf("expected a v4 conflict error")
		}
		if !v4conflict {
			t.Fatalf("expected v4conflict to be true")
		}

		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err == nil {
			t.Fatalf("expected the previous IP's lease to have been released despite the new address conflicting")
		}
		// The conflicting node's claim on the new address must be untouched.
		lease, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv4Address)), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected the conflicting node's lease on the new address to still exist: %v", err)
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "node-other" {
			t.Fatalf("new address lease holder = %v, want node-other", lease.Spec.HolderIdentity)
		}
	})

	// TestCheckConflictingNodesLeaseWiring/releases-the-stale-lease-when-the-address-disappears
	// covers a gap left by the address-change case above: it only exercised
	// the prior address changing to a DIFFERENT non-nil address. This proves
	// the prior Lease is also released when the current address goes from
	// set to nil (e.g. the interface that provided it disappeared) while the
	// Node object itself survives -- reverting the release condition back to
	// requiring a non-nil current address, or moving the release calls back
	// inside the "we have a current address" claim branch, would leak the
	// stale Lease forever in this scenario and would not be caught without
	// this test.
	t.Run("releases the stale lease when the current address disappears entirely", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		oldNode := makeNode("10.0.1.9/24", "")
		if _, _, err := ipclaim.ClaimNodeIPLease(ctx, cs, nil, "node-a", mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)); err != nil {
			t.Fatalf("failed to seed the previous IP's lease: %v", err)
		}

		nodes := &fakeNodeInterface{getNode: oldNode}
		// The current node record has no IPv4 address at all -- simulating
		// the interface that provided it having disappeared. makeNode can't
		// express this (net.ParseCIDR("") would panic inside it), so the
		// Node is built directly with an empty BGP spec.
		node := &internalapi.Node{Spec: internalapi.NodeSpec{BGP: &internalapi.NodeBGPSpec{}}}
		node.Name = "node-a"

		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err == nil {
			t.Fatalf("expected the previous IP's lease to have been released even though there is no current address to claim")
		}
	})

	// TestCheckConflictingNodesLeaseWiring/releases-the-stale-lease-even-when-falling-back-to-the-legacy-scan-forced
	// and its LoadClientConfig-error sibling below close the gap the release
	// subtests above leave open: they only exercise the release call sites
	// inside the main Lease-claim path. checkConflictingNodes' three
	// legacy-scan fallback branches (ForceLegacyScan, a LoadClientConfig
	// error, and a non-Kubernetes datastore type) used to return via
	// checkConflictingNodesByList without ever calling
	// releaseStaleIPClaimLeases, permanently orphaning a stale Lease: once
	// checkConflictingNodesByList finds no conflict, the caller persists the
	// new address, so the next run's diagnostic prior-address comparison can
	// never again compute the old address to release. This proves the
	// release now happens on the ForceLegacyScan fallback path even though it
	// never reaches the main claim logic below.
	t.Run("releases the stale lease even when falling back to the legacy scan (forced)", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		t.Setenv(ipclaim.ForceLegacyScanEnvVar, "true")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		oldNode := makeNode("10.0.1.9/24", "")
		if _, _, err := ipclaim.ClaimNodeIPLease(ctx, cs, nil, "node-a", mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)); err != nil {
			t.Fatalf("failed to seed the previous IP's lease: %v", err)
		}

		nodes := &fakeNodeInterface{getNode: oldNode}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.listCalls != 1 {
			t.Fatalf("expected the legacy list scan to run exactly once, got %d calls", nodes.listCalls)
		}
		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err == nil {
			t.Fatalf("expected the previous IP's lease to have been released despite falling back to the legacy scan")
		}
	})

	t.Run("releases the stale lease even when falling back to the legacy scan (LoadClientConfig error)", func(t *testing.T) {
		resetTestLeaseState(t)
		// See the "apiconfig.LoadClientConfig error falls back to the legacy
		// list scan when the address changed" subtest above: an unparsable
		// CALICO_K8S_CLIENT_QPS makes LoadClientConfig itself fail.
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		t.Setenv("CALICO_K8S_CLIENT_QPS", "not-a-number")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		oldNode := makeNode("10.0.1.9/24", "")
		if _, _, err := ipclaim.ClaimNodeIPLease(ctx, cs, nil, "node-a", mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)); err != nil {
			t.Fatalf("failed to seed the previous IP's lease: %v", err)
		}

		nodes := &fakeNodeInterface{getNode: oldNode}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.listCalls != 1 {
			t.Fatalf("expected the legacy list scan to run exactly once, got %d calls", nodes.listCalls)
		}
		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err == nil {
			t.Fatalf("expected the previous IP's lease to have been released despite falling back to the legacy scan")
		}
	})

	// TestCheckConflictingNodesLeaseWiring/diagnostic-Get-error-with-addressChanged-is-fatal
	// covers a gap: the diagnostic Get error branch (anything other than
	// ErrorResourceDoesNotExist, e.g. a Forbidden/RBAC-denied response) is
	// only reachable when nodes.Get returns a non-NotFound error, which no
	// other subtest here exercises -- every other subtest either has no
	// prior node record (the implicit ErrorResourceDoesNotExist case) or a
	// successful Get. When addressChanged is true, this Get is the only
	// source of truth for the prior address, so this proves the function now
	// returns the Get error rather than pressing on: pressing on would let
	// the caller claim and persist the new address with no way to ever
	// identify and release the old address's Lease again. It also proves the
	// claim itself is never attempted in this case, since the caller (which
	// gates persisting the new address on v4conflict/v6conflict, both false
	// here) must not see a Lease it needs to account for.
	t.Run("diagnostic Get error with addressChanged is fatal and skips the claim", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		// Hook the package-level logrus logger (what startup.go's `log`
		// alias writes through) so we can assert the diagnostic Get error
		// actually gets logged, not just that it doesn't blow up the call.
		hook := logtest.NewGlobal()
		defer hook.Reset()

		getErr := fmt.Errorf("simulated Forbidden error")
		nodes := &fakeNodeInterface{getErr: getErr}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err == nil {
			t.Fatalf("expected the diagnostic Get error to be surfaced as a hard error when addressChanged is true")
		}
		if err != getErr {
			t.Fatalf("returned error = %v, want the injected Get error %v", err, getErr)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict reported: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.getCalls != 1 {
			t.Fatalf("expected the diagnostic prior-IP Get to run exactly once, got %d calls", nodes.getCalls)
		}
		// The claim must never have been attempted: bailing out before it
		// is what keeps the caller from persisting the new address this run.
		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err == nil {
			t.Fatalf("expected no Lease to have been claimed for the current address when the diagnostic Get failed")
		}

		// The diagnostic Get error must still be logged (now at Error
		// level, since it's fatal to this call), with the injected error
		// attached and the node name in the message.
		var found *log.Entry
		for _, e := range hook.AllEntries() {
			if e.Level == log.ErrorLevel && strings.Contains(e.Message, node.Name) {
				found = e
				break
			}
		}
		if found == nil {
			t.Fatalf("expected an Error-level log entry mentioning node %q for the diagnostic Get error, got entries: %+v", node.Name, hook.AllEntries())
		}
		loggedErr, ok := found.Data["error"]
		if !ok {
			t.Fatalf("expected the logged entry to carry the diagnostic Get error via WithError, got fields: %+v", found.Data)
		}
		if loggedErr != getErr {
			t.Fatalf("logged error = %v, want the injected error %v", loggedErr, getErr)
		}
	})

	// Mirrors the subtest above but with addressChanged false: since nothing
	// new would be persisted this run either way, a diagnostic Get error
	// stays a logged warning, not a hard error, and the Lease claim still
	// proceeds normally -- the pre-fix behavior, preserved for this case.
	t.Run("diagnostic Get error without addressChanged is logged, not fatal, and the claim still proceeds", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		hook := logtest.NewGlobal()
		defer hook.Reset()

		getErr := fmt.Errorf("simulated Forbidden error")
		nodes := &fakeNodeInterface{getErr: getErr}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, false); err != nil {
			t.Fatalf("expected the diagnostic Get error to be logged, not surfaced as a hard error: %v", err)
		}
		if nodes.getCalls != 1 {
			t.Fatalf("expected the diagnostic prior-IP Get to run exactly once, got %d calls", nodes.getCalls)
		}
		// The claim itself must still have proceeded normally despite the
		// diagnostic Get failure -- addressChanged=false only gates the
		// legacy-scan and post-backfill branches, not this first claim.
		lease, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv4Address)), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected the IPv4 Lease to have been claimed despite the diagnostic Get error: %v", err)
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "node-a" {
			t.Fatalf("lease holder = %v, want node-a", lease.Spec.HolderIdentity)
		}

		var found *log.Entry
		for _, e := range hook.AllEntries() {
			if e.Level == log.WarnLevel && strings.Contains(e.Message, node.Name) {
				found = e
				break
			}
		}
		if found == nil {
			t.Fatalf("expected a Warn-level log entry mentioning node %q for the diagnostic Get error, got entries: %+v", node.Name, hook.AllEntries())
		}
		loggedErr, ok := found.Data["error"]
		if !ok {
			t.Fatalf("expected the logged entry to carry the diagnostic Get error via WithError, got fields: %+v", found.Data)
		}
		if loggedErr != getErr {
			t.Fatalf("logged error = %v, want the injected error %v", loggedErr, getErr)
		}
	})

	// Proves the retry/self-healing property the fix depends on: a diagnostic
	// Get failure with addressChanged=true must not be a permanent dead end.
	// After it causes an error return (simulating this run bailing out before
	// persisting anything), a subsequent call -- simulating a retry on the
	// next startup, with the same on-disk prior address still available --
	// must still correctly compute and release the true prior address's
	// Lease once the Get succeeds.
	t.Run("a later retry with a successful Get still releases the true prior address's lease", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		oldNode := makeNode("10.0.1.9/24", "")
		oldNode.Name = "node-a"
		if _, _, err := ipclaim.ClaimNodeIPLease(ctx, cs, nil, "node-a", mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)); err != nil {
			t.Fatalf("failed to seed the previous IP's lease: %v", err)
		}

		nodes := &fakeNodeInterface{getErr: fmt.Errorf("simulated Forbidden error")}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		// First attempt: the diagnostic Get fails, so the whole call must
		// bail out with an error and never claim or persist the new
		// address.
		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, true); err == nil {
			t.Fatalf("expected the first attempt to fail since the diagnostic Get errored")
		}
		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err == nil {
			t.Fatalf("expected no Lease to have been claimed for the new address on the failed first attempt")
		}
		// The old address's lease must still exist -- the first attempt
		// bailed out before ever computing what to release.
		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err != nil {
			t.Fatalf("expected the old address's lease to still exist after the failed first attempt: %v", err)
		}

		// Second attempt (the retry): the diagnostic Get now succeeds and
		// finds the true prior address, since the failed first attempt
		// never persisted the new address over it.
		nodes.getErr = nil
		nodes.getNode = oldNode

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err != nil {
			t.Fatalf("unexpected error on retry: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict on retry: v4=%v v6=%v", v4conflict, v6conflict)
		}
		newLease, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv4Address)), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected the new address's lease to have been claimed on retry: %v", err)
		}
		if newLease.Spec.HolderIdentity == nil || *newLease.Spec.HolderIdentity != "node-a" {
			t.Fatalf("new lease holder = %v, want node-a", newLease.Spec.HolderIdentity)
		}
		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, oldNode.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err == nil {
			t.Fatalf("expected the true prior address's lease to have been released on retry")
		}
	})

	t.Run("both v4 and v6 are attempted even when the v4 claim conflicts", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, new(int))

		node := makeNode("10.0.1.5/24", "fe80::1/64")
		node.Name = "node-a"

		// A different node already holds our detected v4 address.
		if _, _, err := ipclaim.ClaimNodeIPLease(ctx, cs, nil, "node-other", mustParseNodeIP(t, node.Spec.BGP.IPv4Address)); err != nil {
			t.Fatalf("failed to seed the conflicting v4 lease: %v", err)
		}

		nodes := &fakeNodeInterface{}
		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, true)
		if err == nil {
			t.Fatalf("expected a v4 conflict error")
		}
		if !v4conflict {
			t.Fatalf("expected v4conflict to be true")
		}
		if v6conflict {
			t.Fatalf("expected no v6 conflict")
		}
		// The v6 claim must still have been attempted despite the v4
		// conflict -- checkConflictingNodes doesn't return early on a
		// conflict (only on a hard error), so both addresses are always
		// processed in order.
		lease, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv6Address)), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected the v6 Lease to have been claimed despite the v4 conflict: %v", err)
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "node-a" {
			t.Fatalf("v6 lease holder = %v, want node-a", lease.Spec.HolderIdentity)
		}
	})

	t.Run("the legacy list scan is skipped when the address hasn't changed (etcd datastore)", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "etcdv3")
		buildCalls := 0
		withFakeIPClaimClientset(t, fake.NewSimpleClientset(), &buildCalls)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.listCalls != 0 {
			t.Fatalf("expected the legacy list scan to be skipped on an unchanged address, got %d calls", nodes.listCalls)
		}
	})

	t.Run("the legacy list scan is skipped when the address hasn't changed (forced legacy scan)", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		t.Setenv(ipclaim.ForceLegacyScanEnvVar, "true")
		buildCalls := 0
		withFakeIPClaimClientset(t, fake.NewSimpleClientset(), &buildCalls)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.listCalls != 0 {
			t.Fatalf("expected the legacy list scan to be skipped on an unchanged address, got %d calls", nodes.listCalls)
		}
		if buildCalls != 0 {
			t.Fatalf("expected no attempt to build a Kubernetes clientset when the scan is skipped, got %d", buildCalls)
		}
	})

	t.Run("the Lease claim path still runs on an unchanged address before it has ever backfilled successfully", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		buildCalls := 0
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, &buildCalls)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		v4conflict, v6conflict, err := checkConflictingNodes(ctx, nodes, node, nil, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v4conflict || v6conflict {
			t.Fatalf("unexpected conflict: v4=%v v6=%v", v4conflict, v6conflict)
		}
		if nodes.listCalls != 0 {
			t.Fatalf("expected the legacy list scan not to run, got %d calls", nodes.listCalls)
		}
		if buildCalls != 1 {
			t.Fatalf("expected the Lease claim path to still build a Kubernetes clientset on an unchanged address before it has ever backfilled, got %d", buildCalls)
		}
		lease, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, node.Spec.BGP.IPv4Address)), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("expected the IPv4 Lease to have been claimed despite the unchanged address: %v", err)
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "node-a" {
			t.Fatalf("lease holder = %v, want node-a", lease.Spec.HolderIdentity)
		}
	})

	// TestCheckConflictingNodesLeaseWiring/lease-claim-backfill-gate covers
	// the CRITICAL fix: once the Lease claim has succeeded once in this
	// process, a later call with an unchanged address must not repeat it.
	// Before this fix, checkConflictingNodes ran the Lease claim
	// unconditionally on every call, including from the periodic
	// monitor-addresses goroutine (default every 60s) which treats any
	// returned error as fatal to the whole calico-node process -- so any
	// transient failure on a later tick would have crash-looped the node
	// forever, long after the fleet had already converged. This proves the
	// gate closes after one success, and that a first failed attempt does
	// not (falsely) close it.
	t.Run("the Lease claim path runs unconditionally only until it first succeeds, then gates on addressChanged", func(t *testing.T) {
		resetTestLeaseState(t)
		t.Setenv("DATASTORE_TYPE", "kubernetes")
		buildCalls := 0
		cs := fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, &buildCalls)

		nodes := &fakeNodeInterface{}
		node := makeNode("10.0.1.5/24", "")
		node.Name = "node-a"

		// A failed attempt (Create keeps failing) must not close the gate:
		// the next call with an unchanged address should still retry.
		cs.PrependReactor("create", "leases", func(action clientgotesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewServerTimeout(coordinationLeaseResource(), "create", 1)
		})
		// ipclaim's own claimRetryAttempts/claimRetryBackoff retry a
		// transient Create failure a few times (~1s total with the package
		// defaults) before giving up; that's exercised here rather than
		// shortened, since those knobs are unexported in the ipclaim
		// package and this test only needs the attempt to fail once, not to
		// be fast.
		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, false); err == nil {
			t.Fatalf("expected the seeded transient failure to surface as an error")
		}
		if buildCalls != 1 {
			t.Fatalf("expected the failed attempt to still have built a clientset, got %d", buildCalls)
		}
		if leaseBackfilled.Load() {
			t.Fatalf("a failed attempt must not mark the backfill as done")
		}

		// Clear the injected failure; the claim now succeeds, closing the
		// gate.
		cs = fake.NewSimpleClientset()
		withFakeIPClaimClientset(t, cs, &buildCalls)
		buildCalls = 0
		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, false); err != nil {
			t.Fatalf("unexpected error on the successful attempt: %v", err)
		}
		if !leaseBackfilled.Load() {
			t.Fatalf("expected a successful claim to mark the backfill as done")
		}

		// A further call with an unchanged address must now be skipped
		// entirely -- no clientset build, no Lease call.
		buildCalls = 0
		if _, _, err := checkConflictingNodes(ctx, nodes, node, nil, false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if buildCalls != 0 {
			t.Fatalf("expected the Lease claim path to be skipped once backfilled and the address hasn't changed, got %d clientset builds", buildCalls)
		}

		// An actual address change still runs the claim even after backfill.
		// getIPClaimClientset memoizes the clientset for the process (see
		// finding #6), so a real address change doesn't rebuild it -- verify
		// the claim itself ran instead, by checking a new Lease appears for
		// the changed address.
		changedNode := makeNode("10.0.1.9/24", "")
		changedNode.Name = "node-a"
		if _, _, err := checkConflictingNodes(ctx, nodes, changedNode, nil, true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := cs.CoordinationV1().Leases(ipclaim.LeaseNamespace).Get(ctx, ipclaim.LeaseNameForIP(mustParseNodeIP(t, changedNode.Spec.BGP.IPv4Address)), metav1.GetOptions{}); err != nil {
			t.Fatalf("expected the changed address to have been claimed even after the backfill gate closed: %v", err)
		}
	})
}

// withFakeIPClaimClientset substitutes newIPClaimClientset -- the seam
// checkConflictingNodes uses to build the Kubernetes clientset for the Lease
// claim -- with one that returns cs and counts how many times it was called,
// restoring the original afterward.
// withFakeIPClaimClientset also resets the getIPClaimClientset memoization
// (see the ipClaimClientsetMu/ipClaimClientset package vars) both before and
// after substituting newIPClaimClientset, so a value cached by a previous
// subtest -- or by earlier steps within the same subtest -- never survives
// to be returned instead of calling the substitute this test just installed.
func withFakeIPClaimClientset(t *testing.T, cs kubernetes.Interface, calls *int) {
	t.Helper()
	origFn := newIPClaimClientset
	resetIPClaimClientsetMemo()
	newIPClaimClientset = func() (kubernetes.Interface, error) {
		*calls++
		return cs, nil
	}
	t.Cleanup(func() {
		newIPClaimClientset = origFn
		resetIPClaimClientsetMemo()
	})
}

// withFakeIPClaimClientsetErr substitutes newIPClaimClientset with one that
// always fails with wantErr, for exercising newIPClaimClientset's own error
// path through getIPClaimClientset/checkConflictingNodes.
func withFakeIPClaimClientsetErr(t *testing.T, wantErr error) {
	t.Helper()
	origFn := newIPClaimClientset
	resetIPClaimClientsetMemo()
	newIPClaimClientset = func() (kubernetes.Interface, error) {
		return nil, wantErr
	}
	t.Cleanup(func() {
		newIPClaimClientset = origFn
		resetIPClaimClientsetMemo()
	})
}

// resetIPClaimClientsetMemo clears getIPClaimClientset's memoized state --
// the cached clientset is reset to nil under its mutex, rather than saved and
// restored, since no test relies on the memoized state surviving across
// subtests; each subtest that touches it starts and ends with a clean slate.
func resetIPClaimClientsetMemo() {
	ipClaimClientsetMu.Lock()
	defer ipClaimClientsetMu.Unlock()
	ipClaimClientset = nil
}

// fakeNodeInterface is a minimal stand-in for client.NodeInterface. It's
// enough to exercise checkConflictingNodes/checkConflictingNodesByList,
// which only ever call Get (the diagnostic prior-IP lookup) and List (the
// legacy scan) on it; Create/Update/Delete/Watch panic if a test path
// reaches them, since none of the cases here are expected to.
type fakeNodeInterface struct {
	getNode  *internalapi.Node
	getErr   error
	getCalls int

	listNodes []internalapi.Node
	listErr   error
	listCalls int
}

func (f *fakeNodeInterface) Create(context.Context, *internalapi.Node, options.SetOptions) (*internalapi.Node, error) {
	panic("fakeNodeInterface: Create not expected in this test")
}

func (f *fakeNodeInterface) Update(context.Context, *internalapi.Node, options.SetOptions) (*internalapi.Node, error) {
	panic("fakeNodeInterface: Update not expected in this test")
}

func (f *fakeNodeInterface) Delete(context.Context, string, options.DeleteOptions) (*internalapi.Node, error) {
	panic("fakeNodeInterface: Delete not expected in this test")
}

func (f *fakeNodeInterface) Get(_ context.Context, name string, _ options.GetOptions) (*internalapi.Node, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getNode == nil {
		// A brand-new node with no prior record: the real Calico datastore
		// client returns cerrors.ErrorResourceDoesNotExist for this, and
		// checkConflictingNodes' addressChanged-fatal diagnostic-Get-error
		// path specifically depends on that type to distinguish "no prior
		// record yet" (expected, not fatal) from a genuine failure to read
		// one (fatal when addressChanged). A generic error here would make
		// every "brand-new node" subtest in this file trip that fatal path.
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: name}
	}
	return f.getNode, nil
}

func (f *fakeNodeInterface) List(context.Context, options.ListOptions) (*internalapi.NodeList, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &internalapi.NodeList{Items: f.listNodes}, nil
}

func (f *fakeNodeInterface) Watch(context.Context, options.ListOptions) (watch.Interface, error) {
	panic("fakeNodeInterface: Watch not expected in this test")
}
