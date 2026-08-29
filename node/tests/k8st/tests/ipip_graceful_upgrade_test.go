// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ipip_graceful_upgrade_test.go covers what a cluster is left with when ownership of the IPIP
// cluster routes moves from confd and BIRD to Felix.
//
// BIRD's kernel protocol is configured with `persist`, so BIRD deliberately leaves its routes in
// the kernel when it exits.  A BIRD that comes back reconciles them away itself once its
// graceful-restart recovery period ends.  This test covers the case where it does not come back,
// because BGP was disabled as part of the same migration -- there, only Felix can clean up.
//
// Note that destinations Felix *does* want a route to were never the problem: Felix replaces any
// previous route for a prefix it wants, whatever protocol that route carried.  What needs Felix's
// ownership rule is a destination Felix does not want, which is what orphanCIDR below stands in
// for: a block that was released while this node was down.

package k8stests

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
)

const (
	// orphanCIDR is inside the cluster's default IPv4 pool but is backed by no IPAM block, so
	// Felix never wants a route to it.  It stands in for a block released while the node was
	// down: BIRD had a route to it, Felix has no route of its own to replace it with.
	orphanCIDR = "192.168.240.0/26"

	// defaultV4PoolPrefix matches the blocks of the cluster's default IPv4 pool.
	defaultV4PoolPrefix = "192.168."
)

// TestIPIPGracefulUpgradeWithBGPDisabled walks a cluster through the migration:
//
//  1. hand the IPIP cluster routes to confd and BIRD, as they were before v3.33;
//  2. take calico-node off the node, so that nothing there can react to what follows;
//  3. leave an orphaned BIRD route behind, of the kind BIRD's `persist` guarantees will survive;
//  4. hand the routes to Felix and disable BGP, in one Installation patch;
//  5. bring calico-node back -- with no BIRD in it at all.
//
// The orphan must survive steps 2 to 4 and be gone after 5.  Because the returning pod has no
// BIRD, only Felix can be what removed it.
//
// Ownership moves via clusterRoutingMode rather than the two programClusterRoutes fields directly,
// because disabling BGP is only a valid Installation once Felix owns the routes -- including the
// unencapsulated ones, which this cluster has (the IPv6 default pool and the LoadBalancer pools),
// so the mode has to be Felix rather than FelixIPIPOnly.
func TestIPIPGracefulUpgradeWithBGPDisabled(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	// NodeInfo returns the control-plane node first, then workers.
	nodes, ips, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 3),
		"need a control-plane node and at least two workers")
	node, peerIP := nodes[1], ips[2]

	// Step 1: BIRD owns the IPIP cluster routes, as before v3.33.
	setClusterRouteOwnership(t, g, cli, ctx, ptrTo(v3.EnabledIPIPOnly), ptrTo(v3.EnabledNoEncapOnly))
	t.Cleanup(func() {
		// Back to the defaults, whatever the test did.  Registered before the Installation
		// cleanup so that it runs after it: the operator writes these two fields whenever
		// clusterRoutingMode is set, so they have to be cleared once the mode is gone.
		setClusterRouteOwnership(t, g, cli, context.Background(), nil, nil)
	})

	t.Log("Waiting for BIRD to take over the IPIP cluster routes")
	utils.AssertRouteOwnership(t, node, defaultV4PoolPrefix, "tunl0", utils.RouteProtoBIRD)

	// Step 2: take calico-node off this node, so nothing there can react to what follows.
	restoreScheduling := evictCalicoNodeFrom(t, g, cli, ctx, node)

	// Step 3: the orphan.  Injected rather than produced by releasing a real block, so that the
	// test does not depend on IPAM timing; the route is identical in form to one BIRD leaves.
	//
	// It has to be installed while no BIRD is running.  BIRD treats routes carrying its own
	// protocol as its own, so a running BIRD reconciles away any it has no record of exporting --
	// within its `scan time` of 2s.  That is only true of a synthetic route: the ones a real
	// upgrade leaves behind are BIRD's own, and they outlive BIRD because of `persist`.
	t.Logf("Installing an orphaned BIRD route to %s on %s", orphanCIDR, node)
	_, err := utils.Run(t, fmt.Sprintf(
		"docker exec %s ip route add %s via %s dev tunl0 onlink proto bird",
		node, orphanCIDR, peerIP))
	g.Expect(err).NotTo(HaveOccurred(), "installing the orphaned BIRD route")

	// Step 4: hand the routes to Felix and drop BGP, in one patch.  Disabling BGP is only a valid
	// Installation once Felix owns the routes, so the two have to move together.
	t.Log("Handing the cluster routes to Felix and disabling BGP")
	restoreInstallation := setClusterRoutingModeAndBGP(
		t, g, cli, ctx, ptrTo(operatorv1.ClusterRoutingModeFelix), operatorv1.BGPDisabled)
	t.Cleanup(restoreInstallation)

	// The orphan must still be there: nothing has run on this node since it was installed.
	// Without this check, step 5 could be passing because something else cleaned up.
	g.Expect(routesOnNodeViaDocker(t, node)).To(ContainSubstring(orphanCIDR),
		"the orphaned route disappeared while calico-node was down, so this test would not be "+
			"showing that Felix removed it")

	// Step 5: bring calico-node back.  This pod has no BIRD in it, so anything that happens to
	// BIRD's leftovers from here is Felix's doing.
	restoreScheduling()
	g.Expect(calicoNodeBackend(t, g, node)).NotTo(Equal("bird"),
		"calico-node came back still running BIRD, so the cleanup could not be attributed to Felix")

	t.Log("Waiting for Felix to remove the orphaned BIRD route")
	utils.AssertNoRouteWithProto(t, node, orphanCIDR, utils.RouteProtoBIRD)

	// ...and the destinations Felix does want end up as Felix's.  (This part would hold with or
	// without the ownership rule: Felix replaces any previous route for a prefix it wants.)
	utils.AssertRouteOwnership(t, node, defaultV4PoolPrefix, "tunl0", utils.RouteProtoFelix)
}

// TestIPIPGracefulUpgradeWithBGPRetained models the mainstream upgrade, where BGP is still in use
// afterwards because the cluster peers with external infrastructure.
//
// The real upgrade changes no configuration at all: both programClusterRoutes fields are unset
// before and after, and it is the default each component derives from unset that moves when the
// code does.  That is not reproducible at a single code level, so the test fakes it -- but it must
// fake it while calico-node is *down*, otherwise confd sees the change live, BIRD reconfigures in
// place and withdraws its own routes, and the test would be exercising a path an upgrade never
// takes.  calico-node is evicted from the node under test for the duration.
//
// Unlike the BGP-disabled case, this one cannot attribute the cleanup to Felix, and in fact almost
// certainly is not Felix: a returning BIRD removes routes carrying its own protocol that it has no
// record of exporting, within its `scan time` of 2s, well before Felix has finished starting.  This
// test is here to show that the transition converges and leaves nothing behind, not to show that
// the ownership rule works -- TestIPIPGracefulUpgradeWithBGPDisabled is the one that does that.
func TestIPIPGracefulUpgradeWithBGPRetained(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	nodes, ips, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 3),
		"need a control-plane node and at least two workers")
	node, peerIP := nodes[1], ips[2]

	// BIRD owns the IPIP cluster routes, as before v3.33.
	setClusterRouteOwnership(t, g, cli, ctx, ptrTo(v3.EnabledIPIPOnly), ptrTo(v3.EnabledNoEncapOnly))
	t.Cleanup(func() {
		setClusterRouteOwnership(t, g, cli, context.Background(), nil, nil)
	})

	t.Log("Waiting for BIRD to take over the IPIP cluster routes")
	utils.AssertRouteOwnership(t, node, defaultV4PoolPrefix, "tunl0", utils.RouteProtoBIRD)

	// Take calico-node off this node, so that the ownership change lands while it is down and no
	// running confd or BIRD can react to it.
	restoreScheduling := evictCalicoNodeFrom(t, g, cli, ctx, node)

	// BIRD's own routes outlive the pod: that is what `persist` guarantees.
	g.Expect(routesOnNodeViaDocker(t, node)).To(ContainSubstring("proto bird"),
		"BIRD's routes did not survive calico-node being removed from the node")

	// Add the orphan now, while nothing is running that could reconcile it away.  A running BIRD
	// removes routes carrying its protocol that it has no record of exporting; with the pod gone
	// there is no BIRD, and no calico-node to exec into either, so this goes in via the node
	// container.
	t.Logf("Installing an orphaned BIRD route to %s on %s", orphanCIDR, node)
	_, err := utils.Run(t, fmt.Sprintf(
		"docker exec %s ip route add %s via %s dev tunl0 onlink proto bird",
		node, orphanCIDR, peerIP))
	g.Expect(err).NotTo(HaveOccurred(), "installing the orphaned BIRD route")

	t.Log("Handing the IPIP cluster routes to Felix while calico-node is down")
	setClusterRouteOwnership(t, g, cli, ctx, nil, nil)

	// Bring calico-node back: this is the upgraded pod, seeing the new ownership for the first
	// time, with BIRD's routes already in the kernel.
	restoreScheduling()

	t.Log("Waiting for the transition to converge")
	utils.AssertRouteOwnership(t, node, defaultV4PoolPrefix, "tunl0", utils.RouteProtoFelix)
	utils.AssertNoRouteWithProto(t, node, orphanCIDR, utils.RouteProtoBIRD)
}

// evictCalicoNodeFrom removes calico-node from one node by labelling every *other* node and
// pinning the DaemonSet to that label through the operator's Installation override.  It returns a
// function that undoes both and waits for the pod to come back.
func evictCalicoNodeFrom(
	t *testing.T,
	g *WithT,
	cli ctrlclient.Client,
	ctx context.Context,
	targetNode string,
) func() {
	t.Helper()

	const labelKey = "calico-st-run-calico-node"

	cs := utils.K8sClient(t)
	nodeList, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	g.Expect(err).NotTo(HaveOccurred(), "listing nodes")

	setLabel := func(ctx context.Context, nodeName string, present bool) {
		var patch string
		if present {
			patch = fmt.Sprintf(`{"metadata":{"labels":{%q:"true"}}}`, labelKey)
		} else {
			patch = fmt.Sprintf(`{"metadata":{"labels":{%q:null}}}`, labelKey)
		}
		_, err := cs.CoreV1().Nodes().Patch(
			ctx, nodeName, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
		g.Expect(err).NotTo(HaveOccurred(), "patching labels of node %s", nodeName)
	}

	for _, n := range nodeList.Items {
		if n.Name != targetNode {
			setLabel(ctx, n.Name, true)
		}
	}

	// Whatever override the cluster already had, so that restoring puts it back rather than
	// clearing it: the STs run against clusters this test does not own.
	inst := &operatorv1.Installation{}
	g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, inst)).
		To(Succeed(), "reading Installation default")
	previousDaemonSet := inst.Spec.CalicoNodeDaemonSet.DeepCopy()

	setDaemonSetOverride := func(ctx context.Context, override *operatorv1.CalicoNodeDaemonSet) {
		inst := &operatorv1.Installation{}
		g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, inst)).
			To(Succeed(), "reading Installation default")
		patch := ctrlclient.MergeFrom(inst.DeepCopy())
		inst.Spec.CalicoNodeDaemonSet = override
		g.Expect(cli.Patch(ctx, inst, patch)).To(Succeed(), "patching Installation calicoNodeDaemonSet")
	}

	pinToLabel := func(ctx context.Context, selector map[string]string) {
		setDaemonSetOverride(ctx, &operatorv1.CalicoNodeDaemonSet{
			Spec: &operatorv1.CalicoNodeDaemonSetSpec{
				Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
					Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{NodeSelector: selector},
				},
			},
		})
	}

	calicoNodePodsOn := func(ctx context.Context, nodeName string) int {
		pods, err := cs.CoreV1().Pods("calico-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=calico-node",
			FieldSelector: "spec.nodeName=" + nodeName,
		})
		if err != nil {
			return -1
		}
		return len(pods.Items)
	}

	t.Logf("Removing calico-node from %s", targetNode)
	pinToLabel(ctx, map[string]string{labelKey: "true"})
	g.Eventually(func() int { return calicoNodePodsOn(ctx, targetNode) }, "3m", "2s").
		Should(BeZero(), "calico-node did not go away on %s", targetNode)

	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		ctx := context.Background()
		t.Logf("Restoring calico-node on %s", targetNode)
		setDaemonSetOverride(ctx, previousDaemonSet)
		for _, n := range nodeList.Items {
			if n.Name != targetNode {
				setLabel(ctx, n.Name, false)
			}
		}
		utils.WaitForPodsReady(t, "calico-system", "k8s-app=calico-node", 5*time.Minute)
	}
	t.Cleanup(restore)
	return restore
}

// setClusterRouteOwnership sets BGPConfiguration.programClusterRoutes and
// FelixConfiguration.programClusterRoutes, each to the given value or, for nil, back to unset so
// that Calico's own defaults apply.
func setClusterRouteOwnership(
	t *testing.T,
	g *WithT,
	cli ctrlclient.Client,
	ctx context.Context,
	bgpValue, felixValue *string,
) {
	t.Helper()

	bgpCfg := &v3.BGPConfiguration{}
	g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, bgpCfg)).
		To(Succeed(), "reading default BGPConfiguration")
	bgpCfg.Spec.ProgramClusterRoutes = bgpValue
	g.Expect(cli.Update(ctx, bgpCfg)).To(Succeed(), "updating default BGPConfiguration")

	felixCfg := &v3.FelixConfiguration{}
	g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, felixCfg)).
		To(Succeed(), "reading default FelixConfiguration")
	felixCfg.Spec.ProgramClusterRoutes = felixValue
	g.Expect(cli.Update(ctx, felixCfg)).To(Succeed(), "updating default FelixConfiguration")

	t.Logf("Cluster route ownership set: BGPConfiguration=%s FelixConfiguration=%s",
		derefOr(bgpValue, "<unset>"), derefOr(felixValue, "<unset>"))
}

// setClusterRoutingModeAndBGP patches the operator Installation's clusterRoutingMode and BGP
// settings together, and returns a function that restores both.  They move together because
// disabling BGP is only a valid Installation once Felix owns the cluster routes: the operator
// rejects the intermediate state outright, degrading without touching the DaemonSet.
//
// Note this does not wait for a rollout.  The caller has calico-node evicted from the node under
// test, so there is nothing to wait for there; the other nodes roll in the background.
func setClusterRoutingModeAndBGP(
	t *testing.T,
	g *WithT,
	cli ctrlclient.Client,
	ctx context.Context,
	mode *operatorv1.ClusterRoutingMode,
	bgp operatorv1.BGPOption,
) func() {
	t.Helper()

	inst := &operatorv1.Installation{}
	g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, inst)).
		To(Succeed(), "reading Installation default")
	g.Expect(inst.Spec.CalicoNetwork).NotTo(BeNil(), "Installation has no calicoNetwork")
	previousMode, previousBGP := inst.Spec.CalicoNetwork.ClusterRoutingMode, inst.Spec.CalicoNetwork.BGP

	patch := func(ctx context.Context, mode *operatorv1.ClusterRoutingMode, bgp *operatorv1.BGPOption) {
		inst := &operatorv1.Installation{}
		g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, inst)).
			To(Succeed(), "reading Installation default")
		p := ctrlclient.MergeFrom(inst.DeepCopy())
		inst.Spec.CalicoNetwork.ClusterRoutingMode = mode
		inst.Spec.CalicoNetwork.BGP = bgp
		g.Expect(cli.Patch(ctx, inst, p)).To(Succeed(), "patching Installation")

		// The operator reports a rejected Installation through TigeraStatus rather than by
		// failing the patch, so check that it actually accepted this one.
		g.Eventually(func() string {
			return tigeraStatusDegradedMessage(t, "calico")
		}, "60s", "2s").Should(BeEmpty(), "the operator rejected the Installation")
	}

	patch(ctx, mode, &bgp)
	return func() {
		ctx := context.Background()
		patch(ctx, previousMode, previousBGP)

		// Re-enabling BGP cannot be left to the DaemonSet's rolling update.  calico-node's
		// readiness gate requires BGP to be established with its peers, and a rolling update
		// brings the nodes back one at a time -- so the first node to roll waits for peers that
		// have no BIRD yet, never becomes ready, and the roll never advances.  Deleting the pods
		// together lets them come back and peer with each other.  `make kind-reload` does the
		// same thing after a Helm upgrade, for what looks like the same reason.
		_, err := utils.Run(t, "kubectl delete pods -n calico-system -l k8s-app=calico-node")
		g.Expect(err).NotTo(HaveOccurred(), "deleting calico-node pods to re-establish BGP")

		utils.WaitForPodsReady(t, "calico-system", "k8s-app=calico-node", 5*time.Minute)
	}
}

// tigeraStatusDegradedMessage returns the Degraded condition's message for a TigeraStatus, or "" if
// it is not degraded.
func tigeraStatusDegradedMessage(t testing.TB, name string) string {
	t.Helper()
	out, err := utils.Run(t,
		"kubectl get tigerastatus "+name+
			` -o jsonpath='{.status.conditions[?(@.type=="Degraded")].message}'`,
		utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	if err != nil {
		// Deliberately not "": the caller waits for this to become empty, so a TigeraStatus it
		// could not read must not be mistaken for a healthy one.
		return fmt.Sprintf("could not read tigerastatus %s: %v", name, err)
	}
	return strings.TrimSpace(strings.Trim(out, "'"))
}

// calicoNodeBackend returns the CALICO_NETWORKING_BACKEND that the calico-node pod on nodeName is
// running with, which is "bird" only when BGP is enabled.
func calicoNodeBackend(t *testing.T, g *WithT, nodeName string) string {
	t.Helper()
	pod := utils.CalicoNodePodName(t, nodeName)
	out, err := utils.Run(t,
		"kubectl get pod -n calico-system "+pod+" -o "+
			`jsonpath='{.spec.containers[0].env[?(@.name=="CALICO_NETWORKING_BACKEND")].value}'`,
		utils.RunOptions{AllowFail: true})
	g.Expect(err).NotTo(HaveOccurred(), "reading calico-node's networking backend on %s", nodeName)
	return strings.TrimSpace(strings.Trim(out, "'"))
}

// routesOnNodeViaDocker returns the node's routing table read from the node container, for use when
// there is no calico-node pod to exec into.
func routesOnNodeViaDocker(t testing.TB, nodeName string) string {
	t.Helper()
	out, err := utils.Run(t, "docker exec "+nodeName+" ip route show",
		utils.RunOptions{AllowFail: true})
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return strings.TrimSpace(out)
}

func ptrTo[T any](v T) *T {
	return &v
}

func derefOr(s *string, fallback string) string {
	if s == nil {
		return fallback
	}
	return *s
}
