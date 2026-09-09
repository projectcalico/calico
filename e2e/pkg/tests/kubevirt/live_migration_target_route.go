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

package kubevirt

import (
	"context"
	"fmt"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/bgp"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

// This file holds the shared choreography for the "target node prefers its
// local workload route" live-migration regression test. Two thin Its invoke
// it: the real-KubeVirt variant in live_migration.go (nc TCP streams to the
// guest's tcp-server) and the MockVirt variant in live_migration_mockvirt.go
// (ICMP cadence probes; mock pods answer ping but run no guest OS).
//
// The bug (fixed in confd's BIRD kernel-protocol import filter): on the node
// receiving a live-migrated workload, the kernel-learned local veth route
// (BIRD preference 10) loses to the stale /32 still advertised over BGP by
// the migration source (preference 100) until the source's veth is torn down
// (~9s). Remote nodes still converge onto the target (ADD-PATH exports the
// non-best local route with elevated local_pref), but the target's own RIB
// resolves recursive next-hops through the workload (e.g. a nested-cluster
// Service VIP) via the stale BGP route, refuses BGP-through-BGP recursion,
// and programs those routes as unreachable — dropping the very traffic the
// rest of the network correctly delivers to it. The fix raises the local
// route to preference 150 while Felix's route elevation (metric 512 <
// NormalRoutePriority) is active.

// Route-preference constants for the target-route test.
const (
	// localWorkloadRoutePreference is the preference confd's kernel-protocol
	// import filter assigns to an elevated local workload route: above a
	// normal remote BGP route (100), deliberately below an elevated remote
	// route (200).
	localWorkloadRoutePreference = 150
	// kernelDefaultRoutePreference is BIRD's default kernel-protocol
	// preference, in effect at rest when the filter's metric gate is false.
	kernelDefaultRoutePreference = 10

	// continuityMaxGap bounds the worst inter-arrival gap between genuine
	// delivery lines on a continuity probe. Sized to catch the ~9-13s
	// black-hole (stale /32 until source teardown) while tolerating the
	// ~1-3s cutover disruption plus scheduling jitter.
	continuityMaxGap = 6 * time.Second

	// contestPollInterval paces the target-node RIB polling: fast enough to
	// observe the stale-/32 overlap before the source's veth teardown ends it.
	contestPollInterval = 500 * time.Millisecond
	// contestSettleWindow is how long the winning state must then hold; kept
	// short so elevation-window polling (elevatedMetricTimeout) plus this
	// stays inside LiveMigrationRouteConvergenceTime (~30s from cutover).
	contestSettleWindow = 3 * time.Second

	targetRouteMigrationTimeout = 10 * time.Minute
)

// continuityProbe couples a stream checkpointer with a filter selecting
// genuine delivery lines ("seq=" data from the VM's TCP server, "bytes from"
// ping replies). The filter matters: during a black-hole, ping keeps printing
// "Destination Net Unreachable" lines at full cadence, so raw line counts
// would mask exactly the disruption this test exists to catch.
type continuityProbe struct {
	name   string
	cp     conncheck.StreamCheckpointer
	filter func(string) bool
}

// targetRouteTestParams parameterizes runTargetRouteMigrationTest per KubeVirt
// flavor (real QEMU vs MockVirt).
type targetRouteTestParams struct {
	vmName    string
	cloudInit string
	// preflight optionally blocks until vmIP is reachable from client. The nc
	// probe needs this: nc exits rc=1 on a refused connect while the VM's TCP
	// server is still booting, and that sticky error kills the stream.
	preflight func(ctx context.Context, client conncheck.Client, tester conncheck.ConnectionTester, vmIP string)
	// startProbe launches the continuity stream from client toward vmIP.
	startProbe func(ctx context.Context, client conncheck.Client, vmIP string) continuityProbe
	// contestGuardHard fails the test if the contested two-route state (stale
	// remote /32 present alongside the local route) was never observed. Real
	// KubeVirt holds the stale route for the ~9s virt-launcher teardown so
	// the window is reliably observable; MockVirt does not model that delay,
	// so its variant only logs.
	contestGuardHard bool
	// requireZeroSeqGaps additionally asserts countSequenceGaps == 0 over the
	// raw stream. Only for tcp-server "seq=N" streams: TCP retransmits
	// through a stall so gaps indicate real segment loss, whereas ping
	// sequence numbers legitimately skip on drops.
	requireZeroSeqGaps bool
	// setupRecursiveRoute, when non-nil, is called once the VM's IP is known and must arrange for
	// an external BGP speaker to advertise some prefix to the cluster with vmIP as its NEXT_HOP,
	// returning that prefix.  It stands in for a nested cluster inside the VM advertising a
	// Service VIP or pod CIDR over BGP, and turns this test from an assertion about BIRD
	// preference numbers into one about whether such a route still forwards.
	//
	// Left nil where no external BIRD peer exists in the environment, in which case the
	// recursive-next-hop assertions are skipped.
	setupRecursiveRoute func(ctx context.Context, vmIP string) string
}

// runTargetRouteMigrationTest runs the shared choreography. The stale /32
// only exists when the migration *source* is a non-owner of the IP's IPAM
// block, so migration 1 merely arms the condition (moves the VM off the block
// owner) and migration 2 — pinned to a third node that also hosts one of the
// client pods — is the observed one.
func runTargetRouteMigrationTest(ctx context.Context, f *framework.Framework, cli ctrlclient.Client, p targetRouteTestParams) {
	GinkgoHelper()
	ns := f.Namespace.Name

	By("Creating the VM")
	vm := &kubeVirtVM{name: p.vmName, namespace: ns, cloudInit: p.cloudInit}
	vm.Create(ctx, cli)
	DeferCleanup(func() { vm.Delete(cli) })
	vmIP, node1 := vm.WaitForRunningWithIP(ctx, cli)
	logrus.Infof("VM %s on %s with IP %s", p.vmName, node1, vmIP)

	// The VMI is Running with an IP, but the guest OS is still booting cloud-init
	// — which is what starts the TCP server. Migrating now would move a VM whose
	// server isn't up yet, so nothing answers after cutover (WaitForRunningWithIP
	// returns at phase=Running, well before the guest finishes booting). Gate on
	// reachability first, mirroring the iBGP test's pre-migration gate. The remote
	// client is pinned to node1 (the VM's current node), so create it here and
	// reuse it below as the mesh-crossing probe.
	remoteClient, remoteTester := setupNodePinnedPod(ctx, f, "remote-client", node1)
	if p.preflight != nil {
		By("Waiting for the VM's TCP server to be reachable before migration 1")
		p.preflight(ctx, remoteClient, remoteTester, vmIP)
	}

	// Stand up the nested-cluster prefix now, while the VM is still on its original node and
	// uncontested, and confirm it resolves there.  That establishes the harness works — the peer
	// really is imposing the VM's IP as NEXT_HOP and the nodes really are importing it — before
	// the post-migration assertions start treating it as a regression signal.  Without this
	// gate, a broken advertisement would look identical to a passing test.
	var recursivePrefix string
	if p.setupRecursiveRoute != nil {
		recursivePrefix = p.setupRecursiveRoute(ctx, vmIP)
		By(fmt.Sprintf("Verifying %s resolves via the VM on its original node %s", recursivePrefix, node1))
		Eventually(func(g Gomega) {
			expectRecursivePrefixResolved(g, f, node1, recursivePrefix, vmIP)
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	}

	By("Migrating the VM off the block owner (arms the stale-/32 condition)")
	vmim1 := newVMIMigration(p.vmName+"-migration1", ns, p.vmName)
	Expect(cli.Create(ctx, vmim1)).To(Succeed())
	DeferCleanup(func() { deleteVMIMigration(cli, vmim1) })
	expectMigrationSuccess(ctx, cli, vmim1)
	vmi := expectMigrationStatePopulated(ctx, cli, ns, p.vmName)
	node2 := vmi.Status.MigrationState.TargetNode
	Expect(node2).NotTo(Equal(node1), "VM didn't migrate off node 1")

	// Wait out migration 1's route elevation. If node2's veth were still at
	// the elevated metric when migration 2 cuts over, node2 would advertise
	// the stale /32 with elevated local_pref, the BGP import filter on the
	// new target would raise it to preference 200, and it would legitimately
	// beat the local route's 150 — invalidating the assertions below.
	By("Waiting for migration 1's route elevation to revert on node 2")
	Eventually(func() (int, error) {
		return queryWorkerMetric(f, node2, vmIP)
	}, metricRevertTimeout, 2*time.Second).Should(Equal(normalRouteMetric),
		"node2's kernel route metric should revert before the observed migration")

	node3 := pickThirdWorkerNode(ctx, f, node1, node2)

	// Remote client (pinned to node1, created before migration 1 above): its path
	// to the VM crosses the mesh, exercising the cutover re-convergence remote
	// nodes perform. Target client: pinned to migration 2's destination,
	// validating that a client colocated with the arriving VM keeps working via
	// the local veth. Note the primary regression signal is the RIB assertions
	// below, not these probes: plain /32 forwarding largely survives the
	// stale-best window (the target's FIB stays correct and ADD-PATH keeps remote
	// nodes converging), whereas the recursive-next-hop black-hole needs a
	// nested-BGP VIP to observe directly.
	targetClient, targetTester := setupNodePinnedPod(ctx, f, "target-client", node3)
	if p.preflight != nil {
		By("Waiting for the VM to be reachable from the target-node client pod")
		p.preflight(ctx, targetClient, targetTester, vmIP)
	}

	By("Starting continuity probes from both client pods")
	remoteProbe := p.startProbe(ctx, remoteClient, vmIP)
	DeferCleanup(func() { _ = remoteProbe.cp.Stop() })
	targetProbe := p.startProbe(ctx, targetClient, vmIP)
	DeferCleanup(func() { _ = targetProbe.cp.Stop() })
	probes := []continuityProbe{remoteProbe, targetProbe}
	for _, probe := range probes {
		waitForDeliveryLines(probe, 5, 2*time.Minute)
	}

	By(fmt.Sprintf("Migrating the VM a second time, pinned to node %s", node3))
	vmim2 := newVMIMigration(p.vmName+"-migration2", ns, p.vmName)
	vmim2.Spec.AddedNodeSelector = map[string]string{"kubernetes.io/hostname": node3}
	Expect(cli.Create(ctx, vmim2)).To(Succeed())
	DeferCleanup(func() { deleteVMIMigration(cli, vmim2) })
	expectMigrationSuccess(ctx, cli, vmim2)

	// The elevated state lasts LiveMigrationRouteConvergenceTime (~30s) from
	// cutover and the stale /32 lasts only until the source veth teardown, so
	// this is a single combined fast poll rather than sequential Eventually
	// blocks whose budgets would add up past the windows.
	By("Verifying the target node's BIRD RIB prefers the local workload route")
	contestSeen := false
	checkTargetRIB := func(g Gomega) {
		metric, err := queryWorkerMetric(f, node3, vmIP)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(metric).To(Equal(elevatedRouteMetric),
			"target kernel route metric should be elevated after migration")

		routes, err := queryWorkerBIRDRoute(f, node3, vmIP)
		g.Expect(err).NotTo(HaveOccurred())
		var local *bgp.BIRDRoute
		remotePresent := false
		for i := range routes {
			r := &routes[i]
			if r.Device {
				local = r
			} else {
				remotePresent = true
				g.Expect(r.Best).To(BeFalse(),
					"a remote route for the VM IP must not beat the local workload route (route: %+v)", *r)
			}
		}
		g.Expect(local).NotTo(BeNil(),
			"no local device route for the VM in the target's BIRD RIB (routes: %+v)", routes)
		if remotePresent {
			contestSeen = true // stale /32 observed alongside the local route
		}
		g.Expect(local.Best).To(BeTrue(), "local workload route should be selected best")
		g.Expect(local.Preference).To(Equal(localWorkloadRoutePreference),
			"local workload route should be raised to the elevated preference")

		// The consequence that actually matters: with the local route best, a route whose next
		// hop is the VM still resolves.  Checked in the same poll as the preference above so it
		// is asserted throughout the contested window rather than after it has passed.
		if recursivePrefix != "" {
			expectRecursivePrefixResolved(g, f, node3, recursivePrefix, vmIP)
		}
	}
	Eventually(checkTargetRIB, elevatedMetricTimeout, contestPollInterval).Should(Succeed())
	// The winning state must then hold for the rest of the overlap, not just once.
	Consistently(checkTargetRIB, contestSettleWindow, contestPollInterval).Should(Succeed())

	By("Verifying the target node's kernel FIB resolves the VM locally")
	pod3 := utils.GetCalicoNodePodOnNode(f.ClientSet, node3)
	Expect(pod3).NotTo(BeNil(), "no calico-node pod on %s", node3)
	out, err := utils.ExecInCalicoNode(pod3, fmt.Sprintf("ip route get %s", strings.Split(vmIP, "/")[0]))
	Expect(err).NotTo(HaveOccurred())
	Expect(out).To(ContainSubstring(" dev cali"),
		"kernel FIB on the target should resolve the VM via its local veth, got: %s", out)

	if recursivePrefix != "" {
		// The end of the chain: BIRD's RIB decision has to reach the FIB, because that is what
		// actually forwards.  Pre-fix this returns "RTNETLINK answers: Host is unreachable" —
		// packets from pods and host processes on this node are dropped locally even though the
		// VM is one veth away.
		By(fmt.Sprintf("Verifying the target node's kernel FIB forwards %s via the VM", recursivePrefix))
		recursiveIP := strings.Split(recursivePrefix, "/")[0]
		Eventually(func(g Gomega) {
			out, err := utils.ExecInCalicoNode(pod3, fmt.Sprintf("ip route get %s", recursiveIP))
			g.Expect(err).NotTo(HaveOccurred(), "ip route get %s failed: %s", recursiveIP, out)
			g.Expect(out).To(ContainSubstring("via "+strings.Split(vmIP, "/")[0]),
				"kernel FIB on the target should forward %s via the VM, got: %s", recursivePrefix, out)
			g.Expect(out).To(ContainSubstring(" dev cali"),
				"kernel FIB on the target should forward %s out the VM's veth, got: %s", recursivePrefix, out)
		}, 15*time.Second, 1*time.Second).Should(Succeed())
	}

	if p.contestGuardHard {
		Expect(contestSeen).To(BeTrue(),
			"never observed the stale remote /32 contesting the local route; the regression surface was not exercised (source teardown faster than polling?)")
	} else if !contestSeen {
		logrus.Warn("target-route test: stale remote /32 never observed in the target RIB; preference assertions passed but the contested state was not exercised")
	}

	By("Waiting for the route elevation to revert on the target node")
	Eventually(func() (int, error) {
		return queryWorkerMetric(f, node3, vmIP)
	}, metricRevertTimeout, 2*time.Second).Should(Equal(normalRouteMetric))

	By("Verifying the local route drops back to the kernel-default preference at rest")
	Eventually(func(g Gomega) {
		routes, err := queryWorkerBIRDRoute(f, node3, vmIP)
		g.Expect(err).NotTo(HaveOccurred())
		var local *bgp.BIRDRoute
		for i := range routes {
			if routes[i].Device {
				local = &routes[i]
			}
		}
		g.Expect(local).NotTo(BeNil())
		g.Expect(local.Best).To(BeTrue(), "local route should remain best at rest")
		g.Expect(local.Preference).To(Equal(kernelDefaultRoutePreference),
			"the preference raise must be a no-op once the metric reverts")
	}, 15*time.Second, 1*time.Second).Should(Succeed())

	By("Verifying both probes kept delivering and recovered quickly")
	for _, probe := range probes {
		base := probe.filteredCount()
		Eventually(probe.filteredCount, 15*time.Second, 500*time.Millisecond).Should(BeNumerically(">", base),
			"stream %s stopped delivering after convergence", probe.name)

		_ = probe.cp.Stop()
		Expect(probe.cp.Err()).NotTo(HaveOccurred(), "stream %s errored", probe.name)
		worst, n := probe.worstDeliveryGap()
		logrus.Infof("stream %s: %d delivery lines, worst inter-arrival gap %v", probe.name, n, worst)
		Expect(n).To(BeNumerically(">=", 10),
			"stream %s captured too few delivery lines for gap analysis", probe.name)
		Expect(worst).To(BeNumerically("<=", continuityMaxGap),
			"stream %s stalled for %v (bound %v) — the migration window black-holed traffic", probe.name, worst, continuityMaxGap)
		if p.requireZeroSeqGaps {
			gaps, lastSeq := countSequenceGaps(probe.cp.Lines())
			logrus.Infof("stream %s: %d sequence gaps, last seq=%d", probe.name, gaps, lastSeq)
			Expect(gaps).To(BeZero(), "stream %s dropped TCP segments across the migration", probe.name)
		}
	}
}

// filteredCount returns how many delivery lines the probe has captured.
func (p continuityProbe) filteredCount() int {
	n := 0
	for _, l := range p.cp.Lines() {
		if p.filter(l) {
			n++
		}
	}
	return n
}

// worstDeliveryGap returns the maximum inter-arrival gap between consecutive
// delivery lines and how many there were. It uses the stream's arrival
// timestamps, so a black-hole shows up as one large gap even though the
// retransmitted backlog arrives as a burst afterwards.
func (p continuityProbe) worstDeliveryGap() (time.Duration, int) {
	lines := p.cp.Lines()
	events := p.cp.Events()
	// Lines() and Events() are separate snapshots; trim to the shorter.
	m := len(lines)
	if len(events) < m {
		m = len(events)
	}
	var worst time.Duration
	var prev time.Time
	n := 0
	for i := 0; i < m; i++ {
		if !p.filter(lines[i]) {
			continue
		}
		if n > 0 {
			if gap := events[i].Sub(prev); gap > worst {
				worst = gap
			}
		}
		prev = events[i]
		n++
	}
	return worst, n
}

// waitForDeliveryLines blocks until the probe has captured at least n
// delivery lines, failing on stream error or timeout. The filtered analog of
// conncheck.WaitForCadence.
func waitForDeliveryLines(p continuityProbe, n int, within time.Duration) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		g.Expect(p.cp.Err()).NotTo(HaveOccurred(), "stream %s errored", p.name)
		g.Expect(p.filteredCount()).To(BeNumerically(">=", n))
	}, within, 500*time.Millisecond).Should(Succeed(),
		"stream %s did not reach %d delivery lines", p.name, n)
}

// setupNodePinnedPod deploys a client pod pinned to a specific node — the
// affinity dual of setupAntiAffinityPod. name must be unique per test since
// several pinned clients can coexist in one namespace.
func setupNodePinnedPod(ctx context.Context, f *framework.Framework, name, node string) (conncheck.Client, conncheck.ConnectionTester) {
	By(fmt.Sprintf("Creating client pod %s pinned to node %s", name, node))
	tester := conncheck.NewConnectionTester(f)
	DeferCleanup(tester.Stop)
	client := conncheck.NewClient(name, f.Namespace,
		conncheck.WithClientCustomizer(func(pod *corev1.Pod) {
			if pod.Spec.Affinity == nil {
				pod.Spec.Affinity = &corev1.Affinity{}
			}
			pod.Spec.Affinity.NodeAffinity = &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "kubernetes.io/hostname",
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{node},
						}},
					}},
				},
			}
		}),
	)
	tester.AddClient(client)
	tester.Deploy()
	pod := client.Pod()
	Expect(pod.Spec.NodeName).To(Equal(node), "client pod %s should be pinned to %s", name, node)
	return client, tester
}

// queryWorkerBIRDRoute returns the parsed BIRD RIB entries for the VM's /32
// on a worker node.
func queryWorkerBIRDRoute(f *framework.Framework, nodeName, vmIP string) ([]bgp.BIRDRoute, error) {
	return queryWorkerBIRDPrefix(f, nodeName, strings.Split(vmIP, "/")[0]+"/32")
}

// queryWorkerBIRDPrefix returns the parsed BIRD RIB entries for an exact prefix on a worker node,
// from "birdcl show route <prefix> all" inside the node's calico-node pod.
//
// The prefix is queried exactly rather than by longest-prefix lookup ("show route for <ip>"),
// because "for" silently falls back to a less specific net when the prefix itself is absent — on
// a node with no /32 for the VM it returns the default route — leaving the caller asserting on a
// different network than it asked about.
func queryWorkerBIRDPrefix(f *framework.Framework, nodeName, prefix string) ([]bgp.BIRDRoute, error) {
	pod := utils.GetCalicoNodePodOnNode(f.ClientSet, nodeName)
	if pod == nil {
		return nil, fmt.Errorf("no calico-node pod on %s", nodeName)
	}
	out, err := utils.ExecInCalicoNode(pod, fmt.Sprintf("birdcl show route %s all", prefix))
	if err != nil {
		return nil, fmt.Errorf("birdcl show route failed on %s: %w", nodeName, err)
	}
	return bgp.ParseBIRDRouteOutput(out), nil
}

// expectRecursivePrefixResolved asserts that prefix is in nodeName's BIRD RIB and resolves
// through the VM's local veth rather than being programmed unreachable.
//
// This is the direct regression signal for the bug the kernel-protocol import filter fixes.  The
// prefix is advertised with vmIP as its NEXT_HOP, so BIRD has to resolve it recursively against
// this node's RIB, and BIRD refuses to resolve a recursive next hop through another recursive
// (BGP) route.  While the stale /32 from the migration source is the best route for vmIP the
// prefix is therefore unreachable — black-holed on the very node now hosting the VM — and once
// the local veth route wins it resolves via cali*.
func expectRecursivePrefixResolved(g Gomega, f *framework.Framework, nodeName, prefix, vmIP string) {
	// Callers pass the VM address in either form; BIRD reports next hops as bare IPs.
	vmIP = strings.Split(vmIP, "/")[0]

	routes, err := queryWorkerBIRDPrefix(f, nodeName, prefix)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(routes).NotTo(BeEmpty(),
		"%s is not in %s's BIRD RIB at all; the external peer is not advertising it (or the node "+
			"is not importing it), so this test is not exercising recursive next-hop resolution",
		prefix, nodeName)

	var best *bgp.BIRDRoute
	for i := range routes {
		if routes[i].Best {
			best = &routes[i]
		}
	}
	g.Expect(best).NotTo(BeNil(), "no best route for %s on %s (routes: %+v)", prefix, nodeName, routes)
	g.Expect(best.BGPNextHop).To(Equal(vmIP),
		"%s should be advertised with the VM's IP as NEXT_HOP; got %q. Without a third-party "+
			"next hop there is no recursive resolution to test", prefix, best.BGPNextHop)
	g.Expect(best.Unreachable).To(BeFalse(),
		"%s is programmed unreachable on %s: BIRD could not resolve next hop %s, which is the "+
			"black-hole this test guards against (route: %+v)", prefix, nodeName, vmIP, *best)
	g.Expect(best.NextHop).To(Equal(vmIP),
		"%s should resolve via the VM's IP on %s (route: %+v)", prefix, nodeName, *best)
}
