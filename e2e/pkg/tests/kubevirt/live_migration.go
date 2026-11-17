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
	"errors"
	"fmt"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"k8s.io/kubernetes/test/e2e/framework"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/bgp"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
)

const (
	// handoverMigrationTimeout covers VM boot (up to 5m), one migration (up to
	// 5m) and the checks either side.
	handoverMigrationTimeout = 15 * time.Minute
	// sourceCleanTimeout covers the source virt-launcher teardown (~9s on real
	// KubeVirt) plus BIRD withdrawing the route, with headroom for a slow node.
	sourceCleanTimeout = 1 * time.Minute
)

// KubeVirt live migration e2e tests validate Calico's seamless migration support for
// KubeVirt VMs. The tests cover:
//   - Zero-downtime TCP connectivity through iBGP during migration (Test 1)
//   - Target-node BIRD route preference during migration (Test 2)
//   - Zero-downtime TCP connectivity from an eBGP external client (Test 3)
//   - One IPAM owner through the handover, and no stale route or BGP export
//     left on the source node (N1, N3)
//
// Prerequisites:
//   - KubeVirt installed with live migration support
//   - IPAMConfig.kubeVirtVMAddressPersistence set to "Enabled"
//   - At least 2 schedulable worker nodes (3 recommended for double-migration tests)
//   - For Test 3: an external TOR node with BIRD eBGP peering (EXT_IP, EXT_KEY, EXT_USER)
//
// All tests are parallel-safe. eBGP uses random suffixes for its
// cluster-scoped resources and treats natOutgoing=false on the VM IPPool
// as a provisioning precondition.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("KubeVirt"),
	describe.RequiresRealKubeVirt(),
	describe.WithCategory(describe.Networking),
	"KubeVirt live migration",
	func() {
		f := utils.NewDefaultFramework("calico-kubevirt")

		var cli ctrlclient.Client

		BeforeEach(func() {
			// Live migration needs at least 2 nodes to migrate between.
			utils.RequireNodeCount(f, 2)

			var err error
			cli, err = e2eclient.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to build controller-runtime client")
		})

		// Test 1: TCP stream over iBGP must not lose any "seq=N" segments across two
		// consecutive cross-node live migrations on a 3-worker cluster (server VM hops,
		// client pod stays put).
		It("should maintain TCP connection over iBGP across two consecutive live migrations", func() {
			if isMockVirtDeployed(f) {
				Fail("This test requires real KubeVirt with QEMU-backed VMs for TCP connectivity; MockVirt does not run a guest OS")
			}
			ctx, cancel := context.WithTimeout(context.Background(), doubleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name
			serverVMName := "e2e-tcp-double-srv"
			serverVM := &kubeVirtVM{name: serverVMName, namespace: ns, cloudInit: tcpServerCloudInit}

			By("Creating server VM with TCP server")
			serverVM.Create(ctx, cli)
			DeferCleanup(func() { serverVM.Delete(cli) })

			serverIP, node1 := serverVM.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("Server VM: %s on %s", serverIP, node1)

			By("Creating client pod on a different node than server VM")
			clientConn, clientTester := setupAntiAffinityPod(ctx, f, node1)
			clientPod := clientConn.Pod()

			// Pre-flight reachability gate. The streaming probe's nc will
			// exit rc=1 on a refused connect (cold-boot VM not yet bound to
			// 9999), and that sticky stream error makes WaitForCadence fail
			// immediately. Wait until TCP is reachable before starting it.
			By("Waiting for VM TCP server to be reachable from client pod")
			vmTarget := conncheck.NewTCPConnectTarget(serverIP, 9999)
			clientTester.WithTimeout(2 * time.Minute)
			clientTester.ExpectSuccess(clientConn, vmTarget)
			clientTester.Execute()
			clientTester.ResetExpectations()

			By("Starting TCP client stream probe")
			probe := conncheck.StartStream(ctx, "tcp-stream",
				conncheck.NewPodSource(f, clientConn),
				conncheck.WithStreamCommand("nc", serverIP, "9999"))
			DeferCleanup(func() { _ = probe.Stop() })

			By("Verifying TCP data is flowing before migration")
			conncheck.WaitForCadence(ctx, probe, 5, 30*time.Second)
			preLines := len(probe.Lines())
			logrus.Infof("Pre-migration: %d lines on client pod", preLines)

			By("Migrating the VM")
			vmim1 := newVMIMigration(serverVMName+"-migration1", ns, serverVMName)
			Expect(cli.Create(ctx, vmim1)).To(Succeed())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim1) })
			expectMigrationSuccess(ctx, cli, vmim1)
			vmi := &kubevirtv1.VirtualMachineInstance{}
			Expect(cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: serverVMName}, vmi)).To(Succeed())
			node2 := vmi.Status.NodeName
			Expect(node2).NotTo(Equal(node1), "VM didn't migrate off node 1")

			By("Verifying TCP stream survived first migration")
			Eventually(probe.NumLines,
				30*time.Second, 2*time.Second).Should(BeNumerically(">=", preLines+5),
				"TCP data should have grown after first migration")
			midLines := len(probe.Lines())
			logrus.Infof("After first migration: %d lines", midLines)

			By("Migrating the VM a second time")
			vmim2 := newVMIMigration(serverVMName+"-migration2", ns, serverVMName)
			Expect(cli.Create(ctx, vmim2)).To(Succeed())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim2) })
			expectMigrationSuccess(ctx, cli, vmim2)
			Expect(cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: serverVMName}, vmi)).To(Succeed())
			node3 := vmi.Status.NodeName
			// With 3 worker nodes, second migration moves away from node2.
			// It could return to node1 — that's fine, we only require it left node2.
			Expect(node3).NotTo(Equal(node2), "VM didn't migrate off node 2")
			// Also require the server lands on a different node than the
			// client pod. Otherwise the post-migration "iBGP cross-node"
			// claim degrades to a same-node loopback path, which would
			// trivially have zero seq gaps regardless of routing behaviour.
			Expect(node3).NotTo(Equal(clientPod.Spec.NodeName),
				"server was scheduled to the same node as the client")

			By("Waiting for TCP data to grow after second migration")
			Eventually(probe.NumLines,
				30*time.Second, 2*time.Second).Should(BeNumerically(">=", midLines+5),
				"TCP data should have grown after second migration")

			By("Checking sequence continuity")
			_ = probe.Stop()
			Expect(probe.Err()).NotTo(HaveOccurred())
			lines := probe.Lines()
			logrus.Infof("TCP stream: %d lines, first: %s, last: %s",
				len(lines), lines[0], lines[len(lines)-1])

			seqGaps, lastSeq := countSequenceGaps(lines)
			logrus.Infof("Sequence: %d gaps, %d data points across 2 migrations", seqGaps, lastSeq)
			Expect(seqGaps).To(BeNumerically("==", 0),
				"seamless live migration must not drop any TCP segments")
		})

		// Test 2: target-node route preference. On the node receiving a
		// migrated VM, BIRD must prefer the VM's local veth route (raised to
		// preference 150 while Felix's route elevation is active) over the
		// stale /32 still advertised by the migration source, and clients
		// must see only a brief cutover disruption — not the ~9s black-hole
		// that lasts until the source's veth teardown. Shared choreography in
		// live_migration_target_route.go; MockVirt runs an ICMP variant.
		It("should prefer the local workload route on the migration target node", func() {
			if isMockVirtDeployed(f) {
				Fail("This test requires real KubeVirt with QEMU-backed VMs for TCP connectivity; MockVirt does not run a guest OS")
			}
			utils.RequireNodeCount(f, 3)
			ctx, cancel := context.WithTimeout(context.Background(), targetRouteMigrationTimeout)
			defer cancel()

			runTargetRouteMigrationTest(ctx, f, cli, targetRouteTestParams{
				vmName:    "e2e-target-route",
				cloudInit: tcpServerCloudInit,
				preflight: func(ctx context.Context, client conncheck.Client, tester conncheck.ConnectionTester, vmIP string) {
					tester.WithTimeout(2 * time.Minute)
					tester.ExpectSuccess(client, conncheck.NewTCPConnectTarget(vmIP, 9999))
					tester.Execute()
					tester.ResetExpectations()
				},
				startProbe: func(ctx context.Context, client conncheck.Client, vmIP string) continuityProbe {
					name := "tcp-stream-" + client.Name()
					cp := conncheck.StartStream(ctx, name,
						conncheck.NewPodSource(f, client),
						conncheck.WithStreamCommand("nc", vmIP, "9999"))
					return continuityProbe{name: name, cp: cp, filter: func(l string) bool {
						return strings.HasPrefix(l, "seq=")
					}}
				},
				contestGuardHard:   true,
				requireZeroSeqGaps: true,
			})
		})

		// Test 3: same as Test 2 but the client runs on an external TOR over eBGP.
		// Validates that elevated krt_metric on the target node propagates via eBGP to
		// flip the TOR's kernel next-hop without dropping the TCP stream, and that
		// priority correctly reverts and re-elevates across two consecutive migrations.
		// Requires EXT_IP, EXT_KEY, EXT_USER.
		framework.Context("eBGP external client", describe.WithExternalNode(), func() {
			It("should maintain TCP connection from eBGP external client across two consecutive migrations", func() {
				if isMockVirtDeployed(f) {
					Fail("This test requires real KubeVirt with QEMU-backed VMs for TCP connectivity; MockVirt does not run a guest OS")
				}
				tor := externalnode.MustNewClient()

				ctx, cancel := context.WithTimeout(context.Background(), eBGPDoubleMigrationTimeout)
				defer cancel()
				ns := f.Namespace.Name

				// Precondition: natOutgoing must be false on the IPv4 pools backing VM
				// workloads. If true, natOutgoing rewrites the VM's source IP to the
				// node's IP at egress NAT and breaks the TOR's reverse-path matching
				// after migration. The pipeline that runs this test is expected to
				// configure the pool with natOutgoing=false at provisioning time; we
				// only verify here so the failure mode is obvious.
				By("Verifying natOutgoing=false on the cluster's IPv4 IP pools")
				pools, err := utils.IPPoolsForFamily(ctx, cli, false)
				Expect(err).NotTo(HaveOccurred(), "list IP pools")
				Expect(pools).NotTo(BeEmpty(), "cluster has no IPv4 IP pool for VM workloads")
				for _, pool := range pools {
					Expect(pool.Spec.NATOutgoing).To(BeFalse(),
						"IPPool %q must have natOutgoing=false (set by cluster provisioning)", pool.Name)
				}

				By("Setting up eBGP peering between TOR and cluster nodes")
				torPeer := setupKubeVirtEBGPPeering(f, tor)

				vmName := "e2e-ebgp-tcp"
				vm := &kubeVirtVM{name: vmName, namespace: ns, cloudInit: tcpServerCloudInit}

				By("Creating a VM with TCP server")
				vm.Create(ctx, cli)
				DeferCleanup(func() { vm.Delete(cli) })

				vmIP, node1 := vm.WaitForRunningWithIP(ctx, cli)
				logrus.Infof("VM %s on %s with IP %s", vmName, node1, vmIP)

				By("Verifying TOR can reach the VM (eBGP routing is up)")
				Eventually(func() error {
					out, err := runOnExternalNode(tor, fmt.Sprintf("ping -c 1 -W 2 %s", vmIP))
					if err != nil {
						routes, _ := runOnExternalNode(tor, "sudo docker exec tor-bird birdcl show route")
						logrus.Infof("TOR BIRD routes:\n%s", routes)
						kernRoutes, _ := runOnExternalNode(tor, fmt.Sprintf("ip route get %s 2>&1", vmIP))
						logrus.Infof("TOR kernel route to %s: %s", vmIP, kernRoutes)
						return fmt.Errorf("ping %s failed: %v (output=%s)", vmIP, err, out)
					}
					return nil
				}, 2*time.Minute, 5*time.Second).Should(Succeed(),
					"TOR cannot reach VM — eBGP routing may not be configured")

				By("Waiting for TCP server on VM to be reachable from TOR")
				const ncClientContainer = "tor-nc-client"
				Eventually(func() error {
					out, _ := runOnExternalNode(tor, fmt.Sprintf(
						"sudo docker run --rm --network host alpine sh -c 'sleep 999 | timeout 5 nc %s 9999' 2>&1", vmIP))
					if !strings.Contains(out, "seq=") {
						return fmt.Errorf("TCP server not sending data from TOR (output=%q)", out)
					}
					return nil
				}, 2*time.Minute, 5*time.Second).Should(Succeed(),
					"TCP server not reachable from TOR")
				logrus.Infof("TCP server on %s:9999 is reachable and sending data from TOR", vmIP)

				By(fmt.Sprintf("Starting TCP client container %s on TOR", ncClientContainer))
				probe := conncheck.StartStream(ctx, "tor-tcp-stream",
					externalnode.NewContainerSource(tor, ncClientContainer, images.Alpine, "--network", "host"),
					conncheck.WithStreamCommand("sh", "-c", fmt.Sprintf("'sleep 999999 | nc %s 9999'", vmIP)))
				DeferCleanup(func() { _ = probe.Stop() })

				By("Waiting for TCP data to flow before migration")
				conncheck.WaitForCadence(ctx, probe, 5, 2*time.Minute)
				preLines := len(probe.Lines())
				logrus.Infof("Pre-migration: %d lines on TOR client", preLines)
				preTime := time.Now()

				By("Starting first migration")
				vmim1 := newVMIMigration(vmName+"-migration1", ns, vmName)
				Expect(cli.Create(ctx, vmim1)).To(Succeed())
				DeferCleanup(func() { deleteVMIMigration(cli, vmim1) })
				expectMigrationSuccess(ctx, cli, vmim1)
				vmi := expectMigrationStatePopulated(ctx, cli, ns, vmName)
				node2 := vmi.Status.MigrationState.TargetNode
				Expect(node2).NotTo(Equal(node1), "VM didn't migrate off node 1")

				// migration.WaitForSuccess returns the moment the VMIM phase is
				// Succeeded, but Felix programs krt_metric=512 asynchronously and
				// later reverts it after LiveMigrationRouteConvergenceTime (~30s).
				// Poll for the elevated state with a budget shorter than the
				// revert window so we observe it deterministically.
				By("Verifying elevated route priority on worker and TOR after first migration")
				Eventually(func(g Gomega) {
					m, err := queryWorkerMetric(f, node2, vmIP)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(m).To(Equal(elevatedRouteMetric),
						"worker kernel metric should be elevated (512) after migration")
					st := torPeer.QueryRoute(vmIP)
					g.Expect(st.Has32).To(BeTrue(), "TOR should have /32 after migration")
					g.Expect(st.Routes).To(HaveLen(1), "should be single /32 route (no ECMP)")
					g.Expect(st.Routes[0].LocalPref).To(Equal(elevatedLocalPref), "TOR /32 should have elevated local_pref")
					g.Expect(st.Routes[0].Community).To(Equal(migrationCommunityTag), "TOR /32 should have community tag")
				}, elevatedMetricTimeout, 1*time.Second).Should(Succeed())

				// Wait for the elevated /32 route to revert to normal local_pref
				// after the LiveMigrationRouteConvergenceTime (default 30s) expires.
				By("Waiting for TOR /32 local_pref to revert to normal after convergence")
				Eventually(func() int {
					snap := torPeer.QuerySnapshot(vmIP)
					if len(snap.Host32.Routes) > 0 {
						return snap.Host32.Routes[0].LocalPref
					}
					return -1
				}, metricRevertTimeout, 2*time.Second).Should(Equal(normalLocalPref),
					"TOR /32 local_pref should revert to 100 after convergence")

				midLines := len(probe.Lines())
				Expect(midLines).To(BeNumerically(">", preLines), "TCP should still be flowing after first migration")

				// Pin migration 2 to a fresh worker via VMIM.Spec.AddedNodeSelector so
				// we exercise a brand-new /32 route. Per-VMIM scope, no cluster-wide
				// cordon to leak.
				thirdNode := pickThirdWorkerNode(ctx, f, node1, node2)

				By(fmt.Sprintf("Migrating the VM a second time, pinned to node %s", thirdNode))
				vmim2 := newVMIMigration(vmName+"-migration2", ns, vmName)
				vmim2.Spec.AddedNodeSelector = map[string]string{
					"kubernetes.io/hostname": thirdNode,
				}
				Expect(cli.Create(ctx, vmim2)).To(Succeed())
				DeferCleanup(func() { deleteVMIMigration(cli, vmim2) })
				expectMigrationSuccess(ctx, cli, vmim2)
				vmi = expectMigrationStatePopulated(ctx, cli, ns, vmName)
				node3 := vmi.Status.MigrationState.TargetNode
				Expect(node3).NotTo(Equal(node2), "VM didn't migrate off node 2")

				// Same race as after the first migration: Felix programs the
				// elevated metric asynchronously and reverts it after the
				// convergence window. Poll for the elevated state.
				By("Verifying TOR route state after second migration")
				Eventually(func(g Gomega) {
					st := torPeer.QueryRoute(vmIP)
					g.Expect(st.Has32).To(BeTrue(), "TOR should have /32 after second migration")
					// Find best route — it must have elevated local_pref (no ECMP).
					var b, nb *bgp.BIRDRoute
					for i := range st.Routes {
						if st.Routes[i].Best {
							b = &st.Routes[i]
						} else {
							nb = &st.Routes[i]
						}
					}
					g.Expect(b).NotTo(BeNil(), "TOR should have a best /32 route")
					g.Expect(b.LocalPref).To(Equal(elevatedLocalPref), "best /32 route should have elevated local_pref")
					g.Expect(b.Community).To(Equal(migrationCommunityTag), "best /32 route should have community tag")
					// After the second migration, two /32 routes must exist: the new
					// node's elevated route and the old node's normal route. They
					// must have different local_pref to avoid ECMP.
					g.Expect(nb).NotTo(BeNil(), "TOR should have two /32 routes after second migration")
					g.Expect(nb.LocalPref).NotTo(Equal(b.LocalPref),
						"two /32 routes must have different local_pref to avoid ECMP")
				}, elevatedMetricTimeout, 1*time.Second).Should(Succeed())

				// Wait for the second migration's /32 route to revert to normal
				// local_pref, same as after the first migration.
				By("Waiting for TOR /32 local_pref to revert after second migration")
				Eventually(func() int {
					snap := torPeer.QuerySnapshot(vmIP)
					if len(snap.Host32.Routes) > 0 {
						return snap.Host32.Routes[0].LocalPref
					}
					return -1
				}, metricRevertTimeout, 2*time.Second).Should(Equal(normalLocalPref),
					"TOR /32 local_pref should revert to 100 after second migration convergence")

				finalLines := len(probe.Lines())
				Expect(finalLines).To(BeNumerically(">", midLines),
					"TCP stream should have continued growing after second migration (final=%d, mid=%d)", finalLines, midLines)

				By("Verifying TCP stream integrity")
				_ = probe.Stop()
				Expect(probe.Err()).NotTo(HaveOccurred())
				lines := probe.Lines()
				logrus.Infof("TIMELINE: total lines=%d, first=%s, last=%s", len(lines), lines[0], lines[len(lines)-1])
				// Show the last 30 lines for quick inspection.
				start := 0
				if len(lines) > 30 {
					start = len(lines) - 30
				}
				logrus.Infof("TIMELINE: tail of stream:\n%s", strings.Join(lines[start:], "\n"))

				seqGaps, lastSeq := countSequenceGaps(lines)
				elapsed := time.Since(preTime).Seconds()
				logrus.Infof("Sequence: %d gaps, last seq=%d, elapsed=%.0fs across 2 eBGP migrations",
					seqGaps, lastSeq, elapsed)
				Expect(seqGaps).To(BeNumerically("==", 0),
					"eBGP live migration must not drop any TCP segments")
				// The server sends seq=N once per second. The actual count should be
				// within 80% of the elapsed wall-clock time — allowing for connection
				// setup delay and scheduling jitter but catching major data loss.
				Expect(lastSeq).To(BeNumerically(">=", int(elapsed*0.8)),
					fmt.Sprintf("TCP seq count (%d) too low for elapsed time (%.0fs)", lastSeq, elapsed))
			})
		})

		// N1, N3: once the VM has left, the source node must neither route to it
		// locally nor advertise it, or traffic can be drawn back to a node that no
		// longer hosts it. Through the handover IPAM must keep one allocation with
		// one active owner, handed over once: two owners, or an owner flapping
		// back, is what lets GC free an address still in use. Sampling at 1s can
		// miss a sub-second window: passing means none was seen. Felix answers
		// proxy ARP from userspace, which no node-side check here can observe.
		It("should hand IPAM ownership over once and leave no route or BGP export on the source node", func() {
			if isMockVirtDeployed(f) {
				Fail("This test requires real KubeVirt: MockVirt doesn't tear down a source pod")
			}
			ctx, cancel := context.WithTimeout(context.Background(), handoverMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-handover"
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })
			vmIP, sourceNode := vm.WaitForRunningWithIP(ctx, cli)
			sourcePod, err := vm.FindVirtLauncherPod(ctx, f)
			Expect(err).NotTo(HaveOccurred(), "find source virt-launcher pod")
			logrus.Infof("VM %s on %s (pod %s) with IP %s", vmName, sourceNode, sourcePod.Name, vmIP)

			lcgc := newLibcalicoClient(f)
			handleID := vmipam.CreateVMHandleID("k8s-pod-network", ns, vmName)

			// Without this baseline the "gone afterwards" checks below would pass on
			// a node that never had the state.
			By("Verifying the source node routes the VM locally, in the kernel and in BIRD, before migration")
			Eventually(func() error {
				routes, err := kernelRoutes(f, sourceNode, vmIP)
				if err != nil {
					return err
				}
				if len(localRoutes(routes)) != 1 {
					return fmt.Errorf("want one local route for %s on %s, got %q", vmIP, sourceNode, routes)
				}
				birdRoutes, err := queryWorkerBIRDRoute(f, sourceNode, vmIP)
				if err != nil {
					return err
				}
				for _, r := range birdRoutes {
					if r.Device {
						return nil
					}
				}
				return fmt.Errorf("BIRD on %s has no local route for %s/32 yet: %+v", sourceNode, vmIP, birdRoutes)
			}, 1*time.Minute, 2*time.Second).Should(Succeed())

			By("Waiting for the source pod to be the active IPAM owner")
			Eventually(func() error {
				owner, err := sampleIPAMOwner(ctx, lcgc, handleID, vmIP)
				if err != nil {
					return err
				}
				if owner != sourcePod.Name {
					return fmt.Errorf("active owner is %q, want source pod %q", owner, sourcePod.Name)
				}
				return nil
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("Migrating the VM while sampling IPAM ownership every second")
			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			Expect(cli.Create(ctx, vmim)).To(Succeed(), "create VMIM")
			DeferCleanup(func() { deleteVMIMigration(cli, vmim) })

			// Owner promotion can trail the VMIM's Succeeded phase, so sampling
			// carries on until the target owns the address, for at most this long.
			const promotionGrace = 1 * time.Minute
			owners := []string{sourcePod.Name}
			var targetPod, targetNode string
			var succeededAt time.Time
			samples, apiErrors := 0, 0
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				owner, err := sampleIPAMOwner(ctx, lcgc, handleID, vmIP)
				samples++
				if err != nil {
					// An ownership violation fails at once; an API blip only if it persists.
					Expect(errors.Is(err, errOwnership)).To(BeFalse(),
						"sample %d during the handover: %v (owners so far %v)", samples, err, owners)
					apiErrors++
					Expect(apiErrors).To(BeNumerically("<", 3),
						"IPAM unreadable for %d samples in a row during the handover: %v", apiErrors, err)
					select {
					case <-ctx.Done():
						Fail(fmt.Sprintf("timed out sampling the handover; owners seen: %v", owners))
					case <-ticker.C:
					}
					continue
				}
				apiErrors = 0
				if owner != owners[len(owners)-1] {
					owners = append(owners, owner)
					logrus.Infof("IPAM active owner of %s changed to %s after %d samples", vmIP, owner, samples)
				}

				// Get errors here are retried on the next tick; the deadlines below
				// bound how long that can go on.
				if targetPod == "" || targetNode == "" {
					vmi := &kubevirtv1.VirtualMachineInstance{}
					if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: vmName}, vmi); err == nil && vmi.Status.MigrationState != nil {
						targetPod = vmi.Status.MigrationState.TargetPod
						targetNode = vmi.Status.MigrationState.TargetNode
					}
				}
				if succeededAt.IsZero() {
					got := &kubevirtv1.VirtualMachineInstanceMigration{}
					if err := cli.Get(ctx, ctrlclient.ObjectKeyFromObject(vmim), got); err == nil {
						Expect(got.Status.Phase).NotTo(Equal(kubevirtv1.MigrationFailed), "migration failed; IPAM owners seen: %v", owners)
						if got.Status.Phase == kubevirtv1.MigrationSucceeded {
							succeededAt = time.Now()
						}
					}
				}
				if !succeededAt.IsZero() && targetPod != "" && owner == targetPod {
					break
				}
				if !succeededAt.IsZero() && time.Since(succeededAt) > promotionGrace {
					Fail(fmt.Sprintf("target pod %q not the active IPAM owner %v after the migration succeeded; owners seen: %v",
						targetPod, promotionGrace, owners))
				}
				select {
				case <-ctx.Done():
					Fail(fmt.Sprintf("timed out sampling the handover; owners seen: %v", owners))
				case <-ticker.C:
				}
			}

			logrus.Infof("IPAM owners of %s across %d samples: %v", vmIP, samples, owners)
			Expect(owners).To(Equal([]string{sourcePod.Name, targetPod}),
				"the active owner should switch from the source pod to the target pod exactly once")
			Expect(targetNode).NotTo(Equal(sourceNode), "VM didn't migrate off the source node")

			// The source pod's teardown (~9s after cutover) runs CNI DEL against the
			// same handle; ownership must not move back or lapse when it does.
			By("Verifying the target keeps ownership through the source pod's teardown")
			Consistently(func() error {
				owner, err := sampleIPAMOwner(ctx, lcgc, handleID, vmIP)
				if err != nil && !errors.Is(err, errOwnership) {
					logrus.Warnf("ignoring unreadable IPAM sample: %v", err)
					return nil
				}
				if err != nil {
					return err
				}
				if owner != targetPod {
					return fmt.Errorf("active owner moved from target %q to %q", targetPod, owner)
				}
				return nil
			}, 30*time.Second, 1*time.Second).Should(Succeed())

			// Then held, so a late re-add by a lingering source pod is caught too.
			By(fmt.Sprintf("Verifying source node %s has no route or BIRD export for %s", sourceNode, vmIP))
			Eventually(func() error { return sourceNodeState(f, sourceNode, vmIP) },
				sourceCleanTimeout, 2*time.Second).Should(Succeed())
			Consistently(func() error {
				err := sourceNodeState(f, sourceNode, vmIP)
				if err != nil && !errors.Is(err, errStaleState) {
					logrus.Warnf("ignoring unreadable source node state: %v", err)
					return nil
				}
				return err
			}, 15*time.Second, 3*time.Second).Should(Succeed())

			// Two kernel routes to the same /32 at different metrics would let a
			// stale one win as soon as the elevated metric reverts.
			By(fmt.Sprintf("Verifying target node %s has exactly one route for %s", targetNode, vmIP))
			Eventually(func() error {
				routes, err := kernelRoutes(f, targetNode, vmIP)
				if err != nil {
					return err
				}
				if len(routes) != 1 || len(localRoutes(routes)) != 1 {
					return fmt.Errorf("want exactly one route, via a local veth, for %s on %s; got %q", vmIP, targetNode, routes)
				}
				return nil
			}, metricRevertTimeout, 2*time.Second).Should(Succeed())
		})
	},
)

// errStaleState marks state the source node still holds, as opposed to a
// failure to read it.
var errStaleState = errors.New("stale state on source node")

// sourceNodeState returns an error describing any state the source node still
// holds for the VM: a local kernel route, or a BIRD route it would export (BIRD
// exports the device routes it learns from the kernel).
func sourceNodeState(f *framework.Framework, nodeName, vmIP string) error {
	ip := strings.Split(vmIP, "/")[0]
	routes, err := kernelRoutes(f, nodeName, vmIP)
	if err != nil {
		return err
	}
	if local := localRoutes(routes); len(local) != 0 {
		return fmt.Errorf("%w: kernel still routes %s locally on %s: %q", errStaleState, ip, nodeName, local)
	}

	birdRoutes, err := queryWorkerBIRDRoute(f, nodeName, vmIP)
	if err != nil {
		return err
	}
	for _, r := range birdRoutes {
		if r.Device {
			return fmt.Errorf("%w: BIRD on %s still has a local route for %s/32 to export: %+v", errStaleState, nodeName, ip, r)
		}
	}
	return nil
}
