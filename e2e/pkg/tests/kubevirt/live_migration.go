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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// KubeVirt live migration e2e tests validate Calico's seamless migration support for
// KubeVirt VMs. The tests cover:
//   - IPAM attribute ownership handover (Test 1)
//   - Zero-downtime TCP connectivity through iBGP and eBGP during migration (Tests 2-3)
//   - Kubernetes NetworkPolicy enforcement survives migration (Test 4)
//
// Prerequisites:
//   - KubeVirt installed with live migration support
//   - IPAMConfig.kubeVirtVMAddressPersistence set to "Enabled"
//   - At least 2 schedulable worker nodes (3 recommended for double-migration tests)
//   - For Test 3: an external TOR node with BIRD eBGP peering (EXT_IP, EXT_KEY, EXT_USER)
//
// The live-migration tests mutate cluster-global state — the Installation
// resource (natOutgoing), global BGPPeer/BGPFilter resources with fixed names
// (kubevirt-lm, tor-ebgp-peer), and BIRD configuration on the TOR. They must
// not run in parallel with each other or with other tests that touch Calico
// configuration.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("KubeVirt"),
	describe.WithCategory(describe.Networking),
	describe.WithSerial(),
	"KubeVirt live migration",
	func() {
		f := utils.NewDefaultFramework("calico-kubevirt")

		var cli ctrlclient.Client

		BeforeEach(func() {
			// Live migration needs at least 2 nodes to migrate between.
			utils.RequireNodeCount(f, 2)

			// Fail fast (with a pointer to the doc workaround) when Typha is
			// in the missing-CRD backoff for LiveMigration. Otherwise the
			// real failure surfaces 5 minutes into the test as a confusing
			// route or TCP-stream timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			requireTyphaWatchingLiveMigrations(ctx, f)

			var err error
			cli, err = e2eclient.NewAPIClient(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to build controller-runtime client")
		})

		// Test 1: Target pod is promoted to active IPAM owner after migration.
		// Validates the IPAM dual-owner mechanism by comparing the owner attributes
		// before and after migration:
		//
		//   Before:  Active=source,  Alternate=empty
		//   After:   Active=target,  Alternate=empty    (Felix EnsureActiveVMOwnerAttrs)
		//
		// The test positively asserts that the final active owner matches the real
		// target pod and node, not just that it differs from the source.
		It("should promote target pod to active IPAM owner after migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-attr-promote"
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })
			originalIP, sourceNode := vm.WaitForRunningWithIP(ctx, cli)

			sourcePod, err := vm.FindVirtLauncherPod(ctx, f)
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("Source pod: %s on %s, IP: %s", sourcePod.Name, sourceNode, originalIP)

			lcgc := newLibcalicoClient(f)

			By("Verifying IPAM attributes before migration (Active=source, Alternate=empty)")
			Eventually(func() error {
				active, alternate, err := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
				if err != nil {
					return err
				}
				if active[model.IPAMBlockAttributePod] != sourcePod.Name {
					return fmt.Errorf("ActiveOwnerAttrs[pod]=%q, want %q",
						active[model.IPAMBlockAttributePod], sourcePod.Name)
				}
				if active[model.IPAMBlockAttributeNode] != sourceNode {
					return fmt.Errorf("ActiveOwnerAttrs[node]=%q, want %q",
						active[model.IPAMBlockAttributeNode], sourceNode)
				}
				if len(alternate) != 0 {
					return fmt.Errorf("AlternateOwnerAttrs should be empty before migration, got %v", alternate)
				}
				return nil
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("Migrating the VM")
			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			err = cli.Create(ctx, vmim)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { deleteVMIMigration(cli,vmim) })
			waitForMigrationSuccess(ctx, cli, vmim)

			// Read the target pod and node directly from the VMI's MigrationState,
			// which KubeVirt populates with the source/target identifiers as part of
			// the migration. waitForMigrationStatePopulated polls until virt-handler
			// finishes writing the state (it can lag the VMIM Succeeded phase).
			vmi := waitForMigrationStatePopulated(ctx, cli, ns, vmName)
			targetPodName := vmi.Status.MigrationState.TargetPod
			targetNode := vmi.Status.MigrationState.TargetNode
			Expect(targetPodName).NotTo(Equal(sourcePod.Name), "target pod should be a new pod")
			Expect(targetNode).NotTo(Equal(sourceNode), "VM should have moved to a different node")
			logrus.Infof("Target pod: %s on %s", targetPodName, targetNode)

			By("Verifying target pod has the original IP")
			targetPod, err := f.ClientSet.CoreV1().Pods(ns).Get(ctx, targetPodName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(targetPod.Status.PodIP).To(Equal(originalIP),
				"target pod IP should match original VM IP")

			By("Verifying Active=target and Alternate=empty after swap")
			Eventually(func() error {
				active, alternate, err := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
				if err != nil {
					return err
				}
				if active[model.IPAMBlockAttributePod] != targetPodName {
					return fmt.Errorf("ActiveOwnerAttrs[pod]=%q, want %q",
						active[model.IPAMBlockAttributePod], targetPodName)
				}
				if active[model.IPAMBlockAttributeNode] != targetNode {
					return fmt.Errorf("ActiveOwnerAttrs[node]=%q, want %q",
						active[model.IPAMBlockAttributeNode], targetNode)
				}
				if len(alternate) != 0 {
					return fmt.Errorf("AlternateOwnerAttrs should be cleared after promotion, got %v", alternate)
				}
				return nil
			}, 1*time.Minute, 2*time.Second).Should(Succeed())
			logrus.Infof("After promotion: Active pod=%s node=%s (was %s on %s)",
				targetPodName, targetNode, sourcePod.Name, sourceNode)
		})

		// Test 2: TCP connection over iBGP survives two consecutive migrations.
		// This is the key seamless migration test. A server VM runs a TCP server that sends
		// "seq=N" every second. A client pod on a different node connects via nc and logs
		// the stream. The server VM is migrated twice across 3 worker nodes. After both
		// migrations, the TCP stream must have zero sequence gaps — proving that Felix's
		// live migration FSM (Target→Live→TimeWait→Base), GARP/RARP detection, elevated
		// BGP route priority, and ARP suppression all work together to maintain connectivity
		// with no packet loss during the handover.
		It("should maintain TCP connection over iBGP across two consecutive live migrations", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
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
			clientPod := setupAntiAffinityPod(ctx, f, node1)
			expectConnectionToTCPServer(ns, clientPod.Name, serverIP)

			// Use nohup to prevent SIGHUP when kubectl exec session closes. The Exec()
			// return is intentionally ignored: `nohup ... &` backgrounds immediately and
			// always returns success, so its error value tells us nothing about whether
			// nc actually connected. We verify liveness explicitly below.
			By("Starting TCP client")
			_, _ = kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"sh", "-c", fmt.Sprintf("nohup nc %s 9999 > /tmp/tcp_stream 2>&1 &", serverIP)).Exec()
			DeferCleanup(func() {
				_, _ = kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
					"pkill", "-f", fmt.Sprintf("nc %s 9999", serverIP)).Exec()
			})

			By("Verifying nc client process is running")
			Eventually(func() error {
				out, err := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
					"pgrep", "-f", fmt.Sprintf("nc %s 9999", serverIP)).Exec()
				if err != nil {
					return fmt.Errorf("pgrep failed: %w (output=%q)", err, out)
				}
				if strings.TrimSpace(out) == "" {
					return fmt.Errorf("nc process not found — client exited immediately")
				}
				return nil
			}, 15*time.Second, 1*time.Second).Should(Succeed(), "TCP client did not start")

			By("Verifying TCP data is flowing before migration")
			var preLines int
			Eventually(func() (int, error) {
				var err error
				preLines, err = tcpStreamLineCount(ns, clientPod.Name, "/tmp/tcp_stream")
				return preLines, err
			}, 30*time.Second, 2*time.Second).Should(BeNumerically(">=", 5),
				"TCP data should be flowing")
			logrus.Infof("Pre-migration: %d lines on client pod", preLines)

			By("Migrating the VM")
			vmim1 := newVMIMigration(serverVMName+"-migration1", ns, serverVMName)
			err := cli.Create(ctx, vmim1)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim1) })
			waitForMigrationSuccess(ctx, cli, vmim1)
			vmi := &kubevirtv1.VirtualMachineInstance{}
			Expect(cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: serverVMName}, vmi)).To(Succeed())
			node2 := vmi.Status.NodeName
			Expect(node2).NotTo(Equal(node1), "VM didn't migrate off node 1")

			By("Verifying TCP stream survived first migration")
			var midLines int
			Eventually(func() (int, error) {
				var err error
				midLines, err = tcpStreamLineCount(ns, clientPod.Name, "/tmp/tcp_stream")
				return midLines, err
			}, 30*time.Second, 2*time.Second).Should(BeNumerically(">=", preLines+5),
				"TCP data should have grown after first migration")
			logrus.Infof("After first migration: %d lines", midLines)

			By("Migrating the VM a second time")
			vmim2 := newVMIMigration(serverVMName+"-migration2", ns, serverVMName)
			err = cli.Create(ctx, vmim2)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { deleteVMIMigration(cli,vmim2) })
			waitForMigrationSuccess(ctx, cli, vmim2)
			err = cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: serverVMName}, vmi)
			Expect(err).NotTo(HaveOccurred())
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
			Eventually(func() (int, error) {
				return tcpStreamLineCount(ns, clientPod.Name, "/tmp/tcp_stream")
			}, 30*time.Second, 2*time.Second).Should(BeNumerically(">=", midLines+5),
				"TCP data should have grown after second migration")

			By("Checking sequence continuity")
			streamAll, err := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"cat", "/tmp/tcp_stream").Exec()
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(strings.TrimSpace(streamAll), "\n")
			logrus.Infof("TCP stream: %d lines, first: %s, last: %s",
				len(lines), lines[0], lines[len(lines)-1])

			seqGaps, lastSeq := countSequenceGaps(lines)
			logrus.Infof("Sequence: %d gaps, %d data points across 2 migrations", seqGaps, lastSeq)
			Expect(seqGaps).To(BeNumerically("==", 0),
				"seamless live migration must not drop any TCP segments")
		})

		// Test 3: TCP connection from external eBGP client survives two consecutive migrations.
		// Same as Test 2 but the TCP client runs on an external TOR node connected via eBGP
		// (ASN 63000) over L2TP tunnels, rather than an in-cluster pod using iBGP mesh.
		// This validates that the BGP route priority mechanism (krt_metric) works end-to-end:
		// when the VM migrates, the elevated-priority route advertisement from the target
		// node reaches the TOR via eBGP, causing the TOR's kernel routing table to switch
		// to the new next-hop without dropping the TCP connection. Two consecutive migrations
		// verify the route priority reverts correctly after the TimeWait period and can be
		// re-elevated for the second migration.
		// Requires EXT_IP, EXT_KEY, EXT_USER env vars pointing to the TOR/external node.
		framework.Context("eBGP external client", describe.RequiresExternalNode(), func() {
			It("should maintain TCP connection from eBGP external client across two consecutive migrations", func() {
				tor := externalnode.NewClient()
				if tor == nil {
					// The RequiresExternalNode label gates whether this test runs at
					// all; once selected, missing credentials are a real failure
					// rather than a self-skip.
					Fail("External node not configured (set EXT_IP, EXT_KEY, EXT_USER)")
				}

				// Only this spec patches the Installation CR (natOutgoing) —
				// that path only exists on operator-managed clusters. Fail fast
				// rather than after the first patch attempt 404s.
				preCtx, preCancel := context.WithTimeout(context.Background(), 30*time.Second)
				requireOperatorManagedCluster(preCtx, f)
				preCancel()

				By("Setting up eBGP peering between TOR and cluster nodes")
				setupEBGPPeering(f, tor)

				// Disable natOutgoing on the IPPool that backs VM workloads. natOutgoing
				// rewrites the VM's source IP to the node's IP at the egress NAT, which
				// breaks the TOR's reverse-path matching after migration (the next-hop
				// changes mid-flow). Doing this through Installation rather than IPPool
				// directly because the operator reconciles the IPPool from Installation
				// and would revert any direct IPPool patch.
				const vmIPPoolName = "default-ipv4-ippool"
				DeferCleanup(func() {
					By("Re-enabling natOutgoing via Installation")
					patchInstallationPoolNATOutgoing(f, vmIPPoolName, "Enabled")
				})

				By("Disabling natOutgoing via Installation to prevent masquerade breaking TCP after migration")
				patchInstallationPoolNATOutgoing(f, vmIPPoolName, "Disabled")

				// Wait for operator to reconcile the IPPool and Felix to drain the masq ipset.
				// When natOutgoing is disabled, the field is omitted from the IPPool spec
				// (jsonpath returns empty string rather than "false").
				logrus.Info("Waiting for natOutgoing=Disabled to propagate...")
				Eventually(func() string {
					out, _ := kubectl.NewKubectlCommand("", "get", "ippool", vmIPPoolName,
						"-o", "jsonpath={.spec.natOutgoing}").Exec()
					return strings.TrimSpace(out)
				}, 30*time.Second, 2*time.Second).ShouldNot(Equal("true"),
					"natOutgoing should not be true on IPPool after Installation patch")
				logrus.Info("natOutgoing disabled confirmed on IPPool")

				ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
				defer cancel()
				ns := f.Namespace.Name

				timeline := newRouteTimeline()
				DeferCleanup(func() { timeline.writeToTOR(tor) })

				vmName := "e2e-ebgp-tcp"
				vm := &kubeVirtVM{name: vmName, namespace: ns, cloudInit: tcpServerCloudInit}

				By("Creating a VM with TCP server")
				vm.Create(ctx, cli)
				DeferCleanup(func() { vm.Delete(cli) })

				vmIP, node1 := vm.WaitForRunningWithIP(ctx, cli)
				logrus.Infof("VM %s on %s with IP %s", vmName, node1, vmIP)

				By("Verifying TOR can reach the VM (eBGP routing is up)")
				Eventually(func() error {
					out, err := runOnTOR(tor, fmt.Sprintf("ping -c 1 -W 2 %s", vmIP))
					if err != nil {
						routes, _ := runOnTOR(tor, "sudo docker exec tor-bird birdcl show route")
						logrus.Infof("TOR BIRD routes:\n%s", routes)
						kernRoutes, _ := runOnTOR(tor, fmt.Sprintf("ip route get %s 2>&1", vmIP))
						logrus.Infof("TOR kernel route to %s: %s", vmIP, kernRoutes)
						return fmt.Errorf("ping %s failed: %v (output=%s)", vmIP, err, out)
					}
					return nil
				}, 2*time.Minute, 5*time.Second).Should(Succeed(),
					"TOR cannot reach VM — eBGP routing may not be configured")

				By("Starting route monitor on TOR")
				stopMonitor := startRouteMonitor(tor, vmIP)
				defer stopMonitor()

				By("Waiting for TCP server on VM to be reachable from TOR")
				const ncClientContainer = "tor-nc-client"
				Eventually(func() error {
					out, _ := runOnTOR(tor, fmt.Sprintf(
						"sudo docker run --rm --network host alpine sh -c 'sleep 999 | timeout 5 nc %s 9999' 2>&1", vmIP))
					if !strings.Contains(out, "seq=") {
						return fmt.Errorf("TCP server not sending data from TOR (output=%q)", out)
					}
					return nil
				}, 2*time.Minute, 5*time.Second).Should(Succeed(),
					"TCP server not reachable from TOR")
				logrus.Infof("TCP server on %s:9999 is reachable and sending data from TOR", vmIP)

				startTCPClientOnTOR(tor, ncClientContainer, vmIP)

				// Start a goroutine that logs seq count every 2 seconds throughout
				// the test. We record but do NOT assert — the goal is to collect
				// a timeline we can analyse after the test finishes.
				//
				// We wait for the goroutine to exit before returning from the It,
				// so timeline.writeToTOR (registered as DeferCleanup) does not race
				// the monitor's last SSH session on the shared TOR client.
				seqStopCh := make(chan struct{})
				seqDoneCh := make(chan struct{})
				defer func() {
					close(seqStopCh)
					<-seqDoneCh
				}()
				go func() {
					defer close(seqDoneCh)
					ticker := time.NewTicker(2 * time.Second)
					defer ticker.Stop()
					for {
						n, err := torContainerLineCount(tor, ncClientContainer)
						if err != nil {
							logrus.Warnf("[seq-monitor] error: %v", err)
						} else {
							logrus.Infof("[seq-monitor] lines=%d", n)
						}
						// Honor stopCh during the wait so the goroutine doesn't do
						// one extra SSH after the test body returns.
						select {
						case <-seqStopCh:
							return
						case <-ticker.C:
						}
					}
				}()

				By("Waiting for TCP data to flow before migration")
				var preLines int
				Eventually(func() (int, error) {
					var err error
					preLines, err = torContainerLineCount(tor, ncClientContainer)
					return preLines, err
				}, 30*time.Second, 2*time.Second).Should(BeNumerically(">=", 5),
					"TCP data should be flowing from TOR")
				logrus.Infof("TIMELINE: pre-migration lines=%d", preLines)

				preTime := time.Now()
				timeline.record(routeTimelineEntry{
					Phase:    "pre-migration",
					VMNode:   node1,
					TOR:      queryTORSnapshot(tor, vmIP),
					TCPLines: preLines,
				})

				// ---- First migration ----
				By("Migrating the VM")
				vmim1 := newVMIMigration(vmName+"-migration1", ns, vmName)
				Expect(cli.Create(ctx, vmim1)).To(Succeed())
				DeferCleanup(func() { deleteVMIMigration(cli, vmim1) })
				waitForMigrationSuccess(ctx, cli, vmim1)
				vmi := waitForMigrationStatePopulated(ctx, cli, ns, vmName)
				node2 := vmi.Status.MigrationState.TargetNode
				Expect(node2).NotTo(Equal(node1), "VM didn't migrate off node 1")

				// migration.WaitForSuccess returns the moment the VMIM phase is
				// Succeeded, but Felix programs krt_metric=512 asynchronously and
				// later reverts it after LiveMigrationRouteConvergenceTime (~30s).
				// Poll for the elevated state with a budget shorter than the
				// revert window so we observe it deterministically.
				By("Verifying elevated route priority on worker and TOR after first migration")
				Eventually(func(g Gomega) {
					g.Expect(queryWorkerMetric(f, node2, vmIP)).To(Equal(512),
						"worker kernel metric should be elevated (512) after migration")
					st := queryTORRoute(tor, vmIP)
					g.Expect(st.Has32).To(BeTrue(), "TOR should have /32 after migration")
					g.Expect(st.Routes).To(HaveLen(1), "should be single /32 route (no ECMP)")
					g.Expect(st.Routes[0].LocalPref).To(Equal(2147483135), "TOR /32 should have elevated local_pref")
					g.Expect(st.Routes[0].Community).To(Equal("(65000,100)"), "TOR /32 should have community tag")
				}, 20*time.Second, 1*time.Second).Should(Succeed())

				firstMigLines, _ := torContainerLineCount(tor, ncClientContainer)
				timeline.record(routeTimelineEntry{
					Phase:    "first-migration-complete",
					VMNode:   node2,
					TOR:      queryTORSnapshot(tor, vmIP),
					TCPLines: firstMigLines,
				})

				// Wait for the elevated /32 route to revert to normal local_pref
				// after the LiveMigrationRouteConvergenceTime (default 30s) expires.
				By("Waiting for TOR /32 local_pref to revert to normal after convergence")
				Eventually(func() int {
					snap := queryTORSnapshot(tor, vmIP)
					pollLines, _ := torContainerLineCount(tor, ncClientContainer)
					timeline.record(routeTimelineEntry{
						Phase:    "convergence-poll",
						VMNode:   node2,
						TOR:      snap,
						TCPLines: pollLines,
					})
					if len(snap.Host32.Routes) > 0 {
						return snap.Host32.Routes[0].LocalPref
					}
					return -1
				}, 45*time.Second, 2*time.Second).Should(Equal(100),
					"TOR /32 local_pref should revert to 100 after convergence")

				convergenceLines, _ := torContainerLineCount(tor, ncClientContainer)
				timeline.record(routeTimelineEntry{
					Phase:    "convergence-done",
					VMNode:   node2,
					TOR:      queryTORSnapshot(tor, vmIP),
					TCPLines: convergenceLines,
				})

				midLines, _ := torContainerLineCount(tor, ncClientContainer)
				Expect(midLines).To(BeNumerically(">", preLines), "TCP should still be flowing after first migration")

				// Cordon node1 (the original node) so the second migration cannot
				// go back there — we want the VM to land on a third node so that a
				// new /32 route is needed.
				By(fmt.Sprintf("Cordoning original node %s to prevent migrate-back", node1))
				Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
					n, err := f.ClientSet.CoreV1().Nodes().Get(ctx, node1, metav1.GetOptions{})
					if err != nil {
						return err
					}
					n.Spec.Unschedulable = true
					_, err = f.ClientSet.CoreV1().Nodes().Update(ctx, n, metav1.UpdateOptions{})
					return err
				})).To(Succeed(), "cordoning %s", node1)
				DeferCleanup(func() {
					By(fmt.Sprintf("Uncordoning node %s", node1))
					// Wrap in RetryOnConflict so a transient apiserver hiccup or
					// concurrent Node update from another controller does not leave
					// the node cordoned for the rest of the suite.
					if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
						n, err := f.ClientSet.CoreV1().Nodes().Get(context.Background(), node1, metav1.GetOptions{})
						if err != nil {
							return err
						}
						n.Spec.Unschedulable = false
						_, err = f.ClientSet.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
						return err
					}); err != nil {
						// Last-resort log; the test has already passed and we don't
						// want to fail cleanup, but flag loudly so a stuck cordon is
						// visible in CI artifacts.
						logrus.WithError(err).Errorf("Failed to uncordon node %s after retries — manual cleanup required", node1)
					}
				})

				// ---- Second migration ----
				By("Migrating the VM a second time")
				vmim2 := newVMIMigration(vmName+"-migration2", ns, vmName)
				Expect(cli.Create(ctx, vmim2)).To(Succeed())
				DeferCleanup(func() { deleteVMIMigration(cli, vmim2) })
				waitForMigrationSuccess(ctx, cli, vmim2)
				vmi = waitForMigrationStatePopulated(ctx, cli, ns, vmName)
				node3 := vmi.Status.MigrationState.TargetNode
				Expect(node3).NotTo(Equal(node2), "VM didn't migrate off node 2")

				// Same race as after the first migration: Felix programs the
				// elevated metric asynchronously and reverts it after the
				// convergence window. Poll for the elevated state.
				By("Verifying TOR route state after second migration")
				Eventually(func(g Gomega) {
					st := queryTORRoute(tor, vmIP)
					g.Expect(st.Has32).To(BeTrue(), "TOR should have /32 after second migration")
					// Find best route — it must have elevated local_pref (no ECMP).
					var b, nb *torBIRDRoute
					for i := range st.Routes {
						if st.Routes[i].Best {
							b = &st.Routes[i]
						} else {
							nb = &st.Routes[i]
						}
					}
					g.Expect(b).NotTo(BeNil(), "TOR should have a best /32 route")
					g.Expect(b.LocalPref).To(Equal(2147483135), "best /32 route should have elevated local_pref")
					g.Expect(b.Community).To(Equal("(65000,100)"), "best /32 route should have community tag")
					// After the second migration, two /32 routes must exist: the new
					// node's elevated route and the old node's normal route. They
					// must have different local_pref to avoid ECMP.
					g.Expect(nb).NotTo(BeNil(), "TOR should have two /32 routes after second migration")
					g.Expect(nb.LocalPref).NotTo(Equal(b.LocalPref),
						"two /32 routes must have different local_pref to avoid ECMP")
				}, 20*time.Second, 1*time.Second).Should(Succeed())

				secondMigLines, _ := torContainerLineCount(tor, ncClientContainer)
				timeline.record(routeTimelineEntry{
					Phase:    "second-migration-complete",
					VMNode:   node3,
					TOR:      queryTORSnapshot(tor, vmIP),
					TCPLines: secondMigLines,
				})

				// Wait for the second migration's /32 route to revert to normal
				// local_pref, same as after the first migration.
				By("Waiting for TOR /32 local_pref to revert after second migration")
				Eventually(func() int {
					snap := queryTORSnapshot(tor, vmIP)
					pollLines, _ := torContainerLineCount(tor, ncClientContainer)
					timeline.record(routeTimelineEntry{
						Phase:    "second-convergence-poll",
						VMNode:   node3,
						TOR:      snap,
						TCPLines: pollLines,
					})
					if len(snap.Host32.Routes) > 0 {
						return snap.Host32.Routes[0].LocalPref
					}
					return -1
				}, 45*time.Second, 2*time.Second).Should(Equal(100),
					"TOR /32 local_pref should revert to 100 after second migration convergence")

				finalLines, _ := torContainerLineCount(tor, ncClientContainer)
				Expect(finalLines).To(BeNumerically(">", midLines),
					"TCP stream should have continued growing after second migration (final=%d, mid=%d)", finalLines, midLines)

				// Dump full seq log and assert on sequence integrity.
				By("Verifying TCP stream integrity")
				streamAll, err := runOnTOR(tor, fmt.Sprintf("sudo docker logs %s 2>/dev/null", ncClientContainer))
				Expect(err).NotTo(HaveOccurred(), "failed to retrieve TCP stream from TOR")
				lines := strings.Split(strings.TrimSpace(streamAll), "\n")
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

				timeline.record(routeTimelineEntry{
					Phase:    "test-complete",
					VMNode:   node3,
					TOR:      queryTORSnapshot(tor, vmIP),
					TCPLines: finalLines,
				})
			})
		})

		// Test 4: Kubernetes NetworkPolicy enforcement survives live migration.
		// After migration, KubeVirt creates a new virt-launcher pod on the target node.
		// Network policies that selected the old pod must also apply to the new pod.
		// This test verifies that an allowed client can still connect and a denied
		// client is still blocked after the VM migrates to a different node.
		It("should enforce NetworkPolicy after live migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name

			vmName := "e2e-netpol-vm"
			vm := &kubeVirtVM{
				name:      vmName,
				namespace: ns,
				cloudInit: tcpServerCloudInit,
				labels:    map[string]string{"app": "vm"},
			}

			By("Creating VM with TCP server and app=vm label")
			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })
			vmIP, node1 := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s on %s with IP %s", vmName, node1, vmIP)

			By("Creating allowed client pod (role=allowed)")
			client1Pod, err := f.ClientSet.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client-allowed",
					Namespace: ns,
					Labels:    map[string]string{"role": "allowed", utils.TestResourceLabel: "true"},
				},
				Spec: corev1.PodSpec{
					Containers:    []corev1.Container{{Name: "client", Image: images.Alpine, Command: []string{"sleep", "3600"}}},
					RestartPolicy: corev1.RestartPolicyNever,
					NodeSelector:  map[string]string{"kubernetes.io/os": "linux"},
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				_ = f.ClientSet.CoreV1().Pods(ns).Delete(context.Background(), client1Pod.Name, metav1.DeleteOptions{})
			})
			err = e2epod.WaitTimeoutForPodRunningInNamespace(ctx, f.ClientSet, client1Pod.Name, ns, 2*time.Minute)
			Expect(err).NotTo(HaveOccurred(), "client-allowed pod not Running")

			By("Creating denied client pod (role=denied)")
			client2Pod, err := f.ClientSet.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client-denied",
					Namespace: ns,
					Labels:    map[string]string{"role": "denied", utils.TestResourceLabel: "true"},
				},
				Spec: corev1.PodSpec{
					Containers:    []corev1.Container{{Name: "client", Image: images.Alpine, Command: []string{"sleep", "3600"}}},
					RestartPolicy: corev1.RestartPolicyNever,
					NodeSelector:  map[string]string{"kubernetes.io/os": "linux"},
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				_ = f.ClientSet.CoreV1().Pods(ns).Delete(context.Background(), client2Pod.Name, metav1.DeleteOptions{})
			})
			err = e2epod.WaitTimeoutForPodRunningInNamespace(ctx, f.ClientSet, client2Pod.Name, ns, 2*time.Minute)
			Expect(err).NotTo(HaveOccurred(), "client-denied pod not Running")

			By("Verifying both clients can reach VM before policy is applied")
			expectConnectionToTCPServer(ns, client1Pod.Name, vmIP)
			expectConnectionToTCPServer(ns, client2Pod.Name, vmIP)

			By("Creating NetworkPolicy to allow only role=allowed on TCP/9999")
			protocol := corev1.ProtocolTCP
			netpol := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-client1-only", Namespace: ns},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "vm"},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"role": "allowed"},
							},
						}},
						Ports: []networkingv1.NetworkPolicyPort{{
							Protocol: &protocol,
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 9999},
						}},
					}},
				},
			}
			_, err = f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(ctx, netpol, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				_ = f.ClientSet.NetworkingV1().NetworkPolicies(ns).Delete(context.Background(), netpol.Name, metav1.DeleteOptions{})
			})

			By("Verifying policy is enforced: client1 allowed, client2 denied")
			expectConnectionToTCPServer(ns, client1Pod.Name, vmIP)
			expectTCPConnectionBlocked(ns, client2Pod.Name, vmIP)

			By("Triggering live migration")
			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			err = cli.Create(ctx, vmim)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { deleteVMIMigration(cli,vmim) })
			waitForMigrationSuccess(ctx, cli, vmim)

			vmi := waitForMigrationStatePopulated(ctx, cli, ns, vmName)
			node2 := vmi.Status.MigrationState.TargetNode
			Expect(node2).NotTo(Equal(node1), "VM should have migrated to a different node")
			logrus.Infof("VM migrated: %s -> %s", node1, node2)

			// After migration the new virt-launcher pod has its own IP-stack
			// on a new node. Felix must learn the workload, recompute policy,
			// and program rules — those are async after VMIM Succeeded. Wait
			// until both directions match the policy intent on the *new* pod
			// before asserting Consistently, otherwise the Consistently
			// window can land on the source's still-active rules and pass
			// for the wrong reason.
			By("Waiting for policy to apply on the migrated pod")
			Eventually(func(g Gomega) {
				out1, _ := kubectl.NewKubectlCommand(ns, "exec", client1Pod.Name, "--",
					"sh", "-c", fmt.Sprintf("timeout 3 nc %s 9999 2>&1", vmIP)).Exec()
				g.Expect(out1).To(ContainSubstring("seq="),
					"client1 (allowed) should reach migrated pod before Consistently asserts")
				out2, _ := kubectl.NewKubectlCommand(ns, "exec", client2Pod.Name, "--",
					"sh", "-c", fmt.Sprintf("timeout 3 nc %s 9999 2>&1", vmIP)).Exec()
				g.Expect(out2).NotTo(ContainSubstring("seq="),
					"client2 (denied) should be blocked from migrated pod before Consistently asserts")
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			By("Verifying policy survives migration: client1 still allowed, client2 still denied")
			expectConnectionToTCPServer(ns, client1Pod.Name, vmIP)
			expectTCPConnectionBlocked(ns, client2Pod.Name, vmIP)
			logrus.Info("NetworkPolicy enforcement confirmed after live migration")
		})
	},
)
