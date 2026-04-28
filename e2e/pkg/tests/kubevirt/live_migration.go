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
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
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
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("KubeVirt"),
	describe.WithCategory(describe.Networking),
	"KubeVirt live migration",
	func() {
		f := utils.NewDefaultFramework("calico-kubevirt")

		var kvClient kubevirtcorev1.KubevirtV1Interface

		BeforeEach(func() {
			// Live migration needs at least 2 nodes to migrate between.
			utils.RequireNodeCount(f, 2)

			var err error
			kvClient, err = kubevirtcorev1.NewForConfig(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to create KubeVirt client")
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
			vm := &testVM{name: vmName, namespace: ns, kvClient: kvClient}

			vm.Create(ctx)
			DeferCleanup(vm.Delete)
			originalIP, sourceNode := vm.WaitForRunningWithIP(ctx)

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

			By("Triggering live migration")
			migration := &testVMIM{name: vmName + "-migration", namespace: ns, vmiName: vmName, kvClient: kvClient}
			migration.Create(ctx)
			DeferCleanup(migration.Delete)
			migration.WaitForSuccess(ctx)

			// Read the target pod and node directly from the VMI's MigrationState,
			// which KubeVirt populates with the source/target identifiers as part of
			// the migration. This avoids races with the source virt-launcher pod still
			// being Running (and the VMI's NodeName flipping) right after the VMIM
			// reaches Succeeded.
			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(vmi.Status.MigrationState).NotTo(BeNil(), "VMI MigrationState should be populated")
			Expect(vmi.Status.MigrationState.Completed).To(BeTrue(), "MigrationState should be marked completed")
			targetPodName := vmi.Status.MigrationState.TargetPod
			targetNode := vmi.Status.MigrationState.TargetNode
			Expect(targetPodName).NotTo(BeEmpty(), "MigrationState.TargetPod should be set")
			Expect(targetNode).NotTo(BeEmpty(), "MigrationState.TargetNode should be set")
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
			serverVM := &testVM{name: serverVMName, namespace: ns, cloudInit: tcpServerCloudInit, kvClient: kvClient}

			By("Creating server VM with TCP server")
			serverVM.Create(ctx)
			DeferCleanup(serverVM.Delete)

			serverIP, node1 := serverVM.WaitForRunningWithIP(ctx)
			logrus.Infof("Server VM: %s on %s", serverIP, node1)

			By("Creating client pod on a different node than server VM")
			clientPod := setupAntiAffinityPod(ctx, f, ns, node1)
			checkConnectionToTCPServer(ns, clientPod.Name, serverIP)

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

			By("First migration")
			migration1 := &testVMIM{name: serverVMName + "-migration1", namespace: ns, vmiName: serverVMName, kvClient: kvClient}
			migration1.Create(ctx)
			DeferCleanup(migration1.Delete)
			migration1.WaitForSuccess(ctx)
			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, serverVMName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node2 := vmi.Status.NodeName
			Expect(node2).NotTo(Equal(node1))
			logrus.Infof("First migration: %s -> %s", node1, node2)

			By("Verifying TCP stream survived first migration")
			var midLines int
			Eventually(func() (int, error) {
				var err error
				midLines, err = tcpStreamLineCount(ns, clientPod.Name, "/tmp/tcp_stream")
				return midLines, err
			}, 30*time.Second, 2*time.Second).Should(BeNumerically(">=", preLines+5),
				"TCP data should have grown after first migration")
			logrus.Infof("After first migration: %d lines", midLines)

			By("Second migration")
			migration2 := &testVMIM{name: serverVMName + "-migration2", namespace: ns, vmiName: serverVMName, kvClient: kvClient}
			migration2.Create(ctx)
			DeferCleanup(migration2.Delete)
			migration2.WaitForSuccess(ctx)
			vmi, err = kvClient.VirtualMachineInstances(ns).Get(ctx, serverVMName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node3 := vmi.Status.NodeName
			// With 3 worker nodes, second migration moves away from node2.
			// It could return to node1 — that's fine, we only require it left node2.
			Expect(node3).NotTo(Equal(node2))
			logrus.Infof("Second migration: %s -> %s", node2, node3)

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
		It("should maintain TCP connection from eBGP external client across two consecutive migrations", func() {
			tor := externalnode.NewClient()
			if tor == nil {
				Skip("External node not configured (set EXT_IP, EXT_KEY, EXT_USER)")
			}

			By("Setting up eBGP peering between TOR and cluster nodes")
			setupEBGPPeering(f, tor)

			// Disable natOutgoing via the Installation resource (not the IPPool directly,
			// because the tigera-operator reconciles the IPPool from Installation and
			// would revert any direct IPPool patch).
			By("Disabling natOutgoing via Installation to prevent masquerade breaking TCP after migration")
			_, err := kubectl.NewKubectlCommand("", "patch", "installation", "default",
				"--type=json", "-p",
				`[{"op":"replace","path":"/spec/calicoNetwork/ipPools/0/natOutgoing","value":"Disabled"}]`).Exec()
			Expect(err).NotTo(HaveOccurred())
			// Wait for operator to reconcile the IPPool and Felix to drain the masq ipset.
			// When natOutgoing is disabled, the field is omitted from the IPPool spec
			// (jsonpath returns empty string rather than "false").
			logrus.Info("Waiting for natOutgoing=Disabled to propagate...")
			Eventually(func() string {
				out, _ := kubectl.NewKubectlCommand("", "get", "ippool", "default-ipv4-ippool",
					"-o", "jsonpath={.spec.natOutgoing}").Exec()
				return strings.TrimSpace(out)
			}, 30*time.Second, 2*time.Second).ShouldNot(Equal("true"),
				"natOutgoing should not be true on IPPool after Installation patch")
			logrus.Info("natOutgoing disabled confirmed on IPPool")
			DeferCleanup(func() {
				By("Re-enabling natOutgoing via Installation")
				_, restoreErr := kubectl.NewKubectlCommand("", "patch", "installation", "default",
					"--type=json", "-p",
					`[{"op":"replace","path":"/spec/calicoNetwork/ipPools/0/natOutgoing","value":"Enabled"}]`).Exec()
				if restoreErr != nil {
					logrus.WithError(restoreErr).Warn("Failed to restore natOutgoing on Installation")
				}
			})

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name

			timeline := newRouteTimeline()
			DeferCleanup(func() { timeline.writeToTOR(tor) })

			vmName := "e2e-ebgp-tcp"
			vm := &testVM{name: vmName, namespace: ns, cloudInit: tcpServerCloudInit, kvClient: kvClient}

			By("Creating a VM with TCP server")
			vm.Create(ctx)
			DeferCleanup(vm.Delete)

			vmIP, node1 := vm.WaitForRunningWithIP(ctx)
			logrus.Infof("VM %s on %s with IP %s", vmName, node1, vmIP)

			By("Verifying TOR can reach the VM (eBGP routing is up)")
			Eventually(func() error {
				out, err := runOnTORE(tor, fmt.Sprintf("ping -c 1 -W 2 %s", vmIP))
				if err != nil {
					routes := runOnTOR(tor, "sudo docker exec tor-bird birdcl show route")
					logrus.Infof("TOR BIRD routes:\n%s", routes)
					kernRoutes := runOnTOR(tor, fmt.Sprintf("ip route get %s 2>&1 || true", vmIP))
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
				out := runOnTOR(tor, fmt.Sprintf(
					"sudo docker run --rm --network host alpine sh -c 'sleep 999 | timeout 5 nc %s 9999' 2>&1 || true", vmIP))
				if !strings.Contains(out, "seq=") {
					return fmt.Errorf("TCP server not sending data from TOR (output=%q)", out)
				}
				return nil
			}, 2*time.Minute, 5*time.Second).Should(Succeed(),
				"TCP server not reachable from TOR")
			logrus.Infof("TCP server on %s:9999 is reachable and sending data from TOR", vmIP)

			By("Starting TCP client container on TOR connecting to VM")
			runOnTOR(tor, fmt.Sprintf("sudo docker rm -f %s 2>/dev/null || true", ncClientContainer))
			runOnTOR(tor, fmt.Sprintf(
				"sudo docker run -d --name %s --network host alpine sh -c 'sleep 999999 | nc %s 9999'",
				ncClientContainer, vmIP))
			DeferCleanup(func() {
				By("Removing TCP client container from TOR")
				runOnTOR(tor, fmt.Sprintf("sudo docker rm -f %s 2>/dev/null || true", ncClientContainer))
			})

			By("Verifying nc client container is running on TOR")
			Eventually(func() error {
				out := runOnTOR(tor, fmt.Sprintf("sudo docker inspect -f '{{.State.Running}}' %s 2>&1 || true", ncClientContainer))
				if strings.TrimSpace(out) != "true" {
					return fmt.Errorf("container %s not running (state=%q)", ncClientContainer, out)
				}
				return nil
			}, 15*time.Second, 1*time.Second).Should(Succeed(), "TCP client container did not start on TOR")

			// Start a goroutine that logs seq count every 2 seconds throughout
			// the test.  We record but do NOT assert — the goal is to collect
			// a timeline we can analyse after the test finishes.
			seqStopCh := make(chan struct{})
			defer close(seqStopCh)
			go func() {
				for {
					select {
					case <-seqStopCh:
						return
					default:
					}
					n, err := torContainerLineCount(tor, ncClientContainer)
					if err != nil {
						logrus.Warnf("[seq-monitor] error: %v", err)
					} else {
						logrus.Infof("[seq-monitor] lines=%d", n)
					}
					time.Sleep(2 * time.Second)
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
			By("First migration")
			logrus.Infof("TIMELINE: starting first migration")
			migration1 := &testVMIM{name: vmName + "-migration1", namespace: ns, vmiName: vmName, kvClient: kvClient}
			migration1.Create(ctx)
			DeferCleanup(migration1.Delete)
			migration1.WaitForSuccess(ctx)
			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(vmi.Status.MigrationState).NotTo(BeNil())
			node2 := vmi.Status.MigrationState.TargetNode
			Expect(node2).NotTo(Equal(node1))
			ms1 := vmi.Status.MigrationState
			logrus.Infof("TIMELINE: first migration complete %s -> %s (StartTimestamp=%v EndTimestamp=%v)",
				node1, node2, ms1.StartTimestamp, ms1.EndTimestamp)

			By("Verifying elevated route priority on worker and TOR after first migration")
			metric := queryWorkerMetric(f, node2, vmIP)
			Expect(metric).To(Equal(512), "worker kernel metric should be elevated (512) after migration")

			torState := queryTORRoute(tor, vmIP)
			Expect(torState.Has32).To(BeTrue(), "TOR should have /32 after migration")
			Expect(torState.Routes).To(HaveLen(1), "should be single /32 route (no ECMP)")
			Expect(torState.Routes[0].LocalPref).To(Equal(2147483135), "TOR /32 should have elevated local_pref")
			Expect(torState.Routes[0].Community).To(Equal("(65000,100)"), "TOR /32 should have community tag")

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
			logrus.Infof("TIMELINE: after first migration wait lines=%d (pre=%d, delta=%d)", midLines, preLines, midLines-preLines)
			Expect(midLines).To(BeNumerically(">", preLines), "TCP should still be flowing after first migration")
			// Cordon node1 (the original node) so the second migration cannot
			// go back there — we want the VM to land on a third node so that a
			// new /32 route is needed.
			By(fmt.Sprintf("Cordoning original node %s to prevent migrate-back", node1))
			node1Obj, err := f.ClientSet.CoreV1().Nodes().Get(ctx, node1, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node1Obj.Spec.Unschedulable = true
			_, err = f.ClientSet.CoreV1().Nodes().Update(ctx, node1Obj, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("TIMELINE: cordoned %s", node1)
			DeferCleanup(func() {
				By(fmt.Sprintf("Uncordoning node %s", node1))
				n, getErr := f.ClientSet.CoreV1().Nodes().Get(context.Background(), node1, metav1.GetOptions{})
				if getErr != nil {
					logrus.WithError(getErr).Warnf("Failed to get node %s for uncordon", node1)
					return
				}
				n.Spec.Unschedulable = false
				_, updateErr := f.ClientSet.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
				if updateErr != nil {
					logrus.WithError(updateErr).Warnf("Failed to uncordon node %s", node1)
				}
			})

			// ---- Second migration ----
			By("Second migration")
			logrus.Infof("TIMELINE: starting second migration")
			migration2 := &testVMIM{name: vmName + "-migration2", namespace: ns, vmiName: vmName, kvClient: kvClient}
			migration2.Create(ctx)
			DeferCleanup(migration2.Delete)
			migration2.WaitForSuccess(ctx)
			vmi, err = kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(vmi.Status.MigrationState).NotTo(BeNil())
			node3 := vmi.Status.MigrationState.TargetNode
			Expect(node3).NotTo(Equal(node2))
			ms2 := vmi.Status.MigrationState
			logrus.Infof("TIMELINE: second migration complete %s -> %s (StartTimestamp=%v EndTimestamp=%v)",
				node2, node3, ms2.StartTimestamp, ms2.EndTimestamp)

			By("Verifying TOR route state after second migration")
			torState = queryTORRoute(tor, vmIP)
			Expect(torState.Has32).To(BeTrue(), "TOR should have /32 after second migration")

			// Find best route — it must have elevated local_pref (no ECMP).
			var bestRoute, nonBestRoute *torBIRDRoute
			for i := range torState.Routes {
				if torState.Routes[i].Best {
					bestRoute = &torState.Routes[i]
				} else {
					nonBestRoute = &torState.Routes[i]
				}
			}
			Expect(bestRoute).NotTo(BeNil(), "TOR should have a best /32 route")
			Expect(bestRoute.LocalPref).To(Equal(2147483135), "best /32 route should have elevated local_pref")
			Expect(bestRoute.Community).To(Equal("(65000,100)"), "best /32 route should have community tag")
			// After the second migration, two /32 routes must exist: the new
			// node's elevated route and the old node's normal route. They must
			// have different local_pref to avoid ECMP.
			Expect(nonBestRoute).NotTo(BeNil(), "TOR should have two /32 routes after second migration")
			Expect(nonBestRoute.LocalPref).NotTo(Equal(bestRoute.LocalPref),
				"two /32 routes must have different local_pref to avoid ECMP")

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
			logrus.Infof("TIMELINE: after second migration convergence lines=%d (mid=%d, delta=%d)", finalLines, midLines, finalLines-midLines)
			Expect(finalLines).To(BeNumerically(">", midLines),
				"TCP stream should have continued growing after second migration (final=%d, mid=%d)", finalLines, midLines)

			// Dump full seq log and assert on sequence integrity.
			By("Verifying TCP stream integrity")
			streamAll, err := runOnTORE(tor, fmt.Sprintf("sudo docker logs %s 2>/dev/null", ncClientContainer))
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

			logrus.Infof("TIMELINE: test complete — analyse route-monitor and seq-monitor logs above")
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
			vm := &testVM{
				name:      vmName,
				namespace: ns,
				cloudInit: tcpServerCloudInit,
				labels:    map[string]string{"app": "vm"},
				kvClient:  kvClient,
			}

			By("Creating VM with TCP server and app=vm label")
			vm.Create(ctx)
			DeferCleanup(vm.Delete)
			vmIP, node1 := vm.WaitForRunningWithIP(ctx)
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
			checkConnectionToTCPServer(ns, client1Pod.Name, vmIP)
			checkConnectionToTCPServer(ns, client2Pod.Name, vmIP)

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
			checkConnectionToTCPServer(ns, client1Pod.Name, vmIP)
			checkTCPConnectionBlocked(ns, client2Pod.Name, vmIP)

			By("Triggering live migration")
			migration := &testVMIM{name: vmName + "-migration", namespace: ns, vmiName: vmName, kvClient: kvClient}
			migration.Create(ctx)
			DeferCleanup(migration.Delete)
			migration.WaitForSuccess(ctx)

			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(vmi.Status.MigrationState).NotTo(BeNil())
			node2 := vmi.Status.MigrationState.TargetNode
			Expect(node2).NotTo(Equal(node1), "VM should have migrated to a different node")
			logrus.Infof("VM migrated: %s -> %s", node1, node2)

			By("Verifying policy survives migration: client1 still allowed, client2 still denied")
			checkConnectionToTCPServer(ns, client1Pod.Name, vmIP)
			checkTCPConnectionBlocked(ns, client2Pod.Name, vmIP)
			logrus.Info("NetworkPolicy enforcement confirmed after live migration")
		})
	},
)
