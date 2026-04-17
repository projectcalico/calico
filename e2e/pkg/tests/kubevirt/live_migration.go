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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// KubeVirt live migration e2e tests validate Calico's seamless migration support for
// KubeVirt VMs. The tests cover:
//   - IPAM attribute ownership handover (Test 1)
//   - Zero-downtime TCP connectivity through iBGP and eBGP during migration (Tests 2-3)
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

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
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
					// Log route debugging on failure.
					routes := runOnTOR(tor, "sudo docker exec tor-bird birdcl show route")
					logrus.Infof("TOR BIRD routes:\n%s", routes)
					kernRoutes := runOnTOR(tor, fmt.Sprintf("ip route get %s 2>&1 || true", vmIP))
					logrus.Infof("TOR kernel route to %s: %s", vmIP, kernRoutes)
					return fmt.Errorf("ping %s failed: %v (output=%s)", vmIP, err, out)
				}
				return nil
			}, 2*time.Minute, 5*time.Second).Should(Succeed(),
				"TOR cannot reach VM — eBGP routing may not be configured")

			pauseForDebug(f)

			By("Starting route monitor on TOR")
			stopMonitor := startRouteMonitor(tor, vmIP)
			defer stopMonitor()

			By("Waiting for TCP server on VM to be reachable from TOR")
			const ncClientContainer = "tor-nc-client"
			Eventually(func() error {
				// Run a short-lived Docker container with nc to verify data flows.
				// sleep keeps stdin open so nc doesn't close; timeout limits the probe.
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
			// On test failure, dump the tail of the container's output for post-mortem.
			DeferCleanup(func() {
				if CurrentSpecReport().Failed() {
					tail := runOnTOR(tor, fmt.Sprintf("sudo docker logs --tail 50 %s 2>/dev/null || true", ncClientContainer))
					logrus.Warnf("TOR %s logs (last 50 lines):\n%s", ncClientContainer, tail)
				}
			})

			By("Verifying nc client container is running on TOR")
			Eventually(func() error {
				out := runOnTOR(tor, fmt.Sprintf("sudo docker inspect -f '{{.State.Running}}' %s 2>&1 || true", ncClientContainer))
				if strings.TrimSpace(out) != "true" {
					return fmt.Errorf("container %s not running (state=%q)", ncClientContainer, out)
				}
				return nil
			}, 15*time.Second, 1*time.Second).Should(Succeed(), "TCP client container did not start on TOR")

			By("Verifying TCP data is flowing from TOR before migration")
			var preLines int
			Eventually(func() (int, error) {
				var err error
				preLines, err = torContainerLineCount(tor, ncClientContainer)
				return preLines, err
			}, 30*time.Second, 2*time.Second).Should(BeNumerically(">=", 5),
				"TCP data should be flowing from TOR")
			logrus.Infof("Pre-migration: %d lines received on TOR", preLines)

			By("First migration")
			migration1 := &testVMIM{name: vmName + "-migration1", namespace: ns, vmiName: vmName, kvClient: kvClient}
			migration1.Create(ctx)
			DeferCleanup(migration1.Delete)
			migration1.WaitForSuccess(ctx)
			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(vmi.Status.MigrationState).NotTo(BeNil())
			node2 := vmi.Status.MigrationState.TargetNode
			Expect(node2).NotTo(Equal(node1))
			logrus.Infof("First eBGP migration: %s -> %s", node1, node2)

			By("Verifying TCP data continued on TOR after first migration")
			var midLines int
			Eventually(func() (int, error) {
				var err error
				midLines, err = torContainerLineCount(tor, ncClientContainer)
				return midLines, err
			}, 1*time.Minute, 2*time.Second).Should(BeNumerically(">=", preLines+5),
				"TCP data should have grown after first eBGP migration")
			logrus.Infof("After first eBGP migration: %d lines", midLines)

			By("Second migration")
			migration2 := &testVMIM{name: vmName + "-migration2", namespace: ns, vmiName: vmName, kvClient: kvClient}
			migration2.Create(ctx)
			DeferCleanup(migration2.Delete)
			migration2.WaitForSuccess(ctx)
			vmi, err = kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(vmi.Status.MigrationState).NotTo(BeNil())
			node3 := vmi.Status.MigrationState.TargetNode
			Expect(node3).NotTo(Equal(node2))
			logrus.Infof("Second eBGP migration: %s -> %s", node2, node3)

			// eBGP route convergence through the external TOR may take longer than
			// iBGP mesh, so allow more time for data to resume after the second migration.
			By("Verifying TCP data continued on TOR after second migration")
			Eventually(func() (int, error) {
				return torContainerLineCount(tor, ncClientContainer)
			}, 1*time.Minute, 2*time.Second).Should(BeNumerically(">=", midLines+5),
				"TCP data should have grown after second eBGP migration")

			By("Checking sequence continuity from TOR across both migrations")
			streamAll, err := runOnTORE(tor, fmt.Sprintf("sudo docker logs %s", ncClientContainer))
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(strings.TrimSpace(streamAll), "\n")
			logrus.Infof("eBGP TCP stream: %d lines, first: %s, last: %s",
				len(lines), lines[0], lines[len(lines)-1])

			seqGaps, lastSeq := countSequenceGaps(lines)
			logrus.Infof("eBGP sequence: %d gaps, %d data points across 2 migrations", seqGaps, lastSeq)
			Expect(seqGaps).To(BeNumerically("==", 0),
				"seamless live migration must not drop any TCP segments over eBGP")
		})
	},
)
