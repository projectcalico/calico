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
//   - Correct route programming and IPAM attribute ownership handover (Tests 1-2)
//   - Zero-downtime TCP connectivity through iBGP and eBGP during migration (Tests 3-4)
//
// Prerequisites:
//   - KubeVirt installed with live migration support
//   - IPAMConfig.kubeVirtVMAddressPersistence set to "Enabled"
//   - At least 2 schedulable worker nodes (3 recommended for double-migration tests)
//   - For Test 4: an external TOR node with BIRD eBGP peering (EXT_IP, EXT_KEY, EXT_USER)
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

		// Test 1: Routes switch to target node after migration.
		// Verifies that Felix correctly updates L3 routes during migration. Before migration,
		// the VM's /32 route is a local "scope link" route on the source node. After migration,
		// Felix detects the GARP/RARP from the newly-active VM on the target node, triggers
		// the VerifyAndSwapOwnerAttributes call, and programs the local route on the target.
		// The source node's local route must be removed.
		It("should update routes to target node after migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-route-check"
			vm := &testVM{name: vmName, namespace: ns, kvClient: kvClient}

			vm.Create(ctx)
			DeferCleanup(vm.Delete)
			originalIP, sourceNode := vm.WaitForRunningWithIP(ctx)

			// Route may take a moment to be programmed after WEP creation.
			By("Verifying local route on source node before migration")
			Eventually(func() string {
				return getRouteOnNode(f, sourceNode, originalIP)
			}, 30*time.Second, 2*time.Second).Should(ContainSubstring("scope link"),
				"expected local route on source node")

			By("Triggering live migration")
			mig := &testVMIM{name: vmName + "-migration", namespace: ns, vmiName: vmName, kvClient: kvClient}
			mig.Create(ctx)
			DeferCleanup(mig.Delete)
			mig.WaitForSuccess(ctx)

			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			targetNode := vmi.Status.NodeName
			Expect(targetNode).NotTo(Equal(sourceNode))

			By("Verifying local route on target node after migration")
			Eventually(func() string {
				return getRouteOnNode(f, targetNode, originalIP)
			}, 1*time.Minute, 5*time.Second).Should(ContainSubstring("scope link"),
				"expected local route on target node")

			By("Verifying source node no longer has local route")
			Eventually(func() bool {
				route := getRouteOnNode(f, sourceNode, originalIP)
				return !strings.Contains(route, "scope link")
			}, 1*time.Minute, 5*time.Second).Should(BeTrue(),
				"source node should not have local route after migration")
			logrus.Infof("Routes correctly switched from %s to %s", sourceNode, targetNode)
		})

		// Test 2: Owner attributes swap during migration.
		// Validates the IPAM dual-owner mechanism. Before migration, ActiveOwnerAttrs points
		// to the source pod and AlternateOwnerAttrs is empty. After migration completes and
		// Felix calls VerifyAndSwapOwnerAttributeForVM, ActiveOwnerAttrs must point to the
		// target pod (new node), confirming the atomic ownership handover worked correctly.
		It("should swap IPAM owner attributes on migration completion", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-attr-swap"
			vm := &testVM{name: vmName, namespace: ns, kvClient: kvClient}

			vm.Create(ctx)
			DeferCleanup(vm.Delete)
			originalIP, sourceNode := vm.WaitForRunningWithIP(ctx)

			sourcePod, err := vm.FindVirtLauncherPod(ctx, f)
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("Source pod: %s on %s, IP: %s", sourcePod.Name, sourceNode, originalIP)

			// IPAM attributes may take a moment to be set after CNI ADD.
			By("Verifying IPAM attributes before migration")
			lcgc := newLibcalicoClient(f)
			Eventually(func() map[string]string {
				active, _ := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
				return active
			}, 30*time.Second, 2*time.Second).Should(
				HaveKeyWithValue(model.IPAMBlockAttributePod, sourcePod.Name))

			_, alternateAttrs := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
			Expect(alternateAttrs).To(BeEmpty())

			By("Triggering live migration")
			mig := &testVMIM{name: vmName + "-migration", namespace: ns, vmiName: vmName, kvClient: kvClient}
			mig.Create(ctx)
			DeferCleanup(mig.Delete)
			mig.WaitForSuccess(ctx)

			By("Verifying ActiveOwnerAttrs changed to target pod after migration")
			var finalActivePod, finalActiveNode string
			Eventually(func() bool {
				active, _ := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
				if len(active) == 0 {
					return false
				}
				finalActivePod = active[model.IPAMBlockAttributePod]
				finalActiveNode = active[model.IPAMBlockAttributeNode]
				return finalActivePod != "" && finalActivePod != sourcePod.Name
			}, 1*time.Minute, 2*time.Second).Should(BeTrue(),
				"ActiveOwnerAttrs should change to target pod after migration")

			logrus.Infof("After swap: Active pod=%s node=%s (was %s on %s)",
				finalActivePod, finalActiveNode, sourcePod.Name, sourceNode)
			Expect(finalActivePod).NotTo(Equal(sourcePod.Name),
				"active owner should be target pod, not source")
			Expect(finalActiveNode).NotTo(Equal(sourceNode),
				"active owner should be on target node, not source node")
		})

		// Test 3: TCP connection over iBGP survives two consecutive migrations.
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
			expectPingSuccess(ns, clientPod.Name, serverIP)
			waitForTCPServer(ns, clientPod.Name, serverIP)

			// Use nohup to prevent SIGHUP when kubectl exec session closes.
			By("Starting TCP client")
			_, err := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"sh", "-c", fmt.Sprintf("nohup nc %s 9999 > /tmp/tcp_stream 2>&1 &", serverIP)).Exec()
			Expect(err).NotTo(HaveOccurred())

			// Poll for data instead of fixed sleep.
			By("Verifying TCP data is flowing before migration")
			var preLines int
			Eventually(func() int {
				preOutput, _ := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
					"wc", "-l", "/tmp/tcp_stream").Exec()
				fmt.Sscanf(strings.TrimSpace(preOutput), "%d", &preLines)
				return preLines
			}, 30*time.Second, 2*time.Second).Should(BeNumerically(">=", 5),
				"TCP data should be flowing")
			logrus.Infof("Pre-migration: %d lines on client pod", preLines)

			By("First migration")
			mig1 := &testVMIM{name: serverVMName + "-mig1", namespace: ns, vmiName: serverVMName, kvClient: kvClient}
			mig1.Create(ctx)
			DeferCleanup(mig1.Delete)
			mig1.WaitForSuccess(ctx)
			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, serverVMName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node2 := vmi.Status.NodeName
			Expect(node2).NotTo(Equal(node1))
			logrus.Infof("First migration: %s -> %s", node1, node2)

			// Poll for data growth instead of fixed sleep.
			By("Verifying TCP stream survived first migration")
			var midLines int
			Eventually(func() int {
				midOutput, _ := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
					"wc", "-l", "/tmp/tcp_stream").Exec()
				fmt.Sscanf(strings.TrimSpace(midOutput), "%d", &midLines)
				return midLines
			}, 30*time.Second, 2*time.Second).Should(BeNumerically(">=", preLines+5),
				"TCP data should have grown after first migration")
			logrus.Infof("After first migration: %d lines", midLines)

			By("Second migration")
			mig2 := &testVMIM{name: serverVMName + "-mig2", namespace: ns, vmiName: serverVMName, kvClient: kvClient}
			mig2.Create(ctx)
			DeferCleanup(mig2.Delete)
			mig2.WaitForSuccess(ctx)
			vmi, err = kvClient.VirtualMachineInstances(ns).Get(ctx, serverVMName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node3 := vmi.Status.NodeName
			// With 3 worker nodes, second migration moves away from node2.
			// It could return to node1 — that's fine, we only require it left node2.
			Expect(node3).NotTo(Equal(node2))
			logrus.Infof("Second migration: %s -> %s", node2, node3)

			// Poll for data growth instead of fixed sleep.
			By("Waiting for TCP data to grow after second migration")
			Eventually(func() int {
				postOutput, _ := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
					"wc", "-l", "/tmp/tcp_stream").Exec()
				var postLines int
				fmt.Sscanf(strings.TrimSpace(postOutput), "%d", &postLines)
				return postLines
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

		// Test 4: TCP connection from external eBGP client survives two consecutive migrations.
		// Same as Test 3 but the TCP client runs on an external TOR node connected via eBGP
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

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-ebgp-tcp"
			vm := &testVM{name: vmName, namespace: ns, cloudInit: tcpServerCloudInit, kvClient: kvClient}

			By("Creating a VM with TCP server")
			vm.Create(ctx)
			DeferCleanup(vm.Delete)

			vmIP, node1 := vm.WaitForRunningWithIP(ctx)

			By("Waiting for VM TCP server")
			probePod := setupPingPod(ctx, f, ns)
			expectPingSuccess(ns, probePod.Name, vmIP)
			waitForTCPServer(ns, probePod.Name, vmIP)
			logrus.Infof("VM %s on %s with IP %s, TCP server ready", vmName, node1, vmIP)
			Eventually(func() string {
				return runOnTOR(tor, fmt.Sprintf("ping -c 1 -W 2 %s", vmIP))
			}, 1*time.Minute, 5*time.Second).Should(ContainSubstring("0% packet loss"),
				"TOR cannot reach VM — eBGP routing may not be configured")

			// Use setsid to fully detach nc from SSH session.
			By("Starting TCP client on TOR connecting to VM")
			runOnTOR(tor, fmt.Sprintf("rm -f /tmp/tcp_stream; setsid nc %s 9999 > /tmp/tcp_stream 2>&1 &", vmIP))

			By("Verifying TCP data is flowing from TOR before migration")
			var preLines int
			Eventually(func() int {
				preOutput := runOnTOR(tor, "wc -l < /tmp/tcp_stream")
				fmt.Sscanf(strings.TrimSpace(preOutput), "%d", &preLines)
				return preLines
			}, 30*time.Second, 2*time.Second).Should(BeNumerically(">=", 5),
				"TCP data should be flowing from TOR")
			logrus.Infof("Pre-migration: %d lines received on TOR", preLines)

			By("First migration")
			mig1 := &testVMIM{name: vmName + "-mig1", namespace: ns, vmiName: vmName, kvClient: kvClient}
			mig1.Create(ctx)
			DeferCleanup(mig1.Delete)
			mig1.WaitForSuccess(ctx)
			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node2 := vmi.Status.NodeName
			Expect(node2).NotTo(Equal(node1))
			logrus.Infof("First eBGP migration: %s -> %s", node1, node2)

			By("Verifying TCP data continued on TOR after first migration")
			var midLines int
			Eventually(func() int {
				midOutput := runOnTOR(tor, "wc -l < /tmp/tcp_stream")
				fmt.Sscanf(strings.TrimSpace(midOutput), "%d", &midLines)
				return midLines
			}, 1*time.Minute, 2*time.Second).Should(BeNumerically(">=", preLines+5),
				"TCP data should have grown after first eBGP migration")
			logrus.Infof("After first eBGP migration: %d lines", midLines)

			By("Second migration")
			mig2 := &testVMIM{name: vmName + "-mig2", namespace: ns, vmiName: vmName, kvClient: kvClient}
			mig2.Create(ctx)
			DeferCleanup(mig2.Delete)
			mig2.WaitForSuccess(ctx)
			vmi, err = kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node3 := vmi.Status.NodeName
			Expect(node3).NotTo(Equal(node2))
			logrus.Infof("Second eBGP migration: %s -> %s", node2, node3)

			// eBGP route convergence through the external TOR may take longer than
			// iBGP mesh, so allow more time for data to resume after the second migration.
			By("Verifying TCP data continued on TOR after second migration")
			Eventually(func() int {
				postOutput := runOnTOR(tor, "wc -l < /tmp/tcp_stream")
				var postLines int
				fmt.Sscanf(strings.TrimSpace(postOutput), "%d", &postLines)
				return postLines
			}, 1*time.Minute, 2*time.Second).Should(BeNumerically(">=", midLines+5),
				"TCP data should have grown after second eBGP migration")

			By("Checking sequence continuity from TOR across both migrations")
			streamAll := runOnTOR(tor, "cat /tmp/tcp_stream")
			lines := strings.Split(strings.TrimSpace(streamAll), "\n")
			logrus.Infof("eBGP TCP stream: %d lines, first: %s, last: %s",
				len(lines), lines[0], lines[len(lines)-1])

			seqGaps, lastSeq := countSequenceGaps(lines)
			logrus.Infof("eBGP sequence: %d gaps, %d data points across 2 migrations", seqGaps, lastSeq)
			Expect(seqGaps).To(BeNumerically("==", 0),
				"seamless live migration must not drop any TCP segments over eBGP")

			// Cleanup: kill nc on TOR.
			runOnTOR(tor, "pkill -f 'nc.*9999' 2>/dev/null || true")
		})
	},
)
