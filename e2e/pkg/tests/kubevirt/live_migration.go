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
	"net"
	"os"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	kubevirtv1 "kubevirt.io/api/core/v1"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func init() {
	// Auto-resolve EXT_KEY from BZ_ROOT_DIR if not explicitly set.
	// This is a temporary solution until banzai-core sets EXT_KEY automatically
	// as part of the cluster provisioning workflow.
	bzRoot := os.Getenv("BZ_ROOT_DIR")
	if bzRoot != "" && os.Getenv("EXT_KEY") == "" {
		keyPath := bzRoot + "/.local/external_key"
		if _, err := os.Stat(keyPath); err == nil {
			os.Setenv("EXT_KEY", keyPath)
		}
	}
}

const (
	defaultVMImage = "mcas/kubevirt-ubuntu-20.04:latest"

	// testTimeout is the per-test context timeout.
	testTimeout = 10 * time.Minute
)

// vmImage returns the container disk image for test VMs. Configurable via the
// KUBEVIRT_TEST_VM_IMAGE env var; defaults to defaultVMImage.
func vmImage() string {
	if img := os.Getenv("KUBEVIRT_TEST_VM_IMAGE"); img != "" {
		return img
	}
	return defaultVMImage
}

// KubeVirt live migration e2e tests validate Calico's IPAM IP persistence and seamless
// migration support for KubeVirt VMs. The tests cover:
//   - IP preservation across migrations, pod evictions, and VM reboots (Tests 1-4)
//   - Correct route programming and IPAM attribute ownership handover (Tests 5-6)
//   - Zero-downtime TCP connectivity through iBGP and eBGP during migration (Tests 7-8)
//
// Prerequisites:
//   - KubeVirt installed with live migration support
//   - IPAMConfig.kubeVirtVMAddressPersistence set to "Enabled"
//   - At least 2 schedulable worker nodes (3 recommended for double-migration tests)
//   - For Test 8: an external TOR node with BIRD eBGP peering (EXT_IP, EXT_KEY, EXT_USER)
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

		// Test 1: Core live migration with IP preservation and connectivity.
		// Verifies the fundamental IPAM requirement: when a VM is live-migrated via VMIM,
		// the VM-based IPAM handle (hashed from VMI namespace+name) ensures the same IP
		// is assigned to the target pod. A ping pod confirms network reachability before
		// and after migration.
		It("should preserve VM IP address across live migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-migration-test"
			vm := &testVM{name: vmName, namespace: ns, kvClient: kvClient}

			pingPod := setupPingPod(ctx, f, ns)
			vm.Create(ctx)
			DeferCleanup(vm.Delete)

			originalIP, sourceNode := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)
			logrus.Infof("VM %s running on node %s with IP %s", vmName, sourceNode, originalIP)

			By("Verifying connectivity to VM before migration")
			expectPingSuccess(ns, pingPod.Name, originalIP)

			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-migration")

			By("Verifying VMI IP is preserved after migration")
			// F6: Use Eventually to avoid reading stale VMI status after migration.
			var postMigrationIP, postMigrationNode string
			Eventually(func() error {
				vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if len(vmi.Status.Interfaces) == 0 || vmi.Status.Interfaces[0].IP == "" {
					return fmt.Errorf("no IP yet")
				}
				if vmi.Status.NodeName == sourceNode {
					return fmt.Errorf("VMI still reports source node")
				}
				postMigrationIP = vmi.Status.Interfaces[0].IP
				postMigrationNode = vmi.Status.NodeName
				return nil
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			Expect(postMigrationIP).To(Equal(originalIP), "IP should be preserved")
			Expect(postMigrationNode).NotTo(Equal(sourceNode), "VM should have moved")
			logrus.Infof("VM migrated from %s to %s, IP preserved: %s", sourceNode, postMigrationNode, originalIP)

			By("Verifying connectivity after migration")
			expectPingSuccess(ns, pingPod.Name, originalIP)
		})

		// Test 2: IP persists when virt-launcher pod is deleted (simulating eviction).
		// When a virt-launcher pod is force-deleted (e.g. node eviction, OOM kill),
		// KubeVirt's VM controller (with RunStrategyAlways) recreates the VMI and pod.
		// Because Calico IPAM uses a VM-based handle ID derived from the VMI namespace+name
		// (not the ephemeral container ID), the new pod gets the same IP allocation.
		It("should preserve VM IP across pod recreation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-pod-recreate"
			vm := &testVM{name: vmName, namespace: ns, kvClient: kvClient}

			vm.Create(ctx)
			DeferCleanup(vm.Delete)
			originalIP, _ := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			sourcePod, err := findVirtLauncherPod(ctx, f, ns, vmName)
			Expect(err).NotTo(HaveOccurred())
			sourcePodName := sourcePod.Name
			logrus.Infof("Original pod: %s, IP: %s", sourcePodName, originalIP)

			By("Deleting the virt-launcher pod to simulate eviction")
			err = f.ClientSet.CoreV1().Pods(ns).Delete(ctx, sourcePodName, metav1.DeleteOptions{
				GracePeriodSeconds: ptrInt64(0),
			})
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for a new virt-launcher pod with the same IP")
			Eventually(func() error {
				pod, err := findVirtLauncherPod(ctx, f, ns, vmName)
				if err != nil {
					return err
				}
				if pod.Name == sourcePodName {
					return fmt.Errorf("old pod still present")
				}
				if pod.Status.Phase != corev1.PodRunning {
					return fmt.Errorf("new pod phase is %s", pod.Status.Phase)
				}
				if pod.Status.PodIP != originalIP {
					return fmt.Errorf("new pod IP %s != original %s", pod.Status.PodIP, originalIP)
				}
				logrus.Infof("New pod %s got same IP %s", pod.Name, pod.Status.PodIP)
				return nil
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		// Test 3: IP persists across VMI recreation (VM reboot).
		// Stopping a VM (RunStrategyHalted) deletes the VMI and its pod, but the IPAM
		// allocation is retained because kube-controllers GC has a 5-minute grace period
		// for VM recreation events. When the VM is started again (RunStrategyAlways),
		// the new VMI gets a new UID but the same name, so the VM-based handle ID matches
		// and the same IP is allocated.
		It("should preserve VM IP across VMI recreation (reboot)", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-vmi-recreate"
			vm := &testVM{name: vmName, namespace: ns, kvClient: kvClient}

			vm.Create(ctx)
			DeferCleanup(vm.Delete)
			originalIP, _ := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			originalVMIUID := vmi.UID
			logrus.Infof("Original VMI UID: %s, IP: %s", originalVMIUID, originalIP)

			By("Stopping the VM")
			vm.Stop(ctx)

			By("Waiting for VMI to be deleted")
			// F12: Check for specific NotFound error, not any error.
			Eventually(func() bool {
				_, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
				return kerrors.IsNotFound(err)
			}, 2*time.Minute, 5*time.Second).Should(BeTrue())

			By("Starting the VM again")
			vm.Start(ctx)

			By("Waiting for new VMI with the same IP")
			var newIP string
			Eventually(func() error {
				vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if vmi.UID == originalVMIUID {
					return fmt.Errorf("still old VMI")
				}
				if vmi.Status.Phase != kubevirtv1.Running {
					return fmt.Errorf("phase is %s", vmi.Status.Phase)
				}
				if len(vmi.Status.Interfaces) == 0 || vmi.Status.Interfaces[0].IP == "" {
					return fmt.Errorf("no IP yet")
				}
				newIP = vmi.Status.Interfaces[0].IP
				return nil
			}, 5*time.Minute, 5*time.Second).Should(Succeed())

			Expect(newIP).To(Equal(originalIP), "IP should be preserved across VMI recreation")
			logrus.Infof("VMI recreated with new UID, same IP %s", newIP)
		})

		// Test 4: Source pod deleted mid-migration — IP preserved after recovery.
		// Exercises a failure scenario: the source virt-launcher pod is force-deleted while
		// migration is in progress. The migration may succeed (if the target was already
		// ready) or fail. In either case, the VM eventually recovers with the same IP
		// because the VM-based IPAM handle persists independently of pod lifecycle.
		It("should preserve VM IP when source pod is deleted during migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-source-delete"
			vm := &testVM{name: vmName, namespace: ns, kvClient: kvClient}

			vm.Create(ctx)
			DeferCleanup(vm.Delete)
			originalIP, _ := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			sourcePod, err := findVirtLauncherPod(ctx, f, ns, vmName)
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("Source pod: %s, IP: %s", sourcePod.Name, originalIP)

			By("Triggering live migration")
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")

			By("Waiting for migration to reach an active phase, then deleting source pod")
			// F2: Migration can be very fast. Accept any non-empty phase including Succeeded.
			// If already Succeeded, we skip the pod deletion — the test still verifies IP persistence.
			var alreadySucceeded bool
			Eventually(func() bool {
				m, mErr := kvClient.VirtualMachineInstanceMigrations(ns).Get(ctx, vmName+"-migration", metav1.GetOptions{})
				if mErr != nil || m == nil {
					return false
				}
				phase := m.Status.Phase
				if phase == kubevirtv1.MigrationSucceeded {
					alreadySucceeded = true
					return true
				}
				return phase == kubevirtv1.MigrationScheduling ||
					phase == kubevirtv1.MigrationScheduled ||
					phase == kubevirtv1.MigrationPreparingTarget ||
					phase == kubevirtv1.MigrationTargetReady ||
					phase == kubevirtv1.MigrationRunning
			}, 2*time.Minute, 500*time.Millisecond).Should(BeTrue())

			if !alreadySucceeded {
				// F3: Source pod may already be gone if migration completed in the window
				// between our phase check and this delete call.
				err = f.ClientSet.CoreV1().Pods(ns).Delete(ctx, sourcePod.Name, metav1.DeleteOptions{
					GracePeriodSeconds: ptrInt64(0),
				})
				if err != nil && !kerrors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred())
				}
				logrus.Infof("Deleted source pod %s during migration", sourcePod.Name)
			} else {
				logrus.Infof("Migration already succeeded before source pod could be deleted")
			}

			By("Waiting for migration to complete (succeed or fail)")
			var migrationPhase kubevirtv1.VirtualMachineInstanceMigrationPhase
			Eventually(func() bool {
				m, mErr := kvClient.VirtualMachineInstanceMigrations(ns).Get(ctx, vmName+"-migration", metav1.GetOptions{})
				if mErr != nil || m == nil {
					return false
				}
				migrationPhase = m.Status.Phase
				return migrationPhase == kubevirtv1.MigrationSucceeded ||
					migrationPhase == kubevirtv1.MigrationFailed
			}, 3*time.Minute, 3*time.Second).Should(BeTrue())
			logrus.Infof("Migration completed with phase: %s", migrationPhase)

			By("Recovering the VM and verifying same IP")
			if migrationPhase == kubevirtv1.MigrationFailed {
				vm.Stop(ctx)
				Eventually(func() bool {
					_, vmiErr := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
					return kerrors.IsNotFound(vmiErr)
				}, 2*time.Minute, 5*time.Second).Should(BeTrue())
				vm.Start(ctx)
			}

			recoveredIP, _ := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)
			Expect(recoveredIP).To(Equal(originalIP), "IP should be preserved after failed migration recovery")
			logrus.Infof("VM recovered with same IP %s (migration was %s)", recoveredIP, migrationPhase)
		})

		// Test 5: Routes switch to target node after migration.
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
			originalIP, sourceNode := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			// F7: Route may take a moment to be programmed after WEP creation.
			By("Verifying local route on source node before migration")
			Eventually(func() string {
				return getRouteOnNode(f, sourceNode, originalIP)
			}, 30*time.Second, 2*time.Second).Should(ContainSubstring("scope link"),
				"expected local route on source node")

			By("Triggering live migration")
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-migration")

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

		// Test 6: Owner attributes swap during migration.
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
			originalIP, sourceNode := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			sourcePod, err := findVirtLauncherPod(ctx, f, ns, vmName)
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("Source pod: %s on %s, IP: %s", sourcePod.Name, sourceNode, originalIP)

			// F8: IPAM attributes may take a moment to be set after CNI ADD.
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
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-migration")

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

		// Test 7: TCP connection over iBGP survives two consecutive migrations.
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

			serverIP, node1 := waitForVMIRunningWithIP(ctx, kvClient, ns, serverVMName)
			logrus.Infof("Server VM: %s on %s", serverIP, node1)

			By("Creating client pod on a different node than server VM")
			clientPod := setupAntiAffinityPod(ctx, f, ns, node1)
			expectPingSuccess(ns, clientPod.Name, serverIP)
			waitForTCPServer(ns, clientPod.Name, serverIP)

			// F4: Use nohup to prevent SIGHUP when kubectl exec session closes.
			By("Starting TCP client")
			_, err := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"sh", "-c", fmt.Sprintf("nohup nc %s 9999 > /tmp/tcp_stream 2>&1 &", serverIP)).Exec()
			Expect(err).NotTo(HaveOccurred())

			// F5: Poll for data instead of fixed sleep.
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
			migrateAndCleanup(ctx, kvClient, ns, serverVMName, serverVMName+"-mig1")
			waitForMigrationSuccess(ctx, kvClient, ns, serverVMName+"-mig1")
			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, serverVMName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node2 := vmi.Status.NodeName
			Expect(node2).NotTo(Equal(node1))
			logrus.Infof("First migration: %s -> %s", node1, node2)

			// F5: Poll for data growth instead of fixed sleep.
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
			migrateAndCleanup(ctx, kvClient, ns, serverVMName, serverVMName+"-mig2")
			waitForMigrationSuccess(ctx, kvClient, ns, serverVMName+"-mig2")
			vmi, err = kvClient.VirtualMachineInstances(ns).Get(ctx, serverVMName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node3 := vmi.Status.NodeName
			// With 3 worker nodes, second migration moves away from node2.
			// It could return to node1 — that's fine, we only require it left node2.
			Expect(node3).NotTo(Equal(node2))
			logrus.Infof("Second migration: %s -> %s", node2, node3)

			// F5: Poll for data growth instead of fixed sleep.
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

		// Test 8: TCP connection from external eBGP client survives two consecutive migrations.
		// Same as Test 7 but the TCP client runs on an external TOR node connected via eBGP
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

			vmIP, node1 := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			By("Waiting for VM TCP server")
			probePod := setupPingPod(ctx, f, ns)
			expectPingSuccess(ns, probePod.Name, vmIP)
			waitForTCPServer(ns, probePod.Name, vmIP)
			logrus.Infof("VM %s on %s with IP %s, TCP server ready", vmName, node1, vmIP)
			Eventually(func() string {
				return runOnTOR(tor, fmt.Sprintf("ping -c 1 -W 2 %s", vmIP))
			}, 1*time.Minute, 5*time.Second).Should(ContainSubstring("0% packet loss"),
				"TOR cannot reach VM — eBGP routing may not be configured")

			// F9: Use setsid to fully detach nc from SSH session.
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
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-mig1")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-mig1")
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
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-mig2")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-mig2")
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

// --- Helper functions ---

const defaultCloudInit = "#cloud-config\npassword: testpass\nchpasswd: { expire: False }\nssh_pwauth: True\n"

const tcpServerCloudInit = `#cloud-config
password: testpass
chpasswd: { expire: False }
ssh_pwauth: True
write_files:
  - path: /usr/local/bin/tcp-server.py
    permissions: '0755'
    content: |
      #!/usr/bin/env python3
      import socket, threading, time
      def handle(conn, addr):
          try:
              seq = 0
              while True:
                  conn.sendall(f"seq={seq}\n".encode())
                  seq += 1
                  time.sleep(1)
          except Exception:
              pass
          finally:
              conn.close()
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      s.bind(("0.0.0.0", 9999))
      s.listen(5)
      while True:
          conn, addr = s.accept()
          threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
runcmd:
  - [bash, -c, "nohup python3 /usr/local/bin/tcp-server.py &"]
`

// testVM encapsulates a KubeVirt VirtualMachine for e2e tests.
type testVM struct {
	name      string
	namespace string
	cloudInit string
	kvClient  kubevirtcorev1.KubevirtV1Interface
}

func (v *testVM) spec() *kubevirtv1.VirtualMachine {
	cloudInit := v.cloudInit
	if cloudInit == "" {
		cloudInit = defaultCloudInit
	}
	runStrategy := kubevirtv1.RunStrategyAlways
	return &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name: v.name, Namespace: v.namespace,
			Labels: map[string]string{"vm": v.name, utils.TestResourceLabel: "true"},
		},
		Spec: kubevirtv1.VirtualMachineSpec{
			RunStrategy: &runStrategy,
			Template: &kubevirtv1.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"kubevirt.io/allow-pod-bridge-network-live-migration": "true"},
					Labels:      map[string]string{"vm": v.name, utils.TestResourceLabel: "true"},
				},
				Spec: kubevirtv1.VirtualMachineInstanceSpec{
					Domain: kubevirtv1.DomainSpec{
						Resources: kubevirtv1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("512Mi")},
						},
						Devices: kubevirtv1.Devices{
							Disks: []kubevirtv1.Disk{
								{Name: "containerdisk", DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}}},
								{Name: "cloudinitdisk", DiskDevice: kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}}},
							},
							Interfaces: []kubevirtv1.Interface{
								{Name: "default", InterfaceBindingMethod: kubevirtv1.InterfaceBindingMethod{Bridge: &kubevirtv1.InterfaceBridge{}}},
							},
						},
					},
					Networks:                      []kubevirtv1.Network{{Name: "default", NetworkSource: kubevirtv1.NetworkSource{Pod: &kubevirtv1.PodNetwork{}}}},
					TerminationGracePeriodSeconds: ptrInt64(30),
					Volumes: []kubevirtv1.Volume{
						{Name: "containerdisk", VolumeSource: kubevirtv1.VolumeSource{ContainerDisk: &kubevirtv1.ContainerDiskSource{Image: vmImage()}}},
						{Name: "cloudinitdisk", VolumeSource: kubevirtv1.VolumeSource{CloudInitNoCloud: &kubevirtv1.CloudInitNoCloudSource{
							UserData: cloudInit,
						}}},
					},
				},
			},
		},
	}
}

// Create creates the VirtualMachine in the cluster.
func (v *testVM) Create(ctx context.Context) {
	By(fmt.Sprintf("Creating VirtualMachine %s", v.name))
	_, err := v.kvClient.VirtualMachines(v.namespace).Create(ctx, v.spec(), metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

// Delete removes the VirtualMachine from the cluster.
func (v *testVM) Delete() {
	logrus.Infof("Cleaning up VM %s/%s", v.namespace, v.name)
	_ = v.kvClient.VirtualMachines(v.namespace).Delete(context.Background(), v.name, metav1.DeleteOptions{})
}

// Stop sets RunStrategy to Halted, causing KubeVirt to delete the VMI and pod.
func (v *testVM) Stop(ctx context.Context) {
	Eventually(func() error {
		stopStrategy := kubevirtv1.RunStrategyHalted
		vm, err := v.kvClient.VirtualMachines(v.namespace).Get(ctx, v.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get VM: %w", err)
		}
		vm.Spec.RunStrategy = &stopStrategy
		vm.Spec.Running = nil
		_, err = v.kvClient.VirtualMachines(v.namespace).Update(ctx, vm, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("update VM: %w", err)
		}
		return nil
	}, 1*time.Minute, 5*time.Second).Should(Succeed(), "failed to stop VM %s", v.name)
}

// Start sets RunStrategy to Always, causing KubeVirt to create a new VMI and pod.
func (v *testVM) Start(ctx context.Context) {
	Eventually(func() error {
		startStrategy := kubevirtv1.RunStrategyAlways
		vm, err := v.kvClient.VirtualMachines(v.namespace).Get(ctx, v.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get VM: %w", err)
		}
		vm.Spec.RunStrategy = &startStrategy
		vm.Spec.Running = nil
		_, err = v.kvClient.VirtualMachines(v.namespace).Update(ctx, vm, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("update VM: %w", err)
		}
		return nil
	}, 1*time.Minute, 5*time.Second).Should(Succeed(), "failed to start VM %s", v.name)
}

// setupPingPod creates a long-running Alpine pod for connectivity checks (ping, nc).
// The pod is scheduled on any Linux node and cleaned up after the test.
func setupPingPod(ctx context.Context, f *framework.Framework, ns string) *corev1.Pod {
	By("Creating a ping pod for connectivity checks")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ping-test", Namespace: ns, Labels: map[string]string{utils.TestResourceLabel: "true"}},
		Spec: corev1.PodSpec{
			Containers:    []corev1.Container{{Name: "ping", Image: images.Alpine, Command: []string{"sleep", "3600"}}},
			RestartPolicy: corev1.RestartPolicyNever,
			NodeSelector:  map[string]string{"kubernetes.io/os": "linux"},
		},
	}
	created, err := f.ClientSet.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() {
		_ = f.ClientSet.CoreV1().Pods(ns).Delete(context.Background(), created.Name, metav1.DeleteOptions{})
	})
	err = e2epod.WaitTimeoutForPodRunningInNamespace(ctx, f.ClientSet, created.Name, ns, 2*time.Minute)
	Expect(err).NotTo(HaveOccurred(), "pod %s not Running", created.Name)
	return created
}

// setupAntiAffinityPod creates a long-running Alpine pod with a node anti-affinity rule
// that prevents scheduling on avoidNode. Used for TCP tests where the client must be on
// a different node than the server VM to exercise cross-node BGP routing.
func setupAntiAffinityPod(ctx context.Context, f *framework.Framework, ns, avoidNode string) *corev1.Pod {
	By(fmt.Sprintf("Creating client pod avoiding node %s", avoidNode))
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "tcp-client", Namespace: ns, Labels: map[string]string{utils.TestResourceLabel: "true"}},
		Spec: corev1.PodSpec{
			Containers:    []corev1.Container{{Name: "client", Image: images.Alpine, Command: []string{"sleep", "3600"}}},
			RestartPolicy: corev1.RestartPolicyNever,
			NodeSelector:  map[string]string{"kubernetes.io/os": "linux"},
			Affinity: &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "kubernetes.io/hostname",
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{avoidNode},
							}},
						}},
					},
				},
			},
		},
	}
	created, err := f.ClientSet.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() {
		_ = f.ClientSet.CoreV1().Pods(ns).Delete(context.Background(), created.Name, metav1.DeleteOptions{})
	})
	err = e2epod.WaitTimeoutForPodRunningInNamespace(ctx, f.ClientSet, created.Name, ns, 2*time.Minute)
	Expect(err).NotTo(HaveOccurred(), "pod %s not Running", created.Name)
	pod2, err := f.ClientSet.CoreV1().Pods(ns).Get(ctx, created.Name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	Expect(pod2.Spec.NodeName).NotTo(Equal(avoidNode), "client pod should be on a different node")
	logrus.Infof("Client pod %s on %s (server VM on %s)", created.Name, pod2.Spec.NodeName, avoidNode)
	return created
}

// migrateAndCleanup creates a VirtualMachineInstanceMigration (VMIM) resource to trigger
// a live migration of the specified VMI, and registers a DeferCleanup to delete the VMIM.
func migrateAndCleanup(ctx context.Context, kvClient kubevirtcorev1.KubevirtV1Interface, ns, vmiName, vmimName string) {
	By(fmt.Sprintf("Creating migration %s", vmimName))
	vmim := &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{Name: vmimName, Namespace: ns},
		Spec:       kubevirtv1.VirtualMachineInstanceMigrationSpec{VMIName: vmiName},
	}
	_, err := kvClient.VirtualMachineInstanceMigrations(ns).Create(ctx, vmim, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() {
		_ = kvClient.VirtualMachineInstanceMigrations(ns).Delete(context.Background(), vmimName, metav1.DeleteOptions{})
	})
}

// waitForVMIRunningWithIP polls the VMI until it reaches Running phase and has an IP
// address assigned. Returns the IP and the node where the VMI is scheduled.
func waitForVMIRunningWithIP(ctx context.Context, kvClient kubevirtcorev1.KubevirtV1Interface, ns, vmName string) (ip, node string) {
	By(fmt.Sprintf("Waiting for VMI %s to be Running with IP", vmName))
	Eventually(func() error {
		vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if vmi.Status.Phase != kubevirtv1.Running {
			return fmt.Errorf("phase is %s", vmi.Status.Phase)
		}
		if len(vmi.Status.Interfaces) == 0 || vmi.Status.Interfaces[0].IP == "" {
			return fmt.Errorf("no IP yet")
		}
		ip = vmi.Status.Interfaces[0].IP
		node = vmi.Status.NodeName
		return nil
	}, 5*time.Minute, 5*time.Second).Should(Succeed())
	return
}

// waitForMigrationSuccess polls the VMIM until it reaches MigrationSucceeded phase.
// Immediately stops polling with a fatal error if MigrationFailed is observed.
func waitForMigrationSuccess(ctx context.Context, kvClient kubevirtcorev1.KubevirtV1Interface, ns, vmimName string) {
	By(fmt.Sprintf("Waiting for migration %s to succeed", vmimName))
	Eventually(func() error {
		m, err := kvClient.VirtualMachineInstanceMigrations(ns).Get(ctx, vmimName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if m.Status.Phase == kubevirtv1.MigrationFailed {
			return StopTrying("migration failed")
		}
		if m.Status.Phase != kubevirtv1.MigrationSucceeded {
			return fmt.Errorf("phase is %s", m.Status.Phase)
		}
		return nil
	}, 5*time.Minute, 5*time.Second).Should(Succeed())
}

// findVirtLauncherPod finds the running virt-launcher pod for a given VMI by label selector.
// Returns the first Running pod that is not being deleted, or an error if none found.
func findVirtLauncherPod(ctx context.Context, f *framework.Framework, namespace, vmiName string) (*corev1.Pod, error) {
	pods, err := f.ClientSet.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("kubevirt.io=virt-launcher,vm.kubevirt.io/name=%s", vmiName),
	})
	if err != nil {
		return nil, err
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase == corev1.PodRunning && pod.DeletionTimestamp == nil {
			return pod, nil
		}
	}
	return nil, fmt.Errorf("no running virt-launcher pod found for VMI %s (total pods: %d)", vmiName, len(pods.Items))
}

// expectPingSuccess verifies ICMP connectivity from a pod to the target IP.
// Retries for up to 3 minutes to allow for route convergence after migration.
func expectPingSuccess(ns, podName, targetIP string) {
	Eventually(func() error {
		output, err := kubectl.NewKubectlCommand(ns, "exec", podName, "--",
			"ping", "-c", "3", "-W", "2", targetIP).Exec()
		if err != nil {
			return fmt.Errorf("ping failed: %v, output: %s", err, output)
		}
		return nil
	}, 3*time.Minute, 10*time.Second).Should(Succeed(), "failed to ping %s", targetIP)
}

// getRouteOnNode runs "ip route show <ip>" inside the calico-node pod on the given node
// and returns the output. Used to verify that Felix programs/removes local routes for
// the VM's /32 during migration.
func getRouteOnNode(f *framework.Framework, nodeName, ip string) string {
	calicoNodePod := utils.GetCalicoNodePodOnNode(f.ClientSet, nodeName)
	if calicoNodePod == nil {
		logrus.Warnf("No calico-node pod found on node %s", nodeName)
		return ""
	}
	output, err := utils.ExecInCalicoNode(calicoNodePod, fmt.Sprintf("ip route show %s", ip))
	if err != nil {
		logrus.Warnf("Failed to get route on node %s: %v", nodeName, err)
		return ""
	}
	return strings.TrimSpace(output)
}

// newLibcalicoClient creates a libcalico-go clientv3.Interface for direct IPAM queries.
// Uses the Kubernetes datastore backend with the test framework's kubeconfig.
func newLibcalicoClient(f *framework.Framework) clientv3.Interface {
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = apiconfig.Kubernetes
	cfg.Spec.Kubeconfig = framework.TestContext.KubeConfig
	c, err := clientv3.New(*cfg)
	Expect(err).NotTo(HaveOccurred())
	return c
}

// getIPAMOwnerAttributes queries Calico IPAM for the ActiveOwnerAttrs and AlternateOwnerAttrs
// of the given IP address. Returns nil maps if the IP is not allocated or on error.
func getIPAMOwnerAttributes(ctx context.Context, c clientv3.Interface, ipStr string) (active, alternate map[string]string) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ip := cnet.IP{IP: net.ParseIP(ipStr)}
	attr, err := c.IPAM().GetAssignmentAttributes(queryCtx, ip)
	if err != nil || attr == nil {
		return nil, nil
	}
	return attr.ActiveOwnerAttrs, attr.AlternateOwnerAttrs
}

// waitForTCPServer waits for the VM's TCP server on port 9999 to accept connections.
// F13: Increased timeout to 5s for nc, and 2 minutes overall for slow-booting VMs.
func waitForTCPServer(ns, podName, vmIP string) {
	By(fmt.Sprintf("Waiting for TCP server on %s:9999", vmIP))
	Eventually(func() error {
		output, err := kubectl.NewKubectlCommand(ns, "exec", podName, "--",
			"sh", "-c", fmt.Sprintf("timeout 5 nc %s 9999 || true", vmIP)).Exec()
		if err != nil {
			return fmt.Errorf("nc exec failed: %v", err)
		}
		if !strings.Contains(output, "seq=") {
			return fmt.Errorf("TCP server not ready (no seq= in output)")
		}
		return nil
	}, 2*time.Minute, 5*time.Second).Should(Succeed(), "TCP server not ready on VM %s", vmIP)
	logrus.Infof("TCP server ready on %s:9999", vmIP)
}

// countSequenceGaps parses "seq=N" lines and counts gaps in the sequence.
func countSequenceGaps(lines []string) (gaps, lastSeq int) {
	first := true
	for _, line := range lines {
		var seq int
		if _, scanErr := fmt.Sscanf(line, "seq=%d", &seq); scanErr == nil {
			if !first && seq != lastSeq+1 {
				gaps++
				logrus.Infof("Sequence gap: %d -> %d", lastSeq, seq)
			}
			first = false
			lastSeq = seq
		}
	}
	return
}

// runOnTOR executes a shell command on the external TOR node via SSH and returns stdout.
// Logs a warning on error but does not fail the test — callers decide how to handle errors.
func runOnTOR(tor *externalnode.Client, cmd string) string {
	output, err := tor.Exec("sh", "-c", cmd)
	if err != nil {
		logrus.Warnf("TOR command failed: %s: %v", cmd, err)
	}
	return output
}

func ptrInt64(v int64) *int64 { return &v }
