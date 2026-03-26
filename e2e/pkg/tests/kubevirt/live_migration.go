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

	"github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	kubevirtv1 "kubevirt.io/api/core/v1"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	torIP   = os.Getenv("TOR_IP")
	torKey  = os.Getenv("TOR_KEY")
	torUser = os.Getenv("TOR_USER")
)

const (
	vmImage = "mcas/kubevirt-ubuntu-20.04:latest"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("KubeVirt"),
	describe.WithCategory(describe.Networking),
	"KubeVirt live migration",
	func() {
		f := utils.NewDefaultFramework("calico-kubevirt")

		var kvClient kubevirtcorev1.KubevirtV1Interface

		ginkgo.BeforeEach(func() {
			nodeCtx, nodeCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer nodeCancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(nodeCtx, f.ClientSet, 3)
			Expect(err).NotTo(HaveOccurred(), "failed to list schedulable nodes")
			if len(nodes.Items) < 2 {
				ginkgo.Skip("live migration requires at least 2 schedulable nodes")
			}

			kvClient, err = kubevirtcorev1.NewForConfig(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to create KubeVirt client")
		})

		// Test 1: Core live migration with IP preservation and connectivity.
		ginkgo.It("should preserve VM IP address across live migration", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			vmName := "e2e-migration-test"

			pingPod := setupPingPod(ctx, f, ns)
			createAndCleanupVM(ctx, kvClient, f, ns, vmName)

			originalIP, sourceNode := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)
			logrus.Infof("VM %s running on node %s with IP %s", vmName, sourceNode, originalIP)

			ginkgo.By("Verifying connectivity to VM before migration")
			expectPingSuccess(ns, pingPod.Name, originalIP)

			vmim := migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")
			_ = vmim
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-migration")

			ginkgo.By("Verifying VMI IP is preserved after migration")
			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(vmi.Status.Interfaces[0].IP).To(Equal(originalIP), "IP should be preserved")
			Expect(vmi.Status.NodeName).NotTo(Equal(sourceNode), "VM should have moved")
			logrus.Infof("VM migrated from %s to %s, IP preserved: %s", sourceNode, vmi.Status.NodeName, originalIP)

			ginkgo.By("Verifying connectivity after migration")
			expectPingSuccess(ns, pingPod.Name, originalIP)
		})

		// Test 2: IP persists when virt-launcher pod is deleted (simulating eviction).
		ginkgo.It("should preserve VM IP across pod recreation", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			vmName := "e2e-pod-recreate"

			createAndCleanupVM(ctx, kvClient, f, ns, vmName)
			originalIP, _ := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			sourcePod, err := findVirtLauncherPod(ctx, f, ns, vmName)
			Expect(err).NotTo(HaveOccurred())
			sourcePodName := sourcePod.Name
			logrus.Infof("Original pod: %s, IP: %s", sourcePodName, originalIP)

			ginkgo.By("Deleting the virt-launcher pod to simulate eviction")
			err = f.ClientSet.CoreV1().Pods(ns).Delete(ctx, sourcePodName, metav1.DeleteOptions{
				GracePeriodSeconds: ptrInt64(0),
			})
			Expect(err).NotTo(HaveOccurred())

			ginkgo.By("Waiting for a new virt-launcher pod with the same IP")
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
		ginkgo.It("should preserve VM IP across VMI recreation (reboot)", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			vmName := "e2e-vmi-recreate"

			createAndCleanupVM(ctx, kvClient, f, ns, vmName)
			originalIP, _ := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			originalVMIUID := vmi.UID
			logrus.Infof("Original VMI UID: %s, IP: %s", originalVMIUID, originalIP)

			ginkgo.By("Stopping the VM")
			stopVM(ctx, kvClient, ns, vmName)

			ginkgo.By("Waiting for VMI to be deleted")
			Eventually(func() bool {
				_, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
				return err != nil
			}, 2*time.Minute, 5*time.Second).Should(BeTrue())

			ginkgo.By("Starting the VM again")
			startVM(ctx, kvClient, ns, vmName)

			ginkgo.By("Waiting for new VMI with the same IP")
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
		ginkgo.It("should preserve VM IP when source pod is deleted during migration", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			vmName := "e2e-source-delete"

			createAndCleanupVM(ctx, kvClient, f, ns, vmName)
			originalIP, _ := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			sourcePod, err := findVirtLauncherPod(ctx, f, ns, vmName)
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("Source pod: %s, IP: %s", sourcePod.Name, originalIP)

			ginkgo.By("Triggering live migration")
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")

			ginkgo.By("Waiting for migration to be Running, then deleting source pod")
			Eventually(func() string {
				m, _ := kvClient.VirtualMachineInstanceMigrations(ns).Get(ctx, vmName+"-migration", metav1.GetOptions{})
				if m == nil {
					return ""
				}
				return string(m.Status.Phase)
			}, 2*time.Minute, 2*time.Second).Should(Equal(string(kubevirtv1.MigrationRunning)))

			err = f.ClientSet.CoreV1().Pods(ns).Delete(ctx, sourcePod.Name, metav1.DeleteOptions{
				GracePeriodSeconds: ptrInt64(0),
			})
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("Deleted source pod %s during migration", sourcePod.Name)

			ginkgo.By("Waiting for migration to fail")
			Eventually(func() string {
				m, _ := kvClient.VirtualMachineInstanceMigrations(ns).Get(ctx, vmName+"-migration", metav1.GetOptions{})
				if m == nil {
					return ""
				}
				return string(m.Status.Phase)
			}, 3*time.Minute, 3*time.Second).Should(Equal(string(kubevirtv1.MigrationFailed)))

			ginkgo.By("Recovering the VM and verifying same IP")
			stopVM(ctx, kvClient, ns, vmName)
			Eventually(func() bool {
				_, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
				return err != nil
			}, 2*time.Minute, 5*time.Second).Should(BeTrue())
			startVM(ctx, kvClient, ns, vmName)

			recoveredIP, _ := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)
			Expect(recoveredIP).To(Equal(originalIP), "IP should be preserved after failed migration recovery")
			logrus.Infof("VM recovered with same IP %s", recoveredIP)
		})

		// Test 5: TCP connection survives live migration.
		// A VM runs a TCP server (via cloud-init) that sends "seq=N" every second.
		// A pod connects as a TCP client. We migrate the VM and verify the TCP
		// stream continues without connection reset.
		ginkgo.It("should maintain TCP connection during live migration", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			vmName := "e2e-tcp-survive"

			clientPod := setupPingPod(ctx, f, ns)

			ginkgo.By("Creating a VM with TCP server on port 9999")
			vm := newTestVMWithTCPServer(vmName, ns)
			_, err := kvClient.VirtualMachines(ns).Create(ctx, vm, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			ginkgo.DeferCleanup(func() {
				_ = kvClient.VirtualMachines(ns).Delete(context.Background(), vmName, metav1.DeleteOptions{})
			})

			vmIP, _ := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			ginkgo.By("Waiting for VM networking and TCP server")
			expectPingSuccess(ns, clientPod.Name, vmIP)
			waitForTCPServer(ns, clientPod.Name, vmIP)

			ginkgo.By("Starting background TCP client collecting data stream")
			_, err = kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"sh", "-c", fmt.Sprintf("nc %s 9999 > /tmp/tcp_stream 2>&1 &", vmIP)).Exec()
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(10 * time.Second)

			ginkgo.By("Verifying TCP data is flowing before migration")
			preOutput, err := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"wc", "-l", "/tmp/tcp_stream").Exec()
			Expect(err).NotTo(HaveOccurred())
			var preLines int
			fmt.Sscanf(strings.TrimSpace(preOutput), "%d", &preLines)
			logrus.Infof("Pre-migration: %d lines received", preLines)
			Expect(preLines).To(BeNumerically(">=", 5), "TCP data should be flowing")

			ginkgo.By("Migrating the VM")
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-migration")
			logrus.Infof("Migration succeeded")
			time.Sleep(15 * time.Second)

			ginkgo.By("Verifying TCP data continued after migration")
			postOutput, err := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"wc", "-l", "/tmp/tcp_stream").Exec()
			Expect(err).NotTo(HaveOccurred())
			var postLines int
			fmt.Sscanf(strings.TrimSpace(postOutput), "%d", &postLines)
			logrus.Infof("Post-migration: %d lines (was %d)", postLines, preLines)
			Expect(postLines).To(BeNumerically(">", preLines),
				"TCP stream stopped — no new data after migration")

			ginkgo.By("Checking sequence continuity")
			streamAll, err := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"cat", "/tmp/tcp_stream").Exec()
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(strings.TrimSpace(streamAll), "\n")
			logrus.Infof("TCP stream: %d lines, first: %s, last: %s",
				len(lines), lines[0], lines[len(lines)-1])

			var lastSeq, seqGaps int
			for _, line := range lines {
				var seq int
				if _, scanErr := fmt.Sscanf(line, "seq=%d", &seq); scanErr == nil {
					if lastSeq > 0 && seq != lastSeq+1 {
						seqGaps++
						logrus.Infof("Sequence gap: %d -> %d", lastSeq, seq)
					}
					lastSeq = seq
				}
			}
			logrus.Infof("Sequence: %d gaps, %d total data points", seqGaps, lastSeq)
			Expect(seqGaps).To(BeNumerically("<=", 3),
				"too many sequence gaps — TCP connection likely reset during migration")
		})

		// Test 6: Routes switch to target node after migration.
		ginkgo.It("should update routes to target node after migration", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			vmName := "e2e-route-check"

			createAndCleanupVM(ctx, kvClient, f, ns, vmName)
			originalIP, sourceNode := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			ginkgo.By("Verifying local route on source node before migration")
			sourceRoute := getRouteOnNode(f, sourceNode, originalIP)
			Expect(sourceRoute).To(ContainSubstring("scope link"),
				"expected local route on source node")
			logrus.Infof("Source route: %s", sourceRoute)

			ginkgo.By("Triggering live migration")
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-migration")

			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			targetNode := vmi.Status.NodeName
			Expect(targetNode).NotTo(Equal(sourceNode))

			ginkgo.By("Verifying local route on target node after migration")
			Eventually(func() string {
				return getRouteOnNode(f, targetNode, originalIP)
			}, 1*time.Minute, 5*time.Second).Should(ContainSubstring("scope link"),
				"expected local route on target node")

			ginkgo.By("Verifying source node no longer has local route")
			Eventually(func() bool {
				route := getRouteOnNode(f, sourceNode, originalIP)
				return !strings.Contains(route, "scope link")
			}, 1*time.Minute, 5*time.Second).Should(BeTrue(),
				"source node should not have local route after migration")
			logrus.Infof("Routes correctly switched from %s to %s", sourceNode, targetNode)
		})

		// Test 7: Owner attributes swap during migration.
		ginkgo.It("should swap IPAM owner attributes on migration completion", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			vmName := "e2e-attr-swap"

			createAndCleanupVM(ctx, kvClient, f, ns, vmName)
			originalIP, sourceNode := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			sourcePod, err := findVirtLauncherPod(ctx, f, ns, vmName)
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("Source pod: %s on %s, IP: %s", sourcePod.Name, sourceNode, originalIP)

			ginkgo.By("Verifying IPAM attributes before migration")
			lcgc := newLibcalicoClient(f)
			activeAttrs, alternateAttrs := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
			Expect(activeAttrs).To(HaveKeyWithValue(model.IPAMBlockAttributePod, sourcePod.Name))
			Expect(alternateAttrs).To(BeEmpty())

			ginkgo.By("Triggering live migration")
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")

			ginkgo.By("Verifying AlternateOwnerAttrs is populated during migration")
			var targetPodName string
			Eventually(func() bool {
				_, alt := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
				if len(alt) > 0 {
					targetPodName = alt[model.IPAMBlockAttributePod]
					return true
				}
				return false
			}, 2*time.Minute, 2*time.Second).Should(BeTrue())

			midActive, midAlternate := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
			logrus.Infof("During migration: Active=%s (source), Alternate=%s (target)",
				midActive[model.IPAMBlockAttributePod], midAlternate[model.IPAMBlockAttributePod])
			Expect(midActive[model.IPAMBlockAttributePod]).To(Equal(sourcePod.Name))
			Expect(targetPodName).NotTo(Equal(sourcePod.Name))

			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-migration")

			ginkgo.By("Verifying attributes are swapped after migration")
			Eventually(func() string {
				active, _ := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
				return active[model.IPAMBlockAttributePod]
			}, 1*time.Minute, 2*time.Second).Should(Equal(targetPodName))

			finalActive, finalAlternate := getIPAMOwnerAttributes(ctx, lcgc, originalIP)
			logrus.Infof("After swap: Active=%s, Alternate=%s",
				finalActive[model.IPAMBlockAttributePod], finalAlternate[model.IPAMBlockAttributePod])
			Expect(finalActive[model.IPAMBlockAttributePod]).To(Equal(targetPodName))
			Expect(finalAlternate[model.IPAMBlockAttributePod]).To(Equal(sourcePod.Name))
		})
		// Test 8: TCP connection survives two consecutive migrations.
		ginkgo.It("should maintain TCP connection across two consecutive live migrations", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			vmName := "e2e-tcp-double"

			clientPod := setupPingPod(ctx, f, ns)

			ginkgo.By("Creating a VM with TCP server")
			vm := newTestVMWithTCPServer(vmName, ns)
			_, err := kvClient.VirtualMachines(ns).Create(ctx, vm, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			ginkgo.DeferCleanup(func() {
				_ = kvClient.VirtualMachines(ns).Delete(context.Background(), vmName, metav1.DeleteOptions{})
			})

			vmIP, node1 := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)
			expectPingSuccess(ns, clientPod.Name, vmIP)
			waitForTCPServer(ns, clientPod.Name, vmIP)

			ginkgo.By("Starting TCP client")
			_, err = kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"sh", "-c", fmt.Sprintf("nc %s 9999 > /tmp/tcp_stream 2>&1 &", vmIP)).Exec()
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(10 * time.Second)

			ginkgo.By("First migration")
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-mig1")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-mig1")
			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node2 := vmi.Status.NodeName
			Expect(node2).NotTo(Equal(node1))
			logrus.Infof("First migration: %s -> %s", node1, node2)
			time.Sleep(10 * time.Second)

			ginkgo.By("Verifying TCP stream survived first migration")
			midOutput, err := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"wc", "-l", "/tmp/tcp_stream").Exec()
			Expect(err).NotTo(HaveOccurred())
			var midLines int
			fmt.Sscanf(strings.TrimSpace(midOutput), "%d", &midLines)
			logrus.Infof("After first migration: %d lines", midLines)
			Expect(midLines).To(BeNumerically(">=", 15))

			ginkgo.By("Second migration")
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-mig2")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-mig2")
			vmi, err = kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node3 := vmi.Status.NodeName
			Expect(node3).NotTo(Equal(node2))
			logrus.Infof("Second migration: %s -> %s", node2, node3)
			time.Sleep(15 * time.Second)

			ginkgo.By("Verifying TCP stream survived both migrations")
			streamAll, err := kubectl.NewKubectlCommand(ns, "exec", clientPod.Name, "--",
				"cat", "/tmp/tcp_stream").Exec()
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(strings.TrimSpace(streamAll), "\n")
			logrus.Infof("TCP stream: %d lines, first: %s, last: %s",
				len(lines), lines[0], lines[len(lines)-1])

			var lastSeq, seqGaps int
			for _, line := range lines {
				var seq int
				if _, scanErr := fmt.Sscanf(line, "seq=%d", &seq); scanErr == nil {
					if lastSeq > 0 && seq != lastSeq+1 {
						seqGaps++
						logrus.Infof("Sequence gap: %d -> %d", lastSeq, seq)
					}
					lastSeq = seq
				}
			}
			logrus.Infof("Sequence: %d gaps, %d data points across 2 migrations", seqGaps, lastSeq)
			Expect(seqGaps).To(BeNumerically("<=", 5),
				"too many gaps — TCP connection likely reset during consecutive migrations")
		})

		// Test 9: TCP connection from external eBGP client survives migration.
		// Requires TOR_IP, TOR_KEY, TOR_USER env vars pointing to the TOR node.
		ginkgo.It("should maintain TCP connection from eBGP external client during migration", func() {
			if torIP == "" || torKey == "" {
				ginkgo.Skip("TOR_IP and TOR_KEY env vars required for eBGP test")
			}
			if torUser == "" {
				torUser = "ubuntu"
			}

			ctx := context.Background()
			ns := f.Namespace.Name
			vmName := "e2e-ebgp-tcp"

			ginkgo.By("Creating a VM with TCP server")
			vm := newTestVMWithTCPServer(vmName, ns)
			_, err := kvClient.VirtualMachines(ns).Create(ctx, vm, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			ginkgo.DeferCleanup(func() {
				_ = kvClient.VirtualMachines(ns).Delete(context.Background(), vmName, metav1.DeleteOptions{})
			})

			vmIP, sourceNode := waitForVMIRunningWithIP(ctx, kvClient, ns, vmName)

			ginkgo.By("Waiting for VM TCP server")
			// Use a cluster pod to verify TCP server is up first.
			probePod := setupPingPod(ctx, f, ns)
			expectPingSuccess(ns, probePod.Name, vmIP)
			waitForTCPServer(ns, probePod.Name, vmIP)
			logrus.Infof("VM %s on %s with IP %s, TCP server ready", vmName, sourceNode, vmIP)

			ginkgo.By("Verifying TOR can reach VM via eBGP")
			tor := externalnode.NewClientManualConfig(torIP, torKey, torUser)
			torOutput := runOnTOR(tor, fmt.Sprintf("ping -c 3 -W 2 %s", vmIP))
			Expect(torOutput).To(ContainSubstring("0% packet loss"),
				"TOR cannot reach VM — eBGP routing may not be configured")

			ginkgo.By("Starting TCP client on TOR connecting to VM")
			runOnTOR(tor, fmt.Sprintf("rm -f /tmp/tcp_stream; nc %s 9999 > /tmp/tcp_stream 2>&1 &", vmIP))
			time.Sleep(10 * time.Second)

			ginkgo.By("Verifying TCP data is flowing from TOR before migration")
			preOutput := runOnTOR(tor, "wc -l < /tmp/tcp_stream")
			var preLines int
			fmt.Sscanf(strings.TrimSpace(preOutput), "%d", &preLines)
			logrus.Infof("Pre-migration: %d lines received on TOR", preLines)
			Expect(preLines).To(BeNumerically(">=", 5), "TCP data should be flowing from TOR")

			ginkgo.By("Migrating the VM")
			migrateAndCleanup(ctx, kvClient, ns, vmName, vmName+"-migration")
			waitForMigrationSuccess(ctx, kvClient, ns, vmName+"-migration")

			vmi, err := kvClient.VirtualMachineInstances(ns).Get(ctx, vmName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			targetNode := vmi.Status.NodeName
			Expect(targetNode).NotTo(Equal(sourceNode))
			logrus.Infof("Migration succeeded: %s -> %s", sourceNode, targetNode)
			time.Sleep(15 * time.Second)

			ginkgo.By("Verifying TCP data continued on TOR after migration")
			postOutput := runOnTOR(tor, "wc -l < /tmp/tcp_stream")
			var postLines int
			fmt.Sscanf(strings.TrimSpace(postOutput), "%d", &postLines)
			logrus.Infof("Post-migration: %d lines (was %d) on TOR", postLines, preLines)
			Expect(postLines).To(BeNumerically(">", preLines),
				"TCP stream stopped on TOR after migration")

			ginkgo.By("Checking sequence continuity from TOR")
			streamAll := runOnTOR(tor, "cat /tmp/tcp_stream")
			lines := strings.Split(strings.TrimSpace(streamAll), "\n")
			logrus.Infof("eBGP TCP stream: %d lines, first: %s, last: %s",
				len(lines), lines[0], lines[len(lines)-1])

			var lastSeq, seqGaps int
			for _, line := range lines {
				var seq int
				if _, scanErr := fmt.Sscanf(line, "seq=%d", &seq); scanErr == nil {
					if lastSeq > 0 && seq != lastSeq+1 {
						seqGaps++
						logrus.Infof("eBGP sequence gap: %d -> %d", lastSeq, seq)
					}
					lastSeq = seq
				}
			}
			logrus.Infof("eBGP sequence: %d gaps, %d data points", seqGaps, lastSeq)
			Expect(seqGaps).To(BeNumerically("<=", 5),
				"too many gaps in eBGP TCP stream — connection likely reset during migration")

			// Cleanup: kill nc on TOR.
			runOnTOR(tor, "pkill -f 'nc.*9999' || true")
		})
	},
)

// --- Helper functions ---

func newTestVM(name, namespace string) *kubevirtv1.VirtualMachine {
	running := true
	return &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace,
			Labels: map[string]string{"vm": name},
		},
		Spec: kubevirtv1.VirtualMachineSpec{
			Running: &running,
			Template: &kubevirtv1.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{"kubevirt.io/allow-pod-bridge-network-live-migration": "true"},
					Labels:      map[string]string{"vm": name},
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
						{Name: "containerdisk", VolumeSource: kubevirtv1.VolumeSource{ContainerDisk: &kubevirtv1.ContainerDiskSource{Image: vmImage}}},
						{Name: "cloudinitdisk", VolumeSource: kubevirtv1.VolumeSource{CloudInitNoCloud: &kubevirtv1.CloudInitNoCloudSource{
							UserData: "#cloud-config\npassword: testpass\nchpasswd: { expire: False }\nssh_pwauth: True\n",
						}}},
					},
				},
			},
		},
	}
}

// newTestVMWithTCPServer creates a VM that runs a TCP server on port 9999 via cloud-init.
// The server sends "seq=N" every second to each connected client.
func newTestVMWithTCPServer(name, namespace string) *kubevirtv1.VirtualMachine {
	vm := newTestVM(name, namespace)
	// Override cloud-init to start a TCP data server.
	for i := range vm.Spec.Template.Spec.Volumes {
		if vm.Spec.Template.Spec.Volumes[i].Name == "cloudinitdisk" {
			vm.Spec.Template.Spec.Volumes[i].VolumeSource.CloudInitNoCloud.UserData = `#cloud-config
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
		}
	}
	return vm
}

// createAndCleanupVM creates a VM and registers cleanup.
func createAndCleanupVM(ctx context.Context, kvClient kubevirtcorev1.KubevirtV1Interface, f *framework.Framework, ns, vmName string) {
	ginkgo.By(fmt.Sprintf("Creating VirtualMachine %s", vmName))
	vm := newTestVM(vmName, ns)
	_, err := kvClient.VirtualMachines(ns).Create(ctx, vm, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	ginkgo.DeferCleanup(func() {
		logrus.Infof("Cleaning up VM %s/%s", ns, vmName)
		_ = kvClient.VirtualMachines(ns).Delete(context.Background(), vmName, metav1.DeleteOptions{})
	})
}

// setupPingPod creates a ping pod and registers cleanup.
func setupPingPod(ctx context.Context, f *framework.Framework, ns string) *corev1.Pod {
	ginkgo.By("Creating a ping pod for connectivity checks")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ping-test", Namespace: ns},
		Spec: corev1.PodSpec{
			Containers:    []corev1.Container{{Name: "ping", Image: "busybox:1.36", Command: []string{"sleep", "3600"}}},
			RestartPolicy: corev1.RestartPolicyNever,
			NodeSelector:  map[string]string{"kubernetes.io/os": "linux"},
		},
	}
	created, err := f.ClientSet.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	ginkgo.DeferCleanup(func() {
		_ = f.ClientSet.CoreV1().Pods(ns).Delete(context.Background(), created.Name, metav1.DeleteOptions{})
	})
	waitForPodRunning(ctx, f, ns, created.Name)
	return created
}

// migrateAndCleanup creates a VMIM and registers cleanup.
func migrateAndCleanup(ctx context.Context, kvClient kubevirtcorev1.KubevirtV1Interface, ns, vmiName, vmimName string) *kubevirtv1.VirtualMachineInstanceMigration {
	ginkgo.By(fmt.Sprintf("Creating migration %s", vmimName))
	vmim := &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{Name: vmimName, Namespace: ns},
		Spec:       kubevirtv1.VirtualMachineInstanceMigrationSpec{VMIName: vmiName},
	}
	created, err := kvClient.VirtualMachineInstanceMigrations(ns).Create(ctx, vmim, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	ginkgo.DeferCleanup(func() {
		_ = kvClient.VirtualMachineInstanceMigrations(ns).Delete(context.Background(), vmimName, metav1.DeleteOptions{})
	})
	return created
}

func waitForVMIRunningWithIP(ctx context.Context, kvClient kubevirtcorev1.KubevirtV1Interface, ns, vmName string) (ip, node string) {
	ginkgo.By(fmt.Sprintf("Waiting for VMI %s to be Running with IP", vmName))
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

func waitForMigrationSuccess(ctx context.Context, kvClient kubevirtcorev1.KubevirtV1Interface, ns, vmimName string) {
	ginkgo.By(fmt.Sprintf("Waiting for migration %s to succeed", vmimName))
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

func stopVM(ctx context.Context, kvClient kubevirtcorev1.KubevirtV1Interface, ns, vmName string) {
	falseVal := false
	vm, err := kvClient.VirtualMachines(ns).Get(ctx, vmName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	vm.Spec.Running = &falseVal
	_, err = kvClient.VirtualMachines(ns).Update(ctx, vm, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func startVM(ctx context.Context, kvClient kubevirtcorev1.KubevirtV1Interface, ns, vmName string) {
	trueVal := true
	vm, err := kvClient.VirtualMachines(ns).Get(ctx, vmName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	vm.Spec.Running = &trueVal
	_, err = kvClient.VirtualMachines(ns).Update(ctx, vm, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

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
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no virt-launcher pod found for VMI %s", vmiName)
	}
	return &pods.Items[0], nil
}

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

func waitForPodRunning(ctx context.Context, f *framework.Framework, namespace, name string) {
	Eventually(func() corev1.PodPhase {
		pod, err := f.ClientSet.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return ""
		}
		return pod.Status.Phase
	}, 2*time.Minute, 5*time.Second).Should(Equal(corev1.PodRunning), "pod %s not Running", name)
}

func getRouteOnNode(f *framework.Framework, nodeName, ip string) string {
	calicoNodePod := utils.GetCalicoNodePodOnNode(f.ClientSet, nodeName)
	if calicoNodePod == nil {
		return ""
	}
	output, err := utils.ExecInCalicoNode(calicoNodePod, fmt.Sprintf("ip route show %s", ip))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

func newLibcalicoClient(f *framework.Framework) clientv3.Interface {
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = apiconfig.Kubernetes
	cfg.Spec.Kubeconfig = framework.TestContext.KubeConfig
	c, err := clientv3.New(*cfg)
	Expect(err).NotTo(HaveOccurred())
	return c
}

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
func waitForTCPServer(ns, podName, vmIP string) {
	ginkgo.By(fmt.Sprintf("Waiting for TCP server on %s:9999", vmIP))
	Eventually(func() error {
		output, _ := kubectl.NewKubectlCommand(ns, "exec", podName, "--",
			"sh", "-c", fmt.Sprintf("timeout 2 nc %s 9999", vmIP)).Exec()
		if strings.Contains(output, "seq=") {
			return nil
		}
		return fmt.Errorf("TCP server not ready")
	}, 1*time.Minute, 5*time.Second).Should(Succeed(), "TCP server not ready on VM")
	logrus.Infof("TCP server ready on %s:9999", vmIP)
}

// runOnTOR executes a command on the TOR node via SSH and returns stdout.
func runOnTOR(tor *externalnode.Client, cmd string) string {
	output, err := tor.Exec("sh", "-c", cmd)
	if err != nil {
		logrus.Warnf("TOR command failed: %s: %v", cmd, err)
	}
	return output
}

func ptrInt64(v int64) *int64 { return &v }
