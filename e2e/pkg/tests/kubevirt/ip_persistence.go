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
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
)

// KubeVirt IP persistence e2e tests validate Calico's IPAM IP preservation for KubeVirt VMs.
// The tests cover:
//   - IP preservation across migrations, pod evictions, and VM reboots (Tests 1-4)
//
// Prerequisites:
//   - KubeVirt installed with live migration support
//   - IPAMConfig.kubeVirtVMAddressPersistence set to "Enabled"
//   - At least 2 schedulable worker nodes
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("KubeVirt"),
	describe.WithCategory(describe.Networking),
	"KubeVirt IP persistence",
	func() {
		f := utils.NewDefaultFramework("calico-kubevirt-ip")

		var cli ctrlclient.Client

		BeforeEach(func() {
			// Live migration needs at least 2 nodes to migrate between.
			utils.RequireNodeCount(f, 2)

			var err error
			cli, err = e2eclient.NewAPIClient(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to build controller-runtime client")
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
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			pingPod := setupPingPod(f)
			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })

			originalIP, sourceNode := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s running on node %s with IP %s", vmName, sourceNode, originalIP)

			By("Verifying connectivity to VM before migration")
			expectPingSuccess(ns, pingPod.Name, originalIP)

			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			err := cli.Create(ctx, vmim)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim) })
			waitForMigrationSuccess(ctx, cli, vmim)

			By("Verifying VMI IP is preserved after migration")
			// Use Eventually to avoid reading stale VMI status after migration.
			var postMigrationIP, postMigrationNode string
			Eventually(func() error {
				vmi := &kubevirtv1.VirtualMachineInstance{}
				if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: vmName}, vmi); err != nil {
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
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })
			originalIP, _ := vm.WaitForRunningWithIP(ctx, cli)

			sourcePod, err := vm.FindVirtLauncherPod(ctx, f)
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
				pod, err := vm.FindVirtLauncherPod(ctx, f)
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
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })
			originalIP, _ := vm.WaitForRunningWithIP(ctx, cli)

			vmi := &kubevirtv1.VirtualMachineInstance{}
			err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: vmName}, vmi)
			Expect(err).NotTo(HaveOccurred())
			originalVMIUID := vmi.UID
			logrus.Infof("Original VMI UID: %s, IP: %s", originalVMIUID, originalIP)

			By("Stopping the VM")
			vm.Stop(ctx, cli)

			// Return an error with diagnostic context so a timeout failure
			// reports what was actually being checked, not just "false".
			By("Waiting for VMI to be deleted")
			Eventually(func() error {
				err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: vmName}, &kubevirtv1.VirtualMachineInstance{})
				if err == nil {
					return fmt.Errorf("VMI %s/%s still exists", ns, vmName)
				}
				if !kerrors.IsNotFound(err) {
					return fmt.Errorf("unexpected error reading VMI %s/%s: %w", ns, vmName, err)
				}
				return nil
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("Starting the VM again")
			vm.Start(ctx, cli)

			By("Waiting for new VMI with the same IP")
			var newIP string
			Eventually(func() error {
				vmi := &kubevirtv1.VirtualMachineInstance{}
				if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: vmName}, vmi); err != nil {
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

		// Test 4: IPAM handle released when VM is deleted.
		// Validates the cleanup path: when a VM is deleted (has deletion timestamp) and
		// its pod is removed, the CNI IPAM DEL must release the VM-based handle so the
		// IP returns to the pool. Without this, deleted VMs would leak IP addresses.
		// This is the e2e counterpart of the CNI FV test in kubevirt_ipam_test.go.
		It("should release IPAM handle when VM is deleted", func() {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-handle-release"
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })
			originalIP, _ := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s running with IP %s", vmName, originalIP)

			By("Verifying IPAM handle exists before deletion")
			lcgc := newLibcalicoClient(f)
			handleID := vmipam.CreateVMHandleID("k8s-pod-network", ns, vmName)
			ips, err := lcgc.IPAM().IPsByHandle(ctx, handleID)
			Expect(err).NotTo(HaveOccurred())
			Expect(ips).NotTo(BeEmpty(), "Handle %s should have IPs allocated", handleID)
			logrus.Infof("Handle %s has %d IPs before deletion", handleID, len(ips))

			By("Deleting the VM")
			vm.Delete(cli)

			By("Waiting for virt-launcher pod to be gone")
			Eventually(func() error {
				pods, listErr := f.ClientSet.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
					LabelSelector: fmt.Sprintf("kubevirt.io/vm=%s", vmName),
				})
				if listErr != nil {
					return fmt.Errorf("list virt-launcher pods: %w", listErr)
				}
				if len(pods.Items) > 0 {
					return fmt.Errorf("%d virt-launcher pod(s) still present for VM %s", len(pods.Items), vmName)
				}
				return nil
			}, 2*time.Minute, 5*time.Second).Should(Succeed(), "virt-launcher pod should be deleted")

			By("Verifying IPAM handle is released")
			Eventually(func() error {
				ips, err := lcgc.IPAM().IPsByHandle(ctx, handleID)
				if err != nil {
					// Handle not found means it was released — success.
					return nil
				}
				if len(ips) > 0 {
					return fmt.Errorf("handle %s still has %d IP(s) allocated", handleID, len(ips))
				}
				return nil
			}, 1*time.Minute, 5*time.Second).Should(Succeed(),
				"Handle %s should be released after VM deletion", handleID)
			logrus.Infof("Handle %s released after VM deletion", handleID)
		})
	},
)
