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
	"k8s.io/utils/ptr"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
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

		// Test 1: live migration via VMIM must keep the same IP on the target pod
		// (Calico's VM-handle IPAM); the VM must remain reachable over ICMP from a
		// ping-client pod before and after.
		It("should preserve VM IP address across live migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), ipPersistenceTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-migration-test"
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			By("Creating ping client pod via conncheck")
			tester := conncheck.NewConnectionTester(f)
			DeferCleanup(tester.Stop)
			pingClient := conncheck.NewClient("ping-test", f.Namespace)
			tester.AddClient(pingClient)
			tester.Deploy()

			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })

			originalIP, sourceNode := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s running on node %s with IP %s", vmName, sourceNode, originalIP)

			sourceLauncher, err := vm.FindVirtLauncherPod(ctx, f)
			Expect(err).NotTo(HaveOccurred())

			// KubeVirt reports VMI Running once virt-launcher starts, but the
			// guest still needs to boot (cloud-init + network) before it
			// responds to ICMP. On a fresh cluster the containerDisk pull
			// adds another ~30s. Wait here as a setup step so the assertion
			// below runs against a warm VM at the default budget.
			//
			// Cadence note: tester.Connect uses ping -c 5 with conncheck's
			// 30s exec timeout. Effective poll cadence is ~5s on success
			// (ping returns fast) and ~30s on failure (ping waits for all
			// 5 replies). Outer 90s budget = ~3 attempts in the worst case.
			By("Waiting for VM guest to become reachable")
			Eventually(func() error {
				_, err := tester.Connect(pingClient, conncheck.NewPodPingTarget(sourceLauncher))
				return err
			}, 90*time.Second, 5*time.Second).Should(Succeed(),
				"VM guest did not respond to ICMP within cold-start budget")

			// KubeVirt with pod-bridge networking gives the VM the same IP as
			// its virt-launcher pod, so pinging the launcher pod is pinging
			// the VM. Using conncheck.NewPodPingTarget keeps the connection
			// check on the same path as the rest of the e2e suite.
			By("Verifying connectivity to VM before migration")
			tester.ExpectSuccess(pingClient, conncheck.NewPodPingTarget(sourceLauncher))
			tester.Execute()

			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			err = cli.Create(ctx, vmim)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim) })
			expectMigrationSuccess(ctx, cli, vmim)

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

			// Re-fetch the virt-launcher pod (it's a new pod on the new node
			// with the same IP per KubeVirt's IP-persistence guarantee).
			By("Verifying connectivity after migration")
			postLauncher, err := vm.FindVirtLauncherPod(ctx, f)
			Expect(err).NotTo(HaveOccurred())
			tester.ResetExpectations()
			tester.ExpectSuccess(pingClient, conncheck.NewPodPingTarget(postLauncher))
			tester.Execute()
		})

		// Test 2: force-deleting a virt-launcher pod recreates it via the VM controller;
		// the VM-handle IPAM (keyed on VMI namespace+name, not container ID) must reassign
		// the same IP to the new pod.
		It("should preserve VM IP across pod recreation", func() {
			ctx, cancel := context.WithTimeout(context.Background(), podRecreationTimeout)
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
				GracePeriodSeconds: ptr.To(int64(0)),
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

		// Test 3: stop (RunStrategyHalted) and restart (RunStrategyAlways) gives a new
		// VMI UID with the same name, so the VM-handle ID matches and the same IP is
		// reallocated. Relies on kube-controllers' 5m GC grace period.
		It("should preserve VM IP across VMI recreation (reboot)", func() {
			ctx, cancel := context.WithTimeout(context.Background(), vmiRecreationTimeout)
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

		// Test 4: deleting the VM (and its pod) must release the VM IPAM handle so the
		// IP returns to the pool. e2e counterpart of the CNI FV in kubevirt_ipam_test.go.
		It("should release IPAM handle when VM is deleted", func() {
			ctx, cancel := context.WithTimeout(context.Background(), ipPersistenceTimeout)
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

		// Test 5: active IPAM owner promotes from source to target after migration.
		// Asserts Active=target,Alternate=empty (Felix EnsureActiveVMOwnerAttrs) by
		// matching the real target pod/node, not just "differs from source".
		It("should promote target pod to active IPAM owner after migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), singleMigrationTimeout)
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
			DeferCleanup(func() { deleteVMIMigration(cli, vmim) })
			expectMigrationSuccess(ctx, cli, vmim)

			// Read the target pod and node directly from the VMI's MigrationState,
			// which KubeVirt populates with the source/target identifiers as part of
			// the migration. expectMigrationStatePopulated polls until virt-handler
			// finishes writing the state (it can lag the VMIM Succeeded phase).
			vmi := expectMigrationStatePopulated(ctx, cli, ns, vmName)
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

		// Test 6: assigning a static IP via the cni.projectcalico.org/ipAddrs annotation
		// on the VM spec template. The annotation propagates through VMI to the
		// virt-launcher pod, where the Calico CNI plugin honours it. After a live
		// migration the same static IP must survive on the new pod.
		It("should assign static IP via annotation and preserve it across migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), singleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-static-ip"

			// Pick an unallocated static IP from the cluster's IPPool.
			lcgc := newLibcalicoClient(f)
			staticIP := pickUnallocatedIP(ctx, lcgc)
			logrus.Infof("Using static IP %s for VM %s", staticIP, vmName)

			vm := &kubeVirtVM{
				name:      vmName,
				namespace: ns,
				annotations: map[string]string{
					"cni.projectcalico.org/ipAddrs": fmt.Sprintf("[%q]", staticIP),
				},
			}

			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })

			// 1. Verify the VM gets the exact static IP.
			ip, sourceNode := vm.WaitForRunningWithIP(ctx, cli)
			Expect(ip).To(Equal(staticIP),
				"VM should receive the static IP from the annotation")

			// 2. Verify the IPAM handle exists for this IP.
			handleID := vmipam.CreateVMHandleID("k8s-pod-network", ns, vmName)
			ips, err := lcgc.IPAM().IPsByHandle(ctx, handleID)
			Expect(err).NotTo(HaveOccurred())
			Expect(ips).To(HaveLen(1))
			Expect(ips[0].String()).To(Equal(staticIP))

			// 3. Migrate and verify the static IP survives.
			vmim := newVMIMigration(vmName+"-mig", ns, vmName)
			err = cli.Create(ctx, vmim)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim) })
			expectMigrationSuccess(ctx, cli, vmim)

			// 4. Verify IP preserved and VM moved to a different node.
			var postIP, postNode string
			Eventually(func() error {
				vmi := &kubevirtv1.VirtualMachineInstance{}
				if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: vmName}, vmi); err != nil {
					return err
				}
				if len(vmi.Status.Interfaces) == 0 || vmi.Status.Interfaces[0].IP == "" {
					return fmt.Errorf("no IP yet")
				}
				if vmi.Status.NodeName == sourceNode {
					return fmt.Errorf("VMI still on source node")
				}
				postIP = vmi.Status.Interfaces[0].IP
				postNode = vmi.Status.NodeName
				return nil
			}, 30*time.Second, 2*time.Second).Should(Succeed())

			Expect(postIP).To(Equal(staticIP),
				"Static IP should survive live migration")
			Expect(postNode).NotTo(Equal(sourceNode))

			// 5. Verify IPAM handle still holds the same IP after migration.
			postIPs, err := lcgc.IPAM().IPsByHandle(ctx, handleID)
			Expect(err).NotTo(HaveOccurred())
			Expect(postIPs).To(HaveLen(1))
			Expect(postIPs[0].String()).To(Equal(staticIP))
		})
	},
)
