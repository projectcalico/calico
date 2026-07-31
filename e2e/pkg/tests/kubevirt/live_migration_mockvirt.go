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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/bgp"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// KubeVirt live migration route convergence tests for MockVirt clusters.
// iBGP test: validates kernel route metric elevation (512) and reversion (1024)
// on worker nodes during live migration — no external BIRD peer required.
// eBGP test: validates BGP route priority (krt_metric, community tagging,
// local_pref) using a local BIRD container on the Docker network.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("KubeVirt"),
	describe.RequiresMockVirt(),
	describe.WithCategory(describe.Networking),
	"KubeVirt live migration (MockVirt)",
	func() {
		f := utils.NewDefaultFramework("calico-kubevirt-mockvirt")

		var cli ctrlclient.Client

		BeforeEach(func() {
			if !isMockVirtDeployed(f) {
				Fail("KubeVirt-MockVirt tests selected but cluster does not have MockVirt deployed")
			}
			// Double migration needs 3 workers: source, first target, second target.
			utils.RequireNodeCount(f, 3)

			var err error
			cli, err = e2eclient.NewAPIClient(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to build controller-runtime client")
		})

		It("should converge iBGP routes after live migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), doubleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name

			// Create a VM with default cloud-init (no TCP server needed — this
			// test only validates kernel route state, not TCP continuity).
			vmName := "e2e-mockvirt-ibgp"
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			By("Creating VM")
			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })

			vmIP, node1 := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s on %s with IP %s", vmName, node1, vmIP)

			// Pre-migration: the source node should have a normal-priority /32 route.
			By("Verifying pre-migration kernel route metric on source node")
			Eventually(func(g Gomega) {
				m, err := queryWorkerMetric(f, node1, vmIP)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(m).To(Equal(normalRouteMetric),
					"source node should have normal kernel route metric (1024) before migration")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			// === First migration ===
			By("Starting first migration")
			vmim1 := newVMIMigration(vmName+"-migration1", ns, vmName)
			Expect(cli.Create(ctx, vmim1)).To(Succeed())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim1) })
			expectMigrationSuccess(ctx, cli, vmim1)
			vmi := expectMigrationStatePopulated(ctx, cli, ns, vmName)
			node2 := vmi.Status.MigrationState.TargetNode
			Expect(node2).NotTo(Equal(node1), "VM should have migrated to a different node")
			logrus.Infof("First migration: %s -> %s", node1, node2)

			// Target node should have elevated metric (512) during convergence window.
			By("Verifying elevated kernel route metric on target node after first migration")
			Eventually(func(g Gomega) {
				m, err := queryWorkerMetric(f, node2, vmIP)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(m).To(Equal(elevatedRouteMetric),
					"target node should have elevated kernel route metric (512) after migration")
			}, elevatedMetricTimeout, 1*time.Second).Should(Succeed())

			// Wait for metric to revert to normal (1024) after convergence window (~30s).
			By("Waiting for kernel route metric to revert to normal on target node")
			Eventually(func(g Gomega) {
				m, err := queryWorkerMetric(f, node2, vmIP)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(m).To(Equal(normalRouteMetric),
					"target node kernel route metric should revert to 1024 after convergence")
			}, metricRevertTimeout, 2*time.Second).Should(Succeed())

			// === Second migration ===
			// Pin to a third worker so we exercise a brand-new /32 route.
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
			Expect(node3).NotTo(Equal(node2), "VM should have migrated to a different node")
			logrus.Infof("Second migration: %s -> %s", node2, node3)

			// Target node should have elevated metric (512) during convergence window.
			By("Verifying elevated kernel route metric on target node after second migration")
			Eventually(func(g Gomega) {
				m, err := queryWorkerMetric(f, node3, vmIP)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(m).To(Equal(elevatedRouteMetric),
					"target node should have elevated kernel route metric (512) after second migration")
			}, elevatedMetricTimeout, 1*time.Second).Should(Succeed())

			// Wait for metric to revert to normal (1024) after convergence window.
			By("Waiting for kernel route metric to revert to normal on target node after second migration")
			Eventually(func(g Gomega) {
				m, err := queryWorkerMetric(f, node3, vmIP)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(m).To(Equal(normalRouteMetric),
					"target node kernel route metric should revert to 1024 after second migration convergence")
			}, metricRevertTimeout, 2*time.Second).Should(Succeed())
		})

		It("should not have /32 host route on target node after a migration timeout", func() {
			ctx, cancel := context.WithTimeout(context.Background(), singleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name

			vmName := "e2e-mockvirt-timeout"
			// The migration-timeout label is set on the VM spec template,
			// which propagates it to the VMI and virt-launcher pod automatically.
			// FakeDomainManager reads vmi.Labels["migration-timeout"] to decide
			// whether to simulate a timeout failure.
			vm := &kubeVirtVM{
				name:      vmName,
				namespace: ns,
				labels:    map[string]string{"migration-timeout": "true"},
			}

			By("Creating VM with migration-timeout label")
			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })

			vmIP, sourceNode := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s on %s with IP %s", vmName, sourceNode, vmIP)

			// Record the source pod before migration.
			sourcePod, err := vm.FindVirtLauncherPod(ctx, f)
			Expect(err).NotTo(HaveOccurred())
			logrus.Infof("Source pod: %s on %s", sourcePod.Name, sourceNode)

			lcgc := newLibcalicoClient(f)

			// Trigger a migration that will time out.
			By("Starting migration (VM has migration-timeout label)")
			vmim := newVMIMigration(vmName+"-timeout", ns, vmName)
			Expect(cli.Create(ctx, vmim)).To(Succeed())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim) })

			// Wait for migration to fail with timeout.
			expectMigrationFailed(ctx, cli, vmim)

			// Re-fetch the VMI to get the MigrationState populated after failure.
			vmi := &kubevirtv1.VirtualMachineInstance{}
			Expect(cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: vmName}, vmi)).To(Succeed())
			Expect(vmi.Status.MigrationState).NotTo(BeNil(), "MigrationState should be populated")
			targetNode := vmi.Status.MigrationState.TargetNode
			targetPodName := vmi.Status.MigrationState.TargetPod
			Expect(targetNode).NotTo(BeEmpty(), "target node should be set")
			Expect(targetPodName).NotTo(BeEmpty(), "target pod should be set")
			logrus.Infof("Migration failed: source=%s, target=%s (pod %s)", sourceNode, targetNode, targetPodName)

			// After migration failure, the target node must NOT have a /32
			// kernel route for the VM IP. During successful migration, Felix
			// programs an elevated /32 (metric 512) on the target; on failure
			// this must not appear or must be cleaned up.
			By("Verifying target node has no /32 kernel route after migration timeout")
			Consistently(func() error {
				_, err := queryWorkerMetric(f, targetNode, vmIP)
				if err == nil {
					return fmt.Errorf("target node should not have /32 kernel route after failed migration")
				}
				return nil
			}, 15*time.Second, 2*time.Second).Should(Succeed())

			// Delete the orphaned target pod and verify IPAM ownership is
			// unchanged: the source pod must remain the sole active owner
			// with no alternate.
			By(fmt.Sprintf("Deleting orphaned target pod %s", targetPodName))
			err = f.ClientSet.CoreV1().Pods(ns).Delete(ctx, targetPodName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to delete target pod")

			By("Waiting for target pod to be fully deleted")
			Eventually(func() bool {
				_, err := f.ClientSet.CoreV1().Pods(ns).Get(ctx, targetPodName, metav1.GetOptions{})
				return err != nil
			}, 1*time.Minute, 2*time.Second).Should(BeTrue(),
				"target pod should be fully deleted")

			By("Verifying IPAM attributes: Active=source, Alternate=empty")
			Eventually(func() error {
				active, alternate, err := getIPAMOwnerAttributes(ctx, lcgc, vmIP)
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
					return fmt.Errorf("AlternateOwnerAttrs should be empty after failed migration cleanup, got %v", alternate)
				}
				return nil
			}, 1*time.Minute, 2*time.Second).Should(Succeed())
			logrus.Infof("IPAM ownership confirmed: Active pod=%s node=%s, Alternate=empty",
				sourcePod.Name, sourceNode)
		})

		It("should enforce NetworkPolicy after live migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), singleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name

			vmName := "e2e-mockvirt-netpol"
			vm := &kubeVirtVM{
				name:      vmName,
				namespace: ns,
				labels:    map[string]string{"app": "vm"},
			}

			By("Creating VM with app=vm label")
			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })
			vmIP, node1 := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s on %s with IP %s", vmName, node1, vmIP)

			tester := conncheck.NewConnectionTester(f)
			DeferCleanup(tester.Stop)
			allowed := conncheck.NewClient("client-allowed", f.Namespace,
				conncheck.WithClientLabels(map[string]string{"role": "allowed"}))
			denied := conncheck.NewClient("client-denied", f.Namespace,
				conncheck.WithClientLabels(map[string]string{"role": "denied"}))
			tester.AddClient(allowed)
			tester.AddClient(denied)
			tester.Deploy()
			vmTarget := conncheck.NewTarget(vmIP, conncheck.TypePodIP, conncheck.ICMP)

			By("Verifying both clients can ping VM before policy")
			tester.WithTimeout(2 * time.Minute)
			tester.ExpectSuccess(allowed, vmTarget)
			tester.ExpectSuccess(denied, vmTarget)
			tester.Execute()
			tester.ResetExpectations()

			By("Creating NetworkPolicy to allow only role=allowed (all protocols including ICMP)")
			netpol := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-allowed-only", Namespace: ns},
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
					}},
				},
			}
			_, err := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(ctx, netpol, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				_ = f.ClientSet.NetworkingV1().NetworkPolicies(ns).Delete(context.Background(), netpol.Name, metav1.DeleteOptions{})
			})

			By("Verifying policy enforced: allowed can ping, denied cannot")
			tester.ExpectSuccess(allowed, vmTarget)
			tester.ExpectFailure(denied, vmTarget)
			tester.Execute()
			tester.ResetExpectations()

			By("Triggering live migration")
			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			Expect(cli.Create(ctx, vmim)).To(Succeed())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim) })
			expectMigrationSuccess(ctx, cli, vmim)

			vmi := expectMigrationStatePopulated(ctx, cli, ns, vmName)
			node2 := vmi.Status.MigrationState.TargetNode
			Expect(node2).NotTo(Equal(node1), "VM should have migrated to a different node")
			logrus.Infof("VM migrated: %s -> %s", node1, node2)

			By("Verifying policy enforcement is consistent for at least 10 seconds")
			Consistently(func(g Gomega) {
				_, err := tester.Connect(allowed, vmTarget)
				g.Expect(err).NotTo(HaveOccurred(),
					"allowed client should still reach VM")
				_, err = tester.Connect(denied, vmTarget)
				g.Expect(err).To(HaveOccurred(),
					"denied client should still be blocked by NetworkPolicy")
			}, 10*time.Second, 2*time.Second).Should(Succeed())
		})

		It("should converge eBGP routes after live migration", Serial, func() {
			ctx, cancel := context.WithTimeout(context.Background(), eBGPDoubleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name

			// Discover the pre-existing BIRD container (created by infra setup).
			bird := bgp.NewContainerBIRDPeer()

			// Set up eBGP peering between the BIRD container and the cluster.
			setupMockVirtEBGPPeering(f, bird)

			// Create a VM with default cloud-init (no TCP server needed — this
			// test only validates route convergence, not TCP continuity).
			vmName := "e2e-mockvirt-ebgp"
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			By("Creating VM")
			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })

			vmIP, node1 := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s on %s with IP %s", vmName, node1, vmIP)

			// Before migration only the /26 block route exists — the /32
			// only appears when Felix programs an elevated krt_metric during
			// migration. Verify the /26 to confirm eBGP routing is working.
			By("Verifying BIRD container has /26 block route for VM subnet")
			Eventually(func() bool {
				snap := bird.QuerySnapshot(vmIP)
				return snap.Block26.Present
			}, 2*time.Minute, 5*time.Second).Should(BeTrue(),
				"BIRD container should have /26 block route via eBGP")

			// === First migration ===
			By("Starting first migration")
			vmim1 := newVMIMigration(vmName+"-migration1", ns, vmName)
			Expect(cli.Create(ctx, vmim1)).To(Succeed())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim1) })
			expectMigrationSuccess(ctx, cli, vmim1)
			vmi := expectMigrationStatePopulated(ctx, cli, ns, vmName)
			node2 := vmi.Status.MigrationState.TargetNode
			Expect(node2).NotTo(Equal(node1), "VM should have migrated to a different node")
			logrus.Infof("First migration: %s -> %s", node1, node2)

			// Verify elevated route priority on the target worker and BIRD container.
			By("Verifying elevated route priority after first migration")
			Eventually(func(g Gomega) {
				m, err := queryWorkerMetric(f, node2, vmIP)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(m).To(Equal(elevatedRouteMetric),
					"worker kernel metric should be elevated (512) after migration")
				st := bird.QueryRoute(vmIP)
				g.Expect(st.Has32).To(BeTrue(), "BIRD should have /32 after migration")
				g.Expect(st.Routes).To(HaveLen(1), "should be single /32 route (no ECMP)")
				g.Expect(st.Routes[0].LocalPref).To(Equal(elevatedLocalPref),
					"BIRD /32 should have elevated local_pref")
				g.Expect(st.Routes[0].Community).To(Equal(migrationCommunityTag),
					"BIRD /32 should have community tag")
			}, elevatedMetricTimeout, 1*time.Second).Should(Succeed())

			// Wait for the elevated /32 route to revert to normal local_pref.
			By("Waiting for BIRD /32 local_pref to revert to normal after convergence")
			Eventually(func() int {
				snap := bird.QuerySnapshot(vmIP)
				if len(snap.Host32.Routes) > 0 {
					return snap.Host32.Routes[0].LocalPref
				}
				return -1
			}, metricRevertTimeout, 2*time.Second).Should(Equal(normalLocalPref),
				"BIRD /32 local_pref should revert to 100 after convergence")

			// === Second migration ===
			// Pin to a third worker so we exercise a brand-new /32 route.
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
			Expect(node3).NotTo(Equal(node2), "VM should have migrated to a different node")
			logrus.Infof("Second migration: %s -> %s", node2, node3)

			// After second migration: expect two /32 routes with different
			// local_pref (elevated for new node, normal for old node).
			By("Verifying BIRD route state after second migration")
			Eventually(func(g Gomega) {
				st := bird.QueryRoute(vmIP)
				g.Expect(st.Has32).To(BeTrue(), "BIRD should have /32 after second migration")
				var b, nb *bgp.BIRDRoute
				for i := range st.Routes {
					if st.Routes[i].Best {
						b = &st.Routes[i]
					} else {
						nb = &st.Routes[i]
					}
				}
				g.Expect(b).NotTo(BeNil(), "BIRD should have a best /32 route")
				g.Expect(b.LocalPref).To(Equal(elevatedLocalPref),
					"best /32 route should have elevated local_pref")
				g.Expect(b.Community).To(Equal(migrationCommunityTag),
					"best /32 route should have community tag")
				// Two /32 routes with different local_pref (no ECMP).
				g.Expect(nb).NotTo(BeNil(),
					"BIRD should have two /32 routes after second migration")
				g.Expect(nb.LocalPref).NotTo(Equal(b.LocalPref),
					"two /32 routes must have different local_pref to avoid ECMP")
			}, elevatedMetricTimeout, 1*time.Second).Should(Succeed())

			// Wait for the second migration's /32 route to revert.
			By("Waiting for BIRD /32 local_pref to revert after second migration")
			Eventually(func() int {
				snap := bird.QuerySnapshot(vmIP)
				if len(snap.Host32.Routes) > 0 {
					return snap.Host32.Routes[0].LocalPref
				}
				return -1
			}, metricRevertTimeout, 2*time.Second).Should(Equal(normalLocalPref),
				"BIRD /32 local_pref should revert to 100 after second migration convergence")
		})
	},
)
