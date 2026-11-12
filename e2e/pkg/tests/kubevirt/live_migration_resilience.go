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

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
	kubevirtv1 "kubevirt.io/api/core/v1"
	migrationsv1alpha1 "kubevirt.io/api/migrations/v1alpha1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
)

const (
	// abortMigrationTimeout covers VM boot, the TCP server coming up, the target
	// pod starting, and the post-abort cleanup checks.
	abortMigrationTimeout = 20 * time.Minute
	// migrationPolicyLabel selects the throttled MigrationPolicy onto one VMI.
	migrationPolicyLabel = "e2e-migration-policy"
)

// Live-migration resilience: an aborted migration must leave the VM where it
// was, with one owner of its address, and nothing behind on the target. The
// success-path handover is checked in live_migration.go.
//
// SCOPE NOTES:
//   - Felix's route elevation and proxy-ARP decisions are unit tested in
//     felix/dataplane/linux/live_migration_test.go and proxy_neigh_mgr_test.go;
//     vmipam owner swaps in libcalico-go/lib/ipam/vmipam. This spec proves the
//     components agree on a real cluster: KubeVirt, CNI, Felix, BIRD and IPAM.
//   - A failed (timed-out) migration is covered on MockVirt by "should not
//     have /32 host route on target node after a migration timeout"; the abort
//     spec here is the real-KubeVirt, user-initiated counterpart.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("KubeVirt"),
	describe.RequiresRealKubeVirt(),
	describe.WithCategory(describe.Networking),
	"KubeVirt live migration resilience",
	func() {
		f := utils.NewDefaultFramework("calico-kubevirt-resilience")

		var cli ctrlclient.Client

		ginkgo.BeforeEach(func() {
			utils.RequireNodeCount(f, 2)
			if isMockVirtDeployed(f) {
				ginkgo.Fail("These tests need real KubeVirt: MockVirt doesn't tear down a source pod or copy guest memory")
			}
			var err error
			cli, err = e2eclient.New(f.ClientConfig())
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to build controller-runtime client")
		})

		// N4: deleting a running VMIM aborts the migration. The VM must stay on
		// the source with its address, ownership and connectivity intact, and the
		// half-built target must leave nothing behind for a later migration to
		// trip over. Uses an in-cluster client, not eBGP, so the eBGP suite's own
		// failures can't mask this one.
		ginkgo.It("should leave the VM intact on the source and the target clean after an aborted migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), abortMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-abort"
			selector := utils.GenerateRandomName("e2e-slow-migration")

			// Throttled so the abort reliably lands before the copy finishes, with
			// a completion timeout high enough that KubeVirt doesn't abort first.
			ginkgo.By("Creating a MigrationPolicy that throttles this VM's migration to 1Mi/s")
			policy := &migrationsv1alpha1.MigrationPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: selector},
				Spec: migrationsv1alpha1.MigrationPolicySpec{
					Selectors: &migrationsv1alpha1.Selectors{
						VirtualMachineInstanceSelector: migrationsv1alpha1.LabelSelector{migrationPolicyLabel: selector},
					},
					BandwidthPerMigration:   ptr.To(resource.MustParse("1Mi")),
					CompletionTimeoutPerGiB: ptr.To(int64(3600)),
					AllowAutoConverge:       ptr.To(false),
					AllowPostCopy:           ptr.To(false),
				},
			}
			gomega.Expect(cli.Create(ctx, policy)).To(gomega.Succeed(), "create MigrationPolicy")
			ginkgo.DeferCleanup(func(ctx context.Context) {
				gomega.Expect(ctrlclient.IgnoreNotFound(cli.Delete(ctx, policy))).To(gomega.Succeed(), "delete MigrationPolicy")
			})

			vm := &kubeVirtVM{
				name:      vmName,
				namespace: ns,
				cloudInit: tcpServerCloudInit,
				labels:    map[string]string{migrationPolicyLabel: selector},
			}
			vm.Create(ctx, cli)
			ginkgo.DeferCleanup(func() { vm.Delete(cli) })
			vmIP, sourceNode := vm.WaitForRunningWithIP(ctx, cli)
			sourcePod, err := vm.FindVirtLauncherPod(ctx, f)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "find source virt-launcher pod")
			logrus.Infof("VM %s on %s (pod %s) with IP %s", vmName, sourceNode, sourcePod.Name, vmIP)

			clientConn, clientTester := setupAntiAffinityPod(ctx, f, sourceNode)
			ginkgo.By("Waiting for the VM's TCP server to be reachable")
			vmTarget := conncheck.NewTCPConnectTarget(vmIP, 9999)
			clientTester.WithTimeout(2 * time.Minute)
			clientTester.ExpectSuccess(clientConn, vmTarget)
			clientTester.Execute()
			clientTester.ResetExpectations()

			ginkgo.By("Starting a long-lived TCP stream to the VM")
			stream := conncheck.StartStream(ctx, "tcp-stream",
				conncheck.NewPodSource(f, clientConn),
				conncheck.WithStreamCommand("nc", vmIP, "9999"))
			ginkgo.DeferCleanup(func() { _ = stream.Stop() })
			conncheck.WaitForCadence(ctx, stream, 5, 30*time.Second)

			ginkgo.By("Starting the migration")
			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			gomega.Expect(cli.Create(ctx, vmim)).To(gomega.Succeed(), "create VMIM")
			ginkgo.DeferCleanup(func() { deleteVMIMigration(cli, vmim) })

			ginkgo.By("Waiting for the target virt-launcher pod to be Running and the copy to start")
			var targetPod *corev1.Pod
			gomega.Eventually(func() error {
				got := &kubevirtv1.VirtualMachineInstanceMigration{}
				if err := cli.Get(ctx, ctrlclient.ObjectKeyFromObject(vmim), got); err != nil {
					return err
				}
				if got.Status.Phase == kubevirtv1.MigrationSucceeded || got.Status.Phase == kubevirtv1.MigrationFailed {
					return gomega.StopTrying(fmt.Sprintf("abort did not land: migration reached %s before its target pod was seen Running", got.Status.Phase))
				}
				pods, err := f.ClientSet.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
					LabelSelector: "kubevirt.io=virt-launcher,vm.kubevirt.io/name=" + vmName,
				})
				if err != nil {
					return err
				}
				for i := range pods.Items {
					p := &pods.Items[i]
					if p.Name != sourcePod.Name && p.Status.Phase == corev1.PodRunning {
						targetPod = p
					}
				}
				if targetPod == nil {
					return fmt.Errorf("no Running target pod yet (VMIM phase %s)", got.Status.Phase)
				}
				// Aborting before the copy starts would cancel scheduling instead,
				// which never sets an abort status: wait for the migration proper.
				if got.Status.Phase != kubevirtv1.MigrationRunning {
					return fmt.Errorf("target pod %s Running, VMIM phase %s", targetPod.Name, got.Status.Phase)
				}
				return nil
			}, 3*time.Minute, 1*time.Second).Should(gomega.Succeed())
			targetNode := targetPod.Spec.NodeName
			logrus.Infof("Target pod %s Running on %s", targetPod.Name, targetNode)

			ginkgo.By("Aborting the migration by deleting the VMIM")
			deleteVMIMigration(cli, vmim)

			ginkgo.By("Verifying the abort landed and the VM stayed on the source node")
			gomega.Eventually(func() error {
				vmi := &kubevirtv1.VirtualMachineInstance{}
				if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: vmName}, vmi); err != nil {
					return err
				}
				ms := vmi.Status.MigrationState
				if ms == nil {
					return fmt.Errorf("VMI has no MigrationState")
				}
				if ms.MigrationPolicyName == nil || *ms.MigrationPolicyName != selector {
					return gomega.StopTrying(fmt.Sprintf("migration did not use the throttling policy %s (got %v)", selector, ms.MigrationPolicyName))
				}
				if ms.Completed && !ms.Failed {
					return gomega.StopTrying(fmt.Sprintf("abort did not land: migration to %s completed", ms.TargetNode))
				}
				if ms.AbortStatus != kubevirtv1.MigrationAbortSucceeded {
					return fmt.Errorf("abort status is %q", ms.AbortStatus)
				}
				if vmi.Status.NodeName != sourceNode {
					return fmt.Errorf("VMI is on %s, want source node %s", vmi.Status.NodeName, sourceNode)
				}
				return nil
			}, 2*time.Minute, 2*time.Second).Should(gomega.Succeed())

			// KubeVirt may keep the aborted target pod as a terminated record, which
			// releases its network like a deleted one.
			ginkgo.By(fmt.Sprintf("Waiting for target pod %s to be deleted or terminated", targetPod.Name))
			gomega.Eventually(func() error {
				pod, err := f.ClientSet.CoreV1().Pods(ns).Get(ctx, targetPod.Name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
					return nil
				}
				return fmt.Errorf("target pod %s still %s", targetPod.Name, pod.Status.Phase)
			}, 2*time.Minute, 2*time.Second).Should(gomega.Succeed())

			lcgc := newLibcalicoClient(f)
			// No WorkloadEndpoint check: in KDD they're derived from pods, and the
			// target pod is gone or terminated.
			ginkgo.By(fmt.Sprintf("Verifying target node %s has no local route for the VM", targetNode))
			gomega.Eventually(func() error {
				routes, err := kernelRoutes(f, targetNode, vmIP)
				if err != nil {
					return err
				}
				if local := localRoutes(routes); len(local) != 0 {
					return fmt.Errorf("target node still routes %s locally: %q", vmIP, local)
				}
				return nil
			}, 1*time.Minute, 2*time.Second).Should(gomega.Succeed())

			ginkgo.By("Verifying the TCP stream kept flowing without gaps")
			base := stream.NumLines()
			gomega.Eventually(stream.NumLines, 30*time.Second, 1*time.Second).Should(gomega.BeNumerically(">=", base+5),
				"TCP stream to the VM stopped delivering after the abort")
			_ = stream.Stop()
			gomega.Expect(stream.Err()).NotTo(gomega.HaveOccurred(), "TCP stream errored across the abort")
			gaps, lastSeq := countSequenceGaps(stream.Lines())
			worst := worstArrivalGap(stream.Events())
			logrus.Infof("TCP stream: %d gaps, last seq=%d, worst arrival gap %v", gaps, lastSeq, worst)
			gomega.Expect(gaps).To(gomega.BeZero(), "an aborted migration must not drop TCP segments")
			// TCP retransmits hide a black-hole from the sequence check; the
			// arrival times don't.
			gomega.Expect(worst).To(gomega.BeNumerically("<=", continuityMaxGap),
				"the TCP stream stalled for %v across the abort", worst)

			ginkgo.By("Verifying a fresh TCP connection to the VM succeeds")
			clientTester.ExpectSuccess(clientConn, vmTarget)
			clientTester.Execute()

			// Log-only until CORE-13929 is fixed: Felix reads the target losing its
			// role on abort as a missed GARP and promotes the target to owner.
			ginkgo.By("Checking the source pod is still the sole IPAM owner (log-only, CORE-13929)")
			handleID := vmipam.CreateVMHandleID("k8s-pod-network", ns, vmName)
			var ownerErr error
			_ = wait.PollUntilContextTimeout(ctx, 2*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
				ownerErr = func() error {
					owner, err := sampleIPAMOwner(ctx, lcgc, handleID, vmIP)
					if err != nil {
						return err
					}
					if owner != sourcePod.Name {
						return fmt.Errorf("active owner is %q, want source pod %q", owner, sourcePod.Name)
					}
					_, alternate, err := getIPAMOwnerAttributes(ctx, lcgc, strings.Split(vmIP, "/")[0])
					if err != nil {
						return err
					}
					if len(alternate) != 0 {
						return fmt.Errorf("alternate owner should be cleared after the abort, got %v", alternate)
					}
					return nil
				}()
				return ownerErr == nil, nil
			})
			if ownerErr != nil {
				logrus.Warnf("source pod not confirmed as sole IPAM owner (CORE-13929): %v", ownerErr)
			}
		})
	},
)

// worstArrivalGap is the longest wait between consecutive stream lines.
func worstArrivalGap(events []time.Time) time.Duration {
	var worst time.Duration
	for i := 1; i < len(events); i++ {
		if g := events[i].Sub(events[i-1]); g > worst {
			worst = g
		}
	}
	return worst
}
