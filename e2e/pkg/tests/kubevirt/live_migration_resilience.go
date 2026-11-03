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
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	kubevirtv1 "kubevirt.io/api/core/v1"
	migrationsv1alpha1 "kubevirt.io/api/migrations/v1alpha1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	// sourceCleanTimeout covers the source virt-launcher teardown (~9s on real
	// KubeVirt) plus BIRD withdrawing the route, with headroom for a slow node.
	sourceCleanTimeout = 1 * time.Minute
	// resilienceMigrationTimeout covers VM boot (up to 5m), one migration (up
	// to 5m) and the checks either side.
	resilienceMigrationTimeout = 15 * time.Minute
	// abortMigrationTimeout covers VM boot, the TCP server coming up, the target
	// pod starting, and the post-abort cleanup checks.
	abortMigrationTimeout = 20 * time.Minute
	// abortDeadline bounds how long after the copy starts the VMIM is deleted. At 1Mi/s the guest's memory can't finish copying in that time.
	abortDeadline = 30 * time.Second
	// migrationPolicyLabel selects the throttled MigrationPolicy onto one VMI.
	migrationPolicyLabel = "e2e-migration-policy"
)

// Live-migration resilience: the handover and abort paths leave exactly one
// owner of the VM's address and no stale state behind. The success-path specs
// in live_migration.go and ip_persistence.go assert on the *target* node; these
// look at the source node, at ownership during the handover, and at an aborted
// migration.
//
// SCOPE NOTES:
//   - Felix's route elevation and proxy-ARP decisions are unit tested in
//     felix/dataplane/linux/live_migration_test.go and proxy_neigh_mgr_test.go;
//     vmipam owner swaps in libcalico-go/lib/ipam/vmipam. These specs prove the
//     components agree on a real cluster: KubeVirt, CNI, Felix, BIRD and IPAM.
//   - A failed (timed-out) migration is covered on MockVirt by "should not
//     have /32 host route on target node after a migration timeout"; the abort
//     spec here is the real-KubeVirt, user-initiated counterpart.
//   - Felix answers proxy ARP from userspace, so the kernel proxy-neighbour
//     check below only catches a kernel entry left behind, not a stale
//     userspace responder.
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

		// N1: once the VM has left, the source node must neither route to it
		// locally nor advertise it, or traffic from elsewhere can be drawn back
		// to a node that no longer hosts it.
		ginkgo.It("should leave no route or BGP export for the VM on the source node", func() {
			ctx, cancel := context.WithTimeout(context.Background(), resilienceMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-source-clean"
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			vm.Create(ctx, cli)
			ginkgo.DeferCleanup(func() { vm.Delete(cli) })
			vmIP, sourceNode := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s on %s with IP %s", vmName, sourceNode, vmIP)

			// Without this baseline the "gone afterwards" checks below would pass on
			// a node that never had the state. The proxy-neighbour check has no
			// baseline: see SCOPE NOTES.
			ginkgo.By("Verifying the source node routes the VM locally, in the kernel and in BIRD, before migration")
			gomega.Eventually(func() error {
				routes, err := kernelRoutes(f, sourceNode, vmIP)
				if err != nil {
					return err
				}
				if len(localRoutes(routes)) != 1 {
					return fmt.Errorf("want one local route for %s on %s, got %q", vmIP, sourceNode, routes)
				}
				birdRoutes, err := queryWorkerBIRDRoute(f, sourceNode, vmIP)
				if err != nil {
					return err
				}
				for _, r := range birdRoutes {
					if r.Device {
						return nil
					}
				}
				return fmt.Errorf("BIRD on %s has no local route for %s/32 yet: %+v", sourceNode, vmIP, birdRoutes)
			}, 1*time.Minute, 2*time.Second).Should(gomega.Succeed())

			ginkgo.By("Migrating the VM")
			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			gomega.Expect(cli.Create(ctx, vmim)).To(gomega.Succeed(), "create VMIM")
			ginkgo.DeferCleanup(func() { deleteVMIMigration(cli, vmim) })
			expectMigrationSuccess(ctx, cli, vmim)
			vmi := expectMigrationStatePopulated(ctx, cli, ns, vmName)
			targetNode := vmi.Status.MigrationState.TargetNode
			gomega.Expect(targetNode).NotTo(gomega.Equal(sourceNode), "VM didn't migrate off the source node")

			// Then held, so a late re-add by a lingering source pod is caught too.
			ginkgo.By(fmt.Sprintf("Verifying source node %s has no route, BIRD export or proxy neighbour for %s", sourceNode, vmIP))
			gomega.Eventually(func() error { return sourceNodeState(f, sourceNode, vmIP) },
				sourceCleanTimeout, 2*time.Second).Should(gomega.Succeed())
			gomega.Consistently(func() error {
				err := sourceNodeState(f, sourceNode, vmIP)
				if err != nil && !errors.Is(err, errStaleState) {
					logrus.Warnf("ignoring unreadable source node state: %v", err)
					return nil
				}
				return err
			}, 15*time.Second, 3*time.Second).Should(gomega.Succeed())

			// Two kernel routes to the same /32 at different metrics would let a
			// stale one win as soon as the elevated metric reverts.
			ginkgo.By(fmt.Sprintf("Verifying target node %s has exactly one route for %s", targetNode, vmIP))
			gomega.Eventually(func() error {
				routes, err := kernelRoutes(f, targetNode, vmIP)
				if err != nil {
					return err
				}
				if len(routes) != 1 || len(localRoutes(routes)) != 1 {
					return fmt.Errorf("want exactly one route, via a local veth, for %s on %s; got %q", vmIP, targetNode, routes)
				}
				return nil
			}, metricRevertTimeout, 2*time.Second).Should(gomega.Succeed())
		})

		// N3: during the handover both virt-launcher pods carry the VM's IP, but
		// IPAM must keep one allocation with one active owner, handed over once.
		// Two owners, or an owner flapping back, is what lets GC free an address
		// still in use. Sampling at 1s can miss a sub-second window: passing means
		// none was seen.
		ginkgo.It("should keep one IPAM owner for the VM's address through the migration handover", func() {
			ctx, cancel := context.WithTimeout(context.Background(), resilienceMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name
			vmName := "e2e-one-owner"
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			vm.Create(ctx, cli)
			ginkgo.DeferCleanup(func() { vm.Delete(cli) })
			vmIP, sourceNode := vm.WaitForRunningWithIP(ctx, cli)
			sourcePod, err := vm.FindVirtLauncherPod(ctx, f)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "find source virt-launcher pod")
			logrus.Infof("VM %s on %s (pod %s) with IP %s", vmName, sourceNode, sourcePod.Name, vmIP)

			lcgc := newLibcalicoClient(f)
			handleID := vmipam.CreateVMHandleID("k8s-pod-network", ns, vmName)

			ginkgo.By("Waiting for the source pod to be the active IPAM owner")
			gomega.Eventually(func() error {
				owner, err := sampleIPAMOwner(ctx, lcgc, handleID, vmIP)
				if err != nil {
					return err
				}
				if owner != sourcePod.Name {
					return fmt.Errorf("active owner is %q, want source pod %q", owner, sourcePod.Name)
				}
				return nil
			}, 30*time.Second, 2*time.Second).Should(gomega.Succeed())

			ginkgo.By("Migrating the VM while sampling IPAM ownership every second")
			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			gomega.Expect(cli.Create(ctx, vmim)).To(gomega.Succeed(), "create VMIM")
			ginkgo.DeferCleanup(func() { deleteVMIMigration(cli, vmim) })

			// Owner promotion can trail the VMIM's Succeeded phase, so sampling
			// carries on until the target owns the address, for at most this long.
			const promotionGrace = 1 * time.Minute
			owners := []string{sourcePod.Name}
			var targetPod string
			var succeededAt time.Time
			samples, apiErrors := 0, 0
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				owner, err := sampleIPAMOwner(ctx, lcgc, handleID, vmIP)
				samples++
				if err != nil {
					// An ownership violation fails at once; an API blip only if it persists.
					gomega.Expect(errors.Is(err, errOwnership)).To(gomega.BeFalse(),
						"sample %d during the handover: %v (owners so far %v)", samples, err, owners)
					apiErrors++
					gomega.Expect(apiErrors).To(gomega.BeNumerically("<", 3),
						"IPAM unreadable for %d samples in a row during the handover: %v", apiErrors, err)
					select {
					case <-ctx.Done():
						ginkgo.Fail(fmt.Sprintf("timed out sampling the handover; owners seen: %v", owners))
					case <-ticker.C:
					}
					continue
				}
				apiErrors = 0
				if owner != owners[len(owners)-1] {
					owners = append(owners, owner)
					logrus.Infof("IPAM active owner of %s changed to %s after %d samples", vmIP, owner, samples)
				}

				// Get errors here are retried on the next tick; the deadlines below
				// bound how long that can go on.
				if targetPod == "" {
					vmi := &kubevirtv1.VirtualMachineInstance{}
					if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: vmName}, vmi); err == nil && vmi.Status.MigrationState != nil {
						targetPod = vmi.Status.MigrationState.TargetPod
					}
				}
				if succeededAt.IsZero() {
					got := &kubevirtv1.VirtualMachineInstanceMigration{}
					if err := cli.Get(ctx, ctrlclient.ObjectKeyFromObject(vmim), got); err == nil {
						gomega.Expect(got.Status.Phase).NotTo(gomega.Equal(kubevirtv1.MigrationFailed), "migration failed; IPAM owners seen: %v", owners)
						if got.Status.Phase == kubevirtv1.MigrationSucceeded {
							succeededAt = time.Now()
						}
					}
				}
				if !succeededAt.IsZero() && targetPod != "" && owner == targetPod {
					break
				}
				if !succeededAt.IsZero() && time.Since(succeededAt) > promotionGrace {
					ginkgo.Fail(fmt.Sprintf("target pod %q not the active IPAM owner %v after the migration succeeded; owners seen: %v",
						targetPod, promotionGrace, owners))
				}
				select {
				case <-ctx.Done():
					ginkgo.Fail(fmt.Sprintf("timed out sampling the handover; owners seen: %v", owners))
				case <-ticker.C:
				}
			}

			logrus.Infof("IPAM owners of %s across %d samples: %v", vmIP, samples, owners)
			gomega.Expect(owners).To(gomega.Equal([]string{sourcePod.Name, targetPod}),
				"the active owner should switch from the source pod to the target pod exactly once")

			// The source pod's teardown (~9s after cutover) runs CNI DEL against the
			// same handle; ownership must not move back or lapse when it does.
			ginkgo.By("Verifying the target keeps ownership through the source pod's teardown")
			gomega.Consistently(func() error {
				owner, err := sampleIPAMOwner(ctx, lcgc, handleID, vmIP)
				if err != nil && !errors.Is(err, errOwnership) {
					logrus.Warnf("ignoring unreadable IPAM sample: %v", err)
					return nil
				}
				if err != nil {
					return err
				}
				if owner != targetPod {
					return fmt.Errorf("active owner moved from target %q to %q", targetPod, owner)
				}
				return nil
			}, 30*time.Second, 1*time.Second).Should(gomega.Succeed())
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
			copyingAt := time.Now()
			targetNode := targetPod.Spec.NodeName
			logrus.Infof("Target pod %s Running on %s", targetPod.Name, targetNode)

			ginkgo.By("Aborting the migration by deleting the VMIM")
			deleteVMIMigration(cli, vmim)
			gomega.Expect(time.Since(copyingAt)).To(gomega.BeNumerically("<", abortDeadline),
				"VMIM deleted too late after the copy started; the abort may not have raced it")

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
			logrus.Infof("TCP stream: %d gaps, last seq=%d", gaps, lastSeq)
			gomega.Expect(gaps).To(gomega.BeZero(), "an aborted migration must not drop TCP segments")

			ginkgo.By("Verifying a fresh TCP connection to the VM succeeds")
			clientTester.ExpectSuccess(clientConn, vmTarget)
			clientTester.Execute()

			// Known red (CORE-13929): Felix reads the target losing its role on
			// abort as a missed GARP and promotes the target to owner. Last, so the
			// connectivity checks above still run while it is red.
			ginkgo.By("Verifying the source pod is still the sole IPAM owner")
			handleID := vmipam.CreateVMHandleID("k8s-pod-network", ns, vmName)
			gomega.Eventually(func() error {
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
			}, 1*time.Minute, 2*time.Second).Should(gomega.Succeed())
		})
	},
)

// kernelRoutes returns the kernel's routes for the VM's /32 on a node, one per
// line, read from the node's calico-node pod.
func kernelRoutes(f *framework.Framework, nodeName, vmIP string) ([]string, error) {
	ip := strings.Split(vmIP, "/")[0]
	pod := utils.GetCalicoNodePodOnNode(f.ClientSet, nodeName)
	if pod == nil {
		return nil, fmt.Errorf("no calico-node pod on %s", nodeName)
	}
	out, err := utils.ExecInCalicoNode(pod, fmt.Sprintf("ip route show %s/32", ip))
	if err != nil {
		return nil, fmt.Errorf("ip route show on %s: %w", nodeName, err)
	}
	var routes []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			routes = append(routes, l)
		}
	}
	return routes, nil
}

// localRoutes filters to routes out of a workload veth. A /32 learned over BGP
// from the node now hosting the VM is expected anywhere else and is excluded.
func localRoutes(routes []string) []string {
	var local []string
	for _, r := range routes {
		if strings.Contains(r, " dev cali") {
			local = append(local, r)
		}
	}
	return local
}

// errStaleState marks state the source node still holds, as opposed to a
// failure to read it.
var errStaleState = errors.New("stale state on source node")

// sourceNodeState returns an error describing any state the source node still
// holds for the VM: a local kernel route, a BIRD route it would export (BIRD
// exports the device routes it learns from the kernel), or a kernel proxy
// neighbour entry.
func sourceNodeState(f *framework.Framework, nodeName, vmIP string) error {
	ip := strings.Split(vmIP, "/")[0]
	routes, err := kernelRoutes(f, nodeName, vmIP)
	if err != nil {
		return err
	}
	if local := localRoutes(routes); len(local) != 0 {
		return fmt.Errorf("%w: kernel still routes %s locally on %s: %q", errStaleState, ip, nodeName, local)
	}

	birdRoutes, err := queryWorkerBIRDRoute(f, nodeName, vmIP)
	if err != nil {
		return err
	}
	for _, r := range birdRoutes {
		if r.Device {
			return fmt.Errorf("%w: BIRD on %s still has a local route for %s/32 to export: %+v", errStaleState, nodeName, ip, r)
		}
	}

	pod := utils.GetCalicoNodePodOnNode(f.ClientSet, nodeName)
	if pod == nil {
		return fmt.Errorf("no calico-node pod on %s", nodeName)
	}
	out, err := utils.ExecInCalicoNode(pod, "ip neigh show proxy")
	if err != nil {
		return fmt.Errorf("ip neigh show proxy on %s: %w", nodeName, err)
	}
	for _, l := range strings.Split(out, "\n") {
		if fields := strings.Fields(l); len(fields) > 0 && fields[0] == ip {
			return fmt.Errorf("%w: proxy neighbour entry for %s remains on %s: %q", errStaleState, ip, nodeName, l)
		}
	}
	return nil
}

// errOwnership marks a sample that broke the ownership invariant, as opposed
// to one that couldn't be read.
var errOwnership = errors.New("IPAM ownership violated")

// sampleIPAMOwner returns the pod named by the active owner attributes of the
// VM's address. The VM's handle must hold that address and no other of its
// family, and some pod must own it.
func sampleIPAMOwner(ctx context.Context, lcgc clientv3.Interface, handleID, vmIP string) (string, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := lcgc.IPAM().IPsByHandle(queryCtx, handleID)
	if err != nil {
		return "", fmt.Errorf("IPAM lookup of handle %s: %w", handleID, err)
	}
	want := net.ParseIP(strings.Split(vmIP, "/")[0])
	found, sameFamily := false, 0
	for _, ip := range ips {
		if (ip.To4() == nil) == (want.To4() == nil) {
			sameFamily++
		}
		found = found || ip.Equal(want)
	}
	if !found || sameFamily != 1 {
		return "", fmt.Errorf("%w: handle %s should hold %s and no other address of its family, holds %v", errOwnership, handleID, want, ips)
	}
	attrs, err := lcgc.IPAM().GetAssignmentAttributes(queryCtx, cnet.IP{IP: want})
	if err != nil {
		return "", fmt.Errorf("IPAM attributes of %s: %w", want, err)
	}
	if attrs == nil {
		return "", fmt.Errorf("%w: no IPAM allocation for %s", errOwnership, want)
	}
	owner := attrs.ActiveOwnerAttrs[model.IPAMBlockAttributePod]
	if owner == "" {
		return "", fmt.Errorf("%w: %s has no active owner pod (attrs %v)", errOwnership, want, attrs.ActiveOwnerAttrs)
	}
	return owner, nil
}
