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
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
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
//
// All tests are parallel-safe. eBGP uses random suffixes for its
// cluster-scoped resources and treats natOutgoing=false on the VM IPPool
// as a provisioning precondition.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("KubeVirt"),
	describe.WithCategory(describe.Networking),
	"KubeVirt live migration",
	func() {
		f := utils.NewDefaultFramework("calico-kubevirt")

		var cli ctrlclient.Client

		BeforeEach(func() {
			// Live migration needs at least 2 nodes to migrate between.
			utils.RequireNodeCount(f, 2)

			var err error
			cli, err = e2eclient.NewAPIClient(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to build controller-runtime client")
		})

		// Test 1: active IPAM owner promotes from source to target after migration.
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
			waitForMigrationSuccess(ctx, cli, vmim)

			// Read the target pod and node directly from the VMI's MigrationState,
			// which KubeVirt populates with the source/target identifiers as part of
			// the migration. waitForMigrationStatePopulated polls until virt-handler
			// finishes writing the state (it can lag the VMIM Succeeded phase).
			vmi := waitForMigrationStatePopulated(ctx, cli, ns, vmName)
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

		// Test 2: TCP stream over iBGP must not lose any "seq=N" segments across two
		// consecutive cross-node live migrations on a 3-worker cluster (server VM hops,
		// client pod stays put).
		It("should maintain TCP connection over iBGP across two consecutive live migrations", func() {
			ctx, cancel := context.WithTimeout(context.Background(), doubleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name
			serverVMName := "e2e-tcp-double-srv"
			serverVM := &kubeVirtVM{name: serverVMName, namespace: ns, cloudInit: tcpServerCloudInit}

			By("Creating server VM with TCP server")
			serverVM.Create(ctx, cli)
			DeferCleanup(func() { serverVM.Delete(cli) })

			serverIP, node1 := serverVM.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("Server VM: %s on %s", serverIP, node1)

			By("Creating client pod on a different node than server VM")
			clientConn, clientTester := setupAntiAffinityPod(ctx, f, node1)
			clientPod := clientConn.Pod()

			// Pre-flight reachability gate. The streaming probe's nc will
			// exit rc=1 on a refused connect (cold-boot VM not yet bound to
			// 9999), and that sticky stream error makes WaitForCadence fail
			// immediately. Wait until TCP is reachable before starting it.
			By("Waiting for VM TCP server to be reachable from client pod")
			vmTarget := conncheck.NewTCPConnectTarget(serverIP, 9999)
			clientTester.WithTimeout(2 * time.Minute)
			clientTester.ExpectSuccess(clientConn, vmTarget)
			clientTester.Execute()
			clientTester.ResetExpectations()

			By("Starting TCP client stream probe")
			probe := conncheck.StartStream(ctx, "tcp-stream",
				conncheck.NewPodSource(f, clientConn),
				conncheck.WithStreamCommand("nc", serverIP, "9999"))
			DeferCleanup(func() { _ = probe.Stop() })

			By("Verifying TCP data is flowing before migration")
			conncheck.WaitForCadence(ctx, probe, 5, 30*time.Second)
			preLines := len(probe.Lines())
			logrus.Infof("Pre-migration: %d lines on client pod", preLines)

			By("Migrating the VM")
			vmim1 := newVMIMigration(serverVMName+"-migration1", ns, serverVMName)
			Expect(cli.Create(ctx, vmim1)).To(Succeed())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim1) })
			waitForMigrationSuccess(ctx, cli, vmim1)
			vmi := &kubevirtv1.VirtualMachineInstance{}
			Expect(cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: serverVMName}, vmi)).To(Succeed())
			node2 := vmi.Status.NodeName
			Expect(node2).NotTo(Equal(node1), "VM didn't migrate off node 1")

			By("Verifying TCP stream survived first migration")
			Eventually(probe.NumLines,
				30*time.Second, 2*time.Second).Should(BeNumerically(">=", preLines+5),
				"TCP data should have grown after first migration")
			midLines := len(probe.Lines())
			logrus.Infof("After first migration: %d lines", midLines)

			By("Migrating the VM a second time")
			vmim2 := newVMIMigration(serverVMName+"-migration2", ns, serverVMName)
			Expect(cli.Create(ctx, vmim2)).To(Succeed())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim2) })
			waitForMigrationSuccess(ctx, cli, vmim2)
			Expect(cli.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: serverVMName}, vmi)).To(Succeed())
			node3 := vmi.Status.NodeName
			// With 3 worker nodes, second migration moves away from node2.
			// It could return to node1 — that's fine, we only require it left node2.
			Expect(node3).NotTo(Equal(node2), "VM didn't migrate off node 2")
			// Also require the server lands on a different node than the
			// client pod. Otherwise the post-migration "iBGP cross-node"
			// claim degrades to a same-node loopback path, which would
			// trivially have zero seq gaps regardless of routing behaviour.
			Expect(node3).NotTo(Equal(clientPod.Spec.NodeName),
				"server was scheduled to the same node as the client")

			By("Waiting for TCP data to grow after second migration")
			Eventually(probe.NumLines,
				30*time.Second, 2*time.Second).Should(BeNumerically(">=", midLines+5),
				"TCP data should have grown after second migration")

			By("Checking sequence continuity")
			_ = probe.Stop()
			Expect(probe.Err()).NotTo(HaveOccurred())
			lines := probe.Lines()
			logrus.Infof("TCP stream: %d lines, first: %s, last: %s",
				len(lines), lines[0], lines[len(lines)-1])

			seqGaps, lastSeq := countSequenceGaps(lines)
			logrus.Infof("Sequence: %d gaps, %d data points across 2 migrations", seqGaps, lastSeq)
			Expect(seqGaps).To(BeNumerically("==", 0),
				"seamless live migration must not drop any TCP segments")
		})

		// Test 3: same as Test 2 but the client runs on an external TOR over eBGP.
		// Validates that elevated krt_metric on the target node propagates via eBGP to
		// flip the TOR's kernel next-hop without dropping the TCP stream, and that
		// priority correctly reverts and re-elevates across two consecutive migrations.
		// Requires EXT_IP, EXT_KEY, EXT_USER.
		framework.Context("eBGP external client", describe.RequiresExternalNode(), func() {
			It("should maintain TCP connection from eBGP external client across two consecutive migrations", func() {
				tor := externalnode.NewClient()
				if tor == nil {
					// The RequiresExternalNode label gates whether this test runs at
					// all; once selected, missing credentials are a real failure
					// rather than a self-skip.
					Fail("External node not configured (set EXT_IP, EXT_KEY, EXT_USER)")
				}

				ctx, cancel := context.WithTimeout(context.Background(), eBGPDoubleMigrationTimeout)
				defer cancel()
				ns := f.Namespace.Name

				// Precondition: natOutgoing must be false on the IPPool backing VM
				// workloads. If true, natOutgoing rewrites the VM's source IP to the
				// node's IP at egress NAT and breaks the TOR's reverse-path matching
				// after migration. The pipeline that runs this test is expected to
				// configure the IPPool with natOutgoing=false at provisioning time;
				// we only verify here so the failure mode is obvious.
				const vmIPPoolName = "default-ipv4-ippool"
				By(fmt.Sprintf("Verifying natOutgoing=false on IPPool %s", vmIPPoolName))
				pool := &v3.IPPool{}
				Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: vmIPPoolName}, pool)).
					To(Succeed(), "IPPool %q must exist", vmIPPoolName)
				Expect(pool.Spec.NATOutgoing).To(BeFalse(),
					"IPPool %q must have natOutgoing=false (set by cluster provisioning)", vmIPPoolName)

				By("Setting up eBGP peering between TOR and cluster nodes")
				setupEBGPPeering(f, tor)

				vmName := "e2e-ebgp-tcp"
				vm := &kubeVirtVM{name: vmName, namespace: ns, cloudInit: tcpServerCloudInit}

				By("Creating a VM with TCP server")
				vm.Create(ctx, cli)
				DeferCleanup(func() { vm.Delete(cli) })

				vmIP, node1 := vm.WaitForRunningWithIP(ctx, cli)
				logrus.Infof("VM %s on %s with IP %s", vmName, node1, vmIP)

				By("Verifying TOR can reach the VM (eBGP routing is up)")
				Eventually(func() error {
					out, err := runOnTOR(tor, fmt.Sprintf("ping -c 1 -W 2 %s", vmIP))
					if err != nil {
						routes, _ := runOnTOR(tor, "sudo docker exec tor-bird birdcl show route")
						logrus.Infof("TOR BIRD routes:\n%s", routes)
						kernRoutes, _ := runOnTOR(tor, fmt.Sprintf("ip route get %s 2>&1", vmIP))
						logrus.Infof("TOR kernel route to %s: %s", vmIP, kernRoutes)
						return fmt.Errorf("ping %s failed: %v (output=%s)", vmIP, err, out)
					}
					return nil
				}, 2*time.Minute, 5*time.Second).Should(Succeed(),
					"TOR cannot reach VM — eBGP routing may not be configured")

				By("Waiting for TCP server on VM to be reachable from TOR")
				const ncClientContainer = "tor-nc-client"
				Eventually(func() error {
					out, _ := runOnTOR(tor, fmt.Sprintf(
						"sudo docker run --rm --network host alpine sh -c 'sleep 999 | timeout 5 nc %s 9999' 2>&1", vmIP))
					if !strings.Contains(out, "seq=") {
						return fmt.Errorf("TCP server not sending data from TOR (output=%q)", out)
					}
					return nil
				}, 2*time.Minute, 5*time.Second).Should(Succeed(),
					"TCP server not reachable from TOR")
				logrus.Infof("TCP server on %s:9999 is reachable and sending data from TOR", vmIP)

				By(fmt.Sprintf("Starting TCP client container %s on TOR", ncClientContainer))
				probe := conncheck.StartStream(ctx, "tor-tcp-stream",
					externalnode.NewContainerSource(tor, ncClientContainer, images.Alpine, "--network", "host"),
					conncheck.WithStreamCommand("sh", "-c", fmt.Sprintf("'sleep 999999 | nc %s 9999'", vmIP)))
				DeferCleanup(func() { _ = probe.Stop() })

				By("Waiting for TCP data to flow before migration")
				conncheck.WaitForCadence(ctx, probe, 5, 2*time.Minute)
				preLines := len(probe.Lines())
				logrus.Infof("Pre-migration: %d lines on TOR client", preLines)
				preTime := time.Now()

				By("Starting first migration")
				vmim1 := newVMIMigration(vmName+"-migration1", ns, vmName)
				Expect(cli.Create(ctx, vmim1)).To(Succeed())
				DeferCleanup(func() { deleteVMIMigration(cli, vmim1) })
				waitForMigrationSuccess(ctx, cli, vmim1)
				vmi := waitForMigrationStatePopulated(ctx, cli, ns, vmName)
				node2 := vmi.Status.MigrationState.TargetNode
				Expect(node2).NotTo(Equal(node1), "VM didn't migrate off node 1")

				// migration.WaitForSuccess returns the moment the VMIM phase is
				// Succeeded, but Felix programs krt_metric=512 asynchronously and
				// later reverts it after LiveMigrationRouteConvergenceTime (~30s).
				// Poll for the elevated state with a budget shorter than the
				// revert window so we observe it deterministically.
				By("Verifying elevated route priority on worker and TOR after first migration")
				Eventually(func(g Gomega) {
					g.Expect(queryWorkerMetric(f, node2, vmIP)).To(Equal(512),
						"worker kernel metric should be elevated (512) after migration")
					st := queryTORRoute(tor, vmIP)
					g.Expect(st.Has32).To(BeTrue(), "TOR should have /32 after migration")
					g.Expect(st.Routes).To(HaveLen(1), "should be single /32 route (no ECMP)")
					g.Expect(st.Routes[0].LocalPref).To(Equal(2147483135), "TOR /32 should have elevated local_pref")
					g.Expect(st.Routes[0].Community).To(Equal("(65000,100)"), "TOR /32 should have community tag")
				}, 20*time.Second, 1*time.Second).Should(Succeed())

				// Wait for the elevated /32 route to revert to normal local_pref
				// after the LiveMigrationRouteConvergenceTime (default 30s) expires.
				By("Waiting for TOR /32 local_pref to revert to normal after convergence")
				Eventually(func() int {
					snap := queryTORSnapshot(tor, vmIP)
					if len(snap.Host32.Routes) > 0 {
						return snap.Host32.Routes[0].LocalPref
					}
					return -1
				}, 45*time.Second, 2*time.Second).Should(Equal(100),
					"TOR /32 local_pref should revert to 100 after convergence")

				midLines := len(probe.Lines())
				Expect(midLines).To(BeNumerically(">", preLines), "TCP should still be flowing after first migration")

				// Pin migration 2 to a fresh worker via VMIM.Spec.AddedNodeSelector so
				// we exercise a brand-new /32 route. Per-VMIM scope, no cluster-wide
				// cordon to leak.
				thirdNode := pickThirdWorkerNode(ctx, f, node1, node2)

				By(fmt.Sprintf("Migrating the VM a second time, pinned to node %s", thirdNode))
				vmim2 := newVMIMigration(vmName+"-migration2", ns, vmName)
				vmim2.Spec.AddedNodeSelector = map[string]string{
					"kubernetes.io/hostname": thirdNode,
				}
				Expect(cli.Create(ctx, vmim2)).To(Succeed())
				DeferCleanup(func() { deleteVMIMigration(cli, vmim2) })
				waitForMigrationSuccess(ctx, cli, vmim2)
				vmi = waitForMigrationStatePopulated(ctx, cli, ns, vmName)
				node3 := vmi.Status.MigrationState.TargetNode
				Expect(node3).NotTo(Equal(node2), "VM didn't migrate off node 2")

				// Same race as after the first migration: Felix programs the
				// elevated metric asynchronously and reverts it after the
				// convergence window. Poll for the elevated state.
				By("Verifying TOR route state after second migration")
				Eventually(func(g Gomega) {
					st := queryTORRoute(tor, vmIP)
					g.Expect(st.Has32).To(BeTrue(), "TOR should have /32 after second migration")
					// Find best route — it must have elevated local_pref (no ECMP).
					var b, nb *torBIRDRoute
					for i := range st.Routes {
						if st.Routes[i].Best {
							b = &st.Routes[i]
						} else {
							nb = &st.Routes[i]
						}
					}
					g.Expect(b).NotTo(BeNil(), "TOR should have a best /32 route")
					g.Expect(b.LocalPref).To(Equal(2147483135), "best /32 route should have elevated local_pref")
					g.Expect(b.Community).To(Equal("(65000,100)"), "best /32 route should have community tag")
					// After the second migration, two /32 routes must exist: the new
					// node's elevated route and the old node's normal route. They
					// must have different local_pref to avoid ECMP.
					g.Expect(nb).NotTo(BeNil(), "TOR should have two /32 routes after second migration")
					g.Expect(nb.LocalPref).NotTo(Equal(b.LocalPref),
						"two /32 routes must have different local_pref to avoid ECMP")
				}, 20*time.Second, 1*time.Second).Should(Succeed())

				// Wait for the second migration's /32 route to revert to normal
				// local_pref, same as after the first migration.
				By("Waiting for TOR /32 local_pref to revert after second migration")
				Eventually(func() int {
					snap := queryTORSnapshot(tor, vmIP)
					if len(snap.Host32.Routes) > 0 {
						return snap.Host32.Routes[0].LocalPref
					}
					return -1
				}, 45*time.Second, 2*time.Second).Should(Equal(100),
					"TOR /32 local_pref should revert to 100 after second migration convergence")

				finalLines := len(probe.Lines())
				Expect(finalLines).To(BeNumerically(">", midLines),
					"TCP stream should have continued growing after second migration (final=%d, mid=%d)", finalLines, midLines)

				By("Verifying TCP stream integrity")
				_ = probe.Stop()
				Expect(probe.Err()).NotTo(HaveOccurred())
				lines := probe.Lines()
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
			})
		})

		// Test 4: a NetworkPolicy selecting the VM (app=vm) by ingress role=allowed must
		// keep applying after the VM live-migrates to a different node, both for an
		// allowed and a denied client.
		It("should enforce NetworkPolicy after live migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), singleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name

			vmName := "e2e-netpol-vm"
			vm := &kubeVirtVM{
				name:      vmName,
				namespace: ns,
				cloudInit: tcpServerCloudInit,
				labels:    map[string]string{"app": "vm"},
			}

			By("Creating VM with TCP server and app=vm label")
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
			vmTarget := conncheck.NewTCPConnectTarget(vmIP, 9999)

			// Cold-boot VM cloud-init can take up to ~2m to bind nc -lkp,
			// so the first reachability assertion needs a longer budget
			// than conncheck's default 30s.
			By("Verifying both clients can reach VM before policy is applied")
			tester.WithTimeout(2 * time.Minute)
			tester.ExpectSuccess(allowed, vmTarget)
			tester.ExpectSuccess(denied, vmTarget)
			tester.Execute()
			tester.ResetExpectations()

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
			_, err := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(ctx, netpol, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				_ = f.ClientSet.NetworkingV1().NetworkPolicies(ns).Delete(context.Background(), netpol.Name, metav1.DeleteOptions{})
			})

			By("Verifying policy is enforced: client1 allowed, client2 denied")
			tester.ExpectSuccess(allowed, vmTarget)
			tester.ExpectFailure(denied, vmTarget)
			tester.Execute()
			tester.ResetExpectations()

			By("Triggering live migration")
			vmim := newVMIMigration(vmName+"-migration", ns, vmName)
			err = cli.Create(ctx, vmim)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { deleteVMIMigration(cli, vmim) })
			waitForMigrationSuccess(ctx, cli, vmim)

			vmi := waitForMigrationStatePopulated(ctx, cli, ns, vmName)
			node2 := vmi.Status.MigrationState.TargetNode
			Expect(node2).NotTo(Equal(node1), "VM should have migrated to a different node")
			logrus.Infof("VM migrated: %s -> %s", node1, node2)

			// Felix is async after VMIM Succeeded: it must learn the new
			// workload and program policy on the target node. Use
			// Eventually wrapping both Connects so the assertion only
			// passes when allowed succeeds AND denied fails in the same
			// iteration; otherwise the denied probe could match
			// ExpectFailure on a transient pre-route window and exit
			// before policy is actually in force.
			By("Verifying policy survives migration: allowed reaches, denied blocked")
			Eventually(func(g Gomega) {
				_, err := tester.Connect(allowed, vmTarget)
				g.Expect(err).NotTo(HaveOccurred(),
					"allowed client should reach migrated pod")
				_, err = tester.Connect(denied, vmTarget)
				g.Expect(err).To(HaveOccurred(),
					"denied client should be blocked by NetworkPolicy")
			}, 90*time.Second, 2*time.Second).Should(Succeed())
			logrus.Info("NetworkPolicy enforcement confirmed after live migration")
		})
	},
)
