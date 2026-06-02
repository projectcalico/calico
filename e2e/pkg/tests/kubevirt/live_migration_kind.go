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
	"os/exec"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// kindBIRDPeer manages a BIRD 1.x container running on the Docker "kind"
// network. Unlike externalnode.Client (SSH-based), this uses local Docker
// commands so no external node or SSH credentials are required.
type kindBIRDPeer struct {
	containerName string
	containerIP   string
}

// startKindBIRDPeer starts a BIRD container on the kind Docker network and
// returns a handle for interacting with it. The container runs in privileged
// mode so BIRD can manipulate the routing table.
func startKindBIRDPeer(name string) *kindBIRDPeer {
	GinkgoHelper()

	// Remove any stale container from a previous run.
	_ = exec.Command("docker", "rm", "-f", name).Run()

	By(fmt.Sprintf("Starting BIRD container %s on kind network", name))
	out, err := exec.Command("docker", "run", "-d", "--privileged",
		"--network", "kind", "--name", name, images.CalicoBIRD).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(),
		"failed to start BIRD container %s: %s", name, string(out))

	// Wait for the container to be running.
	Eventually(func() error {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("docker inspect: %w (%s)", err, string(out))
		}
		if strings.TrimSpace(string(out)) != "true" {
			return fmt.Errorf("container %s not running yet", name)
		}
		return nil
	}, 30*time.Second, 2*time.Second).Should(Succeed(), "BIRD container %s not running", name)

	// Get the container IP on the kind network.
	ipOut, err := exec.Command("docker", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "failed to get IP of container %s", name)
	containerIP := strings.TrimSpace(string(ipOut))
	Expect(containerIP).NotTo(BeEmpty(), "container %s has no IP address", name)

	logrus.Infof("BIRD container %s started with IP %s on kind network", name, containerIP)
	return &kindBIRDPeer{containerName: name, containerIP: containerIP}
}

// PeerIP returns the container IP for the Calico BGPPeer resource.
func (p *kindBIRDPeer) PeerIP() string { return p.containerIP }

// CheckBGPSession returns the output of "birdcl show protocols".
func (p *kindBIRDPeer) CheckBGPSession() (string, error) {
	return p.exec("birdcl", "show", "protocols")
}

// stop removes the BIRD container.
func (p *kindBIRDPeer) stop() {
	By(fmt.Sprintf("Stopping BIRD container %s", p.containerName))
	_ = exec.Command("docker", "rm", "-f", p.containerName).Run()
}

// exec runs a command inside the BIRD container and returns stdout+stderr.
func (p *kindBIRDPeer) exec(args ...string) (string, error) {
	cmdArgs := append([]string{"exec", p.containerName}, args...)
	out, err := exec.Command("docker", cmdArgs...).CombinedOutput()
	return string(out), err
}

// writeFile writes content to a file inside the container via docker exec.
func (p *kindBIRDPeer) writeFile(path, content string) {
	GinkgoHelper()
	cmdArgs := []string{"exec", "-i", p.containerName, "sh", "-c", fmt.Sprintf("cat > %s", path)}
	cmd := exec.Command("docker", cmdArgs...)
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(),
		"failed to write %s in container %s: %s", path, p.containerName, string(out))
}

// ConfigureBIRD writes the peers config, enables merge paths, and reloads BIRD.
func (p *kindBIRDPeer) ConfigureBIRD(peersConf string) {
	GinkgoHelper()

	// Enable merge paths in the kernel protocol for ECMP support.
	out, err := p.exec("sed", "-i", "/protocol kernel {/a merge paths on;", "/etc/bird.conf")
	Expect(err).NotTo(HaveOccurred(),
		"failed to enable merge paths in BIRD: %s", out)

	// Replace the source address placeholder with the container's actual IP.
	peersConf = strings.ReplaceAll(peersConf, "ip@local", p.containerIP)
	p.writeFile("/etc/bird/peers.conf", peersConf)

	By("Reloading BIRD config")
	out, err = p.exec("birdcl", "configure")
	Expect(err).NotTo(HaveOccurred(), "birdcl configure failed: %s", out)
	logrus.Infof("birdcl configure: %s", out)
}

// queryRoute queries the BIRD routing table for a /32 route and returns
// the parsed route state. Uses parseBIRDRouteOutput from utils.go.
func (p *kindBIRDPeer) queryRoute(vmIP string) torRouteState {
	ip := strings.Split(vmIP, "/")[0]

	out, err := p.exec("birdcl", "show", "route", ip+"/32", "all")
	if err != nil {
		logrus.Warnf("kindBIRDPeer.queryRoute: exec error: %v", err)
		return torRouteState{}
	}

	var state torRouteState
	state.Routes = parseBIRDRouteOutput(out)
	state.Has32 = len(state.Routes) > 0
	return state
}

// querySnapshot queries the BIRD routing table for both the /32 host route
// and the /26 block route. Same pattern as queryTORSnapshot but via local
// docker exec instead of SSH.
func (p *kindBIRDPeer) querySnapshot(vmIP string) torRouteSnapshot {
	ip := strings.Split(vmIP, "/")[0]

	parsed := net.ParseIP(ip).To4()
	blockIP := net.IPv4(parsed[0], parsed[1], parsed[2], parsed[3]&0xC0)
	block26 := fmt.Sprintf("%s/26", blockIP)

	// Query /32 route.
	out32, _ := p.exec("birdcl", "show", "route", ip+"/32", "all")
	routes32 := parseBIRDRouteOutput(out32)

	// Query /26 route.
	out26, _ := p.exec("birdcl", "show", "route", block26, "all")
	routes26 := parseBIRDRouteOutput(out26)

	snap := torRouteSnapshot{
		Host32:  torPrefixState{Present: len(routes32) > 0, Routes: routes32},
		Block26: torPrefixState{Present: len(routes26) > 0, Routes: routes26},
	}

	logrus.Infof("kindBIRDPeer.querySnapshot(%s): /32=%v(%d) /26=%v(%d)",
		ip, snap.Host32.Present, len(snap.Host32.Routes),
		snap.Block26.Present, len(snap.Block26.Routes))
	return snap
}

// setupKindEBGPPeering configures eBGP peering between a BIRD container on the
// kind Docker network and the cluster's control-plane calico-node.
func setupKindEBGPPeering(f *framework.Framework, bird *kindBIRDPeer) {
	GinkgoHelper()
	setupEBGPPeeringCommon(f, bird, "kubevirt-kind-lm-", "kind-ebgp-peer-")
}

// expectMigrationFailed polls the VMIM until it reaches MigrationFailed
// phase. Immediately stops polling with a fatal error if MigrationSucceeded is
// observed (the migration was expected to fail).
func expectMigrationFailed(ctx context.Context, cli ctrlclient.Client, vmim *kubevirtv1.VirtualMachineInstanceMigration) {
	GinkgoHelper()
	By(fmt.Sprintf("Waiting for migration %s to fail", vmim.Name))
	Eventually(func() error {
		got := &kubevirtv1.VirtualMachineInstanceMigration{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: vmim.Namespace, Name: vmim.Name}, got); err != nil {
			return err
		}
		if got.Status.Phase == kubevirtv1.MigrationSucceeded {
			return StopTrying("migration unexpectedly succeeded")
		}
		if got.Status.Phase != kubevirtv1.MigrationFailed {
			return fmt.Errorf("phase is %s", got.Status.Phase)
		}
		return nil
	}, 5*time.Minute, 1*time.Second).Should(Succeed())
}

// KubeVirt live migration route convergence tests for KIND clusters.
// iBGP test: validates kernel route metric elevation (512) and reversion (1024)
// on worker nodes during live migration — no external BIRD peer required.
// eBGP test: validates BGP route priority (krt_metric, community tagging,
// local_pref) using a local BIRD container on the Docker "kind" network.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("KubeVirt-KIND"),
	describe.WithCategory(describe.Networking),
	describe.WithSerial(),
	"KubeVirt live migration (KIND)",
	func() {
		f := utils.NewDefaultFramework("calico-kubevirt-kind")

		var cli ctrlclient.Client

		BeforeEach(func() {
			if !isKINDCluster(f) {
				Fail("KubeVirt-KIND tests selected but cluster is not a KIND cluster")
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
			vmName := "e2e-kind-ibgp"
			vm := &kubeVirtVM{name: vmName, namespace: ns}

			By("Creating VM")
			vm.Create(ctx, cli)
			DeferCleanup(func() { vm.Delete(cli) })

			vmIP, node1 := vm.WaitForRunningWithIP(ctx, cli)
			logrus.Infof("VM %s on %s with IP %s", vmName, node1, vmIP)

			// Pre-migration: the source node should have a normal-priority /32 route.
			By("Verifying pre-migration kernel route metric on source node")
			Eventually(func() int {
				return queryWorkerMetric(f, node1, vmIP)
			}, 2*time.Minute, 5*time.Second).Should(Equal(1024),
				"source node should have normal kernel route metric (1024) before migration")

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
			Eventually(func() int {
				return queryWorkerMetric(f, node2, vmIP)
			}, 20*time.Second, 1*time.Second).Should(Equal(512),
				"target node should have elevated kernel route metric (512) after migration")

			// Wait for metric to revert to normal (1024) after convergence window (~30s).
			By("Waiting for kernel route metric to revert to normal on target node")
			Eventually(func() int {
				return queryWorkerMetric(f, node2, vmIP)
			}, 45*time.Second, 2*time.Second).Should(Equal(1024),
				"target node kernel route metric should revert to 1024 after convergence")

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
			Eventually(func() int {
				return queryWorkerMetric(f, node3, vmIP)
			}, 20*time.Second, 1*time.Second).Should(Equal(512),
				"target node should have elevated kernel route metric (512) after second migration")

			// Wait for metric to revert to normal (1024) after convergence window.
			By("Waiting for kernel route metric to revert to normal on target node after second migration")
			Eventually(func() int {
				return queryWorkerMetric(f, node3, vmIP)
			}, 45*time.Second, 2*time.Second).Should(Equal(1024),
				"target node kernel route metric should revert to 1024 after second migration convergence")
		})

		It("should not have /32 host route on target node after a migration timeout", func() {
			ctx, cancel := context.WithTimeout(context.Background(), singleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name

			vmName := "e2e-kind-timeout"
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
			// queryWorkerMetric returns -1 when no /32 route exists.
			By("Verifying target node has no /32 kernel route after migration timeout")
			Consistently(func() int {
				return queryWorkerMetric(f, targetNode, vmIP)
			}, 15*time.Second, 2*time.Second).Should(Equal(-1),
				"target node should not have /32 kernel route after failed migration")

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

			vmName := "e2e-kind-netpol"
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

		It("should converge eBGP routes after live migration", func() {
			ctx, cancel := context.WithTimeout(context.Background(), eBGPDoubleMigrationTimeout)
			defer cancel()
			ns := f.Namespace.Name

			// Start BIRD container on the kind Docker network.
			bird := startKindBIRDPeer("kind-bird-ebgp")
			DeferCleanup(bird.stop)

			// Set up eBGP peering between the BIRD container and the cluster.
			setupKindEBGPPeering(f, bird)

			// Create a VM with default cloud-init (no TCP server needed — this
			// test only validates route convergence, not TCP continuity).
			vmName := "e2e-kind-ebgp"
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
				snap := bird.querySnapshot(vmIP)
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
				g.Expect(queryWorkerMetric(f, node2, vmIP)).To(Equal(512),
					"worker kernel metric should be elevated (512) after migration")
				st := bird.queryRoute(vmIP)
				g.Expect(st.Has32).To(BeTrue(), "BIRD should have /32 after migration")
				g.Expect(st.Routes).To(HaveLen(1), "should be single /32 route (no ECMP)")
				g.Expect(st.Routes[0].LocalPref).To(Equal(2147483135),
					"BIRD /32 should have elevated local_pref")
				g.Expect(st.Routes[0].Community).To(Equal("(65000,100)"),
					"BIRD /32 should have community tag")
			}, 20*time.Second, 1*time.Second).Should(Succeed())

			// Wait for the elevated /32 route to revert to normal local_pref.
			By("Waiting for BIRD /32 local_pref to revert to normal after convergence")
			Eventually(func() int {
				snap := bird.querySnapshot(vmIP)
				if len(snap.Host32.Routes) > 0 {
					return snap.Host32.Routes[0].LocalPref
				}
				return -1
			}, 45*time.Second, 2*time.Second).Should(Equal(100),
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
				st := bird.queryRoute(vmIP)
				g.Expect(st.Has32).To(BeTrue(), "BIRD should have /32 after second migration")
				var b, nb *torBIRDRoute
				for i := range st.Routes {
					if st.Routes[i].Best {
						b = &st.Routes[i]
					} else {
						nb = &st.Routes[i]
					}
				}
				g.Expect(b).NotTo(BeNil(), "BIRD should have a best /32 route")
				g.Expect(b.LocalPref).To(Equal(2147483135),
					"best /32 route should have elevated local_pref")
				g.Expect(b.Community).To(Equal("(65000,100)"),
					"best /32 route should have community tag")
				// Two /32 routes with different local_pref (no ECMP).
				g.Expect(nb).NotTo(BeNil(),
					"BIRD should have two /32 routes after second migration")
				g.Expect(nb.LocalPref).NotTo(Equal(b.LocalPref),
					"two /32 routes must have different local_pref to avoid ECMP")
			}, 20*time.Second, 1*time.Second).Should(Succeed())

			// Wait for the second migration's /32 route to revert.
			By("Waiting for BIRD /32 local_pref to revert after second migration")
			Eventually(func() int {
				snap := bird.querySnapshot(vmIP)
				if len(snap.Host32.Routes) > 0 {
					return snap.Host32.Routes[0].LocalPref
				}
				return -1
			}, 45*time.Second, 2*time.Second).Should(Equal(100),
				"BIRD /32 local_pref should revert to 100 after second migration convergence")
		})
	},
)
