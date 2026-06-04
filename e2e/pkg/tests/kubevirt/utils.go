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
	"math/big"
	"net"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/config"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/bgp"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// Per-test timeouts. Each sized to the sum of the test's inner Eventually
// budgets plus VM/pod boot, so a failure surfaces as the inner timeout, not
// an outer context-cancelled.
const (
	ipPersistenceTimeout       = 3 * time.Minute
	podRecreationTimeout       = 5 * time.Minute
	vmiRecreationTimeout       = 12 * time.Minute
	singleMigrationTimeout     = 5 * time.Minute
	doubleMigrationTimeout     = 6 * time.Minute
	eBGPDoubleMigrationTimeout = 6 * time.Minute
)

// Route convergence constants for KubeVirt live migration tests.
// Felix elevates the kernel route metric to 512 on the target node during
// migration; the BIRD import filter maps community (65000,100) to
// local_pref 2147483135. After LiveMigrationRouteConvergenceTime (~30s),
// metrics revert to their normal values.
const (
	elevatedRouteMetric   = 512
	normalRouteMetric     = 1024
	elevatedLocalPref     = 2147483135
	normalLocalPref       = 100
	migrationCommunityTag = "(65000,100)"

	// elevatedMetricTimeout is the polling budget for observing the elevated
	// metric after migration (Felix programs it asynchronously).
	elevatedMetricTimeout = 20 * time.Second
	// metricRevertTimeout is the polling budget for the metric to revert
	// after the convergence window (~30s) expires.
	metricRevertTimeout = 45 * time.Second
)

// vmImage returns KUBEVIRT_TEST_VM_IMAGE when set, otherwise images.KubeVirtUbuntu.
func vmImage() string {
	if v := config.KubeVirtTestVMImage(); v != "" {
		return v
	}
	return images.KubeVirtUbuntu
}

// defaultCloudInit configures the VM's default user with a known password and
// enables SSH password auth so test debuggers can console in.
const defaultCloudInit = "#cloud-config\npassword: testpass\nchpasswd: { expire: False }\nssh_pwauth: True\n"

// tcpServerCloudInit boots the VM with /usr/local/bin/tcp-server.py: a TCP echo
// server on port 9999 that emits "seq=N\n" once per second per client. Live-
// migration tests use seq gaps as a connection-continuity tripwire.
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

// kubeVirtVM holds the static configuration for a KubeVirt VirtualMachine
// used by e2e tests. The KubeVirt client is NOT a field on this struct; it is
// passed to operations (Create/Delete/Stop/etc.) so the VM and the API client
// stay distinct concepts.
type kubeVirtVM struct {
	name        string
	namespace   string
	cloudInit   string
	labels      map[string]string // extra labels propagated to virt-launcher pod
	annotations map[string]string // extra annotations propagated to virt-launcher pod
}

func (v *kubeVirtVM) spec() *kubevirtv1.VirtualMachine {
	cloudInit := v.cloudInit
	if cloudInit == "" {
		cloudInit = defaultCloudInit
	}
	templateLabels := map[string]string{"vm": v.name, utils.TestResourceLabel: "true"}
	for k, val := range v.labels {
		templateLabels[k] = val
	}
	templateAnnotations := map[string]string{
		"kubevirt.io/allow-pod-bridge-network-live-migration": "true",
	}
	for k, val := range v.annotations {
		templateAnnotations[k] = val
	}
	runStrategy := kubevirtv1.RunStrategyAlways
	return &kubevirtv1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name: v.name, Namespace: v.namespace,
			Labels: templateLabels,
		},
		Spec: kubevirtv1.VirtualMachineSpec{
			RunStrategy: &runStrategy,
			Template: &kubevirtv1.VirtualMachineInstanceTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: templateAnnotations,
					Labels:      templateLabels,
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
					TerminationGracePeriodSeconds: ptr.To(int64(30)),
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
func (v *kubeVirtVM) Create(ctx context.Context, cli ctrlclient.Client) {
	By(fmt.Sprintf("Creating VirtualMachine %s", v.name))
	Expect(cli.Create(ctx, v.spec())).To(Succeed())
}

// Delete removes the VirtualMachine from the cluster. Tolerates NotFound so a
// caller registering Delete via DeferCleanup never fails the test for a
// resource that is already gone (e.g. cleaned up by namespace teardown).
//
// Bounded with a 30s context so a slow / unreachable apiserver during
// teardown doesn't park the entire Ginkgo run waiting for cleanup.
func (v *kubeVirtVM) Delete(cli ctrlclient.Client) {
	logrus.Infof("Cleaning up VM %s/%s", v.namespace, v.name)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vm := &kubevirtv1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: v.namespace, Name: v.name}}
	if err := cli.Delete(ctx, vm); err != nil && !apierrors.IsNotFound(err) {
		Expect(err).NotTo(HaveOccurred())
	}
}

// setRunStrategy mutates the VM's RunStrategy. Stop/Start are thin wrappers
// over this so the only behavioural difference between the two is captured by
// the strategy constant.
func (v *kubeVirtVM) setRunStrategy(ctx context.Context, cli ctrlclient.Client, strategy kubevirtv1.VirtualMachineRunStrategy) {
	Eventually(func() error {
		vm := &kubevirtv1.VirtualMachine{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: v.namespace, Name: v.name}, vm); err != nil {
			return fmt.Errorf("get VM: %w", err)
		}
		vm.Spec.RunStrategy = &strategy
		vm.Spec.Running = nil
		if err := cli.Update(ctx, vm); err != nil {
			return fmt.Errorf("update VM: %w", err)
		}
		return nil
	}, 1*time.Minute, 5*time.Second).Should(Succeed(),
		"failed to set RunStrategy=%s on VM %s", strategy, v.name)
}

// Stop sets RunStrategy to Halted, causing KubeVirt to delete the VMI and pod.
func (v *kubeVirtVM) Stop(ctx context.Context, cli ctrlclient.Client) {
	v.setRunStrategy(ctx, cli, kubevirtv1.RunStrategyHalted)
}

// Start sets RunStrategy to Always, causing KubeVirt to create a new VMI and pod.
func (v *kubeVirtVM) Start(ctx context.Context, cli ctrlclient.Client) {
	v.setRunStrategy(ctx, cli, kubevirtv1.RunStrategyAlways)
}

// WaitForRunningWithIP polls the VMI until it reaches Running phase and has an IP
// address assigned. Returns the IP and the node where the VMI is scheduled.
func (v *kubeVirtVM) WaitForRunningWithIP(ctx context.Context, cli ctrlclient.Client) (ip, node string) {
	By(fmt.Sprintf("Waiting for VMI %s to be Running with IP", v.name))
	Eventually(func() error {
		vmi := &kubevirtv1.VirtualMachineInstance{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: v.namespace, Name: v.name}, vmi); err != nil {
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

// FindVirtLauncherPod finds the running virt-launcher pod for this VM by label selector.
// Returns the first Running pod that is not being deleted, or an error if none found.
func (v *kubeVirtVM) FindVirtLauncherPod(ctx context.Context, f *framework.Framework) (*corev1.Pod, error) {
	pods, err := f.ClientSet.CoreV1().Pods(v.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("kubevirt.io=virt-launcher,vm.kubevirt.io/name=%s", v.name),
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
	return nil, fmt.Errorf("no running virt-launcher pod found for VM %s (total pods: %d)", v.name, len(pods.Items))
}

// setupAntiAffinityPod creates a long-running pod scheduled away from the
// given node, used for TCP tests where the client must be on a different node
// than the server VM to exercise cross-node BGP routing. Returns both the
// Client and the underlying ConnectionTester so callers can reuse the tester
// for pre-flight checks (e.g. TCPConnect reachability gates).
func setupAntiAffinityPod(ctx context.Context, f *framework.Framework, avoidNode string) (conncheck.Client, conncheck.ConnectionTester) {
	By(fmt.Sprintf("Creating client pod avoiding node %s", avoidNode))
	tester := conncheck.NewConnectionTester(f)
	DeferCleanup(tester.Stop)
	client := conncheck.NewClient("tcp-client", f.Namespace,
		conncheck.WithClientCustomizer(func(pod *corev1.Pod) {
			if pod.Spec.Affinity == nil {
				pod.Spec.Affinity = &corev1.Affinity{}
			}
			pod.Spec.Affinity.NodeAffinity = &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      "kubernetes.io/hostname",
							Operator: corev1.NodeSelectorOpNotIn,
							Values:   []string{avoidNode},
						}},
					}},
				},
			}
		}),
	)
	tester.AddClient(client)
	tester.Deploy()
	pod := client.Pod()
	Expect(pod.Spec.NodeName).NotTo(Equal(avoidNode), "client pod should be on a different node")
	logrus.Infof("Client pod %s on %s (server VM on %s)", pod.Name, pod.Spec.NodeName, avoidNode)
	return client, tester
}

// newVMIMigration returns a VMIM object that triggers live migration of vmiName
// when applied. Plain object (no embedded client) so VM-as-data and API client
// stay distinct, matching kubeVirtVM.
func newVMIMigration(name, namespace, vmiName string) *kubevirtv1.VirtualMachineInstanceMigration {
	return &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       kubevirtv1.VirtualMachineInstanceMigrationSpec{VMIName: vmiName},
	}
}

// deleteVMIMigration removes the VMIM resource from the cluster. Tolerates
// NotFound so a caller registering this via DeferCleanup never fails the test
// for a resource that is already gone. Bounded by a 30s context so apiserver
// stalls during teardown can't park the suite.
func deleteVMIMigration(cli ctrlclient.Client, vmim *kubevirtv1.VirtualMachineInstanceMigration) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := cli.Delete(ctx, vmim); err != nil && !apierrors.IsNotFound(err) {
		Expect(err).NotTo(HaveOccurred())
	}
}

// expectMigrationSuccess polls the VMIM until it reaches MigrationSucceeded
// phase. Immediately stops polling with a fatal error if MigrationFailed is
// observed.
func expectMigrationSuccess(ctx context.Context, cli ctrlclient.Client, vmim *kubevirtv1.VirtualMachineInstanceMigration) {
	GinkgoHelper()
	By(fmt.Sprintf("Waiting for migration %s to succeed", vmim.Name))
	Eventually(func() error {
		got := &kubevirtv1.VirtualMachineInstanceMigration{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: vmim.Namespace, Name: vmim.Name}, got); err != nil {
			return err
		}
		if got.Status.Phase == kubevirtv1.MigrationFailed {
			logrus.Warnf("Migration %s FAILED. Conditions: %+v", vmim.Name, got.Status.Conditions)
			vmi := &kubevirtv1.VirtualMachineInstance{}
			if vmiErr := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: vmim.Namespace, Name: vmim.Spec.VMIName}, vmi); vmiErr == nil && vmi.Status.MigrationState != nil {
				ms := vmi.Status.MigrationState
				logrus.Warnf("VMI MigrationState: Completed=%v Failed=%v FailureReason=%s StartTimestamp=%v EndTimestamp=%v",
					ms.Completed, ms.Failed, ms.FailureReason, ms.StartTimestamp, ms.EndTimestamp)
			}
			return StopTrying("migration failed")
		}
		if got.Status.Phase != kubevirtv1.MigrationSucceeded {
			return fmt.Errorf("phase is %s", got.Status.Phase)
		}
		return nil
	}, 5*time.Minute, 1*time.Second).Should(Succeed())
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
// of the given IP address. Returns an error if the IPAM query fails or no assignment exists,
// so callers can distinguish transient failures from a missing allocation.
func getIPAMOwnerAttributes(ctx context.Context, c clientv3.Interface, ipStr string) (active, alternate map[string]string, err error) {
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ip := cnet.IP{IP: net.ParseIP(ipStr)}
	attr, err := c.IPAM().GetAssignmentAttributes(queryCtx, ip)
	if err != nil {
		return nil, nil, fmt.Errorf("IPAM query for %s failed: %w", ipStr, err)
	}
	if attr == nil {
		return nil, nil, fmt.Errorf("no IPAM assignment found for %s", ipStr)
	}
	return attr.ActiveOwnerAttrs, attr.AlternateOwnerAttrs, nil
}

// countSequenceGaps parses "seq=N" lines and counts gaps in the sequence. When a gap is
// found, it logs the lost range together with a small window of surrounding raw lines
// to aid debugging in CI (e.g., distinguishing a clean re-sequence from a stream restart).
func countSequenceGaps(lines []string) (gaps, lastSeq int) {
	first := true
	for i, line := range lines {
		var seq int
		if _, scanErr := fmt.Sscanf(line, "seq=%d", &seq); scanErr == nil {
			if !first && seq != lastSeq+1 {
				gaps++
				start := i - 3
				if start < 0 {
					start = 0
				}
				end := i + 4
				if end > len(lines) {
					end = len(lines)
				}
				logrus.Infof("Sequence gap: %d -> %d (context lines %d-%d: %q)",
					lastSeq, seq, start, end-1, lines[start:end])
			}
			first = false
			lastSeq = seq
		}
	}
	return
}

// runOnExternalNode runs cmd on an external node via SSH and returns stdout
// plus any wrapped error. Used by live_migration.go for non-BIRD operations
// (ping, kernel route checks, docker run).
func runOnExternalNode(node *externalnode.Client, cmd string) (string, error) {
	out, err := node.Exec("sh", "-c", cmd)
	if err != nil {
		return out, fmt.Errorf("SSH cmd %q failed: %w (output=%q)", cmd, err, out)
	}
	return out, nil
}

// discoverPodCIDR returns the CIDR of the first IPv4 IPPool found in the
// cluster, used to gate the TOR BIRD import filter. Fails the test if no IPv4
// IPPool can be found (cluster is broken or in mid-install).
func discoverPodCIDR(ctx context.Context, lcgc clientv3.Interface) string {
	GinkgoHelper()
	pools, err := lcgc.IPPools().List(ctx, options.ListOptions{})
	Expect(err).NotTo(HaveOccurred(), "list IPPools to discover pod CIDR")
	for _, p := range pools.Items {
		if !strings.Contains(p.Spec.CIDR, ":") {
			return p.Spec.CIDR
		}
	}
	Fail("no IPv4 IPPool found — cannot configure TOR BIRD import filter")
	return ""
}

// pickUnallocatedIP discovers the cluster's first IPv4 IPPool and returns an
// IP within that CIDR that is not currently allocated. Fails the test if no
// unallocated IP can be found.
func pickUnallocatedIP(ctx context.Context, lcgc clientv3.Interface) string {
	GinkgoHelper()
	cidr := discoverPodCIDR(ctx, lcgc)
	_, ipNet, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred(), "parse IPPool CIDR %s", cidr)
	base := cnet.IP{IP: ipNet.IP}
	ones, bits := ipNet.Mask.Size()
	numHosts := 1 << (bits - ones) // addresses in the pool (e.g. /24 → 256)
	for offset := 1; offset < numHosts; offset++ {
		candidate := cnet.IncrementIP(base, big.NewInt(int64(offset)))
		_, err := lcgc.IPAM().GetAssignmentAttributes(ctx, candidate)
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			return candidate.String()
		}
	}
	Fail("no unallocated IP found in pool " + cidr)
	return ""
}

// setupEBGPPeeringCommon configures eBGP peering between an external BIRD peer
// and the cluster's control-plane calico-node. It:
//   - discovers the master node and pod CIDR
//   - generates and applies the BIRD peers config via peer.ConfigureBIRD
//   - creates a BGPFilter that tags elevated-priority routes with a community
//   - creates a BGPPeer pointing the master at peer.PeerIP()
//   - waits for confd to regenerate bird.cfg and the eBGP session to establish
//
// All Calico resources are cleaned up via DeferCleanup. filterPrefix and
// peerPrefix control the random name prefixes for stale-resource sweeping.
func setupEBGPPeeringCommon(f *framework.Framework, peer bgp.BIRDPeer, filterPrefix, peerPrefix string) {
	GinkgoHelper()
	By("Setting up eBGP peering")

	// Use the libcalico-go client for Calico resources (BGPPeer, BGPFilter).
	// The controller-runtime client fails resource discovery when the Calico API
	// server aggregated endpoint (projectcalico.org/v3) is registered but not running.
	lcgc := newLibcalicoClient(f)
	ctx := context.Background()

	filterName := utils.GenerateRandomName(filterPrefix)
	peerName := utils.GenerateRandomName(peerPrefix)

	// Sweep stale resources from prior runs whose DeferCleanup didn't fire.
	// Without this, random-suffix leftovers accumulate on the cluster forever.
	// Only delete resources older than staleAge so a concurrent run of the
	// same suite against a shared cluster isn't nuked mid-flight.
	const staleAge = 30 * time.Minute
	staleBefore := time.Now().Add(-staleAge)
	if filters, err := lcgc.BGPFilter().List(ctx, options.ListOptions{}); err == nil {
		for _, bf := range filters.Items {
			if strings.HasPrefix(bf.Name, filterPrefix) && bf.CreationTimestamp.Time.Before(staleBefore) {
				_, _ = lcgc.BGPFilter().Delete(ctx, bf.Name, options.DeleteOptions{})
			}
		}
	}
	if peers, err := lcgc.BGPPeers().List(ctx, options.ListOptions{}); err == nil {
		for _, bp := range peers.Items {
			if strings.HasPrefix(bp.Name, peerPrefix) && bp.CreationTimestamp.Time.Before(staleBefore) {
				_, _ = lcgc.BGPPeers().Delete(ctx, bp.Name, options.DeleteOptions{})
			}
		}
	}

	nodeList, err := f.ClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to list nodes")

	// Find the control-plane node and its BGP address from the Calico annotation.
	// Only the master peers with the eBGP peer; "next hop keep" re-advertises
	// iBGP routes with per-node next-hops, so the external peer routes directly
	// to each workload's host.
	var masterName, masterBGPIP string
	for _, node := range nodeList.Items {
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; !ok {
			continue
		}
		addr := node.Annotations["projectcalico.org/IPv4Address"]
		if addr == "" {
			continue
		}
		masterName = node.Name
		ip, _, err := net.ParseCIDR(addr)
		Expect(err).NotTo(HaveOccurred(), "failed to parse master BGP address %q", addr)
		masterBGPIP = ip.String()
		break
	}
	Expect(masterBGPIP).NotTo(BeEmpty(),
		"no control-plane node found with projectcalico.org/IPv4Address annotation")
	logrus.Infof("Master node: %s, BGP IP: %s", masterName, masterBGPIP)

	// Discover the cluster's pod CIDR from the active IPv4 IPPool so the BIRD
	// import filter accepts the right network range.
	podCIDR := discoverPodCIDR(ctx, lcgc)
	logrus.Infof("Discovered pod CIDR for BIRD import filter: %s", podCIDR)

	// Generate BIRD peers config and apply via the transport-specific peer.
	peersConf := bgp.GenerateBIRDPeersConf(podCIDR, []string{masterBGPIP})
	logrus.Infof("Generated BIRD peers config:\n%s", peersConf)
	peer.ConfigureBIRD(peersConf)

	// Create a BGPFilter that tags elevated-priority routes with a BGP community
	// on export to eBGP peers. During KubeVirt live migration, Felix sets
	// krt_metric=512 (ipv4ElevatedRoutePriority) on the target pod's route.
	// The filter matches this priority and adds community 65000:100, which the
	// peer's import filter reads to set a higher BIRD preference. Routes without
	// elevated priority (normal krt_metric=1024) pass through untagged.
	//
	// IMPORTANT: Do NOT add a catch-all Accept rule here. In BIRD 1.x, accept/reject
	// inside a function terminates the entire filter evaluation. A catch-all Accept
	// would bypass calico_export_to_bgp_peers(), exporting ALL routes from the master's
	// BIRD table (including kernel/direct routes) to the peer.
	By("Creating BGPFilter for KubeVirt live migration community tagging")
	community := v3.BGPCommunityValue("65000:100")
	elevatedPriority := elevatedRouteMetric
	bgpFilter := &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: filterName},
		Spec: v3.BGPFilterSpec{
			ExportV4: []v3.BGPFilterRuleV4{
				{
					Action:   v3.Accept,
					PeerType: v3.BGPFilterPeerTypeEBGP,
					Priority: &elevatedPriority,
					Operations: []v3.BGPFilterOperation{
						{AddCommunity: &v3.BGPFilterAddCommunity{Value: &community}},
					},
				},
			},
		},
	}
	_, err = lcgc.BGPFilter().Create(ctx, bgpFilter, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create BGPFilter")
	DeferCleanup(func() {
		By("Deleting BGPFilter " + filterName)
		_, err := lcgc.BGPFilter().Delete(context.Background(), filterName, options.DeleteOptions{})
		if err != nil {
			logrus.WithError(err).Warnf("Failed to delete BGPFilter %s", filterName)
		}
	})

	// Create a BGPPeer so the master node peers with the external BIRD via eBGP.
	// NextHopMode "Keep" preserves the original next-hop from iBGP routes,
	// so the peer gets per-node next-hops and routes directly to the node
	// hosting each workload — no ECMP, no extra hop through the master.
	By("Creating BGPPeer (master only, next-hop-keep, with filter)")
	nextHopKeep := v3.NextHopMode("Keep")
	bgpPeer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: peerName},
		Spec: v3.BGPPeerSpec{
			Node:        masterName,
			PeerIP:      peer.PeerIP(),
			ASNumber:    numorstring.ASNumber(65001),
			NextHopMode: &nextHopKeep,
			Filters:     []string{filterName},
		},
	}
	_, err = lcgc.BGPPeers().Create(ctx, bgpPeer, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create BGPPeer")
	DeferCleanup(func() {
		By("Deleting BGPPeer " + peerName)
		_, err := lcgc.BGPPeers().Delete(context.Background(), peerName, options.DeleteOptions{})
		if err != nil {
			logrus.WithError(err).Warnf("Failed to delete BGPPeer %s", peerName)
		}
	})

	// Keep the BGP mesh enabled — nodes need iBGP for inter-node routing
	// (required for KubeVirt live migration). The eBGP peer is additive: the
	// master advertises routes via eBGP while all nodes continue to exchange
	// routes with each other via the iBGP mesh.

	// Wait for confd on the master to regenerate bird.cfg with the filter.
	By(fmt.Sprintf("Waiting for confd to regenerate bird.cfg with filter %s on master", filterName))
	masterPod := expectMasterCalicoNodePod(f, masterName)
	Eventually(func() error {
		cfg, err := utils.ExecInCalicoNode(masterPod, "cat /etc/calico/confd/config/bird.cfg")
		if err != nil {
			return fmt.Errorf("read bird.cfg: %w", err)
		}
		if !strings.Contains(cfg, filterName) {
			return fmt.Errorf("bird.cfg does not yet reference filter %s", filterName)
		}
		return nil
	}, 30*time.Second, 1*time.Second).Should(Succeed(),
		"confd never regenerated bird.cfg with filter %s", filterName)

	// Dump master BIRD config + routes on failure for diagnostics.
	DeferCleanup(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		logBIRDDiagnostics(masterPod, filterName)
	})

	By("Waiting for eBGP session to establish")
	Eventually(func() error {
		out, err := peer.CheckBGPSession()
		if err != nil {
			return fmt.Errorf("birdcl show protocols: %w", err)
		}
		if !strings.Contains(out, "Established") {
			return fmt.Errorf("BGP session not established:\n%s", out)
		}
		return nil
	}, 2*time.Minute, 5*time.Second).Should(Succeed(),
		"eBGP session not established")
	logrus.Info("eBGP peering established")
}

// setupKubeVirtEBGPPeering configures eBGP peering between a TOR node (via SSH) and
// the cluster's control-plane calico-node. It discovers the TOR's L2TP IP by
// matching against the master's BGP subnet, then delegates to
// setupEBGPPeeringCommon for the shared BGPFilter/BGPPeer/session logic.
func setupKubeVirtEBGPPeering(f *framework.Framework, tor *externalnode.Client) bgp.BIRDPeer {
	GinkgoHelper()
	By("Setting up eBGP peering between TOR and cluster nodes")

	// Discover the TOR's L2TP IP by matching against the master's BGP subnet.
	nodeList, err := f.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to list nodes")
	var masterAddr string
	for _, node := range nodeList.Items {
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; !ok {
			continue
		}
		if addr := node.Annotations["projectcalico.org/IPv4Address"]; addr != "" {
			masterAddr = addr
			break
		}
	}
	Expect(masterAddr).NotTo(BeEmpty(),
		"no control-plane node found with projectcalico.org/IPv4Address annotation")

	_, bgpSubnet, err := net.ParseCIDR(masterAddr)
	Expect(err).NotTo(HaveOccurred(),
		"failed to parse master node BGP address %q", masterAddr)

	torIPs := tor.IPs()
	Expect(torIPs).NotTo(BeEmpty(), "could not discover TOR IPs")
	var torL2tpIP string
	for _, ip := range torIPs {
		if bgpSubnet.Contains(net.ParseIP(ip)) {
			torL2tpIP = ip
			break
		}
	}
	Expect(torL2tpIP).NotTo(BeEmpty(),
		"no TOR IP found in BGP subnet %s (TOR IPs: %v)", bgpSubnet, torIPs)
	logrus.Infof("TOR L2TP IP: %s", torL2tpIP)

	adapter := bgp.NewSSHBIRDPeer(tor, torL2tpIP)
	setupEBGPPeeringCommon(f, adapter, "kubevirt-lm-", "tor-ebgp-peer-")
	return adapter
}

// expectMasterCalicoNodePod polls until the calico-node pod on the
// control-plane node is observable. Returns the pod. Used as a precondition
// for any test step that needs to exec birdcl on the master.
func expectMasterCalicoNodePod(f *framework.Framework, masterName string) *corev1.Pod {
	GinkgoHelper()
	var pod *corev1.Pod
	Eventually(func() error {
		pod = utils.GetCalicoNodePodOnNode(f.ClientSet, masterName)
		if pod == nil {
			return fmt.Errorf("no calico-node pod on master %s", masterName)
		}
		return nil
	}, 30*time.Second, 1*time.Second).Should(Succeed())
	return pod
}

// logBIRDDiagnostics dumps the master's confd-generated BIRD configs and
// runtime state. filterName scopes the bird.cfg sed range. Only call this
// from failure-gated paths.
func logBIRDDiagnostics(masterPod *corev1.Pod, filterName string) {
	type item struct{ label, cmd string }
	items := []item{
		{"bird.cfg (BGPFilter + TOR peer)", fmt.Sprintf("cat /etc/calico/confd/config/bird.cfg | sed -n '/%s/,/^$/p'", filterName)},
		{"bird_ipam.cfg", "cat /etc/calico/confd/config/bird_ipam.cfg"},
		{"bird_aggr.cfg", "cat /etc/calico/confd/config/bird_aggr.cfg"},
		{"birdcl show route", "birdcl show route"},
		{"birdcl show protocols", "birdcl show protocols"},
	}
	for _, it := range items {
		out, _ := utils.ExecInCalicoNode(masterPod, it.cmd)
		logrus.Infof("FAILURE-DEBUG %s:\n%s", it.label, out)
	}
}

// queryWorkerMetric queries the kernel route metric for a /32 VM route on a
// worker node's calico-node pod. Returns the metric value (e.g. 512 for
// elevated, 1024 for normal) or -1 if the route is not found.
// errNoRoute is returned by queryWorkerMetric when no /32 kernel route exists.
var errNoRoute = fmt.Errorf("no /32 kernel route found")

func queryWorkerMetric(f *framework.Framework, nodeName, vmIP string) (int, error) {
	ip := strings.Split(vmIP, "/")[0]
	pod := utils.GetCalicoNodePodOnNode(f.ClientSet, nodeName)
	if pod == nil {
		return -1, fmt.Errorf("no calico-node pod on %s", nodeName)
	}
	out, err := utils.ExecInCalicoNode(pod, fmt.Sprintf("ip route show %s/32", ip))
	if err != nil {
		return -1, fmt.Errorf("ip route show failed on %s: %w", nodeName, err)
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return -1, errNoRoute
	}
	if idx := strings.Index(out, "metric "); idx >= 0 {
		var metric int
		if _, err := fmt.Sscanf(out[idx:], "metric %d", &metric); err != nil {
			return -1, fmt.Errorf("failed to parse metric from %q on %s: %w", out[idx:], nodeName, err)
		}
		logrus.Infof("queryWorkerMetric(%s, %s): metric=%d (route: %s)", nodeName, ip, metric, out)
		return metric, nil
	}
	logrus.Infof("queryWorkerMetric(%s, %s): no metric field (route: %s)", nodeName, ip, out)
	return -1, errNoRoute
}

// expectMigrationStatePopulated polls the VMI for a fully populated
// MigrationState. virt-handler writes it asynchronously after the VMIM phase
// flips, so a bare read can race.
func expectMigrationStatePopulated(ctx context.Context, cli ctrlclient.Client, namespace, vmiName string) *kubevirtv1.VirtualMachineInstance {
	GinkgoHelper()
	vmi := &kubevirtv1.VirtualMachineInstance{}
	Eventually(func(g Gomega) {
		err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: namespace, Name: vmiName}, vmi)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(vmi.Status.MigrationState).NotTo(BeNil(), "VMI MigrationState should be populated")
		g.Expect(vmi.Status.MigrationState.Completed).To(BeTrue(), "MigrationState should be marked completed")
		g.Expect(vmi.Status.MigrationState.TargetPod).NotTo(BeEmpty(), "MigrationState.TargetPod should be set")
		g.Expect(vmi.Status.MigrationState.TargetNode).NotTo(BeEmpty(), "MigrationState.TargetNode should be set")
	}, 30*time.Second, 1*time.Second).Should(Succeed(),
		"timed out waiting for VMI %s/%s MigrationState to be fully populated", namespace, vmiName)
	return vmi
}

// pickThirdWorkerNode returns the name of a schedulable worker node that is
// neither node1 nor node2. Used to pin the second live-migration target via
// VMIM.Spec.AddedNodeSelector so the test exercises a fresh /32 route.
func pickThirdWorkerNode(ctx context.Context, f *framework.Framework, node1, node2 string) string {
	GinkgoHelper()
	nodes, err := f.ClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred(), "list nodes to pick a third worker")
	for _, n := range nodes.Items {
		if _, isControlPlane := n.Labels["node-role.kubernetes.io/control-plane"]; isControlPlane {
			continue
		}
		// Skip infrastructure-pool nodes. They are reported as schedulable by
		// KubeVirt but live-migration to them is unreliable on this cluster
		// layout, and they typically host platform components rather than
		// general workloads.
		if v, ok := n.Labels["cloud.google.com/gke-nodepool"]; ok && v == "infrastructure" {
			continue
		}
		if n.Spec.Unschedulable {
			continue
		}
		if n.Name == node1 || n.Name == node2 {
			continue
		}
		return n.Name
	}
	Fail(fmt.Sprintf("no third worker node found (node1=%s, node2=%s); need at least 3 schedulable workers for the double-migration eBGP test", node1, node2))
	return ""
}

// isMockVirtDeployed returns true if the cluster is running MockVirt (simulated
// KubeVirt). Detection checks the KubeVirt CR's simulationMode field, which the
// MockVirt deploy script patches to true.
func isMockVirtDeployed(f *framework.Framework) bool {
	GinkgoHelper()
	dynClient, err := dynamic.NewForConfig(f.ClientConfig())
	Expect(err).NotTo(HaveOccurred(), "failed to create dynamic client")
	kvResource := schema.GroupVersionResource{
		Group:    "kubevirt.io",
		Version:  "v1",
		Resource: "kubevirts",
	}
	obj, err := dynClient.Resource(kvResource).Namespace("kubevirt").Get(context.Background(), "kubevirt", metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to get KubeVirt CR kubevirt/kubevirt")
	simMode, found, err := unstructured.NestedBool(obj.Object,
		"spec", "configuration", "developerConfiguration", "simulationMode")
	Expect(err).NotTo(HaveOccurred(), "failed to read simulationMode from KubeVirt CR")
	return found && simMode
}

// setupMockVirtEBGPPeering configures eBGP peering between a BIRD container on
// the Docker network and the cluster's control-plane calico-node.
func setupMockVirtEBGPPeering(f *framework.Framework, bird *bgp.ContainerBIRDPeer) {
	GinkgoHelper()
	setupEBGPPeeringCommon(f, bird, "kubevirt-mockvirt-lm-", "mockvirt-ebgp-peer-")
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
