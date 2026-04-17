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
	"encoding/base64"
	"fmt"
	"net"
	"os"
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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	kubevirtv1 "kubevirt.io/api/core/v1"
	kubevirtcorev1 "kubevirt.io/client-go/kubevirt/typed/core/v1"

	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
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
	err := v.kvClient.VirtualMachines(v.namespace).Delete(context.Background(), v.name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
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

// WaitForRunningWithIP polls the VMI until it reaches Running phase and has an IP
// address assigned. Returns the IP and the node where the VMI is scheduled.
func (v *testVM) WaitForRunningWithIP(ctx context.Context) (ip, node string) {
	By(fmt.Sprintf("Waiting for VMI %s to be Running with IP", v.name))
	Eventually(func() error {
		vmi, err := v.kvClient.VirtualMachineInstances(v.namespace).Get(ctx, v.name, metav1.GetOptions{})
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

// FindVirtLauncherPod finds the running virt-launcher pod for this VM by label selector.
// Returns the first Running pod that is not being deleted, or an error if none found.
func (v *testVM) FindVirtLauncherPod(ctx context.Context, f *framework.Framework) (*corev1.Pod, error) {
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

// testVMIM encapsulates a KubeVirt VirtualMachineInstanceMigration for e2e tests.
type testVMIM struct {
	name      string
	namespace string
	vmiName   string
	kvClient  kubevirtcorev1.KubevirtV1Interface
}

// Create creates the VMIM resource to trigger a live migration.
func (m *testVMIM) Create(ctx context.Context) {
	By(fmt.Sprintf("Creating migration %s", m.name))
	vmim := &kubevirtv1.VirtualMachineInstanceMigration{
		ObjectMeta: metav1.ObjectMeta{Name: m.name, Namespace: m.namespace},
		Spec:       kubevirtv1.VirtualMachineInstanceMigrationSpec{VMIName: m.vmiName},
	}
	_, err := m.kvClient.VirtualMachineInstanceMigrations(m.namespace).Create(ctx, vmim, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

// Delete removes the VMIM resource from the cluster.
func (m *testVMIM) Delete() {
	err := m.kvClient.VirtualMachineInstanceMigrations(m.namespace).Delete(context.Background(), m.name, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}

// WaitForSuccess polls the VMIM until it reaches MigrationSucceeded phase.
// Immediately stops polling with a fatal error if MigrationFailed is observed.
func (m *testVMIM) WaitForSuccess(ctx context.Context) {
	By(fmt.Sprintf("Waiting for migration %s to succeed", m.name))
	Eventually(func() error {
		vmim, err := m.kvClient.VirtualMachineInstanceMigrations(m.namespace).Get(ctx, m.name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if vmim.Status.Phase == kubevirtv1.MigrationFailed {
			logrus.Warnf("Migration %s FAILED. Conditions: %+v", m.name, vmim.Status.Conditions)
			// Check VMI for migration state details.
			vmi, vmiErr := m.kvClient.VirtualMachineInstances(m.namespace).Get(ctx, m.vmiName, metav1.GetOptions{})
			if vmiErr == nil && vmi.Status.MigrationState != nil {
				ms := vmi.Status.MigrationState
				logrus.Warnf("VMI MigrationState: Completed=%v Failed=%v FailureReason=%s StartTimestamp=%v EndTimestamp=%v",
					ms.Completed, ms.Failed, ms.FailureReason, ms.StartTimestamp, ms.EndTimestamp)
			}
			return StopTrying("migration failed")
		}
		if vmim.Status.Phase != kubevirtv1.MigrationSucceeded {
			return fmt.Errorf("phase is %s", vmim.Status.Phase)
		}
		return nil
	}, 5*time.Minute, 5*time.Second).Should(Succeed())
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

// checkConnectionToTCPServer verifies that the client pod can connect to the VM's TCP
// server on port 9999 and receive at least one "seq=" line. Retries for up to 2 minutes
// to accommodate slow-booting VMs where the TCP server may not yet be listening.
func checkConnectionToTCPServer(ns, podName, vmIP string) {
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

// tcpStreamLineCount returns the number of lines in the given file inside the given pod.
// Uses `wc -l < <file>` so the output is a bare integer (no filename suffix) and returns
// a descriptive error if the kubectl exec fails or the output cannot be parsed.
func tcpStreamLineCount(ns, podName, streamFile string) (int, error) {
	output, err := kubectl.NewKubectlCommand(ns, "exec", podName, "--",
		"sh", "-c", fmt.Sprintf("wc -l < %s", streamFile)).Exec()
	if err != nil {
		return 0, fmt.Errorf("wc -l on %s/%s:%s failed: %w (output=%q)",
			ns, podName, streamFile, err, output)
	}
	var n int
	if _, scanErr := fmt.Sscanf(strings.TrimSpace(output), "%d", &n); scanErr != nil {
		return 0, fmt.Errorf("failed to parse wc -l output %q: %w", output, scanErr)
	}
	return n, nil
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

// runOnTOR executes a shell command on the external TOR node via SSH and returns stdout.
// Logs a warning on error but does not fail the test — use this for fire-and-forget
// commands (process spawn, cleanup). For commands whose result drives an assertion, use
// runOnTORE so SSH failures are surfaced rather than silently producing an empty string.
func runOnTOR(tor *externalnode.Client, cmd string) string {
	output, err := tor.Exec("sh", "-c", cmd)
	if err != nil {
		logrus.Warnf("TOR command failed: %s: %v", cmd, err)
	}
	return output
}

// runOnTORE executes a shell command on the TOR and returns stdout plus any SSH error.
// Use this when the command's result drives a test assertion; an SSH/transport failure
// must not be silently parsed as an empty result.
func runOnTORE(tor *externalnode.Client, cmd string) (string, error) {
	out, err := tor.Exec("sh", "-c", cmd)
	if err != nil {
		return out, fmt.Errorf("TOR cmd %q failed: %w (output=%q)", cmd, err, out)
	}
	return out, nil
}

// torStreamLineCount returns the number of lines in the given file on the TOR node.
// Mirrors tcpStreamLineCount but executes via SSH on the external TOR. Surfaces SSH
// errors and parse errors with full context.
func torStreamLineCount(tor *externalnode.Client, file string) (int, error) {
	out, err := runOnTORE(tor, fmt.Sprintf("wc -l < %s", file))
	if err != nil {
		return 0, err
	}
	var n int
	if _, scanErr := fmt.Sscanf(strings.TrimSpace(out), "%d", &n); scanErr != nil {
		return 0, fmt.Errorf("failed to parse wc -l output %q: %w", out, scanErr)
	}
	return n, nil
}

// torContainerLineCount counts lines in a Docker container's stdout logs on the TOR.
func torContainerLineCount(tor *externalnode.Client, container string) (int, error) {
	out, err := runOnTORE(tor, fmt.Sprintf("sudo docker logs %s 2>/dev/null | wc -l", container))
	if err != nil {
		return 0, err
	}
	var n int
	if _, scanErr := fmt.Sscanf(strings.TrimSpace(out), "%d", &n); scanErr != nil {
		return 0, fmt.Errorf("failed to parse docker logs line count %q: %w", out, scanErr)
	}
	return n, nil
}

// pauseForDebug checks for the existence of a "pause-for-debug" namespace and
// waits in a loop if it exists, allowing developers to pause test execution for
// debugging. To pause: kubectl create ns pause-for-debug
// To resume: kubectl delete ns pause-for-debug
func pauseForDebug(f *framework.Framework) {
	const ns = "pause-for-debug"
	maxWait := 1 * time.Hour
	start := time.Now()
	for {
		_, err := f.ClientSet.CoreV1().Namespaces().Get(context.Background(), ns, metav1.GetOptions{})
		if err != nil {
			logrus.Infof("pauseForDebug: namespace %q does not exist, continuing.", ns)
			return
		}
		if time.Since(start) >= maxWait {
			logrus.Infof("pauseForDebug: timeout after 1 hour, continuing.")
			return
		}
		logrus.Infof("pauseForDebug: namespace %q exists, paused for debugging. Elapsed: %v", ns, time.Since(start))
		time.Sleep(30 * time.Second)
	}
}

// generateTORBirdPeersConf returns a BIRD 1.x peers config for the TOR node.
// This is written to /etc/bird/peers.conf inside the calico/bird container,
// which already provides the base config (router id, protocol kernel/device).
// The TOR acts as an eBGP hub (AS 65001) peering with all cluster nodes (AS 64512).
// Uses ip@local as a placeholder replaced with the actual TOR IP at runtime.
func generateTORBirdPeersConf(nodeIPs []string) string {
	var sb strings.Builder
	sb.WriteString(`template bgp bgp_template {
  debug { states };
  description "BGP peer";
  local as 65001;
  multihop;
  gateway recursive;
  import all;
  export all;
  source address ip@local;
  add paths on;
  graceful restart;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
}

`)
	for i, nodeIP := range nodeIPs {
		sb.WriteString(fmt.Sprintf(`protocol bgp node_%d from bgp_template {
  neighbor %s as 64512;
  passive on;
}

`, i, nodeIP))
	}
	return sb.String()
}

// startBirdOnTOR starts a calico/bird container on the TOR node with host networking,
// injects the peer config, and reloads BIRD. Follows the same pattern as
// node/tests/k8st/utils/utils.py:start_external_node_with_bgp.
func startBirdOnTOR(tor *externalnode.Client, torIP string, peersConf string) {
	By("Starting BIRD container on TOR")

	// Remove any prior container.
	runOnTOR(tor, "sudo docker rm -f tor-bird 2>/dev/null || true")

	// Start the container with host networking. The calico/bird image ships with
	// a base bird.conf that defines router id, protocol kernel, and protocol device.
	runOnTOR(tor, "sudo docker run -d --privileged --name tor-bird --network host "+
		"calico/bird:v0.3.3-211-g9111ec3c")

	// Wait for the container to be running.
	Eventually(func() string {
		return runOnTOR(tor, "sudo docker ps --filter name=tor-bird --filter status=running -q")
	}, 30*time.Second, 2*time.Second).ShouldNot(BeEmpty(), "tor-bird container is not running")
	logrus.Info("BIRD container started on TOR")

	// Add "merge paths on" to the kernel protocol block for ECMP support.
	runOnTOR(tor, `sudo docker exec tor-bird sed -i '/protocol kernel {/a merge paths on;' /etc/bird.conf`)

	// Write the peers config, replacing ip@local with the actual TOR IP.
	peersConf = strings.ReplaceAll(peersConf, "ip@local", torIP)

	// Base64-encode locally in Go to avoid SSH quoting issues with
	// multi-line config content containing special characters.
	encoded := base64.StdEncoding.EncodeToString([]byte(peersConf))
	runOnTOR(tor, fmt.Sprintf("echo %s | base64 -d | sudo docker exec -i tor-bird tee /etc/bird/peers.conf > /dev/null", encoded))

	// Reload BIRD to pick up the new peers config.
	By("Reloading BIRD config on TOR")
	out := runOnTOR(tor, "sudo docker exec tor-bird birdcl configure")
	logrus.Infof("birdcl configure: %s", out)
}

// stopBirdOnTOR removes the BIRD container from the TOR node.
func stopBirdOnTOR(tor *externalnode.Client) {
	By("Stopping BIRD on TOR")
	runOnTOR(tor, "sudo docker rm -f tor-bird 2>/dev/null || true")
}

// setupEBGPPeering configures eBGP peering between a TOR node and all cluster nodes.
// It starts a BIRD daemon on the TOR, disables the BGP full mesh, and creates a global
// BGPPeer resource pointing all nodes at the TOR. All resources are cleaned up via
// DeferCleanup when the test completes.
func setupEBGPPeering(f *framework.Framework, tor *externalnode.Client) {
	By("Setting up eBGP peering between TOR and cluster nodes")

	// Use the libcalico-go client for Calico resources (BGPPeer, BGPConfiguration).
	// The controller-runtime client fails resource discovery when the Calico API
	// server aggregated endpoint (projectcalico.org/v3) is registered but not running.
	lcgc := newLibcalicoClient(f)
	ctx := context.Background()

	// Collect node BGP IPs from the projectcalico.org/IPv4Address annotation.
	nodeList, err := f.ClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to list nodes")

	bgpSubnet := &net.IPNet{
		IP:   net.ParseIP("172.16.8.0"),
		Mask: net.CIDRMask(24, 32),
	}

	// Find the master (control-plane) node and its BGP IP. Only the master
	// will peer with the TOR — it re-advertises all iBGP-learned routes with
	// "next hop keep", so the TOR gets the correct per-node next-hop and can
	// route directly to the node hosting each workload.
	var masterName, masterBGPIP string
	for _, node := range nodeList.Items {
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; !ok {
			continue
		}
		addr := node.Annotations["projectcalico.org/IPv4Address"]
		if addr == "" {
			continue
		}
		ip := strings.Split(addr, "/")[0]
		if bgpSubnet.Contains(net.ParseIP(ip)) {
			masterName = node.Name
			masterBGPIP = ip
			break
		}
	}
	Expect(masterBGPIP).NotTo(BeEmpty(),
		"no control-plane node found with BGP IP in 172.16.8.0/24 subnet")
	logrus.Infof("Master node: %s, BGP IP: %s", masterName, masterBGPIP)

	// Find the TOR's L2TP IP by matching against the BGP subnet.
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
		"no TOR IP found in 172.16.8.0/24 subnet (TOR IPs: %v)", torIPs)
	logrus.Infof("TOR L2TP IP: %s", torL2tpIP)

	// Generate peers config with only the master as peer and start BIRD on the TOR.
	peersConf := generateTORBirdPeersConf([]string{masterBGPIP})
	logrus.Infof("Generated BIRD peers config:\n%s", peersConf)
	startBirdOnTOR(tor, torL2tpIP, peersConf)
	DeferCleanup(func() { stopBirdOnTOR(tor) })

	// Create a BGPPeer so the master node peers with the TOR via eBGP.
	// NextHopMode "Keep" preserves the original next-hop from iBGP routes,
	// so the TOR gets per-node next-hops and routes directly to the node
	// hosting each workload — no ECMP, no extra hop through the master.
	By("Creating BGPPeer for TOR (master only, next-hop-keep)")
	nextHopKeep := v3.NextHopMode("Keep")
	bgpPeer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "tor-ebgp-peer"},
		Spec: v3.BGPPeerSpec{
			Node:        masterName,
			PeerIP:      torL2tpIP,
			ASNumber:    numorstring.ASNumber(65001),
			NextHopMode: &nextHopKeep,
		},
	}
	_, err = lcgc.BGPPeers().Create(ctx, bgpPeer, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create BGPPeer")
	DeferCleanup(func() {
		By("Deleting BGPPeer for TOR")
		_, err := lcgc.BGPPeers().Delete(context.Background(), "tor-ebgp-peer", options.DeleteOptions{})
		if err != nil {
			logrus.WithError(err).Warn("Failed to delete BGPPeer tor-ebgp-peer")
		}
	})

	// Keep the BGP mesh enabled — nodes need iBGP for inter-node routing
	// (required for KubeVirt live migration). The eBGP peer to the TOR is
	// additive: the master advertises routes to the TOR via eBGP while all
	// nodes continue to exchange routes with each other via the iBGP mesh.

	// Wait for the eBGP session to establish on the TOR.
	By("Waiting for eBGP session to establish")
	Eventually(func() error {
		out := runOnTOR(tor, "sudo docker exec tor-bird birdcl show protocols")
		logrus.Infof("birdcl show protocols:\n%s", out)
		if !strings.Contains(out, "Established") {
			return fmt.Errorf("BGP session not established:\n%s", out)
		}
		return nil
	}, 2*time.Minute, 5*time.Second).Should(Succeed(),
		"eBGP session not established on TOR")
	logrus.Info("eBGP peering established on TOR")

	// Log the routes the TOR learned via eBGP for debugging.
	routes := runOnTOR(tor, "sudo docker exec tor-bird birdcl show route")
	logrus.Infof("TOR BIRD routes after eBGP establishment:\n%s", routes)
	kernRoutes := runOnTOR(tor, "ip route show proto bird")
	logrus.Infof("TOR kernel routes (proto bird):\n%s", kernRoutes)
}

// startRouteMonitor polls TOR kernel routes for a VM IP and logs changes.
// It monitors both the /32 host route (advertised during migration for the
// specific VM) and the /26 block route (the steady-state subnet route),
// clearly showing how routes transition during live migration.
// Call the returned stop function to terminate the monitor goroutine.
func startRouteMonitor(tor *externalnode.Client, vmIP string) func() {
	ip := strings.Split(vmIP, "/")[0]

	// Determine the /26 block that contains this IP. Calico allocates /26 blocks
	// by default, so mask the IP to find the block prefix.
	parsed := net.ParseIP(ip).To4()
	blockIP := net.IPv4(parsed[0], parsed[1], parsed[2], parsed[3]&0xC0)
	block26 := fmt.Sprintf("%s/26", blockIP)

	logrus.Infof("Route monitor: tracking /32=%s and /26=%s", ip, block26)

	stopCh := make(chan struct{})
	go func() {
		var lastRoutes string
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			// Query both the /32 host route and /26 block route separately
			// so we can see which one exists and how they change.
			out, _ := runOnTORE(tor, fmt.Sprintf(
				"echo '--- /32 route ---'; ip route show proto bird %s/32 2>&1; "+
					"echo '--- /26 route ---'; ip route show proto bird %s 2>&1; "+
					"echo '--- route lookup ---'; ip route get %s 2>&1",
				ip, block26, ip))
			out = strings.TrimSpace(out)
			if out != lastRoutes {
				logrus.Infof("TOR route change:\n%s", out)
				lastRoutes = out
			}
			time.Sleep(1 * time.Second)
		}
	}()
	return func() { close(stopCh) }
}

func ptrInt64(v int64) *int64 { return &v }
