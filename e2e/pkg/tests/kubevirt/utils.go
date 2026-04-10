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

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
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

// getRouteOnNode runs "ip route show <ip>" inside the calico-node pod on the given node
// and returns the output. Used to verify that Felix programs/removes local routes for
// the VM's /32 during migration.
func getRouteOnNode(f *framework.Framework, nodeName, ip string) string {
	calicoNodePod := utils.GetCalicoNodePodOnNode(f.ClientSet, nodeName)
	if calicoNodePod == nil {
		logrus.Warnf("No calico-node pod found on node %s", nodeName)
		return ""
	}
	output, err := utils.ExecInCalicoNode(calicoNodePod, fmt.Sprintf("ip route show %s", ip))
	if err != nil {
		logrus.Warnf("Failed to get route on node %s: %v", nodeName, err)
		return ""
	}
	return strings.TrimSpace(output)
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
// of the given IP address. Returns nil maps if the IP is not allocated or on error.
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
// Increased timeout to 5s for nc, and 2 minutes overall for slow-booting VMs.
func waitForTCPServer(ns, podName, vmIP string) {
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

// countSequenceGaps parses "seq=N" lines and counts gaps in the sequence.
func countSequenceGaps(lines []string) (gaps, lastSeq int) {
	first := true
	for _, line := range lines {
		var seq int
		if _, scanErr := fmt.Sscanf(line, "seq=%d", &seq); scanErr == nil {
			if !first && seq != lastSeq+1 {
				gaps++
				logrus.Infof("Sequence gap: %d -> %d", lastSeq, seq)
			}
			first = false
			lastSeq = seq
		}
	}
	return
}

// runOnTOR executes a shell command on the external TOR node via SSH and returns stdout.
// Logs a warning on error but does not fail the test — callers decide how to handle errors.
func runOnTOR(tor *externalnode.Client, cmd string) string {
	output, err := tor.Exec("sh", "-c", cmd)
	if err != nil {
		logrus.Warnf("TOR command failed: %s: %v", cmd, err)
	}
	return output
}

func ptrInt64(v int64) *int64 { return &v }
