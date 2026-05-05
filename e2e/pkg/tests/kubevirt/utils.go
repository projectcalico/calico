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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/utils"
	e2eclient "github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const (
	// testTimeout is the per-test context timeout. Tightened from 10m: even
	// the longest test (eBGP double-migration) finishes in ~5m on healthy
	// clusters; a generous 6m budget catches genuine hangs without dragging
	// out CI when something else has gone wrong.
	testTimeout = 6 * time.Minute
)

// defaultCloudInit configures the VM's default user with a known password and
// enables SSH password auth so test debuggers can console in.
const defaultCloudInit = "#cloud-config\npassword: testpass\nchpasswd: { expire: False }\nssh_pwauth: True\n"

// tcpServerCloudInit configures the VM with the default debug user (see
// defaultCloudInit) and additionally writes /usr/local/bin/tcp-server.py — a
// small Python TCP echo server that accepts connections on port 9999 and
// streams "seq=N\n" lines once per second per client. The runcmd backgrounds
// the server with nohup so it survives the cloud-init shell exiting.
//
// The seq=N stream is used by the live-migration tests as a tripwire for TCP
// connection continuity across migrations — gaps in the sequence number prove
// the connection was reset rather than seamlessly handed over.
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
	name      string
	namespace string
	cloudInit string
	labels    map[string]string // extra labels propagated to virt-launcher pod
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
					Annotations: map[string]string{"kubevirt.io/allow-pod-bridge-network-live-migration": "true"},
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
					TerminationGracePeriodSeconds: ptrInt64(30),
					Volumes: []kubevirtv1.Volume{
						{Name: "containerdisk", VolumeSource: kubevirtv1.VolumeSource{ContainerDisk: &kubevirtv1.ContainerDiskSource{Image: images.KubeVirtUbuntu}}},
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

// setupPingPod creates a long-running pod for connectivity checks (ping, nc)
// via the shared conncheck builder. Conncheck handles pod creation, readiness,
// and cleanup; the test code just needs the underlying *v1.Pod for kubectl
// exec calls.
func setupPingPod(f *framework.Framework) *corev1.Pod {
	By("Creating a ping pod for connectivity checks")
	tester := conncheck.NewConnectionTester(f)
	DeferCleanup(tester.Stop)
	client := conncheck.NewClient("ping-test", f.Namespace)
	tester.AddClient(client)
	tester.Deploy()
	return client.Pod()
}

// setupAntiAffinityPod creates a long-running pod scheduled away from the
// given node, used for TCP tests where the client must be on a different node
// than the server VM to exercise cross-node BGP routing.
func setupAntiAffinityPod(ctx context.Context, f *framework.Framework, avoidNode string) *corev1.Pod {
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
	return pod
}

// newVMIMigration returns a KubeVirt VirtualMachineInstanceMigration object
// that triggers a live migration of vmiName when applied. The returned
// pointer is intended to be passed straight to the typed-client Create call:
//
//	vmim := newVMIMigration("my-vm-migration1", ns, "my-vm")
//	Expect(cli.Create(ctx, vmim)).To(Succeed())
//
// Keeping the spec a plain object (rather than wrapping it in a builder type
// that owns a client) keeps the VM-as-data and the API client as distinct
// concepts, in line with how the kubeVirtVM type is structured.
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

// waitForMigrationSuccess polls the VMIM until it reaches MigrationSucceeded
// phase. Immediately stops polling with a fatal error if MigrationFailed is
// observed.
func waitForMigrationSuccess(ctx context.Context, cli ctrlclient.Client, vmim *kubevirtv1.VirtualMachineInstanceMigration) {
	By(fmt.Sprintf("Waiting for migration %s to succeed", vmim.Name))
	Eventually(func() error {
		got := &kubevirtv1.VirtualMachineInstanceMigration{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Namespace: vmim.Namespace, Name: vmim.Name}, got); err != nil {
			return err
		}
		if got.Status.Phase == kubevirtv1.MigrationFailed {
			logrus.Warnf("Migration %s FAILED. Conditions: %+v", vmim.Name, got.Status.Conditions)
			// Check VMI for migration state details.
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

// expectPingSuccess verifies ICMP connectivity from a pod to the target IP.
// Retries for up to 60s — generous compared with steady-state ping but tight
// enough to catch routing breakage. After live-migration we expect route
// convergence in a few seconds (BIRD reload, kernel route swap); 60s catches
// genuine wedges without dragging out a failing test for 3 minutes.
func expectPingSuccess(ns, podName, targetIP string) {
	GinkgoHelper()
	Eventually(func() error {
		output, err := kubectl.NewKubectlCommand(ns, "exec", podName, "--",
			"ping", "-c", "3", "-W", "2", targetIP).Exec()
		if err != nil {
			return fmt.Errorf("ping failed: %v, output: %s", err, output)
		}
		return nil
	}, 60*time.Second, 5*time.Second).Should(Succeed(), "failed to ping %s", targetIP)
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

// expectConnectionToTCPServer verifies that the client pod can connect to the VM's TCP
// server on port 9999 and receive at least one "seq=" line. Retries for up to 2 minutes
// to accommodate slow-booting VMs where the TCP server may not yet be listening.
//
// The kubectl exec error is intentionally ignored: `timeout 5 nc` always exits
// 143 (SIGTERM from `timeout`) once the budget elapses, even when the
// connection succeeded and stdout contains the expected seq= lines. Checking
// stdout is the only honest signal here.
func expectConnectionToTCPServer(ns, podName, vmIP string) {
	GinkgoHelper()
	By(fmt.Sprintf("Waiting for TCP server on %s:9999", vmIP))
	Eventually(func() error {
		output, _ := kubectl.NewKubectlCommand(ns, "exec", podName, "--",
			"sh", "-c", fmt.Sprintf("timeout 5 nc %s 9999", vmIP)).Exec()
		if !strings.Contains(output, "seq=") {
			return fmt.Errorf("TCP server not ready (no seq= in output)")
		}
		return nil
	}, 2*time.Minute, 5*time.Second).Should(Succeed(), "TCP server not ready on VM %s", vmIP)
	logrus.Infof("TCP server ready on %s:9999", vmIP)
}

// expectTCPConnectionBlocked verifies that the client pod cannot connect to the VM's TCP
// server on port 9999. Uses Consistently to confirm that nc never receives "seq=" data
// over the check window, indicating the connection is blocked by network policy.
func expectTCPConnectionBlocked(ns, podName, vmIP string) {
	GinkgoHelper()
	By(fmt.Sprintf("Verifying TCP connection to %s:9999 is blocked from %s", vmIP, podName))
	Consistently(func() error {
		output, _ := kubectl.NewKubectlCommand(ns, "exec", podName, "--",
			"sh", "-c", fmt.Sprintf("timeout 3 nc %s 9999 2>&1", vmIP)).Exec()
		if strings.Contains(output, "seq=") {
			return fmt.Errorf("connection succeeded unexpectedly")
		}
		return nil
	}, 10*time.Second, 2*time.Second).Should(Succeed(),
		"TCP connection to %s:9999 should be blocked by policy", vmIP)
}

// lineCount runs the supplied exec closure (which must produce a bare integer
// — typically `wc -l < <file>`) and parses the result. Centralises the parse
// and error-wrapping logic so the three *LineCount helpers below stay one-liners.
func lineCount(label string, exec func() (string, error)) (int, error) {
	output, err := exec()
	if err != nil {
		return 0, fmt.Errorf("%s line-count exec failed: %w (output=%q)", label, err, output)
	}
	var n int
	if _, scanErr := fmt.Sscanf(strings.TrimSpace(output), "%d", &n); scanErr != nil {
		return 0, fmt.Errorf("%s: failed to parse line-count output %q: %w", label, output, scanErr)
	}
	return n, nil
}

// tcpStreamLineCount returns the number of lines in the given file inside the
// given pod.
func tcpStreamLineCount(ns, podName, streamFile string) (int, error) {
	return lineCount(fmt.Sprintf("%s/%s:%s", ns, podName, streamFile), func() (string, error) {
		return kubectl.NewKubectlCommand(ns, "exec", podName, "--",
			"sh", "-c", fmt.Sprintf("wc -l < %s", streamFile)).Exec()
	})
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

// runOnTOR executes a shell command on the external TOR node via SSH and
// returns stdout plus any SSH/transport error wrapped with context. Callers
// who genuinely want to ignore failures (cleanup, fire-and-forget) can drop
// the error explicitly with `_, _ = runOnTOR(...)` — there is no longer a
// silent-failure variant that returns "" on error.
func runOnTOR(tor *externalnode.Client, cmd string) (string, error) {
	out, err := tor.Exec("sh", "-c", cmd)
	if err != nil {
		return out, fmt.Errorf("TOR cmd %q failed: %w (output=%q)", cmd, err, out)
	}
	return out, nil
}

// torStreamLineCount returns the number of lines in the given file on the TOR node.
// Mirrors tcpStreamLineCount but executes via SSH on the external TOR.
func torStreamLineCount(tor *externalnode.Client, file string) (int, error) {
	return lineCount(fmt.Sprintf("tor:%s", file), func() (string, error) {
		return runOnTOR(tor, fmt.Sprintf("wc -l < %s", file))
	})
}

// torContainerLineCount counts lines in a Docker container's stdout logs on the TOR.
func torContainerLineCount(tor *externalnode.Client, container string) (int, error) {
	return lineCount(fmt.Sprintf("tor:docker logs %s", container), func() (string, error) {
		return runOnTOR(tor, fmt.Sprintf("sudo docker logs %s 2>/dev/null | wc -l", container))
	})
}

// torBirdHeaderTemplate is the static header of the TOR BIRD peers config
// (filters + bgp template). The %s placeholder takes the cluster's pod CIDR
// at render time, discovered from the active IPv4 IPPool — this avoids the
// previous hardcoded `192.168.0.0/16` silently rejecting routes on clusters
// with a different IPPool layout.
//
// The import filter follows Calico's confd-generated BIRD config: community
// match → bgp_local_pref, then bgp_local_pref check → preference = 200,
// mirroring confd/tests/compiled_templates/bgpfilter/communities_and_operations/bird.cfg.
const torBirdHeaderTemplate = `function import_community_lp() {
  if ((65000, 100) ~ bgp_community) then { bgp_local_pref = 2147483135; accept; }
  accept;
}

filter import_community_priority {
  # Only accept routes within the pod CIDR. Reject kernel/direct routes
  # (0.0.0.0/0, 10.x, 169.254.x, 172.16.x) that would break TOR routing.
  if (net !~ %s) then reject;

  import_community_lp();
  if (defined(bgp_local_pref)&&(bgp_local_pref > 2147482623)) then
    preference = 200;
  accept;
}

template bgp bgp_template {
  debug { states };
  description "BGP peer";
  local as 65001;
  multihop;
  gateway recursive;
  import filter import_community_priority;
  export none;
  source address ip@local;
  add paths on;
  graceful restart;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
}

`

// torBirdPeerTemplate is the per-peer block format. Args: index, peer IP.
const torBirdPeerTemplate = `protocol bgp node_%d from bgp_template {
  neighbor %s as 64512;
  passive on;
}

`

// generateTORBirdPeersConf returns a BIRD 1.x peers config for the TOR node.
// The podCIDR (e.g. "192.168.0.0/16") gates the import filter so only routes
// within the pod network are accepted; pass the cluster's actual IPv4 IPPool
// CIDR rather than a hardcoded literal.
func generateTORBirdPeersConf(podCIDR string, nodeIPs []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, torBirdHeaderTemplate, podCIDR)
	for i, nodeIP := range nodeIPs {
		sb.WriteString(fmt.Sprintf(torBirdPeerTemplate, i, nodeIP))
	}
	return sb.String()
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

// startBirdOnTOR starts a calico/bird container on the TOR node with host networking,
// injects the peer config, and reloads BIRD. Follows the same pattern as
// node/tests/k8st/utils/utils.py:start_external_node_with_bgp.
func startBirdOnTOR(tor *externalnode.Client, torIP string, peersConf string) {
	By("Starting BIRD container on TOR")

	// Remove any prior container — best effort.
	_, _ = runOnTOR(tor, "sudo docker rm -f tor-bird 2>/dev/null")

	// Start the container with host networking. The calico/bird image ships with
	// a base bird.conf that defines router id, protocol kernel, and protocol device.
	_, err := runOnTOR(tor, "sudo docker run -d --privileged --name tor-bird --network host "+images.CalicoBIRD)
	Expect(err).NotTo(HaveOccurred(), "failed to start BIRD container on TOR")
	// Register cleanup before the readiness wait below — if that wait
	// panics, we still need to remove the container we just created.
	DeferCleanup(func() { stopBirdOnTOR(tor) })

	// Wait for the container to be running.
	Eventually(func() string {
		out, _ := runOnTOR(tor, "sudo docker ps --filter name=tor-bird --filter status=running -q")
		return out
	}, 30*time.Second, 2*time.Second).ShouldNot(BeEmpty(), "tor-bird container is not running")
	logrus.Info("BIRD container started on TOR")

	// Add "merge paths on" to the kernel protocol block for ECMP support.
	// With different BIRD preferences (200 for community-tagged, 100 for default),
	// merge paths only merges routes of equal preference, so the higher-preference
	// route wins during migration.
	_, err = runOnTOR(tor, `sudo docker exec tor-bird sed -i '/protocol kernel {/a merge paths on;' /etc/bird.conf`)
	Expect(err).NotTo(HaveOccurred(), "failed to enable merge paths in tor-bird")

	// Write the peers config, replacing ip@local with the actual TOR IP.
	peersConf = strings.ReplaceAll(peersConf, "ip@local", torIP)

	// Base64-encode locally in Go to avoid SSH quoting issues with
	// multi-line config content containing special characters.
	encoded := base64.StdEncoding.EncodeToString([]byte(peersConf))
	_, err = runOnTOR(tor, fmt.Sprintf("echo %s | base64 -d | sudo docker exec -i tor-bird tee /etc/bird/peers.conf > /dev/null", encoded))
	Expect(err).NotTo(HaveOccurred(), "failed to write BIRD peers config to TOR")

	// Reload BIRD to pick up the new peers config.
	By("Reloading BIRD config on TOR")
	out, err := runOnTOR(tor, "sudo docker exec tor-bird birdcl configure")
	Expect(err).NotTo(HaveOccurred(), "birdcl configure failed: %s", out)
	logrus.Infof("birdcl configure: %s", out)
}

// stopBirdOnTOR removes the BIRD container from the TOR node.
func stopBirdOnTOR(tor *externalnode.Client) {
	By("Stopping BIRD on TOR")
	_, _ = runOnTOR(tor, "sudo docker rm -f tor-bird 2>/dev/null")
}

// startTCPClientOnTOR starts a long-running nc TCP client container on the
// external TOR node, waits for it to be Running, and registers a DeferCleanup
// to remove it. Used by the eBGP live-migration test to keep an open TCP
// stream from the TOR through cluster routing while the VM migrates.
func startTCPClientOnTOR(tor *externalnode.Client, name, vmIP string) {
	GinkgoHelper()
	By(fmt.Sprintf("Starting TCP client container %s on TOR connecting to %s", name, vmIP))
	_, _ = runOnTOR(tor, fmt.Sprintf("sudo docker rm -f %s 2>/dev/null", name))
	_, err := runOnTOR(tor, fmt.Sprintf(
		"sudo docker run -d --name %s --network host alpine sh -c 'sleep 999999 | nc %s 9999'",
		name, vmIP))
	Expect(err).NotTo(HaveOccurred(), "failed to start TCP client container on TOR")
	DeferCleanup(func() {
		By(fmt.Sprintf("Removing TCP client container %s from TOR", name))
		_, _ = runOnTOR(tor, fmt.Sprintf("sudo docker rm -f %s 2>/dev/null", name))
	})

	Eventually(func() error {
		out, _ := runOnTOR(tor, fmt.Sprintf("sudo docker inspect -f '{{.State.Running}}' %s 2>&1", name))
		if strings.TrimSpace(out) != "true" {
			return fmt.Errorf("container %s not running (state=%q)", name, out)
		}
		return nil
	}, 15*time.Second, 1*time.Second).Should(Succeed(), "TCP client container did not start on TOR")
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

	// Discover the cluster's pod CIDR from the active IPv4 IPPool so the BIRD
	// import filter accepts the right network range. Hardcoding 192.168.0.0/16
	// silently rejected pod routes on any cluster with a different layout.
	podCIDR := discoverPodCIDR(ctx, lcgc)
	logrus.Infof("Discovered pod CIDR for BIRD import filter: %s", podCIDR)

	// Generate peers config with only the master as peer and start BIRD on the TOR.
	// startBirdOnTOR registers its own DeferCleanup to remove the tor-bird
	// container, so we don't need a second registration here.
	peersConf := generateTORBirdPeersConf(podCIDR, []string{masterBGPIP})
	logrus.Infof("Generated BIRD peers config:\n%s", peersConf)
	startBirdOnTOR(tor, torL2tpIP, peersConf)

	// Create a BGPFilter that tags elevated-priority routes with a BGP community
	// on export to eBGP peers. During KubeVirt live migration, Felix sets
	// krt_metric=512 (ipv4ElevatedRoutePriority) on the target pod's route.
	// The filter matches this priority and adds community 65000:100, which the
	// TOR's import filter reads to set a higher BIRD preference. Routes without
	// elevated priority (normal krt_metric=1024) pass through untagged.
	//
	// IMPORTANT: Do NOT add a catch-all Accept rule here. In BIRD 1.x, accept/reject
	// inside a function terminates the entire filter evaluation. A catch-all Accept
	// would bypass calico_export_to_bgp_peers(), exporting ALL routes from the master's
	// BIRD table (including kernel/direct routes) to the TOR, breaking SSH connectivity.
	By("Creating BGPFilter for KubeVirt live migration community tagging")
	community := v3.BGPCommunityValue("65000:100")
	elevatedPriority := 512
	bgpFilter := &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "kubevirt-lm"},
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
	// Delete any leftover from a previous failed run before creating.
	_, _ = lcgc.BGPFilter().Delete(ctx, "kubevirt-lm", options.DeleteOptions{})
	_, err = lcgc.BGPFilter().Create(ctx, bgpFilter, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create BGPFilter")
	DeferCleanup(func() {
		By("Deleting BGPFilter kubevirt-lm")
		_, err := lcgc.BGPFilter().Delete(context.Background(), "kubevirt-lm", options.DeleteOptions{})
		if err != nil {
			logrus.WithError(err).Warn("Failed to delete BGPFilter kubevirt-lm")
		}
	})

	// Create a BGPPeer so the master node peers with the TOR via eBGP.
	// NextHopMode "Keep" preserves the original next-hop from iBGP routes,
	// so the TOR gets per-node next-hops and routes directly to the node
	// hosting each workload — no ECMP, no extra hop through the master.
	By("Creating BGPPeer for TOR (master only, next-hop-keep, with filter)")
	nextHopKeep := v3.NextHopMode("Keep")
	bgpPeer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "tor-ebgp-peer"},
		Spec: v3.BGPPeerSpec{
			Node:        masterName,
			PeerIP:      torL2tpIP,
			ASNumber:    numorstring.ASNumber(65001),
			NextHopMode: &nextHopKeep,
			Filters:     []string{"kubevirt-lm"},
		},
	}
	_, _ = lcgc.BGPPeers().Delete(ctx, "tor-ebgp-peer", options.DeleteOptions{})
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

	// Wait for confd on the master to regenerate bird.cfg with the new
	// kubevirt-lm filter and TOR peer block. Polling for the actual file
	// contents avoids both a fixed-time sleep (always too long or too short)
	// and the previous large dev-scaffolding DEBUG dump of every config and
	// routing table on every test run; the relevant configs are dumped only
	// on failure via the AfterEach gate registered below.
	By("Waiting for confd to regenerate bird.cfg with the kubevirt-lm filter on master")
	masterPodName := waitForMasterCalicoNodePod(ctx, f, masterName)
	Eventually(func() error {
		cfg, err := kubectl.NewKubectlCommand("calico-system", "exec", masterPodName, "-c", "calico-node", "--",
			"sh", "-c", "cat /etc/calico/confd/config/bird.cfg").Exec()
		if err != nil {
			return fmt.Errorf("read bird.cfg: %w", err)
		}
		if !strings.Contains(cfg, "kubevirt-lm") {
			return fmt.Errorf("bird.cfg does not yet reference filter kubevirt-lm")
		}
		return nil
	}, 30*time.Second, 1*time.Second).Should(Succeed(),
		"confd never regenerated bird.cfg with the kubevirt-lm filter")

	// On failure dump the master's BIRD config + routes for diagnostics.
	// This replaces the previous unconditional DEBUG: dump that ran on every
	// test invocation, regardless of outcome.
	DeferCleanup(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		logBIRDDiagnostics(masterPodName)
	})

	// Wait for the eBGP session to establish on the TOR.
	By("Waiting for eBGP session to establish")
	Eventually(func() error {
		out, err := runOnTOR(tor, "sudo docker exec tor-bird birdcl show protocols")
		if err != nil {
			return err
		}
		if !strings.Contains(out, "Established") {
			return fmt.Errorf("BGP session not established:\n%s", out)
		}
		return nil
	}, 2*time.Minute, 5*time.Second).Should(Succeed(),
		"eBGP session not established on TOR")
	logrus.Info("eBGP peering established on TOR")
}

// waitForMasterCalicoNodePod polls until the calico-node pod on the
// control-plane node is observable. Returns the pod name. Used as a
// precondition for any test step that needs to exec birdcl on the master.
func waitForMasterCalicoNodePod(ctx context.Context, f *framework.Framework, masterName string) string {
	GinkgoHelper()
	var name string
	Eventually(func() error {
		pods, err := f.ClientSet.CoreV1().Pods("calico-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=calico-node",
			FieldSelector: "spec.nodeName=" + masterName,
		})
		if err != nil {
			return err
		}
		if len(pods.Items) == 0 {
			return fmt.Errorf("no calico-node pod on master %s", masterName)
		}
		name = pods.Items[0].Name
		return nil
	}, 30*time.Second, 1*time.Second).Should(Succeed())
	return name
}

// logBIRDDiagnostics dumps the master's confd-generated BIRD configs and
// runtime state. Only call this from failure-gated paths.
func logBIRDDiagnostics(masterPodName string) {
	type item struct{ label, cmd string }
	items := []item{
		{"bird.cfg (BGPFilter + TOR peer)", "cat /etc/calico/confd/config/bird.cfg | sed -n '/kubevirt-lm/,/^$/p'"},
		{"bird_ipam.cfg", "cat /etc/calico/confd/config/bird_ipam.cfg"},
		{"bird_aggr.cfg", "cat /etc/calico/confd/config/bird_aggr.cfg"},
	}
	for _, it := range items {
		out, _ := kubectl.NewKubectlCommand("calico-system", "exec", masterPodName, "-c", "calico-node", "--", "sh", "-c", it.cmd).Exec()
		logrus.Infof("FAILURE-DEBUG %s:\n%s", it.label, out)
	}
	for _, args := range [][]string{
		{"birdcl", "show", "route"},
		{"birdcl", "show", "protocols"},
	} {
		out, _ := kubectl.NewKubectlCommand("calico-system", append([]string{"exec", masterPodName, "-c", "calico-node", "--"}, args...)...).Exec()
		logrus.Infof("FAILURE-DEBUG %s:\n%s", strings.Join(args, " "), out)
	}
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
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var lastRoutes string
		for {
			// Query kernel routes and BIRD routing table for the /32.
			// The BIRD "show route all" output shows preference, community,
			// and bgp_local_pref — critical for diagnosing ECMP issues.
			out, _ := runOnTOR(tor, fmt.Sprintf(
				"echo '--- /32 kernel ---'; ip route show proto bird %s/32 2>&1; "+
					"echo '--- /26 kernel ---'; ip route show proto bird %s 2>&1; "+
					"echo '--- BIRD /32 ---'; sudo docker exec tor-bird birdcl show route %s/32 all 2>&1; "+
					"echo '--- route lookup ---'; ip route get %s 2>&1",
				ip, block26, ip, ip))
			out = strings.TrimSpace(out)
			if out != lastRoutes {
				logrus.Infof("TOR route change:\n%s", out)
				lastRoutes = out
			}
			// Honor stopCh during the wait so the goroutine exits promptly
			// after stop() is called and does not start one more SSH RT.
			select {
			case <-stopCh:
				return
			case <-ticker.C:
			}
		}
	}()
	// Returned stop closer waits for the goroutine to exit — prevents an
	// in-flight SSH session from racing other cleanups (e.g. the timeline
	// writer) that share the same TOR client.
	return func() {
		close(stopCh)
		<-doneCh
	}
}

// torRouteState captures the parsed state of a /32 route on the TOR's BIRD
// routing table, including all candidate routes and the kernel next hop.
type torRouteState struct {
	Has32         bool           `json:"has32"`
	Routes        []torBIRDRoute `json:"routes"`
	KernelNextHop string         `json:"kernelNextHop"`
}

// torBIRDRoute represents a single BIRD route entry for a /32 prefix.
type torBIRDRoute struct {
	NextHop   string `json:"nextHop"`
	LocalPref int    `json:"localPref"`
	Community string `json:"community"`
	Best      bool   `json:"best"`
}

// torPrefixState captures whether a prefix is present in BIRD and its routes.
type torPrefixState struct {
	Present bool           `json:"present"`
	Routes  []torBIRDRoute `json:"routes"`
}

// torRouteSnapshot captures the full TOR route picture at a point in time:
// the /32 host route (elevated during migration), the /26 block route
// (steady-state subnet route), and the kernel next-hop for the VM IP.
type torRouteSnapshot struct {
	Host32    torPrefixState `json:"host32"`
	Block26   torPrefixState `json:"block26"`
	KernelVia string         `json:"kernelVia"`
}

// parseBIRDRouteOutput parses the output of "birdcl show route <prefix> all"
// and returns the list of routes. Returns nil if the output contains
// "Network not in table" or is empty.
func parseBIRDRouteOutput(output string) []torBIRDRoute {
	if strings.Contains(output, "Network not in table") {
		return nil
	}

	var routes []torBIRDRoute
	var current *torBIRDRoute
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "BIRD") {
			continue
		}

		// Route line: contains "via" but is not a BGP attribute.
		if strings.Contains(line, " via ") && !strings.HasPrefix(trimmed, "BGP.") {
			r := torBIRDRoute{}
			if idx := strings.Index(line, " via "); idx >= 0 {
				fields := strings.Fields(line[idx+5:])
				if len(fields) > 0 {
					r.NextHop = fields[0]
				}
			}
			// BIRD marks the active/best route with " * " (space-asterisk-space)
			// in the output line, e.g.:
			//   10.244.0.64/32     via 172.16.8.2 on eth0 * [bgp_node0 16:22:38] (100/0) [AS65000i]
			//                      via 172.16.8.4 on eth0 [bgp_node2 16:21:49] (100/0) [AS65000i]
			// Match the standalone token rather than substring " * " elsewhere
			// in the line (e.g. interface names containing "*" or AS-path
			// expressions) so we never wrongly mark a non-best route as best.
			r.Best = false
			for _, tok := range strings.Fields(line) {
				if tok == "*" {
					r.Best = true
					break
				}
			}
			routes = append(routes, r)
			current = &routes[len(routes)-1]
			continue
		}

		// BGP attribute lines.
		if current != nil {
			if strings.HasPrefix(trimmed, "BGP.local_pref:") {
				val := strings.TrimSpace(strings.TrimPrefix(trimmed, "BGP.local_pref:"))
				if _, err := fmt.Sscanf(val, "%d", &current.LocalPref); err != nil {
					logrus.Warnf("parseBIRDRouteOutput: failed to parse BGP.local_pref %q: %v", val, err)
				}
			} else if strings.HasPrefix(trimmed, "BGP.community:") {
				current.Community = strings.TrimSpace(strings.TrimPrefix(trimmed, "BGP.community:"))
			}
		}
	}
	return routes
}

// queryTORRoute queries the TOR's BIRD routing table and kernel for the state
// of a /32 VM route. Returns Has32=false if BIRD reports "Network not in table".
//
// This function is invoked from polling Eventually loops; it deliberately does
// NOT log per-route detail on every call (that turned the test logs into
// thousands of identical "queryTORRoute" lines). Callers that want a snapshot
// for debugging should log the returned state themselves.
func queryTORRoute(tor *externalnode.Client, vmIP string) torRouteState {
	ip := strings.Split(vmIP, "/")[0]

	out, err := runOnTOR(tor, fmt.Sprintf(
		"sudo docker exec tor-bird birdcl show route %s/32 all 2>&1", ip))
	if err != nil {
		logrus.Warnf("queryTORRoute: SSH error: %v", err)
		return torRouteState{}
	}

	var state torRouteState
	state.Routes = parseBIRDRouteOutput(out)
	state.Has32 = len(state.Routes) > 0

	// Query kernel route for the active next hop.
	kernOut, _ := runOnTOR(tor, fmt.Sprintf("ip route get %s 2>&1", ip))
	if idx := strings.Index(kernOut, "via "); idx >= 0 {
		fields := strings.Fields(kernOut[idx+4:])
		if len(fields) > 0 {
			state.KernelNextHop = fields[0]
		}
	}

	return state
}

// queryTORSnapshot queries the TOR's BIRD routing table for both the /32 host
// route and the /26 block route, plus the kernel next-hop. This captures the
// full route picture at a point in time with a single SSH call.
func queryTORSnapshot(tor *externalnode.Client, vmIP string) torRouteSnapshot {
	ip := strings.Split(vmIP, "/")[0]

	// Compute /26 block from VM IP.
	parsed := net.ParseIP(ip).To4()
	blockIP := net.IPv4(parsed[0], parsed[1], parsed[2], parsed[3]&0xC0)
	block26 := fmt.Sprintf("%s/26", blockIP)

	// Single SSH call with section markers.
	cmd := fmt.Sprintf(
		"echo '=== /32 ==='; sudo docker exec tor-bird birdcl show route %s/32 all 2>&1; "+
			"echo '=== /26 ==='; sudo docker exec tor-bird birdcl show route %s all 2>&1; "+
			"echo '=== kernel ==='; ip route get %s 2>&1",
		ip, block26, ip)
	out, err := runOnTOR(tor, cmd)
	if err != nil {
		logrus.Warnf("queryTORSnapshot: SSH error: %v", err)
		return torRouteSnapshot{}
	}

	var snap torRouteSnapshot

	// Split by section markers and parse each.
	sections := strings.Split(out, "=== ")
	for _, sec := range sections {
		switch {
		case strings.HasPrefix(sec, "/32 ==="):
			body := strings.TrimPrefix(sec, "/32 ===")
			routes := parseBIRDRouteOutput(body)
			snap.Host32 = torPrefixState{Present: len(routes) > 0, Routes: routes}
		case strings.HasPrefix(sec, "/26 ==="):
			body := strings.TrimPrefix(sec, "/26 ===")
			routes := parseBIRDRouteOutput(body)
			snap.Block26 = torPrefixState{Present: len(routes) > 0, Routes: routes}
		case strings.HasPrefix(sec, "kernel ==="):
			body := strings.TrimPrefix(sec, "kernel ===")
			if idx := strings.Index(body, "via "); idx >= 0 {
				fields := strings.Fields(body[idx+4:])
				if len(fields) > 0 {
					snap.KernelVia = fields[0]
				}
			}
		}
	}

	logrus.Infof("queryTORSnapshot(%s): /32=%v(%d) /26=%v(%d) kernelVia=%s",
		ip, snap.Host32.Present, len(snap.Host32.Routes),
		snap.Block26.Present, len(snap.Block26.Routes), snap.KernelVia)
	return snap
}

// queryWorkerMetric queries the kernel route metric for a /32 VM route on a
// worker node's calico-node pod. Returns the metric value (e.g. 512 for
// elevated, 1024 for normal) or -1 if the route is not found.
func queryWorkerMetric(f *framework.Framework, nodeName, vmIP string) int {
	ctx := context.Background()
	ip := strings.Split(vmIP, "/")[0]
	pods, err := f.ClientSet.CoreV1().Pods("calico-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil || len(pods.Items) == 0 {
		logrus.Warnf("queryWorkerMetric: no calico-node pod on %s: %v", nodeName, err)
		return -1
	}
	out, err := kubectl.NewKubectlCommand("calico-system", "exec", pods.Items[0].Name, "-c", "calico-node", "--",
		"sh", "-c", fmt.Sprintf("ip route show %s/32", ip)).Exec()
	if err != nil {
		logrus.Warnf("queryWorkerMetric: ip route show failed on %s: %v", nodeName, err)
		return -1
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return -1
	}
	if idx := strings.Index(out, "metric "); idx >= 0 {
		var metric int
		if _, err := fmt.Sscanf(out[idx:], "metric %d", &metric); err != nil {
			logrus.Warnf("queryWorkerMetric(%s, %s): failed to parse metric from %q: %v",
				nodeName, ip, out[idx:], err)
			return -1
		}
		logrus.Infof("queryWorkerMetric(%s, %s): metric=%d (route: %s)", nodeName, ip, metric, out)
		return metric
	}
	logrus.Infof("queryWorkerMetric(%s, %s): no metric field (route: %s)", nodeName, ip, out)
	return -1
}

// routeTimelineEntry captures the route state at a single point in time.
type routeTimelineEntry struct {
	Timestamp string           `json:"ts"`
	Phase     string           `json:"phase"`
	VMNode    string           `json:"vmNode,omitempty"`
	TOR       torRouteSnapshot `json:"tor"`
	TCPLines  int              `json:"tcpLines"`
}

// routeTimeline collects route state snapshots at key test phases.
type routeTimeline struct {
	mu      sync.Mutex
	entries []routeTimelineEntry
}

func newRouteTimeline() *routeTimeline {
	return &routeTimeline{}
}

// record appends a timestamped entry to the timeline and logs a one-line summary.
func (t *routeTimeline) record(entry routeTimelineEntry) {
	entry.Timestamp = time.Now().UTC().Format("15:04:05.000")
	t.mu.Lock()
	t.entries = append(t.entries, entry)
	t.mu.Unlock()

	lp32 := -1
	if len(entry.TOR.Host32.Routes) > 0 {
		lp32 = entry.TOR.Host32.Routes[0].LocalPref
	}
	logrus.Infof("TIMELINE[%s] phase=%-28s /32=%v(%d) /26=%v(%d) lp32=%-12d tcpLines=%d",
		entry.Timestamp, entry.Phase,
		entry.TOR.Host32.Present, len(entry.TOR.Host32.Routes),
		entry.TOR.Block26.Present, len(entry.TOR.Block26.Routes),
		lp32, entry.TCPLines)
}

// writeToTOR logs a summary table, marshals the timeline to JSON, and writes
// it to /tmp/route-timeline.json on the TOR node via SSH.
func (t *routeTimeline) writeToTOR(tor *externalnode.Client) {
	t.mu.Lock()
	entries := make([]routeTimelineEntry, len(t.entries))
	copy(entries, t.entries)
	t.mu.Unlock()

	if len(entries) == 0 {
		logrus.Warn("Route timeline: no entries to write")
		return
	}

	// Log compact table summary.
	logrus.Infof("Route timeline summary (%d entries):", len(entries))
	logrus.Infof("  %-12s %-28s %-10s %-10s %-12s %s", "TIME", "PHASE", "/32", "/26", "LP32", "TCP_LINES")
	for _, e := range entries {
		lp32 := -1
		if len(e.TOR.Host32.Routes) > 0 {
			lp32 = e.TOR.Host32.Routes[0].LocalPref
		}
		logrus.Infof("  %-12s %-28s %-10s %-10s %-12d %d",
			e.Timestamp, e.Phase,
			fmt.Sprintf("%v(%d)", e.TOR.Host32.Present, len(e.TOR.Host32.Routes)),
			fmt.Sprintf("%v(%d)", e.TOR.Block26.Present, len(e.TOR.Block26.Routes)),
			lp32, e.TCPLines)
	}

	// Marshal to JSON.
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		logrus.WithError(err).Warn("Route timeline: failed to marshal JSON")
		return
	}

	// Write to TOR via base64 — the TOR is an Ubuntu host with base64 available.
	encoded := base64.StdEncoding.EncodeToString(data)
	cmd := fmt.Sprintf("echo '%s' | base64 -d > /tmp/route-timeline.json", encoded)
	_, err = runOnTOR(tor, cmd)
	if err != nil {
		logrus.WithError(err).Warn("Route timeline: failed to write JSON to TOR")
		return
	}
	logrus.Infof("Route timeline: wrote %d entries (%d bytes) to TOR:/tmp/route-timeline.json",
		len(entries), len(data))
}

func ptrInt64(v int64) *int64 { return &v }

// waitForMigrationStatePopulated returns once the VMI has a non-nil
// MigrationState with Completed=true and a non-empty TargetPod / TargetNode.
// migration.WaitForSuccess only checks the VMIM phase; the VMI's
// MigrationState is populated asynchronously by virt-handler, so a bare read
// immediately after WaitForSuccess can race. Polling here makes the assertion
// deterministic.
func waitForMigrationStatePopulated(ctx context.Context, cli ctrlclient.Client, namespace, vmiName string) *kubevirtv1.VirtualMachineInstance {
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

// requireTyphaWatchingLiveMigrations fails the calling test if Typha has not
// picked up the LiveMigration (KubeVirt VirtualMachineInstanceMigration) CRD.
//
// Background: when Calico is installed before the KubeVirt CRDs are available
// (the common bootstrap order on fresh clusters), Typha's libcalico-go
// watcher-syncer hits a 30-minute backoff and silently misses VMIM events.
// Felix never learns that an incoming pod is a migration target, so it
// programs normal-priority routes and the live-migration tests fail with
// confusing route/TCP-stream symptoms minutes into the run.
//
// This precondition probes Typha's logs for the "Backing API has been
// installed" line emitted by libcalico-go/lib/backend/watchersyncer/
// watchercache.go when the CRD is observed. If absent, fail fast with a
// pointer to the documented Typha-restart workaround.
func requireTyphaWatchingLiveMigrations(ctx context.Context, f *framework.Framework) {
	GinkgoHelper()

	// Operator installs use calico-system; manifest installs may use
	// kube-system. Try both.
	var typhaPods []corev1.Pod
	var typhaNamespace string
	for _, ns := range []string{"calico-system", "kube-system"} {
		pods, err := f.ClientSet.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=calico-typha",
		})
		if err == nil && len(pods.Items) > 0 {
			typhaPods = pods.Items
			typhaNamespace = ns
			break
		}
	}
	if len(typhaPods) == 0 {
		// The Feature:KubeVirt label gates whether this suite runs at all;
		// if a caller selects it, missing prerequisites are real failures —
		// we deliberately do not Skip here.
		Fail("Typha not deployed; live-migration tests require Typha (no calico-typha pods found in calico-system or kube-system)")
	}

	const docURL = "https://docs.tigera.io/calico/latest/networking/kubevirt/kubevirt-networking#restart-typha-after-installing-kubevirt"
	const installedMarker = "Backing API has been installed"
	const liveMigrationsListRoot = "/v3/pc.org/livemigrations"

	for _, pod := range typhaPods {
		// Cap the log read so we never slurp hundreds of MB on long-running
		// Typha pods. The "Backing API …" markers we look for are emitted at
		// startup or on a transition (early in the log), so reading from the
		// beginning up to a generous limit is sufficient.
		const typhaLogLimitBytes = int64(10 * 1024 * 1024)
		logBytes := typhaLogLimitBytes
		req := f.ClientSet.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
			LimitBytes: &logBytes,
		})
		stream, err := req.Stream(ctx)
		Expect(err).NotTo(HaveOccurred(), "reading logs of typha %s/%s", pod.Namespace, pod.Name)
		b, readErr := io.ReadAll(stream)
		_ = stream.Close()
		Expect(readErr).NotTo(HaveOccurred(), "reading logs of typha %s/%s", pod.Namespace, pod.Name)

		// Determine Typha's livemigrations syncer state from logs. Three
		// scenarios:
		//
		//   (a) "Backing API not installed" appears, then later "Backing API
		//       has been installed"        → recovered, healthy.
		//   (b) Neither marker appears                        → Typha started
		//       AFTER the CRD existed; first List succeeded silently. Healthy.
		//   (c) "Backing API not installed" appears but "Backing API has been
		//       installed" does not yet     → still in the missing-CRD
		//       backoff. This is the bug.
		//
		// markInstalled() only logs the "installed" line on a transition from
		// !crdInstalled to crdInstalled, so case (b) silently has no log
		// entry. We must therefore look at "is 'not installed' the last
		// observed state", not "did we see 'installed' at all".
		const notInstalledMarker = "Backing API not installed"
		var sawNotInstalled, sawInstalled bool
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, liveMigrationsListRoot) {
				continue
			}
			if strings.Contains(line, notInstalledMarker) {
				sawNotInstalled = true
			} else if strings.Contains(line, installedMarker) {
				sawInstalled = true
			}
		}
		if sawNotInstalled && !sawInstalled {
			Fail(fmt.Sprintf(
				"Typha pod %s/%s is stuck in the missing-CRD backoff for KubeVirt LiveMigration.\n"+
					"This is a known startup-order issue: Calico was installed before the KubeVirt CRDs.\n"+
					"Restart Typha to recover, then re-run the tests:\n"+
					"  kubectl rollout restart deployment calico-typha -n %s\n"+
					"  kubectl rollout status   deployment calico-typha -n %s --timeout=60s\n"+
					"Docs: %s",
				pod.Namespace, pod.Name, typhaNamespace, typhaNamespace, docURL))
		}
	}
}

// requireOperatorManagedCluster fails the calling test if the cluster does not
// have an operator-managed Installation/default. The live-migration tests patch
// the Installation CR to disable natOutgoing; without an Installation that path
// is invalid (manifest installs configure IPPool directly).
func requireOperatorManagedCluster(ctx context.Context, f *framework.Framework) {
	GinkgoHelper()
	out, err := kubectl.NewKubectlCommand("", "get", "installation", "default",
		"-o", "jsonpath={.metadata.name}").Exec()
	if err != nil || strings.TrimSpace(out) != "default" {
		Fail("Installation/default not found — these tests require an operator-managed cluster (got err=" +
			fmt.Sprintf("%v", err) + " output=" + out + ")")
	}
}

// patchInstallationPoolNATOutgoing finds the IPPool with the given name in the
// Installation default and patches its natOutgoing field via the
// controller-runtime client. Resolves the index by pool name (rather than
// hard-coding /ipPools/0/) so the test works on clusters with multiple pools.
// Wrapped in Eventually so a transient apiserver hiccup or operator-reconcile
// race does not leave the cluster mis-patched.
func patchInstallationPoolNATOutgoing(f *framework.Framework, poolName, value string) {
	GinkgoHelper()
	cli, err := e2eclient.NewAPIClient(f.ClientConfig())
	Expect(err).NotTo(HaveOccurred(), "build controller-runtime client")
	Eventually(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		inst := &operatorv1.Installation{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, inst); err != nil {
			return fmt.Errorf("get installation: %w", err)
		}
		if inst.Spec.CalicoNetwork == nil {
			return fmt.Errorf("Installation default has no CalicoNetwork spec")
		}
		idx := -1
		for i := range inst.Spec.CalicoNetwork.IPPools {
			if inst.Spec.CalicoNetwork.IPPools[i].Name == poolName {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("IPPool %q not found in Installation default", poolName)
		}
		inst.Spec.CalicoNetwork.IPPools[idx].NATOutgoing = operatorv1.NATOutgoingType(value)
		if err := cli.Update(ctx, inst); err != nil {
			return fmt.Errorf("update installation: %w", err)
		}
		return nil
	}, 60*time.Second, 2*time.Second).Should(Succeed(),
		"failed to patch Installation %q natOutgoing=%s", poolName, value)
}
