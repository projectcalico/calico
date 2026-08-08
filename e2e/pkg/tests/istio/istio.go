// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package istio

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

const (
	istioNamespace = "calico-system"

	// Timeouts for Istio operations which can be slow.
	istioEnableTimeout  = 5 * time.Minute
	istioDisableTimeout = 3 * time.Minute
	istioPollInterval   = 5 * time.Second
)

// --- Istio Ambient Mode: Traffic Encryption and Calico NetworkPolicy Enforcement ---
//
// These tests validate Istio Ambient Mode functionality with Calico:
// - Enabling/disabling Istio via the operator Istio CR
// - Traffic encryption via ztunnel when ambient label is applied
// - Calico NetworkPolicy enforcement with Istio ambient mode active
// - UDP traffic bypass of ztunnel with Calico policy enforcement
var _ = describe.CalicoDescribe(
	describe.WithSerial(),
	describe.WithTeam(describe.Core),
	describe.WithFeature("Istio"),
	describe.WithCategory(describe.Networking),
	// Ordered so the Istio ambient install is created once for the whole container
	// instead of per spec. Enabling Istio creates the operator Istio CR and waits for
	// it to report Available, which is slow. Both specs run against the same install,
	// and a final spec disables it and verifies baseline connectivity returns.
	ginkgo.Ordered,
	"Istio Ambient Mode",
	func() {
		f := utils.NewDefaultFramework("istio-ambient")

		var cli ctrlclient.Client
		var (
			// istioSetupDone guards the one-time, container-scoped Istio enable below.
			istioSetupDone bool
			// istioCreated records whether this container created the Istio CR, so
			// teardown only removes an install we own and doesn't run twice.
			istioCreated bool
		)

		ginkgo.BeforeEach(func(ctx ginkgo.SpecContext) {
			var err error
			cli, err = client.New(f.ClientConfig())
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create controller-runtime client")

			// Enable Istio once for the whole container. Guarded rather than done in a
			// BeforeAll because the framework client isn't populated until the framework's
			// own BeforeEach, which runs after BeforeAll in an Ordered container.
			if istioSetupDone {
				return
			}
			istioSetupDone = true
			// Record ownership before waiting for readiness so the AfterAll safety net can
			// tear down a CR we created even if the readiness wait fails.
			istioCreated = createIstioIfAbsent(ctx, cli)
			waitForIstioAvailable(ctx, cli)
		})

		ginkgo.AfterAll(func(ctx ginkgo.SpecContext) {
			// Safety net: the disable spec normally tears the install down, but if an
			// earlier spec failed it gets skipped. Only disable an install we created.
			if istioCreated {
				disableIstioAmbientMode(ctx, cli)
			}
		})

		// Test: Traffic encryption and Calico policy enforcement under Istio ambient mode.
		//
		// Validates:
		// 1. Baseline connectivity before the namespace is enrolled in ambient mode
		// 2. Traffic encryption when the ambient label is applied
		// 3. Traffic unencrypted when the ambient label is removed
		// 4. Calico NetworkPolicy enforcement with Istio active
		ginkgo.It("should encrypt traffic with ambient mode and enforce Calico NetworkPolicy", func(ctx context.Context) {
			ginkgo.By("Setting up connection tester with a client and two servers")
			checker := conncheck.NewConnectionTester(f)
			ginkgo.DeferCleanup(checker.Stop)

			// Create a server that will be "allowed" by policy.
			allowedServer := conncheck.NewServer("allowed-svc", f.Namespace,
				conncheck.WithServerLabels(map[string]string{"app": "allowed-svc", "role": "server"}),
			)
			// Create a server that will be "denied" by policy.
			deniedServer := conncheck.NewServer("denied-svc", f.Namespace,
				conncheck.WithServerLabels(map[string]string{"app": "denied-svc", "role": "server"}),
			)

			// Client pod with capture capabilities for tcpdump encryption verification.
			testClient := conncheck.NewClient("curl-client", f.Namespace,
				conncheck.WithClientLabels(map[string]string{"app": "curl-client"}),
				conncheck.WithCapture(),
			)

			checker.AddServer(allowedServer)
			checker.AddServer(deniedServer)
			checker.AddClient(testClient)
			checker.Deploy()

			// Phase 1: Baseline — verify connectivity before the namespace is enrolled in
			// ambient mode. Istio is installed cluster-wide by the container setup, but an
			// unlabeled namespace is unaffected until the ambient label is applied.
			ginkgo.By("Verifying baseline connectivity to both servers before enrolling the namespace")
			checker.ExpectSuccess(testClient, allowedServer.ClusterIPs()...)
			checker.ExpectSuccess(testClient, deniedServer.ClusterIPs()...)
			checker.Execute()

			// Phase 2: Apply ambient mode label to test namespace.
			ginkgo.By(fmt.Sprintf("Labeling namespace %s with istio ambient mode", f.Namespace.Name))
			applyAmbientLabel(ctx, f, f.Namespace.Name)
			ginkgo.DeferCleanup(func() {
				removeAmbientLabel(context.Background(), f, f.Namespace.Name)
			})

			// Phase 3: Verify connectivity with Istio ambient mode active.
			ginkgo.By("Verifying connectivity to both servers with Istio ambient mode active")
			checker.ResetExpectations()
			checker.ExpectSuccess(testClient, allowedServer.ClusterIPs()...)
			checker.ExpectSuccess(testClient, deniedServer.ClusterIPs()...)
			checker.Execute()

			// Phase 4: Verify traffic encryption via tcpdump.
			// With ambient mode active, TCP traffic should be encrypted by ztunnel.
			ginkgo.By("Verifying traffic is encrypted (tcpdump should not show plaintext HTTP)")
			checker.ExpectEncrypted(testClient, allowedServer.ClusterIP())

			// Phase 5: Apply Calico NetworkPolicy — allow only the allowed-svc.
			ginkgo.By("Applying Calico NetworkPolicy to allow only the allowed server")
			policy := newEgressPolicy(f.Namespace.Name, "curl-client", "allowed-svc")
			policyCtx, policyCancel := context.WithTimeout(ctx, 30*time.Second)
			defer policyCancel()
			err := cli.Create(policyCtx, policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create NetworkPolicy")
			ginkgo.DeferCleanup(func() {
				_ = ctrlclient.IgnoreNotFound(cli.Delete(context.Background(), policy))
			})

			// Phase 6: Verify policy enforcement — allowed server reachable, denied server blocked.
			ginkgo.By("Verifying policy enforcement: allowed-svc reachable, denied-svc blocked")
			checker.ResetExpectations()
			checker.ExpectSuccess(testClient, allowedServer.ClusterIPs()...)
			checker.ExpectFailure(testClient, deniedServer.ClusterIPs()...)
			checker.Execute()

			// Phase 7: Delete policy and verify connectivity restored.
			ginkgo.By("Deleting NetworkPolicy and verifying connectivity is restored")
			delCtx, delCancel := context.WithTimeout(ctx, 30*time.Second)
			defer delCancel()
			err = cli.Delete(delCtx, policy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to delete NetworkPolicy")

			checker.ResetExpectations()
			checker.ExpectSuccess(testClient, allowedServer.ClusterIPs()...)
			checker.ExpectSuccess(testClient, deniedServer.ClusterIPs()...)
			checker.Execute()

			// Phase 8: Verify traffic still encrypted after policy deletion.
			ginkgo.By("Verifying traffic is still encrypted after policy deletion")
			checker.ExpectEncrypted(testClient, allowedServer.ClusterIP())

			// Phase 9: Remove ambient label, verify traffic is no longer encrypted.
			ginkgo.By("Removing ambient label from namespace")
			removeAmbientLabel(ctx, f, f.Namespace.Name)

			ginkgo.By("Verifying traffic is no longer encrypted after label removal")
			checker.ExpectPlaintext(testClient, allowedServer.ClusterIP())
		}, ginkgo.SpecTimeout(15*time.Minute))

		// Test: UDP traffic bypasses ztunnel and Calico policy still enforces UDP rules.
		//
		// Validates:
		// 1. UDP echo works before enrolling the namespace in ambient mode
		// 2. UDP still works with Istio ambient mode (bypasses ztunnel)
		// 3. Calico NetworkPolicy blocks UDP when applied
		ginkgo.It("should allow UDP traffic to bypass ztunnel while Calico enforces UDP policy", func(ctx context.Context) {
			ginkgo.By("Creating a UDP echo server pod")
			udpServerPod := createUDPEchoServer(ctx, f)
			ginkgo.DeferCleanup(func() {
				_ = f.ClientSet.CoreV1().Pods(f.Namespace.Name).Delete(context.Background(), udpServerPod.Name, metav1.DeleteOptions{})
			})

			ginkgo.By("Creating a UDP client pod")
			udpClientPod := createUDPClient(ctx, f)
			ginkgo.DeferCleanup(func() {
				_ = f.ClientSet.CoreV1().Pods(f.Namespace.Name).Delete(context.Background(), udpClientPod.Name, metav1.DeleteOptions{})
			})

			// Phase 1: Baseline UDP connectivity.
			ginkgo.By("Verifying baseline UDP echo works")
			expectUDPEchoWorks(udpClientPod, udpServerPod)

			// Phase 2: Enroll the namespace in ambient mode.
			ginkgo.By(fmt.Sprintf("Labeling namespace %s with istio ambient mode", f.Namespace.Name))
			applyAmbientLabel(ctx, f, f.Namespace.Name)
			ginkgo.DeferCleanup(func() {
				removeAmbientLabel(context.Background(), f, f.Namespace.Name)
			})

			// Phase 3: UDP still works (bypasses ztunnel).
			ginkgo.By("Verifying UDP echo still works with Istio enabled (bypasses ztunnel)")
			expectUDPEchoWorks(udpClientPod, udpServerPod)

			// Phase 4: Verify ztunnel logs contain no UDP entries.
			ginkgo.By("Verifying ztunnel logs show no UDP traffic")
			expectNoUDPInZtunnelLogs(ctx, f)

			// Phase 5: Apply Calico policy to deny UDP from client.
			ginkgo.By("Applying Calico NetworkPolicy to deny UDP from client")
			udpDenyPolicy := newUDPDenyPolicy(f.Namespace.Name, "udp-client")
			policyCtx, policyCancel := context.WithTimeout(ctx, 30*time.Second)
			defer policyCancel()
			err := cli.Create(policyCtx, udpDenyPolicy)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create UDP deny policy")
			ginkgo.DeferCleanup(func() {
				_ = ctrlclient.IgnoreNotFound(cli.Delete(context.Background(), udpDenyPolicy))
			})

			// Phase 6: Verify UDP is blocked by Calico policy.
			ginkgo.By("Verifying UDP echo is blocked by Calico policy")
			expectUDPEchoBlocked(udpClientPod, udpServerPod)
		}, ginkgo.SpecTimeout(10*time.Minute))

		// Test: Disabling Istio ambient mode tears the install down cleanly and leaves the
		// dataplane working. Runs last so the specs above share the single install created by
		// the container setup; the disable helper asserts the Istio CR is fully removed.
		ginkgo.It("should restore baseline connectivity after Istio ambient mode is disabled", func(ctx context.Context) {
			if !istioCreated {
				ginkgo.Skip("Istio pre-existed this suite; not disabling an install we did not create")
			}

			ginkgo.By("Setting up a connection tester with a client and a server")
			checker := conncheck.NewConnectionTester(f)
			ginkgo.DeferCleanup(checker.Stop)

			server := conncheck.NewServer("svc", f.Namespace)
			testClient := conncheck.NewClient("curl-client", f.Namespace)
			checker.AddServer(server)
			checker.AddClient(testClient)
			checker.Deploy()

			ginkgo.By("Disabling Istio ambient mode")
			disableIstioAmbientMode(ctx, cli)
			// The install is gone, so clear the flag to keep the AfterAll safety net from repeating it.
			istioCreated = false

			ginkgo.By("Verifying connectivity is intact after disabling Istio")
			checker.ExpectSuccess(testClient, server.ClusterIPs()...)
			checker.Execute()
		}, ginkgo.SpecTimeout(10*time.Minute))
	},
)

// enableIstioAmbientMode ensures Istio ambient mode is enabled and, if this call created
// the Istio CR, registers a DeferCleanup to delete it after the spec, preserving
// pre-existing Istio installations. Use this for specs that own Istio's whole lifecycle;
// container-scoped setup should call createIstioIfAbsent and manage teardown itself.
func enableIstioAmbientMode(ctx context.Context, cli ctrlclient.Client) {
	// Register cleanup before waiting for Available, so a create followed by a failed
	// readiness wait still tears the CR back down.
	if createIstioIfAbsent(ctx, cli) {
		ginkgo.DeferCleanup(func(ctx context.Context) {
			disableIstioAmbientMode(ctx, cli)
		})
	}
	waitForIstioAvailable(ctx, cli)
}

// createIstioIfAbsent creates the Istio CR if it doesn't already exist. It returns true if
// this call created the CR, so the caller owns teardown. It does not wait for readiness or
// register any cleanup; callers pair it with waitForIstioAvailable.
func createIstioIfAbsent(ctx context.Context, cli ctrlclient.Client) bool {
	existing := &operatorv1.Istio{}
	getCtx, getCancel := context.WithTimeout(ctx, 10*time.Second)
	defer getCancel()
	err := cli.Get(getCtx, types.NamespacedName{Name: "default"}, existing)
	if err == nil {
		logrus.Info("Istio CR already exists, skipping creation")
		return false
	}
	if !apierrors.IsNotFound(err) {
		gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to check for existing Istio CR")
	}

	istioObj := &operatorv1.Istio{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	createCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = cli.Create(createCtx, istioObj)
	if apierrors.IsAlreadyExists(err) {
		// Raced with another creator, or the Get above missed it. It already exists, so
		// we didn't create it and don't own teardown.
		logrus.Info("Istio CR already exists, skipping creation")
		return false
	}
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create Istio CR")
	return true
}

// disableIstioAmbientMode deletes the Istio CR and waits for cleanup.
func disableIstioAmbientMode(ctx context.Context, cli ctrlclient.Client) {
	istioObj := &operatorv1.Istio{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}

	deleteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := cli.Delete(deleteCtx, istioObj)
	gomega.Expect(ctrlclient.IgnoreNotFound(err)).NotTo(gomega.HaveOccurred(), "Failed to delete Istio CR")

	// Wait for the Istio CR to be fully removed.
	gomega.Eventually(func() bool {
		getCtx, getCancel := context.WithTimeout(ctx, 10*time.Second)
		defer getCancel()
		obj := &operatorv1.Istio{}
		err := cli.Get(getCtx, types.NamespacedName{Name: "default"}, obj)
		return apierrors.IsNotFound(err)
	}).WithTimeout(istioDisableTimeout).WithPolling(istioPollInterval).Should(
		gomega.BeTrue(),
		"Istio CR should be deleted",
	)
}

// waitForIstioAvailable waits for the "istio" TigeraStatus to report Available.
// This is more implementation-agnostic than polling individual DaemonSets/Deployments.
func waitForIstioAvailable(ctx context.Context, cli ctrlclient.Client) {
	gomega.Eventually(func() error {
		getCtx, getCancel := context.WithTimeout(ctx, 10*time.Second)
		defer getCancel()
		ts := &operatorv1.TigeraStatus{}
		err := cli.Get(getCtx, types.NamespacedName{Name: "istio"}, ts)
		if err != nil {
			return fmt.Errorf("failed to get TigeraStatus 'istio': %w", err)
		}
		if !ts.Available() {
			return fmt.Errorf("TigeraStatus 'istio' is not yet Available (conditions: %v)", ts.Status.Conditions)
		}
		return nil
	}).WithTimeout(istioEnableTimeout).WithPolling(istioPollInterval).Should(
		gomega.Succeed(),
		"TigeraStatus 'istio' should be Available",
	)
}

// applyAmbientLabel labels a namespace with istio.io/dataplane-mode=ambient.
func applyAmbientLabel(ctx context.Context, f *framework.Framework, nsName string) {
	labelCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ns, err := f.ClientSet.CoreV1().Namespaces().Get(labelCtx, nsName, metav1.GetOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to get namespace %s", nsName)

	if ns.Labels == nil {
		ns.Labels = make(map[string]string)
	}
	ns.Labels[v3.LabelIstioDataplaneMode] = v3.LabelIstioDataplaneModeAmbient

	_, err = f.ClientSet.CoreV1().Namespaces().Update(labelCtx, ns, metav1.UpdateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to label namespace %s with ambient mode", nsName)
}

// removeAmbientLabel removes the istio.io/dataplane-mode label from a namespace.
func removeAmbientLabel(ctx context.Context, f *framework.Framework, nsName string) {
	labelCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ns, err := f.ClientSet.CoreV1().Namespaces().Get(labelCtx, nsName, metav1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Warnf("Failed to get namespace %s for label removal", nsName)
		return
	}

	delete(ns.Labels, v3.LabelIstioDataplaneMode)
	_, err = f.ClientSet.CoreV1().Namespaces().Update(labelCtx, ns, metav1.UpdateOptions{})
	if err != nil {
		logrus.WithError(err).Warnf("Failed to remove ambient label from namespace %s", nsName)
	}
}

// newEgressPolicy creates a Calico NetworkPolicy that allows the client to reach only the allowed
// server (and DNS), denying all other egress.
func newEgressPolicy(namespace, clientApp, allowedApp string) *v3.NetworkPolicy {
	tcpProto := numorstring.ProtocolFromString("TCP")
	udpProto := numorstring.ProtocolFromString("UDP")
	policy := v3.NewNetworkPolicy()
	policy.Name = "allow-egress-to-" + allowedApp
	policy.Namespace = namespace
	policy.Spec = v3.NetworkPolicySpec{
		Selector: fmt.Sprintf("app == '%s'", clientApp),
		Types:    []v3.PolicyType{v3.PolicyTypeEgress},
		Egress: []v3.Rule{
			{
				// Allow DNS resolution.
				Action:   v3.Allow,
				Protocol: &udpProto,
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(53)},
				},
			},
			{
				// Allow egress to the allowed server on HTTP port.
				Action:   v3.Allow,
				Protocol: &tcpProto,
				Destination: v3.EntityRule{
					Selector: fmt.Sprintf("app == '%s'", allowedApp),
					Ports:    []numorstring.Port{numorstring.SinglePort(80)},
				},
			},
			{
				// Deny everything else.
				Action: v3.Deny,
			},
		},
	}
	return policy
}

// newUDPDenyPolicy creates a Calico NetworkPolicy that denies all UDP egress from pods matching clientApp.
func newUDPDenyPolicy(namespace, clientApp string) *v3.NetworkPolicy {
	udpProto := numorstring.ProtocolFromString("UDP")
	policy := v3.NewNetworkPolicy()
	policy.Name = "deny-udp-from-" + clientApp
	policy.Namespace = namespace
	policy.Spec = v3.NetworkPolicySpec{
		Selector: fmt.Sprintf("app == '%s'", clientApp),
		Types:    []v3.PolicyType{v3.PolicyTypeEgress},
		Egress: []v3.Rule{
			{
				Action:   v3.Deny,
				Protocol: &udpProto,
			},
		},
	}
	return policy
}

// createUDPEchoServer creates a pod running socat as a UDP echo server on port 8080.
func createUDPEchoServer(ctx context.Context, f *framework.Framework) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "udp-echo-server",
			Namespace: f.Namespace.Name,
			Labels:    map[string]string{"app": "udp-echo-server"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "echo",
					Image:   images.Socat,
					Command: []string{"socat", "-v", "UDP-LISTEN:8080,fork,reuseaddr", "PIPE"},
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8080, Protocol: corev1.ProtocolUDP},
					},
				},
			},
		},
	}

	createCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	created, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Create(createCtx, pod, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create UDP echo server pod")

	// Wait for pod to be running.
	gomega.Eventually(func() error {
		getCtx, getCancel := context.WithTimeout(ctx, 10*time.Second)
		defer getCancel()
		p, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(getCtx, created.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if p.Status.Phase != corev1.PodRunning {
			return fmt.Errorf("pod %s is in phase %s", p.Name, p.Status.Phase)
		}
		return nil
	}).WithTimeout(2*time.Minute).WithPolling(5*time.Second).Should(
		gomega.Succeed(),
		"UDP echo server pod should be running",
	)

	// Re-fetch to get the pod IP.
	getCtx, getCancel := context.WithTimeout(ctx, 10*time.Second)
	defer getCancel()
	created, err = f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(getCtx, created.Name, metav1.GetOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to get UDP echo server pod")

	return created
}

// createUDPClient creates a pod with networking tools (netshoot) for sending UDP traffic.
func createUDPClient(ctx context.Context, f *framework.Framework) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "udp-client",
			Namespace: f.Namespace.Name,
			Labels:    map[string]string{"app": "udp-client"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "client",
					Image:   images.Netshoot,
					Command: []string{"/bin/bash", "-c", "sleep infinity"},
				},
			},
		},
	}

	createCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	created, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Create(createCtx, pod, metav1.CreateOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create UDP client pod")

	// Wait for pod to be running.
	gomega.Eventually(func() error {
		getCtx, getCancel := context.WithTimeout(ctx, 10*time.Second)
		defer getCancel()
		p, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(getCtx, created.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if p.Status.Phase != corev1.PodRunning {
			return fmt.Errorf("pod %s is in phase %s", p.Name, p.Status.Phase)
		}
		return nil
	}).WithTimeout(2*time.Minute).WithPolling(5*time.Second).Should(
		gomega.Succeed(),
		"UDP client pod should be running",
	)

	return created
}

// expectUDPEchoWorks sends a UDP message from client to server and verifies the echo response.
func expectUDPEchoWorks(clientPod, serverPod *corev1.Pod) {
	serverIP := serverPod.Status.PodIP
	gomega.Expect(serverIP).NotTo(gomega.BeEmpty(), "UDP echo server pod should have an IP")

	gomega.Eventually(func() error {
		msg := "hello-udp-test"
		cmd := fmt.Sprintf(`echo -n "%s" | nc -u -w3 %s 8080`, msg, serverIP)
		output, err := conncheck.ExecInPod(clientPod, "sh", "-c", cmd)
		if err != nil {
			return fmt.Errorf("exec failed: %w", err)
		}
		if !strings.Contains(strings.TrimSpace(output), msg) {
			return fmt.Errorf("expected echo response containing %q, got %q", msg, output)
		}
		return nil
	}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(
		gomega.Succeed(),
		"UDP echo should return the sent message",
	)
}

// expectUDPEchoBlocked sends a UDP message and expects no response (blocked by policy).
func expectUDPEchoBlocked(clientPod, serverPod *corev1.Pod) {
	serverIP := serverPod.Status.PodIP
	gomega.Expect(serverIP).NotTo(gomega.BeEmpty(), "UDP echo server pod should have an IP")

	// Allow time for the policy to take effect.
	gomega.Eventually(func() error {
		cmd := fmt.Sprintf(`echo -n "blocked" | nc -u -w2 %s 8080`, serverIP)
		output, err := conncheck.ExecInPod(clientPod, "sh", "-c", cmd)
		// nc may return an error or empty output when blocked.
		_ = err
		trimmed := strings.TrimSpace(output)
		if trimmed != "" && strings.Contains(trimmed, "blocked") {
			return fmt.Errorf("expected empty response (blocked), got %q", trimmed)
		}
		return nil
	}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(
		gomega.Succeed(),
		"UDP echo should be blocked by Calico policy (empty response)",
	)
}

// expectNoUDPInZtunnelLogs checks that ztunnel pods have no UDP-related log entries,
// confirming that UDP traffic bypasses the ztunnel proxy.
func expectNoUDPInZtunnelLogs(ctx context.Context, f *framework.Framework) {
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	podList, err := f.ClientSet.CoreV1().Pods(istioNamespace).List(getCtx, metav1.ListOptions{
		LabelSelector: "app=ztunnel",
	})
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to list ztunnel pods")
	gomega.Expect(podList.Items).NotTo(gomega.BeEmpty(), "Expected at least one ztunnel pod")

	k := utils.Kubectl{}
	logs, err := k.Logs(istioNamespace, "app=ztunnel", "")
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to get ztunnel logs")

	for _, line := range strings.Split(logs, "\n") {
		// Only check ztunnel access log lines (connection tracking entries) for UDP.
		// Other log lines (startup, config, debug) may legitimately mention "UDP".
		if strings.Contains(line, "direction=") {
			gomega.Expect(strings.ToUpper(line)).NotTo(gomega.ContainSubstring("UDP"),
				"ztunnel access log should not contain UDP traffic entries (UDP bypasses ztunnel): %s", line)
		}
	}
}
