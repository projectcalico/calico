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

package networking

import (
	"context"
	"fmt"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Networking),
	describe.WithFeature("Pods"),
	"Pod Termination Grace Period",
	func() {
		f := utils.NewDefaultFramework("pod-termination")

		// Verifies that a client pod can still reach a server via wget while the
		// client pod is in its termination grace period. This confirms that dataplane
		// rules (routes, iptables/BPF entries) remain in place for terminating pods.
		//
		// Setup: deny-all ingress + targeted allow policies so traffic only flows
		// through explicit policy. A client pod traps SIGTERM and attempts wget
		// during the termination window.
		framework.ConformanceIt("should allow client to reach server while client is terminating", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			gracePeriod := int64(60)
			targetPort := 80

			// Create a deny-all ingress NetworkPolicy to ensure traffic is blocked
			// unless explicitly allowed.
			By("Creating deny-all ingress NetworkPolicy")
			denyPolicy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deny-all",
					Namespace: ns,
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
					Ingress:     []networkingv1.NetworkPolicyIngressRule{},
				},
			}
			denyPolicy, err := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(ctx, denyPolicy, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to create deny-all NetworkPolicy")
			DeferCleanup(func() {
				if err := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Delete(ctx, denyPolicy.Name, metav1.DeleteOptions{}); err != nil {
					framework.Logf("WARNING: failed to delete deny-all NetworkPolicy: %v", err)
				}
			})

			// Create a server pod serving HTTP on port 80.
			By("Creating an HTTP server pod")
			serverPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "server",
					Namespace: ns,
					Labels:    map[string]string{"pod-name": "server", "role": "server"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "server-container",
							Image: images.Agnhost,
							Args:  []string{"serve-hostname", "--http", "--port", fmt.Sprintf("%d", targetPort)},
							Ports: []corev1.ContainerPort{{ContainerPort: int32(targetPort)}},
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			}
			serverPod, err = f.ClientSet.CoreV1().Pods(ns).Create(ctx, serverPod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to create server pod")
			DeferCleanup(func() {
				if err := f.ClientSet.CoreV1().Pods(ns).Delete(ctx, serverPod.Name, metav1.DeleteOptions{}); err != nil {
					framework.Logf("WARNING: failed to delete server pod: %v", err)
				}
			})

			// Create a service for the server pod.
			serverSvc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "server-svc",
					Namespace: ns,
				},
				Spec: corev1.ServiceSpec{
					Selector: map[string]string{"pod-name": "server"},
					Ports: []corev1.ServicePort{
						{Port: int32(targetPort), TargetPort: intstr.FromInt32(int32(targetPort))},
					},
				},
			}
			serverSvc, err = f.ClientSet.CoreV1().Services(ns).Create(ctx, serverSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to create server service")
			DeferCleanup(func() {
				if err := f.ClientSet.CoreV1().Services(ns).Delete(ctx, serverSvc.Name, metav1.DeleteOptions{}); err != nil {
					framework.Logf("WARNING: failed to delete server service: %v", err)
				}
			})

			err = e2epod.WaitForPodRunningInNamespace(ctx, f.ClientSet, serverPod)
			Expect(err).NotTo(HaveOccurred(), "server pod did not reach Running state")

			By("Waiting for server pod to have an IP")
			Eventually(func() error {
				p, err := f.ClientSet.CoreV1().Pods(ns).Get(ctx, serverPod.Name, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get server pod: %w", err)
				}
				if p.Status.PodIP == "" {
					return fmt.Errorf("server pod has no IP yet")
				}
				return nil
			}, 60*time.Second, 2*time.Second).Should(Succeed(), "timed out waiting for server pod IP")

			// Create an allow policy for ingress to the server on the target port.
			By("Creating allow-ingress policy for server")
			protocolTCP := corev1.ProtocolTCP
			allowServerPolicy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-server-ingress",
					Namespace: ns,
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"pod-name": "server"},
					},
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						Ports: []networkingv1.NetworkPolicyPort{
							{Protocol: &protocolTCP, Port: &intstr.IntOrString{Type: intstr.Int, IntVal: int32(targetPort)}},
						},
					}},
				},
			}
			allowServerPolicy, err = f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(ctx, allowServerPolicy, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to create allow-server-ingress policy")
			DeferCleanup(func() {
				if err := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Delete(ctx, allowServerPolicy.Name, metav1.DeleteOptions{}); err != nil {
					framework.Logf("WARNING: failed to delete allow-server-ingress policy: %v", err)
				}
			})

			// Create an allow policy for egress from the client on the target port + DNS.
			By("Creating allow-egress policy for client")
			protocolUDP := corev1.ProtocolUDP
			allowClientPolicy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-client-egress",
					Namespace: ns,
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"pod-name": "client-pod"},
					},
					Egress: []networkingv1.NetworkPolicyEgressRule{{
						Ports: []networkingv1.NetworkPolicyPort{
							{Protocol: &protocolTCP, Port: &intstr.IntOrString{Type: intstr.Int, IntVal: int32(targetPort)}},
							{Protocol: &protocolUDP, Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 53}},
						},
					}},
				},
			}
			allowClientPolicy, err = f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(ctx, allowClientPolicy, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to create allow-client-egress policy")
			DeferCleanup(func() {
				if err := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Delete(ctx, allowClientPolicy.Name, metav1.DeleteOptions{}); err != nil {
					framework.Logf("WARNING: failed to delete allow-client-egress policy: %v", err)
				}
			})

			// Create a client pod that traps SIGTERM and performs wget during the
			// termination grace period. The sleep before wget ensures we're well
			// into the termination window.
			By("Creating client pod that performs wget during termination")
			target := fmt.Sprintf("%s.%s:%d", serverSvc.Name, ns, targetPort)
			clientPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "client-pod",
					Namespace: ns,
					Labels:    map[string]string{"pod-name": "client-pod"},
				},
				Spec: corev1.PodSpec{
					TerminationGracePeriodSeconds: &gracePeriod,
					Containers: []corev1.Container{
						{
							Name:    "client-container",
							Image:   images.Alpine,
							Command: []string{"/bin/sh"},
							Args: []string{"-c", fmt.Sprintf(`
_term() {
  echo "[$(date)] caught SIGTERM signal"
  sleep 5
  for i in $(seq 1 5); do
    echo "attempt $i of 5"
    wget -T 5 %s -O - && { echo "[$(date)] wget success"; sleep 5; exit 0; } || sleep 1
  done
  echo "[$(date)] wget failure"; cat /etc/resolv.conf; exit 1
}
trap _term TERM
echo "[$(date)] starting container"
while :; do sleep 10; done
`, target)},
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			}
			clientPod, err = f.ClientSet.CoreV1().Pods(ns).Create(ctx, clientPod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to create client pod")
			DeferCleanup(func() {
				// The pod may already be deleted by the test.
				_ = f.ClientSet.CoreV1().Pods(ns).Delete(ctx, clientPod.Name, metav1.DeleteOptions{})
			})

			err = e2epod.WaitForPodRunningInNamespace(ctx, f.ClientSet, clientPod)
			Expect(err).NotTo(HaveOccurred(), "client pod did not reach Running state")

			// Trigger pod deletion to start the termination grace period.
			By("Deleting client pod to trigger termination")
			go func() {
				deleteErr := f.ClientSet.CoreV1().Pods(ns).Delete(ctx, clientPod.Name, metav1.DeleteOptions{})
				if deleteErr != nil {
					logrus.WithError(deleteErr).Error("failed to delete client pod")
				}
			}()

			// Wait for the pod logs to contain "wget success", confirming the client
			// could still reach the server during its termination grace period.
			By("Checking pod logs for 'wget success'")
			Eventually(func() error {
				logs, err := e2epod.GetPodLogs(ctx, f.ClientSet, ns, clientPod.Name, "client-container")
				if err != nil {
					return fmt.Errorf("failed to get client pod logs: %w", err)
				}
				logrus.Infof("Client pod logs:\n%s", logs)
				if !strings.Contains(logs, "wget success") {
					return fmt.Errorf("client pod logs do not contain 'wget success' yet")
				}
				return nil
			}, 2*time.Duration(gracePeriod)*time.Second, 2*time.Second).Should(Succeed(),
				"timed out waiting for client pod to successfully wget server during termination")
		})

		// Verifies that a server pod remains pingable while it is terminating.
		// The server pod has a PreStop hook that sleeps, keeping it alive during
		// the termination grace period. A client pod pings the server continuously
		// during this window.
		It("should allow pinging a server pod while it is terminating", func() {
			ctx := context.Background()
			ns := f.Namespace.Name
			gracePeriod := int64(60)

			// Create a server pod with a PreStop hook that sleeps for the grace period,
			// keeping the pod alive and its IP routable.
			By("Creating server pod with PreStop sleep hook")
			serverPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "server",
					Namespace: ns,
					Labels:    map[string]string{"pod-name": "server"},
				},
				Spec: corev1.PodSpec{
					TerminationGracePeriodSeconds: &gracePeriod,
					Containers: []corev1.Container{
						{
							Name:  "server-container",
							Image: images.Agnhost,
							Args:  []string{"serve-hostname", "--http", "--port", "80"},
							Ports: []corev1.ContainerPort{{ContainerPort: 80}},
							Lifecycle: &corev1.Lifecycle{
								PreStop: &corev1.LifecycleHandler{
									Exec: &corev1.ExecAction{
										Command: []string{"/bin/sh", "-c", fmt.Sprintf("sleep %d", gracePeriod)},
									},
								},
							},
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			}
			serverPod, err := f.ClientSet.CoreV1().Pods(ns).Create(ctx, serverPod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to create server pod")
			DeferCleanup(func() {
				// The pod may already be deleted by the test.
				_ = f.ClientSet.CoreV1().Pods(ns).Delete(ctx, serverPod.Name, metav1.DeleteOptions{})
			})

			err = e2epod.WaitForPodRunningInNamespace(ctx, f.ClientSet, serverPod)
			Expect(err).NotTo(HaveOccurred(), "server pod did not reach Running state")

			By("Waiting for server pod to have an IP")
			var serverIP string
			Eventually(func() error {
				p, err := f.ClientSet.CoreV1().Pods(ns).Get(ctx, serverPod.Name, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get server pod: %w", err)
				}
				if p.Status.PodIP == "" {
					return fmt.Errorf("server pod has no IP yet")
				}
				serverIP = p.Status.PodIP
				return nil
			}, 60*time.Second, 2*time.Second).Should(Succeed(), "timed out waiting for server pod IP")

			// Verify that the server is pingable before triggering termination.
			By("Verifying server is pingable before termination")
			expectPingSuccess(ctx, f, ns, "pre-term-ping", serverIP)

			// Record the time we start deletion so we can calculate how much of the
			// grace period remains for the Consistently check.
			deleteTime := time.Now()

			By("Deleting server pod to trigger termination")
			go func() {
				deleteErr := f.ClientSet.CoreV1().Pods(ns).Delete(ctx, serverPod.Name, metav1.DeleteOptions{})
				if deleteErr != nil {
					logrus.WithError(deleteErr).Error("failed to delete server pod")
				}
			}()

			// Continuously ping the server during its termination grace period.
			// Use a conservative duration that stays within the grace period window
			// minus a margin to avoid racing with actual pod shutdown.
			By("Pinging server during termination grace period")
			margin := 15 * time.Second
			consistentlyDuration := time.Duration(gracePeriod)*time.Second - time.Since(deleteTime) - margin
			if consistentlyDuration < 5*time.Second {
				consistentlyDuration = 5 * time.Second
			}
			Consistently(func() error {
				return pingFromNewPod(ctx, f, ns, "grace-ping", serverIP)
			}, consistentlyDuration, 5*time.Second).Should(Succeed(),
				"server pod became unreachable during termination grace period")
		})
	})

// expectPingSuccess creates a short-lived pod that pings the given IP and
// expects it to succeed.
func expectPingSuccess(ctx context.Context, f *framework.Framework, ns, podName, ip string) {
	ExpectWithOffset(1, pingFromNewPod(ctx, f, ns, podName, ip)).To(Succeed(),
		"ping to %s from pod %s failed", ip, podName)
}

// pingFromNewPod creates a pod that pings the given IP, waits for it to complete,
// and returns an error if the ping failed. Each invocation generates a unique pod
// name to avoid conflicts when called repeatedly (e.g., inside Consistently).
func pingFromNewPod(ctx context.Context, f *framework.Framework, ns, podName, ip string) error {
	uniqueName := utils.GenerateRandomName(podName)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      uniqueName,
			Namespace: ns,
			Labels:    map[string]string{"pod-name": podName},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:    "ping",
					Image:   images.Alpine,
					Command: []string{"ping", "-c", "3", "-W", "2", ip},
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"NET_RAW"},
						},
					},
				},
			},
		},
	}

	pod, err := f.ClientSet.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ping pod: %w", err)
	}
	defer func() {
		graceSeconds := ptr.To[int64](0)
		_ = f.ClientSet.CoreV1().Pods(ns).Delete(ctx, pod.Name, metav1.DeleteOptions{GracePeriodSeconds: graceSeconds})
		_ = e2epod.WaitForPodNotFoundInNamespace(ctx, f.ClientSet, pod.Name, ns, 30*time.Second)
	}()

	err = e2epod.WaitForPodSuccessInNamespace(ctx, f.ClientSet, pod.Name, ns)
	if err != nil {
		logs, logErr := e2epod.GetPodLogs(ctx, f.ClientSet, ns, pod.Name, "ping")
		if logErr == nil {
			logrus.Infof("Ping pod %s logs:\n%s", pod.Name, logs)
		}
		return fmt.Errorf("ping to %s failed: %w", ip, err)
	}
	return nil
}
