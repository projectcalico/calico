// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"encoding/json"
	"fmt"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
	e2edeployment "k8s.io/kubernetes/test/e2e/framework/deployment"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("QoS"),
	describe.WithCategory(describe.Networking),
	"QoS Controls",
	func() {
		f := utils.NewDefaultFramework("calico-qos")

		// Verifies that Calico's QoS bandwidth annotations limit actual throughput.
		// An iperf3 server and client are deployed on separate nodes. We first measure
		// baseline (unlimited) throughput, then apply ingress and egress bandwidth
		// limits via pod annotations and verify the actual throughput matches the
		// configured limits within a tolerance.
		It("should limit bandwidth with QoS annotations", func() {
			ctx := context.Background()
			ns := f.Namespace.Name

			By("Getting cluster node names")
			nodeCtx, nodeCancel := context.WithTimeout(ctx, 30*time.Second)
			defer nodeCancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(nodeCtx, f.ClientSet, 3)
			Expect(err).NotTo(HaveOccurred(), "failed to list schedulable nodes")
			nodesInfo := utils.GetNodesInfo(f, nodes, true)
			nodeNames := nodesInfo.GetNames()
			Expect(len(nodeNames)).To(BeNumerically(">=", 2), "QoS test requires at least 2 nodes")
			serverNode := nodeNames[0]
			clientNode := nodeNames[1]

			// Create an iperf3 server pod and service on the first node.
			By("Creating iperf3 server pod and service")
			serverPod, serverSvc := createIperf3Server(ctx, f, ns, serverNode, nil)
			DeferCleanup(func() {
				cleanupIperf3Server(ctx, f, ns, serverPod.Name, serverSvc.Name)
			})

			// Create an iperf3 client deployment on the second node with no bandwidth limit.
			By("Creating iperf3 client with no bandwidth limit")
			clientPod := createIperf3Client(ctx, f, ns, clientNode, nil)
			DeferCleanup(func() {
				deleteIperf3Client(ctx, f, ns)
			})

			// Measure baseline throughput without any QoS limit.
			By("Running iperf3 to measure baseline throughput")
			baselineRate, _, err := retryIperf3(f, &clientPod, 5, 5*time.Second,
				fmt.Sprintf("-c %s -O5 -J", serverSvc.Name))
			Expect(err).NotTo(HaveOccurred(), "failed to measure baseline throughput")
			logrus.Infof("Baseline throughput (bps): %.0f", baselineRate)

			// The baseline should be much higher than the 10Mbit limit we'll configure.
			Expect(baselineRate).To(BeNumerically(">=", 10_000_000.0*5),
				"baseline throughput too low to meaningfully test bandwidth limiting")

			// Recreate the client with an ingress bandwidth limit.
			By("Deleting iperf3 client")
			deleteIperf3Client(ctx, f, ns)
			err = e2epod.WaitForPodNotFoundInNamespace(ctx, f.ClientSet, clientPod.Name, ns, 3*time.Minute)
			Expect(err).NotTo(HaveOccurred(), "timed out waiting for client pod deletion")

			By("Creating iperf3 client with 10Mbit ingress bandwidth limit")
			clientPod = createIperf3Client(ctx, f, ns, clientNode, map[string]string{
				"qos.projectcalico.org/ingressBandwidth": "10M",
			})

			// Measure ingress-limited throughput. Use -R (reverse) so the server sends
			// data to the client, testing the client's ingress limit.
			By("Running iperf3 to measure ingress-limited throughput")
			ingressRate, _, err := retryIperf3(f, &clientPod, 5, 5*time.Second,
				fmt.Sprintf("-c %s -O5 -J -R", serverSvc.Name))
			Expect(err).NotTo(HaveOccurred(), "failed to measure ingress-limited throughput")
			logrus.Infof("Ingress-limited throughput (bps): %.0f", ingressRate)

			// Expect the limited rate to be within 50% of the desired 10Mbit rate.
			// We use a wide tolerance because kind environments can be noisy.
			Expect(ingressRate).To(BeNumerically(">=", 10_000_000.0*0.5),
				"ingress-limited rate too far below target")
			Expect(ingressRate).To(BeNumerically("<=", 10_000_000.0*2.0),
				"ingress-limited rate too far above target")

			// Recreate the client with an egress bandwidth limit.
			By("Deleting iperf3 client")
			deleteIperf3Client(ctx, f, ns)
			err = e2epod.WaitForPodNotFoundInNamespace(ctx, f.ClientSet, clientPod.Name, ns, 3*time.Minute)
			Expect(err).NotTo(HaveOccurred(), "timed out waiting for client pod deletion")

			By("Creating iperf3 client with 10Mbit egress bandwidth limit")
			clientPod = createIperf3Client(ctx, f, ns, clientNode, map[string]string{
				"qos.projectcalico.org/egressBandwidth": "10M",
			})

			// Measure egress-limited throughput. Normal mode (client sends to server)
			// tests the client's egress limit.
			By("Running iperf3 to measure egress-limited throughput")
			egressRate, _, err := retryIperf3(f, &clientPod, 5, 5*time.Second,
				fmt.Sprintf("-c %s -O5 -J", serverSvc.Name))
			Expect(err).NotTo(HaveOccurred(), "failed to measure egress-limited throughput")
			logrus.Infof("Egress-limited throughput (bps): %.0f", egressRate)

			Expect(egressRate).To(BeNumerically(">=", 10_000_000.0*0.5),
				"egress-limited rate too far below target")
			Expect(egressRate).To(BeNumerically("<=", 10_000_000.0*2.0),
				"egress-limited rate too far above target")
		})
	})

// createIperf3Server creates an iperf3 server pod and service on the given node.
func createIperf3Server(ctx context.Context, f *framework.Framework, ns, nodeName string, annotations map[string]string) (*corev1.Pod, *corev1.Service) {
	serverPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "iperf3-server",
			Namespace:   ns,
			Labels:      map[string]string{"app": "iperf3-server"},
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{
				{
					Name:    "iperf3",
					Image:   images.Iperf3,
					Args:    []string{"-s"},
					Ports:   []corev1.ContainerPort{{ContainerPort: 5201, Protocol: corev1.ProtocolTCP}},
					Command: []string{"iperf3"},
				},
			},
			RestartPolicy:                 corev1.RestartPolicyAlways,
			TerminationGracePeriodSeconds: ptr.To[int64](0),
		},
	}
	serverPod, err := f.ClientSet.CoreV1().Pods(ns).Create(ctx, serverPod, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create iperf3 server pod")

	serverSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "iperf3-server",
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "iperf3-server"},
			Ports: []corev1.ServicePort{
				{Port: 5201, TargetPort: intstr.FromInt32(5201), Protocol: corev1.ProtocolTCP},
			},
		},
	}
	serverSvc, err = f.ClientSet.CoreV1().Services(ns).Create(ctx, serverSvc, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create iperf3 server service")

	err = e2epod.WaitForPodRunningInNamespace(ctx, f.ClientSet, serverPod)
	Expect(err).NotTo(HaveOccurred(), "iperf3 server pod did not reach Running state")

	return serverPod, serverSvc
}

// cleanupIperf3Server deletes the iperf3 server pod and service.
func cleanupIperf3Server(ctx context.Context, f *framework.Framework, ns, podName, svcName string) {
	if err := f.ClientSet.CoreV1().Pods(ns).Delete(ctx, podName, metav1.DeleteOptions{}); err != nil {
		framework.Logf("WARNING: failed to delete iperf3 server pod: %v", err)
	}
	if err := f.ClientSet.CoreV1().Services(ns).Delete(ctx, svcName, metav1.DeleteOptions{}); err != nil {
		framework.Logf("WARNING: failed to delete iperf3 server service: %v", err)
	}
}

// createIperf3Client creates an iperf3 client deployment on the given node with
// the specified annotations. Returns the running client pod.
func createIperf3Client(ctx context.Context, f *framework.Framework, ns, nodeName string, annotations map[string]string) corev1.Pod {
	labels := map[string]string{"app": "iperf3-client"}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "iperf3-client",
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels,
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{"kubernetes.io/hostname": nodeName},
					Containers: []corev1.Container{
						{
							Name:            "iperf3",
							Image:           images.Iperf3,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"/bin/sh", "-c", "sleep infinity"},
						},
					},
					TerminationGracePeriodSeconds: ptr.To[int64](0),
				},
			},
		},
	}
	_, err := f.ClientSet.AppsV1().Deployments(ns).Create(ctx, deployment, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to create iperf3 client deployment")

	err = e2edeployment.WaitForDeploymentRevisionAndImage(f.ClientSet, ns, "iperf3-client", "1", images.Iperf3)
	Expect(err).NotTo(HaveOccurred(), "iperf3 client deployment did not become ready")

	// Find the pod created by the deployment.
	podList, err := f.ClientSet.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "app=iperf3-client",
	})
	Expect(err).NotTo(HaveOccurred(), "failed to list iperf3 client pods")
	Expect(podList.Items).NotTo(BeEmpty(), "no iperf3 client pods found")

	clientPod := podList.Items[0]
	err = e2epod.WaitForPodRunningInNamespace(ctx, f.ClientSet, &clientPod)
	Expect(err).NotTo(HaveOccurred(), "iperf3 client pod did not reach Running state")

	return clientPod
}

// deleteIperf3Client deletes the iperf3 client deployment.
func deleteIperf3Client(ctx context.Context, f *framework.Framework, ns string) {
	err := f.ClientSet.AppsV1().Deployments(ns).Delete(ctx, "iperf3-client", metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to delete iperf3 client deployment")
}

// retryIperf3 runs iperf3 in the client pod with retries and returns the measured
// throughput rate and peak rate in bits per second.
func retryIperf3(f *framework.Framework, clientPod *corev1.Pod, retries int, retryInterval time.Duration, args string) (float64, float64, error) {
	var lastErr error
	for i := range retries {
		logrus.Infof("iperf3 attempt %d of %d", i+1, retries)

		out, err := execInPodWithTimeout(f, clientPod, 30*time.Second, "sh", "-c", fmt.Sprintf("iperf3 %s", args))
		if err != nil {
			lastErr = fmt.Errorf("iperf3 exec failed: %w", err)
			logrus.WithError(lastErr).Warn("iperf3 attempt failed, retrying")
			time.Sleep(retryInterval)
			continue
		}

		rate, peakRate, err := parseIperf3JSON(out)
		if err != nil || rate == 0 {
			lastErr = fmt.Errorf("iperf3 parse failed: %w", err)
			logrus.WithError(lastErr).Warn("iperf3 parse failed, retrying")
			time.Sleep(retryInterval)
			continue
		}

		return rate, peakRate, nil
	}
	return 0, 0, fmt.Errorf("iperf3 failed after %d retries: %w", retries, lastErr)
}

// execInPodWithTimeout runs a command in a pod with a configurable timeout.
func execInPodWithTimeout(f *framework.Framework, pod *corev1.Pod, timeout time.Duration, command ...string) (string, error) {
	args := append([]string{"exec", pod.Name, "-n", pod.Namespace, "--"}, command...)
	return e2ekubectl.NewKubectlCommand(pod.Namespace, args...).
		WithTimeout(time.After(timeout)).
		Exec()
}

// iperf3Result is a minimal struct for parsing iperf3 JSON output.
type iperf3Result struct {
	Intervals []struct {
		Sum struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum"`
	} `json:"intervals"`
	End struct {
		SumReceived struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_received"`
	} `json:"end"`
}

// parseIperf3JSON parses iperf3 JSON output and returns the average rate and
// peak rate (first interval) in bits per second.
func parseIperf3JSON(output string) (float64, float64, error) {
	var result iperf3Result
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return 0, 0, fmt.Errorf("failed to parse iperf3 JSON: %w", err)
	}

	rate := result.End.SumReceived.BitsPerSecond
	var peakRate float64
	if len(result.Intervals) > 0 {
		peakRate = result.Intervals[0].Sum.BitsPerSecond
	}

	logrus.Infof("iperf3 result: rate=%.0f bps, peakRate=%.0f bps", rate, peakRate)
	return rate, peakRate, nil
}
