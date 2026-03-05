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
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/iperfcheck"
)

// Tests for Calico QoS bandwidth limiting. Verifies that ingress and egress
// bandwidth annotations produce the expected throughput limits on real traffic.
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

			tester := iperfcheck.NewIperfTester(f)
			defer tester.Stop()

			server := iperfcheck.NewPeer("iperf-server", f.Namespace, iperfcheck.WithNodeName(serverNode))
			client := iperfcheck.NewPeer("iperf-client", f.Namespace, iperfcheck.WithNodeName(clientNode))
			tester.AddPeer(server)
			tester.AddPeer(client)

			// Deploy server and client pods on separate nodes.
			By("Deploying iperf3 server and client pods")
			tester.Deploy()

			// Measure baseline throughput without any QoS limit.
			By("Running iperf3 to measure baseline throughput")
			baseline, err := tester.MeasureBandwidth(client, server, iperfcheck.WithRetries(5, 5*time.Second))
			Expect(err).NotTo(HaveOccurred(), "failed to measure baseline throughput")
			logrus.Infof("Baseline throughput (bps): %.0f", baseline.AverageRate)

			// The baseline should be much higher than the 10Mbit limit we'll configure.
			Expect(baseline.AverageRate).To(BeNumerically(">=", 10_000_000.0*5), "baseline throughput too low to meaningfully test bandwidth limiting")

			// Replace the client with a pod annotated for 10Mbit ingress bandwidth.
			By("Replacing iperf3 client with 10Mbit ingress bandwidth limit")
			tester.RemovePeer("iperf-client")
			client = iperfcheck.NewPeer("iperf-client", f.Namespace,
				iperfcheck.WithNodeName(clientNode),
				iperfcheck.WithPeerCustomizer(func(pod *corev1.Pod) {
					pod.Annotations = map[string]string{
						"qos.projectcalico.org/ingressBandwidth": "10M",
					}
				}))
			tester.AddPeer(client)
			tester.Deploy()

			// Measure ingress-limited throughput. Use -R (reverse) so the server sends
			// data to the client, testing the client's ingress limit.
			By("Running iperf3 to measure ingress-limited throughput")
			ingressResult, err := tester.MeasureBandwidth(client, server, iperfcheck.WithReverse(), iperfcheck.WithRetries(5, 5*time.Second))
			Expect(err).NotTo(HaveOccurred(), "failed to measure ingress-limited throughput")
			logrus.Infof("Ingress-limited throughput (bps): %.0f", ingressResult.AverageRate)

			// Expect the limited rate to be within 50% of the desired 10Mbit rate.
			// We use a wide tolerance because kind environments can be noisy.
			Expect(ingressResult.AverageRate).To(BeNumerically(">=", 10_000_000.0*0.5), "ingress-limited rate too far below target")
			Expect(ingressResult.AverageRate).To(BeNumerically("<=", 10_000_000.0*2.0), "ingress-limited rate too far above target")

			// Replace the client with a pod annotated for 10Mbit egress bandwidth.
			By("Replacing iperf3 client with 10Mbit egress bandwidth limit")
			tester.RemovePeer("iperf-client")
			client = iperfcheck.NewPeer("iperf-client", f.Namespace,
				iperfcheck.WithNodeName(clientNode),
				iperfcheck.WithPeerCustomizer(func(pod *corev1.Pod) {
					pod.Annotations = map[string]string{
						"qos.projectcalico.org/egressBandwidth": "10M",
					}
				}))
			tester.AddPeer(client)
			tester.Deploy()

			// Measure egress-limited throughput. Normal mode (client sends to server)
			// tests the client's egress limit.
			By("Running iperf3 to measure egress-limited throughput")
			egressResult, err := tester.MeasureBandwidth(client, server, iperfcheck.WithRetries(5, 5*time.Second))
			Expect(err).NotTo(HaveOccurred(), "failed to measure egress-limited throughput")
			logrus.Infof("Egress-limited throughput (bps): %.0f", egressResult.AverageRate)

			Expect(egressResult.AverageRate).To(BeNumerically(">=", 10_000_000.0*0.5), "egress-limited rate too far below target")
			Expect(egressResult.AverageRate).To(BeNumerically("<=", 10_000_000.0*2.0), "egress-limited rate too far above target")

			// Replace the client with a pod annotated for both 10Mbit ingress AND egress bandwidth.
			By("Replacing iperf3 client with both ingress and egress bandwidth limits")
			tester.RemovePeer("iperf-client")
			client = iperfcheck.NewPeer("iperf-client", f.Namespace,
				iperfcheck.WithNodeName(clientNode),
				iperfcheck.WithPeerCustomizer(func(pod *corev1.Pod) {
					pod.Annotations = map[string]string{
						"qos.projectcalico.org/ingressBandwidth": "10M",
						"qos.projectcalico.org/egressBandwidth":  "10M",
					}
				}))
			tester.AddPeer(client)
			tester.Deploy()

			By("Running iperf3 to measure ingress throughput with both limits applied")
			bothIngressResult, err := tester.MeasureBandwidth(
				client, server,
				iperfcheck.WithReverse(),
				iperfcheck.WithRetries(5, 5*time.Second),
			)
			Expect(err).NotTo(HaveOccurred(), "failed to measure ingress throughput with both limits")
			logrus.Infof("Both-limited ingress throughput (bps): %.0f", bothIngressResult.AverageRate)
			Expect(bothIngressResult.AverageRate).To(BeNumerically(">=", 10_000_000.0*0.5), "combined ingress rate too far below target")
			Expect(bothIngressResult.AverageRate).To(BeNumerically("<=", 10_000_000.0*2.0), "combined ingress rate too far above target")

			By("Running iperf3 to measure egress throughput with both limits applied")
			bothEgressResult, err := tester.MeasureBandwidth(client, server, iperfcheck.WithRetries(5, 5*time.Second))
			Expect(err).NotTo(HaveOccurred(), "failed to measure egress throughput with both limits")
			logrus.Infof("Both-limited egress throughput (bps): %.0f", bothEgressResult.AverageRate)
			Expect(bothEgressResult.AverageRate).To(BeNumerically(">=", 10_000_000.0*0.5), "combined egress rate too far below target")
			Expect(bothEgressResult.AverageRate).To(BeNumerically("<=", 10_000_000.0*2.0), "combined egress rate too far above target")
		})

		// Verifies that Calico's QoS packet rate annotations limit actual throughput.
		It("should limit packet rate with QoS annotations", func() {
			ctx := context.Background()

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

			tester := iperfcheck.NewIperfTester(f)
			defer tester.Stop()

			server := iperfcheck.NewPeer("iperf-server", f.Namespace, iperfcheck.WithNodeName(serverNode))
			clientPeer := iperfcheck.NewPeer("iperf-client", f.Namespace, iperfcheck.WithNodeName(clientNode))
			tester.AddPeer(server)
			tester.AddPeer(clientPeer)

			By("Deploying iperf3 server and client pods")
			tester.Deploy()

			// Measure baseline UDP throughput to ensure the cluster can handle the test traffic.
			By("Running iperf3 to measure baseline UDP throughput")
			baseline, err := tester.MeasureBandwidth(
				clientPeer, server,
				iperfcheck.WithUDP(),
				iperfcheck.WithPacketLength(1000),
				iperfcheck.WithTargetBandwidth("100M"),
				iperfcheck.WithRetries(5, 5*time.Second),
			)
			Expect(err).NotTo(HaveOccurred(), "failed to measure baseline UDP throughput")
			logrus.Infof("Baseline UDP throughput (bps): %.0f", baseline.AverageRate)
			Expect(baseline.AverageRate).To(BeNumerically(">=", 100_000_000.0*0.8), "baseline UDP throughput too low for packet rate test")

			// --- Ingress packet rate limit ---
			By("Replacing server with ingressPacketRate=100 annotation")
			tester.RemovePeer("iperf-server")
			server = iperfcheck.NewPeer("iperf-server", f.Namespace,
				iperfcheck.WithNodeName(serverNode),
				iperfcheck.WithPeerCustomizer(func(pod *corev1.Pod) {
					pod.Annotations = map[string]string{
						"qos.projectcalico.org/ingressPacketRate": "100",
					}
				}))
			tester.AddPeer(server)
			tester.Deploy()

			By("Running iperf3 to measure ingress-packet-rate-limited throughput")
			ingressResult, err := tester.MeasureBandwidth(
				clientPeer, server,
				iperfcheck.WithUDP(),
				iperfcheck.WithPacketLength(1000),
				iperfcheck.WithTargetBandwidth("100M"),
				iperfcheck.WithRetries(5, 5*time.Second),
			)
			Expect(err).NotTo(HaveOccurred(), "failed to measure ingress packet rate limited throughput")
			logrus.Infof("Ingress packet-rate-limited throughput (bps): %.0f", ingressResult.AverageRate)
			// 1000 bytes * 8 bits * 100 pps = 800kbps; allow 20% margin -> 960kbps
			Expect(ingressResult.AverageRate).To(BeNumerically("<=", 1000*8*100*1.2), "ingress packet rate limit not effective")

			// --- Egress packet rate limit ---
			By("Removing rate-limited server, re-deploying plain server")
			tester.RemovePeer("iperf-server")
			server = iperfcheck.NewPeer("iperf-server", f.Namespace, iperfcheck.WithNodeName(serverNode))
			tester.AddPeer(server)

			By("Replacing client with egressPacketRate=100 annotation")
			tester.RemovePeer("iperf-client")
			clientPeer = iperfcheck.NewPeer("iperf-client", f.Namespace,
				iperfcheck.WithPeerCustomizer(func(pod *corev1.Pod) {
					pod.Spec.NodeName = clientNode
					if pod.Annotations == nil {
						pod.Annotations = map[string]string{}
					}
					pod.Annotations["qos.projectcalico.org/egressPacketRate"] = "100"
				}))
			tester.AddPeer(clientPeer)
			tester.Deploy()

			By("Running iperf3 to measure egress-packet-rate-limited throughput")
			egressResult, err := tester.MeasureBandwidth(
				clientPeer, server,
				iperfcheck.WithUDP(),
				iperfcheck.WithPacketLength(1000),
				iperfcheck.WithTargetBandwidth("100M"),
				iperfcheck.WithRetries(5, 5*time.Second),
			)
			Expect(err).NotTo(HaveOccurred(), "failed to measure egress packet rate limited throughput")
			logrus.Infof("Egress packet-rate-limited throughput (bps): %.0f", egressResult.AverageRate)
			Expect(egressResult.AverageRate).To(BeNumerically("<=", 1000*8*100*1.2), "egress packet rate limit not effective")
		})
	})
