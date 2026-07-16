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
	"io"
	"strconv"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
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
			By("Getting cluster node names")
			nodesInfo := utils.AwaitReadySchedulableNodesInfo(f, 2, true)
			nodeNames := nodesInfo.GetNames()
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
			ingressResult := measureWithRateRetry(tester, client, server, 10_000_000.0*2.0,
				iperfcheck.WithReverse(), iperfcheck.WithRetries(5, 5*time.Second))
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
			egressResult := measureWithRateRetry(tester, client, server, 10_000_000.0*2.0,
				iperfcheck.WithRetries(5, 5*time.Second))
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
			bothIngressResult := measureWithRateRetry(tester, client, server, 10_000_000.0*2.0,
				iperfcheck.WithReverse(),
				iperfcheck.WithRetries(5, 5*time.Second),
			)
			logrus.Infof("Both-limited ingress throughput (bps): %.0f", bothIngressResult.AverageRate)
			Expect(bothIngressResult.AverageRate).To(BeNumerically(">=", 10_000_000.0*0.5), "combined ingress rate too far below target")
			Expect(bothIngressResult.AverageRate).To(BeNumerically("<=", 10_000_000.0*2.0), "combined ingress rate too far above target")

			By("Running iperf3 to measure egress throughput with both limits applied")
			bothEgressResult := measureWithRateRetry(tester, client, server, 10_000_000.0*2.0,
				iperfcheck.WithRetries(5, 5*time.Second))
			logrus.Infof("Both-limited egress throughput (bps): %.0f", bothEgressResult.AverageRate)
			Expect(bothEgressResult.AverageRate).To(BeNumerically(">=", 10_000_000.0*0.5), "combined egress rate too far below target")
			Expect(bothEgressResult.AverageRate).To(BeNumerically("<=", 10_000_000.0*2.0), "combined egress rate too far above target")
		})

		// Verifies that Calico's QoS packet rate annotations limit actual throughput.
		It("should limit packet rate with QoS annotations", func() {
			By("Getting cluster node names")
			nodesInfo := utils.AwaitReadySchedulableNodesInfo(f, 2, true)
			nodeNames := nodesInfo.GetNames()
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

			// 1000 bytes * 8 bits * 100 pps = 800kbps; allow 20% margin -> 960kbps
			maxRate := 1000.0 * 8 * 100 * 1.2
			udpOpts := []iperfcheck.MeasureOption{
				iperfcheck.WithUDP(),
				iperfcheck.WithPacketLength(1000),
				iperfcheck.WithTargetBandwidth("100M"),
				iperfcheck.WithRetries(5, 5*time.Second),
			}

			By("Running iperf3 to measure ingress-packet-rate-limited throughput")
			ingressResult := measureWithRateRetry(tester, clientPeer, server, maxRate, udpOpts...)
			logrus.Infof("Ingress packet-rate-limited throughput (bps): %.0f", ingressResult.AverageRate)
			Expect(ingressResult.AverageRate).To(BeNumerically("<=", maxRate), "ingress packet rate limit not effective")

			// --- Egress packet rate limit ---
			By("Removing rate-limited server, re-deploying plain server")
			tester.RemovePeer("iperf-server")
			server = iperfcheck.NewPeer("iperf-server", f.Namespace, iperfcheck.WithNodeName(serverNode))
			tester.AddPeer(server)

			By("Replacing client with egressPacketRate=100 annotation")
			tester.RemovePeer("iperf-client")
			clientPeer = iperfcheck.NewPeer("iperf-client", f.Namespace,
				iperfcheck.WithNodeName(clientNode),
				iperfcheck.WithPeerCustomizer(func(pod *corev1.Pod) {
					pod.Annotations = map[string]string{
						"qos.projectcalico.org/egressPacketRate": "100",
					}
				}))
			tester.AddPeer(clientPeer)
			tester.Deploy()

			By("Running iperf3 to measure egress-packet-rate-limited throughput")
			egressResult := measureWithRateRetry(tester, clientPeer, server, maxRate, udpOpts...)
			logrus.Infof("Egress packet-rate-limited throughput (bps): %.0f", egressResult.AverageRate)
			Expect(egressResult.AverageRate).To(BeNumerically("<=", maxRate), "egress packet rate limit not effective")
		})

		// Verifies that Calico's QoS connection-limit annotation
		// (qos.projectcalico.org/ingressMaxConnections) caps the number of
		// concurrent TCP connections a workload accepts, and that closing a
		// connection frees a slot for a new one. This mirrors the FV case in
		// felix/fv/qos_controls_test.go ("should limit connections correctly"):
		// hold N connections open, confirm the (N+1)th is refused, then free
		// one and confirm a new connection is admitted.
		//
		// The connlimit counter only manifests when N connections are held
		// concurrently, which the conncheck ConnectionTester's one-shot
		// Execute() model does not express on its own. We therefore hold the N
		// connections open with ExecStream (the e2e analog of the FV's
		// StartPersistentConnection) and use a TCPConnect target (the analog of
		// CanConnectTo) for the one-shot (N+1)th probe. Egress limits use the
		// identical counter and are covered at FV level, so this e2e exercises
		// ingress only.
		It("should limit concurrent connections with QoS annotations", func() {
			const (
				connLimitPort = 8080
				maxConns      = 3
			)

			By("Getting cluster node names")
			nodesInfo := utils.AwaitReadySchedulableNodesInfo(f, 2, true)
			nodeNames := nodesInfo.GetNames()
			serverNode := nodeNames[0]
			clientNode := nodeNames[1]

			checker := conncheck.NewConnectionTester(f)
			defer checker.Stop()

			// Server: a netshoot pod running a socat listener that accepts and
			// holds many concurrent connections (fork spawns a child per
			// connection; each child bridges to a `sleep` so the connection is
			// never closed from the server side), annotated to cap ingress
			// connections at maxConns. socat is used rather than netcat because
			// netshoot's OpenBSD `nc -k` only accepts connections sequentially,
			// whereas this test needs several held open at once. No Service is
			// created — the client dials the pod IP directly, keeping the
			// connlimit semantics clear of any kube-proxy/NAT interaction. socat
			// is not an HTTP server, so the default HTTP readiness probe is
			// dropped.
			listenAddr := fmt.Sprintf("TCP-LISTEN:%d,fork,reuseaddr", connLimitPort)
			server := conncheck.NewServer("qos-connlimit-server", f.Namespace,
				conncheck.WithPorts(connLimitPort),
				conncheck.WithAutoCreateService(false),
				conncheck.WithServerPodCustomizer(conncheck.WithNodeName(serverNode)),
				conncheck.WithServerPodCustomizer(func(pod *corev1.Pod) {
					if pod.Annotations == nil {
						pod.Annotations = map[string]string{}
					}
					pod.Annotations["qos.projectcalico.org/ingressMaxConnections"] = strconv.Itoa(maxConns)
					ctr := &pod.Spec.Containers[0]
					ctr.Image = images.Netshoot
					ctr.Command = []string{"socat"}
					ctr.Args = []string{listenAddr, "EXEC:sleep 3600"}
					ctr.ReadinessProbe = nil
				}),
			)

			// Client: a netshoot pod on a different node, so the test exercises
			// the cross-node ingress path (from-hep/tunnel) rather than the
			// same-node shortcut.
			client := conncheck.NewClient("qos-connlimit-client", f.Namespace,
				conncheck.WithClientCustomizer(conncheck.WithNodeName(clientNode)),
				conncheck.WithClientCustomizer(func(pod *corev1.Pod) {
					pod.Spec.Containers[0].Image = images.Netshoot
				}),
			)

			checker.AddServer(server)
			checker.AddClient(client)

			By("Deploying the connlimit server and client pods")
			checker.Deploy()

			serverIP := server.Pod().Status.PodIP
			Expect(serverIP).NotTo(BeEmpty(), "server pod has no IP after becoming ready")

			probeTarget := conncheck.NewTCPConnectTarget(serverIP, connLimitPort)

			// Confirm the server is reachable before saturating the limit. This
			// also gives the pods a moment to settle; the meaningful assertions
			// are the refusal and reuse steps below, which Execute() retries
			// until the limit is programmed by Felix.
			By("Verifying the server is reachable")
			checker.ExpectSuccess(client, probeTarget)
			checker.Execute()

			// Hold maxConns connections open concurrently. Each holder is a
			// socat that connects to the server and bridges to a `sleep`, so
			// neither end ever closes the socket — it stays ESTABLISHED,
			// occupying a connlimit slot until stopped. This is the e2e analog
			// of the FV's StartPersistentConnection; ExecStream's stop() (the
			// analog of pc.Stop()) terminates socat and closes the connection.
			By(fmt.Sprintf("Holding %d concurrent connections open", maxConns))
			connectAddr := fmt.Sprintf("TCP:%s:%d", serverIP, connLimitPort)
			var holders []func() error
			defer func() {
				for _, stop := range holders {
					_ = stop()
				}
			}()
			for i := range maxConns {
				stop, err := client.ExecStream(
					context.Background(),
					[]string{"socat", connectAddr, "EXEC:sleep 3600"},
					io.Discard,
				)
				Expect(err).NotTo(HaveOccurred(), "failed to open held connection %d", i)
				holders = append(holders, stop)
			}

			// With maxConns connections held, the (N+1)th must be refused.
			// Execute() retries for up to 30s, which absorbs both the window
			// where Felix is still programming the limit and the time for the
			// held connections' handshakes to complete.
			By("Verifying the (N+1)th connection is refused")
			checker.ResetExpectations()
			checker.ExpectFailure(client, probeTarget)
			checker.Execute()

			// Free one slot and confirm a new connection is admitted. This
			// exercises the counter decrement on connection close.
			By("Freeing one connection and verifying a new one is admitted")
			Expect(holders[len(holders)-1]()).To(Succeed(), "failed to stop a held connection")
			holders = holders[:len(holders)-1]
			checker.ResetExpectations()
			checker.ExpectSuccess(client, probeTarget)
			checker.Execute()
		})
	})

// measureWithRateRetry runs a bandwidth measurement and retries once if the
// measured rate exceeds maxRate. This handles two startup conditions on a
// freshly created pod:
//   - the race where iperf3 starts before Felix has finished programming the
//     QoS rules, and
//   - the token-bucket warm-up burst: bandwidth limits use a TBF qdisc whose
//     bucket starts full (the default burst is 4Gi bits / 512MiB), so the first
//     measurement transmits hundreds of MB at line rate before throttling
//     engages, inflating the average. The retry re-measures on the same pod
//     (no redeploy), so the drained bucket yields a steady-state rate.
func measureWithRateRetry(
	tester *iperfcheck.IperfTester,
	client, server *iperfcheck.Peer,
	maxRate float64,
	opts ...iperfcheck.MeasureOption,
) *iperfcheck.Result {
	result, err := tester.MeasureBandwidth(client, server, opts...)
	Expect(err).NotTo(HaveOccurred(), "failed to measure rate from %s to %s", client.Name(), server.Name())
	if result.AverageRate <= maxRate {
		return result
	}
	logrus.Infof("Rate %.0f bps from %s to %s exceeds limit %.0f bps, retrying once (QoS rules may not be programmed yet, or the token-bucket warm-up burst may not have drained)",
		result.AverageRate, client.Name(), server.Name(), maxRate)
	time.Sleep(5 * time.Second)
	result, err = tester.MeasureBandwidth(client, server, opts...)
	Expect(err).NotTo(HaveOccurred(), "failed to measure rate from %s to %s on retry", client.Name(), server.Name())
	return result
}
