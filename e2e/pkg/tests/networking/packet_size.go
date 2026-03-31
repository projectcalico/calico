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
	"strconv"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

const (
	packetTestGET  = "GET"
	packetTestPOST = "POST"
	packetTestUDP  = "UDP"

	// The DataplaneServer Flask app defaults to port 5000.
	packetServerPort = 5000

	// Default MTU for Calico clusters.
	defaultMTU = 1410
)

const (
	pktClientPod = iota
	pktClientHost
	pktClientExt
)

const (
	pktTargetPod = iota
	pktTargetService
	pktTargetNodePort
)

// generatePacketLengths returns payload sizes for GET, POST, and UDP tests.
// The sizes cluster around the MTU to stress fragmentation boundaries.
func generatePacketLengths(mtu int) (getLengths, postLengths, udpLengths []int) {
	// GET: ~190 bytes HTTP overhead.
	getLengths = []int{10}
	for i := mtu - 190 - 80; i <= mtu-190+30; i += 5 {
		getLengths = append(getLengths, i)
	}
	getLengths = append(getLengths, 10000)

	// POST: ~52 bytes TCP+IP overhead (headers in separate packet).
	postLengths = []int{10}
	for i := mtu - 52 - 80; i <= mtu-52+30; i += 5 {
		postLengths = append(postLengths, i)
	}
	postLengths = append(postLengths, 10000)

	// UDP: ~20 bytes IP overhead.
	udpLengths = []int{10}
	for i := mtu - 20 - 80; i <= mtu-20-60; i += 5 {
		udpLengths = append(udpLengths, i)
	}

	return getLengths, postLengths, udpLengths
}

// withDataplaneServer is a conncheck server pod customizer that replaces the
// default image with the DataplaneServer Flask app. This server provides
// GET /length/<N>, POST /post, and UDP echo endpoints for packet size testing.
//
// TODO: Consider replacing with agnhost. Agnhost's /echo endpoint can echo
// back POST data, and nc can be used for UDP. The main gap is GET /length/N
// (configurable response size) which would need a different approach — e.g.,
// POST N bytes and verify the echo, or use dd to generate payloads.
func withDataplaneServer(pod *v1.Pod) {
	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].Image = images.DataplaneServer
		pod.Spec.Containers[i].Args = nil
		if pod.Spec.Containers[i].ReadinessProbe != nil && pod.Spec.Containers[i].ReadinessProbe.HTTPGet != nil {
			pod.Spec.Containers[i].ReadinessProbe.HTTPGet.Path = "/length/1"
		}
	}
}

// withNetshootImage swaps the client pod image to Netshoot, which has curl
// and nc needed for packet size testing.
func withNetshootClient(pod *v1.Pod) {
	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].Image = images.Netshoot
		pod.Spec.Containers[i].Command = []string{"sleep", "3600"}
		pod.Spec.Containers[i].Args = nil
	}
}

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Datapath"),
	describe.WithCategory(describe.Networking),
	"Packet Size Verification",
	func() {
		f := utils.NewDefaultFramework("packet-size")

		getLengths, postLengths, udpLengths := generatePacketLengths(defaultMTU)

		Context("with different packet sizes", func() {
			DescribeTable("using UDP and TCP",
				func(clientType, targetType int, sameNode bool) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, 6)
					Expect(err).NotTo(HaveOccurred())
					nodesInfo := utils.GetNodesInfo(f, nodes, false)
					nodeNames := nodesInfo.GetNames()
					nodeIPs := nodesInfo.GetIPv4s()
					Expect(len(nodeNames)).To(BeNumerically(">=", 2),
						"packet size tests require at least 2 schedulable worker nodes")

					var serverNode string
					if sameNode {
						serverNode = nodeNames[0]
					} else {
						serverNode = nodeNames[1]
					}

					ct := conncheck.NewConnectionTester(f)

					// Create server with the DataplaneServer image.
					serverName := utils.GenerateRandomName("pkt-srv")
					server := conncheck.NewServer(serverName, f.Namespace,
						conncheck.WithPorts(packetServerPort),
						conncheck.WithNodePortService(),
						conncheck.WithServerPodCustomizer(conncheck.WithNodeName(serverNode)),
						conncheck.WithServerPodCustomizer(withDataplaneServer),
					)
					ct.AddServer(server)

					// Create the appropriate client.
					var execFn func(string) (string, error)
					if clientType == pktClientExt {
						extClient := externalnode.NewClient()
						Expect(extClient).NotTo(BeNil(),
							"external node tests require EXT_IP, EXT_KEY, EXT_USER to be configured")
						// Still need to deploy the server, but use external client for exec.
						ct.Deploy()
						DeferCleanup(ct.Stop)
						execFn = func(cmd string) (string, error) {
							return extClient.Exec("sh", "-c", cmd)
						}
					} else {
						clientName := utils.GenerateRandomName("pkt-client")
						clientOpts := []conncheck.ClientOption{
							conncheck.WithClientCustomizer(conncheck.WithNodeName(nodeNames[0])),
							conncheck.WithClientCustomizer(withNetshootClient),
						}
						if clientType == pktClientHost {
							clientOpts = append(clientOpts, conncheck.WithClientCustomizer(func(pod *v1.Pod) {
								pod.Spec.HostNetwork = true
							}))
						}
						client := conncheck.NewClient(clientName, f.Namespace, clientOpts...)
						ct.AddClient(client)
						ct.Deploy()
						DeferCleanup(ct.Stop)
						execFn = func(cmd string) (string, error) {
							return conncheck.ExecInPod(client.Pod(), "sh", "-c", cmd)
						}
					}

					// Build the target address.
					var target string
					switch targetType {
					case pktTargetPod:
						target = fmt.Sprintf("%s:%d", server.Pod().Status.PodIP, packetServerPort)
					case pktTargetService:
						target = fmt.Sprintf("%s:%d", server.Service().Spec.ClusterIP, packetServerPort)
					case pktTargetNodePort:
						target = fmt.Sprintf("%s:%d", nodeIPs[0], server.NodePortPort())
					default:
						framework.Failf("unrecognized target type: %d", targetType)
					}

					packetTestWithLengths(execFn, target, getLengths, packetTestGET)
					packetTestWithLengths(execFn, target, postLengths, packetTestPOST)
					packetTestWithLengths(execFn, target, udpLengths, packetTestUDP)
				},
				Entry("pod to pod, same node", pktClientPod, pktTargetPod, true),
				Entry("pod to service, same node", pktClientPod, pktTargetService, true),
				Entry("pod to nodeport, same node", pktClientPod, pktTargetNodePort, true),
				Entry("pod to pod, different nodes", pktClientPod, pktTargetPod, false),
				Entry("pod to service, different nodes", pktClientPod, pktTargetService, false),
				Entry("pod to nodeport, different nodes", pktClientPod, pktTargetNodePort, false),
				Entry("host to pod, different nodes", pktClientHost, pktTargetPod, false),
				Entry("host to service, different nodes", pktClientHost, pktTargetService, false),
				Entry("host to nodeport, different nodes", pktClientHost, pktTargetNodePort, false),
				Entry("external to nodeport", pktClientExt, pktTargetNodePort, false),
			)
		})
	},
)

// packetTestWithLengths sends packets of various sizes and verifies the
// response matches expectations.
func packetTestWithLengths(execFn func(string) (string, error), target string, lengths []int, testType string) {
	for _, length := range lengths {
		By(fmt.Sprintf("Testing %s with payload length %d to %s", testType, length, target), func() {
			var cmd string
			var postdata string

			switch testType {
			case packetTestGET:
				cmd = fmt.Sprintf(`curl -m2 -w "\n%%{time_total}" http://%s/length/%d`, target, length)
			case packetTestPOST:
				postdata = strings.Repeat("X", length)
				cmd = fmt.Sprintf(`curl -m2 -w "\n%%{time_total}" -d "%s" -X POST http://%s/post`, postdata, target)
			case packetTestUDP:
				postdata = generateUDPPayload(length)
				cmd = packetUDPCommand(target, postdata)
			default:
				Fail(fmt.Sprintf("unrecognized test type: %s", testType))
			}

			Eventually(func() error {
				out, err := execFn(cmd)
				if err != nil {
					return fmt.Errorf("connection failed: %w", err)
				}

				switch testType {
				case packetTestGET:
					data, elapsed, parseErr := packetSplitCurlOutput(out)
					if parseErr != nil {
						return parseErr
					}
					if elapsed > 0.050 {
						return fmt.Errorf("GET took %.3fs (>50ms)", elapsed)
					}
					if len(data) != length {
						return fmt.Errorf("GET response length %d != expected %d", len(data), length)
					}
				case packetTestPOST:
					data, elapsed, parseErr := packetSplitCurlOutput(out)
					if parseErr != nil {
						return parseErr
					}
					if elapsed > 0.050 {
						return fmt.Errorf("POST took %.3fs (>50ms)", elapsed)
					}
					reported, convErr := strconv.Atoi(strings.TrimSpace(data))
					if convErr != nil {
						return fmt.Errorf("could not parse POST response %q: %w", data, convErr)
					}
					if reported != length {
						return fmt.Errorf("POST reported length %d != expected %d", reported, length)
					}
				case packetTestUDP:
					out = strings.TrimSpace(out)
					if out != postdata {
						return fmt.Errorf("UDP response %q != sent %q", out, postdata)
					}
				}
				return nil
			}, 30*time.Second, 1*time.Second).Should(Succeed(),
				"packet test failed for %s length=%d target=%s", testType, length, target)
		})
	}
}

// packetSplitCurlOutput splits curl output (with -w "\n%{time_total}") into
// the response body and elapsed time.
func packetSplitCurlOutput(stdout string) (string, float64, error) {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		return "", 0, fmt.Errorf("expected 2+ lines in curl output, got %d: %q", len(lines), stdout)
	}
	data := strings.Join(lines[:len(lines)-1], "\n")
	elapsed, err := strconv.ParseFloat(strings.TrimSpace(lines[len(lines)-1]), 64)
	if err != nil {
		return data, 0, fmt.Errorf("could not parse elapsed time %q: %w", lines[len(lines)-1], err)
	}
	return data, elapsed, nil
}

// generateUDPPayload creates a predictable string of the given length.
func generateUDPPayload(length int) string {
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		b.WriteByte(byte('0' + i%10))
	}
	return b.String()
}

// packetUDPCommand generates the nc command for UDP testing, handling both
// IPv4 and IPv6 targets.
func packetUDPCommand(target, postdata string) string {
	if strings.HasPrefix(target, "[") {
		// IPv6: [addr]:port
		idx := strings.LastIndex(target, ":")
		addr := strings.Trim(target[:idx], "[]")
		port := target[idx+1:]
		return fmt.Sprintf(`echo %s | nc -6 -u -w1 %s %s`, postdata, addr, port)
	}
	// IPv4: addr:port
	parts := strings.SplitN(target, ":", 2)
	return fmt.Sprintf(`echo %s | nc -u -w1 %s %s`, postdata, parts[0], parts[1])
}
