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
	// The PacketSizeServer defaults to port 5000.
	packetServerPort = 5000
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
// Each set samples densely around the MTU boundary where fragmentation begins,
// adjusted for protocol overhead:
//   - 190 = approximate HTTP response overhead (headers + framing) for GET
//   - 52 = IP (20) + TCP (32 with options) headers for POST body
//   - 20 = IP header (20 bytes; UDP header is 8 bytes but included in the datagram)
//   - 80 = how far below the boundary to start sampling
//   - 30 = how far above the boundary to continue sampling (TCP)
//   - 60 = narrower upper range for UDP (doesn't fragment the same way)
//   - 5 = step size for dense sampling
func generatePacketLengths(mtu int) (getLengths, postLengths, udpLengths []int) {
	// GET: HTTP response headers (~190 bytes) reduce the payload that fits in a
	// single MTU-sized frame. Sample densely around the fragmentation boundary.
	getLengths = []int{10}
	for i := mtu - 190 - 80; i <= mtu-190+30; i += 5 { // 80 below to 30 above boundary
		getLengths = append(getLengths, i)
	}
	getLengths = append(getLengths, 10000)

	// POST: request body plus IP/TCP headers (52 bytes) determines on-wire size.
	postLengths = []int{10}
	for i := mtu - 52 - 80; i <= mtu-52+30; i += 5 { // 80 below to 30 above boundary
		postLengths = append(postLengths, i)
	}
	postLengths = append(postLengths, 10000)

	// UDP: only IP header (20 bytes) overhead. Narrower upper range (60 below
	// boundary only) since UDP doesn't fragment the same way as TCP.
	udpLengths = []int{10}
	for i := mtu - 20 - 80; i <= mtu-20-60; i += 5 { // 80 below to 60 below boundary
		udpLengths = append(udpLengths, i)
	}

	return getLengths, postLengths, udpLengths
}

// withPacketSizeServer is a conncheck server pod customizer that replaces the
// default image with the PacketSizeServer. See images.PacketSizeServer for the
// endpoints the server exposes.
func withPacketSizeServer(pod *v1.Pod) {
	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].Image = images.PacketSizeServer
		pod.Spec.Containers[i].Args = nil
		if pod.Spec.Containers[i].ReadinessProbe != nil && pod.Spec.Containers[i].ReadinessProbe.HTTPGet != nil {
			pod.Spec.Containers[i].ReadinessProbe.HTTPGet.Path = "/length/1"
		}
	}
}

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Datapath"),
	describe.WithCategory(describe.Networking),
	"Packet Size Verification",
	func() {
		f := utils.NewDefaultFramework("packet-size")

		runPacketTest := func(clientType, targetType int, sameNode bool) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, 6)
			Expect(err).NotTo(HaveOccurred())
			nodesInfo := utils.GetNodesInfo(f, nodes, false)
			nodeNames := nodesInfo.GetNames()
			nodeIPs := nodesInfo.GetIPv4s()
			Expect(len(nodeNames)).To(BeNumerically(">=", 2),
				"packet size tests require at least 2 schedulable worker nodes")

			// Sample packet sizes densely around the cluster's effective pod MTU.
			// The MTU is derived from the Installation status so the test tracks
			// whatever encapsulation / WireGuard config is in use.
			mtu := utils.ExpectedPodMTU(f)
			Expect(mtu).NotTo(BeNil(), "could not detect pod MTU from Installation status")
			getLengths, postLengths, udpLengths := generatePacketLengths(int(*mtu))

			var serverNode string
			if sameNode {
				serverNode = nodeNames[0]
			} else {
				serverNode = nodeNames[1]
			}

			ct := conncheck.NewConnectionTester(f)

			serverName := utils.GenerateRandomName("pkt-srv")
			server := conncheck.NewServer(serverName, f.Namespace,
				conncheck.WithPorts(packetServerPort),
				conncheck.WithNodePortService(),
				conncheck.WithServerPodCustomizer(conncheck.WithNodeName(serverNode)),
				conncheck.WithServerPodCustomizer(withPacketSizeServer),
				conncheck.WithServerSvcCustomizer(func(svc *v1.Service) {
					// Add a UDP port alongside the TCP port for UDP echo testing.
					svc.Spec.Ports = append(svc.Spec.Ports, v1.ServicePort{
						Name:     "udp",
						Port:     int32(packetServerPort),
						Protocol: v1.ProtocolUDP,
					})
				}),
			)
			ct.AddServer(server)

			if clientType == pktClientExt {
				extClient := externalnode.NewClient()
				Expect(extClient).NotTo(BeNil(),
					"external node tests require EXT_IP, EXT_KEY, EXT_USER to be configured")
				ct.Deploy()
				DeferCleanup(ct.Stop)

				// External client uses SSH — build targets and test via ext client helpers.
				target := packetBaseTarget(server, nodeIPs, targetType)
				packetTestExternal(extClient, target, getLengths, postLengths, udpLengths)
			} else {
				clientName := utils.GenerateRandomName("pkt-client")
				clientOpts := []conncheck.ClientOption{
					conncheck.WithClientCustomizer(conncheck.WithNodeName(nodeNames[0])),
					conncheck.WithClientCustomizer(withCurlClient),
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

				baseTarget := packetBaseTarget(server, nodeIPs, targetType)
				packetTestViaConncheck(ct, client, baseTarget, getLengths, postLengths, udpLengths)
			}
		}

		Context("with different packet sizes", func() {
			DescribeTable("using UDP and TCP",
				runPacketTest,
				Entry("pod to pod, same node", pktClientPod, pktTargetPod, true),
				Entry("pod to service, same node", pktClientPod, pktTargetService, true),
				Entry("pod to nodeport, same node", pktClientPod, pktTargetNodePort, true),
				Entry("pod to pod, different nodes", pktClientPod, pktTargetPod, false),
				Entry("pod to service, different nodes", pktClientPod, pktTargetService, false),
				Entry("pod to nodeport, different nodes", pktClientPod, pktTargetNodePort, false),
				Entry("host to pod, different nodes", pktClientHost, pktTargetPod, false),
				Entry("host to service, different nodes", pktClientHost, pktTargetService, false),
				Entry("host to nodeport, different nodes", pktClientHost, pktTargetNodePort, false),
			)

			// External-client entry is gated by the ExternalNode label so pipelines
			// without EXT_IP/EXT_KEY/EXT_USER configured filter it out rather than
			// failing hard.
			framework.Context("external client", describe.WithExternalNode(), func() {
				DescribeTable("using UDP and TCP",
					runPacketTest,
					Entry("external to nodeport", pktClientExt, pktTargetNodePort, false),
				)
			})
		})
	},
)

// packetBaseTarget returns a base target for the given target type. Callers add
// protocol-specific options (WithHTTP for GET/POST, WithUDP for UDP) on top.
type packetTarget struct {
	server    conncheck.Server
	nodeIPs   []string
	typ       int
	podIP     string
	port      int
	nodePort  int
	clusterIP string
}

func packetBaseTarget(server conncheck.Server, nodeIPs []string, targetType int) packetTarget {
	return packetTarget{
		server:    server,
		nodeIPs:   nodeIPs,
		typ:       targetType,
		podIP:     server.Pod().Status.PodIP,
		port:      packetServerPort,
		nodePort:  server.NodePortPort(),
		clusterIP: server.Service().Spec.ClusterIP,
	}
}

func (t packetTarget) getTarget(length int) conncheck.Target {
	opt := conncheck.WithHTTP("GET", fmt.Sprintf("/length/%d", length), nil)
	return t.makeTarget(opt)
}

func (t packetTarget) postTarget(body string) conncheck.Target {
	httpOpt := conncheck.WithHTTP("POST", "/post", nil)
	bodyOpt := conncheck.WithHTTPBody(body)
	return t.makeTargetMultiOpt(httpOpt, bodyOpt)
}

func (t packetTarget) udpTarget(payload string) conncheck.Target {
	opt := conncheck.WithUDP(payload)
	return t.makeTarget(opt)
}

func (t packetTarget) makeTarget(opt conncheck.TargetOption) conncheck.Target {
	return t.makeTargetMultiOpt(opt)
}

func (t packetTarget) makeTargetMultiOpt(opts ...conncheck.TargetOption) conncheck.Target {
	switch t.typ {
	case pktTargetPod:
		return conncheck.NewTarget(t.podIP, conncheck.TypePodIP, conncheck.TCP, opts...).Port(t.port)
	case pktTargetService:
		return t.server.ClusterIPv4(opts...).Port(t.port)
	case pktTargetNodePort:
		return t.server.NodePort(t.nodeIPs[0], opts...)
	default:
		Fail(fmt.Sprintf("unrecognized target type: %d", t.typ))
		return nil
	}
}

// packetTestViaConncheck runs GET, POST, and UDP packet size tests using conncheck.
func packetTestViaConncheck(ct conncheck.ConnectionTester, client conncheck.Client, base packetTarget, getLengths, postLengths, udpLengths []int) {
	for _, length := range getLengths {
		By(fmt.Sprintf("Testing GET with payload length %d", length), func() {
			target := base.getTarget(length)
			Eventually(func() error {
				out, err := ct.Connect(client, target)
				if err != nil {
					return fmt.Errorf("GET failed: %w", err)
				}
				out = strings.TrimSpace(out)
				if len(out) != length {
					return fmt.Errorf("GET response length %d != expected %d", len(out), length)
				}
				return nil
			}, 30*time.Second, 1*time.Second).Should(Succeed(), "GET length=%d", length)
		})
	}

	for _, length := range postLengths {
		By(fmt.Sprintf("Testing POST with payload length %d", length), func() {
			postdata := strings.Repeat("X", length)
			target := base.postTarget(postdata)
			Eventually(func() error {
				out, err := ct.Connect(client, target)
				if err != nil {
					return fmt.Errorf("POST failed: %w", err)
				}
				reported, convErr := strconv.Atoi(strings.TrimSpace(out))
				if convErr != nil {
					return fmt.Errorf("could not parse POST response %q: %w", out, convErr)
				}
				if reported != length {
					return fmt.Errorf("POST reported length %d != expected %d", reported, length)
				}
				return nil
			}, 30*time.Second, 1*time.Second).Should(Succeed(), "POST length=%d", length)
		})
	}

	for _, length := range udpLengths {
		By(fmt.Sprintf("Testing UDP with payload length %d", length), func() {
			payload := generateUDPPayload(length)
			target := base.udpTarget(payload)
			Eventually(func() error {
				out, err := ct.Connect(client, target)
				if err != nil {
					return fmt.Errorf("UDP failed: %w", err)
				}
				out = strings.TrimSpace(out)
				if out != payload {
					return fmt.Errorf("UDP response %q != sent payload", out)
				}
				return nil
			}, 30*time.Second, 1*time.Second).Should(Succeed(), "UDP length=%d", length)
		})
	}
}

// packetTestExternal runs packet tests via an external node SSH client.
// Uses the external node's own curl/nc commands.
func packetTestExternal(ext *externalnode.Client, base packetTarget, getLengths, postLengths, udpLengths []int) {
	target := base.nodeIPs[0] + ":" + strconv.Itoa(base.nodePort)

	for _, length := range getLengths {
		By(fmt.Sprintf("Testing GET with payload length %d (external)", length), func() {
			cmd := ext.Get(target, length)
			Eventually(func() error {
				out, err := ext.Exec("sh", "-c", cmd)
				if err != nil {
					return fmt.Errorf("GET failed: %w", err)
				}
				data, parseErr := packetSplitCurlOutput(out)
				if parseErr != nil {
					return parseErr
				}
				if len(data) != length {
					return fmt.Errorf("GET response length %d != expected %d", len(data), length)
				}
				return nil
			}, 30*time.Second, 1*time.Second).Should(Succeed(), "GET length=%d (external)", length)
		})
	}

	for _, length := range postLengths {
		By(fmt.Sprintf("Testing POST with payload length %d (external)", length), func() {
			postdata := strings.Repeat("X", length)
			cmd := ext.Post(target, postdata)
			Eventually(func() error {
				out, err := ext.Exec("sh", "-c", cmd)
				if err != nil {
					return fmt.Errorf("POST failed: %w", err)
				}
				data, parseErr := packetSplitCurlOutput(out)
				if parseErr != nil {
					return parseErr
				}
				reported, convErr := strconv.Atoi(strings.TrimSpace(data))
				if convErr != nil {
					return fmt.Errorf("could not parse POST response %q: %w", data, convErr)
				}
				if reported != length {
					return fmt.Errorf("POST reported length %d != expected %d", reported, length)
				}
				return nil
			}, 30*time.Second, 1*time.Second).Should(Succeed(), "POST length=%d (external)", length)
		})
	}

	for _, length := range udpLengths {
		By(fmt.Sprintf("Testing UDP with payload length %d (external)", length), func() {
			payload := generateUDPPayload(length)
			cmd := ext.UDP(target, payload)
			Eventually(func() error {
				out, err := ext.Exec("sh", "-c", cmd)
				if err != nil {
					return fmt.Errorf("UDP failed: %w", err)
				}
				out = strings.TrimSpace(out)
				if out != payload {
					return fmt.Errorf("UDP response %q != sent payload", out)
				}
				return nil
			}, 30*time.Second, 1*time.Second).Should(Succeed(), "UDP length=%d (external)", length)
		})
	}
}

// packetSplitCurlOutput returns the response body from curl output invoked
// with -w "\n%{time_total}". The trailing elapsed-time line is discarded.
func packetSplitCurlOutput(stdout string) (string, error) {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("expected 2+ lines in curl output, got %d: %q", len(lines), stdout)
	}
	return strings.Join(lines[:len(lines)-1], "\n"), nil
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
