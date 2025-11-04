/*
Copyright (c) 2025 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package networking

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	k8snet "k8s.io/utils/net"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

// DESCRIPTION: This test verifies the operation of Maglev load balancing algorithm.

// TODO:
// DOCS_URL:
// PRECONDITIONS: Enterprise v3.xx or later; OSS v3.xx or later

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Maglev"),
	describe.WithCategory(describe.Networking),
	describe.WithExternalNode(),
	"Maglev load balancing tests",
	func() {
		var (
			f           = utils.NewDefaultFramework("calico-maglev")
			maglevTests *MaglevTests
			nodeNames   []string
			extNode     *externalnode.Client
		)

		BeforeEach(func() {
			// Initialize external node for testing
			extNode = externalnode.NewClient()
			if extNode == nil {
				Skip("External node not available - required for Maglev testing")
			}

			// Get available nodes for pod distribution
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, 10) // Get up to 10 nodes
			Expect(err).ShouldNot(HaveOccurred())
			if len(nodes.Items) == 0 {
				Fail("No schedulable nodes exist, can't continue test.")
			}

			nodesInfo := utils.GetNodesInfo(f, nodes, false)
			nodeNames = nodesInfo.GetNames()
			nodeIPv4s := nodesInfo.GetIPv4s()
			nodeIPv6s := nodesInfo.GetIPv6s()
			Expect(len(nodeNames)).Should(BeNumerically(">", 0))
			framework.Logf("Found %d nodes for testing: %v", len(nodeNames), nodeNames)

			// Initialize the test helper
			maglevTests = NewMaglevTests(f)

			// Populate the node name to IP mappings for routing (using both IPv4 and IPv6 addresses)
			maglevTests.nodeNameToIPv4 = make(map[string]string)
			maglevTests.nodeNameToIPv6 = make(map[string]string)
			for i, nodeName := range nodeNames {
				if i < len(nodeIPv4s) && nodeIPv4s[i] != "" {
					maglevTests.nodeNameToIPv4[nodeName] = nodeIPv4s[i]
				}
				if i < len(nodeIPv6s) && nodeIPv6s[i] != "" {
					maglevTests.nodeNameToIPv6[nodeName] = nodeIPv6s[i]
				}
			}
			framework.Logf("Node name to IPv4 mapping: %v", maglevTests.nodeNameToIPv4)
			framework.Logf("Node name to IPv6 mapping: %v", maglevTests.nodeNameToIPv6)
		})

		It("test service ip load balancing behavior before and after maglev annotation", func() {
			// Ensure we have at least 3 nodes for the test
			Expect(len(nodeNames)).Should(BeNumerically(">=", 3), "Need at least 3 nodes for this test")

			// Deploy 20 backend pods on node 1 (first node)
			maglevTests.DeployBackendPods(20, []string{nodeNames[0]})
			// Deploy service "netexec" backed by the 20 pods
			maglevTests.DeployService()
			// Add route to external node where packets to service cluster IP go to node 2
			maglevTests.SetupExternalNodeClientRoutingToSpecificNode(extNode, nodeNames[1]) // node 2 (second node)

			// Test random backend selection without Maglev annotation for both IPv4 and IPv6
			maglevTests.TestRandomBackendSelection(extNode, false) // IPv4 test
			maglevTests.TestRandomBackendSelection(extNode, true)  // IPv6 test

			// Enable Maglev on the same service by adding annotation
			maglevTests.EnableMaglev()

			// Set a fixed source port for consistent hashing tests
			maglevTests.SetSourcePort(12345)

			// Test Maglev consistent hashing with the annotation for both IPv4 and IPv6 using first source port
			backendViaNode2IPv4Port1 := maglevTests.TestMaglevConsistentHashing(extNode, false) // IPv4 test with port 12345
			backendViaNode2IPv6Port1 := maglevTests.TestMaglevConsistentHashing(extNode, true)  // IPv6 test with port 12345

			// Test Maglev consistent hashing with a different source port to verify different flows can hash to different backends
			maglevTests.SetSourcePort(23456)                                                    // Change source port
			backendViaNode2IPv4Port2 := maglevTests.TestMaglevConsistentHashing(extNode, false) // IPv4 test with port 23456
			backendViaNode2IPv6Port2 := maglevTests.TestMaglevConsistentHashing(extNode, true)  // IPv6 test with port 23456
			framework.Logf("Maglev hashing with different source ports: IPv4 port 12345->%s, port 23456->%s; IPv6 port 12345->%s, port 23456->%s",
				backendViaNode2IPv4Port1, backendViaNode2IPv4Port2, backendViaNode2IPv6Port1, backendViaNode2IPv6Port2)

			// Reset source port for next tests
			maglevTests.SetSourcePort(12345)

			// Then: Remove the routes from external node to service cluster IPs via node 2
			maglevTests.RemoveExternalNodeClientRoutes(extNode, nodeNames[1])

			// Add route to external node where packets to service cluster IP go to node 3
			maglevTests.SetupExternalNodeClientRoutingToSpecificNode(extNode, nodeNames[2]) // node 3 (third node)

			// Test Maglev consistent hashing again for both IPv4 and IPv6 via node 3 with first source port
			backendViaNode3IPv4Port1 := maglevTests.TestMaglevConsistentHashing(extNode, false) // IPv4 test via node 3 with port 12345
			backendViaNode3IPv6Port1 := maglevTests.TestMaglevConsistentHashing(extNode, true)  // IPv6 test via node 3 with port 12345

			// Test Maglev consistent hashing via node 3 with a different source port
			maglevTests.SetSourcePort(23456)                                                    // Change source port
			backendViaNode3IPv4Port2 := maglevTests.TestMaglevConsistentHashing(extNode, false) // IPv4 test via node 3 with port 23456
			backendViaNode3IPv6Port2 := maglevTests.TestMaglevConsistentHashing(extNode, true)  // IPv6 test via node 3 with port 23456
			framework.Logf("Maglev hashing via node 3 with different source ports: IPv4 port 12345->%s, port 23456->%s; IPv6 port 12345->%s, port 23456->%s",
				backendViaNode3IPv4Port1, backendViaNode3IPv4Port2, backendViaNode3IPv6Port1, backendViaNode3IPv6Port2)

			// Reset source port
			maglevTests.SetSourcePort(12345)

			// Assert that the backend selected via node 3 is the same as that selected via node 2 (for same source port)
			Expect(backendViaNode3IPv4Port1).Should(Equal(backendViaNode2IPv4Port1),
				fmt.Sprintf("Expected IPv4 backend selection to be consistent across nodes: node 2 selected %s, node 3 selected %s",
					backendViaNode2IPv4Port1, backendViaNode3IPv4Port1))

			Expect(backendViaNode3IPv6Port1).Should(Equal(backendViaNode2IPv6Port1),
				fmt.Sprintf("Expected IPv6 backend selection to be consistent across nodes: node 2 selected %s, node 3 selected %s",
					backendViaNode2IPv6Port1, backendViaNode3IPv6Port1))

			// Also verify that the second source port routes to the same backend across nodes
			Expect(backendViaNode3IPv4Port2).Should(Equal(backendViaNode2IPv4Port2),
				fmt.Sprintf("Expected IPv4 backend selection (port 23456) to be consistent across nodes: node 2 selected %s, node 3 selected %s",
					backendViaNode2IPv4Port2, backendViaNode3IPv4Port2))

			Expect(backendViaNode3IPv6Port2).Should(Equal(backendViaNode2IPv6Port2),
				fmt.Sprintf("Expected IPv6 backend selection (port 23456) to be consistent across nodes: node 2 selected %s, node 3 selected %s",
					backendViaNode2IPv6Port2, backendViaNode3IPv6Port2))

			framework.Logf("Maglev cross-node consistency verified for both source ports: IPv4 port 12345->%s, port 23456->%s; IPv6 port 12345->%s, port 23456->%s",
				backendViaNode2IPv4Port1, backendViaNode2IPv4Port2, backendViaNode2IPv6Port1, backendViaNode2IPv6Port2)
		})
	})

type MaglevTests struct {
	f                   *framework.Framework
	serviceClusterIPv4  string
	serviceClusterIPv6  string
	loadBalancerService *v1.Service
	maglevConfig        *MaglevConfig
	nodeNameToIPv4      map[string]string
	nodeNameToIPv6      map[string]string
	connTester          conncheck.ConnectionTester
}

type MaglevConfig struct {
	ServiceName      string
	ServicePort      int32
	SourcePort       int // Source port for requests to test consistent hashing
	NumberOfRequests int // Number of requests to send to the cluster IP for testing
	IntervalSeconds  int // Interval between requests in seconds
}

func NewMaglevTests(f *framework.Framework) *MaglevTests {
	return &MaglevTests{
		f: f,
		maglevConfig: &MaglevConfig{
			ServiceName:      "netexec",
			ServicePort:      8080,
			NumberOfRequests: 10, // Default number of requests for testing
			IntervalSeconds:  1,  // Default interval between requests
		},
		nodeNameToIPv4: make(map[string]string),
		nodeNameToIPv6: make(map[string]string),
	}
}

// parseBackendResponse parses the JSON response from netexec and returns the backend pod name
func (m *MaglevTests) parseBackendResponse(output string) (string, error) {
	// NetexecResponse represents the JSON response from the netexec service
	type NetexecResponse struct {
		Output string `json:"output"`
	}

	var response NetexecResponse
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// Remove the trailing newline from the output
	backendName := strings.TrimSpace(response.Output)

	// Verify this matches our expected backend pod naming pattern (backend-pod-0 to backend-pod-19)
	backendPodPattern := regexp.MustCompile(`^backend-pod-\d+$`)
	if !backendPodPattern.MatchString(backendName) {
		return "", fmt.Errorf("response '%s' does not match expected backend pod naming pattern 'backend-pod-N'", backendName)
	}

	return backendName, nil
}

func (m *MaglevTests) DeployBackendPods(numPods int, nodes []string) {
	By(fmt.Sprintf("deploying %d backend pods for load balancing across %d nodes using conncheck package", numPods, len(nodes)))

	// Create connection tester
	m.connTester = conncheck.NewConnectionTester(m.f)

	// Create individual servers for each backend pod
	for i := 1; i <= numPods; i++ {
		podName := fmt.Sprintf("backend-pod-%d", i)
		// Select node using round-robin: (i-1) % len(nodes) to distribute pods evenly
		selectedNode := nodes[(i-1)%len(nodes)]

		// Create server with conncheck, disable automatic service creation
		server := conncheck.NewServer(podName, m.f.Namespace,
			conncheck.WithServerLabels(map[string]string{
				"app": "netexec",
			}),
			conncheck.WithPorts(8080),
			conncheck.WithAutoCreateService(false), // Don't create individual services
			conncheck.WithServerPodCustomizer(func(pod *v1.Pod) {
				// Schedule pod on specific node
				pod.Spec.NodeName = selectedNode

				// Update container to use netexec image and configuration
				pod.Spec.Containers[0].Image = images.Agnhost
				pod.Spec.Containers[0].Args = []string{"netexec"}

				// Set security context
				pod.Spec.SecurityContext = &v1.PodSecurityContext{
					RunAsNonRoot: ptr.To(true),
					RunAsUser:    ptr.To(int64(1000)),
					SeccompProfile: &v1.SeccompProfile{
						Type: v1.SeccompProfileTypeRuntimeDefault,
					},
				}
				pod.Spec.Containers[0].SecurityContext = &v1.SecurityContext{
					AllowPrivilegeEscalation: ptr.To(false),
					RunAsNonRoot:             ptr.To(true),
					RunAsUser:                ptr.To(int64(1000)),
					Capabilities: &v1.Capabilities{
						Drop: []v1.Capability{"ALL"},
					},
				}
			}),
		)

		// Add server to connection tester
		m.connTester.AddServer(server)
		framework.Logf("Added server %s to be deployed on node %s", podName, selectedNode)
	}

	// Deploy all servers at once
	m.connTester.Deploy()

	// Add cleanup using connTester.Stop()
	DeferCleanup(func() {
		if m.connTester != nil {
			m.connTester.Stop()
		}
	})

	framework.Logf("All %d backend pods are now ready using conncheck", numPods)
}

func (m *MaglevTests) DeployService() {
	By("deploying dual-stack service")

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.maglevConfig.ServiceName,
			Namespace: m.f.Namespace.Name,
		},
		Spec: v1.ServiceSpec{
			Type:           v1.ServiceTypeClusterIP,
			IPFamilies:     []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol},
			IPFamilyPolicy: ptr.To(v1.IPFamilyPolicyPreferDualStack),
			Selector: map[string]string{
				"app": "netexec",
			},
			Ports: []v1.ServicePort{
				{
					Port:     m.maglevConfig.ServicePort,
					Protocol: v1.ProtocolTCP,
				},
			},
		},
	}

	createdService, err := m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Create(context.TODO(), service, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	m.loadBalancerService = createdService

	// Store both IPv4 and IPv6 cluster IPs
	if len(createdService.Spec.ClusterIPs) > 0 {
		for _, clusterIP := range createdService.Spec.ClusterIPs {
			if k8snet.IsIPv6String(clusterIP) {
				m.serviceClusterIPv6 = clusterIP
			} else {
				m.serviceClusterIPv4 = clusterIP
			}
		}
	} else {
		// Fallback to single ClusterIP field
		if k8snet.IsIPv6String(createdService.Spec.ClusterIP) {
			m.serviceClusterIPv6 = createdService.Spec.ClusterIP
		} else {
			m.serviceClusterIPv4 = createdService.Spec.ClusterIP
		}
	}

	DeferCleanup(func() {
		m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Delete(context.TODO(), createdService.Name, metav1.DeleteOptions{})
	})

	framework.Logf("Service cluster IPv4: %s", m.serviceClusterIPv4)
	framework.Logf("Service cluster IPv6: %s", m.serviceClusterIPv6)

	// Wait for service endpoints to be ready
	By("waiting for service endpoints to be ready")
	Eventually(func() bool {
		endpoints, err := m.f.ClientSet.CoreV1().Endpoints(m.f.Namespace.Name).Get(context.TODO(), m.maglevConfig.ServiceName, metav1.GetOptions{})
		if err != nil {
			framework.Logf("Failed to get endpoints for service %s: %v", m.maglevConfig.ServiceName, err)
			return false
		}

		// Check if we have any ready endpoints
		totalEndpoints := 0
		for _, subset := range endpoints.Subsets {
			totalEndpoints += len(subset.Addresses)
		}

		if totalEndpoints == 0 {
			framework.Logf("Service %s has no ready endpoints yet", m.maglevConfig.ServiceName)
			return false
		}

		framework.Logf("Service %s has %d ready endpoints", m.maglevConfig.ServiceName, totalEndpoints)
		return true
	}, 60*time.Second, 2*time.Second).Should(BeTrue(), "Service should have ready endpoints")
}

func (m *MaglevTests) EnableMaglev() {
	By("enabling Maglev on the service with annotation")

	// Get the current service
	service, err := m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Get(context.TODO(), m.maglevConfig.ServiceName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	// Add the Maglev annotation
	if service.Annotations == nil {
		service.Annotations = make(map[string]string)
	}
	service.Annotations["lb.projectcalico.org/external-traffic-strategy"] = "maglev"

	// Update the service
	_, err = m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Update(context.TODO(), service, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())

	framework.Logf("Added Maglev annotation to service %s", m.maglevConfig.ServiceName)

	// Wait for the annotation to be processed by verifying it's present
	By("waiting for Maglev annotation to be applied and processed")
	Eventually(func() bool {
		// Verify the annotation is still present and has been processed
		updatedService, err := m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Get(context.TODO(), m.maglevConfig.ServiceName, metav1.GetOptions{})
		if err != nil {
			framework.Logf("Failed to get service while checking annotation: %v", err)
			return false
		}

		// Check if the Maglev annotation is present
		if updatedService.Annotations == nil {
			return false
		}

		annotationValue, exists := updatedService.Annotations["lb.projectcalico.org/external-traffic-strategy"]
		if !exists || annotationValue != "maglev" {
			framework.Logf("Maglev annotation not found or incorrect value: %s", annotationValue)
			return false
		}

		framework.Logf("Maglev annotation confirmed on service")
		return true
	}, 10*time.Second, 1*time.Second).Should(BeTrue(), "Maglev annotation should be applied and processed")
}

func (m *MaglevTests) SetupExternalNodeClientRoutingToSpecificNode(extNode *externalnode.Client, targetNodeName string) {
	By(fmt.Sprintf("setting up routing from external node to service cluster IPs via node %s", targetNodeName))

	// Set up IPv4 routing if IPv4 cluster IP exists
	if m.serviceClusterIPv4 != "" {
		targetNodeIPv4, exists := m.nodeNameToIPv4[targetNodeName]
		if exists && targetNodeIPv4 != "" {
			// Add route from external node to the service cluster IPv4 via the specified Kubernetes node
			routeCmd := fmt.Sprintf("sudo ip route add %s/32 via %s", m.serviceClusterIPv4, targetNodeIPv4)
			_, err := extNode.Exec("sh", "-c", routeCmd)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to add IPv4 route to %s via %s", m.serviceClusterIPv4, targetNodeIPv4))

			// Add cleanup to remove the IPv4 route
			DeferCleanup(func() {
				deleteRouteCmd := fmt.Sprintf("sudo ip route del %s/32 via %s", m.serviceClusterIPv4, targetNodeIPv4)
				_, err := extNode.Exec("sh", "-c", deleteRouteCmd)
				if err != nil {
					// Route may have already been removed, log but don't fail
					framework.Logf("Note: IPv4 route to %s via %s may have already been removed: %v", m.serviceClusterIPv4, targetNodeIPv4, err)
				}
			})

			framework.Logf("Added IPv4 route to service cluster IP %s via node %s (IP: %s)", m.serviceClusterIPv4, targetNodeName, targetNodeIPv4)
		} else {
			framework.Logf("Warning: No IPv4 address found for node %s, skipping IPv4 route setup", targetNodeName)
		}
	}

	// Set up IPv6 routing if IPv6 cluster IP exists
	if m.serviceClusterIPv6 != "" {
		targetNodeIPv6, exists := m.nodeNameToIPv6[targetNodeName]
		if exists && targetNodeIPv6 != "" {
			// Add route from external node to the service cluster IPv6 via the specified Kubernetes node
			routeCmd := fmt.Sprintf("sudo ip -6 route add %s/128 via %s", m.serviceClusterIPv6, targetNodeIPv6)
			_, err := extNode.Exec("sh", "-c", routeCmd)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to add IPv6 route to %s via %s", m.serviceClusterIPv6, targetNodeIPv6))

			// Add cleanup to remove the IPv6 route
			DeferCleanup(func() {
				deleteRouteCmd := fmt.Sprintf("sudo ip -6 route del %s/128 via %s", m.serviceClusterIPv6, targetNodeIPv6)
				_, err := extNode.Exec("sh", "-c", deleteRouteCmd)
				if err != nil {
					// Route may have already been removed, log but don't fail
					framework.Logf("Note: IPv6 route to %s via %s may have already been removed: %v", m.serviceClusterIPv6, targetNodeIPv6, err)
				}
			})

			framework.Logf("Added IPv6 route to service cluster IP %s via node %s (IP: %s)", m.serviceClusterIPv6, targetNodeName, targetNodeIPv6)
		} else {
			framework.Logf("Warning: No IPv6 address found for node %s, skipping IPv6 route setup", targetNodeName)
		}
	}
}

// RemoveExternalNodeClientRoutes removes the routes to service cluster IPs from the external node
func (m *MaglevTests) RemoveExternalNodeClientRoutes(extNode *externalnode.Client, targetNodeName string) {
	By(fmt.Sprintf("removing routes from external node to service cluster IPs via node %s", targetNodeName))

	// Remove IPv4 routing if IPv4 cluster IP exists
	if m.serviceClusterIPv4 != "" {
		targetNodeIPv4, exists := m.nodeNameToIPv4[targetNodeName]
		if exists && targetNodeIPv4 != "" {
			// Remove route from external node to the service cluster IPv4
			deleteRouteCmd := fmt.Sprintf("sudo ip route del %s/32 via %s", m.serviceClusterIPv4, targetNodeIPv4)
			_, err := extNode.Exec("sh", "-c", deleteRouteCmd)
			if err != nil {
				framework.Logf("Warning: Failed to remove IPv4 route (may not exist): %v", err)
			} else {
				framework.Logf("Removed IPv4 route to service cluster IP %s via node %s (IP: %s)", m.serviceClusterIPv4, targetNodeName, targetNodeIPv4)
			}
		} else {
			framework.Logf("Warning: No IPv4 address found for node %s, skipping IPv4 route removal", targetNodeName)
		}
	}

	// Remove IPv6 routing if IPv6 cluster IP exists
	if m.serviceClusterIPv6 != "" {
		targetNodeIPv6, exists := m.nodeNameToIPv6[targetNodeName]
		if exists && targetNodeIPv6 != "" {
			// Remove route from external node to the service cluster IPv6
			deleteRouteCmd := fmt.Sprintf("sudo ip -6 route del %s/128 via %s", m.serviceClusterIPv6, targetNodeIPv6)
			_, err := extNode.Exec("sh", "-c", deleteRouteCmd)
			if err != nil {
				framework.Logf("Warning: Failed to remove IPv6 route (may not exist): %v", err)
			} else {
				framework.Logf("Removed IPv6 route to service cluster IP %s via node %s (IP: %s)", m.serviceClusterIPv6, targetNodeName, targetNodeIPv6)
			}
		} else {
			framework.Logf("Warning: No IPv6 address found for node %s, skipping IPv6 route removal", targetNodeName)
		}
	}
}

// sendRequestsAndGatherStats sends the configured number of requests to the service and returns backend response counts
func (m *MaglevTests) sendRequestsAndGatherStats(extNode *externalnode.Client, useIPv6 bool, testDescription string) map[string]int {
	ipVersion := "IPv4"
	clusterIP := m.serviceClusterIPv4
	if useIPv6 {
		ipVersion = "IPv6"
		clusterIP = m.serviceClusterIPv6
		if clusterIP == "" {
			Fail("IPv6 cluster IP is not available - dual-stack service creation failed")
		}
	}

	By(fmt.Sprintf("testing %s from external node using %s (source port: %d)", testDescription, ipVersion, m.maglevConfig.SourcePort))

	// Track which backends receive requests and their request counts
	uniqueBackends := make(map[string]int)
	totalRequests := m.maglevConfig.NumberOfRequests

	for i := 0; i < totalRequests; i++ {
		// Use external node to run rapidclient with netexec endpoint to get hostname
		// Use configured source port for consistent testing
		var cmd string
		if useIPv6 {
			// For IPv6, we need to wrap the IP in brackets for the URL
			cmd = fmt.Sprintf("sudo docker run --rm --net=host %s -url http://[%s]:%d/shell?cmd=hostname -port %d",
				images.RapidClient, clusterIP, m.maglevConfig.ServicePort, m.maglevConfig.SourcePort)
		} else {
			cmd = fmt.Sprintf("sudo docker run --rm --net=host %s -url http://%s:%d/shell?cmd=hostname -port %d",
				images.RapidClient, clusterIP, m.maglevConfig.ServicePort, m.maglevConfig.SourcePort)
		}
		output, err := extNode.Exec("sh", "-c", cmd)
		Expect(err).NotTo(HaveOccurred())

		framework.Logf("Request %d (%s): backend response: %s", i+1, ipVersion, output)

		// Parse the JSON response to get the exact backend pod name
		matchedBackend, err := m.parseBackendResponse(output)
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Request %d (%s) failed to parse response: %v", i+1, ipVersion, err))

		framework.Logf("Request %d (%s): matched backend: %s", i+1, ipVersion, matchedBackend)

		// Track unique backends
		uniqueBackends[matchedBackend]++

		time.Sleep(time.Duration(m.maglevConfig.IntervalSeconds) * time.Second)
	}

	framework.Logf("Completed %d requests (%s), all received valid backend responses", totalRequests, ipVersion)
	return uniqueBackends
}

func (m *MaglevTests) TestRandomBackendSelection(extNode *externalnode.Client, useIPv6 bool) {
	ipVersion := "IPv4"
	if useIPv6 {
		ipVersion = "IPv6"
	}

	// Send requests and gather backend response statistics
	uniqueBackends := m.sendRequestsAndGatherStats(extNode, useIPv6, "random backend selection")

	// Assert that requests are distributed across at least 3 different backend pods
	Expect(len(uniqueBackends)).Should(BeNumerically(">=", 3),
		fmt.Sprintf("Expected %s requests to be distributed across at least 3 different backends, but only got %d unique backends: %v",
			ipVersion, len(uniqueBackends), uniqueBackends))

	framework.Logf("Random load balancing verified (%s): %d requests distributed across %d unique backends: %v",
		ipVersion, m.maglevConfig.NumberOfRequests, len(uniqueBackends), uniqueBackends)
}

func (m *MaglevTests) TestMaglevConsistentHashing(extNode *externalnode.Client, useIPv6 bool) string {
	ipVersion := "IPv4"
	if useIPv6 {
		ipVersion = "IPv6"
	}

	// Send requests and gather backend response statistics
	uniqueBackends := m.sendRequestsAndGatherStats(extNode, useIPv6, "Maglev consistent hashing with annotation")

	// Assert that all requests went to exactly one backend (consistent hashing)
	Expect(len(uniqueBackends)).Should(Equal(1),
		fmt.Sprintf("Expected all %s requests to go to exactly 1 backend with Maglev annotation, but got %d unique backends: %v",
			ipVersion, len(uniqueBackends), uniqueBackends))

	// Get the first (and only) backend name for return
	var backendName string
	for name := range uniqueBackends {
		backendName = name
		break // There should only be one backend due to consistent hashing
	}

	framework.Logf("Maglev consistent hashing verified (%s): all %d requests consistently routed to backends: %v", ipVersion, m.maglevConfig.NumberOfRequests, uniqueBackends)
	return backendName
}

// SetSourcePort sets the source port for subsequent requests
func (m *MaglevTests) SetSourcePort(port int) {
	framework.Logf("Setting source port to %d for subsequent requests", port)
	m.maglevConfig.SourcePort = port
}
