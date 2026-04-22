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
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	k8snet "k8s.io/utils/net"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
	"github.com/projectcalico/calico/e2e/pkg/utils/format"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

// DESCRIPTION: This test verifies the operation of Maglev load balancing algorithm.

// TODO:
// DOCS_URL:
// PRECONDITIONS: Enterprise v3.23 or later; OSS v3.32 or later

func init() {
	format.RegisterExitErrorFormatter()
}

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Maglev"),
	describe.WithCategory(describe.Networking),
	describe.WithExternalNode(),
	describe.WithDataplane(describe.BPF),
	describe.WithSerial(),
	describe.RequiresAWS(),
	"Maglev load balancing tests",
	func() {
		var (
			f           = utils.NewDefaultFramework("calico-maglev")
			cli         ctrlclient.Client
			maglevTests *MaglevTests
			nodeNames   []string
			extNode     *externalnode.Client
		)

		BeforeEach(func() {
			var err error
			cli, err = client.NewAPIClient(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred(), "failed to create an API client at beginning of setup")

			// Skip unsupported Calico OSS versions.
			if utils.IsCalicoOSS() {
				supported, err := utils.ReleaseStreamIsAtLeast("v3.32")
				Expect(err).NotTo(HaveOccurred(), "Couldn't check OSS release stream")
				if !supported {
					Skip(fmt.Sprintf("Maglev is not supported on OSS release stream %s (requires >=v3.32)", os.Getenv("RELEASE_STREAM")))
				}
			}

			// Skip unsupported Calico Enterprise versions.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			isEE, err := utils.IsCalicoEE(ctx, cli)
			Expect(err).NotTo(HaveOccurred(), "Failed to check if Calico is Enterprise")
			if isEE {
				supported, err := utils.ReleaseStreamIsAtLeast("v3.23")
				Expect(err).NotTo(HaveOccurred(), "Couldn't check EE release stream")
				if !supported {
					Skip(fmt.Sprintf("Maglev is not supported on EE release stream %s (requires >=v3.23)", os.Getenv("RELEASE_STREAM")))
				}
			}

			// Initialize external node for testing
			extNode = externalnode.NewClient()
			if extNode == nil {
				Skip("External node not available - required for Maglev testing")
			}

			// Pre-pull the rapidclient image on the external node to avoid
			// timeout issues when the image is not cached.
			By("pre-pulling rapidclient image on external node")
			prePullCmd := fmt.Sprintf("sudo docker pull %s", images.RapidClient)
			_, err = extNode.ExecTimeout(120, "sh", "-c", prePullCmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to pre-pull rapidclient image on external node")

			// Get available nodes for pod distribution
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, 10) // Get up to 10 nodes
			Expect(err).ShouldNot(HaveOccurred(), "Failed to get schedulable nodes")
			if len(nodes.Items) == 0 {
				Fail("No schedulable nodes exist, can't continue test.")
			}

			nodesInfo := utils.GetNodesInfo(f, nodes, false)
			nodeNames = nodesInfo.GetNames()
			nodeIPv4s := nodesInfo.GetIPv4s()
			nodeIPv6s := nodesInfo.GetIPv6s()
			Expect(len(nodeNames)).Should(BeNumerically(">", 0), "Expected at least one schedulable node")
			framework.Logf("Found %d nodes for testing: %v", len(nodeNames), nodeNames)

			// Verify that the external node shares a subnet with the cluster
			// nodes. The test programs static routes with node IPs as gateways,
			// which requires the gateway to be directly reachable on a connected
			// interface.
			verifyExternalNodeSubnetReachability(extNode, nodeIPv4s)

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

		makeMaglevTest := func(isIPv6 bool) func() {

			ipVer := "IPv4"
			if isIPv6 {
				ipVer = "IPv6"
			}
			return func() {
				maglevTests.SkipUnsupportedIPVersion(isIPv6)
				// Ensure we have at least 3 nodes for the test
				Expect(len(nodeNames)).Should(BeNumerically(">=", 3), "Need at least 3 nodes for this test")

				// Deploy 20 backend pods on node 1 (first node)
				_ = maglevTests.DeployBackendPods(20, []string{nodeNames[0]})
				// Deploy service "netexec" backed by the 20 pods
				maglevTests.DeployService()
				// Add route to external node where packets to service cluster IP go to node 2
				maglevTests.SetupExternalNodeClientRoutingToSpecificNode(extNode, nodeNames[1]) // node 2 (second node)

				// Test random backend selection without Maglev annotation
				maglevTests.TestRandomBackendSelection(extNode, isIPv6)

				// Enable Maglev on the same service by adding annotation
				maglevTests.EnableMaglev()

				// Set a fixed source port for consistent hashing tests
				maglevTests.SetSourcePort(12345)

				// Test Maglev consistent hashing with the annotation using first source port
				backendViaNode2Port1 := maglevTests.TestMaglevConsistentHashing(extNode, isIPv6) // test with port 12345

				// Test Maglev consistent hashing with a different source port to verify different flows can hash to different backends
				maglevTests.SetSourcePort(23456)                                                 // Change source port
				backendViaNode2Port2 := maglevTests.TestMaglevConsistentHashing(extNode, isIPv6) // test with port 23456
				framework.Logf("Maglev hashing with different source ports: %s port 12345->%s, port 23456->%s",
					ipVer, backendViaNode2Port1, backendViaNode2Port2)

				// Reset source port for next tests
				maglevTests.SetSourcePort(12345)

				// Then: Remove the routes from external node to service cluster IPs via node 2
				maglevTests.RemoveExternalNodeClientRoutes(extNode, nodeNames[1])

				// Add route to external node where packets to service cluster IP go to node 3
				maglevTests.SetupExternalNodeClientRoutingToSpecificNode(extNode, nodeNames[2]) // node 3 (third node)

				// Test Maglev consistent hashing again via node 3 with first source port
				backendViaNode3Port1 := maglevTests.TestMaglevConsistentHashing(extNode, isIPv6) // test via node 3 with port 12345

				// Test Maglev consistent hashing via node 3 with a different source port
				maglevTests.SetSourcePort(23456)                                                 // Change source port
				backendViaNode3Port2 := maglevTests.TestMaglevConsistentHashing(extNode, isIPv6) // test via node 3 with port 23456
				framework.Logf("Maglev hashing via node 3 with different source ports: %s port 12345->%s, port 23456->%s",
					ipVer, backendViaNode3Port1, backendViaNode3Port2)

				// Reset source port
				maglevTests.SetSourcePort(12345)

				// Assert that the backend selected via node 3 is the same as that selected via node 2 (for same source port)
				Expect(backendViaNode3Port1).Should(Equal(backendViaNode2Port1),
					fmt.Sprintf("Expected backend selection to be consistent across nodes: node 2 selected %s, node 3 selected %s",
						backendViaNode2Port1, backendViaNode3Port1))

				// Also verify that the second source port routes to the same backend across nodes
				Expect(backendViaNode3Port2).Should(Equal(backendViaNode2Port2),
					fmt.Sprintf("Expected backend selection (port 23456) to be consistent across nodes: node 2 selected %s, node 3 selected %s",
						backendViaNode2Port2, backendViaNode3Port2))

				framework.Logf("Maglev cross-node consistency verified for both source ports: %s port 12345->%s, port 23456->%s",
					ipVer, backendViaNode2Port1, backendViaNode2Port2)
			}
		}

		It("test service ip load balancing behavior before and after maglev annotation (IPv4)", makeMaglevTest(false))
		It("test service ip load balancing behavior before and after maglev annotation (IPv6)", makeMaglevTest(true))

	})

type MaglevTests struct {
	f                  *framework.Framework
	serviceClusterIPv4 string
	serviceClusterIPv6 string
	maglevConfig       *MaglevConfig
	nodeNameToIPv4     map[string]string
	nodeNameToIPv6     map[string]string
	connTester         conncheck.ConnectionTester
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

// IPFamilies returns a list of families compatible with this cluster's configuration - for use in service creation.
func (m *MaglevTests) IPFamilies() []v1.IPFamily {
	families := make([]v1.IPFamily, 0)
	if len(m.nodeNameToIPv4) > 0 {
		framework.Logf("Found IPv4 node IPs; Adding IPv4Protocol to IPFamily list")
		families = append(families, v1.IPv4Protocol)
	}

	if len(m.nodeNameToIPv6) > 0 {
		framework.Logf("Found IPv6 node IPs; Adding IPv6Protocol to IPFamily list")
		families = append(families, v1.IPv6Protocol)
	}

	return families
}

var backendPodPattern = regexp.MustCompile(`^backend-pod-\d+$`)

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
	if !backendPodPattern.MatchString(backendName) {
		return "", fmt.Errorf("response '%s' does not match expected backend pod naming pattern 'backend-pod-N'", backendName)
	}

	return backendName, nil
}

func (m *MaglevTests) SkipUnsupportedIPVersion(isIPv6 bool) {
	if isIPv6 {
		if len(m.nodeNameToIPv6) == 0 {
			Skip("IPv6 is not configured, skipping")
		}
	} else {
		if len(m.nodeNameToIPv4) == 0 {
			Skip("IPv4 is not configured, skipping")
		}
	}
}

func (m *MaglevTests) DeployBackendPods(numPods int, nodes []string) map[string]string {
	By(fmt.Sprintf("deploying %d backend pods for load balancing across %d nodes using conncheck package", numPods, len(nodes)))

	// Create connection tester
	m.connTester = conncheck.NewConnectionTester(m.f)

	// Build pod-to-node mapping based on round-robin deployment.
	podToNode := make(map[string]string)

	// Create individual servers for each backend pod
	for i := 1; i <= numPods; i++ {
		podName := fmt.Sprintf("backend-pod-%d", i)
		// Select node using round-robin: (i-1) % len(nodes) to distribute pods evenly
		selectedNode := nodes[(i-1)%len(nodes)]
		podToNode[podName] = selectedNode

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
	return podToNode
}

func (m *MaglevTests) DeployService() {
	By("deploying service")

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.maglevConfig.ServiceName,
			Namespace: m.f.Namespace.Name,
		},
		Spec: v1.ServiceSpec{
			Type:           v1.ServiceTypeClusterIP,
			IPFamilies:     m.IPFamilies(),
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	createdService, err := m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Create(ctx, service, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "Failed to create service %s", m.maglevConfig.ServiceName)

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
		delCtx, delCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer delCancel()
		_ = m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Delete(delCtx, createdService.Name, metav1.DeleteOptions{})
	})

	framework.Logf("Service cluster IPv4: %s", m.serviceClusterIPv4)
	framework.Logf("Service cluster IPv6: %s", m.serviceClusterIPv6)

	// Wait for service endpoints to be ready
	By("waiting for service endpoints to be ready")
	Eventually(func() bool {
		epCtx, epCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer epCancel()
		endpoints, err := m.f.ClientSet.CoreV1().Endpoints(m.f.Namespace.Name).Get(epCtx, m.maglevConfig.ServiceName, metav1.GetOptions{})
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
	getCtx, getCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer getCancel()
	service, err := m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Get(getCtx, m.maglevConfig.ServiceName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "Failed to get service %s for Maglev annotation", m.maglevConfig.ServiceName)

	// Add the Maglev annotation
	if service.Annotations == nil {
		service.Annotations = make(map[string]string)
	}
	service.Annotations["lb.projectcalico.org/external-traffic-strategy"] = "maglev"

	// Update the service
	updCtx, updCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer updCancel()
	_, err = m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Update(updCtx, service, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred(), "Failed to update service %s with Maglev annotation", m.maglevConfig.ServiceName)

	framework.Logf("Added Maglev annotation to service %s", m.maglevConfig.ServiceName)

	// Wait for the annotation to be processed by verifying it's present
	By("waiting for Maglev annotation to be applied and processed")
	Eventually(func() bool {
		// Verify the annotation is still present and has been processed
		svcCtx, svcCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer svcCancel()
		updatedService, err := m.f.ClientSet.CoreV1().Services(m.f.Namespace.Name).Get(svcCtx, m.maglevConfig.ServiceName, metav1.GetOptions{})
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
			dest := fmt.Sprintf("%s/32", m.serviceClusterIPv4)
			err := addRoute(extNode, dest, targetNodeIPv4, false)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to add IPv4 route to %s via %s", m.serviceClusterIPv4, targetNodeIPv4))

			DeferCleanup(func() {
				removeRoute(extNode, dest, targetNodeIPv4, false)
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
			dest := fmt.Sprintf("%s/128", m.serviceClusterIPv6)
			err := addRoute(extNode, dest, targetNodeIPv6, true)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Failed to add IPv6 route to %s via %s", m.serviceClusterIPv6, targetNodeIPv6))

			DeferCleanup(func() {
				removeRoute(extNode, dest, targetNodeIPv6, true)
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

	if m.serviceClusterIPv4 != "" {
		targetNodeIPv4, exists := m.nodeNameToIPv4[targetNodeName]
		if exists && targetNodeIPv4 != "" {
			removeRoute(extNode, fmt.Sprintf("%s/32", m.serviceClusterIPv4), targetNodeIPv4, false)
			framework.Logf("Removed IPv4 route to service cluster IP %s via node %s (IP: %s)", m.serviceClusterIPv4, targetNodeName, targetNodeIPv4)
		} else {
			framework.Logf("Warning: No IPv4 address found for node %s, skipping IPv4 route removal", targetNodeName)
		}
	}

	if m.serviceClusterIPv6 != "" {
		targetNodeIPv6, exists := m.nodeNameToIPv6[targetNodeName]
		if exists && targetNodeIPv6 != "" {
			removeRoute(extNode, fmt.Sprintf("%s/128", m.serviceClusterIPv6), targetNodeIPv6, true)
			framework.Logf("Removed IPv6 route to service cluster IP %s via node %s (IP: %s)", m.serviceClusterIPv6, targetNodeName, targetNodeIPv6)
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

	for i := range totalRequests {
		// Use external node to run rapidclient with netexec endpoint to get hostname
		// Use configured source port for consistent testing
		ep := net.JoinHostPort(clusterIP, fmt.Sprint(m.maglevConfig.ServicePort))
		cmd := fmt.Sprintf("sudo docker run --rm --net=host %s -url http://%s/shell?cmd=hostname -port %d",
			images.RapidClient, ep, m.maglevConfig.SourcePort)
		output, err := extNode.Exec("sh", "-c", cmd)
		Expect(err).NotTo(HaveOccurred(), "Request %d (%s) to %s failed", i+1, ipVersion, ep)

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

// ErrInvalidNexthop is returned when the kernel rejects a route because the
// gateway address is not on a directly-connected subnet.
type ErrInvalidNexthop struct {
	Gateway string
	Output  string
}

func (e *ErrInvalidNexthop) Error() string {
	return fmt.Sprintf("invalid nexthop gateway %s: %s", e.Gateway, e.Output)
}

// addRoute programs a static route on the external node, routing traffic to
// destCIDR via gatewayIP. Returns *ErrInvalidNexthop when the gateway is not
// directly reachable from the external node (different L2 subnet).
func addRoute(extNode *externalnode.Client, destCIDR, gatewayIP string, ipv6 bool) error {
	var routeCmd string
	if ipv6 {
		routeCmd = fmt.Sprintf("sudo ip -6 route add %s via %s 2>&1", destCIDR, gatewayIP)
	} else {
		routeCmd = fmt.Sprintf("sudo ip route add %s via %s 2>&1", destCIDR, gatewayIP)
	}
	output, err := extNode.Exec("sh", "-c", routeCmd)
	if err != nil {
		if strings.Contains(output, "Nexthop has invalid gateway") ||
			strings.Contains(output, "Network is unreachable") {
			return &ErrInvalidNexthop{Gateway: gatewayIP, Output: output}
		}
		return fmt.Errorf("failed to add route to %s via %s: %s (err: %w)", destCIDR, gatewayIP, output, err)
	}
	return nil
}

// removeRoute removes a static route from the external node. Logs a warning
// if the route doesn't exist instead of failing.
func removeRoute(extNode *externalnode.Client, destCIDR, gatewayIP string, ipv6 bool) {
	var routeCmd string
	if ipv6 {
		routeCmd = fmt.Sprintf("sudo ip -6 route del %s via %s", destCIDR, gatewayIP)
	} else {
		routeCmd = fmt.Sprintf("sudo ip route del %s via %s", destCIDR, gatewayIP)
	}
	_, err := extNode.Exec("sh", "-c", routeCmd)
	if err != nil {
		framework.Logf("Note: route to %s via %s may have already been removed: %v", destCIDR, gatewayIP, err)
	}
}

// verifyExternalNodeSubnetReachability checks that the external node can
// program a static route via a cluster node IP. If the kernel rejects the
// nexthop (nodes are on different L2 subnets), the test is skipped.
func verifyExternalNodeSubnetReachability(extNode *externalnode.Client, nodeIPv4s []string) {
	By("verifying external node can route to cluster nodes")

	if len(nodeIPv4s) == 0 {
		return
	}

	// Try adding a route to a RFC 5737 TEST-NET-2 address via the first
	// cluster node. If the kernel rejects the nexthop, the external node
	// and cluster nodes are on different subnets.
	const testDest = "198.51.100.1/32"
	err := addRoute(extNode, testDest, nodeIPv4s[0], false)
	if err != nil {
		var invalidNexthop *ErrInvalidNexthop
		if errors.As(err, &invalidNexthop) {
			Skip(fmt.Sprintf("External node cannot route to cluster nodes (different subnet) — %v", err))
		}
		// Fail fast: subsequent route programming in the test will hit
		// the same underlying error and fail with less context.
		Expect(err).NotTo(HaveOccurred(), "External node early reachability check failed for an unexpected reason")
	}
	removeRoute(extNode, testDest, nodeIPv4s[0], false)
	framework.Logf("External node subnet reachability verified via node %s", nodeIPv4s[0])
}
