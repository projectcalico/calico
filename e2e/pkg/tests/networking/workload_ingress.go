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
	"net"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
)

// ingressExpectation describes how ingress policy behaves for a scenario.
type ingressExpectation int

const (
	// noSNAT means the source IP is preserved so pod-selector policy works as expected.
	noSNAT ingressExpectation = iota
	// snatWorkingPolicy means SNAT occurs but policy still works (e.g., via host IP matching).
	snatWorkingPolicy
	// snatNoWorkingPolicy means SNAT breaks policy — both clients appear as the same source IP,
	// so the policy cannot distinguish them and blocks both.
	snatNoWorkingPolicy
	// alwaysAllowed means clients cannot be distinguished (host-networked, shared host IP),
	// so both are always allowed regardless of policy.
	alwaysAllowed
)

func (e ingressExpectation) String() string {
	switch e {
	case noSNAT:
		return "noSNAT"
	case snatWorkingPolicy:
		return "snatWorkingPolicy"
	case snatNoWorkingPolicy:
		return "snatNoWorkingPolicy"
	case alwaysAllowed:
		return "alwaysAllowed"
	default:
		return fmt.Sprintf("unknown(%d)", int(e))
	}
}

// ingressScenario defines a single ingress datapath test scenario.
type ingressScenario struct {
	// num is the scenario number (matches the table in the k8s-e2e reference).
	num int
	// srcNode is the node the client runs on: "node0", "node1", "svcNode", or "external".
	srcNode string
	// hostNetworked indicates whether the client pod uses host networking.
	hostNetworked bool
	// dest describes how the client connects: "clusterIP", "svcNodePort", "node1NodePort", or "node0NodePort".
	dest string
	// Per-dataplane expectations. xtablesExpect covers both iptables and
	// nftables dataplanes, which have identical SNAT behavior.
	bpfExpect     ingressExpectation
	xtablesExpect ingressExpectation
	ipvsExpect    ingressExpectation
	vppExpect     ingressExpectation
}

var ingressScenarioTable = []ingressScenario{
	// Scenario 1: pod on svcNode -> clusterIP
	{
		num:           1,
		srcNode:       "svcNode",
		hostNetworked: false,
		dest:          "clusterIP",
		bpfExpect:     noSNAT,
		xtablesExpect: noSNAT,
		ipvsExpect:    noSNAT,
		vppExpect:     noSNAT,
	},
	// Scenario 2: host-networked pod on svcNode -> clusterIP
	{
		num:           2,
		srcNode:       "svcNode",
		hostNetworked: true,
		dest:          "clusterIP",
		bpfExpect:     alwaysAllowed,
		xtablesExpect: alwaysAllowed,
		ipvsExpect:    alwaysAllowed,
		vppExpect:     alwaysAllowed,
	},
	// Scenario 3: pod on node1 -> clusterIP
	{
		num:           3,
		srcNode:       "node1",
		hostNetworked: false,
		dest:          "clusterIP",
		bpfExpect:     noSNAT,
		xtablesExpect: noSNAT,
		ipvsExpect:    noSNAT,
		vppExpect:     noSNAT,
	},
	// Scenario 4: host-networked pod on node1 -> clusterIP
	{
		num:           4,
		srcNode:       "node1",
		hostNetworked: true,
		dest:          "clusterIP",
		bpfExpect:     noSNAT,
		xtablesExpect: noSNAT,
		ipvsExpect:    snatWorkingPolicy, // IPVS SNATs to tunnel IP, CIDR policy matches it
		vppExpect:     noSNAT,
	},
	// Scenario 5: pod on svcNode -> svcNodePort
	{
		num:           5,
		srcNode:       "svcNode",
		hostNetworked: false,
		dest:          "svcNodePort",
		bpfExpect:     noSNAT,
		xtablesExpect: snatWorkingPolicy,
		ipvsExpect:    snatWorkingPolicy,
		vppExpect:     noSNAT,
	},
	// Scenario 6: host-networked pod on svcNode -> svcNodePort
	{
		num:           6,
		srcNode:       "svcNode",
		hostNetworked: true,
		dest:          "svcNodePort",
		bpfExpect:     alwaysAllowed,
		xtablesExpect: alwaysAllowed,
		ipvsExpect:    alwaysAllowed,
		vppExpect:     alwaysAllowed,
	},
	// Scenario 7: pod on node1 -> svcNodePort
	{
		num:           7,
		srcNode:       "node1",
		hostNetworked: false,
		dest:          "svcNodePort",
		bpfExpect:     noSNAT,
		xtablesExpect: snatNoWorkingPolicy,
		ipvsExpect:    snatNoWorkingPolicy,
		vppExpect:     noSNAT,
	},
	// Scenario 8: host-networked pod on node1 -> svcNodePort
	{
		num:           8,
		srcNode:       "node1",
		hostNetworked: true,
		dest:          "svcNodePort",
		bpfExpect:     noSNAT,
		xtablesExpect: noSNAT,
		ipvsExpect:    snatWorkingPolicy, // IPVS SNATs to tunnel IP, CIDR policy matches it
		vppExpect:     noSNAT,
	},
	// Scenario 9: pod on node1 -> node1NodePort (local NodePort)
	{
		num:           9,
		srcNode:       "node1",
		hostNetworked: false,
		dest:          "node1NodePort",
		bpfExpect:     noSNAT,
		xtablesExpect: snatNoWorkingPolicy,
		ipvsExpect:    snatNoWorkingPolicy,
		vppExpect:     noSNAT,
	},
	// Scenario 10: host-networked pod on node1 -> node1NodePort
	{
		num:           10,
		srcNode:       "node1",
		hostNetworked: true,
		dest:          "node1NodePort",
		bpfExpect:     noSNAT,
		xtablesExpect: noSNAT,
		ipvsExpect:    snatWorkingPolicy, // IPVS SNATs to tunnel IP, CIDR policy matches it
		vppExpect:     noSNAT,
	},
	// Scenario 11: pod on node0 -> node1NodePort (remote NodePort)
	{
		num:           11,
		srcNode:       "node0",
		hostNetworked: false,
		dest:          "node1NodePort",
		bpfExpect:     noSNAT,
		xtablesExpect: snatNoWorkingPolicy,
		ipvsExpect:    snatNoWorkingPolicy,
		vppExpect:     snatNoWorkingPolicy,
	},
	// Scenario 12: host-networked pod on node0 -> node1NodePort
	{
		num:           12,
		srcNode:       "node0",
		hostNetworked: true,
		dest:          "node1NodePort",
		bpfExpect:     noSNAT,
		xtablesExpect: snatWorkingPolicy, // SNATs to tunnel IP, CIDR policy matches it
		ipvsExpect:    snatWorkingPolicy, // SNATs to tunnel IP, CIDR policy matches it
		vppExpect:     snatNoWorkingPolicy,
	},
	// Scenario 13 (localhost NodePort) is intentionally omitted.

	// Scenario 14: external node -> node0NodePort
	{
		num:           14,
		srcNode:       "external",
		hostNetworked: false,
		dest:          "node0NodePort",
		bpfExpect:     noSNAT,
		xtablesExpect: snatNoWorkingPolicy,
		ipvsExpect:    snatNoWorkingPolicy,
		vppExpect:     snatNoWorkingPolicy,
	},
	// Scenario 15: external node -> svcNodePort
	{
		num:           15,
		srcNode:       "external",
		hostNetworked: false,
		dest:          "svcNodePort",
		bpfExpect:     noSNAT,
		xtablesExpect: snatNoWorkingPolicy,
		ipvsExpect:    snatNoWorkingPolicy,
		vppExpect:     noSNAT,
	},
}

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Datapath"),
	describe.WithCategory(describe.Networking),
	"Workload Ingress Datapath",
	func() {
		// Topology used by this suite:
		//
		// +----------+ +----------+ +----------+
		// |  node0   | |  node1   | | svcNode  |
		// |          | | +------+ | | +------+ |
		// |          | | | src  | | | | srv  | |
		// |          | | +------+ | | +------+ |
		// +----------+ +----------+ +----------+
		//
		// The server always runs on svcNode (nodeNames[2]). Clients are created on the
		// node designated by each scenario. For pod-networked scenarios we create two
		// pods (client-a and client-b); an ingress NetworkPolicy selects only client-b,
		// and we verify whether the dataplane correctly enforces that distinction. For
		// host-networked scenarios both clients share the node IP, so we use CIDR-based
		// policies instead of pod-selector policies.

		f := utils.NewDefaultFramework("workload-ingress")

		var (
			nodeNames []string
			nodeIPs   []string
			tunnelIPs []string
			dp        utils.ClusterDataplane
		)

		BeforeEach(func() {
			cli, err := client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Request more nodes than we need so we can filter out the control
			// plane and still have 3 workers.
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, 6)
			Expect(err).NotTo(HaveOccurred())
			nodesInfo := utils.GetNodesInfo(f, nodes, false)
			allNames := nodesInfo.GetNames()
			allIPs := nodesInfo.GetIPv4s()
			allTunnelIPs := nodesInfo.GetTunnelIPs()
			Expect(len(allNames)).To(BeNumerically(">=", 3),
				"workload ingress tests require at least 3 schedulable worker nodes, found %d", len(allNames))
			nodeNames = allNames[:3]
			nodeIPs = allIPs[:3]
			tunnelIPs = allTunnelIPs[:3]
			logrus.Infof("Nodes: %v IPs: %v tunnelIPs: %v", nodeNames, nodeIPs, tunnelIPs)

			dp = utils.DetectDataplane(cli, f.ClientSet)
			logrus.Infof("Cluster dataplane: calico=%s BPF=%v IPVS=%v VPP=%v",
				dp.Calico, dp.IsBPF(), dp.IsIPVS(), dp.IsVPP())
		})

		// expectForDP returns the ingressExpectation appropriate for the detected
		// dataplane. IPVS has its own column; iptables and nftables share xtablesExpect.
		expectForDP := func(s ingressScenario) ingressExpectation {
			switch {
			case dp.IsBPF():
				return s.bpfExpect
			case dp.IsVPP():
				return s.vppExpect
			case dp.IsIPVS():
				return s.ipvsExpect
			default:
				return s.xtablesExpect
			}
		}

		// srcNodeName returns the Kubernetes node name for the scenario's source node.
		srcNodeName := func(srcNode string) string {
			switch srcNode {
			case "node0":
				return nodeNames[0]
			case "node1":
				return nodeNames[1]
			case "svcNode":
				return nodeNames[2]
			default:
				framework.Failf("unknown srcNode %q", srcNode)
				return ""
			}
		}

		// srcNodeIP returns the IPv4 of the scenario's source node.
		srcNodeIP := func(srcNode string) string {
			switch srcNode {
			case "node0":
				return nodeIPs[0]
			case "node1":
				return nodeIPs[1]
			case "svcNode":
				return nodeIPs[2]
			default:
				framework.Failf("unknown srcNode %q", srcNode)
				return ""
			}
		}

		// srcNodeTunnelIP returns the tunnel IP for the scenario's source node.
		srcNodeTunnelIP := func(srcNode string) string {
			switch srcNode {
			case "node0":
				return tunnelIPs[0]
			case "node1":
				return tunnelIPs[1]
			case "svcNode":
				return tunnelIPs[2]
			default:
				framework.Failf("unknown srcNode %q", srcNode)
				return ""
			}
		}

		// buildTarget returns the connection target for the given scenario, using the
		// already-deployed server. All targets use HTTP GET /clientip so that
		// checkConnection can verify SNAT behavior from the response body.
		buildTarget := func(s ingressScenario, server *conncheck.Server) conncheck.Target {
			clientIPOpt := conncheck.WithHTTP("GET", "/clientip", nil)
			switch s.dest {
			case "clusterIP":
				// TODO: Also test IPv6 ClusterIP on dual-stack clusters.
				return server.ClusterIPv4(clientIPOpt).Port(80)
			case "svcNodePort":
				return server.NodePort(nodeIPs[2], clientIPOpt)
			case "node1NodePort":
				return server.NodePort(nodeIPs[1], clientIPOpt)
			case "node0NodePort":
				return server.NodePort(nodeIPs[0], clientIPOpt)
			default:
				framework.Failf("unknown dest %q", s.dest)
				return nil
			}
		}

		// runStandardIngressTest handles all non-external scenarios. It creates
		// client-a and client-b on the source node, establishes a baseline, then
		// installs a deny-all policy followed by an allow policy that selects only
		// client-b (by pod label for pod-networked, by CIDR for host-networked).
		runStandardIngressTest := func(s ingressScenario) {
			expect := expectForDP(s)
			logrus.Infof("Scenario %d: srcNode=%s hostNetworked=%v dest=%s dataplane=%s expect=%s",
				s.num, s.srcNode, s.hostNetworked, s.dest, dp.Calico, expect)

			ct := conncheck.NewConnectionTester(f)

			// Server on svcNode.
			serverName := utils.GenerateRandomName("ingress-srv")
			server := conncheck.NewServer(serverName, f.Namespace,
				conncheck.WithEchoServer(),
				conncheck.WithNodePortService(),
				conncheck.WithServerPodCustomizer(conncheck.WithNodeName(nodeNames[2])),
			)
			ct.AddServer(server)

			clientAName := utils.GenerateRandomName("client-a")
			clientBName := utils.GenerateRandomName("client-b")

			baseClientOpts := func(name string) []conncheck.ClientOption {
				opts := []conncheck.ClientOption{
					conncheck.WithClientLabels(map[string]string{"pod-name": name}),
					conncheck.WithClientCustomizer(conncheck.WithNodeName(srcNodeName(s.srcNode))),
					conncheck.WithClientCustomizer(withCurlClient),
				}
				if s.hostNetworked {
					opts = append(opts, conncheck.WithClientCustomizer(func(pod *corev1.Pod) {
						pod.Spec.HostNetwork = true
					}))
				}
				return opts
			}

			clientA := conncheck.NewClient(clientAName, f.Namespace, baseClientOpts(clientAName)...)
			clientB := conncheck.NewClient(clientBName, f.Namespace, baseClientOpts(clientBName)...)
			ct.AddClient(clientA)
			ct.AddClient(clientB)

			ct.Deploy()
			DeferCleanup(ct.Stop)

			target := buildTarget(s, server)

			By("Verifying baseline: both clients can reach the server before any policy")
			baselineResult := reachableNoSNAT
			if expect != noSNAT {
				baselineResult = reachableSNAT
			}
			checkConnection(ct, clientA, target, baselineResult)
			checkConnection(ct, clientB, target, baselineResult)

			// alwaysAllowed: host-networked clients on the same node share an IP, so a
			// pod-selector policy cannot distinguish them. Install a deny-all to confirm
			// that even then both get through (source IP is the node itself).
			if expect == alwaysAllowed {
				By("Installing deny-all ingress policy (expect alwaysAllowed: cannot distinguish clients)")
				denyAll := ingressCreateDenyAllPolicy(f)
				DeferCleanup(ingressDeletePolicy, f, denyAll.Namespace, denyAll.Name)
				By("Verifying both clients are still reachable (shared host IP, policy has no effect)")
				checkConnection(ct, clientA, target, reachableNoSNAT)
				checkConnection(ct, clientB, target, reachableNoSNAT)
				return
			}

			By("Installing deny-all ingress policy")
			denyAll := ingressCreateDenyAllPolicy(f)
			DeferCleanup(ingressDeletePolicy, f, denyAll.Namespace, denyAll.Name)

			By("Verifying both clients are blocked after deny-all")
			checkConnection(ct, clientA, target, unreachable)
			checkConnection(ct, clientB, target, unreachable)

			if s.hostNetworked {
				// Host-networked pods share the node IP, so we allow by source CIDR
				// rather than pod label. Both client-a and client-b will be affected
				// the same way since they're indistinguishable by source IP.
				nodeIP := srcNodeIP(s.srcNode)
				cidrs := ingressNodeCIDRs(nodeIP, []string{srcNodeTunnelIP(s.srcNode)})
				By(fmt.Sprintf("Installing allow-by-CIDR policy for node CIDRs %v (host-networked scenario)", cidrs))
				allowCIDR := ingressCreateAllowByCIDRPolicy(f, cidrs)
				DeferCleanup(ingressDeletePolicy, f, allowCIDR.Namespace, allowCIDR.Name)

				switch expect {
				case noSNAT:
					By("Verifying both clients are allowed (CIDR policy, source IP preserved)")
					checkConnection(ct, clientA, target, reachableNoSNAT)
					checkConnection(ct, clientB, target, reachableNoSNAT)
				case snatWorkingPolicy:
					By("Verifying both clients are allowed (CIDR policy works despite SNAT)")
					checkConnection(ct, clientA, target, reachableSNAT)
					checkConnection(ct, clientB, target, reachableSNAT)
				case snatNoWorkingPolicy:
					By("Verifying both clients are still blocked (SNAT changes source IP, CIDR policy has no effect)")
					checkConnection(ct, clientA, target, unreachable)
					checkConnection(ct, clientB, target, unreachable)
				}
				return
			}

			// Standard pod-networked scenario: allow by pod-name label of client-b only.
			By(fmt.Sprintf("Installing allow-by-pod-label policy selecting only %s", clientBName))
			allowB := ingressCreateAllowByPodLabelPolicy(f, clientBName)
			DeferCleanup(ingressDeletePolicy, f, allowB.Namespace, allowB.Name)

			switch expect {
			case noSNAT:
				// Source IP is preserved; the pod-selector policy correctly distinguishes
				// client-a from client-b.
				By("Verifying client-a is blocked (not selected by policy)")
				checkConnection(ct, clientA, target, unreachable)
				By("Verifying client-b is allowed (selected by policy)")
				checkConnection(ct, clientB, target, reachableNoSNAT)

			case snatWorkingPolicy:
				// SNAT occurs but policy still works via host IP or equivalent mechanism.
				By("Verifying client-a is blocked")
				checkConnection(ct, clientA, target, unreachable)
				By("Verifying client-b is allowed (policy works despite SNAT)")
				checkConnection(ct, clientB, target, reachableSNAT)

			case snatNoWorkingPolicy:
				// SNAT makes both clients appear as the same source IP. The policy
				// cannot distinguish them, so both are blocked.
				By("Verifying both clients are blocked (SNAT prevents policy from distinguishing source IPs)")
				checkConnection(ct, clientA, target, unreachable)
				checkConnection(ct, clientB, target, unreachable)
			}
		}

		// runExternalIngressTest handles scenarios 14 and 15, where the client is a
		// machine outside the cluster accessed via SSH.
		runExternalIngressTest := func(s ingressScenario) {
			expect := expectForDP(s)
			logrus.Infof("Scenario %d (external): dest=%s dataplane=%s expect=%s",
				s.num, s.dest, dp.Calico, expect)

			extNode := externalnode.NewClient()
			Expect(extNode).NotTo(BeNil(),
				"external node scenarios require EXT_IP, EXT_KEY, and EXT_USER to be configured")

			extIPs := extNode.IPs()
			Expect(extIPs).NotTo(BeEmpty(), "could not determine external node IP addresses")
			logrus.Infof("External node IPs: %v", extIPs)

			// Deploy the server on svcNode.
			ct := conncheck.NewConnectionTester(f)
			serverName := utils.GenerateRandomName("ingress-ext-srv")
			server := conncheck.NewServer(serverName, f.Namespace,
				conncheck.WithEchoServer(),
				conncheck.WithNodePortService(),
				conncheck.WithServerPodCustomizer(conncheck.WithNodeName(nodeNames[2])),
			)
			ct.AddServer(server)
			ct.Deploy()
			DeferCleanup(ct.Stop)

			var targetAddr string
			switch s.dest {
			case "svcNodePort":
				targetAddr = fmt.Sprintf("%s:%d", nodeIPs[2], server.NodePortPort())
			case "node0NodePort":
				targetAddr = fmt.Sprintf("%s:%d", nodeIPs[0], server.NodePortPort())
			default:
				framework.Failf("unsupported dest %q for external scenario", s.dest)
			}

			tryConnect := func() error {
				cmd := fmt.Sprintf("wget -qO- -T 5 http://%s/clientip", targetAddr)
				_, err := extNode.Exec("sh", "-c", cmd)
				return err
			}

			tryConnectBlocked := func() error {
				cmd := fmt.Sprintf("wget -qO- -T 5 http://%s/clientip", targetAddr)
				_, err := extNode.Exec("sh", "-c", cmd)
				if err != nil {
					return nil // blocked as expected
				}
				return fmt.Errorf("expected connection to be blocked but it succeeded")
			}

			By("Verifying baseline: external node can reach the server before any policy")
			Eventually(tryConnect, 30*time.Second, 2*time.Second).Should(Succeed())

			By("Installing deny-all ingress policy")
			denyAll := ingressCreateDenyAllPolicy(f)
			DeferCleanup(ingressDeletePolicy, f, denyAll.Namespace, denyAll.Name)

			By("Verifying external node is blocked after deny-all")
			Eventually(tryConnectBlocked, 30*time.Second, 2*time.Second).Should(Succeed())
			Consistently(tryConnectBlocked, 5*time.Second, 1*time.Second).Should(Succeed())

			// Build /32 (IPv4) or /128 (IPv6) CIDRs for the external node's source IPs.
			cidrs := make([]string, 0, len(extIPs))
			for _, ip := range extIPs {
				if net.ParseIP(ip).To4() != nil {
					cidrs = append(cidrs, ip+"/32")
				} else {
					cidrs = append(cidrs, ip+"/128")
				}
			}
			By(fmt.Sprintf("Installing allow-by-CIDR policy for external node IPs: %v", cidrs))
			allowExt := ingressCreateAllowByCIDRPolicy(f, cidrs)
			DeferCleanup(ingressDeletePolicy, f, allowExt.Namespace, allowExt.Name)

			switch expect {
			case noSNAT:
				By("Verifying external node is allowed (CIDR policy, source IP preserved)")
				Eventually(tryConnect, 30*time.Second, 2*time.Second).Should(Succeed())

			case snatNoWorkingPolicy:
				// SNAT rewrites the source IP so the CIDR allow rule never matches.
				By("Verifying external node is still blocked (SNAT breaks CIDR policy)")
				Consistently(tryConnectBlocked, 10*time.Second, 2*time.Second).Should(Succeed())
			}
		}

		// Register test cases for all scenarios. Scenario 3 (cross-node
		// ClusterIP, pod-networked) is marked as conformance since it's the
		// most fundamental ingress path.
		for _, scenario := range ingressScenarioTable {
			s := scenario // capture loop variable
			if s.srcNode == "external" {
				continue
			}
			name := fmt.Sprintf("scenario-%d: %s hostNet=%v -> %s",
				s.num, s.srcNode, s.hostNetworked, s.dest)
			if s.num == 3 {
				framework.ConformanceIt(name, func() {
					runStandardIngressTest(s)
				})
			} else {
				It(name, func() {
					runStandardIngressTest(s)
				})
			}
		}

		// External node scenarios run from a machine outside the cluster via SSH.
		framework.Context("external node", describe.WithExternalNode(), func() {
			for _, scenario := range ingressScenarioTable {
				s := scenario // capture loop variable
				if s.srcNode != "external" {
					continue
				}
				name := fmt.Sprintf("scenario-%d: %s hostNet=%v -> %s",
					s.num, s.srcNode, s.hostNetworked, s.dest)
				It(name, func() {
					runExternalIngressTest(s)
				})
			}
		})
	},
)

// ingressCreateDenyAllPolicy creates a NetworkPolicy that denies all ingress to
// every pod in the test namespace.
func ingressCreateDenyAllPolicy(f *framework.Framework) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.GenerateRandomName("ingress-deny-all"),
			Namespace: f.Namespace.Name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(ctx, policy, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "creating deny-all ingress policy")
	return created
}

// ingressCreateAllowByPodLabelPolicy creates a NetworkPolicy that allows ingress
// from pods with the given pod-name label value.
func ingressCreateAllowByPodLabelPolicy(f *framework.Framework, clientName string) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.GenerateRandomName("ingress-allow-pod"),
			Namespace: f.Namespace.Name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"pod-name": clientName},
					},
				}},
			}},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(ctx, policy, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "creating allow-by-pod-label ingress policy")
	return created
}

// ingressCreateAllowByCIDRPolicy creates a NetworkPolicy that allows ingress from
// the given list of CIDR strings (e.g. "10.0.0.1/32").
func ingressCreateAllowByCIDRPolicy(f *framework.Framework, cidrs []string) *networkingv1.NetworkPolicy {
	peers := make([]networkingv1.NetworkPolicyPeer, 0, len(cidrs))
	for _, cidr := range cidrs {
		peers = append(peers, networkingv1.NetworkPolicyPeer{
			IPBlock: &networkingv1.IPBlock{CIDR: cidr},
		})
	}
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.GenerateRandomName("ingress-allow-cidr"),
			Namespace: f.Namespace.Name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: peers,
			}},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(ctx, policy, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "creating allow-by-CIDR ingress policy")
	return created
}

// ingressDeletePolicy removes a NetworkPolicy, logging but not failing on errors.
func ingressDeletePolicy(f *framework.Framework, namespace, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := f.ClientSet.NetworkingV1().NetworkPolicies(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		logrus.WithError(err).WithField("policy", name).Info("Failed to delete NetworkPolicy during cleanup")
	}
}

// ingressNodeCIDRs returns /32 CIDRs for a node's primary IP and its tunnel IP
// (if any), deduplicating and skipping empty values.
func ingressNodeCIDRs(nodeIP string, tunnelIPs []string) []string {
	seen := map[string]bool{}
	var cidrs []string
	add := func(ip string) {
		if ip == "" || seen[ip] {
			return
		}
		if net.ParseIP(ip) == nil {
			return
		}
		seen[ip] = true
		cidrs = append(cidrs, ip+"/32")
	}
	add(nodeIP)
	for _, t := range tunnelIPs {
		add(t)
	}
	return cidrs
}
