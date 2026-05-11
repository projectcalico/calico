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
	"math/rand"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

const defaultExternalIP = "60.70.80.90"

// egressScenario defines a single egress test scenario.
type egressScenario struct {
	// dstPod is the destination pod number (0, 1, or 2).
	dstPod int
	// dstHostNetworked indicates the destination pod is host-networked.
	dstHostNetworked bool
	// accessType is how the client accesses the service.
	accessType string // "clusterIP", "node0NodePort", "node1NodePort", "externalIP"
	// svcOpts are additional server options for the destination service.
	svcOpts []conncheck.ServerOption
	// expectPolicyBypass indicates policy won't be applied (e.g., BPF self-connection).
	expectPolicyBypass bool
	// skipPolicy indicates policy assertions should be skipped with a reason.
	skipPolicy string
}

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Datapath"),
	describe.WithCategory(describe.Networking),
	"Workload Egress Datapath",
	func() {
		//  We set up the following pods on two nodes:
		//
		// +-------------------+ +----------+
		// |       node0       | |  node1   |
		// | +------+ +------+ | | +------+ |
		// | | pod0 | | pod1 | | | | pod2 | |
		// | +------+ +------+ | | +------+ |
		// +-------------------+ +----------+
		//
		// For each pod we set up a NodePort service. Then we test access from
		// pod0 to each target via ClusterIP, NodePort, ExternalIP, and to
		// host-networked pods, with and without egress NetworkPolicy.

		f := utils.NewDefaultFramework("workload-egress")

		var (
			nodeNames []string
			nodeIPs   []string
			bpfMode   bool
		)

		BeforeEach(func() {
			cli, err := client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, 3)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(nodes.Items)).To(BeNumerically(">=", 2),
				"workload egress tests require at least 2 schedulable nodes")

			nodesInfo := utils.GetNodesInfo(f, nodes, false)
			allNames := nodesInfo.GetNames()
			allIPs := nodesInfo.GetIPv4s()
			Expect(len(allNames)).To(BeNumerically(">=", 2),
				"workload egress tests require at least 2 non-master nodes with names")
			Expect(len(allIPs)).To(BeNumerically(">=", 2),
				"workload egress tests require at least 2 non-master nodes with IPv4 addresses")
			nodeNames = allNames[:2]
			nodeIPs = allIPs[:2]
			logrus.Infof("Nodes: %v IPs: %v", nodeNames, nodeIPs)

			// Detect BPF dataplane mode.
			bpfMode = utils.DetectDataplane(cli, f.ClientSet).IsBPF()
		})

		// runEgressTest executes the standard egress test flow for a single scenario.
		runEgressTest := func(
			ct conncheck.ConnectionTester,
			clientPod *conncheck.Client,
			target conncheck.Target,
			expectSNAT bool,
			scenario egressScenario,
			applyLabels map[string]string,
		) {
			expected := reachableNoSNAT
			if expectSNAT {
				expected = reachableSNAT
			}

			By("Allowing connection with no NetworkPolicy")
			checkConnection(ct, clientPod, target, expected)

			if scenario.expectPolicyBypass {
				By("Skipping policy tests — BPF bypasses policy for self-connections")
				return
			}
			if scenario.skipPolicy != "" {
				By(fmt.Sprintf("Skipping policy tests — %s", scenario.skipPolicy))
				return
			}

			By("Denying traffic after installing a default-deny egress policy")
			denyPolicy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      utils.GenerateRandomName("egress-deny"),
					Namespace: f.Namespace.Name,
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: applyLabels},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			denyPolicy, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(ctx, denyPolicy, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_ = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Delete(ctx, denyPolicy.Name, metav1.DeleteOptions{})
			})

			checkConnection(ct, clientPod, target, unreachable)

			if scenario.dstHostNetworked {
				By("Skipping further policy tests — host-networked destination not implemented")
				return
			}
			if scenario.accessType == "node1NodePort" {
				By("Skipping further policy tests — NAT happens on remote node")
				return
			}
			if scenario.accessType == "externalIP" {
				By("Skipping further policy tests — ExternalIP forwarding detection bug")
				return
			}

			By("Allowing traffic after installing a target-specific egress policy")
			serverLabels := map[string]string{"pod-name": fmt.Sprintf("server-%d", scenario.dstPod)}
			allowPolicy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      utils.GenerateRandomName("egress-allow"),
					Namespace: f.Namespace.Name,
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: applyLabels},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					Egress: []networkingv1.NetworkPolicyEgressRule{{
						To: []networkingv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{MatchLabels: serverLabels},
						}},
					}},
				},
			}
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			allowPolicy, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(ctx, allowPolicy, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			checkConnection(ct, clientPod, target, expected)

			By("Denying traffic after removing the target-specific policy")
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Delete(ctx, allowPolicy.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			checkConnection(ct, clientPod, target, unreachable)

			By("Allowing traffic after removing the default-deny policy")
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Delete(ctx, denyPolicy.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			checkConnection(ct, clientPod, target, expected)
		}

		// setupAndRun creates the topology for a scenario and runs the test.
		setupAndRun := func(scenario egressScenario) {
			// Determine which node the destination pod should be on.
			var dstNode string
			if scenario.dstPod <= 1 {
				dstNode = nodeNames[0]
			} else {
				dstNode = nodeNames[1]
			}

			ct := conncheck.NewConnectionTester(f)

			// Create server pod on the appropriate node.
			serverName := fmt.Sprintf("server-%d", scenario.dstPod)
			// Host-networked pods bind directly to the node's network stack, so
			// port 80 (the default) can conflict with other host-networked pods or
			// services on the same node. Use a random high port instead.
			serverPort := 80
			if scenario.dstHostNetworked {
				serverPort = 10000 + rand.Intn(50000)
			}
			serverOpts := []conncheck.ServerOption{
				conncheck.WithEchoServer(),
				conncheck.WithNodePortService(),
				conncheck.WithPorts(serverPort),
				conncheck.WithServerPodCustomizer(conncheck.WithNodeName(dstNode)),
			}
			if scenario.dstHostNetworked {
				serverOpts = append(serverOpts, conncheck.WithHostNetworking())
			}
			serverOpts = append(serverOpts, scenario.svcOpts...)
			server := conncheck.NewServer(serverName, f.Namespace, serverOpts...)
			ct.AddServer(server)

			// For loopback tests (dstPod==0), the source is the server pod itself.
			// For other tests, create a separate client on node0.
			var clientPod *conncheck.Client
			var applyLabels map[string]string

			clientPod = conncheck.NewClient("client-0", f.Namespace,
				conncheck.WithClientCustomizer(conncheck.WithNodeName(nodeNames[0])),
				conncheck.WithClientCustomizer(withCurlClient),
				conncheck.WithClientLabels(map[string]string{"pod-name": "client-0"}),
			)
			ct.AddClient(clientPod)

			ct.Deploy()
			DeferCleanup(ct.Stop)

			applyLabels = map[string]string{"pod-name": clientPod.Name()}

			// Determine the target and expected SNAT behavior.
			expectSNAT := scenario.dstPod == 0 // Loopback always expects SNAT.
			var target conncheck.Target

			// All targets use HTTP GET /clientip for SNAT detection via conncheck.
			clientIPOpt := conncheck.WithHTTP("GET", "/clientip", nil)

			switch scenario.accessType {
			case "clusterIP":
				target = server.ClusterIPv4(clientIPOpt).Port(serverPort)
				if scenario.dstHostNetworked {
					expectSNAT = true
				}
			case "node0NodePort":
				expectSNAT = true
				target = server.NodePort(nodeIPs[0], clientIPOpt)
			case "node1NodePort":
				expectSNAT = true
				target = server.NodePort(nodeIPs[1], clientIPOpt)
			case "externalIP":
				expectSNAT = true
				target = conncheck.NewTarget(defaultExternalIP, conncheck.TypeClusterIP, conncheck.HTTP, clientIPOpt).Port(serverPort)
			default:
				Fail(fmt.Sprintf("unhandled accessType: %s", scenario.accessType))
			}

			// Adjust for BPF mode.
			if bpfMode && scenario.dstPod == 0 {
				scenario.expectPolicyBypass = true
			}

			runEgressTest(ct, clientPod, target, expectSNAT, scenario, applyLabels)
		}

		// ===== ClusterIP scenarios =====

		Context("ClusterIP access", func() {
			It("scenario-0C0: pod0 -> clusterIP -> pod0 (loopback)", func() {
				setupAndRun(egressScenario{
					dstPod:     0,
					accessType: "clusterIP",
				})
			})

			It("scenario-0C1: pod0 -> clusterIP -> pod1 (same node)", func() {
				setupAndRun(egressScenario{
					dstPod:     1,
					accessType: "clusterIP",
				})
			})

			framework.ConformanceIt("scenario-0C2: pod0 -> clusterIP -> pod2 (cross node)", func() {
				setupAndRun(egressScenario{
					dstPod:     2,
					accessType: "clusterIP",
				})
			})
		})

		// ===== NodePort scenarios =====

		Context("NodePort access", func() {
			It("scenario-0N00: pod0 -> node0 NodePort -> pod0", func() {
				setupAndRun(egressScenario{
					dstPod:     0,
					accessType: "node0NodePort",
				})
			})

			It("scenario-0L00: pod0 -> node0 NodePort local-only -> pod0", func() {
				setupAndRun(egressScenario{
					dstPod:     0,
					accessType: "node0NodePort",
					svcOpts:    []conncheck.ServerOption{conncheck.WithExternalTrafficPolicy("Local")},
				})
			})

			It("scenario-0N10: pod0 -> node1 NodePort -> pod0", func() {
				setupAndRun(egressScenario{
					dstPod:     0,
					accessType: "node1NodePort",
				})
			})

			It("scenario-0N11: pod0 -> node1 NodePort -> pod1 (hairpin)", func() {
				setupAndRun(egressScenario{
					dstPod:     1,
					accessType: "node1NodePort",
					skipPolicy: "NAT happens on remote node",
				})
			})

			It("scenario-0N01: pod0 -> node0 NodePort -> pod1 (same node)", func() {
				setupAndRun(egressScenario{
					dstPod:     1,
					accessType: "node0NodePort",
				})
			})

			It("scenario-0L01: pod0 -> node0 NodePort local-only -> pod1", func() {
				setupAndRun(egressScenario{
					dstPod:     1,
					accessType: "node0NodePort",
					svcOpts:    []conncheck.ServerOption{conncheck.WithExternalTrafficPolicy("Local")},
				})
			})

			framework.ConformanceIt("scenario-0N02: pod0 -> node0 NodePort -> pod2 (other node)", func() {
				setupAndRun(egressScenario{
					dstPod:     2,
					accessType: "node0NodePort",
				})
			})

			It("scenario-0N12: pod0 -> node1 NodePort -> pod2 (pod on other node)", func() {
				setupAndRun(egressScenario{
					dstPod:     2,
					accessType: "node1NodePort",
				})
			})

			It("scenario-0L12: pod0 -> node1 NodePort local-only -> pod2", func() {
				setupAndRun(egressScenario{
					dstPod:     2,
					accessType: "node1NodePort",
					svcOpts:    []conncheck.ServerOption{conncheck.WithExternalTrafficPolicy("Local")},
				})
			})
		})

		// ===== ExternalIP scenarios =====

		Context("ExternalIP access", func() {
			It("scenario-0EL1: pod0 -> externalIP local-only -> pod1", func() {
				setupAndRun(egressScenario{
					dstPod:     1,
					accessType: "externalIP",
					svcOpts: []conncheck.ServerOption{
						conncheck.WithExternalIP(defaultExternalIP),
						conncheck.WithExternalTrafficPolicy("Local"),
					},
				})
			})

			It("scenario-0EC1: pod0 -> externalIP Cluster -> pod1", func() {
				setupAndRun(egressScenario{
					dstPod:     1,
					accessType: "externalIP",
					svcOpts: []conncheck.ServerOption{
						conncheck.WithExternalIP(defaultExternalIP),
						conncheck.WithExternalTrafficPolicy("Cluster"),
					},
				})
			})

			framework.ConformanceIt("scenario-0EC2: pod0 -> externalIP Cluster -> pod2 (other node)", func() {
				setupAndRun(egressScenario{
					dstPod:     2,
					accessType: "externalIP",
					svcOpts: []conncheck.ServerOption{
						conncheck.WithExternalIP(defaultExternalIP),
						conncheck.WithExternalTrafficPolicy("Cluster"),
					},
				})
			})

			It("scenario-0EL0: pod0 -> externalIP local-only -> pod0", func() {
				setupAndRun(egressScenario{
					dstPod:     0,
					accessType: "externalIP",
					svcOpts: []conncheck.ServerOption{
						conncheck.WithExternalIP(defaultExternalIP),
						conncheck.WithExternalTrafficPolicy("Local"),
					},
				})
			})

			It("scenario-0EC0: pod0 -> externalIP Cluster -> pod0", func() {
				setupAndRun(egressScenario{
					dstPod:     0,
					accessType: "externalIP",
					svcOpts: []conncheck.ServerOption{
						conncheck.WithExternalIP(defaultExternalIP),
						conncheck.WithExternalTrafficPolicy("Cluster"),
					},
				})
			})
		})

		// ===== Host-networked destination scenarios =====

		Context("Host-networked destination", func() {
			It("scenario-0H1: pod0 -> clusterIP -> host-networked pod1 (same node)", func() {
				setupAndRun(egressScenario{
					dstPod:           1,
					dstHostNetworked: true,
					accessType:       "clusterIP",
					skipPolicy:       "egress policy to host-networked destination not fully implemented",
				})
			})

			It("scenario-0H2: pod0 -> clusterIP -> host-networked pod2 (other node)", func() {
				setupAndRun(egressScenario{
					dstPod:           2,
					dstHostNetworked: true,
					accessType:       "clusterIP",
					skipPolicy:       "egress policy to host-networked destination not fully implemented",
				})
			})
		})
	})
