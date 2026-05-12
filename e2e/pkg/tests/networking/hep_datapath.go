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
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	numorstring "github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

// hepScenario defines a single host endpoint datapath test scenario.
type hepScenario struct {
	name string

	// srcPod and dstPod map to the pod layout:
	//   0 = host-networked on node0, 1 = normal on node0,
	//   2 = normal on node1, 3 = host-networked on node1
	srcPod int
	dstPod int

	// Whether source/destination are host-networked.
	srcHostNetworked bool
	dstHostNetworked bool

	// How to access the destination: "podIP", "clusterIP", "nodePort"
	accessType string

	// Policy direction for the HEP GNP: "ingress" or "egress"
	policyDirection string

	// Whether the deny policy applies for AOF=false and AOF=true.
	aofFalsePolicyApplies bool
	aofTruePolicyApplies  bool

	// Only applies to tables-based dataplanes (iptables/nftables).
	tablesDataplaneOnly bool
}

// hepScenarioTable defines all HEP test scenarios.
var hepScenarioTable = []hepScenario{
	// ===== Ingress scenarios =====

	// pod3* → pod IP → pod0* (host-to-host, local process)
	{
		name: "ingress-3-0", srcPod: 3, dstPod: 0,
		srcHostNetworked: true, dstHostNetworked: true,
		accessType: "podIP", policyDirection: "ingress",
		aofFalsePolicyApplies: true, aofTruePolicyApplies: true,
	},
	// pod2 → clusterIP → pod0* (pod-to-host via service)
	{
		name: "ingress-2C0", srcPod: 2, dstPod: 0,
		dstHostNetworked: true,
		accessType:       "clusterIP", policyDirection: "ingress",
		aofFalsePolicyApplies: true, aofTruePolicyApplies: true,
	},
	// pod2 → pod IP → pod1 (forwarded traffic)
	{
		name: "ingress-2-1", srcPod: 2, dstPod: 1,
		accessType: "podIP", policyDirection: "ingress",
		aofFalsePolicyApplies: false, aofTruePolicyApplies: true,
	},
	// pod2 → NodePort → pod1 (forwarded via NodePort)
	{
		name: "ingress-2N1", srcPod: 2, dstPod: 1,
		accessType: "nodePort", policyDirection: "ingress",
		aofFalsePolicyApplies: false, aofTruePolicyApplies: true,
	},
	// pod2 → NodePort → pod2 (hairpin, iptables only)
	{
		name: "ingress-2N2", srcPod: 2, dstPod: 2,
		accessType: "nodePort", policyDirection: "ingress",
		aofFalsePolicyApplies: false, aofTruePolicyApplies: true,
		tablesDataplaneOnly: true,
	},

	// ===== Egress scenarios =====

	// pod1 → pod IP → pod2 (forwarded)
	{
		name: "egress-1-2", srcPod: 1, dstPod: 2,
		accessType: "podIP", policyDirection: "egress",
		aofFalsePolicyApplies: false, aofTruePolicyApplies: true,
	},
	// pod1 → clusterIP → pod2 (forwarded)
	{
		name: "egress-1C2", srcPod: 1, dstPod: 2,
		accessType: "clusterIP", policyDirection: "egress",
		aofFalsePolicyApplies: false, aofTruePolicyApplies: true,
	},
	// pod1 → NodePort → pod2 (forwarded)
	{
		name: "egress-1N2", srcPod: 1, dstPod: 2,
		accessType: "nodePort", policyDirection: "egress",
		aofFalsePolicyApplies: false, aofTruePolicyApplies: true,
	},
	// pod0* → pod IP → pod2 (host egress)
	{
		name: "egress-0-2", srcPod: 0, dstPod: 2,
		srcHostNetworked: true,
		accessType:       "podIP", policyDirection: "egress",
		aofFalsePolicyApplies: true, aofTruePolicyApplies: true,
	},
	// pod0* → clusterIP → pod2 (host egress via service)
	{
		name: "egress-0C2", srcPod: 0, dstPod: 2,
		srcHostNetworked: true,
		accessType:       "clusterIP", policyDirection: "egress",
		aofFalsePolicyApplies: true, aofTruePolicyApplies: true,
	},
	// pod0* → NodePort → pod2 (host egress via NodePort)
	{
		name: "egress-0N2", srcPod: 0, dstPod: 2,
		srcHostNetworked: true,
		accessType:       "nodePort", policyDirection: "egress",
		aofFalsePolicyApplies: true, aofTruePolicyApplies: true,
	},
	// pod0* → clusterIP → pod3* (host-to-host via service)
	{
		name: "egress-0C3", srcPod: 0, dstPod: 3,
		srcHostNetworked: true, dstHostNetworked: true,
		accessType: "clusterIP", policyDirection: "egress",
		aofFalsePolicyApplies: true, aofTruePolicyApplies: true,
	},
	// pod0* → NodePort → pod3* (host-to-host via NodePort)
	{
		name: "egress-0N3", srcPod: 0, dstPod: 3,
		srcHostNetworked: true, dstHostNetworked: true,
		accessType: "nodePort", policyDirection: "egress",
		aofFalsePolicyApplies: true, aofTruePolicyApplies: true,
	},
	// pod2 → NodePort → pod2 (iptables only)
	{
		name: "egress-2N2", srcPod: 2, dstPod: 2,
		accessType: "nodePort", policyDirection: "egress",
		aofFalsePolicyApplies: false, aofTruePolicyApplies: true,
		tablesDataplaneOnly: true,
	},
	// pod2 → NodePort → pod1 (forwarded, policy never applies for egress)
	{
		name: "egress-2N1", srcPod: 2, dstPod: 1,
		accessType: "nodePort", policyDirection: "egress",
		aofFalsePolicyApplies: false, aofTruePolicyApplies: false,
	},
}

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Host-Protection"),
	describe.WithSerial(), // Creates cluster-scoped HEPs and GNPs.
	describe.WithCategory(describe.Networking),
	"Host Endpoint Datapath",
	func() {
		// Topology:
		//
		// +-------------------+ +------------------+
		// |       node0       | |       node1      |
		// | +------+ +------+ | | +------+ +------+|
		// | | pod0*|| pod1 | | | | pod2 || pod3*||
		// | +------+ +------+ | | +------+ +------+|
		// +-------------------+ +------------------+
		//
		// pod0 and pod3 are host-networked.
		// HEP is created on node0.
		// Each pod has a NodePort service backed by an EchoServer.

		f := utils.NewDefaultFramework("hep-datapath")

		var (
			cli         ctrlclient.Client
			dp          utils.ClusterDataplane
			encapIface  string
			nodeNames   []string
			nodeIPs     []string
			calicoNames []string
		)

		// Pod index → node index mapping.
		podNode := map[int]int{0: 0, 1: 0, 2: 1, 3: 1}

		BeforeEach(func() {
			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			nodes, err := e2enode.GetBoundedReadySchedulableNodes(ctx, f.ClientSet, 6)
			Expect(err).NotTo(HaveOccurred())
			nodesInfo := utils.GetNodesInfo(f, nodes, false)
			allNames := nodesInfo.GetNames()
			Expect(len(allNames)).To(BeNumerically(">=", 2),
				"HEP datapath tests require at least 2 schedulable worker nodes, found %d", len(allNames))
			nodeNames = allNames[:2]
			nodeIPs = nodesInfo.GetIPv4s()[:2]
			calicoNames = nodesInfo.GetCalicoNames()[:2]
			logrus.Infof("HEP nodes: %v IPs: %v calico: %v", nodeNames, nodeIPs, calicoNames)

			dp = utils.DetectDataplane(cli, f.ClientSet)
			encapIface = detectEncapInterface(cli)
			logrus.Infof("Encap interface: %q", encapIface)
		})

		// hepInterfaceName returns the interface name to use for the HEP based on
		// the scenario and encapsulation mode. On tunnel-based dataplanes, forwarded
		// traffic traverses the tunnel device rather than eth0.
		hepInterfaceName := func(s hepScenario) string {
			if s.dstHostNetworked {
				// Traffic to a host-networked pod goes directly to the host — use default.
				return ""
			}
			if s.srcHostNetworked {
				// Host-originated traffic to a service backend routes via tunnel.
				if encapIface != "" {
					return encapIface
				}
				return ""
			}
			if s.srcPod != s.dstPod {
				// Forwarded pod-to-pod traffic goes via tunnel on overlay networks.
				// Special case: ingress-2N1 on iptables/nftables. NodePort DNAT happens
				// before routing, so traffic arrives on the host interface directly
				// rather than via the tunnel device.
				if s.accessType == "nodePort" && s.srcPod == 2 && s.policyDirection == "ingress" &&
					(dp.Calico == utils.DataplaneIptables || dp.Calico == utils.DataplaneNftables) {
					return ""
				}
				if encapIface != "" {
					return encapIface
				}
				return ""
			}
			// Same-pod NodePort egress (egress-2N2) — traffic routes back via tunnel.
			if s.accessType == "nodePort" && s.srcPod == 2 && s.policyDirection == "egress" {
				if encapIface != "" {
					return encapIface
				}
			}
			return ""
		}

		// runHEPScenario executes a single HEP test scenario for a given AOF setting.
		runHEPScenario := func(s hepScenario, applyOnForward bool) {
			policyApplies := s.aofFalsePolicyApplies
			if applyOnForward {
				policyApplies = s.aofTruePolicyApplies
			}

			logrus.Infof("HEP scenario %s: AOF=%v policyApplies=%v srcPod=%d dstPod=%d access=%s dir=%s",
				s.name, applyOnForward, policyApplies, s.srcPod, s.dstPod, s.accessType, s.policyDirection)

			ct := conncheck.NewConnectionTester(f)

			// Create the destination server on the appropriate node.
			dstNode := nodeNames[podNode[s.dstPod]]
			serverName := utils.GenerateRandomName("hep-srv")
			serverOpts := []conncheck.ServerOption{
				conncheck.WithEchoServer(),
				conncheck.WithNodePortService(),
				conncheck.WithServerPodCustomizer(conncheck.WithNodeName(dstNode)),
			}
			if s.dstHostNetworked {
				serverOpts = append(serverOpts, conncheck.WithHostNetworking())
			}
			server := conncheck.NewServer(serverName, f.Namespace, serverOpts...)
			ct.AddServer(server)

			// Create the source client on the appropriate node.
			srcNode := nodeNames[podNode[s.srcPod]]
			clientName := utils.GenerateRandomName("hep-client")
			clientOpts := []conncheck.ClientOption{
				conncheck.WithClientCustomizer(conncheck.WithNodeName(srcNode)),
				conncheck.WithClientCustomizer(withCurlClient),
			}
			if s.srcHostNetworked {
				clientOpts = append(clientOpts, conncheck.WithClientCustomizer(func(pod *v1.Pod) {
					pod.Spec.HostNetwork = true
				}))
			}
			clientPod := conncheck.NewClient(clientName, f.Namespace, clientOpts...)
			ct.AddClient(clientPod)

			ct.Deploy()
			DeferCleanup(ct.Stop)

			// Build the target based on access type. Use HTTP with /clientip
			// so checkConnection can parse the source IP for SNAT detection.
			clientIPOpt := conncheck.WithHTTP("GET", "/clientip", nil)
			var target conncheck.Target
			expectSNAT := false
			switch s.accessType {
			case "podIP":
				target = conncheck.NewTarget(server.Pod().Status.PodIP, conncheck.TypePodIP, conncheck.TCP, clientIPOpt).Port(80)
			case "clusterIP":
				// TODO: Also test IPv6 ClusterIP on dual-stack clusters.
				target = server.ClusterIPv4(clientIPOpt).Port(80)
				if s.dstHostNetworked {
					expectSNAT = true
				}
			case "nodePort":
				expectSNAT = true
				target = server.NodePort(nodeIPs[0], clientIPOpt) // HEP is on node0
			default:
				Fail(fmt.Sprintf("unhandled accessType: %s", s.accessType))
			}

			baseline := reachableNoSNAT
			if expectSNAT {
				baseline = reachableSNAT
			}

			By("Verifying connectivity with no HEP")
			checkConnection(ct, clientPod, target, baseline)

			// Create a GNP allowing kubectl exec to port 10250 on the HEP node.
			// This must exist before the HEP to avoid breaking kubectl exec.
			kubeletPolicy := &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: utils.GenerateRandomName("hep-kubelet")},
				Spec: v3.GlobalNetworkPolicySpec{
					Order:          ptr.To(800.0),
					Selector:       `hep == "node0"`,
					ApplyOnForward: false,
					Ingress: []v3.Rule{{
						Action:   v3.Allow,
						Protocol: protocolTCP(),
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(10250)},
						},
					}},
					Egress: []v3.Rule{{
						Action:   v3.Allow,
						Protocol: protocolTCP(),
						Source: v3.EntityRule{
							Ports: []numorstring.Port{numorstring.SinglePort(10250)},
						},
					}},
				},
			}
			createCtx, createCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer createCancel()
			Expect(cli.Create(createCtx, kubeletPolicy)).To(Succeed())
			DeferCleanup(func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cleanupCancel()
				if err := cli.Delete(cleanupCtx, kubeletPolicy); err != nil && !apierrors.IsNotFound(err) {
					framework.Logf("WARNING: failed to delete kubelet policy: %v", err)
				}
			})

			// Create the HostEndpoint on node0.
			By("Creating HostEndpoint on node0")
			hep := &v3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name:   utils.GenerateRandomName("hep"),
					Labels: map[string]string{"hep": "node0"},
				},
				Spec: v3.HostEndpointSpec{
					Node:        calicoNames[0],
					ExpectedIPs: []string{nodeIPs[0]},
				},
			}
			ifaceName := hepInterfaceName(s)
			if ifaceName != "" {
				hep.Spec.InterfaceName = ifaceName
			}
			hepCtx, hepCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer hepCancel()
			Expect(cli.Create(hepCtx, hep)).To(Succeed())
			DeferCleanup(func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cleanupCancel()
				if err := cli.Delete(cleanupCtx, hep); err != nil && !apierrors.IsNotFound(err) {
					framework.Logf("WARNING: failed to delete HEP: %v", err)
				}
			})

			// Check whether the HEP causes default deny.
			isDefaultDeny := (s.dstHostNetworked && s.policyDirection == "ingress") ||
				(s.srcHostNetworked && s.policyDirection == "egress")
			if isDefaultDeny {
				By("Verifying HEP default-denies traffic to/from host-networked pod")
				checkConnection(ct, clientPod, target, unreachable)
			} else {
				By("Verifying HEP does not block forwarded traffic without AOF policy")
				checkConnection(ct, clientPod, target, baseline)
			}

			// Create the allow GNP (order 500).
			By("Creating allow GNP with ApplyOnForward=" + fmt.Sprint(applyOnForward))
			allowPolicy := hepBuildGNP(
				utils.GenerateRandomName("hep-allow"),
				500,
				applyOnForward,
				s.policyDirection,
				v3.Allow,
			)
			allowCtx, allowCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer allowCancel()
			Expect(cli.Create(allowCtx, allowPolicy)).To(Succeed())
			DeferCleanup(func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cleanupCancel()
				if err := cli.Delete(cleanupCtx, allowPolicy); err != nil && !apierrors.IsNotFound(err) {
					framework.Logf("WARNING: failed to delete allow policy: %v", err)
				}
			})

			By("Verifying traffic is allowed after allow policy")
			checkConnection(ct, clientPod, target, baseline)

			// Create the deny GNP with higher priority (order 200).
			By("Creating deny GNP with lower order (higher priority)")
			denyPolicy := hepBuildGNP(
				utils.GenerateRandomName("hep-deny"),
				200,
				applyOnForward,
				s.policyDirection,
				v3.Deny,
			)
			denyCtx, denyCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer denyCancel()
			Expect(cli.Create(denyCtx, denyPolicy)).To(Succeed())
			DeferCleanup(func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cleanupCancel()
				if err := cli.Delete(cleanupCtx, denyPolicy); err != nil && !apierrors.IsNotFound(err) {
					framework.Logf("WARNING: failed to delete deny policy: %v", err)
				}
			})

			if policyApplies {
				By("Verifying deny policy blocks traffic (policy applies)")
				checkConnection(ct, clientPod, target, unreachable)
			} else {
				By("Verifying deny policy does NOT block traffic (policy does not apply to forwarded traffic)")
				checkConnection(ct, clientPod, target, baseline)
			}
		}

		for _, scenario := range hepScenarioTable {
			if scenario.tablesDataplaneOnly {
				continue
			}
			s := scenario // capture
			Context(s.name, func() {
				It(fmt.Sprintf("ApplyOnForward=false, %s", s.policyDirection), func() {
					runHEPScenario(s, false)
				})

				It(fmt.Sprintf("ApplyOnForward=true, %s", s.policyDirection), func() {
					runHEPScenario(s, true)
				})
			})
		}

		// Xtables-only scenarios — only valid on iptables/nftables dataplanes.
		framework.Context("xtables-only", describe.RequiresXtables(), func() {
			for _, scenario := range hepScenarioTable {
				if !scenario.tablesDataplaneOnly {
					continue
				}
				s := scenario // capture
				Context(s.name, func() {
					It(fmt.Sprintf("ApplyOnForward=false, %s", s.policyDirection), func() {
						if dp.IsBPF() || dp.IsVPP() {
							Fail("This scenario only applies to xtables-based dataplanes (iptables/nftables)")
						}
						runHEPScenario(s, false)
					})

					It(fmt.Sprintf("ApplyOnForward=true, %s", s.policyDirection), func() {
						if dp.IsBPF() || dp.IsVPP() {
							Fail("This scenario only applies to xtables-based dataplanes (iptables/nftables)")
						}
						runHEPScenario(s, true)
					})
				})
			}
		})
	},
)

// hepBuildGNP creates a GlobalNetworkPolicy for HEP testing.
func hepBuildGNP(name string, order float64, applyOnForward bool, direction string, action v3.Action) *v3.GlobalNetworkPolicy {
	gnp := &v3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.GlobalNetworkPolicySpec{
			Order:          ptr.To(order),
			Selector:       `hep == "node0"`,
			ApplyOnForward: applyOnForward,
		},
	}

	rule := v3.Rule{
		Action:   action,
		Protocol: protocolTCP(),
		Destination: v3.EntityRule{
			Ports: []numorstring.Port{numorstring.SinglePort(80)},
		},
	}

	if direction == "ingress" {
		gnp.Spec.Ingress = []v3.Rule{rule}
		gnp.Spec.Egress = []v3.Rule{{Action: v3.Allow}}
	} else {
		gnp.Spec.Ingress = []v3.Rule{{Action: v3.Allow}}
		gnp.Spec.Egress = []v3.Rule{rule}
	}

	return gnp
}

// protocolTCP returns a numorstring protocol value for TCP.
func protocolTCP() *numorstring.Protocol {
	p := numorstring.ProtocolFromString("TCP")
	return &p
}
