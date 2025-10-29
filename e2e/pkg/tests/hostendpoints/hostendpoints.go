/*
Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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

package hostendpoints

import (
	"context"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	v1 "k8s.io/api/core/v1"
	errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
)

// These tests use a hostNetworked  server pod to simulate network connectivity to the hostEndpoint.
// This is made possible by the fact that hostNetworked pods are subjected to the policies of
// a hostEndpoint.
//
// The test flow is as follows:
// 1. Run a hostNetworked server pod.
// 2. Create a HEP on the node it lands on.
// 3. Create test network policy
// 4. Test the connectivity from clients on other nodes to the hostnetworked pod.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithFeature("Host-Protection"),
	describe.WithSerial(),
	"host endpoint tests",
	func() {
		f := utils.NewDefaultFramework("hep")
		var cli ctrlclient.Client

		var hepNodeName, hepPolicyName string

		// Previously used 9090 and 9091 but these clash with health ports on some systems.
		const hepPort1 = 9190
		const hepPort2 = 9191

		// Policies used in the test.
		var defaultAllow *v3.GlobalNetworkPolicy
		var allowLogCollection *v3.GlobalNetworkPolicy

		// avoidNodeCustomizer is used to ensure our client pod is not on the same node
		// as the hostEndpoint, and that it isn't on the master node.
		avoidNodeCustomizer := func(pod *v1.Pod) {
			pod.Spec.Affinity = &v1.Affinity{
				NodeAffinity: &v1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
						NodeSelectorTerms: []v1.NodeSelectorTerm{
							{
								MatchExpressions: []v1.NodeSelectorRequirement{
									{
										Key:      "node-role.kubernetes.io/master",
										Operator: v1.NodeSelectorOpDoesNotExist,
									},
									{
										Key:      "node-role.kubernetes.io/control-plane",
										Operator: v1.NodeSelectorOpDoesNotExist,
									},
								},
							},
						},
					},
				},
				PodAntiAffinity: &v1.PodAntiAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []v1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"pod-name": "server"},
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			}
		}

		var checker conncheck.ConnectionTester
		var hepServer1 *conncheck.Server
		var client1 *conncheck.Client
		var hep *v3.HostEndpoint

		BeforeEach(func() {
			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

			// Launch a hostNetworked server pod.
			checker = conncheck.NewConnectionTester(f)
			hepServer1 = conncheck.NewServer("server", f.Namespace, conncheck.WithPorts(hepPort1, hepPort2), conncheck.WithHostNetworking())
			client1 = conncheck.NewClient("client", f.Namespace, conncheck.WithClientCustomizer(avoidNodeCustomizer))
			checker.AddServer(hepServer1)
			checker.AddClient(client1)
			checker.Deploy()

			// Applying a hep without any networkpolicy in place will block all inbound and outbound
			// connectivity, including the kubelet's connection to the apiserver, which can
			// disrupt core cluster functionality. This defaultAllow-egress policy
			// simplifies the test by ensuring that outbound connections are allowed.
			defaultAllow = &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "heptest-default-allow",
				},
				Spec: v3.GlobalNetworkPolicySpec{
					Selector: "heptest == \"heptest\"",
					Egress: []v3.Rule{
						{
							Action: v3.Allow,
						},
					},
				},
			}

			// The API server needs to contact the node on port 10250 to
			// get pod logs - important for diags collection.
			allowLogCollection = &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-log-collection",
				},
				Spec: v3.GlobalNetworkPolicySpec{
					Selector: "heptest == \"heptest\"",
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: &numorstring.Protocol{Type: numorstring.NumOrStringString, StrVal: "TCP"},
							Destination: v3.EntityRule{
								Ports: []numorstring.Port{
									numorstring.SinglePort(10250),
								},
							},
						},
					},
				},
			}

			// Get the pod to find out its nodeName, as that information isn't available until
			// it is running.
			pod := hepServer1.Pod()

			// Note that Kubernetes node name is not strictly the same as the calico node name, and its the calico
			// node name that we need for the HEP. But we know these values will match for our rigs so in the interest
			// of keeping things simple, just use the k8s nodename.
			hepNodeName = pod.Spec.NodeName

			// The policy name may only contain lowercase alphanumeric and dashes
			hepPolicyName = strings.ToLower(strings.ReplaceAll(pod.Spec.NodeName, ".", "-"))

			// Create our defaultAllow policy so we don't lock up the node.
			err = cli.Create(context.Background(), defaultAllow)
			Expect(err).NotTo(HaveOccurred())

			// Create policy to allow log collection.
			err = cli.Create(context.Background(), allowLogCollection)
			Expect(err).NotTo(HaveOccurred())

			// Create our hostEndpoint - it is created with the same name as the GNP.
			hep = createHostEndpoint(cli, hepPolicyName, hepNodeName, hepPort1, pod.Status.HostIP)
		})

		AfterEach(func() {
			checker.Stop()

			// Clean up any policies / heps we created.
			err := cli.Delete(context.Background(), defaultAllow)
			if err != nil && !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())
			}
			err = cli.Delete(context.Background(), allowLogCollection)
			if err != nil && !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())
			}
			err = cli.Delete(context.Background(), hep)
			if err != nil && !errors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())
			}
		})

		It("should block all inbound connections by default", func() {
			checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort1))
			checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort2))
			checker.Execute()
		})

		It("should allow inbound connections with an allow-all", func() {
			// Create a networkpolicy that allows all incoming connections.
			// Assert client can now reach the host networked pod.
			policy := &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: hepPolicyName,
				},
				Spec: v3.GlobalNetworkPolicySpec{
					Selector: fmt.Sprintf("host-endpoint == \"%s\"", hepNodeName),
					Ingress: []v3.Rule{
						{
							Action: v3.Allow,
						},
					},
				},
			}
			err := cli.Create(context.Background(), policy)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(context.Background(), policy)
				Expect(err).NotTo(HaveOccurred())
			}()

			checker.ExpectSuccess(client1, hepServer1.ServiceDomain().Port(hepPort1))
			checker.ExpectSuccess(client1, hepServer1.ServiceDomain().Port(hepPort2))
			checker.Execute()
		})

		framework.ConformanceIt("should allow connections using a named port", func() {
			By("asserting connections do not work prior to creating the GNP", func() {
				checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort1))
				checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort2))
				checker.Execute()
				checker.ResetExpectations()
			})

			policy := &v3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: hepPolicyName,
				},
				Spec: v3.GlobalNetworkPolicySpec{
					Selector: fmt.Sprintf("host-endpoint == \"%s\"", hepNodeName),
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: &numorstring.Protocol{Type: numorstring.NumOrStringString, StrVal: "TCP"},
							Destination: v3.EntityRule{
								Ports: []numorstring.Port{
									numorstring.NamedPort("hepport"),
								},
							},
						},
					},
				},
			}

			err := cli.Create(context.Background(), policy)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := cli.Delete(context.Background(), policy)
				Expect(err).NotTo(HaveOccurred())
			}()

			// The named port should be accessible, the other port should not.
			checker.ExpectSuccess(client1, hepServer1.ServiceDomain().Port(hepPort1))
			checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort2))
			checker.Execute()
		})

		Context("doNotTrack policy", func() {
			It("should deny connections to the specified port in a doNotTrack deny policy", func() {
				By("asserting connections do not work initially", func() {
					checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort1))
					checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort2))
					checker.Execute()
					checker.ResetExpectations()
				})

				// create a networkpolicy that allows all incoming connections.
				// assert client can ping hep
				allowIngressPolicy := &v3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("%s-allow-all", hepPolicyName),
					},
					Spec: v3.GlobalNetworkPolicySpec{
						Selector: fmt.Sprintf("host-endpoint == \"%s\"", hepNodeName),
						Ingress: []v3.Rule{
							{
								Action: v3.Allow,
							},
						},
					},
				}

				By("creating an allow-all GNP allowing all traffic", func() {
					err := cli.Create(context.Background(), allowIngressPolicy)
					Expect(err).NotTo(HaveOccurred())
				})
				defer func() {
					err := cli.Delete(context.Background(), allowIngressPolicy)
					Expect(err).NotTo(HaveOccurred())
				}()

				By("asserting connections work now prior to creating the doNotTrack GNP", func() {
					checker.ExpectSuccess(client1, hepServer1.ServiceDomain().Port(hepPort1))
					checker.ExpectSuccess(client1, hepServer1.ServiceDomain().Port(hepPort2))
					checker.Execute()
					checker.ResetExpectations()
				})

				doNotTrackPolicy := &v3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: hepPolicyName,
					},
					Spec: v3.GlobalNetworkPolicySpec{
						Selector:       fmt.Sprintf("host-endpoint == \"%s\"", hepNodeName),
						ApplyOnForward: true,
						DoNotTrack:     true,
						Ingress: []v3.Rule{
							{
								Action:   v3.Deny,
								Protocol: &numorstring.Protocol{Type: numorstring.NumOrStringString, StrVal: "TCP"},
								Destination: v3.EntityRule{
									Ports: []numorstring.Port{
										numorstring.NamedPort("hepport"),
									},
								},
							},
						},
					},
				}

				By(fmt.Sprintf("creating a doNotTrack GNP denying packets to a single named port (tcp %d)", hepPort1), func() {
					err := cli.Create(context.Background(), doNotTrackPolicy)
					Expect(err).NotTo(HaveOccurred())
				})
				defer func() {
					err := cli.Delete(context.Background(), doNotTrackPolicy)
					Expect(err).NotTo(HaveOccurred())
				}()

				// Named port is not accessible, the other port should be.
				checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort1))
				checker.ExpectSuccess(client1, hepServer1.ServiceDomain().Port(hepPort2))
				checker.Execute()
			})

			It("should deny connections from specified source addresses in a doNotTrack deny policy (DoS mitigation) [ExternalNode]", func() {
				extClient := externalnode.NewClient()
				if extClient == nil {
					if describe.IncludesFocus("ExternalNode") {
						framework.Failf("External node client not available")
					} else {
						Skip("Skipping test that requires an external node")
					}
				}

				// create a networkpolicy that allows all incoming connections.
				// assert client can ping hep
				allowIngressPolicy := &v3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("%s-allow-all", hepPolicyName),
					},
					Spec: v3.GlobalNetworkPolicySpec{
						Selector: fmt.Sprintf("host-endpoint == \"%s\"", hepNodeName),
						Ingress: []v3.Rule{
							{
								Action: v3.Allow,
							},
						},
					},
				}

				By("creating an allow-all GlobalNetworkPolicy", func() {
					err := cli.Create(context.Background(), allowIngressPolicy)
					Expect(err).NotTo(HaveOccurred())
				})
				defer func() {
					err := cli.Delete(context.Background(), allowIngressPolicy)
					Expect(err).NotTo(HaveOccurred())
				}()

				By("asserting connections work now from an external node", func() {
					checker.ResetExpectations()
					checker.ExpectSuccess(client1, hepServer1.ServiceDomain().Port(hepPort1))
					checker.ExpectSuccess(client1, hepServer1.ServiceDomain().Port(hepPort2))
					checker.Execute()
				})

				// We need to enable generic XDP to test XDP in Iptables mode, otherwise the raw table
				// is used to implement doNotTrack GNP with deny action (because the interfaces used in e2e testing
				// may not support XDP offload or driver modes)
				felixConfig := v3.NewFelixConfiguration()
				err := cli.Get(context.Background(), types.NamespacedName{Name: "default"}, felixConfig)
				Expect(err).NotTo(HaveOccurred())

				genericXDP := felixConfig.Spec.GenericXDPEnabled
				if genericXDP == nil || !*genericXDP {
					By("enabling generic XDP")
					felixConfig.Spec.GenericXDPEnabled = ptr.To(true)
					err = cli.Update(context.Background(), felixConfig)
					Expect(err).NotTo(HaveOccurred())

					defer func() {
						By("restoring generic XDP setting")
						err = cli.Get(context.Background(), types.NamespacedName{Name: "default"}, felixConfig)
						Expect(err).NotTo(HaveOccurred())
						felixConfig.Spec.GenericXDPEnabled = genericXDP
						err = cli.Update(context.Background(), felixConfig)
						Expect(err).NotTo(HaveOccurred())
					}()
				}

				// The GlobalNetworkSet needed to list the source addresses needed by the following GNP
				globalNetworkSetDOS := &v3.GlobalNetworkSet{
					ObjectMeta: metav1.ObjectMeta{
						Name: "dos-mitigation",
						Labels: map[string]string{
							"dos-deny-list": "true",
						},
					},
					Spec: v3.GlobalNetworkSetSpec{
						Nets: []string{
							fmt.Sprintf("%s/32", extClient.IP()),
						},
					},
				}

				// A GNP to drop all packets with source address of the external node
				doNotTrackExactPolicy := &v3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("%s-dos-mitigation", hepPolicyName),
					},
					Spec: v3.GlobalNetworkPolicySpec{
						Selector:       fmt.Sprintf("host-endpoint == \"%s\"", hepNodeName),
						ApplyOnForward: true,
						DoNotTrack:     true,
						Types:          []v3.PolicyType{v3.PolicyTypeIngress},
						Ingress: []v3.Rule{
							{
								Action: v3.Deny,
								Source: v3.EntityRule{
									Selector: "dos-deny-list == \"true\"",
								},
							},
						},
					},
				}

				By("creating a GlobalNetworkSet and a doNotTrack GNP to deny packets from the external node", func() {
					err := cli.Create(context.Background(), globalNetworkSetDOS)
					Expect(err).NotTo(HaveOccurred())
					err = cli.Create(context.Background(), doNotTrackExactPolicy)
					Expect(err).NotTo(HaveOccurred())
				})
				defer func() {
					err := cli.Delete(context.Background(), doNotTrackExactPolicy)
					Expect(err).NotTo(HaveOccurred())
					err = cli.Delete(context.Background(), globalNetworkSetDOS)
					Expect(err).NotTo(HaveOccurred())
				}()

				By(fmt.Sprintf("asserting that none of the ports (tcp %d, %d) are accessible from the external node", hepPort1, hepPort2), func() {
					checker.ResetExpectations()
					checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort1))
					checker.ExpectFailure(client1, hepServer1.ServiceDomain().Port(hepPort2))
					checker.Execute()
				})
			})
		})
	})

func createHostEndpoint(cli ctrlclient.Client, policyName string, nodeName string, port int, ip string) *v3.HostEndpoint {
	hep := &v3.HostEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyName,
			Labels: map[string]string{
				"host-endpoint": nodeName,
				"heptest":       "heptest",
			},
		},
		Spec: v3.HostEndpointSpec{
			Node:        nodeName,
			ExpectedIPs: []string{ip},
			Ports: []v3.EndpointPort{
				{
					Name:     "hepport",
					Port:     uint16(port),
					Protocol: numorstring.ProtocolFromString("TCP"),
				},
			},
		},
	}

	err := cli.Create(context.Background(), hep)
	Expect(err).NotTo(HaveOccurred())
	return hep
}
