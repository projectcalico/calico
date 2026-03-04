// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostendpoints

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

// DESCRIPTION:
// DOCS_URL:
// PRECONDITIONS:
var _ = describe.CalicoDescribe(describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	describe.WithSerial(),
	describe.WithFeature("AutoHEPs"),
	"auto host endpoint tests",
	func() {
		f := utils.NewDefaultFramework("auto-hep")
		var (
			nodes       *v1.NodeList
			nodeNames   []string
			cli         ctrlclient.Client
			originalKCC v3.KubeControllersConfiguration
			testKCC     v3.KubeControllersConfiguration
		)
		const port9090 = 9090
		const port9091 = 9091

		denyEgressPolicy := &v3.GlobalNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				Kind:       "GlobalNetworkPolicy",
				APIVersion: v3.SchemeGroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "autohep-e2e-egress-deny",
			},
			Spec: v3.GlobalNetworkPolicySpec{
				Selector: "has(deny-egress)",
				Egress: []v3.Rule{
					{
						Action:   v3.Deny,
						Protocol: &numorstring.Protocol{Type: numorstring.NumOrStringString, StrVal: "TCP"},
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(9091),
							},
						},
					},
					{
						Action: v3.Allow,
					},
				},
			},
		}

		ginkgo.BeforeEach(func() {
			// The following code tries to get config information from k8s ConfigMap.
			// A framework clientset is needed to access k8s configmap but it will only be created in the context of BeforeEach or IT.
			// Current solution is to use BeforeEach because this function is not a test case.
			// This will avoid complexity of creating a client by ourselves.
			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

			// Sanity check: make sure we have a default kubecontrollersconfiguration.
			originalKCC = v3.KubeControllersConfiguration{}
			err = cli.Get(context.Background(), types.NamespacedName{Name: "default"}, &originalKCC)
			Expect(err).NotTo(HaveOccurred(), "Error getting kubecontrollersconfiguration")

			// Make a copy of the original KCC so we can restore it later.
			testKCC = *originalKCC.DeepCopy()

			// Turn on default auto host endpoints if not already enabled.
			if !GetAutoHEPsEnabled(originalKCC) {
				logrus.Info("BeforeEach: auto host endpoints not previously enabled so enabling")
				// Enabled creation of auto host endpoints and creation of default host endpoints.
				testKCC.Spec.Controllers.Node.HostEndpoint.AutoCreate = "Enabled"
				testKCC.Spec.Controllers.Node.HostEndpoint.CreateDefaultHostEndpoint = v3.DefaultHostEndpointsEnabled
				updateHostEndpointConfig(cli, testKCC)
				WaitForAutoHEPs(cli, true)
			}

			logrus.Info("BeforeEach for auto host endpoint")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Build a list of Kubernetes node names.
			nodes, err = e2enode.GetReadySchedulableNodes(ctx, f.ClientSet)
			Expect(err).NotTo(HaveOccurred(), "Error getting nodes")
			Expect(nodes.Items).NotTo(BeEmpty(), "No nodes found in the cluster")
			nodeNames = make([]string, len(nodes.Items))
			for i, node := range nodes.Items {
				nodeNames[i] = getNodeHostname(node)
			}
		})

		ginkgo.AfterEach(func() {
			// We've updated the kubecontrollersconfiguration, so we need to restore it to its original state.
			if !reflect.DeepEqual(originalKCC.Spec.Controllers.Node.HostEndpoint, testKCC.Spec.Controllers.Node.HostEndpoint) {
				logrus.Info("AfterEach: auto host endpoints not previously enabled so disabling")
				updateHostEndpointConfig(cli, originalKCC)
				WaitForAutoHEPs(cli, false)
			}
		})

		framework.ConformanceIt("should create host endpoints for each node", func() {
			for _, nodeName := range nodeNames {
				expectAutoHostEndpoint(cli, nodeName)
			}
		})

		ginkgo.Context("with policies in place", func() {
			var checker conncheck.ConnectionTester
			var server *conncheck.Server
			var cliHostNet *conncheck.Client

			ginkgo.BeforeEach(func() {
				checker = conncheck.NewConnectionTester(f)

				// Ensure the host networked server pod is on node 0, and client is on node 1.
				serverNode := getNodeHostname(nodes.Items[0])
				serverPodOnNodeZero := func(pod *v1.Pod) {
					pod.Spec.HostNetwork = true
					pod.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": serverNode}
				}

				clientNode := getNodeHostname(nodes.Items[1])
				clientPodOnNodeOneHostNet := func(pod *v1.Pod) {
					pod.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": clientNode}
					pod.Spec.HostNetwork = true
					pod.Spec.DNSPolicy = "ClusterFirstWithHostNet"
				}

				// Setup a server pod listening on ports 9090 and 9091.
				server = conncheck.NewServer("server", f.Namespace, conncheck.WithPorts(port9090, port9091), conncheck.WithServerPodCustomizer(serverPodOnNodeZero))
				cliHostNet = conncheck.NewClient("client-host-net", f.Namespace, conncheck.WithClientCustomizer(clientPodOnNodeOneHostNet))
				checker.AddClient(cliHostNet)
				checker.AddServer(server)
				checker.Deploy()
			})

			ginkgo.AfterEach(func() {
				checker.Stop()
			})

			ginkgo.Context("with ingress policy", func() {
				var denyIngressPolicy *v3.GlobalNetworkPolicy

				ginkgo.BeforeEach(func() {
					// Declare a policy that blocks ingress to the server
					// pod on port 9090. But don't apply the policy yet.
					denyIngressPolicy = &v3.GlobalNetworkPolicy{
						TypeMeta: metav1.TypeMeta{
							Kind:       "GlobalNetworkPolicy",
							APIVersion: v3.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name: "autohep-e2e-ingress",
						},
						Spec: v3.GlobalNetworkPolicySpec{
							Selector: fmt.Sprintf(`kubernetes.io/hostname == "%s"`, getNodeHostname(nodes.Items[0])),
							Ingress: []v3.Rule{
								{
									Action:   v3.Deny,
									Protocol: &numorstring.Protocol{Type: numorstring.NumOrStringString, StrVal: "TCP"},
									Destination: v3.EntityRule{
										Ports: []numorstring.Port{
											numorstring.SinglePort(9090),
										},
									},
									Source: v3.EntityRule{
										Selector: fmt.Sprintf(`kubernetes.io/hostname == "%s"`, getNodeHostname(nodes.Items[1])),
									},
								},
								{
									Action: v3.Allow,
								},
							},
						},
					}
				})

				ginkgo.AfterEach(func() {
					err := cli.Delete(context.Background(), denyIngressPolicy)
					Expect(err).NotTo(HaveOccurred())
				})

				ginkgo.It("should block one node 1 from entering node 0 on port 9090 with ingress policy", func() {
					// Without any policy, the test pod should be able to hit the service on both ports.
					checker.ExpectSuccess(cliHostNet, server.ClusterIP().Port(port9090))
					checker.ExpectSuccess(cliHostNet, server.ClusterIP().Port(port9091))
					checker.Execute()

					err := cli.Create(context.Background(), denyIngressPolicy)
					Expect(err).NotTo(HaveOccurred())

					// With the policy in place, the test pod can only reach port 9091 on the service.
					checker.ResetExpectations()
					checker.ExpectFailure(cliHostNet, server.ClusterIP().Port(port9090))
					checker.ExpectSuccess(cliHostNet, server.ClusterIP().Port(port9091))
					checker.Execute()
				})
			})

			ginkgo.Context("with egress policy", func() {
				var clientPod *conncheck.Client

				ginkgo.BeforeEach(func() {
					clientNode := getNodeHostname(nodes.Items[1])
					clientPodOnNodeOne := func(pod *v1.Pod) {
						pod.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": clientNode}
						pod.Labels["deny-egress"] = ""
					}
					clientPod = conncheck.NewClient("client", f.Namespace, conncheck.WithClientCustomizer(clientPodOnNodeOne))
					checker.AddClient(clientPod)
					checker.Deploy()
				})

				ginkgo.AfterEach(func() {
					err := cli.Delete(context.Background(), denyEgressPolicy)
					Expect(err).NotTo(HaveOccurred())
				})

				ginkgo.It("should block one node 1 from reaching node 0 on port 9091 with egress policy", func() {
					// Without any policy, the test pod should be able to hit the service on both ports.
					checker.ExpectSuccess(clientPod, server.ClusterIP().Port(port9090))
					checker.ExpectSuccess(clientPod, server.ClusterIP().Port(port9091))
					checker.Execute()

					err := cli.Create(context.Background(), denyEgressPolicy)
					Expect(err).NotTo(HaveOccurred())

					// With the policy in place, the test pod can only reach port 9090 on the service.
					checker.ResetExpectations()
					checker.ExpectSuccess(clientPod, server.ClusterIP().Port(port9090))
					checker.ExpectFailure(clientPod, server.ClusterIP().Port(port9091))
					checker.Execute()
				})
			})
		})
	})

// Note that on OpenShift, the hostname label is truncated.
func getNodeHostname(node v1.Node) string {
	hostname := node.Labels["kubernetes.io/hostname"]

	return hostname
}

// updateHostEndpointConfig updates the HostEndpointConfiguration to the desired state
func updateHostEndpointConfig(client ctrlclient.Client, desiredKCC v3.KubeControllersConfiguration) {
	// Get the kubecontrollersconfiguration and patch it to toggle the
	// auto-creation of host endpoints.
	var currentKCC v3.KubeControllersConfiguration
	err := client.Get(context.Background(), types.NamespacedName{Name: "default"}, &currentKCC)
	Expect(err).NotTo(HaveOccurred(), "Error getting kubecontrollersconfiguration")

	// Patch the kubecontrollersconfiguration to toggle auto-creation of host endpoints.
	currentKCC.Spec.Controllers.Node.HostEndpoint = desiredKCC.Spec.Controllers.Node.HostEndpoint

	err = client.Update(context.Background(), &currentKCC)
	Expect(err).NotTo(HaveOccurred(), "Error updating kubecontrollersconfiguration")

	// Wait for the status to be updated to reflect the change, which indicates that
	// the kube-controllers pod has been restarted and the new config has been applied.
	Eventually(func() error {
		err := client.Get(context.Background(), types.NamespacedName{Name: "default"}, &currentKCC)
		if err != nil {
			return err
		}

		// Check if the current configuration matches the desired configuration.
		if currentKCC.Status.RunningConfig == nil ||
			currentKCC.Status.RunningConfig.Controllers.Node == nil ||
			currentKCC.Status.RunningConfig.Controllers.Node.HostEndpoint == nil {
			return fmt.Errorf("kubecontrollersconfiguration status is not yet updated")
		}
		if !reflect.DeepEqual(currentKCC.Status.RunningConfig.Controllers.Node.HostEndpoint, desiredKCC.Spec.Controllers.Node.HostEndpoint) {
			return fmt.Errorf("failed to toggle auto-creation of host endpoints")
		}
		return nil
	}, 5*time.Second, 1*time.Second).Should(BeNil())
}

// GetAutoHEPsEnabled returns true if AutoHEPs are enabled, false otherwise.
func GetAutoHEPsEnabled(kcc v3.KubeControllersConfiguration) bool {
	if kcc.Spec.Controllers.Node == nil || kcc.Spec.Controllers.Node.HostEndpoint == nil {
		return false
	}
	if kcc.Spec.Controllers.Node.HostEndpoint.AutoCreate != "Enabled" {
		return false
	}
	if kcc.Spec.Controllers.Node.HostEndpoint.CreateDefaultHostEndpoint != v3.DefaultHostEndpointsEnabled {
		return false
	}
	return true
}

func WaitForAutoHEPs(client ctrlclient.Client, expect bool) {
	if expect {
		logrus.Info("Waiting for the host endpoints to be created")
	} else {
		logrus.Info("Waiting for the host endpoints to be deleted")
	}
	EventuallyWithOffset(1, func() error {
		heps := &v3.HostEndpointList{}
		err := client.List(context.Background(), heps)
		if err != nil {
			return err
		}
		if expect && len(heps.Items) == 0 {
			return fmt.Errorf("expected host endpoints to be present, but none found")
		}
		if !expect && len(heps.Items) > 0 {
			return fmt.Errorf("expected no host endpoints, but found %d", len(heps.Items))
		}
		return nil
	}, 1*time.Minute, 2*time.Second).Should(BeNil())
}

// expectAutoHostEndpoint asserts that a specified node has the correct auto
// host endpoint created for it.
func expectAutoHostEndpoint(client ctrlclient.Client, nodeName string) {
	EventuallyWithOffset(1, func() error {
		// Get the node and its auto host endpoint
		// This naming convention is hardcoded in kube-controllers.
		hepName := nodeName + "-auto-hep"
		hep := &v3.HostEndpoint{}
		err := client.Get(context.Background(), types.NamespacedName{Name: hepName}, hep)
		if err != nil {
			return fmt.Errorf("error getting HEP %s: %v", hepName, err)
		}

		// Auto host endpoints are all-interfaces host endpoints.
		if hep.Spec.InterfaceName != "*" {
			return fmt.Errorf("HEP has unexpected interface name: %s", hep.Spec.InterfaceName)
		}

		// Finally, the host endpoint will have one last label added to all auto
		// host endpoints:
		if hep.Labels["projectcalico.org/created-by"] != "calico-kube-controllers" {
			return fmt.Errorf("HEP not created by kube-controllers")
		}
		return nil
	}, 30*time.Second, 2*time.Second).Should(BeNil())
}
