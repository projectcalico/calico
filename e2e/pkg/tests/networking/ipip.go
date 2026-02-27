// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("IPIP"),
	describe.WithCategory(describe.Networking),
	describe.RequiresNoEncap(),
	"IP-in-IP tests",
	func() {
		// Define variables common across all tests.
		var err error
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var server1 *conncheck.Server
		var client1 *conncheck.Client
		var poolName string

		// Create a new framework for the tests.
		f := utils.NewDefaultFramework("ipip")

		ginkgo.BeforeEach(func() {
			if windows.ClusterIsWindows() {
				// These tests exec commands in pods to check routes, which has not been implemented
				// for Windows yet.
				framework.Failf("IPIP tests are not implemented on Windows")
			}

			// Create a connection tester for the test.
			checker = conncheck.NewConnectionTester(f)

			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

			// We need a minimum of two nodes for BGP peering tests.
			utils.RequireNodeCount(f, 2)

			// Make sure the cluster is in BGP mode by querying the Installation resource. The tests in this file
			// all require BGP, and all require Calico be installed by the operator.
			installation := &v1.Installation{}
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, installation)
			Expect(err).NotTo(HaveOccurred(), "Error querying Installation resource")
			Expect(installation.Spec.CalicoNetwork).NotTo(BeNil(), "CalicoNetwork is not configured in the Installation")
			Expect(installation.Spec.CalicoNetwork.BGP).NotTo(BeNil(), "BGP is not enabled in the cluster")
			Expect(*installation.Spec.CalicoNetwork.BGP).To(Equal(v1.BGPEnabled), "BGP is not enabled in the cluster")

			// Create an IP pool for the test.
			poolName = utils.GenerateRandomName("ipip-pool")
			pool := v3.NewIPPool()
			pool.Name = poolName
			pool.Spec.CIDR = "203.0.113.0/24"
			pool.Spec.NATOutgoing = true
			pool.Spec.BlockSize = 28
			pool.Spec.DisableBGPExport = false
			pool.Spec.IPIPMode = v3.IPIPModeAlways
			err = cli.Create(context.Background(), pool)
			Expect(err).NotTo(HaveOccurred(), "Error creating IP pool")
			ginkgo.DeferCleanup(func() {
				err = cli.Delete(context.Background(), pool)
				Expect(err).NotTo(HaveOccurred(), "Error deleting IP pool")
			})

			// Before each test, perform the following steps:
			// - Create a server pod and corresponding service in the main namespace for the test.
			// - Create a client pod and assert that it can connect to the service.
			ginkgo.By(fmt.Sprintf("Creating server pod in namespace %s", f.Namespace.Name))

			// Use customizers to ensure pods use the test IP pool and avoid landing on the same node.
			customizer := conncheck.CombineCustomizers(
				conncheck.UseV4IPPool(pool.Name),
				conncheck.AvoidEachOther,
			)
			server1 = conncheck.NewServer(
				"server",
				f.Namespace,
				conncheck.WithServerLabels(map[string]string{"role": "server"}),
				conncheck.WithServerPodCustomizer(customizer),
			)
			client1 = conncheck.NewClient(
				"client",
				f.Namespace,
				conncheck.WithClientCustomizer(customizer),
			)
			checker.AddServer(server1)
			checker.AddClient(client1)
			checker.Deploy()

			// Verify initial connectivity.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()
		})

		ginkgo.AfterEach(func() {
			checker.Stop()
		})

		ginkgo.It("should support toggling IPIP on and off", func() {
			// Toggle IPIP mode off and on again, verifying connectivity after each step.
			ginkgo.By("Disabling IPIP mode on the IP pool")
			pool := &v3.IPPool{}
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: poolName}, pool)
			Expect(err).NotTo(HaveOccurred(), "Error querying IP pool")
			pool.Spec.IPIPMode = v3.IPIPModeNever
			err = cli.Update(context.Background(), pool)
			Expect(err).NotTo(HaveOccurred(), "Error updating IP pool to disable IPIP")

			// Verify connectivity still works.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()

			// Eventually, the routes for the test's IP pool should no longer use tunl0.
			ginkgo.By("Verifying that node routes no longer use tunl0")
			Eventually(func() error {
				routes := getNodeRoutes(cli, "203.0.113")
				if len(routes) == 0 {
					return fmt.Errorf("no routes found for test IP pool")
				}
				for _, r := range routes {
					if strings.Contains(r, "tunl0") {
						return fmt.Errorf("route for test IP pool is still using tunl0: %s", r)
					}
				}
				return nil
			}, 10*time.Second, 1*time.Second).Should(Succeed(), "Routes for the test IP pool are still using tunl0")

			// CrossSubnet.
			ginkgo.By("Setting IPIP mode to CrossSubnet on the IP pool")
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: poolName}, pool)
			Expect(err).NotTo(HaveOccurred(), "Error querying IP pool")
			pool.Spec.IPIPMode = v3.IPIPModeCrossSubnet
			err = cli.Update(context.Background(), pool)
			Expect(err).NotTo(HaveOccurred(), "Error updating IP pool to set IPIP to CrossSubnet")

			// Verify connectivity still works.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()

			// Always.
			ginkgo.By("Setting IPIP mode to Always on the IP pool")
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: poolName}, pool)
			Expect(err).NotTo(HaveOccurred(), "Error querying IP pool")
			pool.Spec.IPIPMode = v3.IPIPModeAlways
			err = cli.Update(context.Background(), pool)
			Expect(err).NotTo(HaveOccurred(), "Error updating IP pool to set IPIP to Always")

			// Routes should now be using tunl0 again.
			ginkgo.By("Verifying that node routes are using tunl0")
			Eventually(func() error {
				routes := getNodeRoutes(cli, "203.0.113")
				if len(routes) == 0 {
					return fmt.Errorf("no routes found for test IP pool")
				}
				for _, r := range routes {
					if strings.Contains(r, "tunl0") {
						// Found a route using tunl0, as expected.
						return nil
					}
				}
				return fmt.Errorf("no routes for test IP pool are using tunl0: %v", routes)
			}, 10*time.Second, 1*time.Second).Should(Succeed(), "Routes for the test IP pool are not using tunl0")

			// Verify connectivity still works.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()
		})

		ginkgo.It("should assign an IPIP address to the tunl0 interface", func() {
			ginkgo.By("Verifying that each node has a tunl0 interface with an IPIP address")
			pods := corev1.PodList{}
			err := cli.List(context.Background(), &pods, ctrlclient.MatchingLabels{"k8s-app": "calico-node"})
			Expect(err).NotTo(HaveOccurred(), "Error querying calico/node pods")
			Expect(pods.Items).NotTo(BeEmpty(), "No calico/node pods found")

			// Go through each pod and assert that tunl0 has an IP address assigned and that it matches the
			// the tunnel IP address assigned to the node.
			for _, p := range pods.Items {
				// Query the node hosting this pod to get its IP address.
				node := corev1.Node{}
				err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: p.Spec.NodeName}, &node)
				Expect(err).NotTo(HaveOccurred(), "Error querying node %s", p.Spec.NodeName)
				expectedIP, ok := node.Annotations["projectcalico.org/IPv4IPIPTunnelAddr"]
				Expect(ok).To(BeTrue(), "Node %s does not have an IPv4Address annotation", node.Name)

				out, err := conncheck.ExecInPod(&p, "sh", "-c", "ip addr show tunl0")
				Expect(err).NotTo(HaveOccurred(), "Error querying tunl0 interface in pod %s", p.Name)
				Expect(out).To(ContainSubstring(expectedIP), "tunl0 interface in pod %s does not have the expected IPIP address", p.Name)
			}
		})
	})

// getNodeRoutes execs into a calico/node pod and returns the output of "ip route show",
// filtered to only include lines that contain the specified match string.
func getNodeRoutes(cli ctrlclient.Client, match string) []string {
	// Find a calico/node pod to exec into.
	pods := corev1.PodList{}
	err := cli.List(context.Background(), &pods, ctrlclient.MatchingLabels{"k8s-app": "calico-node"})
	Expect(err).NotTo(HaveOccurred(), "Error querying calico/node pods")
	Expect(pods.Items).NotTo(BeEmpty(), "No calico/node pods found")
	p := &pods.Items[0]

	out, err := conncheck.ExecInPod(p, "sh", "-c", "ip route show")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying routes from pod %s", p.Name)

	matches := []string{}
	for s := range strings.SplitSeq(out, "\n") {
		if strings.Contains(s, match) {
			matches = append(matches, s)
		}
	}
	return matches
}
