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

package bgp

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	v1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("BGPPeer"),
	describe.WithCategory(describe.Networking),
	describe.WithDisruptive(),
	"Route reflectors",
	func() {
		// Define variables common across all tests.
		var err error
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var server1 *conncheck.Server
		var client1 *conncheck.Client
		var client2 *conncheck.Client
		var restoreBGPConfig func()

		// Create a new framework for the tests.
		f := utils.NewDefaultFramework("route-reflection")

		BeforeEach(func() {
			// Create a connection tester for the test.
			checker = conncheck.NewConnectionTester(f)

			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

			// We need a minimum of two nodes for BGP peering tests.
			utils.RequireNodeCount(f, 3)

			// Make sure the cluster is in BGP mode by querying the Installation resource. The tests in this file
			// all require BGP, and all require Calico be installed by the operator.
			installation := &v1.Installation{}
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, installation)
			Expect(err).NotTo(HaveOccurred(), "Error querying Installation resource")
			Expect(installation.Spec.CalicoNetwork).NotTo(BeNil(), "CalicoNetwork is not configured in the Installation")
			Expect(installation.Spec.CalicoNetwork.BGP).NotTo(BeNil(), "BGP is not enabled in the cluster")
			Expect(*installation.Spec.CalicoNetwork.BGP).To(Equal(v1.BGPEnabled), "BGP is not enabled in the cluster")

			// Ensure full mesh BGP is functioning before each test.
			restoreBGPConfig = ensureInitialBGPConfig(cli)

			// Before each test, perform the following steps:
			// - Create a server pod and corresponding service in the main namespace for the test.
			// - Create a client pod and assert that it can connect to the service.
			By(fmt.Sprintf("Creating server pod in namespace %s", f.Namespace.Name))
			server1 = conncheck.NewServer(
				"server",
				f.Namespace,
				conncheck.WithServerLabels(map[string]string{"role": "server"}),
				conncheck.WithServerPodCustomizer(conncheck.AvoidEachOther),
			)
			client1 = conncheck.NewClient(
				"client",
				f.Namespace,
				conncheck.WithClientCustomizer(conncheck.AvoidEachOther),
			)
			client2 = conncheck.NewClient(
				"client2",
				f.Namespace,
				conncheck.WithClientCustomizer(conncheck.AvoidEachOther),
			)
			checker.AddServer(server1)
			checker.AddClient(client1)
			checker.AddClient(client2)
			checker.Deploy()

			// Verify initial connectivity.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.ExpectSuccess(client2, server1.ClusterIPs()...)
			checker.Execute()
		})

		AfterEach(func() {
			checker.Stop()
			restoreBGPConfig()
		})

		It("should support in-cluster route reflectors", func() {
			// Disable full mesh BGP.
			disableFullMesh(cli)

			// Set the AS number for the cluster to a non-default value. We do this to get
			// coverage of changing the AS number, but it is not strictly required for this test.
			asn, err := numorstring.ASNumberFromString("4294.566")
			Expect(err).NotTo(HaveOccurred(), "Error converting AS number from string")
			setASNumber(cli, asn)

			// Verify connectivity is lost because the full mesh is disabled.
			checker.ResetExpectations()
			checker.ExpectFailure(client1, server1.ClusterIPs()...)
			checker.ExpectFailure(client2, server1.ClusterIPs()...)
			checker.Execute()

			// Select a node to act as a route reflector. Give it a RR cluster ID, as well
			// as a label identifying it as a route reflector.
			nodes := corev1.NodeList{}
			err = cli.List(context.Background(), &nodes)
			Expect(err).NotTo(HaveOccurred(), "Error querying nodes in the cluster")
			Expect(nodes.Items).NotTo(BeEmpty(), "No nodes found in the cluster")
			setNodeAsRouteReflector(cli, &nodes.Items[0], "225.0.0.4")

			// Create BGP peer that causes all non-RR nodes to peer with the RR.
			By("Creating a BGPPeer to re-enable peers via the RR")
			peer := &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "peer-to-rrs"},
				Spec: v3.BGPPeerSpec{
					NodeSelector: fmt.Sprintf("!has(%s)", resources.RouteReflectorClusterIDAnnotation),
					PeerSelector: fmt.Sprintf("has(%s)", resources.RouteReflectorClusterIDAnnotation),
				},
			}
			err = cli.Create(context.Background(), peer)
			Expect(err).NotTo(HaveOccurred(), "Error creating BGPPeer resource")
			DeferCleanup(func() {
				err := cli.Delete(context.Background(), peer)
				Expect(err).NotTo(HaveOccurred(), "Error deleting BGPPeer resource during cleanup")
			})

			// Verify connectivity is restored.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.ExpectSuccess(client2, server1.ClusterIPs()...)
			checker.Execute()
		})

		It("should support clustered route reflectors", func() {
			// Disable full mesh BGP.
			disableFullMesh(cli)

			// Set the AS number for the cluster to a non-default value. We do this to get
			// coverage of changing the AS number, but it is not strictly required for this test.
			setASNumber(cli, 64514)

			// Verify connectivity is lost.
			checker.ResetExpectations()
			checker.ExpectFailure(client1, server1.ClusterIPs()...)
			checker.ExpectFailure(client2, server1.ClusterIPs()...)
			checker.Execute()

			// Select two nodes to act as route reflectors. Give them RR cluster IDs, as well
			// as a label identifying them as route reflectors.
			nodes := corev1.NodeList{}
			err = cli.List(context.Background(), &nodes)
			Expect(err).NotTo(HaveOccurred(), "Error querying nodes in the cluster")
			setNodeAsRouteReflector(cli, &nodes.Items[0], "225.0.0.4")
			setNodeAsRouteReflector(cli, &nodes.Items[1], "225.0.0.4")

			// Create BGP peer that causes all non-RR nodes to peer with the RRs.
			By("Creating a BGPPeer to re-enable peers via the RRs")
			peer := &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "peer-to-rrs"},
				Spec: v3.BGPPeerSpec{
					NodeSelector: fmt.Sprintf("!has(%s)", resources.RouteReflectorClusterIDAnnotation),
					PeerSelector: fmt.Sprintf("has(%s)", resources.RouteReflectorClusterIDAnnotation),
				},
			}
			err = cli.Create(context.Background(), peer)
			Expect(err).NotTo(HaveOccurred(), "Error creating BGPPeer resource")
			DeferCleanup(func() {
				err := cli.Delete(context.Background(), peer)
				Expect(err).NotTo(HaveOccurred(), "Error deleting BGPPeer resource during cleanup")
			})

			// Verify connectivity is restored.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.ExpectSuccess(client2, server1.ClusterIPs()...)
			checker.Execute()

			// By bringing down one of the nodes acting as a route reflector, we can verify that
			// route reflection is functioning correctly.
			deleteCalicoNode(cli, &nodes.Items[1])

			// Verify connectivity is maintained.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.ExpectSuccess(client2, server1.ClusterIPs()...)
			checker.Execute()

			// Now, remove one of the RRs and verify connectivity is maintained.
			By("Removing one of the route reflectors")
			setNodeAsNotRouteReflector(cli, &nodes.Items[1])

			// Verify connectivity is maintained.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.ExpectSuccess(client2, server1.ClusterIPs()...)
			checker.Execute()

			// Finally, remove the last RR and verify connectivity is lost.
			By("Removing the last route reflector")
			setNodeAsNotRouteReflector(cli, &nodes.Items[0])

			// Verify connectivity is lost.
			checker.ResetExpectations()
			checker.ExpectFailure(client1, server1.ClusterIPs()...)
			checker.ExpectFailure(client2, server1.ClusterIPs()...)
			checker.Execute()
		})
	})
