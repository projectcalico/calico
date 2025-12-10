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

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("BGPPeer"),
	describe.WithCategory(describe.Networking),
	"BGPPeer",
	func() {
		// Define variables common across all tests.
		var err error
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var server1 *conncheck.Server
		var client1 *conncheck.Client
		var restoreBGPConfig func()

		// Create a new framework for the tests.
		f := utils.NewDefaultFramework("bgppeer")

		ginkgo.BeforeEach(func() {
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

			// Ensure full mesh BGP is functioning before each test.
			restoreBGPConfig = ensureInitialBGPConfig(cli)

			// Before each test, perform the following steps:
			// - Create a server pod and corresponding service in the main namespace for the test.
			// - Create a client pod and assert that it can connect to the service.
			ginkgo.By(fmt.Sprintf("Creating server pod in namespace %s", f.Namespace.Name))
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
			restoreBGPConfig()
		})

		ginkgo.It("should support BGP peers", func() {
			// Disable full mesh BGP.
			disableFullMesh(cli)

			// Verify connectivity is lost.
			checker.ResetExpectations()
			checker.ExpectFailure(client1, server1.ClusterIPs()...)
			checker.Execute()

			// Create a BGPPeer to re-enable connectivity.
			ginkgo.By("Creating a BGPPeer to re-enable connectivity, simulating full mesh")
			peer := &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "peer-to-self"},
				Spec: v3.BGPPeerSpec{
					NodeSelector: "all()",
					PeerSelector: "all()",
				},
			}
			err = cli.Create(context.Background(), peer)
			Expect(err).NotTo(HaveOccurred(), "Error creating BGPPeer resource")
			ginkgo.DeferCleanup(func() {
				err := cli.Delete(context.Background(), peer)
				if !errors.IsNotFound(err) {
					Expect(err).NotTo(HaveOccurred(), "Error deleting BGPPeer resource during cleanup")
				}
			})

			// Verify connectivity is restored.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()

			// Delete the BGPPeer to disable connectivity again.
			ginkgo.By("Deleting the BGPPeer to disable connectivity again")
			err = cli.Delete(context.Background(), peer)
			Expect(err).NotTo(HaveOccurred(), "Error deleting BGPPeer resource")

			// Verify connectivity is lost again.
			checker.ResetExpectations()
			checker.ExpectFailure(client1, server1.ClusterIPs()...)
			checker.Execute()

			// Create per-node BGPPeers to re-enable connectivity.
			ginkgo.By("Creating per-node BGPPeers to re-enable connectivity")
			nodes := &corev1.NodeList{}
			err = cli.List(context.Background(), nodes)
			Expect(err).NotTo(HaveOccurred(), "Error querying nodes in the cluster")
			for _, node := range nodes.Items {
				for _, node2 := range nodes.Items {
					if node.Name == node2.Name {
						continue
					}
					peer := &v3.BGPPeer{
						ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("peer-%s-to-%s", node.Name, node2.Name)},
						Spec: v3.BGPPeerSpec{
							Node:         node.Name,
							PeerSelector: fmt.Sprintf("kubernetes.io/hostname == '%s'", node2.Name),
						},
					}
					err = cli.Create(context.Background(), peer)
					Expect(err).NotTo(HaveOccurred(), "Error creating per-node BGPPeer resource")
					ginkgo.DeferCleanup(func() {
						err := cli.Delete(context.Background(), peer)
						if !errors.IsNotFound(err) {
							Expect(err).NotTo(HaveOccurred(), "Error deleting per-node BGPPeer resource during cleanup")
						}
					})
				}
			}

			// Verify connectivity is restored.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()
		})
	})
