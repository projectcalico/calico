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
	v1 "github.com/tigera/operator/api/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
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
		var initialConfig *v3.BGPConfiguration

		// Create a new framework for the tests.
		f := utils.NewDefaultFramework("bgppeer")

		BeforeEach(func() {
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
			initialConfig = &v3.BGPConfiguration{}
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, initialConfig)
			if errors.IsNotFound(err) {
				// Not found - simply create a new one, enabling full mesh (the default behavior). Ideally, our product code
				// would do this automatically, but we do it here until it does.
				By("Creating default BGPConfiguration with full mesh enabled")
				cli.Create(context.Background(), &v3.BGPConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec: v3.BGPConfigurationSpec{
						NodeToNodeMeshEnabled: ptr.To(true),
					},
				})
				initialConfig = nil // Indicate that there was no initial config to restore later.
			} else {
				By("Ensuring full mesh BGP is enabled in existing BGPConfiguration")
				Expect(err).NotTo(HaveOccurred(), "Error querying BGPConfiguration resource")
				Expect(initialConfig.Spec.NodeToNodeMeshEnabled).NotTo(BeNil(), "nodeToNodeMeshEnabled is not configured in BGPConfiguration")
				Expect(initialConfig.Spec.NodeToNodeMeshEnabled).To(BeTrue(), "nodeToNodeMeshEnabled is not enabled in BGPConfiguration")
			}
		})

		// Before each test, perform the following steps:
		// - Create a server pod and corresponding service in the main namespace for the test.
		// - Create a client pod and assert that it can connect to the service.
		BeforeEach(func() {
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
			checker.AddServer(server1)
			checker.AddClient(client1)
			checker.Deploy()
		})

		AfterEach(func() {
			checker.Stop()

			// Restore the initial BGPConfiguration.
			if initialConfig != nil {
				By("Restoring initial BGPConfiguration")
				currentConfig := &v3.BGPConfiguration{}
				err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, currentConfig)
				Expect(err).NotTo(HaveOccurred(), "Error querying BGPConfiguration resource during cleanup")
				initialConfig.ResourceVersion = currentConfig.ResourceVersion
				err = cli.Update(context.Background(), initialConfig)
				Expect(err).NotTo(HaveOccurred(), "Error restoring BGPConfiguration resource during cleanup")
			} else {
				// Delete the BGPConfiguration if it didn't exist at the start of the test.
				By("Deleting BGPConfiguration")
				err := cli.Delete(context.Background(), &v3.BGPConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}})
				Expect(err).NotTo(HaveOccurred(), "Error deleting BGPConfiguration resource during cleanup")
			}
		})

		It("should support BGP peers", func() {
			// Verify initial connectivity.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIP())
			checker.Execute()

			// Disable full mesh BGP.
			By("Disabling full mesh BGP")
			config := &v3.BGPConfiguration{}
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, config)
			Expect(err).NotTo(HaveOccurred(), "Error querying BGPConfiguration resource")
			config.Spec.NodeToNodeMeshEnabled = ptr.To(false)
			err = cli.Update(context.Background(), config)
			Expect(err).NotTo(HaveOccurred(), "Error updating BGPConfiguration resource")

			// Verify connectivity is lost.
			checker.ResetExpectations()
			checker.ExpectFailure(client1, server1.ClusterIP())
			checker.Execute()

			// Create a BGPPeer to re-enable connectivity.
			By("Creating a BGPPeer to re-enable connectivity, simulating full mesh")
			peer := &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "peer-to-self"},
				Spec: v3.BGPPeerSpec{
					NodeSelector: "all()",
					PeerSelector: "all()",
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
			checker.ExpectSuccess(client1, server1.ClusterIP())
			checker.Execute()
		})
	})
