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
	"BGP export tests",
	func() {
		// Define variables common across all tests.
		var err error
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var server1 *conncheck.Server
		var client1 *conncheck.Client
		var restoreBGPConfig func()

		// Create a new framework for the tests.
		f := utils.NewDefaultFramework("bgp-export")

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
			restoreBGPConfig = ensureInitialBGPConfig(cli)

			// Create an IP pool for the test.
			pool := v3.NewIPPool()
			pool.Name = "bgp-export-pool"
			pool.Spec.CIDR = "172.24.0.0/16"
			pool.Spec.NATOutgoing = true
			pool.Spec.BlockSize = 26
			pool.Spec.DisableBGPExport = false
			err = cli.Create(context.Background(), pool)
			Expect(err).NotTo(HaveOccurred(), "Error creating IP pool")
			DeferCleanup(func() {
				err = cli.Delete(context.Background(), pool)
				Expect(err).NotTo(HaveOccurred(), "Error deleting IP pool")
			})

			// Before each test, perform the following steps:
			// - Create a server pod and corresponding service in the main namespace for the test.
			// - Create a client pod and assert that it can connect to the service.
			By(fmt.Sprintf("Creating server pod in namespace %s", f.Namespace.Name))

			// Use customizers to ensure pods use the test IP pool and avoid landing on the same node.
			customtizer := conncheck.CombineCustomizers(
				conncheck.UseV4IPPool(pool.Name),
				conncheck.AvoidEachOther,
			)
			server1 = conncheck.NewServer(
				"server",
				f.Namespace,
				conncheck.WithServerLabels(map[string]string{"role": "server"}),
				conncheck.WithServerPodCustomizer(customtizer),
			)
			client1 = conncheck.NewClient(
				"client",
				f.Namespace,
				conncheck.WithClientCustomizer(customtizer),
			)
			checker.AddServer(server1)
			checker.AddClient(client1)
			checker.Deploy()

			// Verify initial connectivity.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()
		})

		AfterEach(func() {
			checker.Stop()
			restoreBGPConfig()
		})

		It("should not export pools with export disabled", func() {
			// Disable the node to node mesh and replace it with explicit peerings.
			disableFullMesh(cli)
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

			// Disable BGP export on the pool.
			pool := &v3.IPPool{}
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "bgp-export-pool"}, pool)
			Expect(err).NotTo(HaveOccurred(), "Error querying IP pool")
			pool.Spec.DisableBGPExport = true
			err = cli.Update(context.Background(), pool)
			Expect(err).NotTo(HaveOccurred(), "Error updating IP pool")

			// Routing should stop working on the IPv4 pool. If there is an IPv6 pool in the cluster, it will
			// continue to work, so only test the IPv4 address.
			checker.ResetExpectations()
			checker.ExpectFailure(client1, server1.ClusterIPv4())
			checker.Execute()
		})
	})
