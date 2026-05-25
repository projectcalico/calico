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

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

// CIDR for the dedicated IPPools used by these tests. Kept separate from
// other tests' pools so block-routes are easy to identify in `ip route`.
const routeOwnerPoolCIDR = "203.0.113.0/24"

// routeOwnerPoolPrefix is the substring matcher used against `ip route`
// destinations. Any IPAM block carved out of routeOwnerPoolCIDR will start
// with this prefix.
const routeOwnerPoolPrefix = "203.0.113."

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Networking),
	describe.WithSerial(),
	"Cluster route ownership",
	func() {
		var (
			cli     ctrlclient.Client
			checker conncheck.ConnectionTester
			srv     conncheck.Server
			clt     conncheck.Client
		)

		f := utils.NewDefaultFramework("cluster-routes")

		// setUpPoolAndPods creates an IPPool from the supplied spec mutator and
		// schedules a server / client pair on different nodes inside it. The
		// test body then asserts ownership of the routes Felix or BIRD has
		// programmed for that pool.
		setUpPoolAndPods := func(poolMutator func(*v3.IPPool)) {
			if windows.ClusterIsWindows() {
				framework.Failf("Cluster route ownership tests are not implemented on Windows")
			}

			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			utils.RequireNodeCount(f, 2)

			checker = conncheck.NewConnectionTester(f)

			poolName := utils.GenerateRandomName("route-owner-pool")
			pool := v3.NewIPPool()
			pool.Name = poolName
			pool.Spec.CIDR = routeOwnerPoolCIDR
			pool.Spec.NATOutgoing = true
			pool.Spec.BlockSize = 28
			pool.Spec.DisableBGPExport = false
			poolMutator(pool)
			Expect(cli.Create(context.Background(), pool)).To(Succeed(), "Error creating IP pool")
			ginkgo.DeferCleanup(func() {
				Expect(cli.Delete(context.Background(), pool)).To(Succeed(), "Error deleting IP pool")
			})

			customizer := conncheck.CombineCustomizers(
				conncheck.UseV4IPPool(pool.Name),
				conncheck.AvoidEachOther,
			)
			srv = conncheck.NewServer(
				"server", f.Namespace,
				conncheck.WithServerLabels(map[string]string{"role": "server"}),
				conncheck.WithServerPodCustomizer(customizer),
			)
			clt = conncheck.NewClient(
				"client", f.Namespace,
				conncheck.WithClientCustomizer(customizer),
			)
			checker.AddServer(srv)
			checker.AddClient(clt)
			checker.Deploy()

			// Sanity-check that pods actually landed on different nodes —
			// otherwise there is no cross-node route to inspect.
			Expect(srv.Pod().Spec.NodeName).NotTo(Equal(clt.Pod().Spec.NodeName),
				"Server and client landed on the same node; cannot exercise cross-node routes")

			checker.ResetExpectations()
			checker.ExpectSuccess(clt, srv.ClusterIPs()...)
			checker.Execute()
		}

		ginkgo.AfterEach(func() {
			if checker != nil {
				checker.Stop()
				checker = nil
			}
		})

		ginkgo.Context("with an IPIP-Always pool", func() {
			ginkgo.BeforeEach(func() {
				setUpPoolAndPods(func(p *v3.IPPool) {
					p.Spec.IPIPMode = v3.IPIPModeAlways
				})
			})

			framework.ConformanceIt("routes should be programmed by the owner of in-cluster routing",
				func() {
					expectedRoutesOwner := expectedClusterRouteProto(cli)
					assertRouteOwnership(cli, clt.Pod().Spec.NodeName,
						routeOwnerPoolPrefix, "tunl0", expectedRoutesOwner)
				})
		})
	})
