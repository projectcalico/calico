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

	"github.com/onsi/ginkgo/v2"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
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
const routeOwnerPoolCIDR = "203.0.115.0/24"

// routeOwnerPoolPrefix is the substring matcher used against `ip route`
// destinations. Any IPAM block carved out of routeOwnerPoolCIDR will start
// with this prefix.
const routeOwnerPoolPrefix = "203.0.115."

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("IPPool"),
	describe.WithCategory(describe.Networking),
	describe.RequiresNoEncap(),
	describe.WithSerial(),
	"Cluster route ownership",
	func() {
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var srv conncheck.Server
		var clt conncheck.Client

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

			framework.ConformanceIt("Felix programs the IPIP cluster route (proto 80)",
				describe.RequiresFelixClusterRouting(),
				func() {
					assertRouteOwnership(cli, clt.Pod().Spec.NodeName,
						routeOwnerPoolPrefix, "tunl0", RouteProtoFelix)
				})

			framework.ConformanceIt("BIRD programs the IPIP cluster route (proto bird)",
				describe.RequiresBIRDClusterRouting(),
				func() {
					assertRouteOwnership(cli, clt.Pod().Spec.NodeName,
						routeOwnerPoolPrefix, "tunl0", RouteProtoBIRD)
				})
		})

		ginkgo.Context("with a no-encap pool", func() {
			ginkgo.BeforeEach(func() {
				setUpPoolAndPods(func(p *v3.IPPool) {
					p.Spec.IPIPMode = v3.IPIPModeNever
					p.Spec.VXLANMode = v3.VXLANModeNever
				})
			})

			framework.ConformanceIt("Felix programs the no-encap cluster route (proto 80)",
				describe.RequiresFelixClusterRouting(),
				func() {
					// Direct next-hop route — no tunnel device.
					assertRouteOwnership(cli, clt.Pod().Spec.NodeName,
						routeOwnerPoolPrefix, "", RouteProtoFelix)
				})

			framework.ConformanceIt("BIRD programs the no-encap cluster route (proto bird)",
				describe.RequiresBIRDClusterRouting(),
				func() {
					assertRouteOwnership(cli, clt.Pod().Spec.NodeName,
						routeOwnerPoolPrefix, "", RouteProtoBIRD)
				})
		})

		ginkgo.Context("when switching clusterRoutingMode at runtime", func() {
			ginkgo.BeforeEach(func() {
				setUpPoolAndPods(func(p *v3.IPPool) {
					p.Spec.IPIPMode = v3.IPIPModeAlways
				})
			})

			// Disruptive: mutates the cluster-wide Installation resource and
			// triggers FelixConfiguration + BGPConfiguration reconciliation,
			// which transiently affects every node. Excluded from the default
			// CI jobs.
			ginkgo.It("transitions routes between BIRD and Felix",
				framework.WithDisruptive(),
				func() {
					initial := readClusterRoutingMode(cli)
					ginkgo.DeferCleanup(func() {
						setClusterRoutingMode(cli, initial)
					})

					nodeName := clt.Pod().Spec.NodeName

					setClusterRoutingMode(cli, ptrClusterRoutingMode(operatorv1.ClusterRoutingModeBIRD))
					assertRouteOwnership(cli, nodeName, routeOwnerPoolPrefix, "tunl0", RouteProtoBIRD)
					checker.ResetExpectations()
					checker.ExpectSuccess(clt, srv.ClusterIPs()...)
					checker.Execute()

					setClusterRoutingMode(cli, ptrClusterRoutingMode(operatorv1.ClusterRoutingModeFelix))
					assertRouteOwnership(cli, nodeName, routeOwnerPoolPrefix, "tunl0", RouteProtoFelix)
					checker.ResetExpectations()
					checker.ExpectSuccess(clt, srv.ClusterIPs()...)
					checker.Execute()

					setClusterRoutingMode(cli, ptrClusterRoutingMode(operatorv1.ClusterRoutingModeBIRD))
					assertRouteOwnership(cli, nodeName, routeOwnerPoolPrefix, "tunl0", RouteProtoBIRD)
					checker.ResetExpectations()
					checker.ExpectSuccess(clt, srv.ClusterIPs()...)
					checker.Execute()
				})
		})
	})

// assertRouteOwnership polls the kernel routing table on nodeName until at
// least one route matching dstSubstring carries the expected dev (if
// non-empty) and proto. The dev field is the empty string for direct
// next-hop (no-encap) routes since the actual device varies by cluster
// topology — for those, dev is left unchecked and only the proto byte
// matters.
func assertRouteOwnership(cli ctrlclient.Client, nodeName, dstSubstring, expectedDev string, expectedProto RouteProto) {
	ginkgo.By(fmt.Sprintf("Asserting routes for %q on node %s use dev=%q proto=%s",
		dstSubstring, nodeName, expectedDev, expectedProto))
	Eventually(func() error {
		routes := GetNodeRoutes(cli, nodeName, dstSubstring)
		if len(routes) == 0 {
			return fmt.Errorf("no routes found containing %q on node %s", dstSubstring, nodeName)
		}
		for _, r := range routes {
			if expectedDev != "" && r.Dev != expectedDev {
				continue
			}
			if r.Proto == expectedProto {
				return nil
			}
		}
		return fmt.Errorf("no route on node %s with dev=%q proto=%s found among %v",
			nodeName, expectedDev, expectedProto, routes)
	}, 60*time.Second, 2*time.Second).Should(Succeed())
}

func readClusterRoutingMode(cli ctrlclient.Client) *operatorv1.ClusterRoutingMode {
	inst := &operatorv1.Installation{}
	Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, inst)).To(Succeed())
	if inst.Spec.CalicoNetwork == nil || inst.Spec.CalicoNetwork.ClusterRoutingMode == nil {
		return nil
	}
	m := *inst.Spec.CalicoNetwork.ClusterRoutingMode
	return &m
}

func setClusterRoutingMode(cli ctrlclient.Client, mode *operatorv1.ClusterRoutingMode) {
	if mode != nil {
		ginkgo.By(fmt.Sprintf("Setting Installation.spec.calicoNetwork.clusterRoutingMode = %s", *mode))
	} else {
		ginkgo.By("Clearing Installation.spec.calicoNetwork.clusterRoutingMode (revert to default)")
	}
	inst := &operatorv1.Installation{}
	Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, inst)).To(Succeed())
	if inst.Spec.CalicoNetwork == nil {
		inst.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
	}
	inst.Spec.CalicoNetwork.ClusterRoutingMode = mode
	Expect(cli.Update(context.Background(), inst)).To(Succeed())
}

func ptrClusterRoutingMode(m operatorv1.ClusterRoutingMode) *operatorv1.ClusterRoutingMode {
	return &m
}
