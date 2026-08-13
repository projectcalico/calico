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

package bgp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"

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
)

// A node's BGP export is meant to carry the blocks that node owns, and nothing else. Under iBGP
// a node does not re-advertise what it learned from another mesh peer, so in a BIRD-routed cluster
// that property holds for free.
//
// It does not hold for free once Felix owns the cluster routes. Felix programs a route to every
// remote node's block in the kernel; BIRD's kernel protocol is configured with `learn`, so it picks
// those up as its own routes, and a kernel-learned route is not subject to the iBGP
// no-re-advertisement rule. Left alone, every node ends up advertising every other node's blocks.
//
// What stops it is the tunnel-route reject that confd builds in IBGPExportFilterForTunnelRoutes
// (confd/pkg/backends/calico/bgp_processor.go) and the ipam templates render into
// calico_export_to_bgp_peers. The tunl0 arm of that reject is only emitted when Felix is the one
// programming the IPIP cluster routes. In a BIRD-routed cluster that condition is not needed
// because there the routes are BGP-learned and the iBGP rule already covers them.
//
// So this test needs a Felix-routed cluster, which is why it carries Feature:ClusterRoutes and is
// included only by e2e/config/kind-felix-routing.yaml.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("ClusterRoutes"),
	describe.WithCategory(describe.Networking),
	describe.RequiresBGPMesh(),
	describe.WithSerial(),
	"Felix-programmed cluster routes",
	func() {
		const poolName = "felix-routes-ipip-pool"
		const poolCIDR = "172.25.0.0/16"

		var err error
		var cli ctrlclient.Client
		var checker conncheck.ConnectionTester
		var server1 conncheck.Server
		var client1 conncheck.Client
		var restoreBGPConfig func()
		var bgpStatus *BGPStatusMonitor

		f := utils.NewDefaultFramework("felix-routes")

		ginkgo.BeforeEach(func() {
			checker = conncheck.NewConnectionTester(f)

			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Two nodes minimum: with one node there is no remote block to mis-advertise.
			utils.RequireNodeCount(f, 2)

			installation := &v1.Installation{}
			err = cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, installation)
			Expect(err).NotTo(HaveOccurred(), "Error querying Installation resource")
			Expect(installation.Spec.CalicoNetwork).NotTo(BeNil(), "CalicoNetwork is not configured in the Installation")
			Expect(installation.Spec.CalicoNetwork.BGP).NotTo(BeNil(), "BGP is not enabled in the cluster")
			Expect(*installation.Spec.CalicoNetwork.BGP).To(Equal(v1.BGPEnabled), "BGP is not enabled in the cluster")

			// The inverse of requireBGPIsSoleRoutingMechanism, which the other specs in this
			// package use: this one needs a cluster where Felix, not BIRD, owns the routes.
			requireFelixOwnsIPIPClusterRoutes(cli)

			restoreBGPConfig = ensureInitialBGPConfig(cli)
			bgpStatus = NewBGPStatusMonitor(cli)

			// A dedicated IPIP pool, so the blocks under test are easy to identify in BIRD's
			// output and can't be confused with the cluster's default pool.
			pool := v3.NewIPPool()
			pool.Name = poolName
			pool.Spec.CIDR = poolCIDR
			pool.Spec.IPIPMode = v3.IPIPModeAlways
			pool.Spec.VXLANMode = v3.VXLANModeNever
			pool.Spec.NATOutgoing = true
			pool.Spec.BlockSize = 26
			err = cli.Create(context.Background(), pool)
			Expect(err).NotTo(HaveOccurred(), "Error creating IP pool")
			ginkgo.DeferCleanup(func() {
				err := cli.Delete(context.Background(), pool)
				Expect(err).NotTo(HaveOccurred(), "Error deleting IP pool")
			})

			// A client and a server on different nodes, both in the test pool, so that at least
			// two nodes own a block out of it and each has a remote block to reach.
			customizer := conncheck.CombineCustomizers(
				conncheck.UseV4IPPool(pool.Name),
				conncheck.AvoidEachOther,
			)
			server1 = conncheck.NewServer("server", f.Namespace,
				conncheck.WithServerLabels(map[string]string{"role": "server"}),
				conncheck.WithServerPodCustomizer(customizer))
			client1 = conncheck.NewClient("client", f.Namespace,
				conncheck.WithClientCustomizer(customizer))
			checker.AddServer(server1)
			checker.AddClient(client1)
			checker.Deploy()

			// Even though we don't rely on BGP for intra-cluster routing, this test
			// still tests some BGP state; hence checking here that peerings are
			// established.
			bgpStatus.WaitForEstablished()

			// Sanity check: cross-node connectivity works, i.e. Felix really has programmed the
			// remote routes. Without this the export assertion below could pass vacuously.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()
		})

		ginkgo.AfterEach(func() {
			checker.Stop()
			restoreBGPConfig()
		})

		ginkgo.It("should not be advertised over BGP by nodes that do not own them", func() {
			nodes := &corev1.NodeList{}
			err = cli.List(context.Background(), nodes)
			Expect(err).NotTo(HaveOccurred(), "Error listing nodes")

			// Guard against asserting nothing: somewhere in the cluster Felix has to be
			// programming a route to a block it does not own, or there is nothing to leak.
			expectFelixProgramsARemoteBlockRoute(f, nodes, poolCIDR)

			// A node's own block reaches its BGP peers as the blackhole route that confd puts
			// in bird_aggr.cfg from the block affinity. Anything else it exports for this pool
			// -- in practice a "via <node> on tunl0" -- is a route it learned from the kernel
			// because Felix programmed it, and is not this node's to advertise.
			Eventually(func(g Gomega) {
				for _, node := range nodes.Items {
					leaked := nonBlackholePoolExports(f, node.Name, poolCIDR)
					g.Expect(leaked).To(BeEmpty(),
						"node %s is exporting %v over BGP. A node should only advertise its own "+
							"blocks, which it does as blackhole routes; these are Felix's routes "+
							"to other nodes' blocks, learned by BIRD from the kernel and "+
							"re-advertised", node.Name, leaked)
				}
			}, 60*time.Second, 5*time.Second).Should(Succeed())
		})
	})

// expectFelixProgramsARemoteBlockRoute fails unless some node has a route to a block of poolCIDR
// that it does not own -- a "via" route rather than a blackhole -- and that route is Felix's
// rather than BIRD's. Without that there is nothing for the export assertion to catch, and it
// would pass on a cluster where Felix never programmed anything.
func expectFelixProgramsARemoteBlockRoute(f *framework.Framework, nodes *corev1.NodeList, poolCIDR string) {
	ginkgo.GinkgoHelper()

	prefix := poolCIDRPrefix(poolCIDR)
	Eventually(func(g Gomega) {
		for _, node := range nodes.Items {
			pod := utils.GetCalicoNodePodOnNode(f.ClientSet, node.Name)
			if pod == nil {
				continue
			}
			out, err := utils.ExecInCalicoNode(pod, "ip route show")
			if err != nil {
				continue
			}
			for _, line := range strings.Split(out, "\n") {
				if !strings.HasPrefix(strings.TrimSpace(line), prefix) || !strings.Contains(line, " via ") {
					continue
				}
				g.Expect(line).NotTo(ContainSubstring("proto bird"),
					"node %s's route to a remote block is BIRD's, not Felix's (%s); this test "+
						"needs a Felix-routed cluster", node.Name, strings.TrimSpace(line))
				logrus.Infof("Felix-programmed remote block route on %s: %s", node.Name, strings.TrimSpace(line))
				return
			}
		}
		g.Expect(false).To(BeTrue(),
			"no node has a route to a remote block of %s, so there is nothing to leak", poolCIDR)
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

// requireFelixOwnsIPIPClusterRoutes fails unless the cluster is configured with Felix, rather than
// confd and BIRD, programming the cluster routes for IPIP IP pools. This test has nothing to say
// about a BIRD-routed cluster, and asserting against one would pass trivially.
func requireFelixOwnsIPIPClusterRoutes(cli ctrlclient.Client) {
	ginkgo.GinkgoHelper()

	fc := &v3.FelixConfiguration{}
	Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, fc)).
		To(Succeed(), "Error querying default FelixConfiguration")

	// An unset field means Calico's own default, which is EnabledIPIPOnly.
	programClusterRoutes := "EnabledIPIPOnly"
	if fc.Spec.ProgramClusterRoutes != nil {
		programClusterRoutes = *fc.Spec.ProgramClusterRoutes
	}
	Expect(programClusterRoutes).To(BeElementOf("Enabled", "EnabledIPIPOnly"),
		"this test needs Felix to own the IPIP cluster routes, but FelixConfiguration's "+
			"programClusterRoutes is %s.", programClusterRoutes)
}

// nonBlackholePoolExports returns the routes within poolCIDR that the given node's BIRD is
// exporting to its BGP peers other than as a blackhole, by asking BIRD directly rather than
// inferring it from connectivity.
//
// Only lines that start with a CIDR are considered: BIRD prints additional paths for the same
// prefix as continuation lines, and a node's own block legitimately has a second, kernel-sourced
// path behind the static one.
func nonBlackholePoolExports(f *framework.Framework, nodeName, poolCIDR string) []string {
	pod := utils.GetCalicoNodePodOnNode(f.ClientSet, nodeName)
	ExpectWithOffset(1, pod).NotTo(BeNil(), "calico-node pod not found on node %s", nodeName)

	// Each BGP peering is a separate BIRD protocol; ask for the routes exported to all of them.
	// "show route export" needs a protocol name, so enumerate the BGP protocols first. The
	// calico-node image has no awk, so the parsing is all done here.
	protoOut, err := utils.ExecInCalicoNode(pod, "birdcl show protocols")
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error listing BIRD protocols on node %s", nodeName)

	prefix := poolCIDRPrefix(poolCIDR)
	seen := map[string]struct{}{}
	for _, proto := range bgpProtocolNames(protoOut) {
		out, err := utils.ExecInCalicoNode(pod, fmt.Sprintf("birdcl show route export %s", proto))
		if err != nil {
			// A peering that is down has no export table; that is not a failure for this test.
			logrus.WithError(err).Infof("Could not read exports for protocol %s on %s", proto, nodeName)
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			cidr := fields[0]
			if !strings.HasPrefix(cidr, prefix) || !strings.Contains(cidr, "/") {
				continue
			}
			if strings.Contains(line, "blackhole") {
				// The node's own block, advertised from its block affinity. Expected.
				continue
			}
			seen[strings.TrimSpace(line)] = struct{}{}
		}
	}

	leaked := make([]string, 0, len(seen))
	for line := range seen {
		leaked = append(leaked, line)
	}
	logrus.Infof("Node %s exports these non-blackhole %s routes: %v", nodeName, poolCIDR, leaked)
	return leaked
}

// bgpProtocolNames picks the BGP protocol names out of "birdcl show protocols" output, whose
// columns are: name, proto, table, state, since, info.
func bgpProtocolNames(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "BGP" {
			names = append(names, fields[0])
		}
	}
	return names
}

// poolCIDRPrefix reduces a pool CIDR to the leading octets its blocks share, so block CIDRs can be
// matched against it with a string prefix. "172.25.0.0/16" -> "172.25.".
func poolCIDRPrefix(poolCIDR string) string {
	addr := strings.Split(poolCIDR, "/")[0]
	octets := strings.Split(addr, ".")
	if len(octets) < 2 {
		return addr
	}
	return octets[0] + "." + octets[1] + "."
}
