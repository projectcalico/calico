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
// What stops it is the tunnel-route reject that confd builds in
// BGPExportFilterForTunnelRoutes (confd/pkg/backends/calico/bgp_processor.go) and the ipam
// templates render into calico_export_to_bgp_peers. The tunl0 arm of that reject is only emitted
// when BIRD is *not* the one programming the IPIP cluster routes, so this test has to put the
// cluster into that state to exercise it -- which is what the setup below does. In a BIRD-routed
// cluster the arm is absent, correctly, because there the routes are BGP-learned and the iBGP rule
// already covers them.
//
// This test pins that down for IPIP, which is the encapsulation whose ownership moved to Felix by
// default in v3.33. The unencapsulated case has the same shape and is not covered here -- see the
// "Felix-programmed cluster routes and BGP re-advertisement" gap in
// design/cluster-route-programming/DESIGN.md.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("BGPPeer"),
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
		var restoreOwnership func()
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

			// Deliberately no requireBGPIsSoleRoutingMechanism() here: this test wants Felix to own
			// the IPIP routes, and sets that up itself below.
			restoreBGPConfig = ensureInitialBGPConfig(cli)
			restoreOwnership = giveFelixTheClusterRoutes(cli)
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

			bgpStatus.WaitForEstablished()

			// Sanity check: cross-node connectivity works, i.e. Felix really has programmed the
			// remote routes. Without this the export assertion below could pass vacuously.
			checker.ResetExpectations()
			checker.ExpectSuccess(client1, server1.ClusterIPs()...)
			checker.Execute()
		})

		ginkgo.AfterEach(func() {
			checker.Stop()
			restoreOwnership()
			restoreBGPConfig()
		})

		ginkgo.It("should not be advertised over BGP by nodes that do not own them", func() {
			// Work out which node owns which block out of the test pool.
			blocks := &v3.IPAMBlockList{}
			err = cli.List(context.Background(), blocks)
			Expect(err).NotTo(HaveOccurred(), "Error listing IPAM blocks")

			ownerByBlock := map[string]string{}
			for _, b := range blocks.Items {
				if !strings.HasPrefix(b.Spec.CIDR, poolCIDRPrefix(poolCIDR)) {
					continue
				}
				if b.Spec.Affinity == nil {
					continue
				}
				// Affinity is "host:<nodename>".
				owner := strings.TrimPrefix(*b.Spec.Affinity, "host:")
				if owner == *b.Spec.Affinity {
					continue
				}
				ownerByBlock[b.Spec.CIDR] = owner
			}
			Expect(len(ownerByBlock)).To(BeNumerically(">=", 2),
				"expected at least two nodes to own a block out of %s, got %v", poolCIDR, ownerByBlock)
			logrus.Infof("Block ownership under test: %v", ownerByBlock)

			nodes := &corev1.NodeList{}
			err = cli.List(context.Background(), nodes)
			Expect(err).NotTo(HaveOccurred(), "Error listing nodes")

			// Guard against asserting nothing: pick a node and one of the blocks it does not own,
			// and require that node's route to it to be Felix's rather than BIRD's.
			for blockCIDR, owner := range ownerByBlock {
				for _, node := range nodes.Items {
					if node.Name != owner {
						expectFelixOwnsRemoteRoutes(f, node.Name, blockCIDR)
						break
					}
				}
				break
			}

			// For each node, every block it is exporting must be one it owns. Give BIRD a moment
			// to converge after the ownership switch before holding it to that.
			Eventually(func(g Gomega) {
				for _, node := range nodes.Items {
					exported := blocksExportedByNode(f, node.Name, poolCIDR)
					for _, cidr := range exported {
						owner, known := ownerByBlock[cidr]
						g.Expect(known).To(BeTrue(),
							"node %s is exporting %s, which is not a block of pool %s",
							node.Name, cidr, poolCIDR)
						g.Expect(owner).To(Equal(node.Name),
							"node %s is exporting %s, which is owned by %s; a node must only "+
								"advertise its own blocks, but Felix's route to a remote block is "+
								"learned by BIRD from the kernel and re-advertised",
							node.Name, cidr, owner)
					}
				}
			}, 60*time.Second, 5*time.Second).Should(Succeed())
		})
	})

// giveFelixTheClusterRoutes switches the cluster to Felix-programmed cluster routes and waits
// until that has actually taken effect. Returns a function that puts it back.
//
// It goes through Installation.spec.calicoNetwork.clusterRoutingMode rather than writing
// FelixConfiguration directly: on an operator-managed cluster the operator reconciles
// FelixConfiguration.programClusterRoutes from clusterRoutingMode, so a direct write is reverted
// within seconds -- and a test that did that would quietly assert nothing.
func giveFelixTheClusterRoutes(cli ctrlclient.Client) func() {
	ginkgo.By("Switching the cluster to Felix-programmed cluster routes")

	installation := &v1.Installation{}
	err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, installation)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error querying Installation")
	original := installation.Spec.CalicoNetwork.ClusterRoutingMode

	felixMode := v1.ClusterRoutingModeFelix
	installation.Spec.CalicoNetwork.ClusterRoutingMode = &felixMode
	err = cli.Update(context.Background(), installation)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Error updating Installation")

	// Wait for the operator to have pushed the change through to both config resources.
	EventuallyWithOffset(1, func(g Gomega) {
		fc := &v3.FelixConfiguration{}
		g.Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, fc)).To(Succeed())
		g.Expect(fc.Spec.ProgramClusterRoutes).NotTo(BeNil())
		g.Expect(*fc.Spec.ProgramClusterRoutes).To(Equal("Enabled"))

		bc := &v3.BGPConfiguration{}
		g.Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, bc)).To(Succeed())
		g.Expect(bc.Spec.ProgramClusterRoutes).NotTo(BeNil())
		g.Expect(*bc.Spec.ProgramClusterRoutes).To(Equal("Disabled"))
	}, 2*time.Minute, 5*time.Second).Should(Succeed(),
		"operator did not reconcile clusterRoutingMode through to the programClusterRoutes fields")

	return func() {
		ginkgo.By("Restoring the cluster's routing mode")
		installation := &v1.Installation{}
		if err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, installation); err == nil {
			installation.Spec.CalicoNetwork.ClusterRoutingMode = original
			_ = cli.Update(context.Background(), installation)
		}
	}
}

// expectFelixOwnsRemoteRoutes fails unless the kernel route to a remote block really is
// Felix-programmed. Without this the export assertion passes trivially on a BIRD-routed cluster,
// which is exactly what happens if the ownership switch above silently does not stick.
func expectFelixOwnsRemoteRoutes(f *framework.Framework, nodeName, remoteBlockCIDR string) {
	ginkgo.GinkgoHelper()
	Eventually(func(g Gomega) {
		pod := utils.GetCalicoNodePodOnNode(f.ClientSet, nodeName)
		g.Expect(pod).NotTo(BeNil(), "calico-node pod not found on node %s", nodeName)
		out, err := utils.ExecInCalicoNode(pod, fmt.Sprintf("ip route show %s", remoteBlockCIDR))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).NotTo(BeEmpty(), "node %s has no route to remote block %s", nodeName, remoteBlockCIDR)
		g.Expect(out).NotTo(ContainSubstring("proto bird"),
			"node %s's route to remote block %s is still BIRD-programmed (%s); the test would "+
				"assert nothing", nodeName, remoteBlockCIDR, strings.TrimSpace(out))
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
}

// blocksExportedByNode returns the CIDRs within poolCIDR that the given node's BIRD is exporting
// to its BGP peers, by asking BIRD directly rather than inferring it from connectivity.
func blocksExportedByNode(f *framework.Framework, nodeName, poolCIDR string) []string {
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
		out, err := utils.ExecInCalicoNode(pod,
			fmt.Sprintf("birdcl show route export %s", proto))
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
			if strings.HasPrefix(cidr, prefix) && strings.Contains(cidr, "/") {
				seen[cidr] = struct{}{}
			}
		}
	}

	exported := make([]string, 0, len(seen))
	for cidr := range seen {
		exported = append(exported, cidr)
	}
	logrus.Infof("Node %s is exporting these %s blocks: %v", nodeName, poolCIDR, exported)
	return exported
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
