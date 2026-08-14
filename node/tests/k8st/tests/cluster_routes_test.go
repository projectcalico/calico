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

// cluster_routes_test.go holds kind-only system tests for cluster route programming: which
// component programs the cross-node routes, and what a node advertises over BGP once Felix owns
// them.
//
// TestClusterRouteOwnership covers the first.  With an IPIP-Always pool, the route to a remote
// node's IPAM block must go out tunl0 and carry the netlink protocol of whichever component owns
// in-cluster routing: Felix (proto 80) by default, or BIRD (proto 12) if FelixConfiguration's
// ProgramClusterRoutes hands IPIP back to BIRD.
//
// TestFelixClusterRoutesNotReadvertised covers the second.  A node must not advertise another
// node's block over BGP merely because Felix programmed a kernel route to it.

package k8stests

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	e2eutils "github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

const (
	// routeOwnerPoolCIDR is the dedicated IPPool used by this test. Kept
	// separate from other pools so block-routes are easy to identify in
	// `ip route`.
	routeOwnerPoolCIDR = "203.0.113.0/24"

	// routeOwnerPoolPrefix is the substring matcher used against `ip route`
	// destinations. Any IPAM block carved out of routeOwnerPoolCIDR starts
	// with this prefix.
	routeOwnerPoolPrefix = "203.0.113."

	// routeOwnerPoolAnnotation pins a pod's IPAM assignment to our test pool.
	routeOwnerPoolAnnotation = "cni.projectcalico.org/ipv4pools"

	// routeExportPoolCIDR is a second dedicated IPPool, used by
	// TestFelixClusterRoutesNotReadvertised.  Kept separate from
	// routeOwnerPoolCIDR so that neither test can see the other's blocks
	// in BIRD's export tables.
	routeExportPoolCIDR = "192.0.2.0/24"

	// routeExportPoolPrefix is the substring matcher for blocks carved out
	// of routeExportPoolCIDR.
	routeExportPoolPrefix = "192.0.2."

	// routeExportXSubnetPoolCIDR is a third dedicated IPPool, in ipipMode
	// CrossSubnet, which TestFelixClusterRoutesNotReadvertised checks
	// alongside routeExportPoolCIDR.  Its own CIDR again, so that the two
	// pools' exports can be told apart.
	routeExportXSubnetPoolCIDR = "198.51.100.0/24"

	// routeExportXSubnetPoolPrefix is the substring matcher for blocks
	// carved out of routeExportXSubnetPoolCIDR.
	routeExportXSubnetPoolPrefix = "198.51.100."
)

// TestClusterRouteOwnership stands up a server / client pair on different nodes
// inside an IPIP-Always pool, checks cross-node pod connectivity (which must
// traverse the IPIP tunnel), then asserts that the client node's route to the
// server's block is owned by the configured cluster-route owner via tunl0.
func TestClusterRouteOwnership(t *testing.T) {
	// Safe to parallelise: this test confines its mutations to its own
	// dedicated IPPool and randomly-suffixed namespace, and only reads
	// cluster-global config (the default FelixConfiguration). Go defers
	// parallel tests until all serial tests have finished, so the
	// cluster-disruptive k8st tests never overlap with this one.
	t.Parallel()
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	// Need at least two workers so the server and client land on different
	// nodes — otherwise there is no cross-node route to inspect. NodeInfo
	// returns the control-plane node first, then workers.
	nodes, _, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 3),
		"need a control-plane node and at least two workers")
	serverNode, clientNode := nodes[1], nodes[2]

	pool := &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "route-owner-pool"},
		Spec: v3.IPPoolSpec{
			CIDR:             routeOwnerPoolCIDR,
			IPIPMode:         v3.IPIPModeAlways,
			NATOutgoing:      true,
			BlockSize:        28,
			DisableBGPExport: false,
		},
	}
	g.Expect(cli.Create(ctx, pool)).To(Succeed(), "creating IPPool")
	t.Cleanup(func() { deletePool(t, cli, pool.Name) })

	nsName := e2eutils.GenerateRandomName("cluster-routes")
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName}}
	g.Expect(cli.Create(ctx, ns)).To(Succeed(), "creating namespace")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), ns) })

	server := routeOwnerPod(nsName, "server", serverNode, pool.Name, true)
	g.Expect(cli.Create(ctx, server)).To(Succeed(), "creating server pod")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), server) })

	client := routeOwnerPod(nsName, "client", clientNode, pool.Name, false)
	g.Expect(cli.Create(ctx, client)).To(Succeed(), "creating client pod")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), client) })

	serverIP := waitForPodIP(ctx, g, cli, server, corev1.IPv4Protocol)
	t.Logf("Server pod %s/%s scheduled on %s with IP %s", nsName, server.Name, serverNode, serverIP)
	waitForPodIP(ctx, g, cli, client, corev1.IPv4Protocol)

	// Sanity-check cross-node reachability before asserting on routes: the
	// client pod must reach the server's pod IP, which crosses the IPIP tunnel.
	g.Eventually(func() error {
		_, err := utils.ExecInPod(t, nsName, client.Name,
			fmt.Sprintf("curl --silent --show-error --max-time 5 http://%s/clientip", serverIP+":80"),
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		return err
	}, "120s", "1s").Should(Succeed(),
		"client pod could not reach server pod %s across the IPIP tunnel", serverIP)

	// The client node's route to the server's block must be programmed by the
	// configured owner, out tunl0.
	utils.AssertRouteOwnership(t, clientNode, routeOwnerPoolPrefix, "tunl0", expectedIPIPClusterRouteProto(g, cli))
}

// exportTestPool is one of the IP Pools that TestFelixClusterRoutesNotReadvertised stands up.  The
// two differ only in encapsulation mode, which is what decides the device Felix's route to another
// node's block leaves by, and so which arm of the reject has to catch it.
type exportTestPool struct {
	name     string
	cidr     string
	prefix   string
	ipipMode v3.IPIPMode
	// expectedDev is the device Felix's route to another node's block must leave by, or "" when
	// that depends on the cluster's topology rather than on the pool.
	expectedDev string
}

// TestFelixClusterRoutesNotReadvertised checks that a node does not advertise another node's IPAM
// block over BGP merely because Felix programmed a kernel route to it.
//
// A node's BGP export is meant to carry the blocks that node owns, and nothing else.  Under iBGP a
// node does not re-advertise what it learned from another mesh peer, so in a BIRD-routed cluster
// that property holds for free.  It does not hold for free once Felix owns the cluster routes:
// Felix programs a route to every remote node's block, BIRD's kernel protocol is configured with
// `learn` so it picks those up as its own, and a kernel-learned route is not subject to the iBGP
// no-re-advertisement rule.  What stops it is the reject that confd builds in
// IBGPExportFilterForFelixClusterRoutes (confd/pkg/backends/calico/bgp_processor.go) and the ipam
// templates render into calico_export_to_bgp_peers.
//
// That reject has two arms, and this test covers one with each pool:
//
//   - The ipipMode: Always pool exercises the arm that matches on the outgoing interface, whose
//     tunl0 test is only emitted when Felix is the component programming the IPIP cluster routes.
//   - The ipipMode: CrossSubnet pool exercises the arm that matches on the pool's CIDR.  Felix
//     does not encapsulate the route to a node in this node's own subnet, so that route leaves by
//     the host NIC and the interface test does not see it.
func TestFelixClusterRoutesNotReadvertised(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	// The assertion only means something where Felix owns the IPIP cluster routes.  Under BIRD the
	// remote block routes are BGP-learned, the iBGP rule already covers them, and there is nothing
	// here to catch.
	if owner := expectedIPIPClusterRouteProto(g, cli); owner != utils.RouteProtoFelix {
		t.Skipf("cluster is configured for %s-owned IPIP cluster routes, so no route can leak", owner)
	}

	// Two workers, so that two nodes own a block out of the test pool and each has the other's
	// block to route to.  NodeInfo returns the control-plane node first, then workers.
	nodes, _, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 3),
		"need a control-plane node and at least two workers")
	nodeA, nodeB := nodes[1], nodes[2]

	pools := []exportTestPool{
		{
			name:        "route-export-pool",
			cidr:        routeExportPoolCIDR,
			prefix:      routeExportPoolPrefix,
			ipipMode:    v3.IPIPModeAlways,
			expectedDev: "tunl0",
		},
		{
			name:     "route-export-xsubnet-pool",
			cidr:     routeExportXSubnetPoolCIDR,
			prefix:   routeExportXSubnetPoolPrefix,
			ipipMode: v3.IPIPModeCrossSubnet,
			// Whether this one is encapsulated is a property of the cluster, not of the pool: the
			// route to a node in our own subnet leaves by the host NIC, and only a node in another
			// subnet is reached through tunl0.
			expectedDev: "",
		},
	}
	for _, p := range pools {
		pool := &v3.IPPool{
			ObjectMeta: metav1.ObjectMeta{Name: p.name},
			Spec: v3.IPPoolSpec{
				CIDR:        p.cidr,
				IPIPMode:    p.ipipMode,
				NATOutgoing: true,
				BlockSize:   28,
				// Explicit because this test reads BIRD's export tables: with export disabled
				// there would be nothing in them and the assertion would pass vacuously.
				DisableBGPExport: false,
			},
		}
		g.Expect(cli.Create(ctx, pool)).To(Succeed(), "creating IPPool %s", p.name)
		t.Cleanup(func() { deletePool(t, cli, pool.Name) })
	}

	nsName := e2eutils.GenerateRandomName("route-exports")
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName}}
	g.Expect(cli.Create(ctx, ns)).To(Succeed(), "creating namespace")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), ns) })

	// One pod per worker per pool, pinned to that pool, which is what makes each of those nodes
	// take a block affinity out of it.  The pods only need to hold an address, so all of them are
	// idle: crossing the tunnel is TestClusterRouteOwnership's job.
	for _, p := range pools {
		for i, node := range []string{nodeA, nodeB} {
			pod := routeOwnerPod(nsName, fmt.Sprintf("%s-%d", p.name, i), node, p.name, false)
			g.Expect(cli.Create(ctx, pod)).To(Succeed(), "creating pod on %s", node)
			t.Cleanup(func() { _ = cli.Delete(context.Background(), pod) })
			waitForPodIP(ctx, g, cli, pod, corev1.IPv4Protocol)
		}
	}

	// Guard against asserting nothing: each worker must have a Felix-programmed route into each
	// pool, which can only be a route to the other worker's block, since a node's own block is a
	// blackhole with no device.  Those are the routes that could leak.
	for _, p := range pools {
		for _, node := range []string{nodeA, nodeB} {
			utils.AssertRouteOwnership(t, node, p.prefix, p.expectedDev, utils.RouteProtoFelix)
		}
	}
	logUnencapsulatedClusterRoute(t, []string{nodeA, nodeB}, routeExportXSubnetPoolPrefix)

	// Every node's BIRD, control plane included, must export blocks of these pools only as the
	// blackhole route that confd derives from the node's own block affinity.  Anything else -- in
	// practice a "via <node>", on tunl0 or on the host NIC -- is a route the node learned from the
	// kernel because Felix programmed it, and is not the node's to advertise.
	blockOwner := map[string]bool{nodeA: true, nodeB: true}
	g.Eventually(func() error {
		for _, node := range nodes {
			// Nothing can leak to a peering that does not exist: the reject sits inside
			// `if (internal_peer)` in calico_export_to_bgp_peers, so a node with no established
			// peering would satisfy the assertion below for the wrong reason.
			protocols, err := establishedBGPProtocols(t, node)
			if err != nil {
				return err
			}
			if len(protocols) == 0 {
				return fmt.Errorf("node %s has no established BGP peering, so a leak could not show up",
					node)
			}

			for _, p := range pools {
				blackholes, others, err := poolExports(t, node, protocols, p.prefix)
				if err != nil {
					return err
				}
				if len(others) > 0 {
					return fmt.Errorf("node %s is exporting %v from pool %s over BGP; a node should "+
						"advertise only its own blocks, and only as blackhole routes.  These are "+
						"Felix's routes to other nodes' blocks, learned by BIRD from the kernel and "+
						"re-advertised", node, others, p.cidr)
				}

				// Positive control for the nodes that do own a block: without this, "no
				// non-blackhole exports" would also be satisfied by a node exporting nothing at all.
				if blockOwner[node] && len(blackholes) == 0 {
					return fmt.Errorf("node %s owns a block of %s but is not exporting it as a blackhole",
						node, p.cidr)
				}
			}
		}
		return nil
	}, 90*time.Second, 5*time.Second).Should(Succeed())
}

// logUnencapsulatedClusterRoute reports whether the CrossSubnet pool is actually exercising the
// unencapsulated path, which is the one the interface test in calico_export_to_bgp_peers cannot
// catch.  It only holds where the workers share a subnet, which is the case for the kind clusters
// this suite runs on, but is a property of the cluster rather than something the test can impose —
// so this is a log line and not an assertion.
func logUnencapsulatedClusterRoute(t testing.TB, nodes []string, prefix string) {
	t.Helper()
	for _, node := range nodes {
		routes, err := utils.GetNodeRoutes(t, node, prefix)
		if err != nil {
			t.Logf("Could not read routes matching %q on node %s: %v", prefix, node, err)
			continue
		}
		for _, r := range routes {
			// "lo" and no device at all are this node's own blackholed block, not a route to
			// anywhere; tunl0 is the encapsulated case the interface test already covers.
			if r.Proto == utils.RouteProtoFelix && r.Dev != "" && r.Dev != "lo" && r.Dev != "tunl0" {
				t.Logf("Node %s reaches %q unencapsulated, on dev %s: exercising the pool-CIDR arm "+
					"of the export reject", node, r.Dst, r.Dev)
				return
			}
		}
	}
	t.Logf("No unencapsulated Felix route to %q on any worker: the workers of this cluster do not "+
		"share a subnet, so the CrossSubnet pool only re-tests the encapsulated path", prefix)
}

// routeOwnerPod builds a pod pinned to nodeName and to the test IPPool. The
// server runs an HTTP echo server; the client just idles and is curled from
// in the connectivity check.
func routeOwnerPod(namespace, name, nodeName, poolName string, server bool) *corev1.Pod {
	container := corev1.Container{Name: name, Image: utils.Agnhost}
	if server {
		container.Args = []string{"netexec", "--http-port=80"}
		container.Ports = []corev1.ContainerPort{{ContainerPort: 80}}
	} else {
		container.Args = []string{"pause"}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{routeOwnerPoolAnnotation: fmt.Sprintf("[%q]", poolName)},
		},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{container},
		},
	}
}

// expectedIPIPClusterRouteProto returns the route protocol owner that the
// cluster is currently configured to use for IPIP cluster routes: Felix (proto
// 80) unless FelixConfiguration explicitly hands IPIP back to BIRD (proto 12).
// The default, with the field unset, is EnabledIPIPOnly, i.e. Felix.
func expectedIPIPClusterRouteProto(g *WithT, cli ctrlclient.Client) utils.RouteProto {
	fc := &v3.FelixConfiguration{}
	g.Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, fc)).
		To(Succeed(), "querying default FelixConfiguration")
	if fc.Spec.ProgramClusterRoutes == nil {
		return utils.RouteProtoFelix
	}
	switch *fc.Spec.ProgramClusterRoutes {
	case v3.Disabled, v3.EnabledNoEncapOnly:
		return utils.RouteProtoBIRD
	default:
		// Enabled and EnabledIPIPOnly, but also anything this binary does not recognise:
		// Felix replaces an unparseable value with the parameter's default, which is
		// EnabledIPIPOnly, so a newer value than we know about still means Felix here.
		return utils.RouteProtoFelix
	}
}

// establishedBGPProtocols returns the names of the BIRD protocols on nodeName that are BGP and
// Established.  The columns of `birdcl show protocols` are name, proto, table, state, since, info,
// and for a BGP protocol it is the trailing info column that carries "Established".  Sessions that
// are down are left out because they have no export table to inspect.
func establishedBGPProtocols(t testing.TB, nodeName string) ([]string, error) {
	t.Helper()

	out, err := utils.ExecInCalicoNode(t, nodeName, "birdcl show protocols")
	if err != nil {
		return nil, fmt.Errorf("listing BIRD protocols on node %s: %w", nodeName, err)
	}

	var names []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "BGP" && strings.Contains(line, "Established") {
			names = append(names, fields[0])
		}
	}
	return names, nil
}

// poolExports splits the routes matching poolPrefix that nodeName's BIRD is exporting to the given
// peerings into those it exports as a blackhole -- its own block, from its block affinity -- and
// everything else.  It asks BIRD directly rather than inferring the answer from connectivity.
//
// Only lines that start with a CIDR are considered: BIRD prints additional paths for the same prefix
// as continuation lines, and a node's own block legitimately has a second, kernel-sourced path
// behind the static one.
func poolExports(t testing.TB, nodeName string, protocols []string, poolPrefix string) (blackholes, others []string, err error) {
	t.Helper()

	seen := map[string]bool{}
	for _, protocol := range protocols {
		// `show route export` takes a single protocol name, hence one call per peering.
		out, err := utils.ExecInCalicoNode(t, nodeName,
			fmt.Sprintf("birdcl show route export %s", protocol))
		if err != nil {
			return nil, nil, fmt.Errorf("reading exports of protocol %s on node %s: %w",
				protocol, nodeName, err)
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if cidr := fields[0]; !strings.HasPrefix(cidr, poolPrefix) ||
				!strings.Contains(cidr, "/") {
				continue
			}
			line = strings.TrimSpace(line)
			if seen[line] {
				continue
			}
			seen[line] = true
			if strings.Contains(line, "blackhole") {
				blackholes = append(blackholes, line)
			} else {
				others = append(others, line)
			}
		}
	}

	// Deterministic order, so a failure message reads the same way on a re-run.
	slices.Sort(blackholes)
	slices.Sort(others)
	return blackholes, others, nil
}
