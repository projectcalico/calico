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

// bgp_filter_test.go is a kind-only system test for BGPFilter resources. It
// stands up two external BIRD routers (one IPv4, one IPv6) peered with a single
// "egress" cluster node and then asserts that import/export filters attached to
// the BGPPeers take effect: routes the external router advertises stop being
// learned by the cluster's BIRD (import reject), and the cluster's IPAM-block
// routes stop being advertised to the external router (export reject). It also
// exercises multi-rule / multi-filter ordering and global (non-node-selected)
// peers.

package k8stests

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	e2eutils "github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

// bgpFilterBIRDConf is the per-peer BIRD config installed on the external
// routers. "ip@local" is replaced with the router's own address by
// StartExternalNodeWithBGP; the %s is the egress cluster node's address.
const bgpFilterBIRDConf = `
# Template for all BGP clients
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 64512;
  multihop;
  gateway recursive; # This should be the default, but just in case.
  import all;        # Import all routes, since we don't know what the upstream
                     # topology is and therefore have to trust the ToR/RR.
  export all;
  source address ip@local;  # The local address we use for the TCP connection
  add paths on;
  graceful restart;  # See comment in kernel section about graceful restart.
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
}

# ------------- Node-to-node mesh -------------
protocol bgp Mesh_with_node_1 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}
`

const (
	externalNodeV4 = "kube-node-extra"
	externalNodeV6 = "kube-node-extra-v6"

	peerNameV4 = "node-extra.peer"
	peerNameV6 = "node-extra-v6.peer"

	// Route advertised by the external routers and matched in the cluster BIRD.
	externalRouteV4 = "10.111.111.0/24"
	externalRouteV6 = "fd00:1111:1111:1111::/64"

	// Regexes matching a cluster IPAM-block route as seen on the external
	// router (the default pools' block CIDRs).
	clusterRouteRegexV4 = `192\.168\.\d+\.\d+/\d+`
	clusterRouteRegexV6 = `fd00:10:244:.*/\d+`

	// CIDRs that cover the cluster pools, used by the export-reject filters.
	exportFilterCIDRV4 = "192.168.0.0/16"
	exportFilterCIDRV6 = "fd00:10:244::/64"
)

// bgpFilterEnv is the shared, expensive-to-build fixture for the BGPFilter
// tests: two external routers peered with one egress node.
type bgpFilterEnv struct {
	cli ctrlclient.Client

	egressNode    string
	egressNodeIP  string
	egressNodeIP6 string

	externalNodeIP  string
	externalNodeIP6 string
}

// TestBGPFilter sets up the external routers and BGPPeers once, then runs each
// filter scenario across the IPv4, IPv6 and dual-stack variants as subtests.
// Subtests run sequentially and each restores the shared fixture (peer filters,
// node selector, static routes) on completion, so ordering between them does
// not matter.
func TestBGPFilter(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	// Setup stands up two external routers (~30-60s each) before creating the
	// BGPPeers, so give the fixture a generous window.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	t.Cleanup(cancel)

	env := setupBGPFilterEnv(t, ctx, g)

	for _, tc := range []struct {
		name string
		fn   func(t *testing.T, env *bgpFilterEnv, ipv4, ipv6 bool)
	}{
		{"basic", testBGPFilterBasic},
		{"ordering", testBGPFilterOrdering},
		{"global_peer", testBGPFilterGlobalPeer},
	} {
		for _, family := range []struct {
			suffix     string
			ipv4, ipv6 bool
		}{
			{"v4", true, false},
			{"v6", false, true},
			{"v4v6", true, true},
		} {
			t.Run(tc.name+"_"+family.suffix, func(t *testing.T) {
				tc.fn(t, env, family.ipv4, family.ipv6)
			})
		}
	}
}

// setupBGPFilterEnv creates the external routers, labels the egress node and
// establishes the BGPPeers from the cluster to the routers. It registers
// cleanups that tear all of that down. Mirrors test_base.py setUpClass.
func setupBGPFilterEnv(t *testing.T, ctx context.Context, g *WithT) *bgpFilterEnv {
	cli := newClient(g)

	nodes, ips, ip6s := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 2),
		"BGPFilter test needs at least one worker node to peer from")

	env := &bgpFilterEnv{
		cli:           cli,
		egressNode:    nodes[1],
		egressNodeIP:  ips[1],
		egressNodeIP6: ip6s[1],
	}

	// Create the external BGP routers, one per family, peered with the egress
	// node. These are expensive (~30-60s each), so we build them once.
	env.externalNodeIP = utils.StartExternalNodeWithBGP(t, externalNodeV4,
		fmt.Sprintf(bgpFilterBIRDConf, env.egressNodeIP), "")
	t.Cleanup(func() { _, _ = utils.Run(t, "docker rm -f "+externalNodeV4, utils.RunOptions{AllowFail: true}) })

	env.externalNodeIP6 = utils.StartExternalNodeWithBGP(t, externalNodeV6,
		"", fmt.Sprintf(bgpFilterBIRDConf, env.egressNodeIP6))
	t.Cleanup(func() { _, _ = utils.Run(t, "docker rm -f "+externalNodeV6, utils.RunOptions{AllowFail: true}) })

	// Mark the egress node so the node-selected BGPPeers attach to it.
	labelNode(t, env.egressNode, "egress", "true")

	// anchorNS pins an idle pod to the egress node so it owns an IPAM block to
	// advertise. The random suffix keeps it unique per test so concurrent or
	// repeated runs against the same cluster do not collide.
	anchorNS := e2eutils.GenerateRandomName("bgp-filter-anchor")
	ensureEgressNodeOwnsBlock(t, ctx, g, cli, env.egressNode, anchorNS)

	// Establish BGPPeers from the egress node to each external router.
	createBGPPeer(t, ctx, g, cli, peerNameV4, env.externalNodeIP)
	createBGPPeer(t, ctx, g, cli, peerNameV6, env.externalNodeIP6)

	return env
}

// ensureEgressNodeOwnsBlock pins an idle pod to the egress node so it owns an
// IPAM block to advertise — otherwise the export assertions are checking a node
// that may host no pods (and thus no block, especially for IPv6). The pod uses
// the default pools so its block CIDRs match clusterRouteRegexV4/V6; waiting for
// both IPs claims a block in each family before any assertion runs.
func ensureEgressNodeOwnsBlock(t *testing.T, ctx context.Context, g *WithT, cli ctrlclient.Client, node, nsName string) {
	t.Helper()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName}}
	g.Expect(cli.Create(ctx, ns)).To(Succeed(), "creating anchor namespace")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), ns) })

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "block-anchor", Namespace: nsName},
		Spec: corev1.PodSpec{
			NodeName:   node,
			Containers: []corev1.Container{{Name: "anchor", Image: utils.Agnhost, Args: []string{"pause"}}},
		},
	}
	g.Expect(cli.Create(ctx, pod)).To(Succeed(), "creating block-anchor pod on egress node %s", node)
	t.Cleanup(func() { _ = cli.Delete(context.Background(), pod) })

	waitForPodIP(ctx, g, cli, pod, corev1.IPv4Protocol)
	waitForPodIP(ctx, g, cli, pod, corev1.IPv6Protocol)
}

// testBGPFilterBasic adds a route to the external router, verifies import and
// export work both ways, then attaches export- and import-reject filters and
// verifies each route disappears from the respective BIRD.
func testBGPFilterBasic(t *testing.T, env *bgpFilterEnv, ipv4, ipv6 bool) {
	defer utils.CollectDiagsOnFailure(t)()
	g := NewWithT(t)
	ctx := context.Background()

	if ipv4 {
		env.addExternalStaticRoute(t, externalNodeV4, "bird", "birdcl", externalRouteV4, env.externalNodeIP)
	}
	if ipv6 {
		env.addExternalStaticRoute(t, externalNodeV6, "bird6", "birdcl6", externalRouteV6, env.externalNodeIP6)
	}

	// The egress node should learn the route the external router advertises.
	if ipv4 {
		env.assertClusterRoute(t, externalRouteV4, env.externalNodeIP, false, false, true)
	}
	if ipv6 {
		env.assertClusterRoute(t, externalRouteV6, env.externalNodeIP6, true, false, true)
	}

	// The external router should have a route for a cluster IPAM block.
	if ipv4 {
		assertExternalRoute(t, externalNodeV4, "Mesh_with_node_1", clusterRouteRegexV4, regexp.QuoteMeta(env.egressNodeIP), false, true)
	}
	if ipv6 {
		assertExternalRoute(t, externalNodeV6, "Mesh_with_node_1", clusterRouteRegexV6, regexp.QuoteMeta(env.egressNodeIP6), true, true)
	}

	// Export-reject filter: the cluster block should stop being advertised.
	if ipv4 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-export-1"},
			Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
				{CIDR: exportFilterCIDRV4, MatchOperator: v3.MatchOperatorIn, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV4, "test-filter-export-1")
		assertExternalRoute(t, externalNodeV4, "Mesh_with_node_1", clusterRouteRegexV4, regexp.QuoteMeta(env.egressNodeIP), false, false)
	}
	if ipv6 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-export-v6-1"},
			Spec: v3.BGPFilterSpec{ExportV6: []v3.BGPFilterRuleV6{
				{CIDR: exportFilterCIDRV6, MatchOperator: v3.MatchOperatorIn, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV6, "test-filter-export-v6-1")
		assertExternalRoute(t, externalNodeV6, "Mesh_with_node_1", clusterRouteRegexV6, regexp.QuoteMeta(env.egressNodeIP6), true, false)
	}

	// Import-reject filter: the egress node should stop learning the route.
	if ipv4 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-1"},
			Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
				{CIDR: externalRouteV4, MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV4, "test-filter-import-1")
		env.assertClusterRoute(t, externalRouteV4, env.externalNodeIP, false, false, false)
	}
	if ipv6 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-v6-1"},
			Spec: v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{
				{CIDR: externalRouteV6, MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV6, "test-filter-import-v6-1")
		env.assertClusterRoute(t, externalRouteV6, env.externalNodeIP6, true, false, false)
	}
}

// testBGPFilterOrdering exercises multiple rules per filter and multiple
// filters per peer, exhausting the match operators and actions.
func testBGPFilterOrdering(t *testing.T, env *bgpFilterEnv, ipv4, ipv6 bool) {
	defer utils.CollectDiagsOnFailure(t)()
	g := NewWithT(t)
	ctx := context.Background()

	if ipv4 {
		env.addExternalStaticRoute(t, externalNodeV4, "bird", "birdcl", externalRouteV4, env.externalNodeIP)
	}
	if ipv6 {
		env.addExternalStaticRoute(t, externalNodeV6, "bird6", "birdcl6", externalRouteV6, env.externalNodeIP6)
	}

	// Filters whose multiple rules net out to accepting the route.
	if ipv4 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-1"},
			Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
				{CIDR: "10.111.0.0/16", MatchOperator: v3.MatchOperatorIn, Action: v3.Accept},
				{CIDR: "10.111.111.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV4, "test-filter-import-1")
	}
	if ipv6 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-v6-1"},
			Spec: v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{
				{CIDR: "fd00:1111:1111::/48", MatchOperator: v3.MatchOperatorIn, Action: v3.Accept},
				{CIDR: "fd00:1111:1111:1111::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV6, "test-filter-import-v6-1")
	}

	// Routes should be present (first rule accepts).
	if ipv4 {
		env.assertClusterRoute(t, externalRouteV4, env.externalNodeIP, false, false, true)
	}
	if ipv6 {
		env.assertClusterRoute(t, externalRouteV6, env.externalNodeIP6, true, false, true)
	}

	// Higher-priority filters whose rules net out to rejecting the route.
	if ipv4 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-2"},
			Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
				{CIDR: "10.111.0.0/16", MatchOperator: v3.MatchOperatorNotIn, Action: v3.Accept},
				{CIDR: "10.111.111.0/24", MatchOperator: v3.MatchOperatorNotEqual, Action: v3.Accept},
				{CIDR: "10.111.111.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV4, "test-filter-import-2", "test-filter-import-1")
	}
	if ipv6 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-v6-2"},
			Spec: v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{
				{CIDR: "fd00:1111:1111::/48", MatchOperator: v3.MatchOperatorNotIn, Action: v3.Accept},
				{CIDR: "fd00:1111:1111:1111::/64", MatchOperator: v3.MatchOperatorNotEqual, Action: v3.Accept},
				{CIDR: "fd00:1111:1111:1111::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV6, "test-filter-import-v6-2", "test-filter-import-v6-1")
	}

	// Routes should no longer be present.
	if ipv4 {
		env.assertClusterRoute(t, externalRouteV4, env.externalNodeIP, false, false, false)
	}
	if ipv6 {
		env.assertClusterRoute(t, externalRouteV6, env.externalNodeIP6, true, false, false)
	}

	// A single highest-priority filter carrying both families, whose rules net
	// out to accepting both routes again.
	if ipv4 && ipv6 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-v4-v6"},
			Spec: v3.BGPFilterSpec{
				ImportV4: []v3.BGPFilterRuleV4{
					{CIDR: "10.111.111.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					{CIDR: "10.111.0.0/16", MatchOperator: v3.MatchOperatorNotIn, Action: v3.Accept},
					{CIDR: "10.111.111.0/24", MatchOperator: v3.MatchOperatorNotEqual, Action: v3.Accept},
					{CIDR: "10.111.111.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
				},
				ImportV6: []v3.BGPFilterRuleV6{
					{CIDR: "fd00:1111:1111:1111::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					{CIDR: "fd00:1111:1111::/48", MatchOperator: v3.MatchOperatorNotIn, Action: v3.Accept},
					{CIDR: "fd00:1111:1111:1111::/64", MatchOperator: v3.MatchOperatorNotEqual, Action: v3.Accept},
					{CIDR: "fd00:1111:1111:1111::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
				},
			},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV4, "test-filter-import-v4-v6", "test-filter-import-2", "test-filter-import-1")
		env.patchPeerFilters(t, ctx, g, peerNameV6, "test-filter-import-v4-v6", "test-filter-import-v6-2", "test-filter-import-v6-1")

		env.assertClusterRoute(t, externalRouteV4, env.externalNodeIP, false, false, true)
		env.assertClusterRoute(t, externalRouteV6, env.externalNodeIP6, true, false, true)
	}
}

// testBGPFilterGlobalPeer repeats the basic import-reject check against a peer
// that has been made global (its node selector removed).
func testBGPFilterGlobalPeer(t *testing.T, env *bgpFilterEnv, ipv4, ipv6 bool) {
	defer utils.CollectDiagsOnFailure(t)()
	g := NewWithT(t)
	ctx := context.Background()

	if ipv4 {
		env.addExternalStaticRoute(t, externalNodeV4, "bird", "birdcl", externalRouteV4, env.externalNodeIP)
	}
	if ipv6 {
		env.addExternalStaticRoute(t, externalNodeV6, "bird6", "birdcl6", externalRouteV6, env.externalNodeIP6)
	}

	// Make the peers global by clearing their node selectors.
	if ipv4 {
		env.setPeerNodeSelector(t, ctx, g, peerNameV4, "")
	}
	if ipv6 {
		env.setPeerNodeSelector(t, ctx, g, peerNameV6, "")
	}

	// Route should be present, now learned via a Global_ peer protocol.
	if ipv4 {
		env.assertClusterRoute(t, externalRouteV4, env.externalNodeIP, false, true, true)
	}
	if ipv6 {
		env.assertClusterRoute(t, externalRouteV6, env.externalNodeIP6, true, true, true)
	}

	// Import-reject filter: the route should disappear from the cluster BIRD.
	if ipv4 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-1"},
			Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
				{CIDR: externalRouteV4, MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV4, "test-filter-import-1")
		env.assertClusterRoute(t, externalRouteV4, env.externalNodeIP, false, true, false)
	}
	if ipv6 {
		env.createFilter(t, ctx, g, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-v6-1"},
			Spec: v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{
				{CIDR: externalRouteV6, MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		env.patchPeerFilters(t, ctx, g, peerNameV6, "test-filter-import-v6-1")
		env.assertClusterRoute(t, externalRouteV6, env.externalNodeIP6, true, true, false)
	}
}

// --- Fixture + resource helpers ---

// createBGPPeer creates a node-selected BGPPeer to the given external router
// address and registers a cleanup that removes it.
func createBGPPeer(t *testing.T, ctx context.Context, g *WithT, cli ctrlclient.Client, name, peerIP string) {
	t.Helper()
	peer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v3.BGPPeerSpec{
			PeerIP:       peerIP,
			ASNumber:     numorstring.ASNumber(64512),
			NodeSelector: "egress == 'true'",
		},
	}
	g.Expect(cli.Create(ctx, peer)).To(Succeed(), "creating BGPPeer %s", name)
	t.Cleanup(func() { _ = cli.Delete(context.Background(), peer) })
}

// createFilter creates a BGPFilter and registers a cleanup that deletes it.
func (e *bgpFilterEnv) createFilter(t *testing.T, ctx context.Context, g *WithT, filter *v3.BGPFilter) {
	t.Helper()
	g.Expect(e.cli.Create(ctx, filter)).To(Succeed(), "creating BGPFilter %s", filter.Name)
	t.Cleanup(func() { _ = e.cli.Delete(context.Background(), filter) })
}

// patchPeerFilters sets the ordered Filters list on a BGPPeer and registers a
// cleanup that clears it again. Mirrors test_bgp_filter.py:_patch_peer_filters.
func (e *bgpFilterEnv) patchPeerFilters(t *testing.T, ctx context.Context, g *WithT, peerName string, filters ...string) {
	t.Helper()
	e.updatePeer(t, ctx, g, peerName, func(p *v3.BGPPeer) { p.Spec.Filters = filters })
	t.Cleanup(func() {
		e.updatePeer(t, context.Background(), g, peerName, func(p *v3.BGPPeer) { p.Spec.Filters = nil })
	})
}

// setPeerNodeSelector sets a BGPPeer's node selector (empty makes it global)
// and registers a cleanup that restores the egress selector.
func (e *bgpFilterEnv) setPeerNodeSelector(t *testing.T, ctx context.Context, g *WithT, peerName, selector string) {
	t.Helper()
	e.updatePeer(t, ctx, g, peerName, func(p *v3.BGPPeer) { p.Spec.NodeSelector = selector })
	t.Cleanup(func() {
		e.updatePeer(t, context.Background(), g, peerName, func(p *v3.BGPPeer) { p.Spec.NodeSelector = "egress == 'true'" })
	})
}

// updatePeer applies mutate to the named BGPPeer, retrying on update conflicts.
func (e *bgpFilterEnv) updatePeer(t *testing.T, ctx context.Context, g *WithT, peerName string, mutate func(*v3.BGPPeer)) {
	t.Helper()
	g.Eventually(func() error {
		peer := &v3.BGPPeer{}
		if err := e.cli.Get(ctx, ctrlclient.ObjectKey{Name: peerName}, peer); err != nil {
			return err
		}
		mutate(peer)
		return e.cli.Update(ctx, peer)
	}, "20s", "1s").Should(Succeed(), "updating BGPPeer %s", peerName)
}

// addExternalStaticRoute installs a static-route protocol on an external router
// advertising route via the given next hop, reconfigures BIRD and registers a
// cleanup that removes it again. birdDir is the BIRD config dir ("bird" or
// "bird6") and birdCmd the matching client ("birdcl" or "birdcl6").
func (e *bgpFilterEnv) addExternalStaticRoute(t *testing.T, container, birdDir, birdCmd, route, via string) {
	t.Helper()
	g := NewWithT(t)
	conf := fmt.Sprintf("protocol static static1 {\n    route %s via %s;\n    export all;\n}", route, via)

	// Write the config and reconfigure BIRD, verifying it actually accepted the
	// new config: `birdcl configure` exits 0 even when it rejects the config
	// (e.g. a truncated write), silently keeping the old config, which would
	// otherwise surface only as an opaque timeout in the route assertions.
	g.Eventually(func() error {
		if _, err := utils.Run(t, fmt.Sprintf("cat <<'EOF' | docker exec -i %s sh -c 'cat > /etc/%s/static-route.conf'\n%s\nEOF\n",
			container, birdDir, conf), utils.RunOptions{AllowFail: true, SuppressErrLog: true}); err != nil {
			return err
		}
		out, err := utils.Run(t, fmt.Sprintf("docker exec %s %s configure", container, birdCmd),
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		if err != nil {
			return err
		}
		if !strings.Contains(out, "Reconfigur") {
			return fmt.Errorf("%s configure did not accept static-route.conf on %s:\n%s", birdCmd, container, out)
		}
		return nil
	}, 30*time.Second, time.Second).Should(Succeed(), "adding external static route %s via %s on %s", route, via, container)

	t.Cleanup(func() {
		_, _ = utils.Run(t, fmt.Sprintf("docker exec %s sh -c 'rm /etc/%s/static-route.conf; %s configure'",
			container, birdDir, birdCmd), utils.RunOptions{AllowFail: true})
	})
}

// --- Route assertions ---

// assertClusterRoute polls the egress node's calico-node BIRD until the given
// route is (or is not) present in the named peer protocol. peerIP is the
// external router address; global selects the Global_ vs Node_ protocol prefix.
func (e *bgpFilterEnv) assertClusterRoute(t *testing.T, route, peerIP string, ipv6, global, present bool) {
	t.Helper()
	birdCmd := "birdcl"
	if ipv6 {
		birdCmd = "birdcl6"
	}
	proto := birdProtoName(peerIP, global)
	pattern := regexp.QuoteMeta(route) + ` *via ` + regexp.QuoteMeta(peerIP) + ` on .* \[` + proto
	re := regexp.MustCompile(pattern)

	g := NewWithT(t)
	g.Eventually(func() error {
		out, err := utils.ExecInCalicoNode(t, e.egressNode, birdCmd+" show route protocol "+proto,
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		if err != nil {
			return err
		}
		return checkRoutePresence(re, out, route, present)
	}, time.Minute, time.Second).Should(Succeed(), "cluster route check failed for %s on %s", route, e.egressNode)
}

// assertExternalRoute polls an external router's BIRD until a route matching
// routeRegex via peerIPRegex is (or is not) present in the named protocol.
func assertExternalRoute(t *testing.T, container, proto, routeRegex, peerIPRegex string, ipv6, present bool) {
	t.Helper()
	birdCmd := "birdcl"
	if ipv6 {
		birdCmd = "birdcl6"
	}
	// IPv4 routes use the peer's global address as the next-hop, with no "from"
	// field:
	//   v4: <route> via <peerIP> on eth0 [<proto> <time>] ...
	//
	// IPv6 depends on how the peer is configured in bird6.cfg.template:
	//   - OSS pins "gateway recursive" on every peer, so the route is advertised
	//     with the peer's global address as the next-hop (same shape as v4).
	//   - Enterprise emits "direct" for a directly-connected peer (the external
	//     router shares the egress node's segment), so BIRD uses a link-local
	//     next-hop and carries the peer's global address in the "from" field:
	//       v6: <route> via fe80::... on eth0 [<proto> <time> from <peerIP>] ...
	//
	// Accept either form so the assertion holds in both repos regardless of
	// which next-hop BIRD emits. The query is already scoped with
	// "show route protocol <proto>", so the link-local branch needn't re-verify
	// the peer IP.
	pattern := routeRegex + ` *via ` + peerIPRegex + ` on .* \[` + proto
	if ipv6 {
		pattern = `(?:` +
			routeRegex + ` *via ` + peerIPRegex + ` on .* \[` + proto +
			`|` +
			routeRegex + ` *via fe80:[0-9a-f:]+ on .* \[` + proto +
			`)`
	}

	re := regexp.MustCompile(pattern)

	g := NewWithT(t)
	g.Eventually(func() error {
		out, err := utils.Run(t, fmt.Sprintf("docker exec %s %s show route protocol %s", container, birdCmd, proto),
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		if err != nil {
			return err
		}
		return checkRoutePresence(re, out, routeRegex, present)
	}, time.Minute, time.Second).Should(Succeed(), "external route check failed for %s on %s", routeRegex, container)
}

// checkRoutePresence returns nil when re's match of out agrees with the
// expected presence, and an error otherwise.
func checkRoutePresence(re *regexp.Regexp, out, label string, present bool) error {
	matched := re.MatchString(out)
	if !matched && present {
		return fmt.Errorf("route %s not present when it should be", label)
	}
	if matched && !present {
		return fmt.Errorf("route %s present when it should not be", label)
	}
	return nil
}

// birdProtoName returns the BIRD protocol name calico-node assigns to a peer:
// "Node_" (or "Global_" for a global peer) followed by the peer IP with "."
// and ":" replaced by "_".
func birdProtoName(peerIP string, global bool) string {
	prefix := "Node_"
	if global {
		prefix = "Global_"
	}
	return prefix + birdPeerIPReplacer.Replace(peerIP)
}

// birdPeerIPReplacer turns an IP into the form calico-node uses in BIRD
// protocol names ("." and ":" both become "_").
var birdPeerIPReplacer = strings.NewReplacer(".", "_", ":", "_")
