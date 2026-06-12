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

// bgp_filter_test.go is the Go port of test_bgp_filter.py. It stands up two
// external BIRD routers (one v4, one v6) peered with an "egress" cluster node
// and verifies that BGPFilter import/export rules — singly, in ordered sets,
// and on global peers — correctly accept or reject routes in both the cluster
// and external BIRD instances.

package k8stests

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

// birdConfFilter is the external-node BIRD config: one unidirectional mesh
// peering toward the egress cluster node. %s is the neighbour (egress node) IP.
const birdConfFilter = `
# Template for all BGP clients
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 64512;
  multihop;
  gateway recursive;
  import all;
  export all;
  source address ip@local;
  add paths on;
  graceful restart;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
}

# ------------- Node-to-node mesh -------------
protocol bgp Mesh_with_node_1 from bgp_template {
  neighbor %s as 64512;
  passive on;
}
`

// bgpFilterEnv carries the fixtures shared by every BGPFilter subtest.
type bgpFilterEnv struct {
	cli       ctrlclient.Client
	egressIP  string // egress node IPv4
	egressIP6 string // egress node IPv6
	extIP     string // external v4 router's BGP source IP
	extIP6    string // external v6 router's BGP source IP
}

// TestBGPFilter ports test_bgp_filter.py:TestBGPFilter. The expensive external
// routers and peerings are created once; each scenario runs as a subtest with
// its own filter/static-route cleanups.
func TestBGPFilter(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	cli := newClient(g)

	nodes, ips, ip6s := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 2), "need a control-plane node and a worker")
	egressNode := nodes[1]

	env := &bgpFilterEnv{cli: cli, egressIP: ips[1], egressIP6: ip6s[1]}

	// External BIRD routers: one v4, one v6, each peering with the egress node.
	env.extIP = utils.StartExternalNodeWithBGP(t, "kube-node-extra", fmt.Sprintf(birdConfFilter, env.egressIP), "")
	t.Cleanup(func() { _, _ = utils.Run(t, "docker rm -f kube-node-extra", utils.RunOptions{AllowFail: true}) })
	env.extIP6 = utils.StartExternalNodeWithBGP(t, "kube-node-extra-v6", "", fmt.Sprintf(birdConfFilter, env.egressIP6))
	t.Cleanup(func() { _, _ = utils.Run(t, "docker rm -f kube-node-extra-v6", utils.RunOptions{AllowFail: true}) })

	// Label the egress node and create the two peerings toward the routers.
	utils.SetNodeLabel(t, egressNode, "egress", "true")
	t.Cleanup(func() { utils.RemoveNodeLabel(t, egressNode, "egress") })

	v4Peer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "node-extra.peer"},
		Spec:       v3.BGPPeerSpec{PeerIP: env.extIP, ASNumber: numorstring.ASNumber(64512), NodeSelector: "egress == 'true'"},
	}
	v6Peer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "node-extra-v6.peer"},
		Spec:       v3.BGPPeerSpec{PeerIP: env.extIP6, ASNumber: numorstring.ASNumber(64512), NodeSelector: "egress == 'true'"},
	}
	createV3(t, cli, v4Peer)
	t.Cleanup(func() { deleteV3(t, cli, v4Peer) })
	createV3(t, cli, v6Peer)
	t.Cleanup(func() { deleteV3(t, cli, v6Peer) })

	for _, tc := range []struct {
		name       string
		ipv4, ipv6 bool
		run        func(e *bgpFilterEnv, t *testing.T, pod string, v4, v6 bool)
	}{
		{"basic_v4", true, false, (*bgpFilterEnv).runBasic},
		{"basic_v6", false, true, (*bgpFilterEnv).runBasic},
		{"basic_v4v6", true, true, (*bgpFilterEnv).runBasic},
		{"ordering_v4", true, false, (*bgpFilterEnv).runOrdering},
		{"ordering_v6", false, true, (*bgpFilterEnv).runOrdering},
		{"ordering_v4v6", true, true, (*bgpFilterEnv).runOrdering},
		{"global_peer_v4", true, false, (*bgpFilterEnv).runGlobalPeer},
		{"global_peer_v6", false, true, (*bgpFilterEnv).runGlobalPeer},
		{"global_peer_v4v6", true, true, (*bgpFilterEnv).runGlobalPeer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer utils.CollectDiagsOnFailure(t)()
			egressCalicoPod := utils.CalicoNodePodName(t, egressNode)
			tc.run(env, t, egressCalicoPod, tc.ipv4, tc.ipv6)
		})
	}
}

// Test data shared by the scenarios.
const (
	bgpFilterExternalRouteV4 = "10.111.111.0/24"
	bgpFilterExternalRouteV6 = "fd00:1111:1111:1111::/64"
	bgpFilterExportCIDRV4    = "192.168.0.0/16"
	bgpFilterExportCIDRV6    = "fd00:10:244::/64"
)

var (
	bgpFilterClusterRouteRegexV4 = `192\.168\.\d+\.\d+/\d+`
	bgpFilterClusterRouteRegexV6 = `fd00:10:244:.*/\d+`
)

// runBasic ports _test_bgp_filter_basic: import the external route, see the
// cluster's IPAM block exported, then verify a Reject export filter withdraws
// the cluster route and a Reject import filter withdraws the external route.
func (e *bgpFilterEnv) runBasic(t *testing.T, egressCalicoPod string, ipv4, ipv6 bool) {
	g := NewWithT(t)

	if ipv4 {
		e.addExternalStaticRoute(t, "kube-node-extra", bgpFilterExternalRouteV4, e.extIP, false)
	}
	if ipv6 {
		e.addExternalStaticRoute(t, "kube-node-extra-v6", bgpFilterExternalRouteV6, e.extIP6, true)
	}

	// Cluster node hears the external route.
	if ipv4 {
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV4, e.extIP, false, false, true)
		})
	}
	if ipv6 {
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV6, e.extIP6, true, false, true)
		})
	}

	// External node hears the cluster's IPAM block.
	if ipv4 {
		eventuallyRoute(g, func() error {
			return externalBirdHasRoute(t, "kube-node-extra", "Mesh_with_node_1", bgpFilterClusterRouteRegexV4, regexp.QuoteMeta(e.egressIP), false, true)
		})
	}
	if ipv6 {
		eventuallyRoute(g, func() error {
			return externalBirdHasRoute(t, "kube-node-extra-v6", "Mesh_with_node_1", bgpFilterClusterRouteRegexV6, "2001:20::1", true, true)
		})
	}

	// Export Reject filter: external node no longer hears the cluster block.
	if ipv4 {
		e.applyFilterAndPatch(t, "node-extra.peer", &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-export-1"},
			Spec:       v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{{CIDR: bgpFilterExportCIDRV4, MatchOperator: v3.MatchOperatorIn, Action: v3.Reject}}},
		})
		eventuallyRoute(g, func() error {
			return externalBirdHasRoute(t, "kube-node-extra", "Mesh_with_node_1", bgpFilterClusterRouteRegexV4, regexp.QuoteMeta(e.egressIP), false, false)
		})
	}
	if ipv6 {
		e.applyFilterAndPatch(t, "node-extra-v6.peer", &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-export-v6-1"},
			Spec:       v3.BGPFilterSpec{ExportV6: []v3.BGPFilterRuleV6{{CIDR: bgpFilterExportCIDRV6, MatchOperator: v3.MatchOperatorIn, Action: v3.Reject}}},
		})
		eventuallyRoute(g, func() error {
			return externalBirdHasRoute(t, "kube-node-extra-v6", "Mesh_with_node_1", bgpFilterClusterRouteRegexV6, "2001:20::1", true, false)
		})
	}

	// Import Reject filter: cluster node no longer hears the external route.
	if ipv4 {
		e.applyFilterAndPatch(t, "node-extra.peer", &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-1"},
			Spec:       v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{{CIDR: bgpFilterExternalRouteV4, MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject}}},
		})
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV4, e.extIP, false, false, false)
		})
	}
	if ipv6 {
		e.applyFilterAndPatch(t, "node-extra-v6.peer", &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-v6-1"},
			Spec:       v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{{CIDR: bgpFilterExternalRouteV6, MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject}}},
		})
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV6, e.extIP6, true, false, false)
		})
	}
}

// runOrdering ports _test_bgp_filter_ordering: exercise multiple rules per
// filter and multiple filters per peer across the match operators.
func (e *bgpFilterEnv) runOrdering(t *testing.T, egressCalicoPod string, ipv4, ipv6 bool) {
	g := NewWithT(t)

	if ipv4 {
		e.addExternalStaticRoute(t, "kube-node-extra", bgpFilterExternalRouteV4, e.extIP, false)
	}
	if ipv6 {
		e.addExternalStaticRoute(t, "kube-node-extra-v6", bgpFilterExternalRouteV6, e.extIP6, true)
	}

	// Filter set 1: rules that net-accept the external route.
	if ipv4 {
		e.applyFilterAndPatch(t, "node-extra.peer", &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-1"},
			Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
				{CIDR: "10.111.0.0/16", MatchOperator: v3.MatchOperatorIn, Action: v3.Accept},
				{CIDR: "10.111.111.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
	}
	if ipv6 {
		e.applyFilterAndPatch(t, "node-extra-v6.peer", &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-v6-1"},
			Spec: v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{
				{CIDR: "fd00:1111:1111::/48", MatchOperator: v3.MatchOperatorIn, Action: v3.Accept},
				{CIDR: "fd00:1111:1111:1111::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
	}

	if ipv4 {
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV4, e.extIP, false, false, true)
		})
	}
	if ipv6 {
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV6, e.extIP6, true, false, true)
		})
	}

	// Filter set 2 (prepended): rules that net-reject the external route.
	if ipv4 {
		e.applyFilter(t, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-2"},
			Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
				{CIDR: "10.111.0.0/16", MatchOperator: v3.MatchOperatorNotIn, Action: v3.Accept},
				{CIDR: "10.111.111.0/24", MatchOperator: v3.MatchOperatorNotEqual, Action: v3.Accept},
				{CIDR: "10.111.111.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		e.patchPeerFilters(t, "node-extra.peer", []string{"test-filter-import-2", "test-filter-import-1"})
	}
	if ipv6 {
		e.applyFilter(t, &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-v6-2"},
			Spec: v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{
				{CIDR: "fd00:1111:1111::/48", MatchOperator: v3.MatchOperatorNotIn, Action: v3.Accept},
				{CIDR: "fd00:1111:1111:1111::/64", MatchOperator: v3.MatchOperatorNotEqual, Action: v3.Accept},
				{CIDR: "fd00:1111:1111:1111::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject},
			}},
		})
		e.patchPeerFilters(t, "node-extra-v6.peer", []string{"test-filter-import-v6-2", "test-filter-import-v6-1"})
	}

	if ipv4 {
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV4, e.extIP, false, false, false)
		})
	}
	if ipv6 {
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV6, e.extIP6, true, false, false)
		})
	}

	// Combined v4+v6 filter (prepended): net-accepts both routes again.
	if ipv4 && ipv6 {
		e.applyFilter(t, &v3.BGPFilter{
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
		e.patchPeerFilters(t, "node-extra.peer", []string{"test-filter-import-v4-v6", "test-filter-import-2", "test-filter-import-1"})
		e.patchPeerFilters(t, "node-extra-v6.peer", []string{"test-filter-import-v4-v6", "test-filter-import-v6-2", "test-filter-import-v6-1"})

		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV4, e.extIP, false, false, true)
		})
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV6, e.extIP6, true, false, true)
		})
	}
}

// runGlobalPeer ports _test_bgp_filter_global_peer: convert the peer to a
// global peer (drop the nodeSelector) and verify an import filter still works.
func (e *bgpFilterEnv) runGlobalPeer(t *testing.T, egressCalicoPod string, ipv4, ipv6 bool) {
	g := NewWithT(t)

	if ipv4 {
		e.addExternalStaticRoute(t, "kube-node-extra", bgpFilterExternalRouteV4, e.extIP, false)
	}
	if ipv6 {
		e.addExternalStaticRoute(t, "kube-node-extra-v6", bgpFilterExternalRouteV6, e.extIP6, true)
	}

	// Make the peer global by dropping the node selector; restore it after.
	if ipv4 {
		e.setPeerNodeSelector(t, "node-extra.peer", "")
		t.Cleanup(func() { e.setPeerNodeSelector(t, "node-extra.peer", "egress == 'true'") })
	}
	if ipv6 {
		e.setPeerNodeSelector(t, "node-extra-v6.peer", "")
		t.Cleanup(func() { e.setPeerNodeSelector(t, "node-extra-v6.peer", "egress == 'true'") })
	}

	if ipv4 {
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV4, e.extIP, false, true, true)
		})
	}
	if ipv6 {
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV6, e.extIP6, true, true, true)
		})
	}

	if ipv4 {
		e.applyFilterAndPatch(t, "node-extra.peer", &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-1"},
			Spec:       v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{{CIDR: bgpFilterExternalRouteV4, MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject}}},
		})
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV4, e.extIP, false, true, false)
		})
	}
	if ipv6 {
		e.applyFilterAndPatch(t, "node-extra-v6.peer", &v3.BGPFilter{
			ObjectMeta: metav1.ObjectMeta{Name: "test-filter-import-v6-1"},
			Spec:       v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{{CIDR: bgpFilterExternalRouteV6, MatchOperator: v3.MatchOperatorEqual, Action: v3.Reject}}},
		})
		eventuallyRoute(g, func() error {
			return clusterBirdHasRoute(t, egressCalicoPod, bgpFilterExternalRouteV6, e.extIP6, true, true, false)
		})
	}
}

// --- per-env helpers ---

// addExternalStaticRoute installs a static-route protocol in an external BIRD
// router and reconfigures it, registering cleanup to remove it again.
func (e *bgpFilterEnv) addExternalStaticRoute(t *testing.T, container, route, viaIP string, ipv6 bool) {
	t.Helper()
	dir, cmd := "/etc/bird", "birdcl"
	if ipv6 {
		dir, cmd = "/etc/bird6", "birdcl6"
	}
	content := fmt.Sprintf("protocol static static1 {\n    route %s via %s;\n    export all;\n}\n", route, viaIP)
	utils.CopyTextToExternalNode(t, container, dir+"/static-route.conf", content)
	utils.MustRun(t, fmt.Sprintf("docker exec %s %s configure", container, cmd))
	t.Cleanup(func() {
		_, _ = utils.Run(t, fmt.Sprintf("docker exec %s sh -c 'rm %s/static-route.conf; %s configure'", container, dir, cmd),
			utils.RunOptions{AllowFail: true})
	})
}

// applyFilter creates a BGPFilter and registers its deletion.
func (e *bgpFilterEnv) applyFilter(t *testing.T, filter *v3.BGPFilter) {
	t.Helper()
	createV3(t, e.cli, filter)
	t.Cleanup(func() { deleteV3(t, e.cli, filter) })
}

// applyFilterAndPatch creates a BGPFilter, attaches it as the peer's sole
// filter, and registers cleanups to reset the peer's filters and delete the
// filter.
func (e *bgpFilterEnv) applyFilterAndPatch(t *testing.T, peer string, filter *v3.BGPFilter) {
	t.Helper()
	e.applyFilter(t, filter)
	e.patchPeerFilters(t, peer, []string{filter.Name})
}

// patchPeerFilters sets a peer's filters and registers cleanup resetting them.
func (e *bgpFilterEnv) patchPeerFilters(t *testing.T, peer string, filters []string) {
	t.Helper()
	setPeerFilters(t, e.cli, peer, filters)
	t.Cleanup(func() { setPeerFilters(t, e.cli, peer, nil) })
}

// setPeerNodeSelector updates a BGPPeer's nodeSelector, retrying on conflict.
func (e *bgpFilterEnv) setPeerNodeSelector(t *testing.T, name, selector string) {
	t.Helper()
	err := utils.RetryUntilSuccess(t, 30*time.Second, func() error {
		peer := &v3.BGPPeer{}
		if err := e.cli.Get(t.Context(), ctrlclient.ObjectKey{Name: name}, peer); err != nil {
			return err
		}
		peer.Spec.NodeSelector = selector
		return e.cli.Update(t.Context(), peer)
	})
	if err != nil {
		t.Fatalf("setting nodeSelector on BGPPeer %s: %v", name, err)
	}
}

// eventuallyRoute polls fn (a route presence check) until it passes or times
// out, mirroring the Python retry_until_success(timeout=60).
func eventuallyRoute(g *WithT, fn func() error) {
	g.Eventually(fn, "60s", "3s").Should(Succeed())
}
