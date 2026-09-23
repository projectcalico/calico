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

// This is a kind-only system test for BGP advertisement of Kubernetes service IPv6
// addresses (cluster IPs, external IPs and LoadBalancer IPs). It peers the
// cluster with a standalone BIRD6 router on the kind network and asserts that
// the routes the cluster advertises (and withdraws) appear in the external
// node's IPv6 routing table.
//
// TestBGPAdvertV6 covers the full node-to-node-mesh topology and TestBGPAdvertV6RR
// covers the route-reflector topology. Both reuse the shared bgpAdvertEnv fixture and
// helpers from bgp_advert_test.go, differing only in the address family (their
// env.getExternalNodeRoutes reads `ip -6 r`) and the IPv6 CIDRs/addresses used.

package k8stests

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

const (
	// v6ClusterCIDR is the service cluster IPv6 range advertised by the tests.
	v6ClusterCIDR = "fd00:10:96::/112"
)

// birdConfMeshV6Tmpl peers the external node with all four cluster nodes over
// IPv6 (the full-mesh topology). The four %s are filled with the node IPv6
// addresses; ip@local is substituted with the container's own address by
// StartExternalNodeWithBGP.
const birdConfMeshV6Tmpl = `
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
protocol bgp Mesh_with_master_node from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}

protocol bgp Mesh_with_node_1 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}

protocol bgp Mesh_with_node_2 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}

protocol bgp Mesh_with_node_3 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}
`

// birdConfRRV6Tmpl peers the external node only with the in-cluster route
// reflector (kube-node-2) over IPv6. The single %s is filled with that node's
// IPv6 address.
const birdConfRRV6Tmpl = `
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

protocol bgp Mesh_with_node_2 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
}
`

// TestBGPAdvertV6 exercises service-IPv6 advertisement under the full
// node-to-node BGP mesh. A standalone BIRD6 router peers with every cluster
// node; each subtest configures advertisement and asserts the resulting routes
// on that router.
func TestBGPAdvertV6(t *testing.T) {
	g := NewWithT(t)
	cli := newClient(g)
	nodes, _, ip6s := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 4),
		"BGP advert v6 test needs a control-plane node and three workers")

	birdConf := fmt.Sprintf(birdConfMeshV6Tmpl, ip6s[0], ip6s[1], ip6s[2], ip6s[3])
	externalIP := utils.StartExternalNodeWithBGP(t, utils.ExternalNodeName, "", birdConf)
	t.Cleanup(func() { utils.RemoveExternalNode(t, utils.ExternalNodeName) })

	env := &bgpAdvertEnv{cli: cli, nodes: nodes, ips: ip6s, externalNodeIP: externalIP, getExternalNodeRoutes: utils.ExternalNodeRoutesV6, ecmpParentAttrs: " metric 1024 pref medium"}

	// Establish the BGPPeer from the cluster nodes to the external node.
	peer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: extPeerName},
		Spec: v3.BGPPeerSpec{
			PeerIP:   externalIP,
			ASNumber: numorstring.ASNumber(bgpASNumber),
		},
	}
	upsertBGPPeer(t, cli, peer)
	t.Cleanup(func() { deleteBGPPeer(cli, extPeerName) })

	t.Run("cluster_ip_advertisement", env.testClusterIPAdvertisementV6)
	t.Run("external_ip_advertisement", env.testExternalIPAdvertisementV6)
	t.Run("many_services", env.testManyServicesV6)
	t.Run("bgp_filter_ip_advertisement", env.testBGPFilterIPAdvertisementV6)
}

// TestBGPAdvertV6RR exercises service-IPv6 advertisement under a route-reflector
// topology: kube-node-2 acts as the RR and all other nodes (plus the external
// node) peer with it.
func TestBGPAdvertV6RR(t *testing.T) {
	g := NewWithT(t)
	cli := newClient(g)
	nodes, _, ip6s := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 4),
		"BGP advert v6 RR test needs a control-plane node and three workers")

	birdConf := fmt.Sprintf(birdConfRRV6Tmpl, ip6s[2])
	externalIP := utils.StartExternalNodeWithBGP(t, utils.ExternalNodeName, "", birdConf)
	t.Cleanup(func() { utils.RemoveExternalNode(t, utils.ExternalNodeName) })

	env := &bgpAdvertEnv{cli: cli, nodes: nodes, ips: ip6s, externalNodeIP: externalIP, getExternalNodeRoutes: utils.ExternalNodeRoutesV6, ecmpParentAttrs: " metric 1024 pref medium"}

	peer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: extPeerName},
		Spec: v3.BGPPeerSpec{
			Node:     nodes[2],
			PeerIP:   externalIP,
			ASNumber: numorstring.ASNumber(bgpASNumber),
		},
	}
	upsertBGPPeer(t, cli, peer)
	t.Cleanup(func() { deleteBGPPeer(cli, extPeerName) })

	t.Run("rr", env.testRRV6)
	t.Run("single_ip_lb_rr", env.testSingleIPLBRRV6)
}

// ----------------------------------------------------------------------------
// TestBGPAdvertV6 subtests.

func (e *bgpAdvertEnv) testClusterIPAdvertisementV6(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceClusterIPs: []v3.ServiceClusterIPBlock{{CIDR: v6ClusterCIDR}},
	})

	// Assert that a route to the service IP range is present.
	e.assertRouteContains(t, v6ClusterCIDR)

	// Create both a Local and a Cluster type NodePort service with one replica.
	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{IPv6: true})
	utils.Deploy(t, utils.NginxImage, clusterSvc, e.ns, 80, utils.DeployOptions{TrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster, IPv6: true})
	utils.WaitUntilExists(t, localSvc, "svc", e.ns)
	utils.WaitUntilExists(t, clusterSvc, "svc", e.ns)

	localSvcIP := utils.GetSvcClusterIP(t, localSvc, e.ns)
	clusterSvcIP := utils.GetSvcClusterIP(t, clusterSvc, e.ns)

	utils.WaitForDeployment(t, localSvc, e.ns)
	utils.WaitForDeployment(t, clusterSvc, e.ns)

	// Both services should be reachable from the external node.
	curlRetry(t, localSvcIP)
	curlRetry(t, clusterSvcIP)

	// The local clusterIP is advertised; the cluster clusterIP is not.
	e.assertRouteContains(t, localSvcIP)
	e.assertRouteNotContains(t, clusterSvcIP)

	// Connectivity to nginx-local should always succeed.
	curlRetry(t, localSvcIP)

	// NOTE: Unlike in the IPv4 case (in bgp_advert_test.go) we cannot test that
	// connectivity to nginx-cluster is load-balanced across all nodes, because
	// Linux's IPv6 ECMP route choice does not depend on source port even when
	// fib_multipath_hash_policy == 1.

	// Scale the local service to 4 replicas and assert ECMP routing.
	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	e.assertEcmpRoutes(t, localSvcIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	curlRetry(t, localSvcIP)

	// Delete both services; the clusterIP is no longer advertised.
	utils.DeleteAndConfirm(t, localSvc, "svc", e.ns)
	utils.DeleteAndConfirm(t, clusterSvc, "svc", e.ns)
	e.assertRouteNotContains(t, localSvcIP)
}

func (e *bgpAdvertEnv) testExternalIPAdvertisementV6(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	// Allow two IP ranges for the external IPs we'll test with.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceExternalIPs: []v3.ServiceExternalIPBlock{
			{CIDR: "fd5f:1234:175:200::/112"},
			{CIDR: "fd5f:1234:200:255::/120"},
		},
	})

	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{IPv6: true})
	utils.Deploy(t, utils.NginxImage, clusterSvc, e.ns, 80, utils.DeployOptions{TrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster, IPv6: true})
	utils.WaitUntilExists(t, localSvc, "svc", e.ns)
	utils.WaitUntilExists(t, clusterSvc, "svc", e.ns)

	localSvcIP := utils.GetSvcClusterIP(t, localSvc, e.ns)
	clusterSvcIP := utils.GetSvcClusterIP(t, clusterSvc, e.ns)

	utils.WaitForDeployment(t, localSvc, e.ns)
	utils.WaitForDeployment(t, clusterSvc, e.ns)

	// clusterIPs are not advertised (no serviceClusterIPs configured).
	e.assertRouteNotContains(t, localSvcIP)
	e.assertRouteNotContains(t, clusterSvcIP)

	// Network policy that only accepts traffic from the external node.
	createExternalNodeIngressPolicy(t, e.ns, e.externalNodeIP)

	localSvcHostIP := utils.GetSvcHostIPv6(t, localSvc, e.ns)
	clusterSvcHostIP := utils.GetSvcHostIPv6(t, clusterSvc, e.ns)

	// Select an IP from each external IP CIDR.
	localSvcExternalIP := "fd5f:1234:175:200::1"
	clusterSvcExternalIP := "fd5f:1234:200:255::1"

	utils.AddSvcExternalIPs(t, localSvc, e.ns, []string{localSvcExternalIP})
	utils.AddSvcExternalIPs(t, clusterSvc, e.ns, []string{clusterSvcExternalIP})

	// The external IP of the local service is advertised but not the cluster one.
	localSvcExternalIPsRoute := fmt.Sprintf("%s via %s", localSvcExternalIP, localSvcHostIP)
	clusterSvcExternalIPsRoute := fmt.Sprintf("%s via %s", clusterSvcExternalIP, clusterSvcHostIP)
	e.assertRouteContains(t, localSvcExternalIPsRoute)
	e.assertRouteNotContains(t, clusterSvcExternalIPsRoute)

	// Scale the local service to 4 replicas; expect ECMP routes for its ext IP.
	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	e.assertEcmpRoutes(t, localSvcExternalIP, []string{e.ips[1], e.ips[2], e.ips[3]})

	// Delete both services; the external IP is no longer advertised.
	utils.DeleteAndConfirm(t, localSvc, "svc", e.ns)
	utils.DeleteAndConfirm(t, clusterSvc, "svc", e.ns)
	e.assertRouteNotContains(t, localSvcExternalIPsRoute)
}

func (e *bgpAdvertEnv) testManyServicesV6(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceClusterIPs: []v3.ServiceClusterIPBlock{{CIDR: v6ClusterCIDR}},
	})
	e.assertRouteContains(t, v6ClusterCIDR)

	// Create a local service and deployment.
	localSvc := "nginx-local"
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{IPv6: true})
	utils.WaitForDeployment(t, localSvc, e.ns)

	clusterIPs := []string{utils.GetSvcClusterIP(t, localSvc, e.ns)}

	// Create many more services selecting the same deployment.
	const numSvc = 50
	for i := range numSvc {
		utils.CreateService(t, fmt.Sprintf("nginx-svc-%d", i), localSvc, e.ns, 80, utils.DeployOptions{IPv6: true})
	}
	for i := range numSvc {
		clusterIPs = append(clusterIPs, utils.GetSvcClusterIP(t, fmt.Sprintf("nginx-svc-%d", i), e.ns))
	}

	// Assert all are advertised to the other node. This should happen quickly
	// enough that they're programmed by the time we've queried them all.
	g := NewWithT(t)
	g.Eventually(func() error {
		routes := e.getExternalNodeRoutes(t)
		for _, cip := range clusterIPs {
			if !strings.Contains(routes, cip) {
				return fmt.Errorf("route for %s not yet advertised", cip)
			}
		}
		return nil
	}, 20*time.Second, time.Second).Should(Succeed(), "not all service routes advertised")

	// Scale to 0 replicas; all routes are removed.
	utils.ScaleDeployment(t, localSvc, e.ns, 0)
	utils.WaitForDeployment(t, localSvc, e.ns)
	g.Eventually(func() error {
		routes := e.getExternalNodeRoutes(t)
		for _, cip := range clusterIPs {
			if strings.Contains(routes, cip) {
				return fmt.Errorf("route for %s still advertised", cip)
			}
		}
		return nil
	}, 60*time.Second, time.Second).Should(Succeed(), "service routes were not withdrawn")
}

func (e *bgpAdvertEnv) testBGPFilterIPAdvertisementV6(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	// Add BGPConfiguration with serviceClusterIPs.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceClusterIPs: []v3.ServiceClusterIPBlock{{CIDR: v6ClusterCIDR}},
	})
	e.assertRouteContains(t, v6ClusterCIDR)

	// Create a Local type NodePort service with a single replica.
	localSvc := "nginx-local"
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{IPv6: true})
	utils.WaitUntilExists(t, localSvc, "svc", e.ns)

	localSvcIP := utils.GetSvcClusterIP(t, localSvc, e.ns)
	utils.WaitForDeployment(t, localSvc, e.ns)

	curlRetry(t, localSvcIP)
	e.assertRouteContains(t, localSvcIP)

	// Create an export BGP filter that rejects the service IP range.
	filterName := "test-filter-export-1"
	filter := &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: filterName},
		Spec: v3.BGPFilterSpec{
			ExportV6: []v3.BGPFilterRuleV6{{
				CIDR:          v6ClusterCIDR,
				MatchOperator: v3.MatchOperatorIn,
				Action:        v3.Reject,
			}},
		},
	}
	ctx := context.Background()
	g := NewWithT(t)
	g.Expect(e.cli.Create(ctx, filter)).To(Succeed(), "creating BGPFilter %s", filterName)
	t.Cleanup(func() { _ = e.cli.Delete(context.Background(), filter) })

	// Apply the filter to the external peer, restoring an empty filter list in
	// cleanup.
	setPeerFilters(t, e.cli, extPeerName, []string{filterName})
	t.Cleanup(func() { setPeerFilters(t, e.cli, extPeerName, nil) })

	// The clusterIP and the service IP range are no longer advertised.
	e.assertRouteNotContains(t, localSvcIP)
	e.assertRouteNotContains(t, v6ClusterCIDR)
}

// ----------------------------------------------------------------------------
// TestBGPAdvertV6RR subtests.

func (e *bgpAdvertEnv) testRRV6(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	// ExternalTrafficPolicy=Local service with one endpoint on node-1.
	svc := e.createRRWorkload(t, func(s *corev1.Service) {
		s.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv6Protocol}
		s.Spec.Type = corev1.ServiceTypeNodePort
		s.Spec.ExternalIPs = []string{"fd5f:1234:175:200::1"}
		s.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
	})

	// Make node-2 a route reflector, retrying to absorb update conflicts.
	g := NewWithT(t)
	g.Eventually(func() error {
		return setRRConfig(t, e.nodes[2])
	}, 90*time.Second, time.Second).Should(Succeed(), "setting route-reflector config on %s", e.nodes[2])

	// Disable the mesh, advertise the cluster/external CIDRs, and peer the
	// cluster nodes with the RR.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		NodeToNodeMeshEnabled: new(false),
		ASNumber:              new(numorstring.ASNumber(bgpASNumber)),
		ServiceClusterIPs:     []v3.ServiceClusterIPBlock{{CIDR: v6ClusterCIDR}},
		ServiceExternalIPs:    []v3.ServiceExternalIPBlock{{CIDR: "fd5f:1234:175:200::/112"}},
	})
	e.createRRPeer(t)

	clusterIP := svc.Spec.ClusterIP
	externalIP := svc.Spec.ExternalIPs[0]
	e.assertRouteContains(t, clusterIP)
	e.assertRouteContains(t, externalIP)
}

func (e *bgpAdvertEnv) testSingleIPLBRRV6(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	// LB ExternalTrafficPolicy=Local service with one endpoint on node-1.
	svc := e.createRRWorkload(t, func(s *corev1.Service) {
		s.Annotations = map[string]string{
			"projectcalico.org/loadBalancerIPs": `["fdff::96"]`,
		}
		s.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv6Protocol}
		s.Spec.Type = corev1.ServiceTypeLoadBalancer
		s.Spec.LoadBalancerClass = new("calico")
		s.Spec.LoadBalancerIP = "fdff::96"
		s.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
	})

	g := NewWithT(t)
	g.Eventually(func() error {
		return setRRConfig(t, e.nodes[2])
	}, 90*time.Second, time.Second).Should(Succeed(), "setting route-reflector config on %s", e.nodes[2])

	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		NodeToNodeMeshEnabled:  new(false),
		ASNumber:               new(numorstring.ASNumber(bgpASNumber)),
		ServiceClusterIPs:      []v3.ServiceClusterIPBlock{{CIDR: v6ClusterCIDR}},
		ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "fdff::96/128"}},
	})
	e.createRRPeer(t)

	clusterIP := svc.Spec.ClusterIP
	loadBalancerIP := svc.Spec.LoadBalancerIP
	e.assertRouteContains(t, clusterIP)
	e.assertRouteContains(t, loadBalancerIP)
}
