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

// bgp_advert_test.go is a kind-only system test for BGP advertisement of
// Kubernetes service IPs (cluster IPs, external IPs and LoadBalancer IPs). It
// peers the cluster with a standalone BIRD router on the kind network and
// asserts that the routes the cluster advertises (and withdraws) appear in the
// external node's routing table.
//
// TestBGPAdvert covers the full node-to-node-mesh topology
// (the Python TestBGPAdvert class) and TestBGPAdvertRR covers the
// route-reflector topology (TestBGPAdvertRR).

package k8stests

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	e2eutils "github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

const (
	// extPeerName is the BGPPeer from the cluster nodes to the external router.
	extPeerName = "node-extra.peer"
	// rrPeerName is the BGPPeer created by the route-reflector tests.
	rrPeerName = "peer-with-rr"
	// bgpSecretNS / bgpSecretName / bgpSecretKey identify the shared BGP
	// password Secret (referenced by the mesh peering).
	bgpSecretNS   = "calico-system"
	bgpSecretName = "bgp-secrets"
	bgpSecretKey  = "rr-password"
	bgpSecretVal  = "very-secret"
	// bgpASNumber is the AS number shared by the cluster and the external node.
	bgpASNumber = 64512
)

// birdConfMeshTmpl peers the external node with all four cluster nodes (the
// full-mesh topology). The four %s are filled with the node IPs; ip@local is
// substituted with the container's own IP by StartExternalNodeWithBGP.
const birdConfMeshTmpl = `
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
  password "very-secret";
}

protocol bgp Mesh_with_node_1 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
  password "very-secret";
}

protocol bgp Mesh_with_node_2 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
  password "very-secret";
}

protocol bgp Mesh_with_node_3 from bgp_template {
  neighbor %s as 64512;
  passive on; # Mesh is unidirectional, peer will connect to us.
  password "very-secret";
}
`

// birdConfRRTmpl peers the external node only with the in-cluster route
// reflector (kube-node-2). The single %s is filled with that node's IP.
const birdConfRRTmpl = `
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

// bgpAdvertEnv holds the per-class fixture shared by the advertisement
// subtests: the controller-runtime client, the discovered cluster nodes and
// their IPs, and the external BGP node's IP.
type bgpAdvertEnv struct {
	cli            ctrlclient.Client
	nodes          []string
	ips            []string
	externalNodeIP string

	// ns is the namespace the current subtest deploys into. startTest assigns
	// it a fresh random name per subtest so concurrent or repeated runs against
	// the same cluster do not collide.
	ns string
}

// TestBGPAdvert exercises service-IP advertisement under the full node-to-node
// BGP mesh. A standalone BIRD router peers with every cluster node; each
// subtest configures advertisement and asserts the resulting routes on that
// router.
func TestBGPAdvert(t *testing.T) {
	g := NewWithT(t)
	cli := newClient(g)
	nodes, ips, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 4),
		"BGP advert test needs a control-plane node and three workers")

	birdConf := fmt.Sprintf(birdConfMeshTmpl, ips[0], ips[1], ips[2], ips[3])
	externalIP := utils.StartExternalNodeWithBGP(t, utils.ExternalNodeName, birdConf, "")
	t.Cleanup(func() { utils.RemoveExternalNode(t, utils.ExternalNodeName) })

	env := &bgpAdvertEnv{cli: cli, nodes: nodes, ips: ips, externalNodeIP: externalIP}

	// Establish the BGPPeer from the cluster nodes to the external node, with a
	// password sourced from the shared Secret.
	createBGPSecret(t, cli)
	peer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: extPeerName},
		Spec: v3.BGPPeerSpec{
			PeerIP:   externalIP,
			ASNumber: numorstring.ASNumber(bgpASNumber),
			Password: &v3.BGPPassword{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: bgpSecretName},
				Key:                  bgpSecretKey,
			}},
		},
	}
	upsertBGPPeer(t, cli, peer)
	t.Cleanup(func() { deleteBGPPeer(cli, extPeerName) })

	t.Run("cluster_ip_advertisement", env.testClusterIPAdvertisement)
	t.Run("node_exclusion", env.testNodeExclusion)
	t.Run("external_ip_advertisement", env.testExternalIPAdvertisement)
	t.Run("fully_qualified_service_ips", env.testFullyQualifiedServiceIPs)
	t.Run("loadbalancer_ip_advertisement", env.testLoadBalancerIPAdvertisement)
	t.Run("many_services", env.testManyServices)
	t.Run("bgp_filter_ip_advertisement", env.testBGPFilterIPAdvertisement)
}

// TestBGPAdvertRR exercises service-IP advertisement under a route-reflector
// topology: kube-node-2 acts as the RR and all other nodes (plus the external
// node) peer with it.
func TestBGPAdvertRR(t *testing.T) {
	g := NewWithT(t)
	cli := newClient(g)
	nodes, ips, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 4),
		"BGP advert RR test needs a control-plane node and three workers")

	birdConf := fmt.Sprintf(birdConfRRTmpl, ips[2])
	externalIP := utils.StartExternalNodeWithBGP(t, utils.ExternalNodeName, birdConf, "")
	t.Cleanup(func() { utils.RemoveExternalNode(t, utils.ExternalNodeName) })

	env := &bgpAdvertEnv{cli: cli, nodes: nodes, ips: ips, externalNodeIP: externalIP}

	createBGPSecret(t, cli)
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

	t.Run("rr", env.testRR)
	t.Run("single_ip_lb_rr", env.testSingleIPLBRR)
}

// ----------------------------------------------------------------------------
// Per-test setup / teardown.

// startTest creates the per-test namespace and registers the shared teardown.
// The teardown is registered first so any cleanups a subtest registers later
// run before it (matching the Python tearDown ordering, where add_cleanup
// callbacks run before the namespace deletion and config restore).
func (e *bgpAdvertEnv) startTest(t *testing.T) {
	e.ns = e2eutils.GenerateRandomName("bgp-test")
	t.Cleanup(func() { e.teardownTest(t) })
	utils.CreateNamespace(t, e.ns)
}

func (e *bgpAdvertEnv) teardownTest(t *testing.T) {
	utils.DeleteAndConfirm(t, e.ns, "ns", "")

	// Delete the RR-specific BGPPeer (created by some tests), ignoring absence.
	deleteBGPPeer(e.cli, rrPeerName)

	// Restore the node-to-node mesh.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		NodeToNodeMeshEnabled: new(true),
		ASNumber:              new(numorstring.ASNumber(bgpASNumber)),
	})

	// Remove node-2's route-reflector config, retrying to absorb transient
	// update conflicts. This is cleanup, so a failure is reported but not fatal
	// (a fatal here would skip sibling cleanups) — use a non-failing Gomega.
	g := NewGomega(func(message string, _ ...int) { t.Errorf("%s", message) })
	g.Eventually(func() error {
		return clearRRConfig(t, e.nodes[2])
	}, 90*time.Second, time.Second).Should(Succeed(), "failed to clear route-reflector config on %s", e.nodes[2])
}

// ----------------------------------------------------------------------------
// TestBGPAdvert subtests.

func (e *bgpAdvertEnv) testClusterIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceClusterIPs: []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}},
	})

	// Assert that a route to the service IP range is present.
	assertRouteContains(t, "10.96.0.0/12")

	// Create both a Local and a Cluster type NodePort service with one replica.
	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{})
	utils.Deploy(t, utils.NginxImage, clusterSvc, e.ns, 80, utils.DeployOptions{TrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster})
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
	assertRouteContains(t, localSvcIP)
	assertRouteNotContains(t, clusterSvcIP)

	// Scale the local service to 4 replicas and assert ECMP routing.
	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	assertEcmpRoutes(t, localSvcIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	curlRetry(t, localSvcIP)

	// Delete both services; the clusterIP is no longer advertised.
	utils.DeleteAndConfirm(t, localSvc, "svc", e.ns)
	utils.DeleteAndConfirm(t, clusterSvc, "svc", e.ns)
	assertRouteNotContains(t, localSvcIP)
}

func (e *bgpAdvertEnv) testNodeExclusion(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceClusterIPs:  []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}},
		ServiceExternalIPs: []v3.ServiceExternalIPBlock{{CIDR: "175.200.0.0/16"}},
	})

	clusterCIDR := "10.96.0.0/12"
	assertRouteContains(t, clusterCIDR)

	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{})
	utils.Deploy(t, utils.NginxImage, clusterSvc, e.ns, 80, utils.DeployOptions{TrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster})
	utils.WaitUntilExists(t, localSvc, "svc", e.ns)
	utils.WaitUntilExists(t, clusterSvc, "svc", e.ns)

	localSvcIP := utils.GetSvcClusterIP(t, localSvc, e.ns)
	clusterSvcIP := utils.GetSvcClusterIP(t, clusterSvc, e.ns)

	utils.WaitForDeployment(t, localSvc, e.ns)
	utils.WaitForDeployment(t, clusterSvc, e.ns)

	curlRetry(t, localSvcIP)
	curlRetry(t, clusterSvcIP)

	assertRouteContains(t, localSvcIP)
	assertRouteNotContains(t, clusterSvcIP)

	curlRetry(t, localSvcIP)
	curlRetry(t, clusterSvcIP)

	// Scale local service to 4 replicas.
	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)

	// Local service is advertised only from nodes that can run pods; the
	// cluster CIDR is advertised from all nodes.
	assertEcmpRoutes(t, localSvcIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	assertEcmpRoutes(t, clusterCIDR, []string{e.ips[0], e.ips[1], e.ips[2], e.ips[3]})
	curlRetry(t, localSvcIP)

	// Exclude node-1 from service advertisement. Routes from it are withdrawn.
	labelNode(t, e.nodes[1], "node.kubernetes.io/exclude-from-external-load-balancers", "true")

	assertEcmpRoutes(t, localSvcIP, []string{e.ips[2], e.ips[3]})
	assertEcmpRoutes(t, clusterCIDR, []string{e.ips[0], e.ips[2], e.ips[3]})

	// Same for the external IP CIDR.
	externalIPCIDR := "175.200.0.0/16"
	assertEcmpRoutes(t, externalIPCIDR, []string{e.ips[0], e.ips[2], e.ips[3]})

	// Still reachable through other nodes.
	curlRetry(t, localSvcIP)
	curlRetry(t, clusterSvcIP)

	// Delete the local service; it is no longer advertised.
	utils.DeleteAndConfirm(t, localSvc, "svc", e.ns)
	assertRouteNotContains(t, localSvcIP)

	// Re-create the local service; advertised from the correct nodes only.
	utils.CreateService(t, localSvc, localSvc, e.ns, 80, utils.DeployOptions{})
	utils.WaitUntilExists(t, localSvc, "svc", e.ns)
	localSvcIP = utils.GetSvcClusterIP(t, localSvc, e.ns)
	assertEcmpRoutes(t, localSvcIP, []string{e.ips[2], e.ips[3]})
	curlRetry(t, localSvcIP)

	// Add an external IP and assert it follows the same advertisement rules.
	localSvcExternalIP := "175.200.1.1"
	utils.AddSvcExternalIPs(t, localSvc, e.ns, []string{localSvcExternalIP})
	assertEcmpRoutes(t, localSvcExternalIP, []string{e.ips[2], e.ips[3]})

	// Re-enable the excluded node; it advertises service routes again.
	labelNode(t, e.nodes[1], "node.kubernetes.io/exclude-from-external-load-balancers", "false")
	assertEcmpRoutes(t, localSvcIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	assertEcmpRoutes(t, localSvcExternalIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	assertEcmpRoutes(t, clusterCIDR, []string{e.ips[0], e.ips[1], e.ips[2], e.ips[3]})
	curlRetry(t, localSvcIP)

	// Delete both services; the clusterIP is no longer advertised.
	utils.DeleteAndConfirm(t, localSvc, "svc", e.ns)
	utils.DeleteAndConfirm(t, clusterSvc, "svc", e.ns)
	assertRouteNotContains(t, localSvcIP)
}

func (e *bgpAdvertEnv) testExternalIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	// Allow two IP ranges for the external IPs we'll test with.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceExternalIPs: []v3.ServiceExternalIPBlock{
			{CIDR: "175.200.0.0/16"},
			{CIDR: "200.255.0.0/24"},
		},
	})

	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{})
	utils.Deploy(t, utils.NginxImage, clusterSvc, e.ns, 80, utils.DeployOptions{TrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster})
	utils.WaitUntilExists(t, localSvc, "svc", e.ns)
	utils.WaitUntilExists(t, clusterSvc, "svc", e.ns)

	localSvcIP := utils.GetSvcClusterIP(t, localSvc, e.ns)
	clusterSvcIP := utils.GetSvcClusterIP(t, clusterSvc, e.ns)

	utils.WaitForDeployment(t, localSvc, e.ns)
	utils.WaitForDeployment(t, clusterSvc, e.ns)

	// clusterIPs are not advertised (no serviceClusterIPs configured).
	assertRouteNotContains(t, localSvcIP)
	assertRouteNotContains(t, clusterSvcIP)

	// Network policy that only accepts traffic from the external node.
	createExternalNodeIngressPolicy(t, e.ns, e.externalNodeIP)

	localSvcHostIP := utils.GetSvcHostIP(t, localSvc, e.ns)
	clusterSvcHostIP := utils.GetSvcHostIP(t, clusterSvc, e.ns)

	// Select an IP from each external IP CIDR.
	localSvcExternalIP := "175.200.1.1"
	clusterSvcExternalIP := "200.255.255.1"

	utils.AddSvcExternalIPs(t, localSvc, e.ns, []string{localSvcExternalIP})
	utils.AddSvcExternalIPs(t, clusterSvc, e.ns, []string{clusterSvcExternalIP})

	// The external IP of the local service is advertised but not the cluster one.
	localSvcExternalIPsRoute := fmt.Sprintf("%s via %s", localSvcExternalIP, localSvcHostIP)
	clusterSvcExternalIPsRoute := fmt.Sprintf("%s via %s", clusterSvcExternalIP, clusterSvcHostIP)
	assertRouteContains(t, localSvcExternalIPsRoute)
	assertRouteNotContains(t, clusterSvcExternalIPsRoute)

	// Scale the local service to 4 replicas; expect ECMP routes for its ext IP.
	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	assertEcmpRoutes(t, localSvcExternalIP, []string{e.ips[1], e.ips[2], e.ips[3]})

	// Delete both services; the external IP is no longer advertised.
	utils.DeleteAndConfirm(t, localSvc, "svc", e.ns)
	utils.DeleteAndConfirm(t, clusterSvc, "svc", e.ns)
	assertRouteNotContains(t, localSvcExternalIPsRoute)
}

func (e *bgpAdvertEnv) testFullyQualifiedServiceIPs(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	// Allow an exact /32 external IP; expect it advertised from all nodes.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceExternalIPs: []v3.ServiceExternalIPBlock{{CIDR: "90.15.0.1/32"}},
	})

	// Create a Service with the external IP above, using
	// externalTrafficPolicy=Cluster, triggering advertisement from all nodes.
	svcName := "nginx-svc"
	extIP := "90.15.0.1"
	utils.Deploy(t, utils.NginxImage, svcName, e.ns, 80, utils.DeployOptions{
		TrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
		SvcType:       corev1.ServiceTypeClusterIP,
		ExtIP:         extIP,
	})
	utils.WaitUntilExists(t, svcName, "svc", e.ns)
	utils.WaitForDeployment(t, svcName, e.ns)

	assertEcmpRoutes(t, extIP, []string{e.ips[0], e.ips[1], e.ips[2], e.ips[3]})
}

func (e *bgpAdvertEnv) testLoadBalancerIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "80.15.0.0/24"}},
	})

	// Create a dummy service to occupy the first LB IP, so the IP we test with
	// below isn't the zero address of the range.
	utils.CreateService(t, "dummy-service", "dummy-service", e.ns, 80, utils.DeployOptions{SvcType: corev1.ServiceTypeLoadBalancer})

	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	utils.Deploy(t, utils.NginxImage, clusterSvc, e.ns, 80, utils.DeployOptions{
		TrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
		SvcType:       corev1.ServiceTypeLoadBalancer,
	})
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{SvcType: corev1.ServiceTypeLoadBalancer})
	utils.WaitUntilExists(t, localSvc, "svc", e.ns)
	utils.WaitUntilExists(t, clusterSvc, "svc", e.ns)

	localLBIP := utils.GetSvcLoadBalancerIP(t, localSvc, e.ns)
	clusterLBIP := utils.GetSvcLoadBalancerIP(t, clusterSvc, e.ns)

	utils.WaitForDeployment(t, localSvc, e.ns)
	utils.WaitForDeployment(t, clusterSvc, e.ns)

	localSvcHostIP := utils.GetSvcHostIP(t, localSvc, e.ns)
	clusterSvcHostIP := utils.GetSvcHostIP(t, clusterSvc, e.ns)

	// LB IP of the local service is advertised but not the cluster service's.
	localSvcLBRoute := fmt.Sprintf("%s via %s", localLBIP, localSvcHostIP)
	clusterSvcLBRoute := fmt.Sprintf("%s via %s", clusterLBIP, clusterSvcHostIP)
	assertRouteContains(t, localSvcLBRoute)
	assertRouteNotContains(t, clusterSvcLBRoute)

	// The full range is advertised from each node.
	lbCIDR := "80.15.0.0/24"
	assertEcmpRoutes(t, lbCIDR, []string{e.ips[0], e.ips[1], e.ips[2], e.ips[3]})

	// Scale the local service to 4 replicas; expect ECMP for its LB IP.
	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	assertEcmpRoutes(t, localLBIP, []string{e.ips[1], e.ips[2], e.ips[3]})

	// Disable LoadBalancer advertisement; routes are withdrawn.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{})
	assertRouteNotContains(t, localLBIP)
	assertRouteNotContains(t, lbCIDR)

	// Mismatched CIDR; routes stay withdrawn.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "90.15.0.0/24"}},
	})
	assertRouteNotContains(t, localLBIP)
	assertRouteNotContains(t, lbCIDR)

	// Reapply the correct configuration; routes come back.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "80.15.0.0/24"}},
	})
	assertEcmpRoutes(t, localLBIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	assertRouteContains(t, lbCIDR)
	assertRouteNotContains(t, clusterSvcLBRoute)

	// Services should be reachable from the external node.
	curlRetry(t, localLBIP)
	curlRetry(t, clusterLBIP)

	// Delete both services; the LB IP is no longer advertised.
	utils.DeleteAndConfirm(t, localSvc, "svc", e.ns)
	utils.DeleteAndConfirm(t, clusterSvc, "svc", e.ns)
	assertRouteNotContains(t, localLBIP)
}

func (e *bgpAdvertEnv) testManyServices(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceClusterIPs: []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}},
	})
	assertRouteContains(t, "10.96.0.0/12")

	// Create a local service and deployment.
	localSvc := "nginx-local"
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{})
	utils.WaitForDeployment(t, localSvc, e.ns)

	clusterIPs := []string{utils.GetSvcClusterIP(t, localSvc, e.ns)}

	// Create many more services selecting the same deployment.
	const numSvc = 50
	for i := range numSvc {
		utils.CreateService(t, fmt.Sprintf("nginx-svc-%d", i), localSvc, e.ns, 80, utils.DeployOptions{})
	}
	for i := range numSvc {
		clusterIPs = append(clusterIPs, utils.GetSvcClusterIP(t, fmt.Sprintf("nginx-svc-%d", i), e.ns))
	}

	// Assert all are advertised to the other node. This should happen quickly
	// enough that they're programmed by the time we've queried them all.
	g := NewWithT(t)
	g.Eventually(func() error {
		routes := utils.ExternalNodeRoutes(t)
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
		routes := utils.ExternalNodeRoutes(t)
		for _, cip := range clusterIPs {
			if strings.Contains(routes, cip) {
				return fmt.Errorf("route for %s still advertised", cip)
			}
		}
		return nil
	}, 60*time.Second, time.Second).Should(Succeed(), "service routes were not withdrawn")
}

func (e *bgpAdvertEnv) testBGPFilterIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	// Add BGPConfiguration with serviceClusterIPs.
	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceClusterIPs: []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}},
	})
	assertRouteContains(t, "10.96.0.0/12")

	// Create a Local type NodePort service with a single replica.
	localSvc := "nginx-local"
	utils.Deploy(t, utils.NginxImage, localSvc, e.ns, 80, utils.DeployOptions{})
	utils.WaitUntilExists(t, localSvc, "svc", e.ns)

	localSvcIP := utils.GetSvcClusterIP(t, localSvc, e.ns)
	utils.WaitForDeployment(t, localSvc, e.ns)

	curlRetry(t, localSvcIP)
	assertRouteContains(t, localSvcIP)

	// Create an export BGP filter that rejects the service IP range.
	filterName := "test-filter-export-1"
	filter := &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: filterName},
		Spec: v3.BGPFilterSpec{
			ExportV4: []v3.BGPFilterRuleV4{{
				CIDR:          "10.96.0.0/12",
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
	assertRouteNotContains(t, localSvcIP)
	assertRouteNotContains(t, "10.96.0.0/12")
}

// ----------------------------------------------------------------------------
// TestBGPAdvertRR subtests.

func (e *bgpAdvertEnv) testRR(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	// ExternalTrafficPolicy=Local service with one endpoint on node-1.
	svc := e.createRRWorkload(t, func(s *corev1.Service) {
		s.Spec.Type = corev1.ServiceTypeNodePort
		s.Spec.ExternalIPs = []string{"175.200.1.1"}
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
		ServiceClusterIPs:     []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}},
		ServiceExternalIPs:    []v3.ServiceExternalIPBlock{{CIDR: "175.200.0.0/16"}},
	})
	e.createRRPeer(t)

	clusterIP := svc.Spec.ClusterIP
	externalIP := svc.Spec.ExternalIPs[0]
	assertRouteContains(t, clusterIP)
	assertRouteContains(t, externalIP)
}

func (e *bgpAdvertEnv) testSingleIPLBRR(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	// LB ExternalTrafficPolicy=Local service with one endpoint on node-1.
	svc := e.createRRWorkload(t, func(s *corev1.Service) {
		s.Annotations = map[string]string{
			"projectcalico.org/loadBalancerIPs": `["80.15.0.100"]`,
		}
		s.Spec.Type = corev1.ServiceTypeLoadBalancer
		s.Spec.LoadBalancerClass = new("calico")
		s.Spec.LoadBalancerIP = "80.15.0.100"
		s.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
	})

	g := NewWithT(t)
	g.Eventually(func() error {
		return setRRConfig(t, e.nodes[2])
	}, 90*time.Second, time.Second).Should(Succeed(), "setting route-reflector config on %s", e.nodes[2])

	e.setBGPConfig(t, v3.BGPConfigurationSpec{
		NodeToNodeMeshEnabled:  new(false),
		ASNumber:               new(numorstring.ASNumber(bgpASNumber)),
		ServiceClusterIPs:      []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}},
		ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "80.15.0.100/32"}},
	})
	e.createRRPeer(t)

	clusterIP := svc.Spec.ClusterIP
	loadBalancerIP := svc.Spec.LoadBalancerIP
	assertRouteContains(t, clusterIP)
	assertRouteContains(t, loadBalancerIP)
}

// createRRWorkload deploys the nginx-rr Deployment pinned to node-1 and a
// matching Service customised by mutate, then returns the created Service.
func (e *bgpAdvertEnv) createRRWorkload(t *testing.T, mutate func(*corev1.Service)) *corev1.Service {
	t.Helper()
	g := NewWithT(t)
	cs := utils.K8sClient(t)
	ctx := context.Background()

	labels := map[string]string{"app": "nginx", "run": "nginx-rr"}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-rr", Namespace: e.ns, Labels: map[string]string{"app": "nginx"}},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"kubernetes.io/os":       "linux",
						"kubernetes.io/hostname": e.nodes[1],
					},
					Containers: []corev1.Container{{
						Name:  "nginx-rr",
						Image: utils.NginxImage,
						Ports: []corev1.ContainerPort{{ContainerPort: 80}},
					}},
				},
			},
		},
	}
	_, err := cs.AppsV1().Deployments(e.ns).Create(ctx, dep, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred(), "creating nginx-rr deployment")

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-rr", Namespace: e.ns, Labels: labels},
		Spec: corev1.ServiceSpec{
			Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(80)}},
			Selector: labels,
		},
	}
	mutate(svc)
	// The API server assigns the clusterIP synchronously at creation and echoes
	// back the spec we set (including loadBalancerIP / externalIPs), so the
	// returned object carries everything the caller asserts on — matching the
	// Python, which reads spec.clusterIP / spec.loadBalancerIP directly.
	created, err := cs.CoreV1().Services(e.ns).Create(ctx, svc, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred(), "creating nginx-rr service")
	return created
}

// createRRPeer creates the BGPPeer from the cluster nodes to the route
// reflector (kube-node-2).
func (e *bgpAdvertEnv) createRRPeer(t *testing.T) {
	t.Helper()
	peer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: rrPeerName},
		Spec: v3.BGPPeerSpec{
			PeerIP:   e.ips[2],
			ASNumber: numorstring.ASNumber(bgpASNumber),
		},
	}
	upsertBGPPeer(t, e.cli, peer)
}

// ----------------------------------------------------------------------------
// BGP / route helpers.

// setBGPConfig upserts the default BGPConfiguration with the given spec
// (replacing the whole spec, matching `calicoctl apply`).
func (e *bgpAdvertEnv) setBGPConfig(t *testing.T, spec v3.BGPConfigurationSpec) {
	t.Helper()
	g := NewWithT(t)
	ctx := context.Background()

	cfg := &v3.BGPConfiguration{}
	err := e.cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, cfg)
	if apierrors.IsNotFound(err) {
		cfg = &v3.BGPConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: spec}
		g.Expect(e.cli.Create(ctx, cfg)).To(Succeed(), "creating default BGPConfiguration")
		return
	}
	g.Expect(err).NotTo(HaveOccurred(), "reading default BGPConfiguration")
	cfg.Spec = spec
	g.Expect(e.cli.Update(ctx, cfg)).To(Succeed(), "updating default BGPConfiguration")
}

// createBGPSecret creates the shared BGP password Secret, ignoring an existing
// one (it survives across the two test classes).
func createBGPSecret(t *testing.T, cli ctrlclient.Client) {
	t.Helper()
	g := NewWithT(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: bgpSecretName, Namespace: bgpSecretNS},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{bgpSecretKey: bgpSecretVal},
	}
	// The Secret survives across the two test classes, so an existing one is fine.
	g.Expect(ctrlclient.IgnoreAlreadyExists(cli.Create(context.Background(), secret))).
		To(Succeed(), "creating BGP secret")
}

// upsertBGPPeer creates the peer, or replaces its spec if it already exists.
func upsertBGPPeer(t *testing.T, cli ctrlclient.Client, peer *v3.BGPPeer) {
	t.Helper()
	g := NewWithT(t)
	ctx := context.Background()
	err := cli.Create(ctx, peer)
	if apierrors.IsAlreadyExists(err) {
		existing := &v3.BGPPeer{}
		g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: peer.Name}, existing)).To(Succeed())
		existing.Spec = peer.Spec
		g.Expect(cli.Update(ctx, existing)).To(Succeed(), "updating BGPPeer %s", peer.Name)
		return
	}
	g.Expect(err).NotTo(HaveOccurred(), "creating BGPPeer %s", peer.Name)
}

// deleteBGPPeer best-effort removes a BGPPeer; used in cleanup so it ignores
// absence.
func deleteBGPPeer(cli ctrlclient.Client, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	peer := &v3.BGPPeer{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := cli.Delete(ctx, peer); err != nil && !apierrors.IsNotFound(err) {
		fmt.Printf("WARNING: failed to delete BGPPeer %s: %v\n", name, err)
	}
}

// setPeerFilters sets the ordered filter list on a BGPPeer.
func setPeerFilters(t *testing.T, cli ctrlclient.Client, name string, filters []string) {
	t.Helper()
	g := NewWithT(t)
	ctx := context.Background()
	g.Eventually(func() error {
		peer := &v3.BGPPeer{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: name}, peer); err != nil {
			return err
		}
		peer.Spec.Filters = filters
		return cli.Update(ctx, peer)
	}, "20s", "1s").Should(Succeed(), "setting filters %v on BGPPeer %s", filters, name)
}

// labelNode sets a label on a node (overwriting any existing value).
func labelNode(t *testing.T, node, key, value string) {
	t.Helper()
	g := NewWithT(t)
	cs := utils.K8sClient(t)
	g.Eventually(func() error {
		n, err := cs.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		n.Labels[key] = value
		_, err = cs.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
		return err
	}, 30*time.Second, time.Second).Should(Succeed(), "labelling node %s %s=%s", node, key, value)
}

// createExternalNodeIngressPolicy creates a NetworkPolicy in the test namespace
// that only admits TCP/80 ingress from the external node's IP.
func createExternalNodeIngressPolicy(t *testing.T, nsName, externalIP string) {
	t.Helper()
	g := NewWithT(t)
	tcp := corev1.ProtocolTCP
	port80 := intstr.FromInt32(80)
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-tcp-80-ex", Namespace: nsName},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{CIDR: externalIP + "/32"},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port80}},
			}},
		},
	}
	_, err := utils.K8sClient(t).NetworkingV1().NetworkPolicies(nsName).Create(
		context.Background(), policy, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred(), "creating NetworkPolicy")
}

// setRRConfig labels the node as a route reflector and sets its cluster ID,
// going through calicoctl since the Calico Node resource has no typed client
// here. Returns an error so it can be retried.
func setRRConfig(t *testing.T, node string) error {
	m, err := getCalicoNode(t, node)
	if err != nil {
		return err
	}
	meta := mapField(m, "metadata")
	labels := mapField(meta, "labels")
	labels["i-am-a-route-reflector"] = "true"
	spec := mapField(m, "spec")
	bgp := mapField(spec, "bgp")
	bgp["routeReflectorClusterID"] = "224.0.0.1"
	return applyCalicoNode(t, m)
}

// clearRRConfig removes the route-reflector label and cluster ID. Returns an
// error so it can be retried.
func clearRRConfig(t *testing.T, node string) error {
	m, err := getCalicoNode(t, node)
	if err != nil {
		return err
	}
	if labels, ok := mapField(m, "metadata")["labels"].(map[string]any); ok {
		delete(labels, "i-am-a-route-reflector")
	}
	if bgp, ok := mapField(m, "spec")["bgp"].(map[string]any); ok {
		delete(bgp, "routeReflectorClusterID")
	}
	return applyCalicoNode(t, m)
}

func getCalicoNode(t *testing.T, node string) (map[string]any, error) {
	t.Helper()
	out, err := utils.Calicoctl(t, "get node "+node+" -o json",
		utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return nil, fmt.Errorf("parsing node JSON: %w (output: %s)", err, out)
	}
	return m, nil
}

func applyCalicoNode(t *testing.T, m map[string]any) error {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = utils.Calicoctl(t, fmt.Sprintf("apply -f - <<'EOF'\n%s\nEOF\n", string(b)),
		utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	return err
}

// mapField returns m[key] as a map[string]any, creating it if absent.
func mapField(m map[string]any, key string) map[string]any {
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	child := map[string]any{}
	m[key] = child
	return child
}

// assertRouteContains retries until the external node's route table contains
// substr.
func assertRouteContains(t *testing.T, substr string) {
	t.Helper()
	g := NewWithT(t)
	g.Eventually(func() error {
		if routes := utils.ExternalNodeRoutes(t); !strings.Contains(routes, substr) {
			return fmt.Errorf("route table does not contain %q:\n%s", substr, routes)
		}
		return nil
	}, 90*time.Second, time.Second).Should(Succeed(), "expected route %q", substr)
}

// assertRouteNotContains retries until the external node's route table no longer
// contains substr.
func assertRouteNotContains(t *testing.T, substr string) {
	t.Helper()
	g := NewWithT(t)
	g.Eventually(func() error {
		if routes := utils.ExternalNodeRoutes(t); strings.Contains(routes, substr) {
			return fmt.Errorf("route table still contains %q:\n%s", substr, routes)
		}
		return nil
	}, 90*time.Second, time.Second).Should(Succeed(), "expected route %q to be withdrawn", substr)
}

// assertEcmpRoutes retries until the external node's route table contains the
// ECMP route block for dst with exactly the given next-hop IPs. Mirrors
// _TestBGPAdvert.assert_ecmp_routes.
func assertEcmpRoutes(t *testing.T, dst string, via []string) {
	t.Helper()
	sorted := append([]string(nil), via...)
	sort.Strings(sorted)
	match := dst + " proto bird "
	for _, ip := range sorted {
		match += fmt.Sprintf("\n\tnexthop via %s dev eth0 weight 1 ", ip)
	}
	g := NewWithT(t)
	g.Eventually(func() error {
		if routes := utils.ExternalNodeRoutes(t); !strings.Contains(routes, match) {
			return fmt.Errorf("ECMP route block not found:\n%s\nin:\n%s", match, routes)
		}
		return nil
	}, 90*time.Second, time.Second).Should(Succeed(), "expected ECMP routes for %s via %v", dst, sorted)
}

// curlRetry retries a curl from the external node to host until it succeeds.
func curlRetry(t *testing.T, host string) {
	t.Helper()
	g := NewWithT(t)
	g.Eventually(func() error {
		_, err := utils.Curl(t, host)
		return err
	}, 90*time.Second, time.Second).Should(Succeed(), "could not curl %s from external node", host)
}
