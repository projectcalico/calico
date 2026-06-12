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

// bgp_advert_test.go is the Go port of test_bgp_advert.py. It stands up an
// external BIRD node peered with the cluster (full mesh or via a route
// reflector) and verifies BGP advertisement of Kubernetes Service cluster IPs,
// external IPs and LoadBalancer IPs, including ECMP, node exclusion and
// BGPFilter interaction. The shared env/helpers in this file are reused by the
// IPv6 suite in bgp_advert_v6_test.go.

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
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

// External-node BIRD config templates. ip@local is substituted by
// StartExternalNodeWithBGP; %s placeholders are filled with cluster node IPs.

// birdConfAdvertV4Mesh peers (passively) with all four cluster nodes, with a
// shared BGP password.
const birdConfAdvertV4Mesh = `
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

protocol bgp Mesh_with_master_node from bgp_template {
  neighbor %s as 64512;
  passive on;
  password "very-secret";
}

protocol bgp Mesh_with_node_1 from bgp_template {
  neighbor %s as 64512;
  passive on;
  password "very-secret";
}

protocol bgp Mesh_with_node_2 from bgp_template {
  neighbor %s as 64512;
  passive on;
  password "very-secret";
}

protocol bgp Mesh_with_node_3 from bgp_template {
  neighbor %s as 64512;
  passive on;
  password "very-secret";
}
`

// birdConfAdvertV6Mesh peers with all four cluster nodes (no password).
const birdConfAdvertV6Mesh = `
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

protocol bgp Mesh_with_master_node from bgp_template {
  neighbor %s as 64512;
  passive on;
}

protocol bgp Mesh_with_node_1 from bgp_template {
  neighbor %s as 64512;
  passive on;
}

protocol bgp Mesh_with_node_2 from bgp_template {
  neighbor %s as 64512;
  passive on;
}

protocol bgp Mesh_with_node_3 from bgp_template {
  neighbor %s as 64512;
  passive on;
}
`

// birdConfAdvertRR peers only with node-2 (the in-cluster route reflector).
const birdConfAdvertRR = `
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

protocol bgp Mesh_with_node_2 from bgp_template {
  neighbor %s as 64512;
  passive on;
}
`

// bgpAdvertEnv carries the fixtures shared by the advertisement subtests.
type bgpAdvertEnv struct {
	cli            ctrlclient.Client
	nodes          []string
	ips            []string // node IPv4 addresses
	ip6s           []string // node IPv6 addresses
	externalNodeIP string   // the external node's BGP source IP
	v6             bool     // IPv6 suite (affects get_routes and the deploy image)
	ns             string   // per-test namespace, always "bgp-test"
}

const advertNamespace = "bgp-test"

// setupBGPAdvert performs the per-class setUp: it starts the external node,
// creates the cluster→external BGPPeer (and, for the v4 mesh, the BGP password
// Secret), and registers teardown. rr selects the route-reflector topology.
func setupBGPAdvert(t *testing.T, g *WithT, v6, rr bool) *bgpAdvertEnv {
	t.Helper()
	cli := newClient(g)
	nodes, ips, ip6s := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 4), "need a control-plane node and three workers")

	env := &bgpAdvertEnv{cli: cli, nodes: nodes, ips: ips, ip6s: ip6s, v6: v6, ns: advertNamespace}

	// Build the external node's BIRD config and its BGPPeer spec.
	var birdConf string
	addrs := ips
	if v6 {
		addrs = ip6s
	}
	if rr {
		birdConf = fmt.Sprintf(birdConfAdvertRR, addrs[2])
	} else if v6 {
		birdConf = fmt.Sprintf(birdConfAdvertV6Mesh, addrs[0], addrs[1], addrs[2], addrs[3])
	} else {
		birdConf = fmt.Sprintf(birdConfAdvertV4Mesh, addrs[0], addrs[1], addrs[2], addrs[3])
	}

	if v6 {
		env.externalNodeIP = utils.StartExternalNodeWithBGP(t, "kube-node-extra", "", birdConf)
	} else {
		env.externalNodeIP = utils.StartExternalNodeWithBGP(t, "kube-node-extra", birdConf, "")
	}
	t.Cleanup(func() { _, _ = utils.Run(t, "docker rm -f kube-node-extra", utils.RunOptions{AllowFail: true}) })

	// The cluster→external BGPPeer.
	peer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "node-extra.peer"},
		Spec:       v3.BGPPeerSpec{PeerIP: env.externalNodeIP, ASNumber: numorstring.ASNumber(64512)},
	}
	if rr {
		peer.Spec.Node = nodes[2]
	} else if !v6 {
		// The v4 mesh authenticates with a shared password from a Secret.
		peer.Spec.Password = &v3.BGPPassword{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "bgp-secrets"},
			Key:                  "rr-password",
		}}
	}
	createV3(t, cli, peer)
	t.Cleanup(func() { deleteV3(t, cli, peer) })

	if !v6 {
		// The base v4 setUpClass always creates the BGP password Secret.
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "bgp-secrets", Namespace: "calico-system"},
			Type:       corev1.SecretTypeOpaque,
			StringData: map[string]string{"rr-password": "very-secret"},
		}
		_, err := utils.K8sClient(t).CoreV1().Secrets("calico-system").Create(context.Background(), secret, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("creating bgp-secrets Secret: %v", err)
		}
		t.Cleanup(func() {
			_ = utils.K8sClient(t).CoreV1().Secrets("calico-system").Delete(context.Background(), "bgp-secrets", metav1.DeleteOptions{})
		})
	}

	return env
}

// startTest performs the per-test setUp/tearDown: it (re)creates the bgp-test
// namespace and registers the teardown that deletes it, removes any
// peer-with-rr, restores the node-to-node mesh and clears node-2's RR config.
func (e *bgpAdvertEnv) startTest(t *testing.T) {
	t.Helper()
	utils.CreateNamespace(t, e.ns)
	t.Cleanup(func() {
		utils.DeleteNamespaceAndConfirm(t, e.ns)
		deleteV3(t, e.cli, &v3.BGPPeer{ObjectMeta: metav1.ObjectMeta{Name: "peer-with-rr"}})
		e.upsertBGPConfig(t, v3.BGPConfigurationSpec{
			NodeToNodeMeshEnabled: ptr.To(true),
			ASNumber:              ptr.To(numorstring.ASNumber(64512)),
		})
		clearRRConfig(t, e.nodes[2])
	})
}

// TestBGPAdvert ports TestBGPAdvert (full-mesh topology).
func TestBGPAdvert(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	g := NewWithT(t)
	env := setupBGPAdvert(t, g, false, false)

	t.Run("cluster_ip_advertisement", func(t *testing.T) { env.testClusterIPAdvertisement(t) })
	t.Run("node_exclusion", func(t *testing.T) { env.testNodeExclusion(t) })
	t.Run("external_ip_advertisement", func(t *testing.T) { env.testExternalIPAdvertisement(t) })
	t.Run("fully_qualified_service_ips", func(t *testing.T) { env.testFullyQualifiedServiceIPs(t) })
	t.Run("loadbalancer_ip_advertisement", func(t *testing.T) { env.testLoadBalancerIPAdvertisement(t) })
	t.Run("many_services", func(t *testing.T) { env.testManyServices(t) })
	t.Run("bgp_filter_ip_advertisement", func(t *testing.T) { env.testBGPFilterIPAdvertisement(t) })
}

// TestBGPAdvertRR ports TestBGPAdvertRR (route-reflector topology).
func TestBGPAdvertRR(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	g := NewWithT(t)
	env := setupBGPAdvert(t, g, false, true)

	t.Run("rr", func(t *testing.T) { env.testRR(t) })
	t.Run("single_ip_lb_rr", func(t *testing.T) { env.testSingleIPLBRR(t) })
}

// --- v4 mesh tests ---

// testClusterIPAdvertisement ports test_cluster_ip_advertisement.
func (e *bgpAdvertEnv) testClusterIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{ServiceClusterIPs: []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}}})
	e.assertRouteIn(t, "10.96.0.0/12")

	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	e.deploy(t, localSvc, "")
	e.deploy(t, clusterSvc, corev1.ServiceExternalTrafficPolicyTypeCluster)
	utils.WaitUntilServiceExists(t, localSvc, e.ns)
	utils.WaitUntilServiceExists(t, clusterSvc, e.ns)

	localSvcIP := utils.ServiceClusterIP(t, localSvc, e.ns)
	clusterSvcIP := utils.ServiceClusterIP(t, clusterSvc, e.ns)

	utils.WaitForDeployment(t, localSvc, e.ns)
	utils.WaitForDeployment(t, clusterSvc, e.ns)

	e.assertCurl(t, localSvcIP)
	e.assertCurl(t, clusterSvcIP)

	e.assertRouteIn(t, localSvcIP)
	e.assertRouteNotIn(t, clusterSvcIP)

	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	e.assertECMPRoutes(t, localSvcIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	e.assertCurl(t, localSvcIP)

	utils.DeleteServiceAndConfirm(t, localSvc, e.ns)
	utils.DeleteServiceAndConfirm(t, clusterSvc, e.ns)
	e.assertRouteNotIn(t, localSvcIP)
}

// testNodeExclusion ports test_node_exclusion.
func (e *bgpAdvertEnv) testNodeExclusion(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{
		ServiceClusterIPs:  []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}},
		ServiceExternalIPs: []v3.ServiceExternalIPBlock{{CIDR: "175.200.0.0/16"}},
	})

	clusterCIDR := "10.96.0.0/12"
	e.assertRouteIn(t, clusterCIDR)

	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	e.deploy(t, localSvc, "")
	e.deploy(t, clusterSvc, corev1.ServiceExternalTrafficPolicyTypeCluster)
	utils.WaitUntilServiceExists(t, localSvc, e.ns)
	utils.WaitUntilServiceExists(t, clusterSvc, e.ns)

	localSvcIP := utils.ServiceClusterIP(t, localSvc, e.ns)
	clusterSvcIP := utils.ServiceClusterIP(t, clusterSvc, e.ns)

	utils.WaitForDeployment(t, localSvc, e.ns)
	utils.WaitForDeployment(t, clusterSvc, e.ns)

	e.assertCurl(t, localSvcIP)
	e.assertCurl(t, clusterSvcIP)
	e.assertRouteIn(t, localSvcIP)
	e.assertRouteNotIn(t, clusterSvcIP)
	e.assertCurl(t, localSvcIP)
	e.assertCurl(t, clusterSvcIP)

	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)

	e.assertECMPRoutes(t, localSvcIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	e.assertECMPRoutes(t, clusterCIDR, []string{e.ips[0], e.ips[1], e.ips[2], e.ips[3]})
	e.assertCurl(t, localSvcIP)

	// Exclude node-1 from external load balancers; its routes must withdraw.
	utils.SetNodeLabel(t, e.nodes[1], "node.kubernetes.io/exclude-from-external-load-balancers", "true")
	e.assertECMPRoutes(t, localSvcIP, []string{e.ips[2], e.ips[3]})
	e.assertECMPRoutes(t, clusterCIDR, []string{e.ips[0], e.ips[2], e.ips[3]})

	externalIPCIDR := "175.200.0.0/16"
	e.assertECMPRoutes(t, externalIPCIDR, []string{e.ips[0], e.ips[2], e.ips[3]})

	e.assertCurl(t, localSvcIP)
	e.assertCurl(t, clusterSvcIP)

	utils.DeleteServiceAndConfirm(t, localSvc, e.ns)
	e.assertRouteNotIn(t, localSvcIP)

	// Re-create the local service; still excluded from node-1.
	utils.CreateService(t, utils.ServiceOptions{Name: localSvc, App: localSvc, Namespace: e.ns, Port: 80})
	utils.WaitUntilServiceExists(t, localSvc, e.ns)
	localSvcIP = utils.ServiceClusterIP(t, localSvc, e.ns)
	e.assertECMPRoutes(t, localSvcIP, []string{e.ips[2], e.ips[3]})
	e.assertCurl(t, localSvcIP)

	localSvcExternalIP := "175.200.1.1"
	utils.AddServiceExternalIPs(t, localSvc, e.ns, []string{localSvcExternalIP})
	e.assertECMPRoutes(t, localSvcExternalIP, []string{e.ips[2], e.ips[3]})

	// Re-enable node-1; it re-advertises.
	utils.SetNodeLabel(t, e.nodes[1], "node.kubernetes.io/exclude-from-external-load-balancers", "false")
	e.assertECMPRoutes(t, localSvcIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	e.assertECMPRoutes(t, localSvcExternalIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	e.assertECMPRoutes(t, clusterCIDR, []string{e.ips[0], e.ips[1], e.ips[2], e.ips[3]})
	e.assertCurl(t, localSvcIP)

	utils.DeleteServiceAndConfirm(t, localSvc, e.ns)
	utils.DeleteServiceAndConfirm(t, clusterSvc, e.ns)
	e.assertRouteNotIn(t, localSvcIP)
}

// testExternalIPAdvertisement ports test_external_ip_advertisement.
func (e *bgpAdvertEnv) testExternalIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{ServiceExternalIPs: []v3.ServiceExternalIPBlock{
		{CIDR: "175.200.0.0/16"}, {CIDR: "200.255.0.0/24"},
	}})

	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	e.deploy(t, localSvc, "")
	e.deploy(t, clusterSvc, corev1.ServiceExternalTrafficPolicyTypeCluster)
	utils.WaitUntilServiceExists(t, localSvc, e.ns)
	utils.WaitUntilServiceExists(t, clusterSvc, e.ns)

	localSvcIP := utils.ServiceClusterIP(t, localSvc, e.ns)
	clusterSvcIP := utils.ServiceClusterIP(t, clusterSvc, e.ns)

	utils.WaitForDeployment(t, localSvc, e.ns)
	utils.WaitForDeployment(t, clusterSvc, e.ns)

	e.assertRouteNotIn(t, localSvcIP)
	e.assertRouteNotIn(t, clusterSvcIP)

	// Network policy allowing only the external node.
	e.applyAllowTCP80FromExternal(t)

	localSvcHostIP := utils.ServiceHostIP(t, localSvc, e.ns)
	clusterSvcHostIP := utils.ServiceHostIP(t, clusterSvc, e.ns)

	localSvcExternalIP := "175.200.1.1"
	clusterSvcExternalIP := "200.255.255.1"
	utils.AddServiceExternalIPs(t, localSvc, e.ns, []string{localSvcExternalIP})
	utils.AddServiceExternalIPs(t, clusterSvc, e.ns, []string{clusterSvcExternalIP})

	e.assertRouteIn(t, fmt.Sprintf("%s via %s", localSvcExternalIP, localSvcHostIP))
	e.assertRouteNotIn(t, fmt.Sprintf("%s via %s", clusterSvcExternalIP, clusterSvcHostIP))

	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	e.assertECMPRoutes(t, localSvcExternalIP, []string{e.ips[1], e.ips[2], e.ips[3]})

	utils.DeleteServiceAndConfirm(t, localSvc, e.ns)
	utils.DeleteServiceAndConfirm(t, clusterSvc, e.ns)
	e.assertRouteNotIn(t, fmt.Sprintf("%s via %s", localSvcExternalIP, localSvcHostIP))
}

// testFullyQualifiedServiceIPs ports test_fully_qualified_service_ips.
func (e *bgpAdvertEnv) testFullyQualifiedServiceIPs(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{ServiceExternalIPs: []v3.ServiceExternalIPBlock{{CIDR: "90.15.0.1/32"}}})

	svcName := "nginx-svc"
	extIP := "90.15.0.1"
	utils.Deploy(t, utils.DeployOptions{
		Image: e.image(), Name: svcName, Namespace: e.ns, Port: 80,
		TrafficPolicy: corev1.ServiceExternalTrafficPolicyTypeCluster,
		SvcType:       corev1.ServiceTypeClusterIP, ExternalIP: extIP, IPv6: e.v6,
	})
	utils.WaitUntilServiceExists(t, svcName, e.ns)
	utils.WaitForDeployment(t, svcName, e.ns)

	e.assertECMPRoutes(t, extIP, []string{e.ips[0], e.ips[1], e.ips[2], e.ips[3]})
}

// testLoadBalancerIPAdvertisement ports test_loadbalancer_ip_advertisement.
func (e *bgpAdvertEnv) testLoadBalancerIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "80.15.0.0/24"}}})

	// A dummy service occupies the zero address in the range.
	utils.CreateService(t, utils.ServiceOptions{Name: "dummy-service", App: "dummy-service", Namespace: e.ns, Port: 80, Type: corev1.ServiceTypeLoadBalancer})

	localSvc, clusterSvc := "nginx-local", "nginx-cluster"
	utils.Deploy(t, utils.DeployOptions{Image: e.image(), Name: clusterSvc, Namespace: e.ns, Port: 80, TrafficPolicy: corev1.ServiceExternalTrafficPolicyTypeCluster, SvcType: corev1.ServiceTypeLoadBalancer, IPv6: e.v6})
	utils.Deploy(t, utils.DeployOptions{Image: e.image(), Name: localSvc, Namespace: e.ns, Port: 80, SvcType: corev1.ServiceTypeLoadBalancer, IPv6: e.v6})
	utils.WaitUntilServiceExists(t, localSvc, e.ns)
	utils.WaitUntilServiceExists(t, clusterSvc, e.ns)

	localLBIP := utils.ServiceLoadBalancerIP(t, localSvc, e.ns)
	clusterLBIP := utils.ServiceLoadBalancerIP(t, clusterSvc, e.ns)

	utils.WaitForDeployment(t, localSvc, e.ns)
	utils.WaitForDeployment(t, clusterSvc, e.ns)

	localSvcHostIP := utils.ServiceHostIP(t, localSvc, e.ns)
	clusterSvcHostIP := utils.ServiceHostIP(t, clusterSvc, e.ns)

	e.assertRouteIn(t, fmt.Sprintf("%s via %s", localLBIP, localSvcHostIP))
	e.assertRouteNotIn(t, fmt.Sprintf("%s via %s", clusterLBIP, clusterSvcHostIP))

	lbCIDR := "80.15.0.0/24"
	e.assertECMPRoutes(t, lbCIDR, []string{e.ips[0], e.ips[1], e.ips[2], e.ips[3]})

	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	e.assertECMPRoutes(t, localLBIP, []string{e.ips[1], e.ips[2], e.ips[3]})

	// Disable LB advertisement: routes withdraw.
	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{})
	e.assertRouteNotIn(t, localLBIP)
	e.assertRouteNotIn(t, lbCIDR)

	// Mismatched CIDR: still withdrawn.
	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "90.15.0.0/24"}}})
	e.assertRouteNotIn(t, localLBIP)
	e.assertRouteNotIn(t, lbCIDR)

	// Reapply correct config: routes return.
	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "80.15.0.0/24"}}})
	e.assertECMPRoutes(t, localLBIP, []string{e.ips[1], e.ips[2], e.ips[3]})
	e.assertRouteIn(t, lbCIDR)
	e.assertRouteNotIn(t, fmt.Sprintf("%s via %s", clusterLBIP, clusterSvcHostIP))

	e.assertCurl(t, localLBIP)
	e.assertCurl(t, clusterLBIP)

	utils.DeleteServiceAndConfirm(t, localSvc, e.ns)
	utils.DeleteServiceAndConfirm(t, clusterSvc, e.ns)
	e.assertRouteNotIn(t, localLBIP)
}

// testManyServices ports test_many_services.
func (e *bgpAdvertEnv) testManyServices(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)
	g := NewWithT(t)

	clusterCIDR := "10.96.0.0/12"
	if e.v6 {
		clusterCIDR = "fd00:10:96::/112"
	}
	e.upsertServiceClusterIPs(t, clusterCIDR)
	e.assertRouteIn(t, clusterCIDR)

	localSvc := "nginx-local"
	utils.Deploy(t, utils.DeployOptions{Image: e.image(), Name: localSvc, Namespace: e.ns, Port: 80, IPv6: e.v6})
	utils.WaitForDeployment(t, localSvc, e.ns)

	var clusterIPs []string
	clusterIPs = append(clusterIPs, utils.ServiceClusterIP(t, localSvc, e.ns))

	const numSvc = 50
	for i := 0; i < numSvc; i++ {
		name := fmt.Sprintf("nginx-svc-%d", i)
		utils.CreateService(t, utils.ServiceOptions{Name: name, App: localSvc, Namespace: e.ns, Port: 80, IPv6: e.v6})
	}
	for i := 0; i < numSvc; i++ {
		name := fmt.Sprintf("nginx-svc-%d", i)
		clusterIPs = append(clusterIPs, utils.ServiceClusterIP(t, name, e.ns))
	}

	g.Eventually(func() error {
		routes := e.routes(t)
		for _, cip := range clusterIPs {
			if !strings.Contains(routes, cip) {
				return fmt.Errorf("route for %s not yet advertised", cip)
			}
		}
		return nil
	}, "20s", "1s").Should(Succeed())

	utils.ScaleDeployment(t, localSvc, e.ns, 0)
	utils.WaitForDeployment(t, localSvc, e.ns)
	g.Eventually(func() error {
		routes := e.routes(t)
		for _, cip := range clusterIPs {
			if strings.Contains(routes, cip) {
				return fmt.Errorf("route for %s still advertised", cip)
			}
		}
		return nil
	}, "60s", "2s").Should(Succeed())
}

// testBGPFilterIPAdvertisement ports test_bgp_filter_ip_advertisement.
func (e *bgpAdvertEnv) testBGPFilterIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	clusterCIDR := "10.96.0.0/12"
	if e.v6 {
		clusterCIDR = "fd00:10:96::/112"
	}
	e.upsertServiceClusterIPs(t, clusterCIDR)
	e.assertRouteIn(t, clusterCIDR)

	localSvc := "nginx-local"
	utils.Deploy(t, utils.DeployOptions{Image: e.image(), Name: localSvc, Namespace: e.ns, Port: 80, IPv6: e.v6})
	utils.WaitUntilServiceExists(t, localSvc, e.ns)
	localSvcIP := utils.ServiceClusterIP(t, localSvc, e.ns)
	utils.WaitForDeployment(t, localSvc, e.ns)

	e.assertCurl(t, localSvcIP)
	e.assertRouteIn(t, localSvcIP)

	// Export BGPFilter rejecting the service IP range.
	filter := &v3.BGPFilter{ObjectMeta: metav1.ObjectMeta{Name: "test-filter-export-1"}}
	if e.v6 {
		filter.Spec.ExportV6 = []v3.BGPFilterRuleV6{{CIDR: clusterCIDR, MatchOperator: v3.MatchOperatorIn, Action: v3.Reject}}
	} else {
		filter.Spec.ExportV4 = []v3.BGPFilterRuleV4{{CIDR: clusterCIDR, MatchOperator: v3.MatchOperatorIn, Action: v3.Reject}}
	}
	createV3(t, e.cli, filter)
	t.Cleanup(func() { deleteV3(t, e.cli, filter) })
	setPeerFilters(t, e.cli, "node-extra.peer", []string{"test-filter-export-1"})
	t.Cleanup(func() { setPeerFilters(t, e.cli, "node-extra.peer", nil) })

	e.assertRouteNotIn(t, localSvcIP)
	e.assertRouteNotIn(t, clusterCIDR)
}

// --- v4 RR tests ---

// testRR ports TestBGPAdvertRR.test_rr.
func (e *bgpAdvertEnv) testRR(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)
	g := NewWithT(t)

	svc := e.createRRDeploymentAndService(t, rrServiceConfig{
		externalIPs:   []string{"175.200.1.1"},
		svcType:       corev1.ServiceTypeNodePort,
		trafficPolicy: corev1.ServiceExternalTrafficPolicyTypeLocal,
	})

	utils.RetryUntilSuccess(t, 30*time.Second, func() error { return setRRConfigErr(t, e.nodes[2]) })

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{
		NodeToNodeMeshEnabled: ptr.To(false),
		ASNumber:              ptr.To(numorstring.ASNumber(64512)),
		ServiceClusterIPs:     []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}},
		ServiceExternalIPs:    []v3.ServiceExternalIPBlock{{CIDR: "175.200.0.0/16"}},
	})
	e.createPeerWithRR(t)

	g.Expect(svc.Spec.ClusterIP).NotTo(BeEmpty())
	e.assertRouteIn(t, svc.Spec.ClusterIP)
	e.assertRouteIn(t, svc.Spec.ExternalIPs[0])
}

// testSingleIPLBRR ports TestBGPAdvertRR.test_single_ip_lb_rr.
func (e *bgpAdvertEnv) testSingleIPLBRR(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)
	g := NewWithT(t)

	svc := e.createRRDeploymentAndService(t, rrServiceConfig{
		svcType:        corev1.ServiceTypeLoadBalancer,
		trafficPolicy:  corev1.ServiceExternalTrafficPolicyTypeLocal,
		loadBalancerIP: "80.15.0.100",
		annotations:    map[string]string{"projectcalico.org/loadBalancerIPs": `["80.15.0.100"]`},
	})

	utils.RetryUntilSuccess(t, 30*time.Second, func() error { return setRRConfigErr(t, e.nodes[2]) })

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{
		NodeToNodeMeshEnabled:  ptr.To(false),
		ASNumber:               ptr.To(numorstring.ASNumber(64512)),
		ServiceClusterIPs:      []v3.ServiceClusterIPBlock{{CIDR: "10.96.0.0/12"}},
		ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "80.15.0.100/32"}},
	})
	e.createPeerWithRR(t)

	g.Expect(svc.Spec.ClusterIP).NotTo(BeEmpty())
	e.assertRouteIn(t, svc.Spec.ClusterIP)
	e.assertRouteIn(t, svc.Spec.LoadBalancerIP)
}

// --- shared helpers ---

// image returns the web-server image for this suite.
func (e *bgpAdvertEnv) image() string {
	if e.v6 {
		return "gcr.io/kubernetes-e2e-test-images/test-webserver:1.0"
	}
	return utils.NginxImage
}

// deploy is the common case: deploy e.image() with the given traffic policy
// (empty = the Deploy default of Local), NodePort, single replica.
func (e *bgpAdvertEnv) deploy(t *testing.T, name string, trafficPolicy corev1.ServiceExternalTrafficPolicyType) {
	t.Helper()
	utils.Deploy(t, utils.DeployOptions{
		Image: e.image(), Name: name, Namespace: e.ns, Port: 80,
		TrafficPolicy: trafficPolicy, IPv6: e.v6,
	})
}

// routes returns the external node's routing table for this suite's family.
func (e *bgpAdvertEnv) routes(t *testing.T) string {
	t.Helper()
	return utils.ExternalNodeRoutes(t, "kube-node-extra", e.v6)
}

// assertRouteIn waits until substr appears in the external node's routes.
func (e *bgpAdvertEnv) assertRouteIn(t *testing.T, substr string) {
	t.Helper()
	NewWithT(t).Eventually(func() bool { return strings.Contains(e.routes(t), substr) }, "90s", "3s").
		Should(BeTrue(), "expected %q in external node routes", substr)
}

// assertRouteNotIn waits until substr is absent from the external node's routes.
func (e *bgpAdvertEnv) assertRouteNotIn(t *testing.T, substr string) {
	t.Helper()
	NewWithT(t).Eventually(func() bool { return !strings.Contains(e.routes(t), substr) }, "90s", "3s").
		Should(BeTrue(), "expected %q to be absent from external node routes", substr)
}

// assertECMPRoutes waits until the external node has an ECMP route to dst via
// exactly the given next hops. Mirrors assert_ecmp_routes.
func (e *bgpAdvertEnv) assertECMPRoutes(t *testing.T, dst string, via []string) {
	t.Helper()
	sorted := append([]string(nil), via...)
	sort.Strings(sorted)
	var b strings.Builder
	if e.v6 {
		b.WriteString(dst + " proto bird metric 1024 pref medium")
	} else {
		b.WriteString(dst + " proto bird ")
	}
	for _, ip := range sorted {
		b.WriteString(fmt.Sprintf("\n\tnexthop via %s dev eth0 weight 1 ", ip))
	}
	want := b.String()
	NewWithT(t).Eventually(func() bool { return strings.Contains(e.routes(t), want) }, "90s", "3s").
		Should(BeTrue(), "expected ECMP route:\n%s", want)
}

// assertCurl waits until the service IP is curlable from the external node.
func (e *bgpAdvertEnv) assertCurl(t *testing.T, ip string) {
	t.Helper()
	NewWithT(t).Eventually(func() error {
		_, err := utils.Curl(t, "kube-node-extra", ip)
		return err
	}, "90s", "3s").Should(Succeed(), "could not curl %s from external node", ip)
}

// upsertBGPConfig creates or updates the default BGPConfiguration's spec.
func (e *bgpAdvertEnv) upsertBGPConfig(t testing.TB, spec v3.BGPConfigurationSpec) {
	t.Helper()
	err := utils.RetryUntilSuccess(t, 30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg := &v3.BGPConfiguration{}
		err := e.cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, cfg)
		if apierrors.IsNotFound(err) {
			return e.cli.Create(ctx, &v3.BGPConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: spec})
		}
		if err != nil {
			return err
		}
		cfg.Spec = spec
		return e.cli.Update(ctx, cfg)
	})
	if err != nil {
		t.Fatalf("applying BGPConfiguration: %v", err)
	}
}

// upsertServiceClusterIPs is a convenience for the common single-CIDR spec.
func (e *bgpAdvertEnv) upsertServiceClusterIPs(t *testing.T, cidr string) {
	t.Helper()
	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{ServiceClusterIPs: []v3.ServiceClusterIPBlock{{CIDR: cidr}}})
}

// createPeerWithRR creates the cluster→RR BGPPeer (peering nodes with node-2).
func (e *bgpAdvertEnv) createPeerWithRR(t *testing.T) {
	t.Helper()
	peerIP := e.ips[2]
	if e.v6 {
		peerIP = e.ip6s[2]
	}
	createV3(t, e.cli, &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-with-rr"},
		Spec:       v3.BGPPeerSpec{PeerIP: peerIP, ASNumber: numorstring.ASNumber(64512)},
	})
}

// applyAllowTCP80FromExternal creates a NetworkPolicy that only admits TCP/80
// traffic from the external node.
func (e *bgpAdvertEnv) applyAllowTCP80FromExternal(t *testing.T) {
	t.Helper()
	tcp := corev1.ProtocolTCP
	port := intstr.FromInt32(80)
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-tcp-80-ex", Namespace: e.ns},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: e.externalNodeIP + "/32"}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}},
			}},
		},
	}
	if _, err := utils.K8sClient(t).NetworkingV1().NetworkPolicies(e.ns).Create(context.Background(), policy, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating NetworkPolicy: %v", err)
	}
}

// rrServiceConfig parameterises the nginx-rr Deployment + Service.
type rrServiceConfig struct {
	externalIPs    []string
	svcType        corev1.ServiceType
	trafficPolicy  corev1.ServiceExternalTrafficPolicyType
	loadBalancerIP string
	annotations    map[string]string
}

// createRRDeploymentAndService creates the nginx-rr Deployment (pinned to
// node-1) and its Service, then returns the created Service.
func (e *bgpAdvertEnv) createRRDeploymentAndService(t *testing.T, cfg rrServiceConfig) *corev1.Service {
	t.Helper()
	cs := utils.K8sClient(t)
	labels := map[string]string{"app": "nginx", "run": "nginx-rr"}

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-rr", Namespace: e.ns, Labels: map[string]string{"app": "nginx"}},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/hostname": e.nodes[1]},
					Containers: []corev1.Container{{
						Name:  "nginx-rr",
						Image: utils.NginxImage,
						Ports: []corev1.ContainerPort{{ContainerPort: 80}},
					}},
				},
			},
		},
	}
	if _, err := cs.AppsV1().Deployments(e.ns).Create(context.Background(), dep, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating nginx-rr deployment: %v", err)
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx-rr", Namespace: e.ns, Labels: labels, Annotations: cfg.annotations},
		Spec: corev1.ServiceSpec{
			Ports:                 []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(80)}},
			Selector:              labels,
			Type:                  cfg.svcType,
			ExternalTrafficPolicy: cfg.trafficPolicy,
			ExternalIPs:           cfg.externalIPs,
		},
	}
	if e.v6 {
		svc.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv6Protocol}
	}
	if cfg.svcType == corev1.ServiceTypeLoadBalancer {
		svc.Spec.LoadBalancerClass = ptr.To("calico")
		svc.Spec.LoadBalancerIP = cfg.loadBalancerIP
	}
	created, err := cs.CoreV1().Services(e.ns).Create(context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating nginx-rr service: %v", err)
	}
	return created
}

// --- Calico Node RR config (via calicoctl, as the v3 Node is not in the
// controller-runtime scheme) ---

// setRRConfigErr labels the node a route reflector and sets its cluster ID.
func setRRConfigErr(t testing.TB, node string) error {
	t.Helper()
	return mutateCalicoNode(t, node, func(m map[string]any) {
		meta := childMap(m, "metadata")
		labels := childMap(meta, "labels")
		labels["i-am-a-route-reflector"] = "true"
		spec := childMap(m, "spec")
		bgp := childMap(spec, "bgp")
		bgp["routeReflectorClusterID"] = "224.0.0.1"
	})
}

// clearRRConfig removes the route-reflector label and cluster ID from the node.
func clearRRConfig(t testing.TB, node string) {
	t.Helper()
	err := utils.RetryUntilSuccess(t, 30*time.Second, func() error {
		return mutateCalicoNode(t, node, func(m map[string]any) {
			if labels, ok := childMap(m, "metadata")["labels"].(map[string]any); ok {
				delete(labels, "i-am-a-route-reflector")
			}
			if bgp, ok := childMap(m, "spec")["bgp"].(map[string]any); ok {
				delete(bgp, "routeReflectorClusterID")
			}
		})
	})
	if err != nil {
		t.Logf("WARNING: clearing RR config on %s: %v", node, err)
	}
}

// mutateCalicoNode reads the Calico v3 Node via calicoctl, applies mutate, and
// writes it back.
func mutateCalicoNode(t testing.TB, node string, mutate func(map[string]any)) error {
	t.Helper()
	out, err := utils.Calicoctl(t, "get node "+node+" -o json", utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return fmt.Errorf("parsing node JSON: %w", err)
	}
	mutate(m)
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	utils.CalicoctlApply(t, string(b))
	return nil
}

// childMap returns m[key] as a map, creating it if absent.
func childMap(m map[string]any, key string) map[string]any {
	if existing, ok := m[key].(map[string]any); ok {
		return existing
	}
	child := map[string]any{}
	m[key] = child
	return child
}
