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

// bgp_advert_v6_test.go is the Go port of test_bgp_advert_v6.py: the IPv6
// counterpart of bgp_advert_test.go. It reuses the shared bgpAdvertEnv and
// helpers, with v6 set so routes are read with `ip -6 r`, services are pinned
// to the IPv6 family and the test-webserver image is used. A handful of
// scenarios differ from v4 (notably external-IP host-IP mapping and the v6
// service CIDRs), so they are ported explicitly here.

package k8stests

import (
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

const (
	v6ServiceClusterCIDR = "fd00:10:96::/112"
	webServerImage       = "gcr.io/kubernetes-e2e-test-images/test-webserver:1.0"
)

// TestBGPAdvertV6 ports TestBGPAdvertV6 (full-mesh topology).
func TestBGPAdvertV6(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	g := NewWithT(t)
	env := setupBGPAdvert(t, g, true, false)

	t.Run("cluster_ip_advertisement", func(t *testing.T) { env.testV6ClusterIPAdvertisement(t) })
	t.Run("external_ip_advertisement", func(t *testing.T) { env.testV6ExternalIPAdvertisement(t) })
	t.Run("many_services", func(t *testing.T) { env.testManyServices(t) })
	t.Run("bgp_filter_ip_advertisement", func(t *testing.T) { env.testBGPFilterIPAdvertisement(t) })
}

// TestBGPAdvertV6RR ports TestBGPAdvertV6RR (route-reflector topology).
func TestBGPAdvertV6RR(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	g := NewWithT(t)
	env := setupBGPAdvert(t, g, true, true)

	t.Run("rr", func(t *testing.T) { env.testV6RR(t) })
	t.Run("single_ip_lb_rr", func(t *testing.T) { env.testV6SingleIPLBRR(t) })
}

// testV6ClusterIPAdvertisement ports TestBGPAdvertV6.test_cluster_ip_advertisement.
func (e *bgpAdvertEnv) testV6ClusterIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.upsertServiceClusterIPs(t, v6ServiceClusterCIDR)
	e.assertRouteIn(t, v6ServiceClusterCIDR)

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

	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	e.assertECMPRoutes(t, localSvcIP, []string{e.ip6s[1], e.ip6s[2], e.ip6s[3]})
	e.assertCurl(t, localSvcIP)

	utils.DeleteServiceAndConfirm(t, localSvc, e.ns)
	utils.DeleteServiceAndConfirm(t, clusterSvc, e.ns)
	e.assertRouteNotIn(t, localSvcIP)
}

// testV6ExternalIPAdvertisement ports TestBGPAdvertV6.test_external_ip_advertisement.
func (e *bgpAdvertEnv) testV6ExternalIPAdvertisement(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{ServiceExternalIPs: []v3.ServiceExternalIPBlock{
		{CIDR: "fd5f:1234:175:200::/112"}, {CIDR: "fd5f:1234:200:255::/120"},
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

	e.applyAllowTCP80FromExternal(t)

	localSvcHostIP := e.serviceHostIPv6(t, localSvc)
	clusterSvcHostIP := e.serviceHostIPv6(t, clusterSvc)

	localSvcExternalIP := "fd5f:1234:175:200::1"
	clusterSvcExternalIP := "fd5f:1234:200:255::1"
	utils.AddServiceExternalIPs(t, localSvc, e.ns, []string{localSvcExternalIP})
	utils.AddServiceExternalIPs(t, clusterSvc, e.ns, []string{clusterSvcExternalIP})

	e.assertRouteIn(t, fmt.Sprintf("%s via %s", localSvcExternalIP, localSvcHostIP))
	e.assertRouteNotIn(t, fmt.Sprintf("%s via %s", clusterSvcExternalIP, clusterSvcHostIP))

	utils.ScaleDeployment(t, localSvc, e.ns, 4)
	utils.WaitForDeployment(t, localSvc, e.ns)
	e.assertECMPRoutes(t, localSvcExternalIP, []string{e.ip6s[1], e.ip6s[2], e.ip6s[3]})

	utils.DeleteServiceAndConfirm(t, localSvc, e.ns)
	utils.DeleteServiceAndConfirm(t, clusterSvc, e.ns)
	e.assertRouteNotIn(t, fmt.Sprintf("%s via %s", localSvcExternalIP, localSvcHostIP))
}

// testV6RR ports TestBGPAdvertV6RR.test_rr.
func (e *bgpAdvertEnv) testV6RR(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)
	g := NewWithT(t)

	svc := e.createRRDeploymentAndService(t, rrServiceConfig{
		externalIPs:   []string{"fd5f:1234:175:200::1"},
		svcType:       corev1.ServiceTypeNodePort,
		trafficPolicy: corev1.ServiceExternalTrafficPolicyTypeLocal,
	})

	utils.RetryUntilSuccess(t, 30*time.Second, func() error { return setRRConfigErr(t, e.nodes[2]) })

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{
		NodeToNodeMeshEnabled: ptr.To(false),
		ASNumber:              ptr.To(numorstring.ASNumber(64512)),
		ServiceClusterIPs:     []v3.ServiceClusterIPBlock{{CIDR: v6ServiceClusterCIDR}},
		ServiceExternalIPs:    []v3.ServiceExternalIPBlock{{CIDR: "fd5f:1234:175:200::/112"}},
	})
	e.createPeerWithRR(t)

	g.Expect(svc.Spec.ClusterIP).NotTo(BeEmpty())
	e.assertRouteIn(t, svc.Spec.ClusterIP)
	e.assertRouteIn(t, svc.Spec.ExternalIPs[0])
}

// testV6SingleIPLBRR ports TestBGPAdvertV6RR.test_single_ip_lb_rr.
func (e *bgpAdvertEnv) testV6SingleIPLBRR(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	e.startTest(t)
	g := NewWithT(t)

	svc := e.createRRDeploymentAndService(t, rrServiceConfig{
		svcType:        corev1.ServiceTypeLoadBalancer,
		trafficPolicy:  corev1.ServiceExternalTrafficPolicyTypeLocal,
		loadBalancerIP: "fdff::96",
		annotations:    map[string]string{"projectcalico.org/loadBalancerIPs": `["fdff::96"]`},
	})

	utils.RetryUntilSuccess(t, 30*time.Second, func() error { return setRRConfigErr(t, e.nodes[2]) })

	e.upsertBGPConfig(t, v3.BGPConfigurationSpec{
		NodeToNodeMeshEnabled:  ptr.To(false),
		ASNumber:               ptr.To(numorstring.ASNumber(64512)),
		ServiceClusterIPs:      []v3.ServiceClusterIPBlock{{CIDR: v6ServiceClusterCIDR}},
		ServiceLoadBalancerIPs: []v3.ServiceLoadBalancerIPBlock{{CIDR: "fdff::96/128"}},
	})
	e.createPeerWithRR(t)

	g.Expect(svc.Spec.ClusterIP).NotTo(BeEmpty())
	e.assertRouteIn(t, svc.Spec.ClusterIP)
	e.assertRouteIn(t, svc.Spec.LoadBalancerIP)
}

// serviceHostIPv6 returns the IPv6 address of the node hosting the given app's
// first pod, by mapping the pod's (IPv4) hostIP through the node IP tables.
// Mirrors _TestBGPAdvertV6.get_svc_host_ipv6.
func (e *bgpAdvertEnv) serviceHostIPv6(t *testing.T, app string) string {
	t.Helper()
	hostIPv4 := utils.ServiceHostIP(t, app, e.ns)
	for i, ip := range e.ips {
		if ip == hostIPv4 {
			return e.ip6s[i]
		}
	}
	t.Fatalf("could not map host IPv4 %s to an IPv6 address", hostIPv4)
	return ""
}
