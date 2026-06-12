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

// local_bgp_peer_test.go is the Go port of test_local_bgp_peer.py. It models a
// "child cluster" of BIRD workload pods that peer with their host node over
// Calico's local-workload BGP peering, and checks route propagation up to an
// external ToR — in both a full-mesh and a route-reflector cluster topology.

package k8stests

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

const workloadBirdImage = "calico/bird:v0.3.3-211-g9111ec3c"

// ToR BIRD config templates. %s placeholders are filled with cluster node IPs;
// ip@local is substituted by StartExternalNodeWithBGP.
const birdConfTorMesh = `
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 63000;
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

const birdConfTorRR = `
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 63000;
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

protocol bgp RR_with_master_node from bgp_template {
  neighbor %s as 64512;
  passive on;
}
`

// TestLocalBGPPeerMesh ports TestLocalBGPPeerMesh.
func TestLocalBGPPeerMesh(t *testing.T) {
	runLocalBGPPeer(t, "mesh")
}

// TestLocalBGPPeerRR ports TestLocalBGPPeerRR.
func TestLocalBGPPeerRR(t *testing.T) {
	runLocalBGPPeer(t, "rr")
}

// localBGPWorkload pairs a workload pod with its assigned child IPAM blocks.
type localBGPWorkload struct {
	pod     *utils.Pod
	blockV4 string
	blockV6 string
}

func runLocalBGPPeer(t *testing.T, topology string) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	cli := newClient(g)

	nodes, ips, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 4), "need a control-plane node and three workers")

	ns := utils.GenerateUniqueID(t, 8, "bgp-test")
	utils.CreateNamespace(t, ns)
	t.Cleanup(func() { utils.DeleteNamespaceAndConfirm(t, ns) })

	// Clean up any external node left over from a previous run, then create it.
	_, _ = utils.Run(t, "docker rm -f kind-node-tor", utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	var torConf string
	if topology == "mesh" {
		torConf = fmt.Sprintf(birdConfTorMesh, ips[0], ips[1], ips[2], ips[3])
	} else {
		torConf = fmt.Sprintf(birdConfTorRR, ips[0])
	}
	utils.StartExternalNodeWithBGP(t, "kind-node-tor", torConf, "")
	t.Cleanup(func() { _, _ = utils.Run(t, "docker rm -f kind-node-tor", utils.RunOptions{AllowFail: true}) })
	externalNodeIP := strings.TrimSpace(utils.MustRun(t,
		"docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' kind-node-tor"))

	// BGPFilter that exports the child cluster CIDR up toward the ToR.
	exportFilter := &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "export-child-cluster-cidr"},
		Spec: v3.BGPFilterSpec{
			ExportV4: []v3.BGPFilterRuleV4{{Action: v3.Accept, MatchOperator: v3.MatchOperatorIn, CIDR: "10.123.0.0/16", Source: v3.BGPFilterSourceRemotePeers}},
			ExportV6: []v3.BGPFilterRuleV6{{Action: v3.Accept, MatchOperator: v3.MatchOperatorIn, CIDR: "ca11:c0::/32", Source: v3.BGPFilterSourceRemotePeers}},
		},
	}
	createV3(t, cli, exportFilter)
	t.Cleanup(func() { deleteV3(t, cli, exportFilter) })

	asn := func(n uint32) numorstring.ASNumber { return numorstring.ASNumber(n) }

	if topology == "mesh" {
		peer := &v3.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: "node-tor-peer"},
			Spec:       v3.BGPPeerSpec{PeerIP: externalNodeIP, ASNumber: asn(63000), Filters: []string{"export-child-cluster-cidr"}},
		}
		createV3(t, cli, peer)
		t.Cleanup(func() { deleteV3(t, cli, peer) })
	} else {
		// Make kind-control-plane a route reflector.
		utils.SetNodeAnnotation(t, "kind-control-plane", "projectcalico.org/RouteReflectorClusterID", "244.0.0.1")
		t.Cleanup(func() {
			utils.RemoveNodeAnnotation(t, "kind-control-plane", "projectcalico.org/RouteReflectorClusterID")
		})

		peerWithRR := &v3.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: "peer-with-rr"},
			Spec: v3.BGPPeerSpec{
				NodeSelector:   "all()",
				PeerSelector:   "kubernetes.io/hostname == 'kind-control-plane'",
				NextHopMode:    ptr.To(v3.NextHopMode("Self")),
				ReversePeering: ptr.To(v3.ReversePeeringManual),
				Filters:        []string{"export-child-cluster-cidr"},
			},
		}
		peerFromRR := &v3.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: "peer-from-rr"},
			Spec: v3.BGPPeerSpec{
				PeerSelector:   "all()",
				NodeSelector:   "kubernetes.io/hostname == 'kind-control-plane'",
				ReversePeering: ptr.To(v3.ReversePeeringManual),
				Filters:        []string{"export-child-cluster-cidr"},
			},
		}
		rrTorPeer := &v3.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: "rr-tor-peer"},
			Spec: v3.BGPPeerSpec{
				NodeSelector: "kubernetes.io/hostname == 'kind-control-plane'",
				PeerIP:       externalNodeIP,
				ASNumber:     asn(63000),
				NextHopMode:  ptr.To(v3.NextHopMode("Keep")),
				Filters:      []string{"export-child-cluster-cidr"},
			},
		}
		for _, p := range []*v3.BGPPeer{peerWithRR, peerFromRR, rrTorPeer} {
			createV3(t, cli, p)
			t.Cleanup(func() { deleteV3(t, cli, p) })
		}
	}

	// Create four workload pods: red & blue on each of the first two workers.
	workloads := []localBGPWorkload{
		{pod: newWorkloadPod(t, ns, "red-pod-0-0", nodes[1], "red"), blockV4: "10.123.0.0/26", blockV6: "ca11:c0::/96"},
		{pod: newWorkloadPod(t, ns, "red-pod-1-0", nodes[2], "red"), blockV4: "10.123.1.0/26", blockV6: "ca11:c0:1::/96"},
		{pod: newWorkloadPod(t, ns, "blue-pod-0-0", nodes[1], "blue"), blockV4: "10.123.2.0/26", blockV6: "ca11:c0:2::/96"},
		{pod: newWorkloadPod(t, ns, "blue-pod-1-0", nodes[2], "blue"), blockV4: "10.123.3.0/26", blockV6: "ca11:c0:3::/96"},
	}
	for _, w := range workloads {
		w.pod.WaitReady()
		setupWorkloadBird(t, w.pod, w.blockV4, w.pod.IP(), "169.254.0.179", false)
		setupWorkloadBird(t, w.pod, w.blockV6, w.pod.IPv6(), "fd12:3456:789a::1", true)
	}

	// Define local workload peering IPs and disable the node-to-node mesh.
	bgpConfig := &v3.BGPConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v3.BGPConfigurationSpec{
			LocalWorkloadPeeringIPV4: "169.254.0.179",
			LocalWorkloadPeeringIPV6: "fd12:3456:789a::1",
			NodeToNodeMeshEnabled:    ptr.To(false),
			ASNumber:                 ptr.To(asn(64512)),
		},
	}
	createV3(t, cli, bgpConfig)
	t.Cleanup(func() { deleteV3(t, cli, bgpConfig) })

	// Filters for the local peerings: accept child routes, never export the
	// parent's routes down to the children (they already have a default route).
	acceptChild := &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "accept-pod-cidr-child-cluster"},
		Spec: v3.BGPFilterSpec{
			ImportV4: []v3.BGPFilterRuleV4{{Action: v3.Accept, MatchOperator: v3.MatchOperatorIn, CIDR: "10.123.0.0/16"}},
			ImportV6: []v3.BGPFilterRuleV6{{Action: v3.Accept, MatchOperator: v3.MatchOperatorIn, CIDR: "ca11:c0::/32"}},
		},
	}
	noExport := &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "no-export-from-parent-cluster"},
		Spec: v3.BGPFilterSpec{
			ExportV4: []v3.BGPFilterRuleV4{{Action: v3.Reject}},
			ExportV6: []v3.BGPFilterRuleV6{{Action: v3.Reject}},
		},
	}
	createV3(t, cli, acceptChild)
	t.Cleanup(func() { deleteV3(t, cli, acceptChild) })
	createV3(t, cli, noExport)
	t.Cleanup(func() { deleteV3(t, cli, noExport) })

	// Local peerings: a global peer selecting red pods, and a node-specific
	// peer selecting the blue pod on kind-worker2.
	globalPeer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "global-peer"},
		Spec: v3.BGPPeerSpec{
			LocalWorkloadSelector: "color == 'red'",
			ASNumber:              asn(65401),
			Filters:               []string{"no-export-from-parent-cluster", "accept-pod-cidr-child-cluster"},
		},
	}
	nodePeer := &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "node-peer"},
		Spec: v3.BGPPeerSpec{
			NodeSelector:          "kubernetes.io/hostname == 'kind-worker2'",
			LocalWorkloadSelector: "color == 'blue'",
			ASNumber:              asn(65401),
			Filters:               []string{"no-export-from-parent-cluster", "accept-pod-cidr-child-cluster"},
		},
	}
	createV3(t, cli, globalPeer)
	t.Cleanup(func() { deleteV3(t, cli, globalPeer) })
	createV3(t, cli, nodePeer)
	t.Cleanup(func() { deleteV3(t, cli, nodePeer) })

	assertLocalBGPPeers(t, g, topology, nodes, ips, workloads)
}

// assertLocalBGPPeers ports _test_local_bgp_peers.
func assertLocalBGPPeers(t *testing.T, g *WithT, topology string, nodes, ips []string, w []localBGPWorkload) {
	redPod00, redPod10, bluePod00, bluePod10 := w[0].pod, w[1].pod, w[2].pod, w[3].pod

	// red pods (worker1 + worker2) and the blue pod on worker2 peer; the blue
	// pod on worker1 must not (no node-specific peer selects it there).
	g.Eventually(func() error { return workloadBGPEstablished(t, redPod00, true) }, "90s", "3s").Should(Succeed())
	g.Eventually(func() error { return workloadBGPEstablished(t, redPod10, true) }, "90s", "3s").Should(Succeed())
	g.Expect(workloadBGPEstablished(t, bluePod00, false)).To(Succeed(), "blue pod on worker1 should not peer")
	g.Eventually(func() error { return workloadBGPEstablished(t, bluePod10, true) }, "90s", "3s").Should(Succeed())

	// Export filter: children get only a default route, not the parent's pod CIDRs.
	out := redPod00.Execute("birdcl show route")
	g.Expect(out).To(MatchRegexp(`0\.0\.0\.0.*via 169.254.1.1`))
	g.Expect(out).NotTo(MatchRegexp(`192\.168\.\d+\.\d+/26`), "unexpected route to parent cluster")

	// Import filter: the host calico-node learns the child routes via local workload peering.
	w1 := utils.CalicoNodePodName(t, redPod00.NodeName())
	g.Eventually(func() error {
		return calicoNodeBirdRoute(t, w1, false, `10\.123\.0\.0/26.*via .* on cali.*Local_Workload_.*AS65401`)
	}, "60s", "3s").Should(Succeed())
	g.Eventually(func() error {
		return calicoNodeBirdRoute(t, w1, true, `ca11:c0::/96.*via .* on cali.*Local_Workload_.*AS65401`)
	}, "60s", "3s").Should(Succeed())

	// worker2 hosts two children (one red, one blue), so it has two routes each family.
	w2 := utils.CalicoNodePodName(t, redPod10.NodeName())
	g.Eventually(func() error {
		return calicoNodeBirdRoute(t, w2, false, `10\.123\.1\.0/26.*via .* on cali.*Local_Workload_.*AS65401`)
	}, "60s", "3s").Should(Succeed())
	g.Eventually(func() error {
		return calicoNodeBirdRoute(t, w2, false, `10\.123\.3\.0/26.*via .* on cali.*Local_Workload_.*AS65401`)
	}, "60s", "3s").Should(Succeed())
	g.Eventually(func() error {
		return calicoNodeBirdRoute(t, w2, true, `ca11:c0:1::/96.*via .* on cali.*Local_Workload_.*AS65401`)
	}, "60s", "3s").Should(Succeed())
	g.Eventually(func() error {
		return calicoNodeBirdRoute(t, w2, true, `ca11:c0:3::/96.*via .* on cali.*Local_Workload_.*AS65401`)
	}, "60s", "3s").Should(Succeed())

	if topology == "mesh" {
		// The ToR hears all the child routes via the node-to-node mesh peerings.
		g.Eventually(func() error {
			out := utils.MustRun(t, "docker exec kind-node-tor birdcl show route")
			return allMatch(out,
				fmt.Sprintf(`10\.123\.0\.0/26.*via %s on .*Mesh_with_node_1.*AS65401`, regexp.QuoteMeta(ips[1])),
				fmt.Sprintf(`10\.123\.1\.0/26.*via %s on .*Mesh_with_node_2.*AS65401`, regexp.QuoteMeta(ips[2])),
				fmt.Sprintf(`10\.123\.3\.0/26.*via %s on .*Mesh_with_node_2.*AS65401`, regexp.QuoteMeta(ips[2])),
			)
		}, "60s", "3s").Should(Succeed())
	} else {
		// kind-worker3 hears all child routes reflected from the RR, with the
		// original next hop preserved.
		w3 := utils.CalicoNodePodName(t, nodes[3])
		g.Eventually(func() error {
			out, err := utils.ExecInPod(t, "calico-system", w3, "birdcl show route", utils.RunOptions{AllowFail: true, SuppressErrLog: true})
			if err != nil {
				return err
			}
			return allMatch(out,
				fmt.Sprintf(`10\.123\.0\.0/26.*via %s on .*Node_.*AS65401`, regexp.QuoteMeta(ips[1])),
				fmt.Sprintf(`10\.123\.1\.0/26.*via %s on .*Node_.*AS65401`, regexp.QuoteMeta(ips[2])),
				fmt.Sprintf(`10\.123\.3\.0/26.*via %s on .*Node_.*AS65401`, regexp.QuoteMeta(ips[2])),
			)
		}, "60s", "3s").Should(Succeed())

		// The ToR hears all child routes reflected from the RR (next hop kept).
		g.Eventually(func() error {
			out := utils.MustRun(t, "docker exec kind-node-tor birdcl show route")
			return allMatch(out,
				fmt.Sprintf(`10\.123\.0\.0/26.*via %s on .*RR_with_master_node.*AS65401`, regexp.QuoteMeta(ips[1])),
				fmt.Sprintf(`10\.123\.1\.0/26.*via %s on .*RR_with_master_node.*AS65401`, regexp.QuoteMeta(ips[2])),
				fmt.Sprintf(`10\.123\.3\.0/26.*via %s on .*RR_with_master_node.*AS65401`, regexp.QuoteMeta(ips[2])),
			)
		}, "60s", "3s").Should(Succeed())
	}

	// Connectivity from the ToR to a workload's loopback address proves the
	// advertised route is usable.
	redPod00.Execute("ip addr add 10.123.0.1 dev lo")
	g.Eventually(func() error {
		out, err := utils.Run(t, "docker exec kind-node-tor ping -c3 10.123.0.1", utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		if err != nil {
			return err
		}
		if !regexp.MustCompile(`3 packets transmitted, 3 packets received`).MatchString(out) {
			return fmt.Errorf("ping did not report 3/3 received: %s", out)
		}
		return nil
	}, "60s", "3s").Should(Succeed())
}

// newWorkloadPod creates a privileged BIRD workload pod on the given node.
func newWorkloadPod(t *testing.T, ns, name, node, color string) *utils.Pod {
	t.Helper()
	pod := utils.NewPod(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"color": color}},
		Spec: corev1.PodSpec{
			NodeName:                      node,
			TerminationGracePeriodSeconds: ptr.To(int64(0)),
			Containers: []corev1.Container{{
				Name:            "bird",
				Image:           workloadBirdImage,
				SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)},
			}},
		},
	})
	t.Cleanup(pod.Delete)
	return pod
}

// setupWorkloadBird renders the workload BIRD config and (re)configures it.
// For v4 it writes /etc/bird.conf; for v6 /etc/bird6.conf. routerID is always
// the pod's IPv4 address; childIP is the pod IP of the relevant family.
func setupWorkloadBird(t *testing.T, pod *utils.Pod, childBlock, childIP, localPeerIP string, ipv6 bool) {
	t.Helper()
	conf := workloadBirdConfig(pod.IP(), childBlock, childIP, localPeerIP)
	if ipv6 {
		pod.CopyInto(conf, "/etc/bird6.conf")
		pod.Execute("birdcl6 configure")
	} else {
		pod.CopyInto(conf, "/etc/bird.conf")
		pod.Execute("birdcl configure")
	}
}

// workloadBirdConfig renders get_bird_config_workload with as_number_child
// 65401 and as_number_parent 64512.
func workloadBirdConfig(routerID, childBlock, childIP, localPeerIP string) string {
	return fmt.Sprintf(`
router id %s;

function calico_cidr_filter() {
  if ( net ~ %s ) then {
    accept;
  }
}

protocol kernel {
  learn;
  persist;
  scan time 2;
  import all;
  export filter {
    calico_cidr_filter();
    reject;
  };
  graceful restart;
  merge paths on;
}

protocol device {
  debug { states };
  scan time 2;
}

protocol static {
    route %s via %s;
}

template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 65401;
  gateway recursive;
  add paths on;
  graceful restart;
  connect delay time 2;
  connect retry time 5;
  error wait time 5,30;
  import filter {
    calico_cidr_filter();
    reject;
  };
  export filter {
    calico_cidr_filter();
    reject;
  };
  ttl security off;
  multihop;
}

protocol bgp from_workload_to_local_host from bgp_template {
  neighbor %s as 64512;
}
`, routerID, childBlock, childBlock, childIP, localPeerIP)
}

// workloadBGPEstablished checks whether the workload pod's BGP session to its
// host is Established (both families), returning an error if the state does
// not match `established`. Mirrors assert_bgp_(not_)established.
func workloadBGPEstablished(t *testing.T, pod *utils.Pod, established bool) error {
	t.Helper()
	const re = `from_workload_to_local_host.*Established`
	for _, cmd := range []string{"birdcl show protocols", "birdcl6 show protocols"} {
		out, err := utils.ExecInPod(t, pod.Namespace, pod.Name, cmd, utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		if err != nil {
			return fmt.Errorf("exec %q in %s: %w", cmd, pod.Name, err)
		}
		matched := regexp.MustCompile(re).MatchString(out)
		if established && !matched {
			return fmt.Errorf("BGP not established (%s) in pod %s", cmd, pod.Name)
		}
		if !established && matched {
			return fmt.Errorf("BGP unexpectedly established (%s) in pod %s", cmd, pod.Name)
		}
	}
	return nil
}

// calicoNodeBirdRoute checks the given calico-node pod's BIRD route table
// against a regexp, returning an error if it does not match.
func calicoNodeBirdRoute(t *testing.T, calicoPod string, ipv6 bool, routeRegex string) error {
	t.Helper()
	cmd := "birdcl show route"
	if ipv6 {
		cmd = "birdcl6 show route"
	}
	out, err := utils.ExecInPod(t, "calico-system", calicoPod, cmd, utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	if err != nil {
		return err
	}
	if !regexp.MustCompile(routeRegex).MatchString(out) {
		return fmt.Errorf("route %q not found in %s output", routeRegex, cmd)
	}
	return nil
}

// allMatch returns nil only if every pattern matches text.
func allMatch(text string, patterns ...string) error {
	for _, p := range patterns {
		if !regexp.MustCompile(p).MatchString(text) {
			return fmt.Errorf("pattern %q not found", p)
		}
	}
	return nil
}
