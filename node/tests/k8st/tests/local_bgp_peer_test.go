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

// local_bgp_peer_test.go is a kind-only system test for "local BGP peers": BGP
// sessions between a Calico node and the workloads (pods) running on it. It
// models a parent Kubernetes cluster whose nodes peer with BIRD-running pods
// that stand in for child clusters, each advertising its own IPAM block.
//
// The topology: an external BIRD router ("kind-node-tor", the top-of-rack)
// peers with the cluster nodes, and each cluster node peers locally with the
// child-cluster pods scheduled on it (selected by localWorkloadSelector). The
// child routes flow node -> ToR and, in the route-reflector topology, via the
// in-cluster RR. The tests assert the local sessions come up only for selected
// pods, that import/export filters take effect, and that the child routes reach
// the ToR (and, for RR, the other cluster nodes) with the expected next hops.
//
// TestLocalBGPPeerMesh covers the full node-to-node-mesh topology (the Python
// TestLocalBGPPeerMesh class) and TestLocalBGPPeerRR covers the route-reflector
// topology (TestLocalBGPPeerRR). Both are 1:1 ports of
// tests/k8st/tests/test_local_bgp_peer.py.

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

// topologyMode selects the BGP topology between the cluster nodes and the ToR.
type topologyMode string

const (
	topologyRR   topologyMode = "rr"
	topologyMesh topologyMode = "mesh"
)

const (
	// torNodeName is the docker container name of the external top-of-rack BIRD
	// router the cluster nodes peer with. Matches the Python "kind-node-tor".
	torNodeName = "kind-node-tor"

	// localBGPBirdImage is the BIRD image used for the child-cluster workload
	// pods. Pinned to match the Python test.
	localBGPBirdImage = "calico/bird:v0.3.3-211-g9111ec3c"

	// localPeeringIPV4 / localPeeringIPV6 are the link-local-ish addresses the
	// node presents to its local workload peers (BGPConfiguration
	// localWorkloadPeeringIP{V4,V6}).
	localPeeringIPV4 = "169.254.0.179"
	localPeeringIPV6 = "fd12:3456:789a::1"

	// childASNumber is the AS number of the child-cluster workload peers.
	childASNumber = 65401
	// parentASNumber is the cluster (parent) AS number.
	parentASNumber = 64512
	// torASNumber is the AS number of the external ToR router.
	torASNumber = 63000

	// bgpEstablishedRegex matches an Established local-peering session in
	// `birdcl show protocols` output inside a workload pod.
	bgpEstablishedRegex = `from_workload_to_local_host.*Established`
)

// birdConfTorMeshTmpl peers the ToR with all four cluster nodes (full-mesh
// topology). The four %s are the node IPs; ip@local is substituted with the
// container's own IP by StartExternalNodeWithBGP.
const birdConfTorMeshTmpl = `
# Template for all BGP clients
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 63000;
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

// birdConfTorRRTmpl peers the ToR only with the master node (which acts as the
// route reflector). The single %s is the master node's IP.
const birdConfTorRRTmpl = `
# Template for all BGP clients
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as 63000;
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

# ------------- RR -------------
protocol bgp RR_with_master_node from bgp_template {
  neighbor %s as 64512;
  passive on;
}
`

// birdConfWorkloadTmpl is the BIRD config installed in a child-cluster workload
// pod. The %s placeholders, in order, are: router id, the accepted child CIDR
// (in the filter), the child CIDR (static route), the next hop for the static
// route, the child AS number, the local workload peering IP, and the parent AS
// number. Mirrors test_local_bgp_peer.py:get_bird_config_workload.
const birdConfWorkloadTmpl = `
router id %s;

function calico_cidr_filter() {
  if ( net ~ %s ) then {
    accept;
  }
}

# Configure synchronization between routing tables and kernel.
protocol kernel {
  learn;             # Learn all alien routes from the kernel
  persist;           # Don't remove routes on bird shutdown
  scan time 2;       # Scan kernel routing table every 2 seconds
  import all;
  export filter {
    calico_cidr_filter();
    reject;
  };
  graceful restart;  # Turn on graceful restart to reduce potential flaps in
                     # routes when reloading BIRD configuration.
  merge paths on;    # Allow export multipath routes (ECMP)
}

# Watch interface up/down events.
protocol device {
  debug { states };
  scan time 2;    # Scan interfaces every 2 seconds
}

# A static route to export to the parent cluster.
protocol static {
    route %s via %s;
}

# Template for all BGP clients
template bgp bgp_template {
  debug { states };
  description "Connection to BGP peer";
  local as %s;
  gateway recursive; # This should be the default, but just in case.
  add paths on;
  graceful restart;  # See comment in kernel section about graceful restart.
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
  neighbor %s as %s;
}
`

// workloadPod is a child-cluster BIRD pod: its name, namespace, host node and
// the IPv4/IPv6 addresses assigned to it.
type workloadPod struct {
	name  string
	ns    string
	node  string
	ipv4  string
	ipv6  string
	block workloadBlock
}

// workloadBlock is the IPv4/IPv6 IPAM block a workload pod advertises.
type workloadBlock struct {
	v4 string
	v6 string
}

// localBGPPeerEnv holds the fixture for one topology: the controller-runtime
// client, the discovered cluster nodes and IPs, the ToR's IP, the test
// namespace and the four child-cluster pods.
type localBGPPeerEnv struct {
	cli      ctrlclient.Client
	topology topologyMode
	nodes    []string
	ips      []string
	torIP    string
	ns       string

	redPod00  *workloadPod
	redPod10  *workloadPod
	bluePod00 *workloadPod
	bluePod10 *workloadPod
}

// TestLocalBGPPeerMesh exercises local BGP peering with the full node-to-node
// mesh between the cluster nodes and the ToR.
func TestLocalBGPPeerMesh(t *testing.T) {
	runLocalBGPPeerTest(t, topologyMesh)
}

// TestLocalBGPPeerRR exercises local BGP peering with the master node acting as
// an in-cluster route reflector.
func TestLocalBGPPeerRR(t *testing.T) {
	runLocalBGPPeerTest(t, topologyRR)
}

// runLocalBGPPeerTest builds the fixture for the given topology and runs the
// shared assertions. A 1:1 port of _TestLocalBGPPeer.setUp +
// _test_local_bgp_peers.
func runLocalBGPPeerTest(t *testing.T, topology topologyMode) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	cli := newClient(g)
	nodes, ips, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 4),
		"local BGP peer test needs a control-plane node and three workers")

	env := &localBGPPeerEnv{cli: cli, topology: topology, nodes: nodes, ips: ips}
	env.setup(t)
	env.runAssertions(t)
}

// ----------------------------------------------------------------------------
// Setup.

func (e *localBGPPeerEnv) setup(t *testing.T) {
	t.Helper()

	// Per-test namespace.
	e.ns = e2eutils.GenerateRandomName("bgp-test")
	utils.CreateNamespace(t, e.ns)
	t.Cleanup(func() { utils.DeleteAndConfirm(t, e.ns, "ns", "") })

	// Clean up any external node left over from a previous run, then create the
	// ToR router peered with the cluster nodes for this topology.
	utils.RemoveExternalNode(t, torNodeName)
	e.torIP = utils.StartExternalNodeWithBGP(t, torNodeName, e.torBirdConf(), "")
	t.Cleanup(func() { utils.RemoveExternalNode(t, torNodeName) })

	// Export the child-cluster CIDRs to the ToR (only routes from remote peers).
	e.applyResource(t, &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "export-child-cluster-cidr"},
		Spec: v3.BGPFilterSpec{
			ExportV4: []v3.BGPFilterRuleV4{{
				Action: v3.Accept, MatchOperator: v3.MatchOperatorIn,
				CIDR: "10.123.0.0/16", Source: v3.BGPFilterSourceRemotePeers,
			}},
			ExportV6: []v3.BGPFilterRuleV6{{
				Action: v3.Accept, MatchOperator: v3.MatchOperatorIn,
				CIDR: "ca11:c0::/32", Source: v3.BGPFilterSourceRemotePeers,
			}},
		},
	})

	switch e.topology {
	case topologyMesh:
		e.setupMeshPeering(t)
	case topologyRR:
		e.setupRRPeering(t)
	}

	// Create the four child-cluster pods. kind-worker starts at nodes[1].
	e.redPod00 = e.createWorkloadPod(t, "red-pod-0-0", e.nodes[1], "red", workloadBlock{"10.123.0.0/26", "ca11:c0::/96"})
	e.redPod10 = e.createWorkloadPod(t, "red-pod-1-0", e.nodes[2], "red", workloadBlock{"10.123.1.0/26", "ca11:c0:1::/96"})
	e.bluePod00 = e.createWorkloadPod(t, "blue-pod-0-0", e.nodes[1], "blue", workloadBlock{"10.123.2.0/26", "ca11:c0:2::/96"})
	e.bluePod10 = e.createWorkloadPod(t, "blue-pod-1-0", e.nodes[2], "blue", workloadBlock{"10.123.3.0/26", "ca11:c0:3::/96"})

	for _, p := range []*workloadPod{e.redPod00, e.redPod10, e.bluePod00, e.bluePod10} {
		e.setupWorkloadPod(t, p)
	}

	// Define the local workload peering IPs and turn off the node-to-node mesh.
	e.setDefaultBGPConfig(t, v3.BGPConfigurationSpec{
		LocalWorkloadPeeringIPV4: localPeeringIPV4,
		LocalWorkloadPeeringIPV6: localPeeringIPV6,
		NodeToNodeMeshEnabled:    new(false),
		ASNumber:                 new(numorstring.ASNumber(parentASNumber)),
	})

	// Import filters for the local peerings: accept the child CIDRs, and avoid
	// exporting parent routes to the local peers (they already have a default
	// route).
	e.applyResource(t, &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "accept-pod-cidr-child-cluster"},
		Spec: v3.BGPFilterSpec{
			ImportV4: []v3.BGPFilterRuleV4{{Action: v3.Accept, MatchOperator: v3.MatchOperatorIn, CIDR: "10.123.0.0/16"}},
			ImportV6: []v3.BGPFilterRuleV6{{Action: v3.Accept, MatchOperator: v3.MatchOperatorIn, CIDR: "ca11:c0::/32"}},
		},
	})
	e.applyResource(t, &v3.BGPFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "no-export-from-parent-cluster"},
		Spec: v3.BGPFilterSpec{
			ExportV4: []v3.BGPFilterRuleV4{{Action: v3.Reject}},
			ExportV6: []v3.BGPFilterRuleV6{{Action: v3.Reject}},
		},
	})

	localFilters := []string{"no-export-from-parent-cluster", "accept-pod-cidr-child-cluster"}

	// A global peer selecting red workloads, and a node-specific peer selecting
	// blue workloads on kind-worker2 (nodes[2]).
	e.applyResource(t, &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "global-peer"},
		Spec: v3.BGPPeerSpec{
			LocalWorkloadSelector: "color == 'red'",
			ASNumber:              numorstring.ASNumber(childASNumber),
			Filters:               localFilters,
		},
	})
	e.applyResource(t, &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "node-peer"},
		Spec: v3.BGPPeerSpec{
			NodeSelector:          fmt.Sprintf("kubernetes.io/hostname == '%s'", e.nodes[2]),
			LocalWorkloadSelector: "color == 'blue'",
			ASNumber:              numorstring.ASNumber(childASNumber),
			Filters:               localFilters,
		},
	})
}

// setupMeshPeering establishes the BGPPeer from the cluster nodes to the ToR.
func (e *localBGPPeerEnv) setupMeshPeering(t *testing.T) {
	t.Helper()
	e.applyResource(t, &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "node-tor-peer"},
		Spec: v3.BGPPeerSpec{
			PeerIP:   e.torIP,
			ASNumber: numorstring.ASNumber(torASNumber),
			Filters:  []string{"export-child-cluster-cidr"},
		},
	})
}

// setupRRPeering configures the master node as a route reflector and the
// peerings between the other nodes, the RR and the ToR.
func (e *localBGPPeerEnv) setupRRPeering(t *testing.T) {
	t.Helper()

	// Configure the master node (nodes[0]) as a route reflector.
	annotateNode(t, e.nodes[0], "projectcalico.org/RouteReflectorClusterID", "244.0.0.1")
	t.Cleanup(func() { removeNodeAnnotation(t, e.nodes[0], "projectcalico.org/RouteReflectorClusterID") })

	rrSelector := fmt.Sprintf("kubernetes.io/hostname == '%s'", e.nodes[0])

	// Other nodes peer with the RR.
	e.applyResource(t, &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-with-rr"},
		Spec: v3.BGPPeerSpec{
			NodeSelector:   "all()",
			PeerSelector:   rrSelector,
			NextHopMode:    new(v3.NextHopMode("Self")),
			ReversePeering: new(v3.ReversePeeringManual),
			Filters:        []string{"export-child-cluster-cidr"},
		},
	})

	// RR peers with the other nodes.
	e.applyResource(t, &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-from-rr"},
		Spec: v3.BGPPeerSpec{
			PeerSelector:   "all()",
			NodeSelector:   rrSelector,
			ReversePeering: new(v3.ReversePeeringManual),
			Filters:        []string{"export-child-cluster-cidr"},
		},
	})

	// RR peers with the ToR, keeping the original next hop.
	e.applyResource(t, &v3.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "rr-tor-peer"},
		Spec: v3.BGPPeerSpec{
			NodeSelector: rrSelector,
			PeerIP:       e.torIP,
			ASNumber:     numorstring.ASNumber(torASNumber),
			NextHopMode:  new(v3.NextHopMode("Keep")),
			Filters:      []string{"export-child-cluster-cidr"},
		},
	})
}

// torBirdConf returns the ToR's per-peer BIRD config for this topology.
func (e *localBGPPeerEnv) torBirdConf() string {
	switch e.topology {
	case topologyMesh:
		return fmt.Sprintf(birdConfTorMeshTmpl, e.ips[0], e.ips[1], e.ips[2], e.ips[3])
	case topologyRR:
		return fmt.Sprintf(birdConfTorRRTmpl, e.ips[0])
	}
	return ""
}

// ----------------------------------------------------------------------------
// Workload pods.

// createWorkloadPod creates a privileged BIRD pod on the given node with the
// color label, waits for it to be ready, records its IPs and registers a
// cleanup. Mirrors _TestLocalBGPPeer.create_workload_pod.
func (e *localBGPPeerEnv) createWorkloadPod(t *testing.T, name, node, color string, block workloadBlock) *workloadPod {
	t.Helper()
	g := NewWithT(t)
	cs := utils.K8sClient(t)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: e.ns,
			Labels:    map[string]string{"color": color},
		},
		Spec: corev1.PodSpec{
			NodeName:                      node,
			TerminationGracePeriodSeconds: new(int64(0)),
			Containers: []corev1.Container{{
				Name:            "bird",
				Image:           localBGPBirdImage,
				SecurityContext: &corev1.SecurityContext{Privileged: new(true)},
			}},
		},
	}
	_, err := cs.CoreV1().Pods(e.ns).Create(context.Background(), pod, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred(), "creating workload pod %s", name)
	t.Cleanup(func() { _ = cs.CoreV1().Pods(e.ns).Delete(context.Background(), name, metav1.DeleteOptions{}) })

	utils.WaitForPodReady(t, e.ns, name, 60*time.Second)

	wp := &workloadPod{name: name, ns: e.ns, node: node, block: block}
	wp.ipv4, wp.ipv6 = e.podIPs(t, name)
	return wp
}

// podIPs returns the pod's IPv4 and IPv6 addresses, waiting up to 30s for both
// to be assigned. Mirrors the Pod.ip / Pod.ipv6 properties.
func (e *localBGPPeerEnv) podIPs(t *testing.T, name string) (v4, v6 string) {
	t.Helper()
	g := NewWithT(t)
	cs := utils.K8sClient(t)
	g.Eventually(func() error {
		pod, err := cs.CoreV1().Pods(e.ns).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		v4, v6 = "", ""
		for _, ip := range pod.Status.PodIPs {
			if strings.Contains(ip.IP, ":") {
				v6 = ip.IP
			} else {
				v4 = ip.IP
			}
		}
		if v4 == "" || v6 == "" {
			return fmt.Errorf("pod %s does not yet have both IPv4 and IPv6 addresses (v4=%q v6=%q)", name, v4, v6)
		}
		return nil
	}, 30*time.Second, 100*time.Millisecond).Should(Succeed(), "waiting for pod %s IPs", name)
	return v4, v6
}

// setupWorkloadPod installs the IPv4 and IPv6 BIRD configs into the pod and
// reconfigures BIRD, mirroring setup_workload_pod_v4 / setup_workload_pod_v6.
func (e *localBGPPeerEnv) setupWorkloadPod(t *testing.T, p *workloadPod) {
	t.Helper()

	// IPv4: router id and next hop are the pod's IPv4 address; peer with the
	// local IPv4 peering IP.
	v4conf := fmt.Sprintf(birdConfWorkloadTmpl,
		p.ipv4, p.block.v4, p.block.v4, p.ipv4, fmt.Sprint(childASNumber), localPeeringIPV4, fmt.Sprint(parentASNumber))
	e.applyPodBirdConfig(t, p, "/etc/bird.conf", "birdcl", v4conf)

	// IPv6: router id is still the pod's IPv4 address, next hop is its IPv6
	// address; peer with the local IPv6 peering IP.
	v6conf := fmt.Sprintf(birdConfWorkloadTmpl,
		p.ipv4, p.block.v6, p.block.v6, p.ipv6, fmt.Sprint(childASNumber), localPeeringIPV6, fmt.Sprint(parentASNumber))
	e.applyPodBirdConfig(t, p, "/etc/bird6.conf", "birdcl6", v6conf)
}

// applyPodBirdConfig writes the BIRD config to destPath inside the pod and runs
// `<birdcl> configure`, retrying the whole write+reconfigure until BIRD accepts
// the new config.
//
// The write is fed over an exec stdin stream (the client-go equivalent of the
// Python `kubectl cp`), which occasionally delivers a truncated — empty — file
// without surfacing an error. When that happens `birdcl configure` still exits
// 0 but rejects the config ("No protocol is specified in the config file") and
// BIRD silently keeps its previous config, so the local peering session never
// comes up. Verifying that the reconfigure actually took effect, and re-writing
// when it did not, makes the setup robust against that flake.
func (e *localBGPPeerEnv) applyPodBirdConfig(t *testing.T, p *workloadPod, destPath, birdcl, content string) {
	t.Helper()
	g := NewWithT(t)
	g.Eventually(func() error {
		if _, err := utils.ExecInPodStdin(t, p.ns, p.name, content,
			[]string{"sh", "-c", "cat > " + destPath},
			utils.RunOptions{AllowFail: true, SuppressErrLog: true}); err != nil {
			return err
		}
		out, err := utils.ExecInPod(t, p.ns, p.name, birdcl+" configure",
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		if err != nil {
			return err
		}
		// BIRD echoes "Reconfiguration in progress" (or "Reconfigured") when it
		// accepts the new config, and a "<file>:<line>:<col> ..." parse error
		// when it rejects it — the latter exits 0 too, so match on the output.
		if !strings.Contains(out, "Reconfigur") {
			return fmt.Errorf("%s configure did not accept %s:\n%s", birdcl, destPath, out)
		}
		return nil
	}, 30*time.Second, time.Second).Should(Succeed(), "configuring BIRD (%s) in pod %s", destPath, p.name)
}

func (e *localBGPPeerEnv) mustExecInPod(t *testing.T, p *workloadPod, command string) string {
	t.Helper()
	g := NewWithT(t)
	out, err := utils.ExecInPod(t, p.ns, p.name, command)
	g.Expect(err).NotTo(HaveOccurred(), "exec %q in pod %s", command, p.name)
	return out
}

// ----------------------------------------------------------------------------
// Assertions.

func (e *localBGPPeerEnv) runAssertions(t *testing.T) {
	t.Helper()

	// Local sessions should come up for the selected workloads: red pods on
	// both worker nodes, and the blue pod on kind-worker2 (nodes[2]). The blue
	// pod on kind-worker (nodes[1]) is not selected by any peer.
	e.assertBGPEstablished(t, e.redPod00)
	e.assertBGPEstablished(t, e.redPod10)
	e.assertBGPNotEstablished(t, e.bluePod00)
	e.assertBGPEstablished(t, e.bluePod10)

	// The export filter keeps parent routes from the child: the child should
	// see only its default route (via 169.254.1.1) and no parent /26 blocks.
	e.assertPodRoute(t, e.redPod00, `0\.0\.0\.0.*via 169.254.1.1`, true)
	e.assertPodRoute(t, e.redPod00, `192\.168\.\d+\.\d+/26`, false)

	// The import filter accepts child routes on the hosting node's calico-node.
	w1 := e.redPod00.node
	e.assertNodeRoute(t, w1, false, `10\.123\.0\.0/26.*via .* on cali.*Local_Workload_.*AS65401`, true)
	e.assertNodeRoute(t, w1, true, `ca11:c0::/96.*via .* on cali.*Local_Workload_.*AS65401`, true)

	// kind-worker2 hosts two children, so it has two routes of each family.
	w2 := e.redPod10.node
	e.assertNodeRoute(t, w2, false, `10\.123\.1\.0/26.*via .* on cali.*Local_Workload_.*AS65401`, true)
	e.assertNodeRoute(t, w2, false, `10\.123\.3\.0/26.*via .* on cali.*Local_Workload_.*AS65401`, true)
	e.assertNodeRoute(t, w2, true, `ca11:c0:1::/96.*via .* on cali.*Local_Workload_.*AS65401`, true)
	e.assertNodeRoute(t, w2, true, `ca11:c0:3::/96.*via .* on cali.*Local_Workload_.*AS65401`, true)

	switch e.topology {
	case topologyMesh:
		// The ToR hears about all the child routes with the hosting nodes as
		// next hops.
		e.assertTorRoute(t, fmt.Sprintf(`10\.123\.0\.0/26.*via %s on .*Mesh_with_node_1.*AS65401`, regexp.QuoteMeta(e.ips[1])))
		e.assertTorRoute(t, fmt.Sprintf(`10\.123\.1\.0/26.*via %s on .*Mesh_with_node_2.*AS65401`, regexp.QuoteMeta(e.ips[2])))
		e.assertTorRoute(t, fmt.Sprintf(`10\.123\.3\.0/26.*via %s on .*Mesh_with_node_2.*AS65401`, regexp.QuoteMeta(e.ips[2])))
	case topologyRR:
		// kind-worker3 (nodes[3]) hears about all the routes from the RR with
		// their original next hops.
		w3 := e.nodes[3]
		e.assertNodeRoute(t, w3, false, fmt.Sprintf(`10\.123\.0\.0/26.*via %s on .*Node_.*AS65401`, regexp.QuoteMeta(e.ips[1])), true)
		e.assertNodeRoute(t, w3, false, fmt.Sprintf(`10\.123\.1\.0/26.*via %s on .*Node_.*AS65401`, regexp.QuoteMeta(e.ips[2])), true)
		e.assertNodeRoute(t, w3, false, fmt.Sprintf(`10\.123\.3\.0/26.*via %s on .*Node_.*AS65401`, regexp.QuoteMeta(e.ips[2])), true)

		// The ToR hears about all the routes from the RR. With nextHopMode Keep
		// on rr-tor-peer, the ToR sees the original next hops.
		e.assertTorRoute(t, fmt.Sprintf(`10\.123\.0\.0/26.*via %s on .*RR_with_master_node.*AS65401`, regexp.QuoteMeta(e.ips[1])))
		e.assertTorRoute(t, fmt.Sprintf(`10\.123\.1\.0/26.*via %s on .*RR_with_master_node.*AS65401`, regexp.QuoteMeta(e.ips[2])))
		e.assertTorRoute(t, fmt.Sprintf(`10\.123\.3\.0/26.*via %s on .*RR_with_master_node.*AS65401`, regexp.QuoteMeta(e.ips[2])))
	}

	// Connectivity from the ToR to a workload address behind the child.
	e.mustExecInPod(t, e.redPod00, "ip addr add 10.123.0.1 dev lo")
	g := NewWithT(t)
	g.Eventually(func() error {
		out, err := utils.Run(t, "docker exec "+torNodeName+" ping -c3 10.123.0.1",
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		if err != nil {
			return err
		}
		if !regexp.MustCompile("3 packets transmitted, 3 packets received").MatchString(out) {
			return fmt.Errorf("ping did not report 3/3 received:\n%s", out)
		}
		return nil
	}, 90*time.Second, time.Second).Should(Succeed(), "ToR could not ping workload 10.123.0.1")
}

// assertBGPEstablished retries until both the IPv4 and IPv6 local peering
// sessions are Established in the pod's BIRD.
func (e *localBGPPeerEnv) assertBGPEstablished(t *testing.T, p *workloadPod) {
	t.Helper()
	re := regexp.MustCompile(bgpEstablishedRegex)
	g := NewWithT(t)
	g.Eventually(func() error {
		for _, cmd := range []string{"birdcl show protocols", "birdcl6 show protocols"} {
			out, err := utils.ExecInPod(t, p.ns, p.name, cmd, utils.RunOptions{AllowFail: true, SuppressErrLog: true})
			if err != nil {
				return err
			}
			if !re.MatchString(out) {
				return fmt.Errorf("%s: session not established for pod %s:\n%s", cmd, p.name, out)
			}
		}
		return nil
	}, 90*time.Second, time.Second).Should(Succeed(), "BGP connection not established, pod %s", p.name)
}

// assertBGPNotEstablished checks that neither the IPv4 nor IPv6 local peering
// session is Established in the pod's BIRD.
func (e *localBGPPeerEnv) assertBGPNotEstablished(t *testing.T, p *workloadPod) {
	t.Helper()
	re := regexp.MustCompile(bgpEstablishedRegex)
	g := NewWithT(t)
	for _, cmd := range []string{"birdcl show protocols", "birdcl6 show protocols"} {
		out := e.mustExecInPod(t, p, cmd)
		g.Expect(re.MatchString(out)).To(BeFalse(),
			"BGP connection unexpectedly established (%s), pod %s:\n%s", cmd, p.name, out)
	}
}

// assertPodRoute retries until the pod's BIRD routing table matches (or does not
// match) pattern.
func (e *localBGPPeerEnv) assertPodRoute(t *testing.T, p *workloadPod, pattern string, want bool) {
	t.Helper()
	re := regexp.MustCompile(pattern)
	assertBirdRouteEventually(t, fmt.Sprintf("pod %s route %q", p.name, pattern), re, want, func() (string, error) {
		return utils.ExecInPod(t, p.ns, p.name, "birdcl show route", utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	})
}

// assertNodeRoute retries until the calico-node BIRD routing table on node
// matches pattern. v6 selects birdcl6 vs birdcl.
func (e *localBGPPeerEnv) assertNodeRoute(t *testing.T, node string, v6 bool, pattern string, want bool) {
	t.Helper()
	birdCmd := "birdcl"
	if v6 {
		birdCmd = "birdcl6"
	}
	re := regexp.MustCompile(pattern)
	assertBirdRouteEventually(t, fmt.Sprintf("node %s route %q", node, pattern), re, want, func() (string, error) {
		return utils.ExecInCalicoNode(t, node, birdCmd+" show route", utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	})
}

// assertTorRoute retries until the ToR's BIRD routing table matches pattern.
func (e *localBGPPeerEnv) assertTorRoute(t *testing.T, pattern string) {
	t.Helper()
	re := regexp.MustCompile(pattern)
	assertBirdRouteEventually(t, fmt.Sprintf("ToR route %q", pattern), re, true, func() (string, error) {
		return utils.Run(t, "docker exec "+torNodeName+" birdcl show route",
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	})
}

// assertBirdRouteEventually retries getOutput until re's match agrees with want.
func assertBirdRouteEventually(t *testing.T, desc string, re *regexp.Regexp, want bool, getOutput func() (string, error)) {
	t.Helper()
	g := NewWithT(t)
	g.Eventually(func() error {
		out, err := getOutput()
		if err != nil {
			return err
		}
		matched := re.MatchString(out)
		if want && !matched {
			return fmt.Errorf("%s: pattern not found in:\n%s", desc, out)
		}
		if !want && matched {
			return fmt.Errorf("%s: pattern unexpectedly found in:\n%s", desc, out)
		}
		return nil
	}, 90*time.Second, time.Second).Should(Succeed(), desc)
}

// ----------------------------------------------------------------------------
// Resource / node helpers.

// applyResource creates a cluster-scoped resource and registers a cleanup that
// deletes it.
func (e *localBGPPeerEnv) applyResource(t *testing.T, obj ctrlclient.Object) {
	t.Helper()
	g := NewWithT(t)
	g.Expect(e.cli.Create(context.Background(), obj)).To(Succeed(),
		"creating %T %s", obj, obj.GetName())
	t.Cleanup(func() { _ = e.cli.Delete(context.Background(), obj) })
}

// setDefaultBGPConfig upserts the default BGPConfiguration with the given spec
// and registers a cleanup that deletes it. Mirrors the Python which applies then
// deletes the default BGPConfiguration.
func (e *localBGPPeerEnv) setDefaultBGPConfig(t *testing.T, spec v3.BGPConfigurationSpec) {
	t.Helper()
	g := NewWithT(t)
	ctx := context.Background()

	cfg := &v3.BGPConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	err := e.cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, cfg)
	if err == nil {
		cfg.Spec = spec
		g.Expect(e.cli.Update(ctx, cfg)).To(Succeed(), "updating default BGPConfiguration")
	} else {
		cfg = &v3.BGPConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: spec}
		g.Expect(e.cli.Create(ctx, cfg)).To(Succeed(), "creating default BGPConfiguration")
	}
	t.Cleanup(func() {
		_ = e.cli.Delete(context.Background(), &v3.BGPConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}})
	})
}

// annotateNode sets an annotation on a node (overwriting any existing value).
func annotateNode(t *testing.T, node, key, value string) {
	t.Helper()
	g := NewWithT(t)
	cs := utils.K8sClient(t)
	g.Eventually(func() error {
		n, err := cs.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if n.Annotations == nil {
			n.Annotations = map[string]string{}
		}
		n.Annotations[key] = value
		_, err = cs.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
		return err
	}, 30*time.Second, time.Second).Should(Succeed(), "annotating node %s %s=%s", node, key, value)
}

// removeNodeAnnotation deletes an annotation from a node. Used in cleanup, so it
// reports rather than fatally fails.
func removeNodeAnnotation(t *testing.T, node, key string) {
	t.Helper()
	cs := utils.K8sClient(t)
	g := NewGomega(func(message string, _ ...int) { t.Errorf("%s", message) })
	g.Eventually(func() error {
		n, err := cs.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
		if err != nil {
			return err
		}
		delete(n.Annotations, key)
		_, err = cs.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
		return err
	}, 30*time.Second, time.Second).Should(Succeed(), "removing annotation %s from node %s", key, node)
}
