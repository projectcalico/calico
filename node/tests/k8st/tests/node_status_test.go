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

// node_status_test.go is a kind-only system test for the CalicoNodeStatus
// resource. It creates a status object scoped to one worker node and asserts
// that Calico populates the agent (BIRD), BGP-peer and route sub-statuses to
// reflect the running node-to-node mesh.

package k8stests

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

// TestNodeMeshStatus creates a CalicoNodeStatus for the first worker node and
// verifies the agent, BGP and route sub-statuses Calico reports back. The kind
// cluster runs a four-node node-to-node mesh (control-plane + three workers),
// so the status for any one node should show three established peers in each
// family and the corresponding mesh-learned routes.
func TestNodeMeshStatus(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	// NodeInfo returns the control-plane node first, then the workers. The test
	// scopes its status to the first worker (nodes[1]) and asserts on the peers
	// formed with the other three mesh members (indices 0, 2 and 3).
	nodes, ips, ip6s := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 4),
		"node status test needs a four-node mesh (control-plane + three workers)")
	testNode := nodes[1]
	testNodeIP := ips[1]

	statusName := "node-status-0"
	status := &v3.CalicoNodeStatus{
		ObjectMeta: metav1.ObjectMeta{Name: statusName},
		Spec: v3.CalicoNodeStatusSpec{
			Node: testNode,
			Classes: []v3.NodeStatusClassType{
				v3.NodeStatusClassTypeAgent,
				v3.NodeStatusClassTypeBGP,
				v3.NodeStatusClassTypeRoutes,
			},
			UpdatePeriodSeconds: new(uint32(10)),
		},
	}
	g.Expect(cli.Create(ctx, status)).To(Succeed(), "creating CalicoNodeStatus %s", statusName)
	t.Cleanup(func() { _ = cli.Delete(context.Background(), status) })

	// Wait until Calico has populated the status and the mesh is fully
	// established for this node — the update period is 10s, so the first
	// populated snapshot may still be mid-convergence.
	var st v3.CalicoNodeStatusStatus
	g.Eventually(func() error {
		got := &v3.CalicoNodeStatus{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: statusName}, got); err != nil {
			return err
		}
		st = got.Status
		if st.Agent.BIRDV4.State != v3.BGPDaemonStateReady || st.Agent.BIRDV6.State != v3.BGPDaemonStateReady {
			return fmt.Errorf("BIRD not yet Ready (v4=%q v6=%q)", st.Agent.BIRDV4.State, st.Agent.BIRDV6.State)
		}
		if st.BGP.NumberEstablishedV4 != 3 || st.BGP.NumberEstablishedV6 != 3 {
			return fmt.Errorf("mesh not yet fully established (establishedV4=%d establishedV6=%d)",
				st.BGP.NumberEstablishedV4, st.BGP.NumberEstablishedV6)
		}
		return nil
	}, "60s", "2s").Should(Succeed(), "CalicoNodeStatus %s never reported a fully-established mesh", statusName)

	// Agent (BIRD) status: both daemons Ready, router ID equal to the node IP.
	g.Expect(st.Agent.BIRDV4.RouterID).To(Equal(testNodeIP), "birdV4 router ID")
	g.Expect(st.Agent.BIRDV6.RouterID).To(Equal(testNodeIP), "birdV6 router ID")

	// BGP session counts for a fully-converged four-node mesh.
	g.Expect(st.BGP.NumberEstablishedV4).To(Equal(3), "numberEstablishedV4")
	g.Expect(st.BGP.NumberEstablishedV6).To(Equal(3), "numberEstablishedV6")
	g.Expect(st.BGP.NumberNotEstablishedV4).To(Equal(0), "numberNotEstablishedV4")
	g.Expect(st.BGP.NumberNotEstablishedV6).To(Equal(0), "numberNotEstablishedV6")

	// Peers and routes for each of the three other mesh members. (The Python
	// original computed these subdict matches but never asserted on the result
	// — a latent no-op; this port turns them into real assertions.)
	for _, i := range []int{0, 2, 3} {
		g.Expect(hasMeshPeer(st.BGP.PeersV4, ips[i])).To(BeTrue(),
			"expected established NodeMesh IPv4 peer %s in %v", ips[i], st.BGP.PeersV4)
		g.Expect(hasMeshPeer(st.BGP.PeersV6, ip6s[i])).To(BeTrue(),
			"expected established NodeMesh IPv6 peer %s in %v", ip6s[i], st.BGP.PeersV6)

		g.Expect(hasMeshRoute(st.Routes.RoutesV4, ips[i])).To(BeTrue(),
			"expected NodeMesh-learned IPv4 route via %s in %v", ips[i], st.Routes.RoutesV4)
		g.Expect(hasMeshRoute(st.Routes.RoutesV6, ip6s[i])).To(BeTrue(),
			"expected NodeMesh-learned IPv6 route via %s in %v", ip6s[i], st.Routes.RoutesV6)
	}
}

// hasMeshPeer reports whether peers contains an established node-to-node-mesh
// session with the given peer IP.
func hasMeshPeer(peers []v3.CalicoNodePeer, peerIP string) bool {
	for _, p := range peers {
		if p.PeerIP == peerIP &&
			p.State == v3.BGPSessionStateEstablished &&
			p.Type == v3.BGPPeerTypeNodeMesh {
			return true
		}
	}
	return false
}

// hasMeshRoute reports whether routes contains a FIB route over eth0 with the
// given gateway that was learned from the node-to-node mesh.
func hasMeshRoute(routes []v3.CalicoNodeRoute, gateway string) bool {
	for _, r := range routes {
		if r.Gateway == gateway &&
			r.Interface == "eth0" &&
			r.Type == v3.RouteTypeFIB &&
			r.LearnedFrom.SourceType == v3.RouteSourceTypeNodeMesh {
			return true
		}
	}
	return false
}
