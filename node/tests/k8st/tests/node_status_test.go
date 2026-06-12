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

// node_status_test.go is the Go port of test_node_status.py. It creates a
// CalicoNodeStatus for one worker node and asserts that Calico populates the
// node's agent (BIRD), BGP-peer and route status for both IP families in a
// node-to-node mesh.

package k8stests

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

// TestNodeMeshStatus verifies dual-stack CalicoNodeStatus reporting on a
// node-to-node mesh cluster. Port of
// test_node_status.py:TestNodeMeshStatus.test_dual_stack_status.
func TestNodeMeshStatus(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	// nodes[0] is the control plane; nodes[1..3] are workers. We report status
	// for the first worker and expect it to peer with all three other nodes.
	nodes, ips, ip6s := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 4), "need a control-plane node and three workers")

	testNode := nodes[1]
	testNodeIP := ips[1]

	const statusName = "node-status-0"
	status := &v3.CalicoNodeStatus{
		ObjectMeta: metav1.ObjectMeta{Name: statusName},
		Spec: v3.CalicoNodeStatusSpec{
			Node: testNode,
			Classes: []v3.NodeStatusClassType{
				v3.NodeStatusClassTypeAgent,
				v3.NodeStatusClassTypeBGP,
				v3.NodeStatusClassTypeRoutes,
			},
			UpdatePeriodSeconds: ptr.To(uint32(10)),
		},
	}
	g.Expect(cli.Create(ctx, status)).To(Succeed(), "creating CalicoNodeStatus")
	t.Cleanup(func() {
		_ = cli.Delete(context.Background(), &v3.CalicoNodeStatus{ObjectMeta: metav1.ObjectMeta{Name: statusName}})
	})

	// The other nodes this worker peers with in the mesh.
	peerIdxs := []int{0, 2, 3}

	g.Eventually(func() error {
		got := &v3.CalicoNodeStatus{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: statusName}, got); err != nil {
			return err
		}
		s := got.Status

		// Agent (BIRD) status. Both bird4 and bird6 report the node's IPv4
		// address as their router ID.
		if s.Agent.BIRDV4.State != v3.BGPDaemonStateReady || s.Agent.BIRDV4.RouterID != testNodeIP {
			return fmt.Errorf("birdV4 not ready with routerID %s: %+v", testNodeIP, s.Agent.BIRDV4)
		}
		if s.Agent.BIRDV6.State != v3.BGPDaemonStateReady || s.Agent.BIRDV6.RouterID != testNodeIP {
			return fmt.Errorf("birdV6 not ready with routerID %s: %+v", testNodeIP, s.Agent.BIRDV6)
		}

		// BGP session counts.
		if s.BGP.NumberEstablishedV4 != 3 || s.BGP.NumberEstablishedV6 != 3 ||
			s.BGP.NumberNotEstablishedV4 != 0 || s.BGP.NumberNotEstablishedV6 != 0 {
			return fmt.Errorf("unexpected BGP session counts: %+v", s.BGP)
		}

		// Per-peer and per-route status for each of the other mesh nodes.
		for _, i := range peerIdxs {
			if !hasEstablishedNodeMeshPeer(s.BGP.PeersV4, ips[i]) {
				return fmt.Errorf("no established NodeMesh IPv4 peer %s in %+v", ips[i], s.BGP.PeersV4)
			}
			if !hasEstablishedNodeMeshPeer(s.BGP.PeersV6, ip6s[i]) {
				return fmt.Errorf("no established NodeMesh IPv6 peer %s in %+v", ip6s[i], s.BGP.PeersV6)
			}
			if !hasNodeMeshRoute(s.Routes.RoutesV4, ips[i]) {
				return fmt.Errorf("no NodeMesh IPv4 route via %s in %+v", ips[i], s.Routes.RoutesV4)
			}
			if !hasNodeMeshRoute(s.Routes.RoutesV6, ip6s[i]) {
				return fmt.Errorf("no NodeMesh IPv6 route via %s in %+v", ip6s[i], s.Routes.RoutesV6)
			}
		}
		return nil
	}, "60s", "5s").Should(Succeed(), "CalicoNodeStatus never reported the expected mesh state")
}

// hasEstablishedNodeMeshPeer reports whether peers contains an Established
// node-to-node-mesh peering with the given peer IP.
func hasEstablishedNodeMeshPeer(peers []v3.CalicoNodePeer, peerIP string) bool {
	for _, p := range peers {
		if p.PeerIP == peerIP && p.State == v3.BGPSessionStateEstablished && p.Type == v3.BGPPeerTypeNodeMesh {
			return true
		}
	}
	return false
}

// hasNodeMeshRoute reports whether routes contains a FIB route over eth0 whose
// gateway is the given IP and that was learned from the node-to-node mesh.
func hasNodeMeshRoute(routes []v3.CalicoNodeRoute, gateway string) bool {
	for _, r := range routes {
		if r.Gateway == gateway && r.Interface == "eth0" && r.Type == v3.RouteTypeFIB &&
			r.LearnedFrom.SourceType == v3.RouteSourceTypeNodeMesh {
			return true
		}
	}
	return false
}
