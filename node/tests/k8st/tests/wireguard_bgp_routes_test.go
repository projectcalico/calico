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

// wireguard_bgp_routes_test.go is a kind-only system test for the WireGuard BGP
// peer filter. With WireGuard enabled in a no-encap pool, BIRD must not install
// kernel routes to a WireGuard peer's block - Felix routes that traffic over
// the WireGuard device instead. kind nodes share an L2 segment, so without the
// filter BIRD would install (and win) the route; the test asserts BIRD is
// suppressed while cross-node pod connectivity still works over WireGuard.

package k8stests

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	e2eutils "github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

const (
	// wgBGPPoolCIDR is a dedicated no-encap IPPool for this test, kept separate
	// so its block routes are easy to match in `ip route`.
	wgBGPPoolCIDR = "203.0.114.0/24"

	// wgBGPPoolPrefix matches any IPAM block carved out of wgBGPPoolCIDR.
	wgBGPPoolPrefix = "203.0.114."
)

// TestWireguardBGPRouteSuppression enables WireGuard cluster-wide in a no-encap
// pool, then asserts that the client node's kernel route to the server's block
// is not owned by BIRD (the WireGuard peer filter suppresses it) while the
// server pod stays reachable across nodes over the WireGuard device.
func TestWireguardBGPRouteSuppression(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	// Need two workers so the server and client land on different nodes -
	// otherwise there is no cross-node route to inspect. NodeInfo returns the
	// control-plane node first, then workers.
	nodes, _, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 3),
		"need a control-plane node and at least two workers")
	serverNode, clientNode := nodes[1], nodes[2]

	// With every node running WireGuard, each node's BIRD rejects kernel routes
	// to its peers' blocks and lets Felix route them over wireguard.cali.
	t.Cleanup(setWireguardEnabled(ctx, g, cli, true))

	// The peer filter only targets no-encap BGP routes; VXLAN and IPIP routes
	// are already suppressed by their own tunnel-route filters.
	pool := &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "wireguard-bgp-pool"},
		Spec: v3.IPPoolSpec{
			CIDR:        wgBGPPoolCIDR,
			IPIPMode:    v3.IPIPModeNever,
			VXLANMode:   v3.VXLANModeNever,
			NATOutgoing: true,
			BlockSize:   26,
		},
	}
	g.Expect(cli.Create(ctx, pool)).To(Succeed(), "creating IPPool")
	t.Cleanup(func() { deletePool(t, cli, pool.Name) })

	// WireGuard has to actually come up, otherwise the filter never engages.
	waitForWireguardDevice(t, g, serverNode)
	waitForWireguardDevice(t, g, clientNode)

	nsName := e2eutils.GenerateRandomName("wireguard-bgp")
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName}}
	g.Expect(cli.Create(ctx, ns)).To(Succeed(), "creating namespace")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), ns) })

	server := routeOwnerPod(nsName, "server", serverNode, pool.Name, true)
	g.Expect(cli.Create(ctx, server)).To(Succeed(), "creating server pod")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), server) })

	client := routeOwnerPod(nsName, "client", clientNode, pool.Name, false)
	g.Expect(cli.Create(ctx, client)).To(Succeed(), "creating client pod")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), client) })

	serverIP := waitForPodIP(ctx, g, cli, server, corev1.IPv4Protocol)
	t.Logf("Server pod %s/%s scheduled on %s with IP %s", nsName, server.Name, serverNode, serverIP)
	waitForPodIP(ctx, g, cli, client, corev1.IPv4Protocol)

	// Cross-node pod traffic must still flow with BIRD's kernel routes
	// suppressed - Felix carries it over the WireGuard device.
	g.Eventually(func() error {
		_, err := utils.ExecInPod(t, nsName, client.Name,
			fmt.Sprintf("curl --silent --show-error --max-time 5 http://%s/clientip", serverIP+":80"),
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		return err
	}, "120s", "1s").Should(Succeed(),
		"client pod could not reach server pod %s over WireGuard", serverIP)

	// The fix itself: BIRD must not own a kernel route to the server's block on
	// the client node. Without the filter BIRD installs one (kind nodes share an
	// L2, so it would otherwise succeed) and fights Felix's WireGuard route.
	utils.AssertNoRouteWithProto(t, clientNode, wgBGPPoolPrefix, utils.RouteProtoBIRD)
}

// setWireguardEnabled flips WireguardEnabled on the default FelixConfiguration
// and returns an idempotent restore function.
func setWireguardEnabled(ctx context.Context, g *WithT, cli ctrlclient.Client, enabled bool) func() {
	cfg := &v3.FelixConfiguration{}
	g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, cfg)).
		To(Succeed(), "fetching default FelixConfiguration")

	var original *bool
	if cfg.Spec.WireguardEnabled != nil {
		v := *cfg.Spec.WireguardEnabled
		original = &v
	}

	cfg.Spec.WireguardEnabled = &enabled
	g.Expect(cli.Update(ctx, cfg)).To(Succeed(), "setting WireguardEnabled=%v", enabled)

	restored := false
	return func() {
		if restored {
			return
		}
		restored = true
		// Re-fetch and write back the original, retrying to absorb concurrent
		// updates.
		g.Eventually(func() error {
			cur := &v3.FelixConfiguration{}
			rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer rcancel()
			if err := cli.Get(rctx, ctrlclient.ObjectKey{Name: "default"}, cur); err != nil {
				return err
			}
			cur.Spec.WireguardEnabled = original
			return cli.Update(rctx, cur)
		}, "20s", "1s").Should(Succeed(), "restoring original WireguardEnabled")
	}
}

// waitForWireguardDevice waits for wireguard.cali to appear in the calico-node
// host namespace on nodeName. A missing interface usually means the node's
// kernel lacks the wireguard module, so fail loudly rather than skip.
func waitForWireguardDevice(t testing.TB, g *WithT, nodeName string) {
	t.Helper()
	g.Eventually(func() error {
		_, err := utils.ExecInCalicoNode(t, nodeName, "ip link show wireguard.cali",
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		return err
	}, "120s", "2s").Should(Succeed(),
		"wireguard.cali never appeared on node %s - is the wireguard kernel module available?", nodeName)
}
