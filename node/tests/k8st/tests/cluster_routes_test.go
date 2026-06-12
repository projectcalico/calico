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

// cluster_routes_test.go is a kind-only system test asserting that cross-node
// cluster routes are programmed by the configured owner. With an IPIP-Always
// pool, the route to a remote node's IPAM block must go out tunl0 and carry the
// netlink protocol of whichever component owns in-cluster routing: Felix (proto
// 80) when ProgramClusterRoutes is Enabled, otherwise BIRD (proto 12).
//
// Ported from the former e2e test e2e/pkg/tests/networking/cluster_routes.go.

package k8stests

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

const (
	// routeOwnerPoolCIDR is the dedicated IPPool used by this test. Kept
	// separate from other pools so block-routes are easy to identify in
	// `ip route`.
	routeOwnerPoolCIDR = "203.0.113.0/24"

	// routeOwnerPoolPrefix is the substring matcher used against `ip route`
	// destinations. Any IPAM block carved out of routeOwnerPoolCIDR starts
	// with this prefix.
	routeOwnerPoolPrefix = "203.0.113."

	// routeOwnerPoolAnnotation pins a pod's IPAM assignment to our test pool.
	routeOwnerPoolAnnotation = "cni.projectcalico.org/ipv4pools"
)

// TestClusterRouteOwnership stands up a server / client pair on different nodes
// inside an IPIP-Always pool, checks cross-node pod connectivity (which must
// traverse the IPIP tunnel), then asserts that the client node's route to the
// server's block is owned by the configured cluster-route owner via tunl0.
func TestClusterRouteOwnership(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	// Need at least two workers so the server and client land on different
	// nodes — otherwise there is no cross-node route to inspect. NodeInfo
	// returns the control-plane node first, then workers.
	nodes, _, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 3),
		"need a control-plane node and at least two workers")
	serverNode, clientNode := nodes[1], nodes[2]

	pool := &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "route-owner-pool"},
		Spec: v3.IPPoolSpec{
			CIDR:             routeOwnerPoolCIDR,
			IPIPMode:         v3.IPIPModeAlways,
			NATOutgoing:      true,
			BlockSize:        28,
			DisableBGPExport: false,
		},
	}
	g.Expect(cli.Create(ctx, pool)).To(Succeed(), "creating IPPool")
	t.Cleanup(func() { deletePool(cli, pool.Name) })

	nsName := "cluster-routes"
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

	// Sanity-check cross-node reachability before asserting on routes: the
	// client pod must reach the server's pod IP, which crosses the IPIP tunnel.
	g.Eventually(func() error {
		_, err := utils.ExecInPod(t, nsName, client.Name,
			fmt.Sprintf("curl --silent --show-error --max-time 5 http://%s/clientip", serverIP+":80"),
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		return err
	}, "120s", "5s").Should(Succeed(),
		"client pod could not reach server pod %s across the IPIP tunnel", serverIP)

	// The client node's route to the server's block must be programmed by the
	// configured owner, out tunl0.
	assertRouteOwnership(t, g, clientNode, routeOwnerPoolPrefix, "tunl0", expectedClusterRouteProto(g, cli))
}

// routeOwnerPod builds a pod pinned to nodeName and to the test IPPool. The
// server runs an HTTP echo server; the client just idles and is curled from
// in the connectivity check.
func routeOwnerPod(namespace, name, nodeName, poolName string, server bool) *corev1.Pod {
	container := corev1.Container{Name: name, Image: utils.Agnhost}
	if server {
		container.Args = []string{"netexec", "--http-port=80"}
		container.Ports = []corev1.ContainerPort{{ContainerPort: 80}}
	} else {
		container.Args = []string{"pause"}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{routeOwnerPoolAnnotation: fmt.Sprintf("[%q]", poolName)},
		},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{container},
		},
	}
}

// ----------------------------------------------------------------------------
// Route-ownership helpers (ported from e2e/pkg/tests/networking/routes.go).

// routeProto identifies the netlink protocol that owns a kernel route. The
// numeric values match the kernel's RTPROT_* constants. Felix-programmed
// routes carry protocol 80 (felix/dataplane/linux/dataplanedefs.DefaultRouteProto);
// BIRD-programmed routes carry protocol 12 (RTPROT_BIRD).
type routeProto int

const (
	routeProtoUnknown routeProto = -1
	routeProtoBIRD    routeProto = 12
	routeProtoFelix   routeProto = 80
)

func (p routeProto) String() string {
	switch p {
	case routeProtoBIRD:
		return "bird"
	case routeProtoFelix:
		return "felix"
	case routeProtoUnknown:
		return "unknown"
	}
	return fmt.Sprintf("proto-%d", int(p))
}

// route is a parsed entry from `ip -j route show` as seen from the host
// network namespace of a calico-node pod.
type route struct {
	Dst   string
	Dev   string
	Proto routeProto
	Raw   string
}

// jsonRoute is the on-the-wire form emitted by `ip -j route show`. Protocol is
// a string in iproute2's JSON output regardless of whether the kernel proto has
// a name in /etc/iproute2/rt_protos: named protos appear as e.g. "bird";
// unnamed appear as the decimal value (e.g. "80").
type jsonRoute struct {
	Dst      string `json:"dst"`
	Dev      string `json:"dev"`
	Protocol string `json:"protocol"`
}

// getNodeRoutes returns routes from the host routing table of the calico-node
// pod running on nodeName, filtered to those whose Dst contains dstMatch.
func getNodeRoutes(t testing.TB, g *WithT, nodeName, dstMatch string) []route {
	t.Helper()
	out, err := utils.ExecInCalicoNode(t, nodeName, "ip -j route show")
	g.Expect(err).NotTo(HaveOccurred(), "running 'ip -j route show' on node %s", nodeName)
	return parseRoutes(g, out, dstMatch)
}

func parseRoutes(g *WithT, out, dstMatch string) []route {
	var parsed []jsonRoute
	g.Expect(json.Unmarshal([]byte(out), &parsed)).To(Succeed(),
		"parsing `ip -j route show` output: %s", out)
	rows := make([]route, 0, len(parsed))
	for _, jr := range parsed {
		if dstMatch != "" && !strings.Contains(jr.Dst, dstMatch) {
			continue
		}
		raw, _ := json.Marshal(jr)
		rows = append(rows, route{
			Dst:   jr.Dst,
			Dev:   jr.Dev,
			Proto: parseProto(jr.Protocol),
			Raw:   string(raw),
		})
	}
	return rows
}

func parseProto(s string) routeProto {
	switch s {
	case "":
		return routeProtoUnknown
	case "bird":
		return routeProtoBIRD
	}
	if n, err := strconv.Atoi(s); err == nil {
		return routeProto(n)
	}
	return routeProtoUnknown
}

// expectedClusterRouteProto returns the route protocol owner that the cluster
// is currently configured to use for IPIP and no-encap cluster routes.
// "Enabled" => Felix (proto 80), anything else (including unset) => BIRD's
// proto 12.
func expectedClusterRouteProto(g *WithT, cli ctrlclient.Client) routeProto {
	fc := &v3.FelixConfiguration{}
	g.Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, fc)).
		To(Succeed(), "querying default FelixConfiguration")
	if fc.Spec.ProgramClusterRoutes != nil && *fc.Spec.ProgramClusterRoutes == "Enabled" {
		return routeProtoFelix
	}
	return routeProtoBIRD
}

// assertRouteOwnership polls the kernel routing table on nodeName until at
// least one route matching dstSubstring carries the expected dev (if non-empty)
// and proto.
func assertRouteOwnership(t testing.TB, g *WithT, nodeName, dstSubstring, expectedDev string, expectedProto routeProto) {
	t.Helper()
	t.Logf("Asserting routes for %q on node %s use dev=%q proto=%s",
		dstSubstring, nodeName, expectedDev, expectedProto)
	g.Eventually(func() error {
		routes := getNodeRoutes(t, g, nodeName, dstSubstring)
		if len(routes) == 0 {
			return fmt.Errorf("no routes found containing %q on node %s", dstSubstring, nodeName)
		}
		for _, r := range routes {
			if expectedDev != "" && r.Dev != expectedDev {
				continue
			}
			if r.Proto == expectedProto {
				return nil
			}
		}
		return fmt.Errorf("no route on node %s with dev=%q proto=%s found among %v",
			nodeName, expectedDev, expectedProto, routes)
	}, "60s", "2s").Should(Succeed())
}
