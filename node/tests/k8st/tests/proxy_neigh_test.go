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

// proxy_neigh_test.go is a kind-only system test for Felix's
// LocalSubnetL2Reachability feature (proxy ARP/NDP). It verifies that an
// L2-adjacent client outside the cluster can reach a pod IP or LoadBalancer VIP
// that lives in the host's L2 subnet — which only works if Felix answers the
// ARP (IPv4) / NDP (IPv6) request on behalf of the hosting/owning node.
//
// Topology (all on the "kind" docker network, sharing one L2 segment):
//
//	+------+  +------+  +------+   +-----------------+
//	| node |  | node |  | node |  | extL2 peer (us) |
//	+------+  +------+  +------+   +-----------------+
//	   pod IP / LB VIP from host-subnet pools                    curl

package k8stests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

const (
	// kindNetworkName is the docker network kind attaches its nodes to.
	kindNetworkName = "kind"

	// CIDRs carved out of the kind network for the two test pools. We use the
	// high end of the kind range so we don't collide with docker-assigned node
	// addresses (which start at .0.2). Pools must be >= Calico's default block
	// size (/26 IPv4, /122 IPv6).
	v4WorkloadOffset = "0.0.255.0/26"     // 64 addresses
	v4LBOffset       = "0.0.255.64/26"    // 64 addresses
	v6WorkloadSuffix = "::ff00:0:0:0/122" // 64 addresses
	v6LBSuffix       = "::ff40:0:0:0/122" // 64 addresses
)

// TestProxyNeigh runs the proxy ARP (IPv4) and proxy NDP (IPv6) scenarios. Each
// family gets its own host-subnet pools, an L2-adjacent peer, a backend pod and
// a LoadBalancer service, then probes the pod IP and the VIP from the peer.
func TestProxyNeigh(t *testing.T) {
	for _, family := range []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol} {
		t.Run(string(family), func(t *testing.T) {
			runFamily(t, family)
		})
	}
}

func runFamily(t *testing.T, family corev1.IPFamily) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	// The cluster's nodes (and our L2 peer) sit on kind's docker network; derive
	// the two pool CIDRs from its subnet for this family.
	v4Net, v6Net, err := detectKindNetworkSubnets(t, kindNetworkName)
	g.Expect(err).NotTo(HaveOccurred(), "detecting docker network subnets")

	var workloadCIDR, lbCIDR, poolAnnotation, lbPoolAnnotation string
	if family == corev1.IPv4Protocol {
		g.Expect(v4Net).NotTo(BeNil(), "kind network has no IPv4 subnet")
		workloadCIDR, err = v4SubnetOffset(v4Net, v4WorkloadOffset)
		g.Expect(err).NotTo(HaveOccurred(), "deriving workload v4 CIDR")
		lbCIDR, err = v4SubnetOffset(v4Net, v4LBOffset)
		g.Expect(err).NotTo(HaveOccurred(), "deriving LB v4 CIDR")
		poolAnnotation = "cni.projectcalico.org/ipv4pools"
		lbPoolAnnotation = "projectcalico.org/ipv4pools"
	} else {
		g.Expect(v6Net).NotTo(BeNil(), "kind network has no IPv6 subnet (recreate the cluster dual-stack to run NDP tests)")
		workloadCIDR, err = v6SubnetWithSuffix(v6Net, v6WorkloadSuffix)
		g.Expect(err).NotTo(HaveOccurred(), "deriving workload v6 CIDR")
		lbCIDR, err = v6SubnetWithSuffix(v6Net, v6LBSuffix)
		g.Expect(err).NotTo(HaveOccurred(), "deriving LB v6 CIDR")
		poolAnnotation = "cni.projectcalico.org/ipv6pools"
		lbPoolAnnotation = "projectcalico.org/ipv6pools"
	}
	t.Logf("Test pool CIDRs (%s): workload=%s LB=%s", family, workloadCIDR, lbCIDR)

	suffix := strings.ToLower(string(family))
	nsName := "proxy-neigh-" + suffix

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName}}
	g.Expect(cli.Create(ctx, ns)).To(Succeed(), "creating namespace")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), ns) })

	// Manual assignment mode keeps these host-subnet IPs from being auto-assigned
	// to other pods on the cluster; the server pod requests this pool explicitly
	// below via the cni.projectcalico.org/ipv4pools annotation.
	workloadPool := &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy-neigh-wl-" + suffix},
		Spec: v3.IPPoolSpec{
			CIDR:           workloadCIDR,
			IPIPMode:       v3.IPIPModeNever,
			VXLANMode:      v3.VXLANModeNever,
			AssignmentMode: new(v3.Manual),
			AllowedUses:    []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload},
		},
	}
	g.Expect(cli.Create(ctx, workloadPool)).To(Succeed(), "creating workload IPPool")
	t.Cleanup(func() { deletePool(t, cli, workloadPool.Name) })

	lbPool := &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "proxy-neigh-lb-" + suffix},
		Spec: v3.IPPoolSpec{
			CIDR:           lbCIDR,
			IPIPMode:       v3.IPIPModeNever,
			VXLANMode:      v3.VXLANModeNever,
			AssignmentMode: new(v3.Manual),
			AllowedUses:    []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer},
		},
	}
	g.Expect(cli.Create(ctx, lbPool)).To(Succeed(), "creating LoadBalancer IPPool")
	t.Cleanup(func() { deletePool(t, cli, lbPool.Name) })

	// Turn on the feature under test, restoring the original value afterwards.
	restore := setLocalSubnetL2Reachability(ctx, g, cli, v3.LocalSubnetL2ReachabilityPodsAndLoadBalancers)
	t.Cleanup(restore)

	// Spawn the L2-adjacent peer on the kind network.
	peer, err := newExtL2Peer(t, "proxy-neigh-extl2-"+suffix, kindNetworkName)
	g.Expect(err).NotTo(HaveOccurred(), "spawning L2 peer")
	t.Cleanup(func() { _ = peer.Close() })

	// Deploy an echo server pinned to the workload pool, plus a LoadBalancer
	// service in front of it.
	appLabels := map[string]string{"app": "proxy-neigh-" + suffix}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "proxy-neigh-server",
			Namespace:   nsName,
			Labels:      appLabels,
			Annotations: map[string]string{poolAnnotation: fmt.Sprintf("[%q]", workloadPool.Name)},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "echo",
				Image: utils.Agnhost,
				Args:  []string{"netexec", "--http-port=80"},
				Ports: []corev1.ContainerPort{{ContainerPort: 80}},
			}},
		},
	}
	g.Expect(cli.Create(ctx, pod)).To(Succeed(), "creating server pod")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), pod) })

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-neigh-lb",
			Namespace: nsName,
			// Pin LB-IPAM to our kind-L2-subnet pool (by name). Without this the
			// cluster's pre-existing LoadBalancer pool — which sits off the kind
			// subnet (e.g. 80.15.0.0/24) and is advertised by other means — can
			// win the allocation, leaving the VIP not L2-adjacent to the peer and
			// the proxy-ARP/NDP behaviour untestable.
			Annotations: map[string]string{lbPoolAnnotation: fmt.Sprintf("[%q]", lbPool.Name)},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			Selector:          appLabels,
			Ports:             []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(80)}},
			IPFamilies:        []corev1.IPFamily{family},
			IPFamilyPolicy:    new(corev1.IPFamilyPolicySingleStack),
			LoadBalancerClass: new("calico"),
		},
	}
	g.Expect(cli.Create(ctx, svc)).To(Succeed(), "creating LoadBalancer service")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), svc) })

	podIP := waitForPodIP(ctx, g, cli, pod, family)
	t.Logf("Server pod %s/%s has %s IP %s", nsName, pod.Name, family, podIP)
	vip := waitForLBVIP(ctx, g, cli, svc)
	t.Logf("Service %s/%s allocated %s VIP %s", nsName, svc.Name, family, vip)

	// A pod that lives on the host subnet must be reachable from the L2-adjacent
	// peer even though the peer has no route to the pod IP — the only way it
	// succeeds is if Felix answers the ARP/NDP request for the hosting node.
	t.Run("pod_ip", func(t *testing.T) {
		probe(NewWithT(t), peer, podIP)
	})

	// LoadBalancer VIPs take the same path, except the manager hash-picks a
	// single node to answer for each VIP. We assert only that *some* node
	// answers and traffic flows, not which one.
	t.Run("lb_vip", func(t *testing.T) {
		probe(NewWithT(t), peer, vip)
	})
}

// probe confirms the L2-adjacent peer can reach ip over HTTP. The peer has no
// route to ip, so the connection only succeeds if Felix answered the ARP (v4) /
// Neighbor Solicitation (v6) for it and then routed the traffic.
func probe(g *WithT, peer *extL2Peer, ip string) {
	g.Eventually(func() error {
		_, err := peer.Curl(httpURL(ip))
		return err
	}, "60s", "2s").Should(Succeed(), "HTTP request to %s never succeeded — Felix did not answer ARP/NDP for it", ip)
}

func httpURL(ip string) string {
	return fmt.Sprintf("http://%s/clientip", net.JoinHostPort(ip, "80"))
}

// --- Cluster client + resource helpers ---

// newClient builds a controller-runtime client for k8s core, projectcalico.org/v3
// and operator.tigera.io/v1 from the ambient kubeconfig
// (KUBECONFIG / ~/.kube/config / in-cluster).
func newClient(g *WithT) ctrlclient.Client {
	cfg, err := ctrlconfig.GetConfig()
	g.Expect(err).NotTo(HaveOccurred(), "loading kubeconfig")

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(v3.AddToScheme(scheme))
	utilruntime.Must(operatorv1.AddToScheme(scheme))

	cli, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: scheme})
	g.Expect(err).NotTo(HaveOccurred(), "creating controller-runtime client")
	return cli
}

// deletePool best-effort removes an IPPool; runs during cleanup so it logs
// rather than fails.
func deletePool(t testing.TB, cli ctrlclient.Client, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := &v3.IPPool{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := cli.Delete(ctx, pool); err != nil && !apierrors.IsNotFound(err) {
		t.Logf("WARNING: failed to delete IPPool %s: %v", name, err)
	}
}

// setLocalSubnetL2Reachability flips the default FelixConfiguration into the
// requested mode and returns an idempotent restore function.
func setLocalSubnetL2Reachability(ctx context.Context, g *WithT, cli ctrlclient.Client, mode v3.LocalSubnetL2ReachabilityMode) func() {
	cfg := &v3.FelixConfiguration{}
	g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, cfg)).To(Succeed(), "fetching default FelixConfiguration")

	var original *v3.LocalSubnetL2ReachabilityMode
	if cfg.Spec.LocalSubnetL2Reachability != nil {
		v := *cfg.Spec.LocalSubnetL2Reachability
		original = &v
	}

	cfg.Spec.LocalSubnetL2Reachability = new(mode)
	g.Expect(cli.Update(ctx, cfg)).To(Succeed(), "setting LocalSubnetL2Reachability=%s", mode)

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
			cur.Spec.LocalSubnetL2Reachability = original
			return cli.Update(rctx, cur)
		}, "20s", "2s").Should(Succeed(), "restoring original LocalSubnetL2Reachability")
	}
}

// waitForPodIP waits for the pod to be Running and returns its IP of the
// requested family. The pod is dual-stack, so we pick the matching family.
func waitForPodIP(ctx context.Context, g *WithT, cli ctrlclient.Client, pod *corev1.Pod, family corev1.IPFamily) string {
	wantV6 := family == corev1.IPv6Protocol
	var ip string
	g.Eventually(func() error {
		got := &corev1.Pod{}
		if err := cli.Get(ctx, ctrlclient.ObjectKeyFromObject(pod), got); err != nil {
			return err
		}
		if got.Status.Phase != corev1.PodRunning {
			return fmt.Errorf("pod %s is %s", pod.Name, got.Status.Phase)
		}
		for _, podIP := range got.Status.PodIPs {
			if parsed := net.ParseIP(podIP.IP); parsed != nil && (parsed.To4() == nil) == wantV6 {
				ip = podIP.IP
				return nil
			}
		}
		return fmt.Errorf("pod %s has no %s IP yet", pod.Name, family)
	}, "120s", "2s").Should(Succeed(), "server pod never got a %s IP", family)
	return ip
}

// waitForLBVIP waits for Calico's service-IP allocator to populate the
// LoadBalancer ingress IP. The Service is single-stack, so there's exactly one.
func waitForLBVIP(ctx context.Context, g *WithT, cli ctrlclient.Client, svc *corev1.Service) string {
	var vip string
	g.Eventually(func() error {
		got := &corev1.Service{}
		if err := cli.Get(ctx, ctrlclient.ObjectKeyFromObject(svc), got); err != nil {
			return err
		}
		ingress := got.Status.LoadBalancer.Ingress
		if len(ingress) == 0 || ingress[0].IP == "" {
			return fmt.Errorf("service %s has no LoadBalancer ingress IP yet", svc.Name)
		}
		vip = ingress[0].IP
		return nil
	}, "120s", "2s").Should(Succeed(), "Calico did not allocate a VIP for service %s", svc.Name)
	return vip
}

// --- Kind-network subnet math (carried over from the former e2e test) ---

// detectKindNetworkSubnets returns the IPv4 and IPv6 subnets configured on the
// given docker network. Either may be nil if the network lacks that family.
func detectKindNetworkSubnets(t testing.TB, networkName string) (v4, v6 *net.IPNet, err error) {
	out, err := utils.Run(t, "docker network inspect "+networkName, utils.RunOptions{AllowFail: true})
	if err != nil {
		return nil, nil, fmt.Errorf("docker network inspect %s: %w", networkName, err)
	}
	var inspected []struct {
		IPAM struct {
			Config []struct {
				Subnet string
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &inspected); err != nil {
		return nil, nil, fmt.Errorf("parsing docker network inspect output: %w", err)
	}
	if len(inspected) == 0 {
		return nil, nil, fmt.Errorf("docker network %s not found", networkName)
	}
	for _, cfg := range inspected[0].IPAM.Config {
		_, n, err := net.ParseCIDR(cfg.Subnet)
		if err != nil {
			continue
		}
		if n.IP.To4() != nil {
			v4 = n
		} else {
			v6 = n
		}
	}
	return v4, v6, nil
}

// v4SubnetOffset ORs an IPv4 offset CIDR into a parent network's address, e.g.
// v4SubnetOffset(172.18.0.0/16, "0.0.255.0/26") -> "172.18.255.0/26".
func v4SubnetOffset(parent *net.IPNet, offset string) (string, error) {
	parent4 := parent.IP.To4()
	if parent4 == nil {
		return "", fmt.Errorf("v4SubnetOffset: parent %s is not IPv4", parent)
	}
	offIP, offNet, err := net.ParseCIDR(offset)
	if err != nil {
		return "", err
	}
	off4 := offIP.To4()
	if off4 == nil {
		return "", fmt.Errorf("v4SubnetOffset: offset %s is not IPv4", offset)
	}
	out := make(net.IP, 4)
	for i := range out {
		out[i] = parent4[i] | off4[i]
	}
	maskOnes, _ := offNet.Mask.Size()
	return fmt.Sprintf("%s/%d", out, maskOnes), nil
}

// v6SubnetWithSuffix ORs an IPv6 suffix prefix (e.g. "::ff00:0:0:0/122") into
// the host bits of an IPv6 /64 parent network, yielding a sub-CIDR.
func v6SubnetWithSuffix(parent *net.IPNet, suffixCIDR string) (string, error) {
	parentAddr, ok := netip.AddrFromSlice(parent.IP.To16())
	if !ok {
		return "", fmt.Errorf("invalid parent IPv6 address %s", parent.IP)
	}
	suffix, err := netip.ParsePrefix(suffixCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid suffix %q: %w", suffixCIDR, err)
	}
	pBytes := parentAddr.As16()
	sBytes := suffix.Addr().As16()
	for i := range pBytes {
		pBytes[i] |= sBytes[i]
	}
	return fmt.Sprintf("%s/%d", netip.AddrFrom16(pBytes), suffix.Bits()), nil
}

// --- L2-adjacent docker peer (carried over from the former e2e test) ---

// extL2Peer wraps a single container on a docker bridge network — layer-2
// adjacent to the cluster nodes but not itself a cluster node — that we curl
// cluster IPs from.
type extL2Peer struct {
	t    testing.TB
	name string
}

func newExtL2Peer(t testing.TB, name, network string) (*extL2Peer, error) {
	if network == "" {
		return nil, fmt.Errorf("newExtL2Peer: network must not be empty")
	}
	allow := utils.RunOptions{AllowFail: true, SuppressErrLog: true}
	if _, err := utils.Run(t, "docker network inspect "+network, allow); err != nil {
		return nil, fmt.Errorf("docker network %q not reachable: %w", network, err)
	}
	// Best-effort cleanup of a stale container with the same name.
	_, _ = utils.Run(t, "docker rm -f "+name, allow)
	if _, err := utils.Run(t, fmt.Sprintf(
		"docker run -d --name %s --network %s --cap-add NET_RAW --cap-add NET_ADMIN %s pause",
		name, network, utils.Agnhost), utils.RunOptions{AllowFail: true}); err != nil {
		return nil, fmt.Errorf("docker run for %q failed: %w", name, err)
	}
	return &extL2Peer{t: t, name: name}, nil
}

// Close removes the container. Safe to call multiple times.
func (p *extL2Peer) Close() error {
	if p == nil || p.name == "" {
		return nil
	}
	_, err := utils.Run(p.t, "docker rm -f "+p.name, utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	p.name = ""
	return err
}

// Curl performs an HTTP GET against url with a short timeout.
func (p *extL2Peer) Curl(url string) (string, error) {
	out, err := p.exec("curl", "--silent", "--show-error", "--max-time", "5", url)
	if err != nil {
		return out, fmt.Errorf("curl %s failed: %w (output: %s)", url, err, strings.TrimSpace(out))
	}
	return out, nil
}

// exec runs a command inside the peer via `docker exec`. Unlike the rest of the
// docker plumbing (which goes through k8stutils.Run), this uses exec.Command so
// caller-supplied args — IPv6 literals, bracketed URLs — pass straight through
// as argv with no shell-quoting hazard. Returns combined stdout+stderr, which
// the caller parses for curl output.
func (p *extL2Peer) exec(argv ...string) (string, error) {
	if p == nil || p.name == "" {
		return "", fmt.Errorf("extL2Peer: container has been closed")
	}
	out, err := exec.Command("docker", append([]string{"exec", p.name}, argv...)...).CombinedOutput()
	return string(out), err
}
