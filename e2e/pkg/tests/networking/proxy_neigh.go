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

package networking

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

// proxy_neigh.go exercises the HostSubnetNeighResponses Felix feature
// (a.k.a. proxy ARP/NDP). The feature lets Felix answer ARP (IPv4) and NDP
// (IPv6) requests on host interfaces for pod IPs and LoadBalancer VIPs that
// fall within the same L2 subnet as the host's interface. Without it, an
// L2-adjacent client outside the cluster cannot reach a pod or VIP that lives
// in the host subnet because no host claims the IP at L2.
//
// Test environment requirements (see RequiresKindNetwork):
//   - The test runner has direct access to the local docker daemon.
//   - The cluster's worker nodes are attached to a docker bridge network
//     (the "kind" network) that has both IPv4 and IPv6 subnets configured.
//
// Topology:
//
//                +-------------------- kind docker network --------------------+
//                |                                                             |
//                |   +-------+     +-------+     +-------+     +-----------+   |
//                |   | node0 |     | node1 |     | node2 |     | extL2 (us)|   |
//                |   +-------+     +-------+     +-------+     +-----------+   |
//                |       ^             ^             ^               ^         |
//                |       |             |             |               |         |
//                |   pod IP from   LB VIP from        |       arping/rdisc6    |
//                |   workload pool LB pool            |       curl ...         |
//                +-------------------------------------------------------------+
//
// The extL2 container shares the L2 segment with the cluster nodes. It has no
// /32 or /128 route to the test pool, so it must ARP/NDP for any address in
// that pool — which is precisely what HostSubnetNeighResponses answers.

const (
	// CIDRs we carve out of the kind network for the two test pools. We use
	// the high end of the kind range so we don't collide with the addresses
	// docker hands out to nodes (which start from .0.2). Pool size must be
	// >= Calico's default block size (/26 IPv4, /122 IPv6), so we pick /26
	// and /122 — the smallest sizes Calico IPAM accepts by default.
	proxyNeighV4WorkloadOffset = "0.0.255.0/26"  // 64 addresses
	proxyNeighV4LBOffset       = "0.0.255.64/26" // 64 addresses
	proxyNeighV6WorkloadSuffix = ":ff00::/122"   // 64 addresses
	proxyNeighV6LBSuffix       = ":ff40::/122"   // 64 addresses
)

// proxyNeighEnv collects the per-spec state shared by every proxy ARP/NDP
// test: a controller client, an L2-adjacent docker peer, the names of the two
// IP pools (workload + LoadBalancer) created from the host subnet, and a
// callback that restores the original FelixConfiguration value.
type proxyNeighEnv struct {
	cli              ctrlclient.Client
	extL2            *extL2Peer
	workloadPoolName string
	lbPoolName       string
}

// setupProxyNeighEnv creates two IPPools (workload + LoadBalancer) in the
// host's L2 subnet for the requested family, sets HostSubnetNeighResponses to
// PodsAndLoadBalancers, and spawns a docker container on the kind network.
// All cleanup is registered via DeferCleanup so the caller doesn't need to
// track restoration separately.
func setupProxyNeighEnv(f *framework.Framework, family corev1.IPFamily) *proxyNeighEnv {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	By("Creating a controller-runtime client for Calico resources")
	cli, err := client.New(f.ClientConfig())
	Expect(err).NotTo(HaveOccurred(), "creating ctrl client")

	By("Detecting the kind docker network's subnet for " + string(family))
	v4Net, v6Net, err := detectKindNetworkSubnets(kindNetwork)
	Expect(err).NotTo(HaveOccurred(), "detecting kind network subnets")

	var workloadCIDR, lbCIDR string
	if family == corev1.IPv4Protocol {
		Expect(v4Net).NotTo(BeNil(), "this test requires the kind network to have an IPv4 subnet")
		workloadCIDR, err = subnetOffset(v4Net, proxyNeighV4WorkloadOffset)
		Expect(err).NotTo(HaveOccurred(), "deriving workload v4 CIDR")
		lbCIDR, err = subnetOffset(v4Net, proxyNeighV4LBOffset)
		Expect(err).NotTo(HaveOccurred(), "deriving LB v4 CIDR")
	} else {
		Expect(v6Net).NotTo(BeNil(), "this test requires the kind network to have an IPv6 subnet — re-create the cluster with dual-stack enabled to run NDP tests")
		workloadCIDR, err = v6SubnetWithSuffix(v6Net, proxyNeighV6WorkloadSuffix)
		Expect(err).NotTo(HaveOccurred(), "deriving workload v6 CIDR")
		lbCIDR, err = v6SubnetWithSuffix(v6Net, proxyNeighV6LBSuffix)
		Expect(err).NotTo(HaveOccurred(), "deriving LB v6 CIDR")
	}
	logrus.Infof("Test pool CIDRs (%s): workload=%s LB=%s", family, workloadCIDR, lbCIDR)

	By("Creating IP pools for workload and LoadBalancer addresses inside the host subnet")
	env := &proxyNeighEnv{
		cli:              cli,
		workloadPoolName: utils.GenerateRandomName("proxy-neigh-wl"),
		lbPoolName:       utils.GenerateRandomName("proxy-neigh-lb"),
	}

	// Workload pool: scoped to the test namespace via NamespaceSelector so it
	// doesn't pull IPs away from other test workloads on this cluster.
	createIPPool(ctx, cli, &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: env.workloadPoolName},
		Spec: v3.IPPoolSpec{
			CIDR:              workloadCIDR,
			IPIPMode:          v3.IPIPModeNever,
			VXLANMode:         v3.VXLANModeNever,
			NamespaceSelector: fmt.Sprintf("kubernetes.io/metadata.name == '%s'", f.Namespace.Name),
			AllowedUses:       []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload},
		},
	})
	DeferCleanup(deleteIPPoolIfExists, cli, env.workloadPoolName)

	// LoadBalancer pool: cluster-wide, used by Calico's service IP allocator
	// to assign VIPs to type=LoadBalancer services.
	createIPPool(ctx, cli, &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: env.lbPoolName},
		Spec: v3.IPPoolSpec{
			CIDR:        lbCIDR,
			IPIPMode:    v3.IPIPModeNever,
			VXLANMode:   v3.VXLANModeNever,
			AllowedUses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer},
		},
	})
	DeferCleanup(deleteIPPoolIfExists, cli, env.lbPoolName)

	By("Ensuring HostSubnetNeighResponses=PodsAndLoadBalancers in default FelixConfiguration")
	DeferCleanup(setHostSubnetNeighResponses(cli, v3.HostSubnetNeighResponsesPodsAndLoadBalancers))

	By("Spawning an L2-adjacent docker container on the kind network")
	env.extL2, err = newExtL2Peer(utils.GenerateRandomName("proxy-neigh-extl2"), kindNetwork)
	Expect(err).NotTo(HaveOccurred(), "creating L2-adjacent docker client")
	logrus.Infof("External L2 client: name=%s", env.extL2.name)
	DeferCleanup(func() {
		if err := env.extL2.Close(); err != nil {
			logrus.WithError(err).Warn("Failed to close docker L2 client")
		}
	})

	return env
}

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("HostSubnetNeighResponses"),
	describe.WithCategory(describe.Networking),
	describe.WithSerial(),
	describe.RequiresKindNetwork(),
	describe.RequiresNoEncap(),
	"HostSubnetNeighResponses (proxy ARP)",
	func() {
		f := utils.NewDefaultFramework("proxy-arp")
		var env *proxyNeighEnv

		BeforeEach(func() {
			env = setupProxyNeighEnv(f, corev1.IPv4Protocol)
		})

		// A pod that lives on the host subnet must be reachable from an
		// L2-adjacent client even though the client has no /32 route for the
		// pod IP — this is exactly the scenario Felix's proxy ARP covers, and
		// the only way the connection succeeds is if Felix answers the ARP
		// request on behalf of the hosting node.
		It("responds to ARP for pod IPs in the host subnet", func() {
			ct := conncheck.NewConnectionTester(f)
			DeferCleanup(ct.Stop)
			_, podIP := deployServer(f, ct, "proxy-arp-pod", env.workloadPoolName, corev1.IPv4Protocol)

			By(fmt.Sprintf("Probing pod IP %s with ARP from %s", podIP, env.extL2.name))
			Eventually(func() error {
				_, err := env.extL2.Arping(net.ParseIP(podIP), 3)
				return err
			}, "30s", "2s").Should(Succeed(), "ARP probe for pod IP %s never received a reply", podIP)

			By("Confirming end-to-end reachability via curl")
			Eventually(func() error {
				_, err := env.extL2.Curl(fmt.Sprintf("http://%s/clientip", podIP))
				return err
			}, "30s", "2s").Should(Succeed(), "HTTP request to pod IP %s never succeeded", podIP)
		})

		// LoadBalancer VIPs go through the same code path with one twist: the
		// manager hash-picks a single node to answer for each VIP rather than
		// every node answering. We don't try to assert *which* node responds —
		// only that some node does and traffic flows.
		It("responds to ARP for LoadBalancer VIPs in the host subnet", func() {
			ct := conncheck.NewConnectionTester(f)
			DeferCleanup(ct.Stop)
			vip := deployLoadBalancerVIP(f, ct, env.workloadPoolName, corev1.IPv4Protocol)

			By(fmt.Sprintf("Probing LoadBalancer VIP %s with ARP from %s", vip, env.extL2.name))
			Eventually(func() error {
				_, err := env.extL2.Arping(net.ParseIP(vip), 3)
				return err
			}, "60s", "2s").Should(Succeed(), "ARP probe for LB VIP %s never received a reply", vip)

			By("Confirming end-to-end reachability via curl")
			Eventually(func() error {
				_, err := env.extL2.Curl(fmt.Sprintf("http://%s/clientip", vip))
				return err
			}, "30s", "2s").Should(Succeed(), "HTTP request to LB VIP %s never succeeded", vip)
		})

	},
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("HostSubnetNeighResponses"),
	describe.WithCategory(describe.Networking),
	describe.WithSerial(),
	describe.RequiresKindNetwork(),
	describe.RequiresNoEncap(),
	"HostSubnetNeighResponses (proxy NDP)",
	func() {
		f := utils.NewDefaultFramework("proxy-ndp")
		var env *proxyNeighEnv

		BeforeEach(func() {
			env = setupProxyNeighEnv(f, corev1.IPv6Protocol)
		})

		It("responds to NDP for pod IPs in the host subnet", func() {
			ct := conncheck.NewConnectionTester(f)
			DeferCleanup(ct.Stop)
			_, podIP := deployServer(f, ct, "proxy-ndp-pod", env.workloadPoolName, corev1.IPv6Protocol)

			By(fmt.Sprintf("Probing pod IP %s with NDP from %s", podIP, env.extL2.name))
			Eventually(func() error {
				_, err := env.extL2.NeighborSolicit(net.ParseIP(podIP))
				return err
			}, "30s", "2s").Should(Succeed(), "NDP probe for pod IP %s never received an advertisement", podIP)

			By("Confirming end-to-end reachability via curl")
			Eventually(func() error {
				_, err := env.extL2.Curl(fmt.Sprintf("http://[%s]/clientip", podIP))
				return err
			}, "30s", "2s").Should(Succeed(), "HTTP request to pod IP %s never succeeded", podIP)
		})

		It("responds to NDP for LoadBalancer VIPs in the host subnet", func() {
			ct := conncheck.NewConnectionTester(f)
			DeferCleanup(ct.Stop)
			vip := deployLoadBalancerVIP(f, ct, env.workloadPoolName, corev1.IPv6Protocol)

			By(fmt.Sprintf("Probing LoadBalancer VIP %s with NDP from %s", vip, env.extL2.name))
			Eventually(func() error {
				_, err := env.extL2.NeighborSolicit(net.ParseIP(vip))
				return err
			}, "60s", "2s").Should(Succeed(), "NDP probe for LB VIP %s never received an advertisement", vip)

			By("Confirming end-to-end reachability via curl")
			Eventually(func() error {
				_, err := env.extL2.Curl(fmt.Sprintf("http://[%s]/clientip", vip))
				return err
			}, "30s", "2s").Should(Succeed(), "HTTP request to LB VIP %s never succeeded", vip)
		})

	},
)

// detectKindNetworkSubnets returns the IPv4 and IPv6 subnets configured on the
// given docker network. Either return value may be nil if the network has no
// subnet of that family.
func detectKindNetworkSubnets(networkName string) (v4, v6 *net.IPNet, err error) {
	out, err := exec.Command("docker", "network", "inspect", networkName).Output()
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
	if err := json.Unmarshal(out, &inspected); err != nil {
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

// subnetOffset returns the CIDR formed by OR-ing the offset's address bits
// into the parent network's address. The offset is itself a CIDR string that
// describes the "low bits" to set within the parent. E.g.
// subnetOffset(172.18.0.0/16, "0.0.255.0/29") -> "172.18.255.0/29".
//
// Both inputs must be IPv4. We normalize to 4-byte form because net.ParseCIDR
// can return either 4- or 16-byte representations depending on the input
// string.
func subnetOffset(parent *net.IPNet, offset string) (string, error) {
	parent4 := parent.IP.To4()
	if parent4 == nil {
		return "", fmt.Errorf("subnetOffset: parent %s is not IPv4", parent)
	}
	offIP, offNet, err := net.ParseCIDR(offset)
	if err != nil {
		return "", err
	}
	off4 := offIP.To4()
	if off4 == nil {
		return "", fmt.Errorf("subnetOffset: offset %s is not IPv4", offset)
	}
	out := make(net.IP, 4)
	for i := range out {
		out[i] = parent4[i] | off4[i]
	}
	maskOnes, _ := offNet.Mask.Size()
	return fmt.Sprintf("%s/%d", out, maskOnes), nil
}

// v6SubnetWithSuffix returns a CIDR built by appending an IPv6 suffix CIDR
// (e.g. ":ff00::/125") to the high bits of an IPv6 parent network. We use
// netip.Addr math so the rules around IPv6 zero-compression are consistent.
func v6SubnetWithSuffix(parent *net.IPNet, suffixCIDR string) (string, error) {
	parentAddr, ok := netip.AddrFromSlice(parent.IP.To16())
	if !ok {
		return "", fmt.Errorf("invalid parent IPv6 address %s", parent.IP)
	}
	suffix, err := netip.ParsePrefix("::" + suffixCIDR)
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

// createIPPool creates the given pool and registers a DeferCleanup to delete
// it. We don't return the cleanup func because every pool we create in this
// test should be torn down at the end of the spec.
func createIPPool(ctx context.Context, cli ctrlclient.Client, pool *v3.IPPool) {
	err := cli.Create(ctx, pool)
	Expect(err).NotTo(HaveOccurred(), "creating IPPool %s", pool.Name)
}

// deleteIPPoolIfExists best-effort deletes an IPPool by name and logs (rather
// than fails) on errors so that AfterEach can clean up everything regardless
// of what went wrong inside the test.
func deleteIPPoolIfExists(cli ctrlclient.Client, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := &v3.IPPool{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := cli.Delete(ctx, pool); err != nil {
		logrus.WithError(err).WithField("pool", name).Info("Failed to delete IPPool during cleanup")
	}
}

// setHostSubnetNeighResponses mutates the default FelixConfiguration to put
// HostSubnetNeighResponses into the requested mode and returns a function
// that restores the original value. The restore function is idempotent.
func setHostSubnetNeighResponses(cli ctrlclient.Client, mode v3.HostSubnetNeighResponsesMode) func() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := &v3.FelixConfiguration{}
	err := cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, cfg)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "fetching default FelixConfiguration")

	var original *v3.HostSubnetNeighResponsesMode
	if cfg.Spec.HostSubnetNeighResponses != nil {
		v := *cfg.Spec.HostSubnetNeighResponses
		original = &v
	}

	cfg.Spec.HostSubnetNeighResponses = ptr.To(mode)
	err = cli.Update(ctx, cfg)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "updating FelixConfiguration to %s", mode)

	restored := false
	return func() {
		if restored {
			return
		}
		restored = true
		// Re-fetch the latest version, then write back the original value.
		// Retry briefly to absorb any concurrent updates.
		Eventually(func() error {
			cur := &v3.FelixConfiguration{}
			rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer rcancel()
			if err := cli.Get(rctx, ctrlclient.ObjectKey{Name: "default"}, cur); err != nil {
				return err
			}
			cur.Spec.HostSubnetNeighResponses = original
			return cli.Update(rctx, cur)
		}, "20s", "2s").Should(Succeed(), "restoring original HostSubnetNeighResponses")
	}
}

// deployServer brings up a conncheck Server backed by a pod whose IP is
// allocated from the given IP pool. It returns the conncheck Server (so the
// caller can register cleanup with ct.Stop) and the pod's IP of the requested
// family. The conncheck framework handles pod creation, readiness, and
// re-fetching the pod after it's running so Status.PodIPs is populated.
func deployServer(
	f *framework.Framework,
	ct conncheck.ConnectionTester,
	namePrefix, workloadPoolName string,
	family corev1.IPFamily,
	extraServerOpts ...conncheck.ServerOption,
) (*conncheck.Server, string) {
	useIPPool := conncheck.UseV4IPPool(workloadPoolName)
	if family == corev1.IPv6Protocol {
		useIPPool = conncheck.UseV6IPPool(workloadPoolName)
	}

	opts := []conncheck.ServerOption{
		conncheck.WithEchoServer(),
		conncheck.WithServerPodCustomizer(useIPPool),
	}
	opts = append(opts, extraServerOpts...)

	server := conncheck.NewServer(utils.GenerateRandomName(namePrefix), f.Namespace, opts...)
	ct.AddServer(server)
	ct.Deploy()

	ip := pickPodIP(server.Pod(), family)
	Expect(ip).NotTo(BeEmpty(), "server %s came up without a %s IP", server.Name(), family)
	logrus.Infof("Server %s ready with %s IP %s", server.Name(), family, ip)
	return server, ip
}

// deployLoadBalancerVIP brings up a conncheck Server with a LoadBalancer
// service in the given IP family, waits for Calico's service-IP allocator to
// populate Status.LoadBalancer.Ingress, and returns the VIP. The backend pod
// itself comes from workloadPoolName — only the VIP needs to live in the
// host-subnet LB pool.
func deployLoadBalancerVIP(
	f *framework.Framework,
	ct conncheck.ConnectionTester,
	workloadPoolName string,
	family corev1.IPFamily,
) string {
	ipFamilyPolicy := corev1.IPFamilyPolicySingleStack
	server, _ := deployServer(f, ct, "proxy-neigh-lb", workloadPoolName, family,
		conncheck.WithServerSvcCustomizer(func(svc *corev1.Service) {
			svc.Spec.Type = corev1.ServiceTypeLoadBalancer
			svc.Spec.IPFamilies = []corev1.IPFamily{family}
			svc.Spec.IPFamilyPolicy = &ipFamilyPolicy
		}),
	)

	// Calico's service-IP allocator runs in kube-controllers and may take a
	// few seconds after Service creation to populate the ingress IP.
	var vip string
	Eventually(func() error {
		gctx, gcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer gcancel()
		got, err := f.ClientSet.CoreV1().Services(f.Namespace.Name).Get(gctx, server.Service().Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, ing := range got.Status.LoadBalancer.Ingress {
			if ing.IP == "" {
				continue
			}
			parsed := net.ParseIP(ing.IP)
			if parsed == nil {
				continue
			}
			isV4 := parsed.To4() != nil
			if (family == corev1.IPv4Protocol && isV4) || (family == corev1.IPv6Protocol && !isV4) {
				vip = ing.IP
				return nil
			}
		}
		return fmt.Errorf("service %s has no %s LoadBalancer ingress IP yet", server.Service().Name, family)
	}, "120s", "2s").Should(Succeed(), "Calico did not allocate a %s LoadBalancer VIP for service %s", family, server.Service().Name)

	logrus.Infof("Service %s allocated %s VIP %s", server.Service().Name, family, vip)
	return vip
}

// pickPodIP returns the first PodIP of the requested family, or "" if none.
func pickPodIP(pod *corev1.Pod, family corev1.IPFamily) string {
	for _, ip := range pod.Status.PodIPs {
		parsed := net.ParseIP(ip.IP)
		if parsed == nil {
			continue
		}
		isV4 := parsed.To4() != nil
		if (family == corev1.IPv4Protocol && isV4) || (family == corev1.IPv6Protocol && !isV4) {
			return ip.IP
		}
	}
	return ""
}

// The helpers below manage a netshoot container attached to a docker bridge
// network (the kind network by default). Tests use it to send ARP/NDP probes
// from a location that is layer-2 adjacent to the cluster nodes but is not
// itself a cluster node.
//
// The container is given NET_RAW (for raw ARP/NDP sockets) and NET_ADMIN (for
// netshoot tools that tweak interfaces/routes) and runs `sleep infinity` so we
// can docker exec into it. Callers MUST defer Close() to remove the container.

const (
	kindNetwork = "kind"
	extL2Iface  = "eth0"
)

// extL2Peer wraps a single docker container attached to a bridge network.
type extL2Peer struct {
	name string
}

func newExtL2Peer(name, network string) (*extL2Peer, error) {
	if network == "" {
		network = kindNetwork
	}

	if err := dockerRun("network", "inspect", network); err != nil {
		return nil, fmt.Errorf("docker network %q not reachable: %w", network, err)
	}

	// Best-effort cleanup of a stale container with the same name.
	_ = dockerRun("rm", "-f", name)

	args := []string{
		"run", "-d",
		"--name", name,
		"--network", network,
		"--cap-add", "NET_RAW",
		"--cap-add", "NET_ADMIN",
		images.Netshoot,
		"sleep", "infinity",
	}
	if err := dockerRun(args...); err != nil {
		return nil, fmt.Errorf("docker run for %q failed: %w", name, err)
	}

	return &extL2Peer{name: name}, nil
}

// Close removes the container. Safe to call multiple times.
func (p *extL2Peer) Close() error {
	if p == nil || p.name == "" {
		return nil
	}
	err := dockerRun("rm", "-f", p.name)
	p.name = ""
	return err
}

// Arping sends `count` ARP requests for ip via arping(8). Returns an error if
// no reply is received within the per-probe timeout.
func (p *extL2Peer) Arping(ip net.IP, count int) (string, error) {
	if ip.To4() == nil {
		return "", fmt.Errorf("arping requires an IPv4 address, got %s", ip)
	}
	out, err := p.exec(
		"arping",
		"-c", fmt.Sprint(count),
		"-w", "5",
		"-I", extL2Iface,
		ip.String(),
	)
	if err != nil {
		return out, fmt.Errorf("arping %s failed: %w (output: %s)", ip, err, strings.TrimSpace(out))
	}
	return out, nil
}

// NeighborSolicit sends an IPv6 NDP Neighbor Solicitation for ip via rdisc6.
func (p *extL2Peer) NeighborSolicit(ip net.IP) (string, error) {
	if ip.To4() != nil {
		return "", fmt.Errorf("NeighborSolicit requires an IPv6 address, got %s", ip)
	}
	out, err := p.exec("rdisc6", "-1", "-w", "5000", extL2Iface, ip.String())
	if err != nil {
		return out, fmt.Errorf("rdisc6 %s failed: %w (output: %s)", ip, err, strings.TrimSpace(out))
	}
	return out, nil
}

// Curl performs an HTTP GET against url with a short timeout.
func (p *extL2Peer) Curl(url string) (string, error) {
	out, err := p.exec("curl", "--silent", "--show-error", "--max-time", "5", url)
	if err != nil {
		return out, fmt.Errorf("curl %s failed: %w (output: %s)", url, err, strings.TrimSpace(out))
	}
	return out, nil
}

func (p *extL2Peer) exec(argv ...string) (string, error) {
	if p == nil || p.name == "" {
		return "", fmt.Errorf("extL2Peer: container has been closed")
	}
	full := append([]string{"exec", p.name}, argv...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	return string(out), err
}

// dockerRun runs `docker <args...>` and surfaces any error with the combined
// output attached for easier debugging.
func dockerRun(args ...string) error {
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
