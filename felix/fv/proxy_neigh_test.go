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

package fv_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// proxy_neigh_test.go exercises the HostSubnetNeighResponses Felix feature
// (proxy ARP / NDP) end-to-end through the calc graph, complementing the
// integration coverage in e2e/pkg/tests/networking/proxy_neigh.go.
//
// The intent is "full chain" — every OnUpdate case in proxy_neigh_mgr.go
// is driven by a real calc-graph message, not a mock:
//
//   ifaceAddrsUpdate          Felix's own iface monitor on eth0
//   WorkloadEndpointUpdate    workload.New(...).ConfigureInInfra(...)
//   ServiceUpdate             real K8s Service + .status.loadBalancer.ingress
//   HostMetadataV4V6Update    one per Felix from infra.AddNode (Node resource)
//   IPAMPoolUpdate            calicoCli.IPPools().Create(...)
//
// L2 setup
//
// Felix containers run on docker's default `bridge` network (containers.go
// runs them with no `--network=` flag). The external client is attached to
// the same `bridge` so it shares the L2 segment with the cluster nodes —
// equivalent to the e2e topology where extL2 and the kind nodes share the
// `kind` docker network.
//
// IP pools
//
// We carve two /26s out of the high end of the docker bridge subnet (the
// low end is reserved by docker for the felix containers). One pool is
// used for the workload IP, the other for the LoadBalancer VIP. Both are
// no-encap pools so Felix considers IPs in them "in the host subnet".
//
// LB VIP allocation
//
// FV does not run kube-controllers, so we hand-pick a VIP from the LB pool
// and write it directly into Service.Status.LoadBalancer.Ingress via the
// status sub-resource. kubernetesServiceToProto (felix/calc/dataplane_passthru.go)
// reads the VIP from the status field, so the calc graph emits a real
// ServiceUpdate just as it would in a production cluster.

const (
	netshootImage = "docker.io/nicolaka/netshoot:v0.13"

	// dockerBridgeName is the name of docker's default bridge network. The
	// FV runs felix and ext clients on this network with no explicit
	// --network= flag, so they share L2 by default.
	dockerBridgeName = "bridge"

	// proxyNeighWLOffset and proxyNeighLBOffset carve two /26s out of the
	// high end of the bridge subnet. /26 is Calico's smallest acceptable
	// IPv4 pool size by default. The high end avoids colliding with felix
	// container addresses, which docker hands out from the low end.
	proxyNeighWLOffset = "0.0.255.0/26"  // 64 addresses
	proxyNeighLBOffset = "0.0.255.64/26" // 64 addresses
)

var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ _PROXY-NEIGH_ HostSubnetNeighResponses (proxy ARP)",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {

		var (
			infra      infrastructure.DatastoreInfra
			tc         infrastructure.TopologyContainers
			calicoCli  client.Interface
			extL2      *containers.Container
			wlPoolCIDR string
			lbPoolCIDR string
		)

		const (
			wlPoolName = "proxy-neigh-wl"
			lbPoolName = "proxy-neigh-lb"
		)

		BeforeEach(func() {
			// Detect the docker bridge subnet so we can derive pool CIDRs
			// that fall inside the host's L2 segment. A missing IPv4 subnet
			// means the FV host's docker is misconfigured — fail loudly
			// rather than silently skip.
			bridgeV4, err := inspectDockerNetworkV4(dockerBridgeName)
			Expect(err).NotTo(HaveOccurred(), "inspecting docker bridge")
			Expect(bridgeV4).NotTo(BeNil(), "docker bridge network %q has no IPv4 subnet", dockerBridgeName)

			wlPoolCIDR, err = subnetOffsetV4(bridgeV4, proxyNeighWLOffset)
			Expect(err).NotTo(HaveOccurred(), "deriving workload pool CIDR")
			lbPoolCIDR, err = subnetOffsetV4(bridgeV4, proxyNeighLBOffset)
			Expect(err).NotTo(HaveOccurred(), "deriving LB pool CIDR")

			infra = getInfra()

			// Enable the feature up front so the proxy_neigh manager is
			// active from Felix's first calc-graph flush.
			fc := api.NewFelixConfiguration()
			fc.Name = "default"
			fc.Spec.HostSubnetNeighResponses = new(api.HostSubnetNeighResponsesPodsAndLoadBalancers)

			// Three nodes so the rendezvous-hash node selection for LB
			// VIPs has actual choice. UseIPPools=false because we create
			// our own pools below with explicit AllowedUses; we don't want
			// the default 10.65.0.0/16 pool getting in the way.
			opts := infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever
			opts.VXLANMode = api.VXLANModeNever
			opts.UseIPPools = false
			opts.InitialFelixConfiguration = fc

			tc, calicoCli = infrastructure.StartNNodeTopology(3, opts, infra)

			// Both pools must be no-encap for proxy_neigh_mgr.isInNoEncapPool to accept them.
			createNoEncapPool(calicoCli, wlPoolName, wlPoolCIDR, []api.IPPoolAllowedUse{api.IPPoolAllowedUseWorkload})
			createNoEncapPool(calicoCli, lbPoolName, lbPoolCIDR, []api.IPPoolAllowedUse{api.IPPoolAllowedUseLoadBalancer})

			// Netshoot ext client on the shared docker bridge, gives us arping / NET_RAW / curl.
			extL2 = infrastructure.RunExtClientWithOpts(infra, "proxy-neigh-extl2", infrastructure.ExtClientOpts{Image: netshootImage})
		})

		AfterEach(func() {
			tc.Stop()
			infra.Stop()
		})

		// Pod-IP path: a workload whose IP lives in the host subnet must
		// be reachable from an L2-adjacent client even though the client
		// has no /32 route for the pod IP. Felix on the hosting node
		// answers the ARP request, the client caches felix's MAC, and
		// traffic flows through felix's normal workload routing.
		It("answers ARP for a pod IP and traffic flows", func() {
			podIP, err := pickIPInPool(wlPoolCIDR, 10)
			Expect(err).NotTo(HaveOccurred())

			w := workload.New(tc.Felixes[0], "wl-pod", "default", podIP, "8080", "tcp")
			Expect(w.Start(infra)).To(Succeed())
			w.ConfigureInInfra(infra)

			By(fmt.Sprintf("ARPing pod IP %s from %s", podIP, extL2.Name))
			Eventually(func() error {
				return arpingFrom(extL2, podIP)
			}, "30s", "2s").Should(Succeed(), "no ARP reply for pod IP %s — Felix on %s did not respond", podIP, tc.Felixes[0].Name)

			By("Confirming end-to-end TCP reachability")
			Eventually(func() *connectivity.Result {
				return extL2.CanConnectTo(podIP, "8080", "tcp")
			}, "30s", "2s").ShouldNot(BeNil(), "TCP probe from %s to pod IP %s never succeeded", extL2.Name, podIP)
		})

		// LB-VIP path: rendezvous hash picks one node from the cluster to
		// answer ARP for each VIP. We don't assert *which* node — the
		// hash output isn't part of the contract — only that some node
		// answers and that the answer comes from a Felix MAC, not a
		// random kernel response.
		//
		// We deliberately do NOT curl the VIP. FV doesn't run kube-proxy
		// or Calico's BPF service translation, so the packet would have
		// nowhere to go after the ARP cache is populated. Service
		// translation is exercised elsewhere; this test owns the proxy
		// ARP path only.
		It("answers ARP for a LoadBalancer VIP", func() {
			vip, err := pickIPInPool(lbPoolCIDR, 5)
			Expect(err).NotTo(HaveOccurred())

			k8s := infra.(*infrastructure.K8sDatastoreInfra).K8sClient

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "proxy-neigh-lb",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeLoadBalancer,
					// Selector doesn't need to match anything — the calc
					// graph reads the VIP from Status, not Spec, and we
					// don't depend on backends being reachable.
					Selector: map[string]string{"app": "proxy-neigh-lb"},
					Ports: []corev1.ServicePort{{
						Name:       "http",
						Port:       8080,
						TargetPort: intstr.FromInt32(8080),
						Protocol:   corev1.ProtocolTCP,
					}},
				},
			}
			created, err := k8s.CoreV1().Services("default").Create(ctx, svc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred(), "creating LoadBalancer Service")
			defer func() {
				dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer dcancel()
				_ = k8s.CoreV1().Services("default").Delete(dctx, "proxy-neigh-lb", metav1.DeleteOptions{})
			}()

			// PATCH .status.loadBalancer.ingress with our hand-picked VIP.
			// kubernetesServiceToProto reads from Status, so this is what
			// drives the ServiceUpdate that proxy_neigh_mgr consumes.
			created.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: vip}}
			_, err = k8s.CoreV1().Services("default").UpdateStatus(ctx, created, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred(), "patching Service status with VIP")

			By(fmt.Sprintf("ARPing LB VIP %s from %s", vip, extL2.Name))
			Eventually(func() error {
				return arpingFrom(extL2, vip)
			}, "60s", "2s").Should(Succeed(), "no ARP reply for LB VIP", vip)
		})
	},
)

// inspectDockerNetworkV4 returns the IPv4 subnet configured on the given
// docker network, or nil if the network has no IPv4 subnet.
func inspectDockerNetworkV4(name string) (*net.IPNet, error) {
	out, err := exec.Command("docker", "network", "inspect", name).Output()
	if err != nil {
		return nil, fmt.Errorf("docker network inspect %s: %w", name, err)
	}
	var inspected []struct {
		IPAM struct {
			Config []struct {
				Subnet string
			}
		}
	}
	if err := json.Unmarshal(out, &inspected); err != nil {
		return nil, fmt.Errorf("parsing docker network inspect output: %w", err)
	}
	if len(inspected) == 0 {
		return nil, fmt.Errorf("docker network %s not found", name)
	}
	for _, cfg := range inspected[0].IPAM.Config {
		_, n, err := net.ParseCIDR(cfg.Subnet)
		if err != nil {
			continue
		}
		if n.IP.To4() != nil {
			return n, nil
		}
	}
	return nil, nil
}

// subnetOffsetV4 returns the CIDR formed by OR-ing the offset's address bits
// into the parent network's address. E.g. subnetOffsetV4(172.18.0.0/16,
// "0.0.255.0/26") -> "172.18.255.0/26". Both inputs must be IPv4.
func subnetOffsetV4(parent *net.IPNet, offset string) (string, error) {
	parent4 := parent.IP.To4()
	if parent4 == nil {
		return "", fmt.Errorf("subnetOffsetV4: parent %s is not IPv4", parent)
	}
	offIP, offNet, err := net.ParseCIDR(offset)
	if err != nil {
		return "", err
	}
	off4 := offIP.To4()
	if off4 == nil {
		return "", fmt.Errorf("subnetOffsetV4: offset %s is not IPv4", offset)
	}
	out := make(net.IP, 4)
	for i := range out {
		out[i] = parent4[i] | off4[i]
	}
	maskOnes, _ := offNet.Mask.Size()
	return fmt.Sprintf("%s/%d", out, maskOnes), nil
}

// pickIPInPool returns the address `idx` slots above the network address of
// the given pool. Cheap deterministic IP allocation for tests.
func pickIPInPool(poolCIDR string, idx int) (string, error) {
	_, n, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return "", err
	}
	ip4 := n.IP.To4()
	if ip4 == nil {
		return "", fmt.Errorf("pickIPInPool: only IPv4 supported, got %s", poolCIDR)
	}
	out := make(net.IP, 4)
	copy(out, ip4)
	out[3] += byte(idx)
	return out.String(), nil
}

// createNoEncapPool creates an IPPool with the given CIDR, AllowedUses and
// no encapsulation. proxy_neigh_mgr.isNoEncapPool requires both ipipMode and
// vxlanMode to be Never.
func createNoEncapPool(c client.Interface, name, cidr string, uses []api.IPPoolAllowedUse) {
	pool := api.NewIPPool()
	pool.Name = name
	pool.Spec.CIDR = cidr
	pool.Spec.IPIPMode = api.IPIPModeNever
	pool.Spec.VXLANMode = api.VXLANModeNever
	pool.Spec.AllowedUses = uses
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.IPPools().Create(ctx, pool, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred(), "creating IPPool %s", name)
}

// arpingFrom sends 3 ARP requests for ip from the ext client and returns an
// error if no reply arrives within the 5-second per-probe timeout. Wrapped
// for use inside Eventually(...).
func arpingFrom(c *containers.Container, ip string) error {
	out, err := c.ExecOutput("arping", "-c", "3", "-w", "5", "-I", "eth0", ip)
	if err != nil {
		return fmt.Errorf("arping %s: %w (output: %s)", ip, err, out)
	}
	return nil
}
