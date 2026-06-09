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
	"fmt"
	"net"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// proxy_neigh_test.go exercises Felix's LocalSubnetL2Reachability feature —
// proxy ARP for IPv4, proxy NDP for IPv6 — end-to-end through the calc graph,
// in felix's own CI. It complements the full-cluster coverage (real LB-IPAM,
// kube-proxy) in the node k8st suite at
// node/tests/k8st/tests/proxy_neigh_test.go.
//
// Topology: a dual-stack single-node cluster plus an external client, all on
// docker's default `bridge` network (containers run with no `--network=` flag,
// so they share one L2 segment — the equivalent of the kind nodes and the
// external client sharing the `kind` network in the k8st test).
//
// We carve a small no-encap pool out of the high end of the bridge's IPv4 and
// IPv6 subnets (docker hands container addresses out from the low end), give a
// workload an IP in each, and connect to those IPs from the external client.
// The client is L2-adjacent to the pod IPs but has no route to them, so it must
// ARP (v4) / send a Neighbor Solicitation (v6) first — which only Felix's
// proxy-neigh manager answers. A successful connection therefore verifies the
// whole ARP/NDP path end-to-end for both families, with no low-level arping.

const (
	// proxyNeighWLOffsetV4/V6 carve a pool out of the high end of the bridge's
	// v4 and v6 subnets — clear of the addresses docker hands containers from
	// the low end. /26 and /122 are Calico's smallest default pool sizes.
	proxyNeighWLOffsetV4 = "0.0.255.0/26"
	proxyNeighWLOffsetV6 = "::ff00:0:0:0/122"
)

var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ _PROXY-NEIGH_ LocalSubnetL2Reachability (proxy ARP/NDP)",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {

		var (
			infra     infrastructure.DatastoreInfra
			tc        infrastructure.TopologyContainers
			calicoCli client.Interface
			extL2     *containers.Container
			podV4     string
			podV6     string
		)

		BeforeEach(func() {
			infra = getInfra()

			// Enable the feature up front so the proxy_neigh manager is active
			// from Felix's first calc-graph flush.
			fc := api.NewFelixConfiguration()
			fc.Name = "default"
			mode := api.LocalSubnetL2ReachabilityPodsAndLoadBalancers
			fc.Spec.LocalSubnetL2Reachability = &mode

			// Dual-stack so we exercise both proxy ARP (v4) and proxy NDP (v6).
			// No encap + UseIPPools=false because we create our own no-encap
			// host-subnet pools below; the default pools would get in the way.
			opts := infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever
			opts.VXLANMode = api.VXLANModeNever
			opts.UseIPPools = false
			opts.EnableIPv6 = true
			opts.InitialFelixConfiguration = fc

			tc, calicoCli = infrastructure.StartNNodeTopology(1, opts, infra)
			felix := tc.Felixes[0]

			// Derive a host-subnet pool per family, reading eth0's subnets
			// straight from Felix.
			v4Net, err := felixSubnet(felix, false)
			Expect(err).NotTo(HaveOccurred(), "reading eth0 IPv4 subnet from %s", felix.Name)
			v6Net, err := felixSubnet(felix, true)
			Expect(err).NotTo(HaveOccurred(), "reading eth0 IPv6 subnet from %s", felix.Name)

			wlV4Pool, err := subnetOffset(v4Net, proxyNeighWLOffsetV4)
			Expect(err).NotTo(HaveOccurred(), "deriving IPv4 workload pool")
			wlV6Pool, err := subnetOffset(v6Net, proxyNeighWLOffsetV6)
			Expect(err).NotTo(HaveOccurred(), "deriving IPv6 workload pool")

			createNoEncapPool(calicoCli, "proxy-neigh-wl-v4", wlV4Pool, []api.IPPoolAllowedUse{api.IPPoolAllowedUseWorkload})
			createNoEncapPool(calicoCli, "proxy-neigh-wl-v6", wlV6Pool, []api.IPPoolAllowedUse{api.IPPoolAllowedUseWorkload})

			podV4, err = pickIPInPool(wlV4Pool, 10)
			Expect(err).NotTo(HaveOccurred())
			podV6, err = pickIPInPool(wlV6Pool, 10)
			Expect(err).NotTo(HaveOccurred())

			extL2 = infrastructure.RunExtClientWithOpts(infra, "proxy-neigh-extl2",
				infrastructure.ExtClientOpts{Image: utils.Config.FelixImage, IPv6Enabled: true})
		})

		AfterEach(func() {
			tc.Stop()
			infra.Stop()
		})

		// A workload whose IP lives in the host subnet must be reachable from an
		// L2-adjacent client that has no route to it. The client ARPs (v4) or
		// sends a Neighbor Solicitation (v6) for the pod IP; that is only
		// answered if Felix's proxy-neigh manager responds on the pod's behalf,
		// after which Felix routes the traffic to the pod. A successful TCP
		// connection therefore verifies the whole ARP/NDP path end-to-end.
		It("answers proxy ARP/NDP for a pod IP so traffic flows over v4 and v6", func() {
			w := workload.New(tc.Felixes[0], "wl-pod", "default", podV4, "8080", "tcp",
				workload.WithIPv6Address(podV6))
			Expect(w.Start(infra)).To(Succeed())
			w.ConfigureInInfra(infra)

			for _, tgt := range []struct {
				family string
				ip     string
			}{
				{"IPv4 (ARP)", podV4},
				{"IPv6 (NDP)", podV6},
			} {
				By(fmt.Sprintf("Connecting from %s to %s pod IP %s", extL2.Name, tgt.family, tgt.ip))
				Eventually(func() *connectivity.Result {
					return extL2.CanConnectTo(tgt.ip, "8080", "tcp")
				}, "30s", "2s").ShouldNot(BeNil(),
					"no %s connectivity from %s to pod IP %s — Felix did not answer for it",
					tgt.family, extL2.Name, tgt.ip)
			}
		})
	},
)

// felixSubnet reads the IPv4 or IPv6 global subnet of the
// given Felix's eth0 — the host L2 segment proxy-neigh operates on — straight
// from the container
func felixSubnet(felix *infrastructure.Felix, v6 bool) (*net.IPNet, error) {
	fam := "-4"
	if v6 {
		fam = "-6"
	}
	out, err := felix.ExecOutput("ip", fam, "-o", "addr", "show", "dev", "eth0", "scope", "global")
	if err != nil {
		return nil, fmt.Errorf("ip %s addr show eth0 on %s: %w (output: %s)", fam, felix.Name, err, out)
	}
	// One-line form, e.g. "2: eth0  inet 172.17.0.3/16 ..." or
	// "2: eth0  inet6 2001:db8::3/64 ...".
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "inet" || fields[i] == "inet6" {
			_, n, err := net.ParseCIDR(fields[i+1])
			if err != nil {
				return nil, fmt.Errorf("parsing %q from ip output on %s: %w", fields[i+1], felix.Name, err)
			}
			return n, nil
		}
	}
	return nil, fmt.Errorf("no global %s address on eth0 of %s (output: %q)", fam, felix.Name, out)
}

// subnetOffset ORs the offset CIDR's address bits into the parent network's
// address, e.g. (172.17.0.0/16, "0.0.255.0/26") -> "172.17.255.0/26" and
// (fd00::/64, "::ff00:0:0:0/122") -> "fd00::ff00:0:0:0/122". Works for v4 and v6
// provided parent and offset are the same family.
func subnetOffset(parent *net.IPNet, offset string) (string, error) {
	offIP, offNet, err := net.ParseCIDR(offset)
	if err != nil {
		return "", err
	}
	pip := parent.IP
	var oip net.IP
	if p4 := pip.To4(); p4 != nil {
		pip, oip = p4, offIP.To4()
	} else {
		pip, oip = pip.To16(), offIP.To16()
	}
	if oip == nil || len(pip) != len(oip) {
		return "", fmt.Errorf("subnetOffset: family mismatch between parent %s and offset %s", parent, offset)
	}
	out := make(net.IP, len(pip))
	for i := range out {
		out[i] = pip[i] | oip[i]
	}
	ones, _ := offNet.Mask.Size()
	return fmt.Sprintf("%s/%d", out, ones), nil
}

// pickIPInPool returns the address idx slots above the pool's network address.
// Cheap deterministic IP allocation for tests; idx must be small. Works for v4
// and v6.
func pickIPInPool(poolCIDR string, idx int) (string, error) {
	_, n, err := net.ParseCIDR(poolCIDR)
	if err != nil {
		return "", err
	}
	ip := n.IP
	if i4 := ip.To4(); i4 != nil {
		ip = i4
	} else {
		ip = ip.To16()
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	out[len(out)-1] += byte(idx)
	return out.String(), nil
}

// createNoEncapPool creates an IPPool with the given CIDR, AllowedUses and no encapsulation.
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
