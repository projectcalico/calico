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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ Network policy only mode (RouteSyncDisabled=true) tests",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {
		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			probeWl      *workload.Workload
		)

		const (
			probeV4 = "10.65.0.10"
			probeV6 = "dead:beef::10"
			wlV4    = "10.65.0.2"
			wlV6    = "dead:beef::2"
			peerV4  = "169.254.0.179"
			peerV6  = "fe80::179"
		)

		BeforeEach(func() {
			infra = getInfra()

			opts := infrastructure.DefaultTopologyOptions()
			// Dual-stack: exercise both v4 and v6 paths.
			opts.IPIPMode = api.IPIPModeNever
			opts.EnableIPv6 = true

			// Set RouteSyncDisabled=true in the initial FelixConfiguration so
			// Felix picks it up on startup — RouteSyncDisabled requires a Felix
			// restart to take effect.
			felixConfig := api.NewFelixConfiguration()
			felixConfig.Name = "default"
			routeSyncDisabled := true
			felixConfig.Spec.RouteSyncDisabled = &routeSyncDisabled
			opts.InitialFelixConfiguration = felixConfig

			tc, calicoClient = infrastructure.StartSingleNodeTopology(opts, infra)

			By("Installing a default-allow GlobalNetworkPolicy")
			// In network-policy-only mode we still expect Felix to program
			// policy. Install an allow-all policy and verify that Felix has
			// rendered it before running the rest of the test.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "default-allow"
			policy.Spec.Selector = "all()"
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := calicoClient.GlobalNetworkPolicies().Create(ctx, policy, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a probe workload so the policy becomes active")
			// Felix only renders policy chains for policies that select at
			// least one local endpoint, so we need a workload on the node
			// before we can assert that the policy has been programmed.
			probeWl = workload.Run(tc.Felixes[0], "probe", "default", probeV4, "8088", "tcp",
				workload.WithIPv6Address(probeV6))
			probeWl.ConfigureInInfra(infra)

			if BPFMode() {
				// In BPF mode, policy lives in BPF programs attached to the
				// workload's veth; wait for those to come up before asserting.
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
			}

			By("Verifying the default-allow policy is programmed in the dataplane")
			Eventually(policyProgrammedOn(tc.Felixes[0], probeWl.InterfaceName, "default-allow"), "30s", "500ms").
				Should(BeTrue(), "Felix should program the default-allow policy even when RouteSyncDisabled is true")
		})

		// assertNoRouteEntry asserts that no route entry exists in any routing
		// table for the given address on the given interface. Felix should not
		// program routes at all when RouteSyncDisabled is true; this includes
		// the side-channel entries that the kernel would install if Felix
		// assigned an address to the veth via LinkAddrsManager.
		assertNoRouteEntry := func(iface string, addrs ...string) {
			for _, addr := range addrs {
				flag := "-4"
				if strings.Contains(addr, ":") {
					flag = "-6"
				}
				query := func() string {
					out, err := tc.Felixes[0].ExecOutput(
						"ip", flag, "route", "show", "table", "all", addr, "dev", iface)
					Expect(err).NotTo(HaveOccurred())
					return out
				}
				Eventually(query, "5s", "500ms").Should(BeEmpty(),
					"Felix should not program a route for %s on %s when RouteSyncDisabled is true",
					addr, iface)
				Consistently(query, "3s", "500ms").Should(BeEmpty(),
					"Felix should not program a route for %s on %s when RouteSyncDisabled is true",
					addr, iface)
			}
		}

		It("should not program routes for workload endpoint addresses", func() {
			By("Creating a dual-stack local workload")
			wl := workload.Run(tc.Felixes[0], "w0", "default", wlV4, "8088", "tcp",
				workload.WithIPv6Address(wlV6))
			wl.ConfigureInInfra(infra)

			By("Waiting for the workload's veth to exist on the host")
			Eventually(func() string {
				out, _ := tc.Felixes[0].ExecOutput("ip", "link", "show", wl.InterfaceName)
				return out
			}, "30s").Should(ContainSubstring(wl.InterfaceName))

			By("Verifying no routes are programmed for the workload IPs")
			// With RouteSyncDisabled=true, Felix's endpoint manager writes
			// workload routes into a DummyTable; no /32 or /128 entry should
			// appear in any kernel routing table.
			assertNoRouteEntry(wl.InterfaceName, wlV4+"/32", wlV6+"/128")
		})

		It("should not program routes for link-local peer addresses", func() {
			// When a workload is selected as a local BGP peer, the endpoint
			// manager would normally call LinkAddrsManager.SetLinkLocalAddress,
			// which issues netlink AddrAdd on the workload's veth. The kernel
			// then populates the local routing table with entries for the
			// assigned address. With RouteSyncDisabled=true the link-address
			// manager must be inert, so no such local-table entries should
			// appear.
			By("Creating a workload labelled for local BGP peering")
			wl := workload.Run(tc.Felixes[0], "w0", "default", wlV4, "8088", "tcp",
				workload.WithIPv6Address(wlV6))
			wl.WorkloadEndpoint.Labels["role"] = "bgp-peer"
			wl.ConfigureInInfra(infra)

			By("Configuring the local workload peering IPs (v4 + v6)")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			bgpCfg := api.NewBGPConfiguration()
			bgpCfg.Name = "default"
			bgpCfg.Spec.LocalWorkloadPeeringIPV4 = peerV4
			bgpCfg.Spec.LocalWorkloadPeeringIPV6 = peerV6
			_, err := calicoClient.BGPConfigurations().Create(ctx, bgpCfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Creating a BGPPeer that selects the workload")
			asn, err := numorstring.ASNumberFromString("65401")
			Expect(err).NotTo(HaveOccurred())
			peer := api.NewBGPPeer()
			peer.Name = "local-wl-peer"
			peer.Spec.LocalWorkloadSelector = "role == 'bgp-peer'"
			peer.Spec.ASNumber = asn
			_, err = calicoClient.BGPPeers().Create(ctx, peer, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for the workload's veth to exist on the host")
			Eventually(func() string {
				out, _ := tc.Felixes[0].ExecOutput("ip", "link", "show", wl.InterfaceName)
				return out
			}, "30s").Should(ContainSubstring(wl.InterfaceName))

			By("Verifying no routes are programmed for the workload IPs or the peer IPs")
			assertNoRouteEntry(
				wl.InterfaceName,
				wlV4+"/32", wlV6+"/128",
				peerV4+"/32", peerV6+"/128",
			)
		})
	},
)

// policyProgrammedOn returns a function that reports whether the given policy
// is programmed on the given workload interface. In BPF mode it inspects the
// per-interface BPF policy dump for the canonical
// "Policy: GlobalNetworkPolicy <name>" marker — the tool's "all" pseudo-iface
// cannot be used because the debug JSON is keyed by real interface name and
// the command silently produces no output when the file is missing. In
// iptables/nftables mode, policy chain names embed the policy name, so a
// ruleset grep is sufficient.
func policyProgrammedOn(felix *infrastructure.Felix, ifaceName, policyName string) func() bool {
	return func() bool {
		if BPFMode() {
			marker := "Policy: GlobalNetworkPolicy " + policyName
			for _, hook := range []string{"ingress", "egress"} {
				out, err := felix.ExecOutput("calico-bpf", "policy", "dump", ifaceName, hook)
				if err != nil {
					continue
				}
				if strings.Contains(out, marker) {
					return true
				}
			}
			return false
		}
		var cmd []string
		if NFTMode() {
			cmd = []string{"nft", "list", "ruleset"}
		} else {
			cmd = []string{"iptables-save", "-t", "filter"}
		}
		out, err := felix.ExecOutput(cmd...)
		if err != nil {
			return false
		}
		return strings.Contains(out, policyName)
	}
}
