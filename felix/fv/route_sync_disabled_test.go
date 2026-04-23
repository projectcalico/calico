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
	"Network policy only mode (RouteSyncDisabled=true) tests",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {
		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			probeWl      *workload.Workload
		)

		BeforeEach(func() {
			infra = getInfra()

			opts := infrastructure.DefaultTopologyOptions()
			// Default topology uses IPIPModeAlways; turn off all encap so Felix
			// would otherwise program plain workload routes directly on veths.
			opts.IPIPMode = api.IPIPModeNever
			opts.VXLANMode = api.VXLANModeNever
			opts.EnableIPv6 = false

			// Set RouteSyncDisabled=true in the initial FelixConfiguration so
			// Felix picks it up on startup — RouteSyncDisabled requires a Felix
			// restart to take effect.
			routeSyncDisabled := true
			felixConfig := api.NewFelixConfiguration()
			felixConfig.Name = "default"
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
			probeWl = workload.Run(tc.Felixes[0], "probe", "default", "10.65.0.10", "8088", "tcp")
			probeWl.ConfigureInInfra(infra)

			By("Verifying the default-allow policy is programmed in the dataplane")
			Eventually(policyProgrammedOn(tc.Felixes[0], probeWl.InterfaceName, "default-allow"), "30s", "500ms").
				Should(BeTrue(), "Felix should program the default-allow policy even when RouteSyncDisabled is true")
		})

		It("should not assign IPv4 addresses to workload endpoints", func() {
			By("Creating a local workload")
			wl := workload.Run(tc.Felixes[0], "w0", "default", "10.65.0.2", "8088", "tcp")
			wl.ConfigureInInfra(infra)

			By("Waiting for the workload's veth to exist on the host")
			Eventually(func() string {
				out, _ := tc.Felixes[0].ExecOutput("ip", "link", "show", wl.InterfaceName)
				return out
			}, "30s").Should(ContainSubstring(wl.InterfaceName))

			By("Verifying no IPv4 address is assigned to the workload interface")
			// With RouteSyncDisabled=true, Felix should not touch the workload
			// veth beyond what's required for policy. The host side of the veth
			// should have no IPv4 addresses attached.
			Consistently(func() string {
				out, _ := tc.Felixes[0].ExecOutput("ip", "-4", "addr", "show", "dev", wl.InterfaceName)
				return out
			}, "5s", "500ms").ShouldNot(ContainSubstring("inet "),
				"Felix should not assign any IPv4 address to the workload interface when RouteSyncDisabled is true")
		})

		It("should not assign link-local peer addresses to the workload interface", func() {
			// When a workload is selected as a local BGP peer, the endpoint
			// manager calls LinkAddrsManager.SetLinkLocalAddress, which issues
			// netlink AddrAdd on the workload's veth. That peer address is only
			// useful when Felix is also programming routes, but not when RouteSyncDisabled is true.
			By("Creating a workload labelled for local BGP peering")
			wl := workload.Run(tc.Felixes[0], "w0", "default", "10.65.0.2", "8088", "tcp")
			wl.WorkloadEndpoint.Labels["role"] = "bgp-peer"
			wl.ConfigureInInfra(infra)

			By("Configuring the local workload peering IP")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			bgpCfg := api.NewBGPConfiguration()
			bgpCfg.Name = "default"
			bgpCfg.Spec.LocalWorkloadPeeringIPV4 = "169.254.0.179"
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

			By("Verifying that the link-local peer address is not assigned to the workload interface")
			// Expected to fail today: LinkAddrsManager runs unconditionally and
			// will assign 169.254.0.179/32 to the veth, even though routes to
			// make it useful are suppressed by RouteSyncDisabled.
			Consistently(func() string {
				out, _ := tc.Felixes[0].ExecOutput("ip", "-4", "addr", "show", "dev", wl.InterfaceName)
				return out
			}, "5s", "500ms").ShouldNot(ContainSubstring("inet "),
				"Felix should not assign the link-local peer address to the workload interface "+
					"when RouteSyncDisabled is true")
		})
	},
)

// policyProgrammedOn returns a function that reports whether the given policy
// is programmed on the given workload interface. In BPF mode it inspects the
// per-interface BPF policy dump for the canonical
// "Policy: GlobalNetworkPolicy <name>" marker — the tool's "all" pseudo-iface
// cannot be used here because the debug JSON is keyed by real interface name
// and the command silently produces no output when the file is missing. In
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
