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
	"fmt"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// Standalone tests for BPFOverlayHostSourceIP.  In TunnelAddress mode the tunnel device is
// assigned an IP and host-networked traffic to a remote workload is SNATed to it (the legacy
// behaviour, exercising HOST_TUNNEL_IP and the SNAT conflict resolution).  In HostAddress mode
// the tunnel device has no IP, so the inner source is the node IP and the workload's reply must
// be re-encapsulated back to the node rather than leaking un-encapsulated with a pod-CIDR source.
var _ = describeBPFOverlayTests("ipip", "TunnelAddress")
var _ = describeBPFOverlayTests("vxlan", "TunnelAddress")
var _ = describeBPFOverlayTests("ipip", "HostAddress")
var _ = describeBPFOverlayTests("vxlan", "HostAddress")

func describeBPFOverlayTests(tunnel, hostSourceIP string) bool {
	if !BPFMode() {
		return true
	}

	desc := fmt.Sprintf("_BPF_ _BPF-SAFE_ BPF overlay host source IP %s (%s)", hostSourceIP, tunnel)
	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		const numNodes = 2
		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			cc           *Checker
			options      infrastructure.TopologyOptions
			w            [numNodes]*workload.Workload
			hostW        [numNodes]*workload.Workload
		)

		BeforeEach(func() {
			infra = getInfra()

			options = infrastructure.DefaultTopologyOptions()
			options.FelixLogSeverity = "Debug"
			options.NATOutgoingEnabled = true
			options.AutoHEPsEnabled = true
			options.IPIPMode = api.IPIPModeNever

			switch tunnel {
			case "ipip":
				options.IPIPStrategy = infrastructure.NewDefaultTunnelStrategy(options.IPPoolCIDR, options.IPv6PoolCIDR)
				options.IPIPMode = api.IPIPModeAlways
			case "vxlan":
				options.VXLANMode = api.VXLANModeAlways
				options.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(options.IPPoolCIDR, options.IPv6PoolCIDR)
			}

			options.DelayFelixStart = true
			options.TriggerDelayedFelixStart = true

			options.ExtraEnvVars["FELIX_BPFLogLevel"] = "debug"
			options.ExtraEnvVars["FELIX_BPFConntrackLogLevel"] = "debug"
			options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBEnabled)
			options.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATDisabled)
			options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "ACCEPT"
			options.ExtraEnvVars["FELIX_BPFOverlayHostSourceIP"] = hostSourceIP

			cc = &Checker{}
			cc.Protocol = "tcp"

			tc, calicoClient = infrastructure.StartNNodeTopology(numNodes, options, infra)

			for ii := range numNodes {
				// Host-networked workload on each node.
				hostW[ii] = workload.Run(
					tc.Felixes[ii],
					fmt.Sprintf("host%d", ii),
					"default",
					tc.Felixes[ii].IP,
					"8055",
					"tcp")
				hostW[ii].WorkloadEndpoint.Labels = map[string]string{"name": hostW[ii].Name}
				hostW[ii].ConfigureInInfra(infra)

				// One regular workload per node.
				wIP := fmt.Sprintf("10.65.%d.2", ii)
				wName := fmt.Sprintf("w%d", ii)
				infrastructure.AssignIP(wName, wIP, tc.Felixes[ii].Hostname, calicoClient)
				w[ii] = workload.New(tc.Felixes[ii], wName, "default", wIP, "8055", "tcp")
				w[ii].WorkloadEndpoint.Labels = map[string]string{
					"name":     w[ii].Name,
					"workload": "regular",
				}
				err := w[ii].Start(infra)
				Expect(err).NotTo(HaveOccurred())
				w[ii].ConfigureInInfra(infra)
			}

			// Allow-all policy so we can focus on dataplane connectivity.
			pol := api.NewGlobalNetworkPolicy()
			pol.Namespace = "fv"
			pol.Name = "allow-all"
			one := float64(1)
			pol.Spec.Order = &one
			pol.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			pol.Spec.Egress = []api.Rule{{Action: api.Allow}}
			pol.Spec.Selector = "all()"
			_, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, pol, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		})

		AfterEach(func() {
			for ii := range numNodes {
				w[ii].Stop()
				hostW[ii].Stop()
			}
			tc.Stop()
			infra.Stop()
		})

		It("should have host-networked connectivity to remote workloads and hosts", func() {
			// Host -> remote workload is the key scenario: BPF uses HOST_TUNNEL_IP
			// for SNAT conflict resolution when host-networked traffic hits a remote
			// tunneled workload.
			cc.ExpectSome(hostW[0], w[1])
			cc.ExpectSome(hostW[1], w[0])

			// Host -> remote host via host-networked workloads.
			cc.ExpectSome(hostW[0], hostW[1])
			cc.ExpectSome(hostW[1], hostW[0])

			// Pod -> remote pod (basic overlay connectivity).
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])

			cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)
		})

		itTunnelAddr := It
		if hostSourceIP != "TunnelAddress" {
			itTunnelAddr = PIt
		}
		itTunnelAddr("should use the host IP, not the tunnel IP, as the overlay underlay source", func() {
			// The outer (underlay) source of encapsulated host-networked traffic must be
			// the node's own IP.  The overlay tunnel-device IP is not underlay-routable; a
			// fabric that checks source addresses (e.g. GCP) drops packets carrying it.
			// Connectivity alone does not catch this on a permissive underlay, so capture
			// the encapsulated traffic and check its outer source.  Selection is done with
			// tcpdump's own filter (by outer source host), not by parsing its text, whose
			// format varies by tcpdump version.
			var encap []string
			var tunnelAddr string
			switch tunnel {
			case "vxlan":
				tunnelAddr = tc.Felixes[0].ExpectedVXLANTunnelAddr
				encap = []string{"udp", "and", "port", "4789"}
			case "ipip":
				tunnelAddr = tc.Felixes[0].ExpectedIPIPTunnelAddr
				encap = []string{"ip", "proto", "4"}
			}
			Expect(tunnelAddr).NotTo(BeEmpty(), "tunnel address should be assigned in TunnelAddress mode")

			// Any captured packet line contains " > "; the tcpdump banner does not.
			pkt := regexp.MustCompile(" > ")

			// Encapsulated packets whose outer source is the node IP (correct).
			fromNode := tc.Felixes[0].AttachTCPDump("eth0")
			fromNode.SetLogEnabled(true)
			fromNode.AddMatcher("pkt", pkt)
			fromNode.Start(infra, append(append([]string{"-n"}, encap...), "and", "src", "host", tc.Felixes[0].IP)...)

			// Encapsulated packets whose outer source is the tunnel IP (the bug).
			fromTunnel := tc.Felixes[0].AttachTCPDump("eth0")
			fromTunnel.SetLogEnabled(true)
			fromTunnel.AddMatcher("pkt", pkt)
			fromTunnel.Start(infra, append(append([]string{"-n"}, encap...), "and", "src", "host", tunnelAddr)...)

			// Host-networked -> remote workload drives the encapsulated host-origin flow.
			cc.ExpectSome(hostW[0], w[1])
			cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)

			Eventually(fromNode.MatchCountFn("pkt"), "5s", "100ms").Should(BeNumerically(">", 0),
				fmt.Sprintf("overlay outer source should be the node IP %s", tc.Felixes[0].IP))
			Consistently(fromTunnel.MatchCountFn("pkt"), "2s", "100ms").Should(BeZero(),
				fmt.Sprintf("overlay outer source must never be the tunnel IP %s", tunnelAddr))
		})

		itHostAddr := It
		if hostSourceIP != "HostAddress" {
			itHostAddr = PIt
		}
		itHostAddr("should re-encapsulate a workload's reply to a host-networked client", func() {
			// In HostAddress mode the tunnel device has no IP, so a host-networked client's
			// encapsulated request carries the node IP as its inner source.  The workload's
			// reply therefore targets a bare node IP, which has no overlay route: without
			// re-encapsulation it leaves the node un-encapsulated with a pod-CIDR source,
			// which a source-checking fabric (e.g. GCP) drops.  Connectivity still succeeds on
			// a permissive FV underlay, so assert on the wire: the reply must leave the
			// workload's node encapsulated (outer source = that node IP) and must never appear
			// with the pod IP as its outer source.  Selection uses tcpdump's own source-host
			// filter, not text parsing.
			var encap []string
			switch tunnel {
			case "vxlan":
				encap = []string{"udp", "and", "port", "4789"}
			case "ipip":
				encap = []string{"ip", "proto", "4"}
			}

			// Any captured packet line contains " > "; the tcpdump banner does not.
			pkt := regexp.MustCompile(" > ")
			podNode := tc.Felixes[1]

			// The reply leaves the workload's node encapsulated, outer source = that node (correct).
			encapReply := podNode.AttachTCPDump("eth0")
			encapReply.SetLogEnabled(true)
			encapReply.AddMatcher("pkt", pkt)
			encapReply.Start(infra, append(append([]string{"-n"}, encap...), "and", "src", "host", podNode.IP)...)

			// The reply leaves the node un-encapsulated with the pod IP as its outer source (the bug).
			bareReply := podNode.AttachTCPDump("eth0")
			bareReply.SetLogEnabled(true)
			bareReply.AddMatcher("pkt", pkt)
			bareReply.Start(infra, "-n", "src", "host", w[1].IP)

			// Host-networked client on nodeA -> workload on nodeB; its reply is the flow under test.
			cc.ExpectSome(hostW[0], w[1])
			cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)

			Eventually(encapReply.MatchCountFn("pkt"), "5s", "100ms").Should(BeNumerically(">", 0),
				fmt.Sprintf("workload reply should leave node %s encapsulated", podNode.IP))
			Consistently(bareReply.MatchCountFn("pkt"), "2s", "100ms").Should(BeZero(),
				fmt.Sprintf("workload reply must never leave the node un-encapsulated with pod source %s", w[1].IP))
		})
	})
}
