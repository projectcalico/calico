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

// Standalone tests for BPFOverlayHostSourceIP=TunnelAddress — verifies that overlay connectivity
// works when the tunnel device is assigned an IP address (the legacy behaviour).  The primary
// scenario is host-networked traffic to/from remote tunneled workloads, which is where
// HOST_TUNNEL_IP and the SNAT conflict resolution logic come into play.
var _ = describeBPFOverlayTunnelAddrTests("ipip")
var _ = describeBPFOverlayTunnelAddrTests("vxlan")

func describeBPFOverlayTunnelAddrTests(tunnel string) bool {
	if !BPFMode() {
		return true
	}

	desc := fmt.Sprintf("_BPF_ _BPF-SAFE_ BPF overlay host source IP tunnel address (%s)", tunnel)
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
			options.ExtraEnvVars["FELIX_BPFOverlayHostSourceIP"] = "TunnelAddress"

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

		It("should use the host IP, not the tunnel IP, as the overlay underlay source", func() {
			// The outer (underlay) source of encapsulated host-networked traffic must be
			// the node's own IP.  The overlay tunnel-device IP is not underlay-routable; a
			// fabric that checks source addresses (e.g. GCP) drops packets carrying it.
			// Connectivity alone does not catch this on a permissive underlay, so assert
			// the outer source seen on the wire.
			var filter []string
			var goodSrc, badSrc, tunnelAddr string
			switch tunnel {
			case "vxlan":
				tunnelAddr = tc.Felixes[0].ExpectedVXLANTunnelAddr
				filter = []string{"-n", "-vvv", "udp", "port", "4789"}
				goodSrc = fmt.Sprintf(`%s\.\d+ > %s\.4789: VXLAN`,
					regexp.QuoteMeta(tc.Felixes[0].IP), regexp.QuoteMeta(tc.Felixes[1].IP))
				badSrc = fmt.Sprintf(`%s\.\d+ > .*\.4789: VXLAN`, regexp.QuoteMeta(tunnelAddr))
			case "ipip":
				tunnelAddr = tc.Felixes[0].ExpectedIPIPTunnelAddr
				filter = []string{"-n", "-vvv", "ip", "proto", "4"}
				goodSrc = fmt.Sprintf(`%s > %s: `,
					regexp.QuoteMeta(tc.Felixes[0].IP), regexp.QuoteMeta(tc.Felixes[1].IP))
				badSrc = fmt.Sprintf(`%s > .*: `, regexp.QuoteMeta(tunnelAddr))
			}
			Expect(tunnelAddr).NotTo(BeEmpty(), "tunnel address should be assigned in TunnelAddress mode")

			tcpd := tc.Felixes[0].AttachTCPDump("eth0")
			tcpd.SetLogEnabled(true)
			tcpd.AddMatcher("good-outer-src", regexp.MustCompile(goodSrc))
			tcpd.AddMatcher("bad-outer-src", regexp.MustCompile(badSrc))
			tcpd.Start(infra, filter...)

			// Host-networked -> remote workload drives the encapsulated host-origin flow.
			cc.ExpectSome(hostW[0], w[1])
			cc.CheckConnectivity(conntrackChecks(tc.Felixes)...)

			Eventually(tcpd.MatchCountFn("good-outer-src"), "5s", "100ms").Should(BeNumerically(">", 0),
				fmt.Sprintf("overlay outer source should be the node IP %s", tc.Felixes[0].IP))
			Consistently(tcpd.MatchCountFn("bad-outer-src"), "2s", "100ms").Should(BeZero(),
				fmt.Sprintf("overlay outer source must never be the tunnel IP %s", tunnelAddr))
		})
	})
}
