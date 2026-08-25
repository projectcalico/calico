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

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = describeBPFAsymTunnelTests()

// Covers github.com/projectcalico/calico/issues/13191: a flow that is
// asymmetric by design - the forward direction arrives natively on a data
// interface (e.g. BGP-routed via an external router), while the reply route
// points at the VXLAN overlay. The conntrack entry records the forward
// direction's ingress ifindex, and the reply must not be shortcut onto that
// iface as a raw, unencapsulated pod frame; it must leave via vxlan.calico.
func describeBPFAsymTunnelTests() bool {
	if !BPFMode() {
		return true
	}
	desc := "_BPF_ _BPF-SAFE_ BPF asymmetric routing with VXLAN overlay"
	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			felix1       *infrastructure.Felix
			w0, w1       *workload.Workload
			extRouter    *workload.Workload
		)

		BeforeEach(func() {
			infra = getInfra()
			opts := infrastructure.DefaultTopologyOptions()
			opts.FelixLogSeverity = "Debug"
			opts.ExtraEnvVars["FELIX_BPFLogLevel"] = "Debug"
			opts.IPIPMode = api.IPIPModeNever
			opts.VXLANMode = api.VXLANModeAlways
			opts.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(opts.IPPoolCIDR, opts.IPv6PoolCIDR)
			// Avoid felix restart mid-test, wait for the node resource to be
			// created before starting Felix.
			opts.DelayFelixStart = true
			opts.TriggerDelayedFelixStart = true
			tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)
			felix1 = tc.Felixes[1]

			// w0 exists so that felix[1] has a real remote *tunneled*
			// workload route for its IP.
			infrastructure.AssignIP("w0", "10.65.0.2", tc.Felixes[0].Hostname, calicoClient)
			w0 = workload.New(tc.Felixes[0], "w0", "default", "10.65.0.2", "8055", "tcp")
			Expect(w0.Start(infra)).NotTo(HaveOccurred())
			w0.ConfigureInInfra(infra)

			infrastructure.AssignIP("w1", "10.65.1.2", felix1.Hostname, calicoClient)
			w1 = workload.New(felix1, "w1", "default", "10.65.1.2", "8055", "tcp")
			Expect(w1.Start(infra)).NotTo(HaveOccurred())
			w1.ConfigureInInfra(infra)

			ensureAllNodesBPFProgramsAttached(tc.Felixes)

			By("setting up node's fake external iface")
			// We name the iface eth20 since such ifaces are treated by felix
			// as external to the node (they match the default
			// BPFDataIfacePattern). The netns behind it stands in for the
			// natively-routed path of the forward direction.
			extRouter = &workload.Workload{
				Name:          "extrtr",
				C:             felix1.Container,
				IP:            "192.168.20.1",
				Ports:         "57005", // 0xdead
				Protocol:      "tcp",
				InterfaceName: "eth20",
				MTU:           1500, // Need to match host MTU or felix will restart.
			}
			Expect(extRouter.Start(infra)).NotTo(HaveOccurred())

			felix1.Exec("ip", "addr", "add", "192.168.20.20/24", "dev", "eth20")
			// This multi-NIC scenario works only if the kernel's RPF check
			// is not strict.
			felix1.Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")
			Eventually(func() error {
				return felix1.ExecMayFail("sysctl", "-w", "net.ipv4.conf.eth20.rp_filter=2")
			}, "5s", "300ms").Should(Succeed())

			_, err := extRouter.RunCmd("ip", "addr", "add", "192.168.20.1/24", "dev", "eth0")
			Expect(err).NotTo(HaveOccurred())
			_, err = extRouter.RunCmd("ip", "route", "add", "10.65.1.0/24", "via", "192.168.20.20", "dev", "eth0")
			Expect(err).NotTo(HaveOccurred())

			// The conntrack entry must be created by eth20's from-HEP
			// program so that the forward direction's ingress ifindex is
			// recorded, so wait for the programs to be attached there.
			ensureBPFProgramsAttached(felix1, "eth20")
		})

		It("should keep symmetric overlay traffic flowing through the tunnel", func() {
			// Guards the conntrack fast path: for symmetric flows the
			// recorded ingress device is the tunnel itself and replies
			// must keep flowing (via the direct redirect, not the stack
			// fallback used for asymmetric flows).
			cc := &connectivity.Checker{}
			cc.ExpectSome(w0, w1)
			cc.ExpectSome(w1, w0)
			cc.CheckConnectivity()
		})

		It("should tunnel the reply of a flow whose forward direction ingressed natively", func() {
			// The failure mode: the reply forwarded verbatim to the iface
			// the forward direction came in on - an unencapsulated pod
			// frame that is unroutable on the underlay.
			dumpExt := felix1.AttachTCPDump("eth20")
			dumpExt.SetLogEnabled(true)
			dumpExt.AddMatcher("raw-reply", regexp.MustCompile(`10\.65\.1\.2\.30444 > 10\.65\.0\.2\.30444`))
			dumpExt.Start(infra, "-e", "udp", "and", "dst", "host", "10.65.0.2")

			dumpVxlan := felix1.AttachTCPDump("vxlan.calico")
			dumpVxlan.SetLogEnabled(true)
			dumpVxlan.AddMatcher("tunneled-reply", regexp.MustCompile(`10\.65\.1\.2\.30444 > 10\.65\.0\.2\.30444`))
			dumpVxlan.Start(infra, "udp", "and", "dst", "host", "10.65.0.2")

			for round := 1; round <= 3; round += 2 {
				By("Injecting the forward packet natively via eth20 (src = remote tunneled pod IP)")
				_, err := extRouter.RunCmd("pktgen", w0.IP, w1.IP, "udp",
					"--ip-id", fmt.Sprint(round), "--port-src", "30444", "--port-dst", "30444")
				Expect(err).NotTo(HaveOccurred())

				By("Sending the reply from the local workload")
				_, err = w1.RunCmd("pktgen", w1.IP, w0.IP, "udp",
					"--ip-id", fmt.Sprint(round+1), "--port-src", "30444", "--port-dst", "30444")
				Expect(err).NotTo(HaveOccurred())
			}

			Eventually(dumpVxlan.MatchCountFn("tunneled-reply"), "5s", "330ms").Should(BeNumerically("==", 2),
				"replies did not leave via the VXLAN tunnel")
			Consistently(dumpExt.MatchCountFn("raw-reply"), "2s", "330ms").Should(BeZero(),
				"replies leaked raw out of the forward direction's ingress iface")
		})
	})
}
