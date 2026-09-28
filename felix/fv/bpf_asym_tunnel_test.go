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

//go:build fvtests

package fv_test

import (
	"context"
	"fmt"
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = describeBPFAsymmetricTunnelTests()

// Covers #13191: the forward direction enters through a native data
// interface, while the reply route points at the VXLAN overlay.  The reply
// must not reuse the native ingress interface as a raw egress device.
func describeBPFAsymmetricTunnelTests() bool {
	if !BPFMode() {
		return true
	}

	return infrastructure.DatastoreDescribe(
		"_BPF_ _BPF-SAFE_ BPF asymmetric routing with VXLAN overlay",
		[]apiconfig.DatastoreType{apiconfig.Kubernetes},
		func(getInfra infrastructure.InfraFactory) {
			var (
				infra        infrastructure.DatastoreInfra
				tc           infrastructure.TopologyContainers
				calicoClient client.Interface
				local        *workload.Workload
				remote       *workload.Workload
				external     *workload.Workload
			)

			BeforeEach(func() {
				infra = getInfra()
				opts := infrastructure.DefaultTopologyOptions()
				opts.FelixLogSeverity = "Debug"
				opts.ExtraEnvVars["FELIX_BPFLogLevel"] = "Debug"
				opts.IPIPMode = api.IPIPModeNever
				opts.VXLANMode = api.VXLANModeAlways
				opts.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(opts.IPPoolCIDR, opts.IPv6PoolCIDR)
				opts.DelayFelixStart = true
				opts.TriggerDelayedFelixStart = true
				tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)

				assignIP := func(address, handle, hostname string) {
					err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
						IP:       cnet.MustParseIP(address),
						HandleID: &handle,
						Attrs: map[string]string{
							ipam.AttributeNode: hostname,
						},
						Hostname: hostname,
					})
					Expect(err).NotTo(HaveOccurred())
				}

				remote = workload.New(tc.Felixes[0], "remote", "default", "10.65.0.2", "8055", "tcp")
				assignIP(remote.IP, remote.Name, tc.Felixes[0].Hostname)
				Expect(remote.Start()).NotTo(HaveOccurred())
				remote.ConfigureInInfra(infra)

				local = workload.New(tc.Felixes[1], "local", "default", "10.65.1.2", "8055", "tcp")
				assignIP(local.IP, local.Name, tc.Felixes[1].Hostname)
				Expect(local.Start()).NotTo(HaveOccurred())
				local.ConfigureInInfra(infra)

				ensureAllNodesBPFProgramsAttached(tc.Felixes)

				// eth20 represents the native router connected to the node.  Its name
				// matches the default BPF data-interface pattern, so the from-HEP
				// program records its ifindex when the forward packet enters the node.
				external = &workload.Workload{
					Name:          "extrtr",
					C:             tc.Felixes[1].Container,
					IP:            "192.168.20.1",
					Ports:         "57005",
					Protocol:      "tcp",
					InterfaceName: "eth20",
					MTU:           1500,
				}
				Expect(external.Start()).NotTo(HaveOccurred())

				tc.Felixes[1].Exec("ip", "addr", "add", "192.168.20.20/24", "dev", "eth20")
				tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")
				Eventually(func() error {
					return tc.Felixes[1].ExecMayFail("sysctl", "-w", "net.ipv4.conf.eth20.rp_filter=2")
				}, "5s", "300ms").Should(Succeed())

				_, err := external.RunCmd("ip", "addr", "add", "192.168.20.1/24", "dev", "eth0")
				Expect(err).NotTo(HaveOccurred())
				_, err = external.RunCmd("ip", "route", "add", local.IP+"/32", "via", "192.168.20.20", "dev", "eth0")
				Expect(err).NotTo(HaveOccurred())

				ensureBPFProgramsAttached(tc.Felixes[1], "eth20")
			})

			AfterEach(func() {
				tc.Stop()
				infra.Stop()
			})

			It("should keep symmetric overlay traffic flowing through the tunnel", func() {
				cc := &connectivity.Checker{}
				cc.ExpectSome(remote, local)
				cc.ExpectSome(local, remote)
				cc.CheckConnectivity()
			})

			It("should tunnel replies whose forward direction entered natively", func() {
				rawReply := fmt.Sprintf(`%s\.30444 > %s\.30444`, local.IP, remote.IP)

				dumpExternal := tc.Felixes[1].AttachTCPDump("eth20")
				dumpExternal.SetLogEnabled(true)
				dumpExternal.AddMatcher("raw-reply", regexp.MustCompile(rawReply))
				dumpExternal.Start("-e", "udp", "and", "dst", "host", remote.IP)
				defer dumpExternal.Stop()

				dumpVXLAN := tc.Felixes[1].AttachTCPDump("vxlan.calico")
				dumpVXLAN.SetLogEnabled(true)
				dumpVXLAN.AddMatcher("tunneled-reply", regexp.MustCompile(rawReply))
				dumpVXLAN.Start("udp", "and", "dst", "host", remote.IP)
				defer dumpVXLAN.Stop()

				for round := 1; round <= 3; round += 2 {
					By("injecting the forward packet through the native interface")
					_, err := external.RunCmd("pktgen", remote.IP, local.IP, "udp",
						"--ip-id", fmt.Sprint(round), "--port-src", "30444", "--port-dst", "30444")
					Expect(err).NotTo(HaveOccurred())

					By("sending the reply from the local workload")
					_, err = local.RunCmd("pktgen", local.IP, remote.IP, "udp",
						"--ip-id", fmt.Sprint(round+1), "--port-src", "30444", "--port-dst", "30444")
					Expect(err).NotTo(HaveOccurred())
				}

				Eventually(dumpVXLAN.MatchCountFn("tunneled-reply"), "5s", "330ms").
					Should(BeNumerically("==", 2), "replies did not leave via the VXLAN tunnel")
				Consistently(dumpExternal.MatchCountFn("raw-reply"), "2s", "330ms").
					Should(BeZero(), "replies leaked raw out of the native ingress interface")
			})
		})
}
