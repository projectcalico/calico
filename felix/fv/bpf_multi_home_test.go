// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	_ = describeBPFMultiHomedTests()
)

func describeBPFMultiHomedTests() bool {
	if !BPFMode() {
		return true
	}
	desc := "_BPF_ _BPF-SAFE_ BPF multi-homed tests"
	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			Felix        *infrastructure.Felix
			w            *workload.Workload
		)

		BeforeEach(func() {
			infra = getInfra()
			opts := infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever
			opts.SimulateBIRDRoutes = true
			opts.FelixLogSeverity = "Debug"
			opts.ExtraEnvVars["FELIX_BPFLogLevel"] = "Debug"
			tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)
			Felix = tc.Felixes[0]

			w = workload.New(Felix, "workload", "default", "10.65.0.2", "8055", "tcp")
			err := w.Start()
			Expect(err).NotTo(HaveOccurred())
			w.ConfigureInInfra(infra)

			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       cnet.MustParseIP(w.IP),
				HandleID: &w.Name,
				Attrs: map[string]string{
					ipam.AttributeNode: Felix.Hostname,
				},
				Hostname: Felix.Hostname,
			})
			Expect(err).NotTo(HaveOccurred())
			ensureBPFProgramsAttached(tc.Felixes[0])
		})

		AfterEach(func() {
			tc.Stop()
			infra.Stop()
		})

		JustAfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				Felix.Exec("conntrack", "-L", "-f", "ipv6")
				Felix.Exec("ip6tables-save", "-c")
				Felix.Exec("ip", "link")
				Felix.Exec("ip", "addr")
				Felix.Exec("ip", "rule")
				Felix.Exec("ip", "route", "show", "table", "all")
				Felix.Exec("calico-bpf", "routes", "dump")
			}
		})

		It("should allow asymmetric routing", func() {
			By("setting up node's fake external iface")
			// We name the iface eth20 since such ifaces are
			// treated by felix as external to the node
			//
			// Using a test-workload creates the namespaces and the
			// interfaces to emulate the host NICs
			eth20 := &workload.Workload{
				Name:          "eth20",
				C:             Felix.Container,
				IP:            "192.168.20.1",
				Ports:         "57005", // 0xdead
				Protocol:      "tcp",
				InterfaceName: "eth20",
				MTU:           1500, // Need to match host MTU or felix will restart.
			}
			err := eth20.Start()
			Expect(err).NotTo(HaveOccurred())

			eth30 := &workload.Workload{
				Name:          "eth30",
				C:             Felix.Container,
				IP:            "192.168.30.1",
				Ports:         "57005", // 0xdead
				Protocol:      "tcp",
				InterfaceName: "eth30",
				MTU:           1500, // Need to match host MTU or felix will restart.
			}
			err = eth30.Start()
			Expect(err).NotTo(HaveOccurred())

			// assign address to eth20 and add route to the .20 network
			// tc.Felixes[1].Exec("ip", "route", "add", eth20Route, "dev", "eth20")
			// This multi-NIC scenario works only if the kernel's RPF check
			// is not strict so we need to override it for the test and must
			// be set properly when product is deployed. We reply on
			// iptables to do require check for us.
			Felix.Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")

			Eventually(func() error {
				return Felix.ExecMayFail("sysctl", "-w", "net.ipv4.conf.eth20.rp_filter=2")
			}, "5s", "300ms").Should(Succeed())

			Felix.Exec("ip", "addr", "add", "192.168.20.20/24", "dev", "lo")
			Felix.Exec("ip", "addr", "add", "192.168.30.30/24", "dev", "eth30")
			Felix.Exec("bash", "-c", "echo 200 container_route >> /etc/iproute2/rt_tables")
			Felix.Exec("ip", "route", "add", "10.65.1.0/24", "dev", "eth20",
				"table", "container_route")
			Felix.Exec("ip", "rule", "add", "from", w.IP, "table", "container_route")
			Felix.Exec("ip", "route", "flush", "cache")
			Felix.Exec("ip", "neigh", "add", "10.65.1.3", "lladdr", "ee:ee:ee:ee:ee:ee", "dev", "eth20")

			Felix.Exec("ip", "route", "add", "192.168.30.1/32", "dev", "eth30")

			_, err = eth20.RunCmd("ip", "route", "add", "blackhole", "10.65.1.0/32")
			Expect(err).NotTo(HaveOccurred())

			_, err = eth30.RunCmd("ip", "addr", "add", "192.168.30.1/24", "dev", "eth0")
			Expect(err).NotTo(HaveOccurred())
			_, err = eth30.RunCmd("ip", "route", "add", "10.65.0.0/24", "via", "192.168.30.30", "dev", "eth0")
			Expect(err).NotTo(HaveOccurred())
			Felix.Exec("sysctl", "-w", "net.ipv4.conf.eth30.rp_filter=2")

			_, err = w.RunCmd("bash", "-c", "echo 200 bh_route >> /etc/iproute2/rt_tables")
			Expect(err).NotTo(HaveOccurred())
			_, err = w.RunCmd("ip", "rule", "add", "from", "10.65.1.3", "table", "bh_route", "priority", "1")
			Expect(err).NotTo(HaveOccurred())
			_, err = w.RunCmd("ip", "rule", "del", "from", "all", "lookup", "local", "priority", "0")
			Expect(err).NotTo(HaveOccurred())
			_, err = w.RunCmd("ip", "rule", "add", "from", "all", "lookup", "local", "priority", "2")
			Expect(err).NotTo(HaveOccurred())
			_, err = w.RunCmd("ip", "route", "add", "blackhole", w.IP+"/32")
			Expect(err).NotTo(HaveOccurred())

			err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       cnet.MustParseIP("10.65.1.3"),
				HandleID: &w.Name,
				Attrs: map[string]string{
					ipam.AttributeNode: tc.Felixes[1].Hostname,
				},
				Hostname: tc.Felixes[1].Hostname,
			})
			Expect(err).NotTo(HaveOccurred())

			dump20 := Felix.AttachTCPDump("eth20")
			dump20.SetLogEnabled(true)
			dump20.AddMatcher("eth20-egress", regexp.MustCompile("10.65.0.2.30444 > 10.65.1.3.30444: UDP"))
			dump20.Start("-v", "udp", "and", "dst", "host", "10.65.1.3")
			defer dump20.Stop()

			dump30 := Felix.AttachTCPDump("eth30")
			dump30.SetLogEnabled(true)
			dump30.AddMatcher("eth30-ingress", regexp.MustCompile("10.65.1.3.30444 > 10.65.0.2.30444: UDP"))
			dump30.Start("-v", "udp", "and", "dst", "host", "10.65.0.2")
			defer dump30.Stop()

			By("Sending packet from the workload via eth20")
			_, err = w.RunCmd("pktgen", w.IP, "10.65.1.3", "udp", "--ip-id", "1",
				"--port-src", "30444", "--port-dst", "30444")
			Expect(err).NotTo(HaveOccurred())

			By("Sending reply via eth30")
			_, err = eth30.RunCmd("pktgen", "10.65.1.3", w.IP, "udp", "--ip-id", "2",
				"--port-src", "30444", "--port-dst", "30444")
			Expect(err).NotTo(HaveOccurred())

			By("Sending packet from the workload via eth20")
			_, err = w.RunCmd("pktgen", w.IP, "10.65.1.3", "udp", "--ip-id", "3",
				"--port-src", "30444", "--port-dst", "30444")
			Expect(err).NotTo(HaveOccurred())

			By("Sending reply via eth30")
			_, err = eth30.RunCmd("pktgen", "10.65.1.3", w.IP, "udp", "--ip-id", "4",
				"--port-src", "30444", "--port-dst", "30444")
			Expect(err).NotTo(HaveOccurred())

			Eventually(dump20.MatchCountFn("eth20-egress"), "5s", "330ms").Should(BeNumerically("==", 2))
			Eventually(dump30.MatchCountFn("eth30-ingress"), "5s", "330ms").Should(BeNumerically("==", 2))
		})
	})
}
