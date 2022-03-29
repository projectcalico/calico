// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe(
	"RPF tests",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {

		// Only BPF mode enforces strict RPF by default.
		if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
			// Non-BPF run.
			return
		}

		var (
			infra        infrastructure.DatastoreInfra
			felixes      []*infrastructure.Felix
			options      infrastructure.TopologyOptions
			calicoClient client.Interface
			w            *workload.Workload
			cc           *Checker
		)

		BeforeEach(func() {
			infra = getInfra()
			options = infrastructure.DefaultTopologyOptions()
		})

		AfterEach(func() {
			infra.Stop()
		})

		JustBeforeEach(func() {
			felixes, calicoClient = infrastructure.StartNNodeTopology(1, options, infra)

			wIP := "10.65.0.2"
			w = workload.Run(felixes[0], "w0", "default", wIP, "8055", "udp")
			w.WorkloadEndpoint.Labels = map[string]string{"name": w.Name}
			w.ConfigureInInfra(infra)

			pol := api.NewGlobalNetworkPolicy()
			pol.Namespace = "fv"
			pol.Name = "policy-1"
			pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
			pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
			pol.Spec.Selector = "all()"

			log.WithField("policy", dumpResource(pol)).Info("Creating policy")
			pol, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, pol, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			cc = &Checker{
				CheckSNAT: true,
				Protocol:  "udp",
			}
		})

		JustAfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				for _, felix := range felixes {
					felix.Exec("iptables-save", "-c")
					felix.Exec("ip", "link")
					felix.Exec("ip", "addr")
					felix.Exec("ip", "rule")
					felix.Exec("ip", "route")
				}
			}
		})

		It("should not allow packets from wrong direction with non-strict RPF on main device", func() {
			By("turning off RPF per device", func() {
				felixes[0].Exec("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
				felixes[0].Exec("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
				felixes[0].Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=0")
			})

			var external *workload.Workload

			By("setting up node's fake external ifaces", func() {
				// We name the ifaces ethXY since such ifaces are
				// treated by felix as external to the node
				//
				// Using a test-workload creates the namespaces and the
				// interfaces to emulate the host NICs

				external = &workload.Workload{
					Name:          "eth20",
					C:             felixes[0].Container,
					IP:            "192.168.20.1",
					Ports:         "57005", // 0xdead
					Protocol:      "udp",
					InterfaceName: "eth20",
				}
				err := external.Start()
				Expect(err).NotTo(HaveOccurred())

				// assign address to eth20 and add route to the .20 network
				felixes[0].Exec("ip", "route", "add", "192.168.20.0/24", "dev", "eth20")
				felixes[0].Exec("ip", "addr", "add", "10.0.0.20/32", "dev", "eth20")
				_, err = external.RunCmd("ip", "route", "add", "10.0.0.20/32", "dev", "eth0")
				Expect(err).NotTo(HaveOccurred())
				// Add a route to the test workload to the fake external
				// client emulated by the test-workload so that RPF can find a
				// valid route.
				_, err = external.RunCmd("ip", "route", "add", w.IP+"/32", "via", "10.0.0.20")
				Expect(err).NotTo(HaveOccurred())

				// Make sure that networking with the .20 network works
				cc.ResetExpectations()
				cc.Expect(Some, external, w)
				cc.CheckConnectivity()
			})

			By("testing with bad source", func() {
				fakeWorkloadIP := "10.65.15.15"

				tcpdumpHEP := felixes[0].AttachTCPDump("eth20")
				tcpdumpHEP.SetLogEnabled(true)
				matcherHEP := fmt.Sprintf("IP %s\\.30446 > %s\\.30446: UDP", fakeWorkloadIP, w.IP)
				tcpdumpHEP.AddMatcher("UDP-30446", regexp.MustCompile(matcherHEP))
				tcpdumpHEP.Start()
				defer tcpdumpHEP.Stop()

				tcpdumpWl := w.AttachTCPDump()
				tcpdumpWl.SetLogEnabled(true)
				matcherWl := fmt.Sprintf("IP %s\\.30446 > %s\\.30446: UDP", fakeWorkloadIP, w.IP)
				tcpdumpWl.AddMatcher("UDP-30446", regexp.MustCompile(matcherWl))
				tcpdumpWl.Start()
				defer tcpdumpWl.Stop()

				_, err := external.RunCmd("/pktgen", fakeWorkloadIP, w.IP, "udp",
					"--port-src", "30446", "--port-dst", "30446", "--ip-id", "666")
				Expect(err).NotTo(HaveOccurred())

				// Expect to see the packet from the .20 network at eth20 before RPF
				Eventually(func() int { return tcpdumpHEP.MatchCount("UDP-30446") }, "1s", "100ms").
					Should(BeNumerically("==", 1), "HEP - "+matcherHEP)

				// Expect not to receive the packet from the .20 as it is dropped by RPF.
				Consistently(func() int { return tcpdumpWl.MatchCount("UDP-30446") }, "1s", "100ms").
					Should(BeNumerically("==", 0), "Wl - "+matcherWl)
			})
		})
	})
