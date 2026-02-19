// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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
	"regexp"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	options2 "github.com/projectcalico/calico/libcalico-go/lib/options"
)

func describeBPFSpecialTests(s *bpfTestContext) {
	_ = s.testOpts.tunnel != "vxlan" && Describe("with BPF disabled to begin with", func() {
		var pc *PersistentConnection

		BeforeEach(func() {
			s.options.TestManagesBPF = true
			s.setupCluster()

			// Default to Allow...
			pol := api.NewGlobalNetworkPolicy()
			pol.Namespace = "fv"
			pol.Name = "policy-1"
			pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
			pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
			pol.Spec.Selector = "all()"
			pol = s.createPolicy(pol)

			pc = nil
			if NFTMode() && s.testOpts.ipv6 && !s.testOpts.dsr && s.testOpts.tunnel == "none" && s.testOpts.connTimeEnabled {
				// In NFT mode, we add the kube-proxy tables.
				s.tc.Felixes[0].Exec("nft", "add", "table", "ip", "kube-proxy")
				s.tc.Felixes[0].Exec("nft", "add", "chain", "ip", "kube-proxy", "KUBE-TEST", "{ type filter hook forward priority 0 ; }")
				s.tc.Felixes[0].Exec("nft", "add", "table", "ip6", "kube-proxy")
				s.tc.Felixes[0].Exec("nft", "add", "chain", "ip6", "kube-proxy", "KUBE-TEST", "{ type filter hook forward priority 0 ; }")
			}
		})

		AfterEach(func() {
			if pc != nil {
				pc.Stop()
			}
		})

		enableBPF := func() {
			By("Enabling BPF")
			// Some tests start with a felix config pre-created, try to update it...
			fc, err := s.calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
			bpfEnabled := true
			if err == nil {
				fc.Spec.BPFEnabled = &bpfEnabled
				_, err := s.calicoClient.FelixConfigurations().Update(context.Background(), fc, options2.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			} else {
				// Fall back on creating it...
				fc = api.NewFelixConfiguration()
				fc.Name = "default"
				fc.Spec.BPFEnabled = &bpfEnabled
				fc, err = s.calicoClient.FelixConfigurations().Create(context.Background(), fc, options2.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}

			// Wait for BPF to be active.
			ensureAllNodesBPFProgramsAttached(s.tc.Felixes)
			if NFTMode() && s.testOpts.ipv6 && !s.testOpts.dsr && s.testOpts.tunnel == "none" && s.testOpts.connTimeEnabled {
				Eventually(func() string {
					out, _ := s.tc.Felixes[0].ExecOutput("nft", "list", "tables")
					return out
				}, "15s", "1s").ShouldNot(ContainSubstring("kube-proxy"))
			}
		}

		expectPongs := func() {
			count := pc.PongCount()
			EventuallyWithOffset(1, pc.PongCount, "60s").Should(
				BeNumerically(">", count),
				"Expected to see pong responses on the connection but didn't receive any")
			log.Info("Pongs received")
		}

		if s.testOpts.protocol == "tcp" && (s.testOpts.dsr || s.testOpts.ipv6) {
			verifyConnectivityWhileEnablingBPF := func(from, to *workload.Workload) {
				By("Starting persistent connection")
				pc = from.StartPersistentConnection(to.IP, 8055, workload.PersistentConnectionOpts{
					MonitorConnectivity: true,
					Timeout:             60 * time.Second,
				})

				By("having initial connectivity", expectPongs)
				By("enabling BPF mode", enableBPF) // Waits for BPF programs to be installed
				By("still having connectivity on the existing connection", expectPongs)
			}

			It("should keep a connection up between hosts when BPF is enabled", func() {
				verifyConnectivityWhileEnablingBPF(s.hostW[0], s.hostW[1])
			})

			It("should keep a connection up between workloads on different hosts when BPF is enabled", func() {
				verifyConnectivityWhileEnablingBPF(s.w[0][0], s.w[1][0])
			})

			It("should keep a connection up between hosts and remote workloads when BPF is enabled", func() {
				verifyConnectivityWhileEnablingBPF(s.hostW[0], s.w[1][0])
			})

			It("should keep a connection up between hosts and local workloads when BPF is enabled", func() {
				verifyConnectivityWhileEnablingBPF(s.hostW[0], s.w[0][0])
			})
		}
	})

	Describe("3rd party CNI", func() {
		// We do not use tunnel in such environments, no need to test.
		if s.testOpts.tunnel != "none" {
			return
		}

		BeforeEach(func() {
			// To mimic 3rd party CNI, we do not install IPPools and set the source to
			// learn routes to WorkloadIPs as IPAM/CNI is not going to provide either.
			s.options.UseIPPools = false
			s.options.SimulateBIRDRoutes = true
			s.options.ExtraEnvVars["FELIX_ROUTESOURCE"] = "WorkloadIPs"
			s.setupCluster()
		})

		Describe("CNI installs NAT outgoing iptable rules", func() {
			var extWorkload *workload.Workload
			BeforeEach(func() {
				if NFTMode() {
					Skip("NFT does not support third-party rules")
				}

				c := infrastructure.RunExtClient(s.infra, "ext-workload")
				extWorkload = &workload.Workload{
					C:        c,
					Name:     "ext-workload",
					Ports:    "4321",
					Protocol: s.testOpts.protocol,
					IP:       s.containerIP(c),
				}

				err := extWorkload.Start(s.infra) // FIXME
				Expect(err).NotTo(HaveOccurred())

				tool := "iptables"
				if s.testOpts.ipv6 {
					tool = "ip6tables"
				}

				for _, felix := range s.tc.Felixes {
					felix.Exec(tool, "-t", "nat", "-A", "POSTROUTING", "-d", extWorkload.IP, "-j", "MASQUERADE")
				}
			})

			It("should have connectivity to external workload", func() {
				By("allowing any traffic", func() {
					pol := api.NewGlobalNetworkPolicy()
					pol.Namespace = "fv"
					pol.Name = "policy-1"
					pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
					pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
					pol.Spec.Selector = "all()"

					pol = s.createPolicy(pol)

					s.cc.ExpectSome(s.w[1][0], s.w[0][0])
					s.cc.ExpectSome(s.w[1][1], s.w[0][0])
					s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
					s.cc.ResetExpectations()
				})

				By("checking connectivity to the external workload", func() {
					s.cc.Expect(Some, s.w[0][0], extWorkload, ExpectWithPorts(4321), ExpectWithSrcIPs(s.felixIP(0)))
					s.cc.Expect(Some, s.w[1][0], extWorkload, ExpectWithPorts(4321), ExpectWithSrcIPs(s.felixIP(1)))
					s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
				})
			})

			AfterEach(func() {
				extWorkload.Stop()
			})
		})
	})

	Context("With host interface not managed by calico", func() {
		BeforeEach(func() {
			s.setupCluster()
			poolName := infrastructure.DefaultIPPoolName
			if s.testOpts.ipv6 {
				poolName = infrastructure.DefaultIPv6PoolName
			}
			pool, err := s.calicoClient.IPPools().Get(context.TODO(), poolName, options2.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			pool.Spec.NATOutgoing = false
			pool, err = s.calicoClient.IPPools().Update(context.TODO(), pool, options2.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			pol := api.NewGlobalNetworkPolicy()
			pol.Name = "allow-all"
			pol.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			pol.Spec.Egress = []api.Rule{{Action: api.Allow}}
			pol.Spec.Selector = "all()"

			pol = s.createPolicy(pol)
		})

		if s.testOpts.protocol == "udp" || s.testOpts.tunnel == "ipip" || s.testOpts.ipv6 {
			return
		}
		It("should allow traffic from workload to this host device", func() {
			var (
				test30            *workload.Workload
				test30IP          string
				test30ExtIP       string
				test30Route, mask string
			)
			if s.testOpts.ipv6 {
				test30IP = "fd00::3001"
				test30ExtIP = "1000::0030"
				test30Route = "fd00::3000/120"
				mask = "128"
			} else {
				test30IP = "192.168.30.1"
				test30ExtIP = "10.0.0.30"
				test30Route = "192.168.30.0/24"
				mask = "32"
			}

			test30 = &workload.Workload{
				Name:          "test30",
				C:             s.tc.Felixes[1].Container,
				IP:            test30IP,
				Ports:         "57005", // 0xdead
				Protocol:      s.testOpts.protocol,
				InterfaceName: "test30",
				MTU:           1500, // Need to match host MTU or felix will restart.
			}
			err := test30.Start(s.infra)
			Expect(err).NotTo(HaveOccurred())
			// assign address to test30 and add route to the .30 network
			if s.testOpts.ipv6 {
				s.tc.Felixes[1].Exec("ip", "-6", "route", "add", test30Route, "dev", "test30")
				s.tc.Felixes[1].Exec("ip", "-6", "addr", "add", test30ExtIP+"/"+mask, "dev", "test30")
				_, err = test30.RunCmd("ip", "-6", "route", "add", test30ExtIP+"/"+mask, "dev", "eth0")
				Expect(err).NotTo(HaveOccurred())
				// Add a route to the test workload to the fake external
				// client emulated by the test-workload
				_, err = test30.RunCmd("ip", "-6", "route", "add", s.w[1][1].IP+"/"+mask, "via", test30ExtIP)
				Expect(err).NotTo(HaveOccurred())

			} else {
				s.tc.Felixes[1].Exec("ip", "route", "add", test30Route, "dev", "test30")
				s.tc.Felixes[1].Exec("ip", "addr", "add", test30ExtIP+"/"+mask, "dev", "test30")
				_, err = test30.RunCmd("ip", "route", "add", test30ExtIP+"/"+mask, "dev", "eth0")
				Expect(err).NotTo(HaveOccurred())
				// Add a route to the test workload to the fake external
				// client emulated by the test-workload
				_, err = test30.RunCmd("ip", "route", "add", s.w[1][1].IP+"/"+mask, "via", test30ExtIP)
				Expect(err).NotTo(HaveOccurred())

			}

			s.cc.ResetExpectations()
			s.cc.ExpectSome(s.w[1][1], TargetIP(test30.IP), 0xdead)
			s.cc.CheckConnectivity()
		})
	})

	Context("With BPFEnforceRPF=Strict", func() {
		BeforeEach(func() {
			s.options.ExtraEnvVars["FELIX_BPFEnforceRPF"] = "Strict"
			s.setupCluster()
		})

		// Test doesn't use services so ignore the runs with those turned on.
		if s.testOpts.protocol == "udp" && !s.testOpts.connTimeEnabled && !s.testOpts.dsr {
			It("should not be able to spoof UDP", func() {
				if !s.testOpts.ipv6 {
					By("Disabling dev RPF")
					setRPF(s.tc.Felixes, s.testOpts.tunnel, 0, 0)
					s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf."+s.w[1][0].InterfaceName+".rp_filter=0")
					s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf."+s.w[1][1].InterfaceName+".rp_filter=0")
				}

				By("allowing any traffic", func() {
					pol := api.NewGlobalNetworkPolicy()
					pol.Name = "allow-all"
					pol.Spec.Ingress = []api.Rule{{Action: api.Allow}}
					pol.Spec.Egress = []api.Rule{{Action: api.Allow}}
					pol.Spec.Selector = "all()"

					pol = s.createPolicy(pol)

					s.cc.ExpectSome(s.w[1][0], s.w[0][0])
					s.cc.ExpectSome(s.w[1][1], s.w[0][0])
					s.cc.CheckConnectivity()
				})

				By("testing that packet sent by another workload is dropped", func() {
					tcpdump := s.w[0][0].AttachTCPDump()
					tcpdump.SetLogEnabled(true)
					ipVer := "IP"
					if s.testOpts.ipv6 {
						ipVer = "IP6"
					}

					matcher := fmt.Sprintf("%s %s\\.30444 > %s\\.30444: UDP", ipVer, s.w[1][0].IP, s.w[0][0].IP)
					tcpdump.AddMatcher("UDP-30444", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra, s.testOpts.protocol, "port", "30444", "or", "port", "30445")

					// send a packet from the correct workload to create a conntrack entry
					_, err := s.w[1][0].RunCmd("pktgen", s.w[1][0].IP, s.w[0][0].IP, "udp",
						"--port-src", "30444", "--port-dst", "30444")
					Expect(err).NotTo(HaveOccurred())

					// We must eventually see the packet at the target
					Eventually(func() int { return tcpdump.MatchCount("UDP-30444") }).
						Should(BeNumerically("==", 1), matcher)

					// Send a spoofed packet from a different pod. Since we hit the
					// conntrack we would not do the WEP only RPF check.
					_, err = s.w[1][1].RunCmd("pktgen", s.w[1][0].IP, s.w[0][0].IP, "udp",
						"--port-src", "30444", "--port-dst", "30444")
					Expect(err).NotTo(HaveOccurred())

					// Since the packet will get dropped, we would not see it at the dest.
					// So we send another good packet from the spoofing workload, that we
					// will see at the dest.
					matcher2 := fmt.Sprintf("%s %s\\.30445 > %s\\.30445: UDP", ipVer, s.w[1][1].IP, s.w[0][0].IP)
					tcpdump.AddMatcher("UDP-30445", regexp.MustCompile(matcher2))

					_, err = s.w[1][1].RunCmd("pktgen", s.w[1][1].IP, s.w[0][0].IP, "udp",
						"--port-src", "30445", "--port-dst", "30445")
					Expect(err).NotTo(HaveOccurred())

					// Wait for the good packet from the bad workload
					Eventually(func() int { return tcpdump.MatchCount("UDP-30445") }).
						Should(BeNumerically("==", 1), matcher2)

					// Check that we have not seen the spoofed packet. If there was not
					// packet reordering, which in our setup is guaranteed not to happen,
					// we know that the spoofed packet was dropped.
					Expect(tcpdump.MatchCount("UDP-30444")).To(BeNumerically("==", 1), matcher)
				})

				var (
					eth20, eth30                           *workload.Workload
					eth20IP, eth30IP, ipVer                string
					eth20ExtIP, eth30ExtIP, fakeWorkloadIP string
					eth20Route, eth30Route, mask           string
					family                                 int
				)

				defer func() {
					if eth20 != nil {
						eth20.Stop()
					}
					if eth30 != nil {
						eth30.Stop()
					}
				}()

				// Now, set up a topology that mimics two host NICs by creating one workload per fake NIC.
				// We then move a route between the two NICs to pretend that there's a workload behind
				// one or other of them.
				//
				//      eth20 = workload used as a NIC
				//         - eth20 ------ movable fake workload 10.65.15.15
				//       192.168.20.1
				//       /
				//    10.0.0.20
				// Felix
				//    10.0.0.30
				//       \
				//       192.168.30.1
				//         - eth30 ------ movable fake workload 10.65.15.15
				//      eth30 = workload used as a NIC
				//

				By("setting up node's fake external ifaces", func() {
					// We name the ifaces ethXY since such ifaces are
					// treated by felix as external to the node
					//
					// Using a test-workload creates the namespaces and the
					// interfaces to emulate the host NICs

					if s.testOpts.ipv6 {
						eth20IP = "fd00::2001"
						eth30IP = "fd00::3001"
						eth20ExtIP = "1000::0020"
						eth30ExtIP = "1000::0030"
						eth20Route = "fd00::2000/120"
						eth30Route = "fd00::3000/120"
						mask = "128"
						ipVer = "IP6"
						fakeWorkloadIP = "dead:beef::15:15"
						family = 6
					} else {
						eth20IP = "192.168.20.1"
						eth30IP = "192.168.30.1"
						eth20ExtIP = "10.0.0.20"
						eth30ExtIP = "10.0.0.30"
						eth20Route = "192.168.20.0/24"
						eth30Route = "192.168.30.0/24"
						mask = "32"
						ipVer = "IP"
						fakeWorkloadIP = "10.65.15.15"
						family = 4
					}

					eth20 = &workload.Workload{
						Name:          "eth20",
						C:             s.tc.Felixes[1].Container,
						IP:            eth20IP,
						Ports:         "57005", // 0xdead
						Protocol:      s.testOpts.protocol,
						InterfaceName: "eth20",
						MTU:           1500, // Need to match host MTU or felix will restart.
					}
					err := eth20.Start(s.infra)
					Expect(err).NotTo(HaveOccurred())

					// assign address to eth20 and add route to the .20 network
					if s.testOpts.ipv6 {
						s.tc.Felixes[1].Exec("ip", "-6", "route", "add", eth20Route, "dev", "eth20")
						s.tc.Felixes[1].Exec("ip", "-6", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
						_, err = eth20.RunCmd("ip", "-6", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
						Expect(err).NotTo(HaveOccurred())
						// Add a route to the test workload to the fake external
						// client emulated by the test-workload
						_, err = eth20.RunCmd("ip", "-6", "route", "add", s.w[1][1].IP+"/"+mask, "via", eth20ExtIP)
						Expect(err).NotTo(HaveOccurred())
					} else {
						s.tc.Felixes[1].Exec("ip", "route", "add", eth20Route, "dev", "eth20")
						s.tc.Felixes[1].Exec("ip", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
						_, err = eth20.RunCmd("ip", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
						Expect(err).NotTo(HaveOccurred())
						// Add a route to the test workload to the fake external
						// client emulated by the test-workload
						_, err = eth20.RunCmd("ip", "route", "add", s.w[1][1].IP+"/"+mask, "via", eth20ExtIP)
						Expect(err).NotTo(HaveOccurred())
					}

					eth30 = &workload.Workload{
						Name:          "eth30",
						C:             s.tc.Felixes[1].Container,
						IP:            eth30IP,
						Ports:         "57005", // 0xdead
						Protocol:      s.testOpts.protocol,
						InterfaceName: "eth30",
						MTU:           1500, // Need to match host MTU or felix will restart.
					}
					err = eth30.Start(s.infra)
					Expect(err).NotTo(HaveOccurred())

					// assign address to eth30 and add route to the .30 network
					if s.testOpts.ipv6 {
						s.tc.Felixes[1].Exec("ip", "-6", "route", "add", eth30Route, "dev", "eth30")
						s.tc.Felixes[1].Exec("ip", "-6", "addr", "add", eth30ExtIP+"/"+mask, "dev", "eth30")
						_, err = eth30.RunCmd("ip", "-6", "route", "add", eth30ExtIP+"/"+mask, "dev", "eth0")
						Expect(err).NotTo(HaveOccurred())
						// Add a route to the test workload to the fake external
						// client emulated by the test-workload
						_, err = eth30.RunCmd("ip", "-6", "route", "add", s.w[1][1].IP+"/"+mask, "via", eth30ExtIP)
						Expect(err).NotTo(HaveOccurred())
					} else {
						s.tc.Felixes[1].Exec("ip", "route", "add", eth30Route, "dev", "eth30")
						s.tc.Felixes[1].Exec("ip", "addr", "add", eth30ExtIP+"/"+mask, "dev", "eth30")
						_, err = eth30.RunCmd("ip", "route", "add", eth30ExtIP+"/"+mask, "dev", "eth0")
						Expect(err).NotTo(HaveOccurred())
						// Add a route to the test workload to the fake external
						// client emulated by the test-workload
						_, err = eth30.RunCmd("ip", "route", "add", s.w[1][1].IP+"/"+mask, "via", eth30ExtIP)
						Expect(err).NotTo(HaveOccurred())
					}

					// Make sure Felix adds a BPF program before we run the test, otherwise the conntrack
					// may be crated in the reverse direction.  Since we're pretending to be a host interface
					// Felix doesn't block traffic by default.
					Eventually(s.tc.Felixes[1].NumTCBPFProgsFn("eth20"), "30s", "200ms").Should(Equal(2))
					Eventually(s.tc.Felixes[1].NumTCBPFProgsFn("eth30"), "30s", "200ms").Should(Equal(2))

					// Make sure that networking with the .20 and .30 networks works
					s.cc.ResetExpectations()
					s.cc.ExpectSome(s.w[1][1], TargetIP(eth20.IP), 0xdead)
					s.cc.ExpectSome(s.w[1][1], TargetIP(eth30.IP), 0xdead)
					s.cc.CheckConnectivity()
				})

				By("testing that external traffic updates the RPF check if routing changes", func() {
					// set the route to the fake workload to .20 network
					if s.testOpts.ipv6 {
						s.tc.Felixes[1].Exec("ip", "-6", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth20")
					} else {
						s.tc.Felixes[1].Exec("ip", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth20")
					}

					tcpdump := s.w[1][1].AttachTCPDump()
					tcpdump.SetLogEnabled(true)
					matcher := fmt.Sprintf("%s %s\\.30446 > %s\\.30446: UDP", ipVer, fakeWorkloadIP, s.w[1][1].IP)
					tcpdump.AddMatcher("UDP-30446", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra)

					_, err := eth20.RunCmd("pktgen", fakeWorkloadIP, s.w[1][1].IP, "udp",
						"--port-src", "30446", "--port-dst", "30446")
					Expect(err).NotTo(HaveOccurred())

					// Expect to receive the packet from the .20 as the routing is correct
					Eventually(func() int { return tcpdump.MatchCount("UDP-30446") }).
						Should(BeNumerically("==", 1), matcher)

					ctBefore := dumpCTMapsAny(family, s.tc.Felixes[1])

					var k conntrack.KeyInterface
					if s.testOpts.ipv6 {
						k = conntrack.NewKeyV6(17, net.ParseIP(s.w[1][1].IP).To16(), 30446,
							net.ParseIP(fakeWorkloadIP).To16(), 30446)
					} else {
						k = conntrack.NewKey(17, net.ParseIP(s.w[1][1].IP).To4(), 30446,
							net.ParseIP(fakeWorkloadIP).To4(), 30446)
					}
					Expect(ctBefore).To(HaveKey(k))

					// XXX Since the same code is used to do the drop of spoofed
					// packet between pods, we do not repeat it here as it is not 100%
					// bulletproof.
					//
					// We should perhaps compare the iptables counter and see if the
					// packet was dropped by the RPF check.

					// Change the routing to be from the .30
					if s.testOpts.ipv6 {
						s.tc.Felixes[1].Exec("ip", "-6", "route", "del", fakeWorkloadIP+"/"+mask, "dev", "eth20")
						s.tc.Felixes[1].Exec("ip", "-6", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth30")
					} else {
						s.tc.Felixes[1].Exec("ip", "route", "del", fakeWorkloadIP+"/"+mask, "dev", "eth20")
						s.tc.Felixes[1].Exec("ip", "route", "add", fakeWorkloadIP+"/"+mask, "dev", "eth30")
					}

					_, err = eth30.RunCmd("pktgen", fakeWorkloadIP, s.w[1][1].IP, "udp",
						"--port-src", "30446", "--port-dst", "30446")
					Expect(err).NotTo(HaveOccurred())

					// Expect the packet from the .30 to make it through as RPF will
					// allow it and we will update the expected interface
					Eventually(func() int { return tcpdump.MatchCount("UDP-30446") }).
						Should(BeNumerically("==", 2), matcher)

					ctAfter := dumpCTMapsAny(family, s.tc.Felixes[1])
					Expect(ctAfter).To(HaveKey(k))

					// Ifindex must have changed
					// B2A because of IPA > IPB - deterministic
					Expect(ctBefore[k].Data().B2A.Ifindex).NotTo(BeNumerically("==", 0),
						"Expected 'before' conntrack B2A ifindex to be set")
					Expect(ctAfter[k].Data().B2A.Ifindex).NotTo(BeNumerically("==", 0),
						"Expected 'after' conntrack B2A ifindex to be set")
					Expect(ctBefore[k].Data().B2A.Ifindex).
						NotTo(BeNumerically("==", ctAfter[k].Data().B2A.Ifindex))
				})
			})
		}
	})
}
