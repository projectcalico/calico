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
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/nat"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
)

func describeBPFNodePortTests(s *bpfTestContext, clusterIP, loIP string) {
	npPort := uint16(30333)

	nodePortsTest := func(extLocal, intLocal bool) {
		var (
			testSvc          *v1.Service
			testSvcNamespace string
			feKey            nat.FrontendKeyInterface
			family           int
		)

		testSvcName := "test-service"
		testSvcExtIP0 := "10.123.0.0"
		testSvcExtIP1 := "10.123.0.1"
		if s.testOpts.ipv6 {
			testSvcExtIP0 = net.ParseIP("dead:beef::123:0:0:0").String()
			testSvcExtIP1 = net.ParseIP("dead:beef::123:0:0:1").String()
		}

		BeforeEach(func() {
			s.k8sClient = s.infra.(*infrastructure.K8sDatastoreInfra).K8sClient
			testSvc = k8sService(testSvcName, clusterIP,
				s.w[0][0], 80, 8055, int32(npPort), s.testOpts.protocol)
			testSvc.Spec.ExternalIPs = []string{testSvcExtIP0, testSvcExtIP1}
			if extLocal {
				testSvc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeLocal
			}
			if intLocal {
				internalLocal := v1.ServiceInternalTrafficPolicyLocal
				testSvc.Spec.InternalTrafficPolicy = &internalLocal
			}
			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
				"Service endpoints didn't get created? Is controller-manager happy?")
		})

		It("should have connectivity from all workloads via a service to workload 0", func() {
			clusterIP := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			exp := Some
			if intLocal {
				exp = None
			}

			w00Expects := []ExpectationOption{ExpectWithPorts(port)}
			hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
			if s.testOpts.ipv6 {
				hostW0SrcIP = ExpectWithSrcIPs(s.felixIP(0))
				switch s.testOpts.tunnel {
				case "vxlan":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
				case "wireguard":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
				}
			}
			switch s.testOpts.tunnel {
			case "ipip":
				hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
			}

			if !s.testOpts.connTimeEnabled {
				w00Expects = append(w00Expects, hostW0SrcIP)
			}

			s.cc.Expect(Some, s.w[0][0], TargetIP(clusterIP), w00Expects...)
			s.cc.Expect(Some, s.w[0][1], TargetIP(clusterIP), ExpectWithPorts(port))
			s.cc.Expect(exp, s.w[1][0], TargetIP(clusterIP), ExpectWithPorts(port))
			s.cc.Expect(exp, s.w[1][1], TargetIP(clusterIP), ExpectWithPorts(port))
			s.cc.CheckConnectivity()
		})

		if intLocal {
			It("should not have connectivity from all workloads via a nodeport to non-local workload 0", func() {
				By("Checking connectivity")

				node0IP := s.felixIP(0)
				node1IP := s.felixIP(1)

				// Should work through the nodeport from a pod on the node where the backend is
				s.cc.ExpectSome(s.w[0][1], TargetIP(node0IP), npPort)

				// Should not work through the nodeport from a node where the backend is not.
				s.cc.ExpectNone(s.w[1][0], TargetIP(node0IP), npPort)
				s.cc.ExpectNone(s.w[1][1], TargetIP(node0IP), npPort)
				s.cc.ExpectNone(s.w[0][1], TargetIP(node1IP), npPort)
				s.cc.ExpectNone(s.w[1][0], TargetIP(node1IP), npPort)
				s.cc.ExpectNone(s.w[1][1], TargetIP(node1IP), npPort)

				s.cc.CheckConnectivity()

				// Enough to test for one protocol
				if s.testIfTCP {
					By("checking correct NAT entries for remote nodeports")

					ipOK := []string{
						"255.255.255.255", "10.101.0.1", "dead:beef::abcd:0:0:1", /* API server */
						testSvc.Spec.ClusterIP, testSvcExtIP0, testSvcExtIP1,
						s.felixIP(0), s.felixIP(1), s.felixIP(2),
					}

					if s.testOpts.tunnel == "ipip" {
						ipOK = append(ipOK, s.tc.Felixes[0].ExpectedIPIPTunnelAddr,
							s.tc.Felixes[1].ExpectedIPIPTunnelAddr, s.tc.Felixes[2].ExpectedIPIPTunnelAddr)
					}
					if s.testOpts.tunnel == "vxlan" {
						if s.testOpts.ipv6 {
							ipOK = append(ipOK, s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr,
								s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr, s.tc.Felixes[2].ExpectedVXLANV6TunnelAddr)
						} else {
							ipOK = append(ipOK, s.tc.Felixes[0].ExpectedVXLANTunnelAddr,
								s.tc.Felixes[1].ExpectedVXLANTunnelAddr, s.tc.Felixes[2].ExpectedVXLANTunnelAddr)
						}
					}
					if s.testOpts.tunnel == "wireguard" {
						if s.testOpts.ipv6 {
							ipOK = append(ipOK, s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr,
								s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr, s.tc.Felixes[2].ExpectedWireguardV6TunnelAddr)
						} else {
							ipOK = append(ipOK, s.tc.Felixes[0].ExpectedWireguardTunnelAddr,
								s.tc.Felixes[1].ExpectedWireguardTunnelAddr, s.tc.Felixes[2].ExpectedWireguardTunnelAddr)
						}
					}

					if s.testOpts.ipv6 {
						family = 6
						feKey = nat.NewNATKeyV6(net.ParseIP(s.felixIP(0)), npPort, 6)
					} else {
						family = 4
						feKey = nat.NewNATKey(net.ParseIP(s.felixIP(0)), npPort, 6)
					}

					for _, felix := range s.tc.Felixes {
						fe, _, _ := dumpNATMapsAny(family, felix)
						for key := range fe {
							Expect(key.Addr().String()).To(BeElementOf(ipOK))
						}
					}

					// RemoteNodeport on node 0
					fe, _, _ := dumpNATMapsAny(family, s.tc.Felixes[0])
					Expect(fe).To(HaveKey(feKey))
					be := fe[feKey]
					Expect(be.Count()).To(Equal(uint32(1)))
					Expect(be.LocalCount()).To(Equal(uint32(1)))

					// RemoteNodeport on node 1
					fe, _, _ = dumpNATMapsAny(family, s.tc.Felixes[1])
					Expect(fe).To(HaveKey(feKey))
					be = fe[feKey]
					Expect(be.Count()).To(Equal(uint32(1)))
					Expect(be.LocalCount()).To(Equal(uint32(0)))
				}
			})
		} else if !extLocal && !intLocal {
			It("should have connectivity from all workloads via a nodeport to workload 0", func() {
				node0IP := s.felixIP(0)
				node1IP := s.felixIP(1)

				s.cc.ExpectSome(s.w[0][1], TargetIP(node0IP), npPort)
				s.cc.ExpectSome(s.w[1][0], TargetIP(node0IP), npPort)
				s.cc.ExpectSome(s.w[1][1], TargetIP(node0IP), npPort)

				s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)

				s.cc.CheckConnectivity()
			})

			Describe("with policy enabling ingress to s.w[0][0] from host endpoints", func() {
				BeforeEach(func() {
					s.pol = api.NewGlobalNetworkPolicy()
					s.pol.Namespace = "fv"
					s.pol.Name = "policy-host-eps"
					s.pol.Spec.Ingress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "ep-type=='host'",
							},
						},
						{
							Action: "Allow",
							Source: api.EntityRule{
								Nets: []string{testSvcExtIP0 + "/" + s.ipMask(), testSvcExtIP1 + "/" + s.ipMask()},
							},
						},
					}
					w00Selector := fmt.Sprintf("name=='%s'", s.w[0][0].Name)
					s.pol.Spec.Selector = w00Selector

					s.pol = s.createPolicy(s.pol)
				})

				It("should have connectivity from all host-networked workloads to workload 0 via nodeport", func() {
					node0IP := s.felixIP(0)
					node1IP := s.felixIP(1)

					hostW0SrcIP := ExpectWithSrcIPs(node0IP)
					hostW1SrcIP := ExpectWithSrcIPs(node1IP)

					if s.testOpts.ipv6 {
						switch s.testOpts.tunnel {
						case "wireguard":
							if s.testOpts.connTimeEnabled {
								hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
							}
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
						case "vxlan":
							if s.testOpts.connTimeEnabled {
								hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
							}
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
						}
					} else {
						switch s.testOpts.tunnel {
						case "ipip":
							if s.testOpts.connTimeEnabled {
								hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
							}
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
						case "wireguard":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
						case "vxlan":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
						}
					}

					ports := ExpectWithPorts(npPort)

					s.cc.Expect(Some, s.hostW[0], TargetIP(node0IP), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[0], TargetIP(node1IP), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(node0IP), ports, hostW1SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(node1IP), ports, hostW1SrcIP)

					s.cc.CheckConnectivity()
				})

				It("should have connectivity from all host-networked workloads to workload 0 via ExternalIP", func() {
					if s.testOpts.connTimeEnabled {
						// not valid for CTLB as it is just and approx.
						return
					}
					// This test is primarily to make sure that the external
					// IPs do not interfere with the workaround and vise
					// versa.
					By("Setting ExternalIPs")
					s.tc.Felixes[0].Exec("ip", "addr", "add", testSvcExtIP0+"/"+s.ipMask(), "dev", "eth0")
					s.tc.Felixes[1].Exec("ip", "addr", "add", testSvcExtIP1+"/"+s.ipMask(), "dev", "eth0")

					ipRoute := []string{"ip"}
					if s.testOpts.ipv6 {
						ipRoute = append(ipRoute, "-6")
					}

					// The external IPs must be routable
					By("Setting routes for the ExternalIPs")
					cmd := append(ipRoute[:len(ipRoute):len(ipRoute)],
						"route", "add", testSvcExtIP1+"/"+s.ipMask(), "via", s.felixIP(1))
					s.tc.Felixes[0].Exec(cmd...)
					cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
						"route", "add", testSvcExtIP0+"/"+s.ipMask(), "via", s.felixIP(0))
					s.tc.Felixes[1].Exec(cmd...)
					cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
						"route", "add", testSvcExtIP1+"/"+s.ipMask(), "via", s.felixIP(1))
					s.externalClient.Exec(cmd...)
					cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
						"route", "add", testSvcExtIP0+"/"+s.ipMask(), "via", s.felixIP(0))
					s.externalClient.Exec(cmd...)

					By("Allow ingress from external client", func() {
						s.pol = api.NewGlobalNetworkPolicy()
						s.pol.Namespace = "fv"
						s.pol.Name = "policy-ext-client"
						s.pol.Spec.Ingress = []api.Rule{
							{
								Action: "Allow",
								Source: api.EntityRule{
									Nets: []string{s.containerIP(s.externalClient) + "/" + s.ipMask()},
								},
							},
						}
						w00Selector := fmt.Sprintf("name=='%s'", s.w[0][0].Name)
						s.pol.Spec.Selector = w00Selector

						s.pol = s.createPolicy(s.pol)
					})

					node0IP := s.felixIP(0)
					node1IP := s.felixIP(1)

					hostW0SrcIP := ExpectWithSrcIPs(node0IP)
					hostW1SrcIP := ExpectWithSrcIPs(node1IP)
					hostW11SrcIP := ExpectWithSrcIPs(testSvcExtIP1)

					if s.testOpts.ipv6 {
						switch s.testOpts.tunnel {
						case "none":
							hostW0SrcIP = ExpectWithSrcIPs(testSvcExtIP0)
							hostW1SrcIP = ExpectWithSrcIPs(testSvcExtIP1)
						case "wireguard":
							hostW0SrcIP = ExpectWithSrcIPs(testSvcExtIP0)
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
						case "vxlan":
							hostW0SrcIP = ExpectWithSrcIPs(testSvcExtIP0)
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
						}
					} else {
						switch s.testOpts.tunnel {
						case "ipip":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
						case "wireguard":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
						case "vxlan":
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
							hostW11SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
						}
					}

					ports := ExpectWithPorts(80)

					s.cc.Expect(Some, s.hostW[0], TargetIP(testSvcExtIP0), ports, ExpectWithSrcIPs(testSvcExtIP0))
					s.cc.Expect(Some, s.hostW[1], TargetIP(testSvcExtIP0), ports, hostW1SrcIP)
					s.cc.Expect(Some, s.hostW[0], TargetIP(testSvcExtIP1), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(testSvcExtIP1), ports, hostW11SrcIP)

					s.cc.Expect(Some, s.externalClient, TargetIP(testSvcExtIP0), ports)
					s.cc.Expect(Some, s.externalClient, TargetIP(testSvcExtIP1), ports)

					s.cc.CheckConnectivity()
				})

				_ = s.testIfNotUDPUConnected && // two app with two sockets cannot conflict
					Context("with conflict from host-networked workloads via clusterIP and directly", func() {
						JustBeforeEach(func() {
							for i, felix := range s.tc.Felixes {
								f := felix
								idx := i
								Eventually(func() bool {
									return checkServiceRoute(f, testSvc.Spec.ClusterIP)
								}, 10*time.Second, 300*time.Millisecond).Should(BeTrue(),
									fmt.Sprintf("felix %d failed to sync with service", idx))

								if s.testOpts.ipv6 {
									felix.Exec("ip", "-6", "route")
								} else {
									felix.Exec("ip", "route")
								}
							}
						})
						if !s.testOpts.connTimeEnabled {
							It("should have connection when via clusterIP starts first", func() {
								node1IP := s.felixIP(1)

								hostW1SrcIP := ExpectWithSrcIPs(node1IP)

								switch s.testOpts.tunnel {
								case "ipip":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
								case "wireguard":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
									if s.testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
									}
								case "vxlan":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
									if s.testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
									}
								}

								clusterIP := testSvc.Spec.ClusterIP
								port := uint16(testSvc.Spec.Ports[0].Port)

								By("syncing with service programming")
								ports := ExpectWithPorts(port)
								s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)
								s.cc.CheckConnectivity()
								s.cc.ResetExpectations()

								By("starting a persistent connection to cluster IP")
								pc := s.hostW[1].StartPersistentConnection(clusterIP, int(port),
									workload.PersistentConnectionOpts{
										SourcePort:          12345,
										MonitorConnectivity: true,
									},
								)
								defer pc.Stop()

								s.cc.Expect(Some, s.hostW[1], s.w[0][0], hostW1SrcIP, ExpectWithSrcPort(12345))
								s.cc.CheckConnectivity()

								prevCount := pc.PongCount()
								Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
									"Expected to see pong responses on the connection but didn't receive any")
							})

							It("should have connection when direct starts first", func() {
								node1IP := s.felixIP(1)

								hostW1SrcIP := ExpectWithSrcIPs(node1IP)

								switch s.testOpts.tunnel {
								case "ipip":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
								case "wireguard":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
									if s.testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
									}
								case "vxlan":
									hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
									if s.testOpts.ipv6 {
										hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
									}
								}

								clusterIP := testSvc.Spec.ClusterIP
								port := uint16(testSvc.Spec.Ports[0].Port)

								By("syncing with service programming")
								ports := ExpectWithPorts(port)
								s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)
								s.cc.CheckConnectivity()
								s.cc.ResetExpectations()

								By("starting a persistent connection directly")
								pc := s.hostW[1].StartPersistentConnection(s.w[0][0].IP, 8055,
									workload.PersistentConnectionOpts{
										SourcePort:          12345,
										MonitorConnectivity: true,
									},
								)
								defer pc.Stop()

								s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports,
									hostW1SrcIP, ExpectWithSrcPort(12345))
								s.cc.CheckConnectivity()

								prevCount := pc.PongCount()
								Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
									"Expected to see pong responses on the connection but didn't receive any")
							})
						}
					})

				It("should have connectivity from all host-networked workloads to workload 0 via clusterIP", func() {
					node0IP := s.felixIP(0)
					node1IP := s.felixIP(1)

					hostW0SrcIP := ExpectWithSrcIPs(node0IP)
					hostW1SrcIP := ExpectWithSrcIPs(node1IP)

					switch s.testOpts.tunnel {
					case "ipip":
						if s.testOpts.connTimeEnabled {
							hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
						}
						hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
					case "wireguard":
						if s.testOpts.ipv6 {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
							hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
						} else {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
						}
					case "vxlan":
						if s.testOpts.ipv6 {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
							hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
						} else {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
						}
					}

					clusterIP := testSvc.Spec.ClusterIP
					ports := ExpectWithPorts(uint16(testSvc.Spec.Ports[0].Port))

					s.tc.Felixes[0].Exec("sysctl", "-w", "net.ipv6.conf.eth0.disable_ipv6=0")
					s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv6.conf.eth0.disable_ipv6=0")

					// Also try host networked pods, both on a local and remote node.
					s.cc.Expect(Some, s.hostW[0], TargetIP(clusterIP), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)

					if s.testOpts.protocol == "tcp" && !s.testOpts.ipv6 {
						// Also excercise ipv4 as ipv6
						s.cc.Expect(Some, s.hostW[0], TargetIPv4AsIPv6(clusterIP), ports, hostW0SrcIP)
						s.cc.Expect(Some, s.hostW[1], TargetIPv4AsIPv6(clusterIP), ports, hostW1SrcIP)
					}

					s.cc.CheckConnectivity()
				})

				It("should have connectivity from all host-networked workloads to workload 0 "+
					"via clusterIP with non-routable address set on lo", func() {
					// It only makes sense for turned off CTLB as with CTLB routing
					// picks the right source IP.
					if s.testOpts.connTimeEnabled {
						return
					}
					By("Configuring ip on lo")
					s.tc.Felixes[0].Exec("ip", "addr", "add", loIP+"/"+s.ipMask(), "dev", "lo")
					s.tc.Felixes[1].Exec("ip", "addr", "add", loIP+"/"+s.ipMask(), "dev", "lo")

					By("testing connectivity")

					node0IP := s.felixIP(0)
					node1IP := s.felixIP(1)
					hostW0SrcIP := ExpectWithSrcIPs(node0IP)
					hostW1SrcIP := ExpectWithSrcIPs(node1IP)

					switch s.testOpts.tunnel {
					case "ipip":
						hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedIPIPTunnelAddr)
					case "wireguard":
						if s.testOpts.ipv6 {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardV6TunnelAddr)
						} else {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedWireguardTunnelAddr)
						}
					case "vxlan":
						if s.testOpts.ipv6 {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANV6TunnelAddr)
						} else {
							hostW1SrcIP = ExpectWithSrcIPs(s.tc.Felixes[1].ExpectedVXLANTunnelAddr)
						}
					}
					clusterIP := testSvc.Spec.ClusterIP
					ports := ExpectWithPorts(uint16(testSvc.Spec.Ports[0].Port))

					s.cc.Expect(Some, s.hostW[0], TargetIP(clusterIP), ports, hostW0SrcIP)
					s.cc.Expect(Some, s.hostW[1], TargetIP(clusterIP), ports, hostW1SrcIP)

					s.cc.CheckConnectivity()
				})
			})
		}

		if intLocal {
			It("workload should have connectivity to self via local and not remote node", func() {
				w00Expects := []ExpectationOption{ExpectWithPorts(npPort)}
				hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
				if s.testOpts.ipv6 {
					hostW0SrcIP = ExpectWithSrcIPs(s.felixIP(0))
					switch s.testOpts.tunnel {
					case "vxlan":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
					case "wireguard":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
					}
				}
				switch s.testOpts.tunnel {
				case "ipip":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
				}

				if !s.testOpts.connTimeEnabled {
					w00Expects = append(w00Expects, hostW0SrcIP)
				}

				s.cc.Expect(None, s.w[0][0], TargetIP(s.felixIP(1)), w00Expects...)
				s.cc.Expect(Some, s.w[0][0], TargetIP(s.felixIP(0)), w00Expects...)
				s.cc.CheckConnectivity()
			})
		} else {
			It("should have connectivity from a workload via a nodeport on another node to workload 0", func() {
				ip := s.felixIP(1)

				s.cc.ExpectSome(s.w[2][1], TargetIP(ip), npPort)
				s.cc.CheckConnectivity()
			})

			It("workload should have connectivity to self via local/remote node", func() {
				w00Expects := []ExpectationOption{ExpectWithPorts(npPort)}
				hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
				if s.testOpts.ipv6 {
					switch s.testOpts.tunnel {
					case "wireguard":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
					case "vxlan":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
					}
				} else {
					switch s.testOpts.tunnel {
					case "ipip":
						hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
					}
				}

				if !s.testOpts.connTimeEnabled {
					w00Expects = append(w00Expects, hostW0SrcIP)
				}

				s.cc.Expect(Some, s.w[0][0], TargetIP(s.felixIP(1)), w00Expects...)
				s.cc.Expect(Some, s.w[0][0], TargetIP(s.felixIP(0)), w00Expects...)
				s.cc.CheckConnectivity()
			})
		}

		It("should not have connectivity from external to w[0] via local/remote node", func() {
			s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(1)), npPort)
			s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(0)), npPort)
			// Include a check that goes via the local nodeport to make sure the dataplane has converged.
			s.cc.ExpectSome(s.w[0][1], TargetIP(s.felixIP(0)), npPort)
			s.cc.CheckConnectivity()
		})

		Describe("after updating the policy to allow traffic from s.externalClient", func() {
			BeforeEach(func() {
				extClIP := s.externalClient.IP + "/32"
				if s.testOpts.ipv6 {
					extClIP = s.externalClient.IPv6 + "/128"
				}
				s.pol.Spec.Ingress = []api.Rule{
					{
						Action: "Allow",
						Source: api.EntityRule{
							Nets: []string{extClIP},
						},
					},
				}
				s.pol = s.updatePolicy(s.pol)
			})

			if extLocal && !s.testOpts.connTimeEnabled {
				It("should not have connectivity from external to w[0] via node1->node0 fwd", func() {
					s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(1)), npPort)
					// Include a check that goes via the nodeport with a local backing pod to make sure the dataplane has converged.
					s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(0)), npPort)
					s.cc.CheckConnectivity()
				})
			} else if !s.testOpts.connTimeEnabled && !intLocal /* irrelevant option for extClient */ {
				It("should have connectivity from external to w[0] via node1->node0 fwd", func() {
					By("checking the connectivity and thus populating the  neigh table", func() {
						s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(1)), npPort)
						s.cc.CheckConnectivity()
					})

					// The test does not make sense in DSR mode as the neigh
					// table is not used on the return path.
					if !s.testOpts.dsr {
						var srcMAC, dstMAC string

						By("making sure that neigh table is populated", func() {
							var (
								out string
								err error
							)

							if s.testOpts.ipv6 {
								out, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "-6", "arp", "dump")
							} else {
								out, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "arp", "dump")
							}
							Expect(err).NotTo(HaveOccurred())

							arpRegexp := regexp.MustCompile(fmt.Sprintf(".*%s : (.*) -> (.*)", s.felixIP(1)))

							lines := strings.SplitSeq(out, "\n")
							for l := range lines {
								if strings.Contains(l, s.felixIP(1)) {
									MACs := arpRegexp.FindStringSubmatch(l)
									Expect(MACs).To(HaveLen(3))
									srcMAC = MACs[1]
									dstMAC = MACs[2]
								}
							}

							Expect(srcMAC).NotTo(Equal(""))
							Expect(dstMAC).NotTo(Equal(""))
						})

						// Since local-host networking ignores L2 addresses, we
						// need to make sure by other means that they are set
						// correctly.
						By("making sure that return VXLAN has the right MACs using tcpdump", func() {
							tcpdump := s.tc.Felixes[0].AttachTCPDump("eth0")
							tcpdump.SetLogEnabled(true)
							tcpdump.AddMatcher("MACs", regexp.MustCompile(fmt.Sprintf("%s > %s", srcMAC, dstMAC)))
							tcpdump.Start(s.infra, "-e", "udp", "and", "src", s.felixIP(0), "and", "port", "4789")

							s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(1)), npPort)
							s.cc.CheckConnectivity()

							Eventually(func() int { return tcpdump.MatchCount("MACs") }).
								Should(BeNumerically(">", 0), "MACs do not match")
						})
					}
				})

				// Our unconnected test client cannot handle multiple streams. Two
				// clients cannot use the same local address. The connected case shows
				// that it works in principle.
				_ = s.testIfNotUDPUConnected && It("should not break connectivity with source port collision", func() {
					By("Synchronizing with policy and services")
					s.cc.Expect(Some, s.externalClient, TargetIP(s.felixIP(0)), ExpectWithPorts(npPort))
					s.cc.Expect(Some, s.externalClient, TargetIP(s.felixIP(1)), ExpectWithPorts(npPort))
					s.cc.CheckConnectivity()

					pc := &PersistentConnection{
						Runtime:             s.externalClient,
						RuntimeName:         s.externalClient.Name,
						IP:                  s.felixIP(0),
						Port:                int(npPort),
						SourcePort:          12345,
						Protocol:            s.testOpts.protocol,
						MonitorConnectivity: true,
					}

					err := pc.Start()
					Expect(err).NotTo(HaveOccurred())
					defer pc.Stop()

					Eventually(pc.PongCount, "5s").Should(
						BeNumerically(">", 0),
						"Expected to see pong responses on the connection but didn't receive any")
					log.Info("Pongs received within last 1s")

					s.cc.ResetExpectations()
					s.cc.Expect(Some, s.externalClient, TargetIP(s.felixIP(1)),
						ExpectWithPorts(npPort), ExpectWithSrcPort(12345))
					s.cc.CheckConnectivity()

					prevCount := pc.PongCount()

					Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
						"Expected to see pong responses on the connection but didn't receive any")
					log.Info("Pongs received within last 1s")
				})

				_ = s.testIfTCP && It("should survive conntrack cleanup sweep", func() {
					By("checking the connectivity and thus syncing with service creation", func() {
						s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(1)), npPort)
						s.cc.CheckConnectivity()
					})

					By("monitoring a persistent connection", func() {
						pc := &PersistentConnection{
							Runtime:             s.externalClient,
							RuntimeName:         s.externalClient.Name,
							IP:                  s.felixIP(1),
							Port:                int(npPort),
							Protocol:            s.testOpts.protocol,
							MonitorConnectivity: true,
						}

						err := pc.Start()
						Expect(err).NotTo(HaveOccurred())
						defer pc.Stop()

						EventuallyWithOffset(1, pc.PongCount, "5s").Should(
							BeNumerically(">", 0),
							"Expected to see pong responses on the connection but didn't receive any")
						log.Info("Pongs received within last 1s")

						// We make sure that at least one iteration of the conntrack
						// cleanup executes and we periodically monitor the connection if
						// it is alive by checking that the number of PONGs keeps
						// increasing.
						start := time.Now()
						prevCount := pc.PongCount()
						for time.Since(start) < 2*timeouts.ScanPeriod {
							time.Sleep(time.Second)
							newCount := pc.PongCount()
							Expect(prevCount).Should(
								BeNumerically("<", newCount),
								"No new pongs since the last iteration. Connection broken?",
							)
							prevCount = newCount
						}
					})
				})

				_ = s.testIfTCP && !s.testOpts.ipv6 && s.testOpts.bpfLogLevel == "debug" && !s.testOpts.dsr &&
					s.testOpts.tunnel != "vxlan" &&
					It("tcp should survive spurious RST", func() {
						s.externalClient.Exec("ip", "route", "add", s.w[0][0].IP, "via", s.felixIP(0))
						pc := &PersistentConnection{
							Runtime:             s.externalClient,
							RuntimeName:         s.externalClient.Name,
							IP:                  s.w[0][0].IP,
							Port:                8055,
							SourcePort:          54321,
							Protocol:            s.testOpts.protocol,
							MonitorConnectivity: true,
							Sleep:               21 * time.Second,
						}
						tcpdump := s.tc.Felixes[0].AttachTCPDump("eth0")
						tcpdump.SetLogEnabled(true)
						tcpdump.Start(s.infra, "tcp", "port", "8055")

						err := pc.Start()
						Expect(err).NotTo(HaveOccurred())
						defer pc.Stop()

						EventuallyWithOffset(1, pc.PongCount, "5s").Should(
							BeNumerically(">", 0),
							"Expected to see pong responses on the connection but didn't receive any")
						log.Info("Pongs received within last 1s")

						// Now we send a spurious RST, which would bring the connection
						// down as the pace is a PING every 21s so once a periodic
						// cleanup ticks the entry is older than the TCPResetSeen timer
						// of 5s (40s by default).
						err = s.externalClient.ExecMayFail("pktgen",
							s.containerIP(s.externalClient), s.w[0][0].IP, "tcp",
							"--port-src", "54321", "--port-dst", "8055", "--tcp-rst", "--tcp-seq-no=123456")
						Expect(err).NotTo(HaveOccurred())

						time.Sleep(200 * time.Millisecond)

						// This is quite a bit artificial. We send a totally random ACK.
						// If the connection was idle for TCPResetSeen timeout, we clean
						// it up no matter what. This random ack kinda mimics that the
						// connection is not idle. (1) our conntrack does not maintain
						// the "in-window" for simplicity so it will say, OK some data
						// still going through, don't rush to clean it up. (2) it
						// triggers a proper ACK from the receiver side and its
						// ACKnowledgement from the sender side as a response, so some
						// real traffic, but no data. It allows us to control things
						// more precisely than say keepalive and minic active
						// connection.
						err = s.externalClient.ExecMayFail("pktgen", s.containerIP(s.externalClient), s.w[0][0].IP, "tcp",
							"--port-src", "54321", "--port-dst", "8055", "--tcp-ack-no=87238974", "--tcp-seq-no=98793")
						Expect(err).NotTo(HaveOccurred())

						// We make sure that at least two iteration of the conntrack
						// cleanup executes and we periodically monitor the connection if
						// it is alive by checking that the number of PONGs keeps
						// increasing. The ct entry may not be old enough in the first
						// iteration yet.
						time.Sleep(3 * timeouts.ScanPeriod)
						prevCount := pc.PongCount()

						// Try log enough to see a ping-pong
						Eventually(pc.PongCount, "22s", "1s").Should(
							BeNumerically(">", prevCount),
							"No new pongs since the last iteration. Connection broken?")
					})

				if !s.testOpts.dsr {
					// When DSR is enabled, we need to have away how to pass the
					// original traffic back.
					//
					// felixes[0].Exec("ip", "route", "add", "192.168.20.0/24", "via", felixes[1].IP)
					//
					// This does not work since the other node would treat it as
					// DNAT due to the existing CT entries and NodePort traffix
					// otherwise :-/

					It("should have connectivity from external to w[0] via node1IP2 -> nodeIP1 -> node0 fwd", func() {
						// 192.168.20.1              +----------|---------+
						//      |                    |          |         |
						//      v                    |          |         V
						//    eth20                 eth0        |       eth0
						//  10.0.0.20:30333 --> felixes[1].IP   |   felixes[0].IP
						//                                      |        |
						//                                      |        V
						//                                      |     caliXYZ
						//                                      |    s.w[0][0].IP:8055
						//                                      |
						//                node1                 |      node0

						var (
							eth20                     *workload.Workload
							eth20IP, mask, eth20Route string
							eth20ExtIP                string
						)

						defer func() {
							if eth20 != nil {
								eth20.Stop()
							}
						}()
						if s.testOpts.ipv6 {
							eth20IP = "fd00::2001"
							eth20Route = "fd00::2000/120"
							eth20ExtIP = "1000::0020"
							mask = "128"

						} else {
							eth20IP = "192.168.20.1"
							eth20Route = "192.168.20.0/24"
							eth20ExtIP = "10.0.0.20"
							mask = "32"
						}

						By("setting up node's fake external iface", func() {
							// We name the iface eth20 since such ifaces are
							// treated by felix as external to the node
							//
							// Using a test-workload creates the namespaces and the
							// interfaces to emulate the host NICs
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
								// Add a route to felix[1] to be able to reach the nodeport
								_, err = eth20.RunCmd("ip", "-6", "route", "add", s.felixIP(1)+"/"+mask, "via", eth20ExtIP)
								Expect(err).NotTo(HaveOccurred())
							} else {
								s.tc.Felixes[1].Exec("ip", "route", "add", eth20Route, "dev", "eth20")
								s.tc.Felixes[1].Exec("ip", "addr", "add", eth20ExtIP+"/"+mask, "dev", "eth20")
								_, err = eth20.RunCmd("ip", "route", "add", eth20ExtIP+"/"+mask, "dev", "eth0")
								Expect(err).NotTo(HaveOccurred())
								// Add a route to felix[1] to be able to reach the nodeport
								_, err = eth20.RunCmd("ip", "route", "add", s.felixIP(1)+"/"+mask, "via", eth20ExtIP)
								Expect(err).NotTo(HaveOccurred())
								// This multi-NIC scenario works only if the kernel's RPF check
								// is not strict so we need to override it for the test and must
								// be set properly when product is deployed. We reply on
								// iptables to do require check for us.
								s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")
								s.tc.Felixes[1].Exec("sysctl", "-w", "net.ipv4.conf.eth20.rp_filter=2")
							}
						})

						By("setting up routes to .20 net on dest node to trigger RPF check", func() {
							if s.testOpts.ipv6 {
								// set up a dummy interface just for the routing purpose
								s.tc.Felixes[0].Exec("ip", "-6", "link", "add", "dummy1", "type", "dummy")
								s.tc.Felixes[0].Exec("ip", "-6", "link", "set", "dummy1", "up")
								// set up route to the .20 net through the dummy iface. This
								// makes the .20 a universally reachable external world from the
								// internal/private eth0 network
								s.tc.Felixes[0].Exec("ip", "-6", "route", "add", eth20Route, "dev", "dummy1")
							} else {
								// set up a dummy interface just for the routing purpose
								s.tc.Felixes[0].Exec("ip", "link", "add", "dummy1", "type", "dummy")
								s.tc.Felixes[0].Exec("ip", "link", "set", "dummy1", "up")
								// set up route to the .20 net through the dummy iface. This
								// makes the .20 a universally reachable external world from the
								// internal/private eth0 network
								s.tc.Felixes[0].Exec("ip", "route", "add", eth20Route, "dev", "dummy1")
								// This multi-NIC scenario works only if the kernel's RPF check
								// is not strict so we need to override it for the test and must
								// be set properly when product is deployed. We reply on
								// iptables to do require check for us.
								s.tc.Felixes[0].Exec("sysctl", "-w", "net.ipv4.conf.eth0.rp_filter=2")
								s.tc.Felixes[0].Exec("sysctl", "-w", "net.ipv4.conf.dummy1.rp_filter=2")
							}
						})

						By("Allowing traffic from the eth20 network", func() {
							s.pol.Spec.Ingress = []api.Rule{
								{
									Action: "Allow",
									Source: api.EntityRule{
										Nets: []string{
											eth20.IP + "/" + s.ipMask(),
										},
									},
								},
							}
							s.pol = s.updatePolicy(s.pol)
						})

						By("Checking that there is connectivity from eth20 network", func() {
							s.cc.ExpectSome(eth20, TargetIP(s.felixIP(1)), npPort)
							s.cc.CheckConnectivity()
						})
					})
				}

				if s.testOpts.protocol == "tcp" {

					const (
						hostIfaceMTU = 1500
						podIfaceMTU  = 1450
						sendLen      = hostIfaceMTU
						recvLen      = podIfaceMTU
					)

					Context("with TCP, tx/rx close to MTU size on NP via node1->node0 ", func() {
						It("should not adjust MTU on client side if GRO off on nodes", func() {
							// force non-GSO packets on node ingress
							err := s.tc.Felixes[1].ExecMayFail("ethtool", "-K", "eth0", "gro", "off")
							Expect(err).NotTo(HaveOccurred())

							s.cc.Expect(Some, s.externalClient, TargetIP(s.felixIP(1)),
								ExpectWithPorts(npPort),
								ExpectWithSendLen(sendLen),
								ExpectWithRecvLen(recvLen),
								ExpectWithClientAdjustedMTU(hostIfaceMTU, hostIfaceMTU),
							)
							s.cc.CheckConnectivity()
						})
					})
				}
			}

			if !s.testOpts.connTimeEnabled {
				It("should have connectivity from external to w[0] via node0", func() {
					log.WithFields(log.Fields{
						"externalClientIP": s.containerIP(s.externalClient),
						"nodePortIP":       s.felixIP(1),
					}).Infof("external->nodeport connection")

					s.cc.ExpectSome(s.externalClient, TargetIP(s.felixIP(0)), npPort)
					s.cc.CheckConnectivity()
				})
			}
		})
	}

	Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort)), func() {
		nodePortsTest(false, false)

		if !s.testOpts.connTimeEnabled && s.testOpts.tunnel == "none" &&
			s.testOpts.protocol == "tcp" && !s.testOpts.dsr {
			Context("with small MTU between remote client and cluster", func() {
				var remoteWL *workload.Workload
				hostNP := uint16(30555)

				BeforeEach(func() {
					remoteWL = &workload.Workload{
						C:             s.externalClient,
						Name:          "remoteWL",
						InterfaceName: "ethwl",
						Protocol:      s.testOpts.protocol,
						MTU:           1500,
					}

					remoteWLIP := "192.168.15.15"
					remoteWL.IP = remoteWLIP
					if s.testOpts.ipv6 {
						remoteWLIP = "dead:beef:1515::1515"
						remoteWL.IP6 = remoteWLIP
					}

					err := remoteWL.Start(s.infra)
					Expect(err).NotTo(HaveOccurred())

					clusterIP := "10.101.0.211"
					if s.testOpts.ipv6 {
						clusterIP = "dead:beef::abcd:0:0:211"
					}

					svcHostNP := k8sService("test-host-np", clusterIP, s.hostW[0], 81, 8055, int32(hostNP), s.testOpts.protocol)
					testSvcNamespace := svcHostNP.Namespace
					_, err = s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), svcHostNP, metav1.CreateOptions{})
					Expect(err).NotTo(HaveOccurred())
					Eventually(checkSvcEndpoints(s.k8sClient, svcHostNP), "10s").Should(Equal(1),
						"Service endpoints didn't get created? Is controller-manager happy?")

					if s.testOpts.ipv6 {
						s.externalClient.Exec("ip", "-6", "route", "add", remoteWLIP, "dev",
							remoteWL.InterfaceName, "scope", "link")
						s.externalClient.Exec("ip", "-6", "route", "add", s.w[0][0].IP, "via", s.tc.Felixes[0].IPv6, "dev", "eth0")
						s.externalClient.Exec("ip", "addr", "add", "169.254.169.254", "dev", remoteWL.InterfaceName)
						// Need to change the MTU on the host side of the veth. If
						// we change it on the eth0 of the docker iface, no ICMP
						// is generated.
						s.externalClient.Exec("ip", "link", "set", "ethwl", "mtu", "1300")
						for _, f := range s.tc.Felixes {
							f.Exec("ip", "-6", "route", "add", remoteWLIP,
								"via", s.externalClient.IPv6, "dev", "eth0")
						}
					} else {
						s.externalClient.Exec("ip", "route", "add", remoteWLIP, "dev",
							remoteWL.InterfaceName, "scope", "link")
						s.externalClient.Exec("ip", "route", "add", s.w[0][0].IP, "via", s.tc.Felixes[0].IP, "dev", "eth0")
						s.externalClient.Exec("ip", "addr", "add", "169.254.169.254", "dev", remoteWL.InterfaceName)
						// Need to change the MTU on the host side of the veth. If
						// we change it on the eth0 of the docker iface, not ICMP
						// is generated.
						s.externalClient.Exec("ip", "link", "set", "ethwl", "mtu", "1300")
						for _, f := range s.tc.Felixes {
							f.Exec("ip", "route", "add", remoteWLIP,
								"via", s.externalClient.IP, "dev", "eth0")
						}
					}

					s.pol.Spec.Ingress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Nets: []string{remoteWLIP + "/" + s.ipMask()},
							},
						},
					}
					s.pol = s.updatePolicy(s.pol)
				})

				It("should have connectivity to service backend", func() {
					tcpdump := s.w[0][0].AttachTCPDump()
					tcpdump.SetLogEnabled(true)
					tcpdump.AddMatcher("mtu-1300", regexp.MustCompile("mtu 1300"))
					tcpdump.Start(s.infra, "-vvv", "icmp", "or", "icmp6")

					ipRouteFlushCache := []string{"ip", "route", "flush", "cache"}
					if s.testOpts.ipv6 {
						ipRouteFlushCache = []string{"ip", "-6", "route", "flush", "cache"}
					}

					By("Trying directly to pod")
					s.w[0][0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, s.w[0][0], ExpectWithPorts(8055), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))

					By("Trying directly to node with pod")
					s.cc.ResetExpectations()
					tcpdump.ResetCount("mtu-1300")
					s.w[0][0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, TargetIP(s.felixIP(0)), ExpectWithPorts(npPort), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))

					By("Trying to node without pod")
					s.cc.ResetExpectations()
					tcpdump.ResetCount("mtu-1300")
					s.w[0][0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, TargetIP(s.felixIP(1)), ExpectWithPorts(npPort), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))
				})

				It("should have connectivity to service host-networked backend", func() {
					tcpdump := s.tc.Felixes[0].AttachTCPDump("eth0")
					tcpdump.SetLogEnabled(true)
					tcpdump.AddMatcher("mtu-1300", regexp.MustCompile("mtu 1300"))
					// we also need to watch for the ICMP forwarded to the host with the backend via VXLAN
					tcpdump.Start(s.infra, "-vvv", "icmp", "or", "icmp6", "or", "udp", "port", "4789")

					ipRouteFlushCache := []string{"ip", "route", "flush", "cache"}
					if s.testOpts.ipv6 {
						ipRouteFlushCache = []string{"ip", "-6", "route", "flush", "cache"}
					}

					By("Trying directly to host")
					s.tc.Felixes[0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, s.hostW[0], ExpectWithPorts(8055), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))

					By("Trying directly to node with pod")
					s.cc.ResetExpectations()
					tcpdump.ResetCount("mtu-1300")
					s.tc.Felixes[0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, TargetIP(s.felixIP(0)), ExpectWithPorts(hostNP), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))

					By("Trying to node without pod")
					s.cc.ResetExpectations()
					tcpdump.ResetCount("mtu-1300")
					s.tc.Felixes[0].Exec(ipRouteFlushCache...)
					s.cc.Expect(Some, remoteWL, TargetIP(s.felixIP(1)), ExpectWithPorts(hostNP), ExpectWithRecvLen(1350))
					s.cc.CheckConnectivity()
					// tpcudmp for some reason does not print content of the vxlan
					// packet when it is over ipv6
					if !s.testOpts.ipv6 {
						Eventually(tcpdump.MatchCountFn("mtu-1300"), "5s", "330ms").Should(BeNumerically("==", 1))
					}
				})
			})
		}
	})

	// FIXME connect time shares the same NAT table and it is a lottery which one it gets
	if !s.testOpts.connTimeEnabled {
		Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort))+
			" ExternalTrafficPolicy=local", func() {
			nodePortsTest(true, false)
		})
		Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort))+
			" InternalTrafficPolicy=local", func() {
			nodePortsTest(false, true)
		})
	}

	Context("with icmp blocked from workloads, external client", func() {
		var (
			testSvc          *v1.Service
			testSvcNamespace string
		)

		testSvcName := "test-service"
		nets := []string{"0.0.0.0/0"}
		if s.testOpts.ipv6 {
			nets = []string{"::/0"}
		}

		BeforeEach(func() {
			icmpProto := numorstring.ProtocolFromString("icmp")
			if s.testOpts.ipv6 {
				icmpProto = numorstring.ProtocolFromString("icmpv6")
			}
			s.pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: nets,
					},
				},
			}
			s.pol.Spec.Egress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: nets,
					},
				},
				{
					Action:   "Deny",
					Protocol: &icmpProto,
				},
			}
			s.pol = s.updatePolicy(s.pol)
		})

		var tgtPort int
		var tgtWorkload *workload.Workload

		JustBeforeEach(func() {
			s.k8sClient = s.infra.(*infrastructure.K8sDatastoreInfra).K8sClient
			testSvc = k8sService(testSvcName, clusterIP,
				tgtWorkload, 80, tgtPort, int32(npPort), s.testOpts.protocol)
			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
				"Service endpoints didn't get created? Is controller-manager happy?")

			// Sync with all felixes because some fwd tests with "none"
			// connectivity need this to be set on all sides as they will not
			// retry when there is no connectivity.
			Eventually(func() bool {
				for _, flx := range s.tc.Felixes {
					var (
						family   int
						natFtKey nat.FrontendKeyInterface
					)

					if s.testOpts.ipv6 {
						natFtKey = nat.NewNATKeyV6Intf(net.ParseIP(s.containerIP(flx.Container)), npPort, s.numericProto)
						family = 6
					} else {
						natFtKey = nat.NewNATKeyIntf(net.ParseIP(s.containerIP(flx.Container)), npPort, s.numericProto)
						family = 4
					}

					m, be, _ := dumpNATMapsAny(family, flx)
					v, ok := m[natFtKey]
					if !ok || v.Count() == 0 {
						return false
					}

					beKey := nat.NewNATBackendKey(v.ID(), 0)

					if _, ok := be[beKey]; !ok {
						return false
					}
				}
				return true
			}, 5*time.Second).Should(BeTrue())

			// Sync with policy
			s.cc.ExpectSome(s.w[1][0], s.w[0][0])
			s.cc.CheckConnectivity()
		})

		icmpProto := "icmp"
		if s.testOpts.ipv6 {
			icmpProto = "icmp6"
		}

		Describe("with dead workload", func() {
			if s.testOpts.connTimeEnabled {
				// FIXME s.externalClient also does conntime balancing
				return
			}

			BeforeEach(func() {
				s.deadWorkload.ConfigureInInfra(s.infra)
				tgtPort = 8057
				tgtWorkload = s.deadWorkload
			})

			It("should get host unreachable from nodeport via node1->node0 fwd", func() {
				err := s.tc.Felixes[0].ExecMayFail("ip", "route", "add", "unreachable", s.deadWorkload.IP)
				Expect(err).NotTo(HaveOccurred())

				tcpdump := s.externalClient.AttachTCPDump("any")
				tcpdump.SetLogEnabled(true)
				var matcher string
				if s.testOpts.ipv6 {
					matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable route %s",
						s.felixIP(1), s.containerIP(s.externalClient), s.felixIP(1))
				} else {
					matcher = fmt.Sprintf("IP %s > %s: ICMP host %s unreachable",
						s.felixIP(1), s.containerIP(s.externalClient), s.felixIP(1))
				}
				tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
				tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(int(npPort)), "or", icmpProto)

				s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(1)), npPort)
				s.cc.CheckConnectivity()

				Eventually(func() int { return tcpdump.MatchCount("ICMP") }, 10*time.Second, 200*time.Millisecond).
					Should(BeNumerically(">", 0), matcher)
			})
		})

		Describe("with wrong target port", func() {
			// TCP would send RST instead of ICMP, it is enough to test one way of
			// triggering the ICMP message
			if s.testOpts.protocol != "udp" {
				return
			}

			BeforeEach(func() {
				tgtPort = 0xdead
				tgtWorkload = s.w[0][0]
			})

			if !s.testOpts.connTimeEnabled {
				It("should get port unreachable via node1->node0 fwd", func() {
					tcpdump := s.externalClient.AttachTCPDump("any")
					tcpdump.SetLogEnabled(true)

					var matcher string

					if s.testOpts.ipv6 {
						matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
							s.felixIP(1), s.containerIP(s.externalClient), s.felixIP(1), npPort)
					} else {
						matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
							s.felixIP(1), s.containerIP(s.externalClient), s.felixIP(1), npPort)
					}
					tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(int(npPort)), "or", icmpProto)

					s.cc.ExpectNone(s.externalClient, TargetIP(s.felixIP(1)), npPort)
					s.cc.CheckConnectivity()
					Eventually(func() int { return tcpdump.MatchCount("ICMP") }, 10*time.Second, 200*time.Millisecond).
						Should(BeNumerically(">", 0), matcher)
				})
			}

			It("should get port unreachable workload to workload", func() {
				tcpdump := s.w[1][1].AttachTCPDump()
				tcpdump.SetLogEnabled(true)

				var matcher string

				if s.testOpts.ipv6 {
					matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
						tgtWorkload.IP, s.w[1][1].IP, tgtWorkload.IP, tgtPort)
				} else {
					matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
						tgtWorkload.IP, s.w[1][1].IP, tgtWorkload.IP, tgtPort)
				}
				tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
				tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(tgtPort), "or", icmpProto)

				s.cc.ExpectNone(s.w[1][1], TargetIP(tgtWorkload.IP), uint16(tgtPort))
				s.cc.CheckConnectivity()
				Eventually(func() int { return tcpdump.MatchCount("ICMP") }, 10*time.Second, 200*time.Millisecond).
					Should(BeNumerically(">", 0), matcher)
			})

			It("should get port unreachable workload to workload through NP", func() {
				tcpdump := s.w[1][1].AttachTCPDump()
				tcpdump.SetLogEnabled(true)

				var matcher string

				if s.testOpts.connTimeEnabled {
					if s.testOpts.ipv6 {
						matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
							tgtWorkload.IP, s.w[1][1].IP, s.w[0][0].IP, tgtPort)
					} else {
						matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
							tgtWorkload.IP, s.w[1][1].IP, s.w[0][0].IP, tgtPort)
					}
					tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(tgtPort), "or", icmpProto)
				} else {
					if s.testOpts.ipv6 {
						matcher = fmt.Sprintf("IP6 %s > %s: ICMP6, destination unreachable, unreachable port, %s udp port %d",
							tgtWorkload.IP, s.w[1][1].IP, s.felixIP(1), npPort)
					} else {
						matcher = fmt.Sprintf("IP %s > %s: ICMP %s udp port %d unreachable",
							tgtWorkload.IP, s.w[1][1].IP, s.felixIP(1), npPort)
					}
					tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
					tcpdump.Start(s.infra, s.testOpts.protocol, "port", strconv.Itoa(int(npPort)), "or", icmpProto)
				}

				s.cc.ExpectNone(s.w[1][1], TargetIP(s.felixIP(1)), npPort)
				s.cc.CheckConnectivity()
				Eventually(func() int { return tcpdump.MatchCount("ICMP") }, 10*time.Second, 200*time.Millisecond).
					Should(BeNumerically(">", 0), matcher)
			})
		})
	})
}
