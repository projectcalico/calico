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
	"encoding/json"
	"fmt"
	"net"
	"path"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/bpf/nat"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	options2 "github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func describeBPFSingleNodeTests(s *bpfTestContext) {
Describe("with a single node and an allow-all policy", func() {
	var (
		hostW   *workload.Workload
		w       [2]*workload.Workload
		wepCopy [2]*libapi.WorkloadEndpoint
	)

	if !s.testOpts.connTimeEnabled {
		// These tests don't depend on NAT.
		return
	}

	if s.testOpts.tunnel != "none" {
		// Single node so tunnel doesn't matter.
		return
	}

	JustBeforeEach(func() {
		s.tc, s.calicoClient = infrastructure.StartNNodeTopology(1, s.options, s.infra)
		hostW = workload.Run(
			s.tc.Felixes[0],
			"host",
			"default",
			s.felixIP(0), // Same IP as felix means "run in the host's namespace"
			"8055",
			s.testOpts.protocol)

		// Start a couple of workloads so we can check workload-to-workload and workload-to-host.
		for i := range 2 {
			wIP := fmt.Sprintf("10.65.0.%d", i+2)
			if s.testOpts.ipv6 {
				wIP = fmt.Sprintf("dead:beef::%d", i+2)
			}
			w[i] = workload.Run(s.tc.Felixes[0], fmt.Sprintf("w%d", i), "default", wIP, "8055", s.testOpts.protocol)
			w[i].WorkloadEndpoint.Labels = map[string]string{"name": w[i].Name}
			// WEP gets clobbered when we add it to the datastore, take a copy so we can re-create the WEP.
			wepCopy[i] = w[i].WorkloadEndpoint
			w[i].ConfigureInInfra(s.infra)
		}

		err := s.infra.AddDefaultDeny()
		Expect(err).NotTo(HaveOccurred())

		ensureBPFProgramsAttached(s.tc.Felixes[0])

		pol := api.NewGlobalNetworkPolicy()
		pol.Namespace = "fv"
		pol.Name = "policy-1"
		if true || s.testOpts.bpfLogLevel == "info" {
			pol.Spec.Ingress = []api.Rule{{Action: "Log"}, {Action: "Allow"}}
			pol.Spec.Egress = []api.Rule{{Action: "Log"}, {Action: "Allow"}}
		} else {
			pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
			pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
		}
		pol.Spec.Selector = "all()"

		pol = s.createPolicy(pol)
		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(s.tc.Felixes[0], w[0].InterfaceName, "ingress", "policy-1", "allow", true)
		}, "5s", "200ms").Should(BeTrue())
		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(s.tc.Felixes[0], w[0].InterfaceName, "egress", "policy-1", "allow", true)
		}, "5s", "200ms").Should(BeTrue())
		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(s.tc.Felixes[0], w[1].InterfaceName, "ingress", "policy-1", "allow", true)
		}, "5s", "200ms").Should(BeTrue())
		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(s.tc.Felixes[0], w[1].InterfaceName, "egress", "policy-1", "allow", true)
		}, "5s", "200ms").Should(BeTrue())
	})

	if s.testOpts.bpfLogLevel == "debug" && s.testOpts.protocol == "tcp" {
		Describe("with custom IptablesMarkMask", func() {
			BeforeEach(func() {
				// Disable core dumps, we know we're about to cause a panic.
				s.options.FelixCoreDumpsEnabled = false
			})

			It("0xffff000 not covering BPF bits should panic", func() {
				s.tc.Felixes[0].PanicExpected = true
				panicC := s.tc.Felixes[0].WatchStdoutFor(regexp.MustCompile("PANIC.*IptablesMarkMask/NftablesMarkMask doesn't cover bits that are used"))

				fc, err := s.calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
				felixConfigExists := err == nil
				if !felixConfigExists {
					fc = api.NewFelixConfiguration()
				}
				fc.Name = "default"
				mark := uint32(0x0ffff000)
				fc.Spec.IptablesMarkMask = &mark
				fc.Spec.NftablesMarkMask = &mark
				if felixConfigExists {
					_, err = s.calicoClient.FelixConfigurations().Update(context.Background(), fc, options2.SetOptions{})
				} else {
					fc, err = s.calicoClient.FelixConfigurations().Create(context.Background(), fc, options2.SetOptions{})
				}
				Expect(err).NotTo(HaveOccurred())

				Eventually(panicC, "5s", "100ms").Should(BeClosed())
			})

			It("0xfff00000 only covering BPF bits should panic", func() {
				s.tc.Felixes[0].PanicExpected = true
				panicC := s.tc.Felixes[0].WatchStdoutFor(regexp.MustCompile("PANIC.*Not enough mark bits available"))

				fc, err := s.calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
				felixConfigExists := err == nil
				if !felixConfigExists {
					fc = api.NewFelixConfiguration()
				}
				fc.Name = "default"
				mark := uint32(0xfff00000)
				fc.Spec.IptablesMarkMask = &mark
				fc.Spec.NftablesMarkMask = &mark
				if felixConfigExists {
					_, err = s.calicoClient.FelixConfigurations().Update(context.Background(), fc, options2.SetOptions{})
				} else {
					fc, err = s.calicoClient.FelixConfigurations().Create(context.Background(), fc, options2.SetOptions{})
				}
				Expect(err).NotTo(HaveOccurred())

				Eventually(panicC, "5s", "100ms").Should(BeClosed())
			})
		})
	}

	if s.testOpts.bpfLogLevel == "debug" && s.testOpts.protocol == "udp" && !s.testOpts.ipv6 {
		It("udp should have connectivity after a service is recreated", func() {
			clusterIP := "10.101.123.1"

			tcpdump := w[0].AttachTCPDump()
			tcpdump.SetLogEnabled(true)
			tcpdump.AddMatcher("udp-be",
				regexp.MustCompile(fmt.Sprintf("%s\\.12345 > %s\\.8055: \\[udp sum ok\\] UDP", w[1].IP, w[0].IP)))
			tcpdump.Start(s.infra, "-vvv", "udp")

			// Just to create the wrong normal entry to the service
			_, err := w[1].RunCmd("pktgen", w[1].IP, clusterIP, "udp",
				"--port-src", "12345", "--port-dst", "80")
			Expect(err).NotTo(HaveOccurred())

			// Make sure we got normal conntrack to service
			ct := dumpCTMapsAny(4, s.tc.Felixes[0])
			k1 := conntrack.NewKey(17, net.ParseIP(w[1].IP), 12345, net.ParseIP(clusterIP), 80)
			k2 := conntrack.NewKey(17, net.ParseIP(clusterIP), 80, net.ParseIP(w[1].IP), 12345)

			if v, ok := ct[k1]; ok {
				Expect(v.Type() == conntrack.TypeNormal)
			} else if v, ok := ct[k2]; ok {
				Expect(v.Type() == conntrack.TypeNormal)
			} else {
				Fail("No TypeNormal ct entry")
			}

			// Make sure the packet did not reach the backend (yet)
			Consistently(func() int { return tcpdump.MatchCount("udp-be") }, "1s").
				Should(BeNumerically("==", 0))

			testSvc := k8sService("svc-no-backends", clusterIP, w[0], 80, 8055, 0, s.testOpts.protocol)
			testSvcNamespace := testSvc.Namespace
			k8sClient := s.infra.(*infrastructure.K8sDatastoreInfra).K8sClient
			_, err = k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(),
				testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)
			natK := nat.NewNATKey(net.ParseIP(ip), port, 17)

			Eventually(func() bool {
				natmaps, _, _ := dumpNATMapsAny(4, s.tc.Felixes[0])
				if _, ok := natmaps[natK]; !ok {
					return false
				}
				return true
			}, "5s").Should(BeTrue(), "service NAT key didn't show up")

			// Make sure that despite the wrong ct entry to start with,
			// packets eventually go through.
			Eventually(func() int {
				_, err := w[1].RunCmd("pktgen", w[1].IP, clusterIP, "udp",
					"--port-src", "12345", "--port-dst", "80")
				Expect(err).NotTo(HaveOccurred())
				return tcpdump.MatchCount("udp-be")
			}, (timeouts.ScanPeriod + 5*time.Second).String(), "1s").
				Should(BeNumerically(">=", 1)) // tcpdump may not get a packet and then get 2...

			// Check that the service is properly NATted
			ct = dumpCTMapsAny(4, s.tc.Felixes[0])

			if v, ok := ct[k1]; ok {
				Expect(v.Type() == conntrack.TypeNATForward)
			} else if v, ok := ct[k2]; ok {
				Expect(v.Type() == conntrack.TypeNATForward)
			} else {
				Fail("No TypeNATForward ct entry")
			}

			k1 = conntrack.NewKey(17, net.ParseIP(w[1].IP), 12345, net.ParseIP(w[0].IP), 8055)
			k2 = conntrack.NewKey(17, net.ParseIP(w[0].IP), 8055, net.ParseIP(w[1].IP), 12345)

			if v, ok := ct[k1]; ok {
				Expect(v.Type() == conntrack.TypeNATReverse)
			} else if v, ok := ct[k2]; ok {
				Expect(v.Type() == conntrack.TypeNATReverse)
			} else {
				Fail("No TypeNATReverse ct entry")
			}
		})
	}

	Describe("with DefaultEndpointToHostAction=DROP", func() {
		BeforeEach(func() {
			s.options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "DROP"
		})
		It("should only allow traffic from workload to workload", func() {
			s.cc.ExpectSome(w[0], w[1])
			s.cc.ExpectSome(w[1], w[0])
			s.cc.ExpectNone(w[1], hostW)
			s.cc.ExpectSome(hostW, w[0])
			s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
		})
	})

	Describe("with DefaultEndpointToHostAction=RETURN", func() {
		BeforeEach(func() {
			s.options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "RETURN"
			s.options.AutoHEPsEnabled = false
		})
		It("should allow traffic from workload to host", func() {
			s.cc.Expect(Some, w[1], hostW)
			s.cc.Expect(Some, hostW, w[0])
			s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
		})
	})

	Describe("with DefaultEndpointToHostAction=ACCEPT", func() {
		BeforeEach(func() {
			s.options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "ACCEPT"
		})

		It("should allow traffic from workload to workload and to/from host", func() {
			s.cc.ExpectSome(w[0], w[1])
			s.cc.ExpectSome(w[1], w[0])
			s.cc.ExpectSome(w[1], hostW)
			s.cc.ExpectSome(hostW, w[0])
			s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
		})
	})

	if s.testOpts.protocol == "udp" && s.testOpts.connTimeEnabled {
		Describe("with BPFHostNetworkedNAT enabled", func() {
			BeforeEach(func() {
				s.options.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATEnabled)
				s.options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBTCP)
			})
			It("should not program non-udp services", func() {
				clusterIP := "10.101.0.201"
				if s.testOpts.ipv6 {
					clusterIP = "dead:beef::abcd:0:0:201"
				}
				udpsvc := &v1.Service{
					TypeMeta: typeMetaV1("Service"),
					ObjectMeta: metav1.ObjectMeta{
						Name:      "udp-service",
						Namespace: "default",
					},
					Spec: v1.ServiceSpec{
						ClusterIP: clusterIP,
						Type:      v1.ServiceTypeClusterIP,
						Ports: []v1.ServicePort{
							{
								Protocol: v1.ProtocolUDP,
								Port:     1234,
							},
						},
					},
				}

				k8sClient := s.infra.(*infrastructure.K8sDatastoreInfra).K8sClient

				_, err := k8sClient.CoreV1().Services("default").Create(context.Background(),
					udpsvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() bool {
					return checkServiceRoute(s.tc.Felixes[0], udpsvc.Spec.ClusterIP)
				}, 10*time.Second, 300*time.Millisecond).Should(BeTrue(), "Failed to sync with udp service")

				clusterIP2 := "10.101.0.202"
				if s.testOpts.ipv6 {
					clusterIP2 = "dead:beef::abcd:0:0:202"
				}
				tcpsvc := &v1.Service{
					TypeMeta: typeMetaV1("Service"),
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tcp-service",
						Namespace: "default",
					},
					Spec: v1.ServiceSpec{
						ClusterIP: clusterIP2,
						Type:      v1.ServiceTypeClusterIP,
						Ports: []v1.ServicePort{
							{
								Protocol: v1.ProtocolTCP,
								Port:     4321,
							},
						},
					},
				}

				_, err = k8sClient.CoreV1().Services("default").Create(context.Background(),
					tcpsvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				Consistently(func() bool {
					return checkServiceRoute(s.tc.Felixes[0], tcpsvc.Spec.ClusterIP)
				}, 1*time.Second, 300*time.Millisecond).Should(BeFalse(), "Unexpected TCP service")

				clusterIP3 := "10.101.0.203"
				if s.testOpts.ipv6 {
					clusterIP3 = "dead:beef::abcd:0:0:203"
				}
				tcpudpsvc := &v1.Service{
					TypeMeta: typeMetaV1("Service"),
					ObjectMeta: metav1.ObjectMeta{
						Name:      "tcp-udp-service",
						Namespace: "default",
					},
					Spec: v1.ServiceSpec{
						ClusterIP: clusterIP3,
						Type:      v1.ServiceTypeClusterIP,
						Ports: []v1.ServicePort{
							{
								Name:     "udp",
								Protocol: v1.ProtocolUDP,
								Port:     1234,
							},
							{
								Name:     "tcp",
								Protocol: v1.ProtocolTCP,
								Port:     4321,
							},
						},
					},
				}

				_, err = k8sClient.CoreV1().Services("default").Create(context.Background(),
					tcpudpsvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() bool {
					return checkServiceRoute(s.tc.Felixes[0], tcpudpsvc.Spec.ClusterIP)
				}, 10*time.Second, 300*time.Millisecond).Should(BeTrue(), "Failed to sync with tcpudp service")

				Expect(checkServiceRoute(s.tc.Felixes[0], tcpsvc.Spec.ClusterIP)).To(BeFalse())
			})
		})
	}

	if s.testOpts.protocol != "udp" { // No need to run these tests per-protocol.
		It("should recover if the BPF programs are removed", func() {
			flapInterface := func() {
				By("Flapping interface")
				s.tc.Felixes[0].Exec("ip", "link", "set", "down", w[0].InterfaceName)
				s.tc.Felixes[0].Exec("ip", "link", "set", "up", w[0].InterfaceName)
			}

			recreateWEP := func() {
				By("Recreating WEP.")
				w[0].RemoveFromInfra(s.infra)
				w[0].WorkloadEndpoint = wepCopy[0]
				w[0].ConfigureInInfra(s.infra)
			}

			for _, trigger := range []func(){flapInterface, recreateWEP} {
				// Wait for initial programming to complete.
				s.cc.Expect(Some, w[0], w[1])
				s.cc.CheckConnectivity()
				s.cc.ResetExpectations()

				By("handling ingress program removal")
				if BPFAttachType() == "tc" {
					s.tc.Felixes[0].Exec("tc", "filter", "del", "ingress", "dev", w[0].InterfaceName)
				} else {
					s.tc.Felixes[0].Exec("rm", "-rf", path.Join(bpfdefs.TcxPinDir, fmt.Sprintf("%s_ingress", w[0].InterfaceName)))
				}

				// Removing the ingress program should break connectivity due to the lack of "seen" mark.
				s.cc.Expect(None, w[0], w[1])
				s.cc.CheckConnectivity()
				s.cc.ResetExpectations()

				// Trigger felix to recover.
				trigger()
				s.cc.Expect(Some, w[0], w[1])
				s.cc.CheckConnectivity()

				// Check the program is put back.
				if BPFAttachType() == "tc" {
					Eventually(func() string {
						out, _ := s.tc.Felixes[0].ExecOutput("tc", "filter", "show", "ingress", "dev", w[0].InterfaceName)
						return out
					}, "5s", "200ms").Should(ContainSubstring("cali_tc_preambl"),
						fmt.Sprintf("from wep not loaded for %s", w[0].InterfaceName))
				} else {
					Eventually(func() string {
						out, _ := s.tc.Felixes[0].ExecOutput("stat", path.Join(bpfdefs.TcxPinDir, fmt.Sprintf("%s_ingress", w[0].InterfaceName)))
						return out
					}, "5s", "200ms").ShouldNot(ContainSubstring("No such file or directory"),
						fmt.Sprintf("from wep not loaded for %s", w[0].InterfaceName))
				}

				By("handling egress program removal")
				if BPFAttachType() == "tc" {
					s.tc.Felixes[0].Exec("tc", "filter", "del", "egress", "dev", w[0].InterfaceName)
				} else {
					s.tc.Felixes[0].Exec("rm", "-rf", path.Join(bpfdefs.TcxPinDir, fmt.Sprintf("%s_egress", w[0].InterfaceName)))
				}
				// Removing the egress program doesn't stop traffic.

				// Trigger felix to recover.
				trigger()

				// Check the program is put back.
				if BPFAttachType() == "tc" {
					Eventually(func() string {
						out, _ := s.tc.Felixes[0].ExecOutput("tc", "filter", "show", "egress", "dev", w[0].InterfaceName)
						return out
					}, "5s", "200ms").Should(ContainSubstring("cali_tc_preambl"),
						fmt.Sprintf("to wep not loaded for %s", w[0].InterfaceName))
				} else {
					Eventually(func() string {
						out, _ := s.tc.Felixes[0].ExecOutput("stat", path.Join(bpfdefs.TcxPinDir, fmt.Sprintf("%s_egress", w[0].InterfaceName)))
						return out
					}, "5s", "200ms").ShouldNot(ContainSubstring("No such file or directory"),
						fmt.Sprintf("from wep not loaded for %s", w[0].InterfaceName))
				}
				s.cc.CheckConnectivity()

				if BPFAttachType() == "tc" {
					By("Handling qdisc removal")
					s.tc.Felixes[0].Exec("tc", "qdisc", "delete", "dev", w[0].InterfaceName, "clsact")

					// Trigger felix to recover.
					trigger()

					// Check programs are put back.
					Eventually(func() string {
						out, _ := s.tc.Felixes[0].ExecOutput("tc", "filter", "show", "ingress", "dev", w[0].InterfaceName)
						return out
					}, "5s", "200ms").Should(ContainSubstring("cali_tc_preambl"),
						fmt.Sprintf("from wep not loaded for %s", w[0].InterfaceName))
					Eventually(func() string {
						out, _ := s.tc.Felixes[0].ExecOutput("tc", "filter", "show", "egress", "dev", w[0].InterfaceName)
						return out
					}, "5s", "200ms").Should(ContainSubstring("cali_tc_preambl"),
						fmt.Sprintf("to wep not loaded for %s", w[0].InterfaceName))
					s.cc.CheckConnectivity()
				}
				s.cc.ResetExpectations()

				// Add a policy to block traffic.
				By("Adding deny policy")
				denyPol := api.NewGlobalNetworkPolicy()
				denyPol.Name = "policy-2"
				var one float64 = 1
				denyPol.Spec.Order = &one
				denyPol.Spec.Ingress = []api.Rule{{Action: "Deny"}}
				denyPol.Spec.Egress = []api.Rule{{Action: "Deny"}}
				denyPol.Spec.Selector = "all()"
				denyPol = s.createPolicy(denyPol)

				s.cc.Expect(None, w[0], w[1])
				s.cc.Expect(None, w[1], w[0])
				s.cc.CheckConnectivity()
				s.cc.ResetExpectations()

				By("Removing deny policy")
				_, err := s.calicoClient.GlobalNetworkPolicies().Delete(context.Background(), "policy-2", options2.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				s.cc.Expect(Some, w[0], w[1])
				s.cc.Expect(Some, w[1], w[0])
				s.cc.CheckConnectivity()
				s.cc.ResetExpectations()
			}
		})

		It("should respond back to host is the original traffic came from the host", func() {
			if NFTMode() || s.testOpts.ipv6 {
				return
			}

			By("Setting up istio-like rules that SNAT host as link-local IP")

			s.tc.Felixes[0].Exec("iptables", "-t", "nat", "-A", "POSTROUTING", "-d", w[0].IP, "-j",
				"SNAT", "--to-source", "169.254.7.127")

			By("Testing connectivity from host to pod")

			s.cc.Expect(Some, hostW, w[0], ExpectWithSrcIPs("169.254.7.127"))
			s.cc.CheckConnectivity()
		})
	}

	if s.testOpts.nonProtoTests {
		// We can only test that felix _sets_ this because the flag is one-way and cannot be unset.
		It("should enable the kernel.unprivileged_bpf_disabled sysctl", func() {
			Eventually(func() string {
				out, err := s.tc.Felixes[0].ExecOutput("sysctl", "kernel.unprivileged_bpf_disabled")
				if err != nil {
					log.WithError(err).Error("Failed to run sysctl")
				}
				return out
			}).Should(ContainSubstring("kernel.unprivileged_bpf_disabled = 1"))
		})

		It("should remove terminating workload from the NAT backends", func() {
			By("Creating a fake service with fake endpoint")

			clusterIP := "10.101.0.254"
			svcIP1 := "192.168.12.1"
			svcIP2 := "192.168.12.2"
			svcIP3 := "192.168.12.3"
			addrType := discovery.AddressTypeIPv4
			family := 4
			if s.testOpts.ipv6 {
				clusterIP = "dead:beef::abcd:0:0:254"
				svcIP1 = "dead:beef::192:168:12:1"
				svcIP2 = "dead:beef::192:168:12:2"
				svcIP3 = "dead:beef::192:168:12:3"
				addrType = discovery.AddressTypeIPv6
				family = 6
			}

			fakeSvc := &v1.Service{
				TypeMeta:   typeMetaV1("Service"),
				ObjectMeta: objectMetaV1("fake-service"),
				Spec: v1.ServiceSpec{
					ClusterIP: clusterIP,
					Type:      "ClusterIP",
					Ports: []v1.ServicePort{
						{
							Protocol: v1.ProtocolTCP,
							Port:     int32(11666),
						},
					},
				},
			}

			k8sClient := s.infra.(*infrastructure.K8sDatastoreInfra).K8sClient
			_, err := k8sClient.CoreV1().Services("default").Create(context.Background(), fakeSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			portName := ""
			portProto := v1.ProtocolTCP
			portPort := int32(11166)
			falsePtr := new(bool)
			*falsePtr = false
			truePtr := new(bool)
			*truePtr = true

			fakeEps := &discovery.EndpointSlice{
				TypeMeta: metav1.TypeMeta{
					Kind:       "EndpointSlice",
					APIVersion: "discovery.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-service-eps",
					Namespace: "default",
					Labels: map[string]string{
						"kubernetes.io/service-name": "fake-service",
					},
				},
				AddressType: addrType,
				Endpoints: []discovery.Endpoint{
					{
						Addresses: []string{svcIP1},
						Conditions: discovery.EndpointConditions{
							Ready:       truePtr,
							Terminating: falsePtr,
						},
					},
					{
						Addresses: []string{svcIP2},
						Conditions: discovery.EndpointConditions{
							Ready:       truePtr,
							Terminating: falsePtr,
						},
					},
					{
						Addresses: []string{svcIP3},
						Conditions: discovery.EndpointConditions{
							Ready:       truePtr,
							Terminating: falsePtr,
						},
					},
				},
				Ports: []discovery.EndpointPort{{
					Name:     &portName,
					Protocol: &portProto,
					Port:     &portPort,
				}},
			}

			_, err = k8sClient.DiscoveryV1().EndpointSlices("default").
				Create(context.Background(), fakeEps, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			var natK nat.FrontendKeyInterface
			if s.testOpts.ipv6 {
				natK = nat.NewNATKeyV6(net.ParseIP(clusterIP), 11666, 6)
			} else {
				natK = nat.NewNATKey(net.ParseIP(clusterIP), 11666, 6)
			}

			Eventually(func(g Gomega) {
				natmap, natbe, _ := dumpNATMapsAny(family, s.tc.Felixes[0])
				g.Expect(natmap).To(HaveKey(natK))
				g.Expect(natmap[natK].Count()).To(Equal(uint32(3)))
				svc := natmap[natK]
				bckID := svc.ID()
				g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 0)))
				g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 1)))
				g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 2)))
				g.Expect(natbe).NotTo(HaveKey(nat.NewNATBackendKey(bckID, 3)))
			}, "5s").Should(Succeed(), "service or backedns didn't show up")

			fakeEps.Endpoints[1].Conditions.Ready = falsePtr
			fakeEps.Endpoints[1].Conditions.Terminating = truePtr

			_, err = k8sClient.DiscoveryV1().EndpointSlices("default").
				Update(context.Background(), fakeEps, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				natmap, natbe, _ := dumpNATMapsAny(family, s.tc.Felixes[0])
				g.Expect(natmap).To(HaveKey(natK))
				g.Expect(natmap[natK].Count()).To(Equal(uint32(2)))
				svc := natmap[natK]
				bckID := svc.ID()
				g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 0)))
				g.Expect(natbe).To(HaveKey(nat.NewNATBackendKey(bckID, 1)))
				g.Expect(natbe).NotTo(HaveKey(nat.NewNATBackendKey(bckID, 2)))
			}, "5s").Should(Succeed(), "NAT did not get updated properly")
		})

		It("should cleanup after we disable eBPF", func() {
			By("Waiting for dp to get setup up")

			ensureBPFProgramsAttached(s.tc.Felixes[0], "bpfout.cali")
			progIDs := set.New[int]()
			mapIDs := set.New[int]()

			// Get the program IDs of the preamble programs that we attach
			// as part of this test. There can be other preamble programs
			// from previous tests and we want to ignore those when checking that programs are cleaned up after disabling BPF.
			getPreambleProgramIDs := func() set.Set[int] {
				var bpfnetTCX []struct {
					TC []struct {
						Name string `json:"name"`
						ID   int    `json:"prog_id"`
					} `json:"tc"`
				}

				var bpfnet []struct {
					TC []struct {
						Name string `json:"name"`
						ID   int    `json:"id"`
					} `json:"tc"`
				}
				out, err := s.tc.Felixes[0].ExecOutput("bpftool", "net", "show", "-j")
				Expect(err).NotTo(HaveOccurred())
				preambleIDs := set.New[int]()
				if BPFAttachType() == "tc" {
					err = json.Unmarshal([]byte(out), &bpfnet)
					Expect(err).NotTo(HaveOccurred())
					for _, entry := range bpfnet {
						for _, prog := range entry.TC {
							if strings.Contains(prog.Name, "cali_tc_pream") {
								preambleIDs.Add(prog.ID)
							}
						}
					}
				} else {
					err = json.Unmarshal([]byte(out), &bpfnetTCX)
					Expect(err).NotTo(HaveOccurred())
					for _, entry := range bpfnetTCX {
						for _, prog := range entry.TC {
							if strings.Contains(prog.Name, "cali_tc_pream") {
								preambleIDs.Add(prog.ID)
							}
						}
					}
				}
				return preambleIDs
			}

			var preambleIDsBefore set.Set[int]
			Eventually(func() int {
				preambleIDsBefore = getPreambleProgramIDs()
				return preambleIDsBefore.Len()
			}, "15s", "1s").Should(Equal(10)) // 10 = 2 (ingress+egress) * 5 interfaces (bpfout, lo, eth0, caliXXX x2)

			type bpfProgs []struct {
				ID     int    `json:"id"`
				Name   string `json:"name"`
				MapIDs []int  `json:"map_ids"`
			}
			programs := bpfProgs{}
			out, err := s.tc.Felixes[0].ExecOutput("bpftool", "prog", "show", "-j")
			Expect(err).NotTo(HaveOccurred())
			err = json.Unmarshal([]byte(out), &programs)
			Expect(err).NotTo(HaveOccurred())

			// Get the program and map IDs of all program that are currently attached.
			for _, prog := range programs {
				if strings.Contains(prog.Name, "cali_tc_pream") && !preambleIDsBefore.Contains(prog.ID) {
					continue
				}
				progIDs.Add(prog.ID)
				mapIDs.AddAll(prog.MapIDs)
			}

			// check for cgroups
			out, err = s.tc.Felixes[0].ExecOutput("bpftool", "cgroup", "show", "/run/calico/cgroup")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("calico_connect"))

			By("Changing env and restarting felix")

			s.tc.Felixes[0].SetEnv(map[string]string{"FELIX_BPFENABLED": "false"})
			s.tc.Felixes[0].Restart()

			By("Checking that all programs got cleaned up")

			// Check that the preamble programs we attached got cleaned up.
			Eventually(func() int {
				return getPreambleProgramIDs().Len()
			}, "15s", "1s").Should(Equal(0))

			programs = bpfProgs{}
			out, err = s.tc.Felixes[0].ExecOutput("bpftool", "prog", "show", "-j")
			Expect(err).NotTo(HaveOccurred())
			err = json.Unmarshal([]byte(out), &programs)
			Expect(err).NotTo(HaveOccurred())
			mapIDsAfter := set.New[int]()
			progIDsAfter := set.New[int]()
			for _, prog := range programs {
				progIDsAfter.Add(prog.ID)
			}

			for _, prog := range progIDs.Slice() {
				Expect(progIDsAfter).NotTo(ContainElement(prog))
			}

			var bpfMaps []struct {
				ID int `json:"id"`
			}
			out, err = s.tc.Felixes[0].ExecOutput("bpftool", "map", "show", "-j")
			Expect(err).NotTo(HaveOccurred())
			err = json.Unmarshal([]byte(out), &bpfMaps)
			Expect(err).NotTo(HaveOccurred())

			for _, m := range bpfMaps {
				mapIDsAfter.Add(m.ID)
			}
			for _, id := range mapIDs.Slice() {
				Expect(mapIDsAfter).NotTo(ContainElement(id))
			}

			out, err = s.tc.Felixes[0].ExecOutput("bpftool", "cgroup", "show", "/run/calico/cgroup")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).NotTo(ContainSubstring("calico_connect"))

			out, _ = s.tc.Felixes[0].ExecCombinedOutput("ip", "link", "show", "dev", "bpfin.cali")
			Expect(out).To(Equal("Device \"bpfin.cali\" does not exist.\n"))
			out, _ = s.tc.Felixes[0].ExecCombinedOutput("ip", "link", "show", "dev", "bpfout.cali")
			Expect(out).To(Equal("Device \"bpfout.cali\" does not exist.\n"))
		})
	}
})
}
