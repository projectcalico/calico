// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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
	"errors"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ cluster routing using Felix programming routes", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	type testConf struct {
		IPIPMode    api.IPIPMode
		RouteSource string
		BrokenXSum  bool
		EnableIPv6  bool
	}
	for _, testConfig := range []testConf{
		// IPIP does not support IPv6.
		{api.IPIPModeCrossSubnet, "CalicoIPAM", true, false},
		{api.IPIPModeCrossSubnet, "WorkloadIPs", false, false},

		{api.IPIPModeAlways, "CalicoIPAM", true, false},
		{api.IPIPModeAlways, "WorkloadIPs", false, false},

		// No encap routing tests. BrokenXSum is irrelevant in these cases.
		{api.IPIPModeNever, "CalicoIPAM", false, false},
		{api.IPIPModeNever, "WorkloadIPs", false, false},
		{api.IPIPModeNever, "CalicoIPAM", false, true},
		{api.IPIPModeNever, "WorkloadIPs", false, true},
	} {
		ipipMode := testConfig.IPIPMode
		routeSource := testConfig.RouteSource
		brokenXSum := testConfig.BrokenXSum
		enableIPv6 := testConfig.EnableIPv6

		Describe(fmt.Sprintf("with topology set to IPIPMode %s, routeSource %s, brokenXSum: %v, enableIPv6: %v", ipipMode, routeSource, brokenXSum, enableIPv6), func() {
			var (
				infra           infrastructure.DatastoreInfra
				tc              infrastructure.TopologyContainers
				felixes         []*infrastructure.Felix
				client          client.Interface
				w               [3]*workload.Workload
				w6              [3]*workload.Workload
				hostW           [3]*workload.Workload
				hostW6          [3]*workload.Workload
				cc              *connectivity.Checker
				topologyOptions infrastructure.TopologyOptions
				timeout         time.Duration = time.Second * 30
			)

			BeforeEach(func() {
				infra = getInfra()
				if (NFTMode() || BPFMode()) && getDataStoreType(infra) == "etcdv3" {
					Skip("Skipping NFT / BPF test for etcdv3 backend.")
				}

				topologyOptions = createIPIPBaseTopologyOptions(ipipMode, enableIPv6, routeSource, brokenXSum)
				tc, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

				w, w6, hostW, hostW6 = setupWorkloads(infra, tc, topologyOptions, client, enableIPv6)
				felixes = tc.Felixes

				cc = &connectivity.Checker{}
			})

			AfterEach(func() {
				if CurrentGinkgoTestDescription().Failed {
					for _, felix := range tc.Felixes {
						if NFTMode() {
							logNFTDiags(felix)
						} else {
							felix.Exec("iptables-save", "-c")
							felix.Exec("ipset", "list")
						}
						felix.Exec("ip", "r")
						if enableIPv6 {
							felix.Exec("ip", "-6", "route")
						}
						felix.Exec("ip", "a")
						if BPFMode() {
							felix.Exec("calico-bpf", "policy", "dump", "eth0", "all", "--asm")
						}
					}
				}

				for _, wl := range w {
					wl.Stop()
				}
				for _, wl := range w6 {
					wl.Stop()
				}
				for _, wl := range hostW {
					wl.Stop()
				}
				for _, wl := range hostW6 {
					wl.Stop()
				}
				tc.Stop()

				if CurrentGinkgoTestDescription().Failed {
					infra.DumpErrorData()
				}
				infra.Stop()
			})

			// Only applicable to IPIP encap
			if ipipMode != api.IPIPModeNever {
				if brokenXSum {
					It("should disable checksum offload", func() {
						Eventually(func() string {
							out, err := felixes[0].ExecOutput("ethtool", "-k", dataplanedefs.IPIPIfaceName)
							if err != nil {
								return fmt.Sprintf("ERROR: %v", err)
							}
							return out
						}, "15s", "100ms").Should(ContainSubstring("tx-checksumming: off"))
					})
				} else {
					It("should not disable checksum offload", func() {
						Eventually(func() string {
							out, err := felixes[0].ExecOutput("ethtool", "-k", dataplanedefs.IPIPIfaceName)
							if err != nil {
								return fmt.Sprintf("ERROR: %v", err)
							}
							return out
						}, "15s", "100ms").Should(ContainSubstring("tx-checksumming: on"))
					})
				}

				It("should fully randomize MASQUERADE rules", func() {
					for _, felix := range tc.Felixes {
						if NFTMode() {
							Eventually(func() string {
								out, _ := felix.ExecOutput("nft", "list", "table", "calico")
								return out
							}, "15s", "100ms").Should(ContainSubstring("fully-random"))
						} else {
							Eventually(func() string {
								out, _ := felix.ExecOutput("iptables-save", "-c")
								return out
							}, "15s", "100ms").Should(ContainSubstring("--random-fully"))
						}
					}
				})
			}

			It("should have workload to workload connectivity", func() {
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[1], w[0])

				if enableIPv6 {
					cc.ExpectSome(w6[0], w6[1])
					cc.ExpectSome(w6[1], w6[0])
				}

				cc.CheckConnectivityWithTimeout(timeout)
			})

			It("should have some blackhole routes installed", func() {
				if routeSource == "WorkloadIPs" {
					Skip("not applicable for workload ips")
					return
				}

				nodes := []string{
					"blackhole 10.65.0.0/26 proto 80",
					"blackhole 10.65.1.0/26 proto 80",
					"blackhole 10.65.2.0/26 proto 80",
				}

				for n, result := range nodes {
					Eventually(func() string {
						o, _ := felixes[n].ExecOutput("ip", "r", "s", "type", "blackhole")
						return o
					}, "20s", "100ms").Should(ContainSubstring(result))
					wName := fmt.Sprintf("w%d", n)

					err := client.IPAM().ReleaseByHandle(context.TODO(), wName)
					Expect(err).NotTo(HaveOccurred())

					if enableIPv6 {
						w6Name := fmt.Sprintf("w6-%d", n)
						err := client.IPAM().ReleaseByHandle(context.TODO(), w6Name)
						Expect(err).NotTo(HaveOccurred())
					}

					affinityCfg := ipam.AffinityConfig{
						AffinityType: ipam.AffinityTypeHost,
						Host:         felixes[n].Hostname,
					}
					err = client.IPAM().ReleaseHostAffinities(context.TODO(), affinityCfg, true)
					Expect(err).NotTo(HaveOccurred())

					Eventually(func() string {
						o, _ := felixes[n].ExecOutput("ip", "r", "s", "type", "blackhole")
						return o
					}, "20s", "100ms").Should(BeEmpty())
				}
			})

			if ipipMode == api.IPIPModeCrossSubnet && !enableIPv6 && routeSource == "CalicoIPAM" {
				It("should move no encap routes when the node IP moves to a new interface", func() {
					// Routes should look like this:
					//
					//   default via 172.17.0.1 dev eth0
					//   blackhole 10.65.0.0/26 proto 80
					//   10.65.0.2 dev cali29f56ea1abf scope link
					//   10.65.1.0/26 via 172.17.0.6 dev eth0 proto 80 onlink
					//   10.65.2.0/26 via 172.17.0.5 dev eth0 proto 80 onlink
					//   172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.7
					felix := tc.Felixes[0]
					Eventually(felix.ExecOutputFn("ip", "route", "show"), "15s").Should(ContainSubstring(
						fmt.Sprintf("10.65.1.0/26 via %s dev eth0 proto 80 onlink", tc.Felixes[1].IP)))

					// Find the default and subnet routes, we'll need to
					// recreate those after moving the IP.
					defaultRoute, err := felix.ExecOutput("ip", "route", "show", "default")
					Expect(err).NotTo(HaveOccurred())
					lines := strings.Split(strings.Trim(defaultRoute, "\n "), "\n")
					Expect(lines).To(HaveLen(1))
					defaultRouteArgs := strings.Split(strings.Replace(lines[0], "eth0", "bond0", -1), " ")

					// Assuming the subnet route will be "proto kernel" and that will be the only such route.
					subnetRoute, err := felix.ExecOutput("ip", "route", "show", "proto", "kernel")
					Expect(err).NotTo(HaveOccurred())
					lines = strings.Split(strings.Trim(subnetRoute, "\n "), "\n")
					Expect(lines).To(HaveLen(1), "expected only one proto kernel route, has docker's routing set-up changed?")
					subnetArgs := strings.Split(strings.Replace(lines[0], "eth0", "bond0", -1), " ")

					// Add the bond, replacing eth0.
					felix.Exec("ip", "addr", "del", felix.IP, "dev", "eth0")
					felix.Exec("ip", "link", "add", "dev", "bond0", "type", "bond")
					felix.Exec("ip", "link", "set", "dev", "eth0", "down")
					felix.Exec("ip", "link", "set", "dev", "eth0", "master", "bond0")
					felix.Exec("ip", "link", "set", "dev", "eth0", "up")
					felix.Exec("ip", "link", "set", "dev", "bond0", "up")

					// Move IP to bond0.  We don't actually set up more than one
					// bonded interface in this test, we just want to know that
					// felix spots the IP move.
					ipWithSubnet := felix.IP + "/" + felix.GetIPPrefix()
					felix.Exec("ip", "addr", "add", ipWithSubnet, "dev", "bond0")

					// Re-add the default routes, via bond0 (one gets removed when
					// eth0 goes down, the other gets stuck on eth0).
					felix.Exec(append([]string{"ip", "r", "add"}, defaultRouteArgs...)...)
					felix.Exec(append([]string{"ip", "r", "replace"}, subnetArgs...)...)

					expCrossSubRoute := fmt.Sprintf("10.65.1.0/26 via %s dev bond0 proto 80 onlink", tc.Felixes[1].IP)
					Eventually(felix.ExecOutputFn("ip", "route", "show"), "60s").Should(
						ContainSubstring(expCrossSubRoute),
						"Cross-subnet route should move from eth0 to bond0.",
					)
				})
			}

			It("should have host to workload connectivity", func() {
				if ipipMode == api.IPIPModeAlways && routeSource == "WorkloadIPs" {
					Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
				}

				cc.ExpectSome(tc.Felixes[0], w[0])
				cc.ExpectSome(tc.Felixes[0], w[1])

				if enableIPv6 {
					cc.ExpectSome(tc.Felixes[0], w6[0])
					cc.ExpectSome(tc.Felixes[0], w6[1])
				}

				cc.CheckConnectivityWithTimeout(timeout)
			})

			It("should have host to host connectivity", func() {
				cc.ExpectSome(tc.Felixes[0], hostW[1])
				cc.ExpectSome(tc.Felixes[1], hostW[0])

				if enableIPv6 {
					cc.ExpectSome(felixes[0], hostW6[1])
					cc.ExpectSome(felixes[1], hostW6[0])
				}

				cc.CheckConnectivityWithTimeout(timeout)
			})

			Context("with host protection policy in place", func() {
				BeforeEach(func() {
					if enableIPv6 {
						Skip("Skipping due to known issue with ICMPv6 NDP being dropped with host endpoints")
					}

					// Make sure our new host endpoints don't cut felix off from the datastore.
					err := infra.AddAllowToDatastore("host-endpoint=='true'")
					Expect(err).NotTo(HaveOccurred())

					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()

					for _, f := range tc.Felixes {
						hep := api.NewHostEndpoint()
						hep.Name = "eth0-" + f.Name
						hep.Labels = map[string]string{
							"host-endpoint": "true",
						}
						hep.Spec.Node = f.Hostname
						hep.Spec.ExpectedIPs = []string{f.IP}
						_, err := client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
						Expect(err).NotTo(HaveOccurred())
					}
				})

				It("should have workload connectivity but not host connectivity", func() {
					// Host endpoints (with no policies) block host-host traffic due to default drop.
					cc.ExpectNone(tc.Felixes[0], hostW[1])
					cc.ExpectNone(tc.Felixes[1], hostW[0])
					if enableIPv6 {
						cc.ExpectNone(felixes[0], hostW6[1])
						cc.ExpectNone(felixes[1], hostW6[0])
					}

					// But the rules to allow IPIP between our hosts let the workload traffic through.
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					if enableIPv6 {
						cc.ExpectSome(w6[0], w6[1])
						cc.ExpectSome(w6[1], w6[0])
					}
					cc.CheckConnectivityWithTimeout(timeout)
				})
			})

			Context("with all-interfaces host protection policy in place", func() {
				BeforeEach(func() {
					if enableIPv6 {
						Skip("Skipping due to known issue with ICMPv6 NDP being dropped with host endpoints")
					}

					// Make sure our new host endpoints don't cut felix off from the datastore.
					err := infra.AddAllowToDatastore("host-endpoint=='true'")
					Expect(err).NotTo(HaveOccurred())

					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()

					// Create host endpoints for each node.
					for _, f := range tc.Felixes {
						hep := api.NewHostEndpoint()
						hep.Name = "all-interfaces-" + f.Name
						hep.Labels = map[string]string{
							"host-endpoint": "true",
							"hostname":      f.Hostname,
						}
						hep.Spec.Node = f.Hostname
						hep.Spec.ExpectedIPs = []string{f.IP}
						hep.Spec.InterfaceName = "*"
						_, err := client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
						Expect(err).NotTo(HaveOccurred())
					}
				})

				It("should have workload connectivity but not host connectivity", func() {
					// Host endpoints (with no policies) block host-host traffic due to default drop.
					cc.ExpectNone(felixes[0], hostW[1])
					cc.ExpectNone(felixes[1], hostW[0])
					if enableIPv6 {
						cc.ExpectNone(felixes[0], hostW6[1])
						cc.ExpectNone(felixes[1], hostW6[0])
					}

					// Host => workload is not allowed
					cc.ExpectNone(felixes[0], w[1])
					cc.ExpectNone(felixes[1], w[0])
					if enableIPv6 {
						cc.ExpectNone(felixes[0], w6[1])
						cc.ExpectNone(felixes[1], w6[0])
					}

					// But host => own-workload is allowed
					cc.ExpectSome(felixes[0], w[0])
					cc.ExpectSome(felixes[1], w[1])
					if enableIPv6 {
						cc.ExpectSome(felixes[0], w6[0])
						cc.ExpectSome(felixes[1], w6[1])
					}

					// But the rules to allow VXLAN between our hosts let the workload traffic through.
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					if enableIPv6 {
						cc.ExpectSome(w6[0], w6[1])
						cc.ExpectSome(w6[1], w6[0])
					}

					cc.CheckConnectivityWithTimeout(timeout)
				})

				It("should allow felixes[0] to reach felixes[1] if ingress and egress policies are in place", func() {
					// Create a policy selecting felix[1] that allows egress.
					policy := api.NewGlobalNetworkPolicy()
					policy.Name = "f0-egress"
					policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
					policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[0].Hostname)
					_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())

					// But there is no policy allowing ingress into felix[1].
					cc.ExpectNone(felixes[0], hostW[1])
					if enableIPv6 {
						cc.ExpectNone(felixes[0], hostW6[1])
					}

					// felixes[1] can't reach felixes[0].
					cc.ExpectNone(felixes[1], hostW[0])
					if enableIPv6 {
						cc.ExpectNone(felixes[1], hostW6[0])
					}

					// Workload connectivity is unchanged.
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					if enableIPv6 {
						cc.ExpectSome(w6[0], w6[1])
						cc.ExpectSome(w6[1], w6[0])
					}
					cc.CheckConnectivityWithTimeout(timeout)

					cc.ResetExpectations()

					// Now add a policy selecting felix[1] that allows ingress.
					policy = api.NewGlobalNetworkPolicy()
					policy.Name = "f1-ingress"
					policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
					policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", tc.Felixes[1].Hostname)
					_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())

					// Now felixes[0] can reach felixes[1].
					cc.ExpectSome(felixes[0], hostW[1])
					if enableIPv6 {
						cc.ExpectSome(felixes[0], hostW6[1])
					}

					// felixes[1] still can't reach felixes[0].
					cc.ExpectNone(felixes[1], hostW[0])
					if enableIPv6 {
						cc.ExpectNone(felixes[1], hostW6[0])
					}

					// Workload connectivity is unchanged.
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					if enableIPv6 {
						cc.ExpectSome(w6[0], w6[1])
						cc.ExpectSome(w6[1], w6[0])
					}

					cc.CheckConnectivityWithTimeout(timeout)
				})

				Context("with policy allowing port 8055", func() {
					BeforeEach(func() {
						tcp := numorstring.ProtocolFromString("tcp")
						udp := numorstring.ProtocolFromString("udp")
						p8055 := numorstring.SinglePort(8055)
						policy := api.NewGlobalNetworkPolicy()
						policy.Name = "allow-8055"
						policy.Spec.Ingress = []api.Rule{
							{
								Protocol: &udp,
								Destination: api.EntityRule{
									Ports: []numorstring.Port{p8055},
								},
								Action: api.Allow,
							},
							{
								Protocol: &tcp,
								Destination: api.EntityRule{
									Ports: []numorstring.Port{p8055},
								},
								Action: api.Allow,
							},
						}
						policy.Spec.Egress = []api.Rule{
							{
								Protocol: &udp,
								Destination: api.EntityRule{
									Ports: []numorstring.Port{p8055},
								},
								Action: api.Allow,
							},
							{
								Protocol: &tcp,
								Destination: api.EntityRule{
									Ports: []numorstring.Port{p8055},
								},
								Action: api.Allow,
							},
						}
						policy.Spec.Selector = fmt.Sprintf("has(host-endpoint)")
						_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())
					})

					// Please take care if adding other connectivity checks into this case, to
					// avoid those other checks setting up conntrack state that allows the
					// existing case to pass for a different reason.
					It("allows host0 to remote Calico-networked workload via service IP", func() {
						if ipipMode == api.IPIPModeAlways && routeSource == "WorkloadIPs" {
							Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
						}
						// Allocate a service IP.
						serviceIP := "10.101.0.11"
						serviceV6IP := "deca:fbad:0000:0000:0000:0000:0000:0001"
						port := 8055
						tgtPort := 8055

						createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
							infra:     infra,
							felix:     tc.Felixes[0],
							w:         w[1],
							svcName:   "test-svc",
							serviceIP: serviceIP,
							targetIP:  w[1].IP,
							port:      port,
							tgtPort:   tgtPort,
							chain:     "OUTPUT",
						})
						if enableIPv6 {
							createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
								infra:     infra,
								felix:     felixes[0],
								w:         w6[1],
								svcName:   "test-v6-svc",
								serviceIP: serviceV6IP,
								targetIP:  w6[1].IP,
								port:      port,
								tgtPort:   tgtPort,
								chain:     "OUTPUT",
								ipv6:      true,
							})
						}
						// Expect to connect to the service IP.
						cc.ExpectSome(felixes[0], connectivity.TargetIP(serviceIP), uint16(port))
						if enableIPv6 {
							cc.ExpectSome(felixes[0], connectivity.TargetIP(serviceV6IP), uint16(port))
						}
						cc.CheckConnectivityWithTimeout(timeout)
					})
				})
			})

			Context("after removing BGP address from third node", func() {
				// Simulate having a host send VXLAN traffic from an unknown source, should get blocked.
				BeforeEach(func() {
					ipsetLen := allHostsIPSetSize(felixes, ipipMode)
					for _, f := range felixes {
						if BPFMode() {
							// one host and one host tunnel routes per node
							expectedNumRoutes := len(felixes) * 2
							if ipipMode == api.IPIPModeNever {
								// one host routes per node
								expectedNumRoutes = len(felixes)
							}
							Eventually(func() int {
								return strings.Count(f.BPFRoutes(), "host")
							}).Should(Equal(expectedNumRoutes),
								fmt.Sprintf("Expected %v route per node, not: %v", expectedNumRoutes, f.BPFRoutes()))
						} else if NFTMode() {
							Eventually(f.NFTSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(ipsetLen))
						} else {
							Eventually(f.IPSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(ipsetLen))
						}
					}

					// Pause felix[2], so it can't touch the dataplane; we want to
					// test that felix[0] blocks the traffic.
					pid := felixes[2].GetFelixPID()
					felixes[2].Exec("kill", "-STOP", fmt.Sprint(pid))

					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					infra.RemoveNodeAddresses(felixes[2])
					node, err := client.Nodes().Get(ctx, felixes[2].Hostname, options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())

					node.Spec.BGP = nil
					_, err = client.Nodes().Update(ctx, node, options.SetOptions{})
				})

				It("should have no connectivity from third felix and expected number of IPs in allow list", func() {
					ipsetLen := allHostsIPSetSize(felixes, ipipMode)
					if BPFMode() {
						// one host and one host tunnel routes per node
						expectedNumRoutes := (len(felixes) - 1) * 2
						if ipipMode == api.IPIPModeNever {
							// one host routes per node
							expectedNumRoutes = (len(felixes) - 1)
						}
						Eventually(func() int {
							return strings.Count(felixes[0].BPFRoutes(), "host")
						}).Should(Equal(expectedNumRoutes),
							fmt.Sprintf("Expected %v route per node, not: %v", expectedNumRoutes, felixes[0].BPFRoutes()))
					} else if NFTMode() {
						Eventually(felixes[0].NFTSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(ipsetLen))
					} else {
						Eventually(felixes[0].IPSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(ipsetLen))
					}

					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					cc.ExpectNone(w[0], w[2])
					cc.ExpectNone(w[1], w[2])
					cc.ExpectNone(w[2], w[0])
					cc.ExpectNone(w[2], w[1])

					if enableIPv6 {
						cc.ExpectSome(w6[0], w6[1])
						cc.ExpectSome(w6[1], w6[0])
						cc.ExpectNone(w6[0], w6[2])
						cc.ExpectNone(w6[2], w6[0])
						cc.ExpectNone(w6[1], w6[2])
						cc.ExpectNone(w6[2], w6[1])
					}
					cc.CheckConnectivityWithTimeout(timeout)
				})
			})

			// Explicitly verify that the IPIP allow-list IP set is doing its job (since Felix makes multiple dataplane
			// changes when the BGP IP disappears, and we want to make sure that it's the rule that's causing the
			// connectivity to drop).
			Context("after removing BGP address from third node, all felixes paused", func() {
				// Simulate having a host send IPIP traffic from an unknown source, should get blocked.
				BeforeEach(func() {
					if BPFMode() {
						Skip("Skipping due to manual removal of host from ipset not breaking connectivity in BPF mode")
						return
					}

					// Check we initially have the expected number of entries.
					for _, f := range felixes {
						// Wait for Felix to set up the allow list.
						if NFTMode() {
							Eventually(f.NFTSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(len(felixes)))
						} else {
							Eventually(f.IPSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(len(felixes)))
						}
					}

					// Wait until dataplane has settled.
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[0], w[2])
					cc.ExpectSome(w[1], w[2])
					cc.CheckConnectivityWithTimeout(timeout)

					cc.ResetExpectations()

					// Then pause all the felixes.
					for _, f := range felixes {
						pid := f.GetFelixPID()
						f.Exec("kill", "-STOP", fmt.Sprint(pid))
					}
				})

				// BPF mode doesn't use the IP set.
				if ipipMode == api.IPIPModeAlways && !BPFMode() {
					It("after manually removing third node from allow list should have expected connectivity", func() {
						if NFTMode() {
							felixes[0].Exec("nft", "delete", "element", "ip", "calico", "cali40all-hosts-net", fmt.Sprintf("{ %s }", felixes[2].IP))
							if enableIPv6 {
								felixes[0].Exec("nft", "delete", "element", "ip6", "calico", "cali60all-hosts-net", fmt.Sprintf("{ %s }", felixes[2].IPv6))
							}
						} else {
							felixes[0].Exec("ipset", "del", "cali40all-hosts-net", felixes[2].IP)
							if enableIPv6 {
								felixes[0].Exec("ipset", "del", "cali60all-hosts-net", felixes[2].IPv6)
							}
						}

						cc.ExpectSome(w[0], w[1])
						cc.ExpectSome(w[1], w[0])
						cc.ExpectSome(w[1], w[2])
						cc.ExpectNone(w[2], w[0])

						if enableIPv6 {
							cc.ExpectSome(w6[0], w6[1])
							cc.ExpectSome(w6[1], w6[0])
							cc.ExpectSome(w6[1], w6[2])
							cc.ExpectNone(w6[2], w6[0])
						}

						cc.CheckConnectivityWithTimeout(timeout)
					})
				}
			})

			It("should configure the ipip device correctly", func() {
				if ipipMode == api.IPIPModeNever {
					Skip("ipip device is not available in no encap routing")
				}
				// The ipip device should appear with default MTU, etc. FV environment uses MTU 1500,
				// which means that we should expect 1480 after subtracting IPIP overhead for IPv4.
				mtuStr := "mtu 1480"
				for _, felix := range felixes {
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", dataplanedefs.IPIPIfaceName)
						return out
					}, "60s", "500ms").Should(ContainSubstring(mtuStr))
				}

				// Change the host device's MTU, and expect the IPIP device to be updated.
				for _, felix := range felixes {
					Eventually(func() error {
						_, err := felix.ExecOutput("ip", "link", "set", "eth0", "mtu", "1400")
						return err
					}, "15s", "100ms").Should(BeNil())
				}

				// MTU should be auto-detected, and updated to the host MTU minus 20 bytes overhead IPIP.
				mtuStr = "mtu 1380"
				mtuValue := "1380"
				for _, felix := range felixes {
					// Felix checks host MTU every 30s
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", dataplanedefs.IPIPIfaceName)
						return out
					}, "60s", "500ms").Should(ContainSubstring(mtuStr))

					// And expect the MTU file on disk to be updated.
					Eventually(func() string {
						out, _ := felix.ExecOutput("cat", "/var/lib/calico/mtu")
						return out
					}, "30s", "100ms").Should(ContainSubstring(mtuValue))
				}

				// Explicitly configure the MTU.
				felixConfig := api.NewFelixConfiguration() // Create a default FelixConfiguration
				felixConfig.Name = "default"
				mtu := 1300
				felixConfig.Spec.IPIPMTU = &mtu
				_, err := client.FelixConfigurations().Create(context.Background(), felixConfig, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Expect the settings to be changed on the device.
				for _, felix := range felixes {
					// Felix checks host MTU every 30s
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", dataplanedefs.IPIPIfaceName)
						return out
					}, "60s", "500ms").Should(ContainSubstring("mtu 1300"))
				}
			})

			Context("external nodes configured", func() {
				var externalClient *containers.Container

				BeforeEach(func() {
					externalClient = infrastructure.RunExtClient("ext-client")

					Eventually(func() error {
						err := externalClient.ExecMayFail("ip", "tunnel", "add", "tunl0", "mode", "ipip")
						if err != nil && strings.Contains(err.Error(), "SIOCADDTUNNEL: File exists") {
							return nil
						}
						return err
					}).Should(Succeed())

					externalClient.Exec("ip", "link", "set", "tunl0", "up")
					externalClient.Exec("ip", "addr", "add", "dev", "tunl0", "10.65.222.1")
					externalClient.Exec("ip", "route", "add", "10.65.0.0/24", "via",
						tc.Felixes[0].IP, "dev", "tunl0", "onlink")
				})

				JustAfterEach(func() {
					if CurrentGinkgoTestDescription().Failed {
						externalClient.Exec("ip", "r")
						externalClient.Exec("ip", "l")
						externalClient.Exec("ip", "a")
					}
				})

				AfterEach(func() {
					externalClient.Stop()
				})

				It("should allow IPIP to external client if it is in ExternalNodesCIDRList", func() {
					if ipipMode == api.IPIPModeNever {
						Skip("external nodes is not applicable to no encap routing")
					}

					By("testing that ext client ipip does not work if not part of ExternalNodesCIDRList")
					for _, f := range tc.Felixes {
						// Make sure that only the internal nodes are present in the ipset
						if BPFMode() {
							Eventually(f.BPFRoutes, "15s").Should(ContainSubstring(f.IP))
							Consistently(f.BPFRoutes).ShouldNot(ContainSubstring(externalClient.IP))
						} else if NFTMode() {
							Eventually(f.NFTSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(len(felixes)))
						} else {
							Eventually(f.IPSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(len(felixes)))
						}
					}

					cc.ExpectNone(externalClient, w[0])
					cc.CheckConnectivityWithTimeout(timeout)

					By("changing configuration to include the external client")

					updateConfig := func(addr string) {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						c, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
						if err != nil {
							// Create the default config if it doesn't already exist.
							if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
								c = api.NewFelixConfiguration()
								c.Name = "default"
								c, err = client.FelixConfigurations().Create(ctx, c, options.SetOptions{})
								Expect(err).NotTo(HaveOccurred())
							} else {
								Expect(err).NotTo(HaveOccurred())
							}
						}
						c.Spec.ExternalNodesCIDRList = &[]string{addr}
						logrus.WithFields(logrus.Fields{"felixconfiguration": c, "adding Addr": addr}).Info("Updating FelixConfiguration ")
						_, err = client.FelixConfigurations().Update(ctx, c, options.SetOptions{})
						Expect(err).NotTo(HaveOccurred())
					}

					updateConfig(externalClient.IP)

					// Wait for the config to take
					for _, f := range tc.Felixes {
						if BPFMode() {
							Eventually(f.BPFRoutes, "15s").Should(ContainSubstring(externalClient.IP))
							Expect(f.IPSetSize("cali40all-hosts-net")).To(BeZero(),
								"BPF mode shouldn't program IP sets")
						} else if NFTMode() {
							Eventually(f.NFTSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(len(felixes) + 1))
						} else {
							Eventually(f.IPSetSizeFn("cali40all-hosts-net"), "15s", "200ms").Should(Equal(len(felixes) + 1))
						}
					}

					// Pause felix[0], so it can't touch the dataplane; we want to
					// test that felix[0] blocks the traffic.
					pid := felixes[0].GetFelixPID()
					felixes[0].Exec("kill", "-STOP", fmt.Sprint(pid))

					tc.Felixes[0].Exec("ip", "route", "add", "10.65.222.1", "via",
						externalClient.IP, "dev", dataplanedefs.IPIPIfaceName, "onlink", "proto", "90")

					By("testing that the ext client can connect via ipip")
					cc.ResetExpectations()
					cc.ExpectSome(externalClient, w[0])
					cc.CheckConnectivityWithTimeout(timeout)
				})
			})
		})

		Describe("with a borrowed tunnel IP on one host", func() {
			var (
				infra           infrastructure.DatastoreInfra
				tc              infrastructure.TopologyContainers
				felixes         []*infrastructure.Felix
				client          client.Interface
				w               [3]*workload.Workload
				w6              [3]*workload.Workload
				hostW           [3]*workload.Workload
				hostW6          [3]*workload.Workload
				cc              *connectivity.Checker
				topologyOptions infrastructure.TopologyOptions
				timeout         time.Duration = time.Second * 30
			)

			BeforeEach(func() {
				infra = getInfra()

				if (NFTMode() || BPFMode()) && getDataStoreType(infra) == "etcdv3" {
					Skip("Skipping NFT / BPF tests for etcdv3 backend.")
				}

				topologyOptions = createIPIPBaseTopologyOptions(ipipMode, enableIPv6, routeSource, brokenXSum)
				topologyOptions.IPIPStrategy = infrastructure.NewBorrowedIPTunnelStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR, 3)

				cc = &connectivity.Checker{}

				// Deploy the topology.
				tc, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

				w, w6, hostW, hostW6 = setupWorkloads(infra, tc, topologyOptions, client, enableIPv6)
				felixes = tc.Felixes

				// Assign tunnel addresees in IPAM based on the topology.
				assignTunnelAddresses(infra, tc, client)
			})

			AfterEach(func() {
				if CurrentGinkgoTestDescription().Failed {
					for _, felix := range felixes {
						if NFTMode() {
							logNFTDiags(felix)
						} else {
							felix.Exec("iptables-save", "-c")
							felix.Exec("ipset", "list")
						}
						felix.Exec("ipset", "list")
						felix.Exec("ip", "r")
						felix.Exec("ip", "a")
						felix.Exec("calico-bpf", "routes", "dump")
						if enableIPv6 {
							felix.Exec("ip", "-6", "route")
							felix.Exec("calico-bpf", "-6", "routes", "dump")
						}
					}
				}

				for _, wl := range w {
					wl.Stop()
				}
				for _, wl := range w6 {
					wl.Stop()
				}
				for _, wl := range hostW {
					wl.Stop()
				}
				for _, wl := range hostW6 {
					wl.Stop()
				}
				tc.Stop()

				if CurrentGinkgoTestDescription().Failed {
					infra.DumpErrorData()
				}
				infra.Stop()
			})

			It("should have host to workload connectivity", func() {
				if ipipMode == api.IPIPModeAlways && routeSource == "WorkloadIPs" {
					Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
				}

				for i := 0; i < 3; i++ {
					f := felixes[i]
					cc.ExpectSome(f, w[0])
					cc.ExpectSome(f, w[1])
					cc.ExpectSome(f, w[2])

					if enableIPv6 {
						cc.ExpectSome(f, w6[0])
						cc.ExpectSome(f, w6[1])
						cc.ExpectSome(f, w6[2])
					}
				}

				cc.CheckConnectivityWithTimeout(timeout)
			})
		})

		Describe("with a separate tunnel address pool that uses /32 blocks", func() {
			var (
				infra           infrastructure.DatastoreInfra
				tc              infrastructure.TopologyContainers
				felixes         []*infrastructure.Felix
				client          client.Interface
				w               [3]*workload.Workload
				w6              [3]*workload.Workload
				hostW           [3]*workload.Workload
				hostW6          [3]*workload.Workload
				cc              *connectivity.Checker
				topologyOptions infrastructure.TopologyOptions
				timeout         time.Duration = time.Second * 30
			)

			BeforeEach(func() {
				infra = getInfra()

				if (NFTMode() || BPFMode()) && getDataStoreType(infra) == "etcdv3" {
					Skip("Skipping NFT / BPF tests for etcdv3 backend.")
				}

				topologyOptions = createIPIPBaseTopologyOptions(ipipMode, enableIPv6, routeSource, brokenXSum)

				// Configure the default IP pool to be used for workloads only.
				topologyOptions.IPPoolUsages = []api.IPPoolAllowedUse{api.IPPoolAllowedUseWorkload}
				topologyOptions.IPv6PoolUsages = []api.IPPoolAllowedUse{api.IPPoolAllowedUseWorkload}

				// Create a separate IP pool for tunnel addresses that uses /32 addresses.
				tunnelPool := api.NewIPPool()
				tunnelPool.Name = "tunnel-addr-pool"
				tunnelPool.Spec.CIDR = "10.66.0.0/16"
				tunnelPool.Spec.BlockSize = 32
				tunnelPool.Spec.IPIPMode = ipipMode
				tunnelPool.Spec.AllowedUses = []api.IPPoolAllowedUse{api.IPPoolAllowedUseTunnel}
				cli := infra.GetCalicoClient()
				_, err := cli.IPPools().Create(context.Background(), tunnelPool, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// And one for v6.
				tunnelPoolV6 := api.NewIPPool()
				tunnelPoolV6.Name = "tunnel-addr-pool-v6"
				tunnelPoolV6.Spec.CIDR = "dead:feed::/64"
				tunnelPoolV6.Spec.BlockSize = 128
				tunnelPoolV6.Spec.IPIPMode = ipipMode
				tunnelPoolV6.Spec.AllowedUses = []api.IPPoolAllowedUse{api.IPPoolAllowedUseTunnel}
				_, err = cli.IPPools().Create(context.Background(), tunnelPoolV6, options.SetOptions{})
				if ipipMode == api.IPIPModeNever {
					Expect(err).NotTo(HaveOccurred()) // IPIP does not support IPv6 yet.
				} else {
					Expect(err).To(HaveOccurred()) // IPIP does not support IPv6 yet.
				}

				// Configure the IPIP strategy to use this IP pool for tunnel addresses allocation.
				topologyOptions.IPIPStrategy = infrastructure.NewDefaultTunnelStrategy(tunnelPool.Spec.CIDR, tunnelPoolV6.Spec.CIDR)

				cc = &connectivity.Checker{}

				// Deploy the topology.
				tc, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

				w, w6, hostW, hostW6 = setupWorkloads(infra, tc, topologyOptions, client, enableIPv6)
				felixes = tc.Felixes

				// Assign tunnel addresees in IPAM based on the topology.
				assignTunnelAddresses(infra, tc, client)
			})

			AfterEach(func() {
				if CurrentGinkgoTestDescription().Failed {
					for _, felix := range felixes {
						if NFTMode() {
							logNFTDiags(felix)
						} else {
							felix.Exec("iptables-save", "-c")
							felix.Exec("ipset", "list")
						}
						felix.Exec("ipset", "list")
						felix.Exec("ip", "r")
						felix.Exec("ip", "a")
						if enableIPv6 {
							felix.Exec("ip", "-6", "route")
						}
						felix.Exec("calico-bpf", "routes", "dump")
					}
				}

				for _, wl := range w {
					wl.Stop()
				}
				for _, wl := range w6 {
					wl.Stop()
				}
				for _, wl := range hostW {
					wl.Stop()
				}
				for _, wl := range hostW6 {
					wl.Stop()
				}
				tc.Stop()

				if CurrentGinkgoTestDescription().Failed {
					infra.DumpErrorData()
				}
				infra.Stop()
			})

			It("should have host to workload connectivity", func() {
				if ipipMode == api.IPIPModeAlways && routeSource == "WorkloadIPs" {
					Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
				}

				cc.ExpectSome(tc.Felixes[0], w[0])
				cc.ExpectSome(tc.Felixes[0], w[1])
				cc.ExpectSome(tc.Felixes[0], w[2])
				if enableIPv6 {
					cc.ExpectSome(tc.Felixes[0], w6[0])
					cc.ExpectSome(tc.Felixes[0], w6[1])
					cc.ExpectSome(tc.Felixes[0], w6[2])
				}

				cc.CheckConnectivityWithTimeout(timeout)
			})

			It("should have workload to workload connectivity", func() {
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[1], w[0])
				if enableIPv6 {
					cc.ExpectSome(w6[0], w6[1])
					cc.ExpectSome(w6[1], w6[0])
				}
				cc.CheckConnectivityWithTimeout(timeout)
			})
		})
	}
})

type createK8sServiceWithoutKubeProxyArgs struct {
	infra     infrastructure.DatastoreInfra
	felix     *infrastructure.Felix
	w         *workload.Workload
	svcName   string
	serviceIP string
	targetIP  string
	port      int
	tgtPort   int
	chain     string
	ipv6      bool
}

func createK8sServiceWithoutKubeProxy(args createK8sServiceWithoutKubeProxyArgs) {
	if BPFMode() {
		k8sClient := args.infra.(*infrastructure.K8sDatastoreInfra).K8sClient
		testSvc := k8sService(args.svcName, args.serviceIP, args.w, args.port, args.tgtPort, 0, "tcp")
		testSvcNamespace := testSvc.ObjectMeta.Namespace
		_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
			"Service endpoints didn't get created? Is controller-manager happy?")
	}

	if NFTMode() {
		args.felix.ProgramNftablesDNAT(args.serviceIP, args.targetIP, args.chain, args.ipv6)
	} else {
		args.felix.ProgramIptablesDNAT(args.serviceIP, args.targetIP, args.chain, args.ipv6)
	}
}

func getDataStoreType(infra infrastructure.DatastoreInfra) string {
	switch infra.(type) {
	case *infrastructure.K8sDatastoreInfra:
		return "kubernetes"
	case *infrastructure.EtcdDatastoreInfra:
		return "etcdv3"
	default:
		return "kubernetes"
	}
}

func createIPIPBaseTopologyOptions(
	ipipMode api.IPIPMode,
	enableIPv6 bool,
	routeSource string,
	brokenXSum bool,
) infrastructure.TopologyOptions {
	topologyOptions := infrastructure.DefaultTopologyOptions()
	topologyOptions.IPIPMode = ipipMode
	topologyOptions.IPIPStrategy = infrastructure.NewDefaultTunnelStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR)
	topologyOptions.VXLANMode = api.VXLANModeNever
	topologyOptions.SimulateBIRDRoutes = false
	topologyOptions.EnableIPv6 = enableIPv6
	topologyOptions.FelixLogSeverity = "Debug"
	topologyOptions.ExtraEnvVars["FELIX_ProgramClusterRoutes"] = "Enabled"
	topologyOptions.ExtraEnvVars["FELIX_ROUTESOURCE"] = routeSource
	// We force the broken checksum handling on or off so that we're not dependent on kernel version
	// for these tests.  Since we're testing in containers anyway, checksum offload can't really be
	// tested but we can verify the state with ethtool.
	topologyOptions.ExtraEnvVars["FELIX_FeatureDetectOverride"] = fmt.Sprintf("ChecksumOffloadBroken=%t", brokenXSum)
	topologyOptions.FelixDebugFilenameRegex = "ipip|route_mgr|route_table|l3_route_resolver|int_dataplane"
	return topologyOptions
}

func waitForIPIPDevice() {
	// Wait until the ipip device appears; it is created when felix inserts the ipip module
	// into the kernel.
	Eventually(func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, link := range links {
			if link.Attrs().Name == "tunl0" {
				return nil
			}
		}
		return errors.New("tunl0 wasn't auto-created")
	}).Should(BeNil())
}

func allHostsIPSetSize(felixes []*infrastructure.Felix, ipipMode api.IPIPMode) int {
	if ipipMode == api.IPIPModeNever {
		// All Hosts IPSet Manager is not enabled in IPIP encapsulation.
		return 0
	}
	return len(felixes)
}
