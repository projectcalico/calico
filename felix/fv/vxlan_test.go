// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"strings"
	"time"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ VXLAN topology before adding host IPs to IP sets", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	type testConf struct {
		VXLANMode   api.VXLANMode
		RouteSource string
		BrokenXSum  bool
		EnableIPv6  bool
	}
	for _, testConfig := range []testConf{
		{api.VXLANModeCrossSubnet, "CalicoIPAM", true, true},
		{api.VXLANModeCrossSubnet, "WorkloadIPs", false, true},
		{api.VXLANModeCrossSubnet, "CalicoIPAM", true, false},
		{api.VXLANModeCrossSubnet, "WorkloadIPs", false, false},

		{api.VXLANModeAlways, "CalicoIPAM", true, true},
		{api.VXLANModeAlways, "WorkloadIPs", false, true},
		{api.VXLANModeAlways, "CalicoIPAM", true, false},
		{api.VXLANModeAlways, "WorkloadIPs", false, false},
	} {
		vxlanMode := testConfig.VXLANMode
		routeSource := testConfig.RouteSource
		brokenXSum := testConfig.BrokenXSum
		enableIPv6 := testConfig.EnableIPv6

		if BPFMode() && enableIPv6 && !BPFIPv6Support() {
			continue
		}

		Describe(fmt.Sprintf("VXLAN mode set to %s, routeSource %s, brokenXSum: %v, enableIPv6: %v", vxlanMode, routeSource, brokenXSum, enableIPv6), func() {
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
			)

			BeforeEach(func() {
				infra = getInfra()

				if getDataStoreType(infra) == "etcdv3" && BPFMode() {
					Skip("Skipping BPF tests for etcdv3 backend.")
				}

				topologyOptions = createBaseTopologyOptions(vxlanMode, enableIPv6, routeSource, brokenXSum)
				tc, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)

				w, w6, hostW, hostW6 = setupWorkloads(infra, tc, topologyOptions, client, enableIPv6)
				felixes = tc.Felixes

				cc = &connectivity.Checker{}
			})

			AfterEach(func() {
				if CurrentGinkgoTestDescription().Failed {
					for _, felix := range felixes {
						felix.Exec("iptables-save", "-c")
						felix.Exec("ipset", "list")
						felix.Exec("ip", "r")
						felix.Exec("ip", "a")
					}
				}

				for _, wl := range w {
					wl.Stop()
				}
				for _, wl := range hostW {
					wl.Stop()
				}
				tc.Stop()

				if CurrentGinkgoTestDescription().Failed {
					infra.DumpErrorData()
				}
				infra.Stop()
			})
			if brokenXSum {
				It("should disable checksum offload", func() {
					Eventually(func() string {
						out, err := felixes[0].ExecOutput("ethtool", "-k", "vxlan.calico")
						if err != nil {
							return fmt.Sprintf("ERROR: %v", err)
						}
						return out
					}, "10s", "100ms").Should(ContainSubstring("tx-checksumming: off"))
				})
			} else {
				It("should not disable checksum offload", func() {
					Eventually(func() string {
						out, err := felixes[0].ExecOutput("ethtool", "-k", "vxlan.calico")
						if err != nil {
							return fmt.Sprintf("ERROR: %v", err)
						}
						return out
					}, "10s", "100ms").Should(ContainSubstring("tx-checksumming: on"))
				})
			}
			It("should use the --random-fully flag in the MASQUERADE rules", func() {
				for _, felix := range felixes {
					Eventually(func() string {
						out, _ := felix.ExecOutput("iptables-save", "-c")
						return out
					}, "10s", "100ms").Should(ContainSubstring("--random-fully"))
				}
			})
			It("should have workload to workload connectivity", func() {
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[1], w[0])

				if enableIPv6 {
					cc.ExpectSome(w6[0], w6[1])
					cc.ExpectSome(w6[1], w6[0])
				}

				cc.CheckConnectivity()
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
					}, "10s", "100ms").Should(ContainSubstring(result))
					wName := fmt.Sprintf("w%d", n)

					err := client.IPAM().ReleaseByHandle(context.TODO(), wName)
					Expect(err).NotTo(HaveOccurred())

					if enableIPv6 {
						w6Name := fmt.Sprintf("w6-%d", n)
						err := client.IPAM().ReleaseByHandle(context.TODO(), w6Name)
						Expect(err).NotTo(HaveOccurred())
					}

					err = client.IPAM().ReleaseHostAffinities(context.TODO(), felixes[n].Hostname, true)
					Expect(err).NotTo(HaveOccurred())

					Eventually(func() string {
						o, _ := felixes[n].ExecOutput("ip", "r", "s", "type", "blackhole")
						return o
					}, "10s", "100ms").Should(BeEmpty())
				}
			})

			It("should have host to workload connectivity", func() {
				if vxlanMode == api.VXLANModeAlways && routeSource == "WorkloadIPs" {
					Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
				}
				cc.ExpectSome(felixes[0], w[1])
				cc.ExpectSome(felixes[0], w[0])

				if enableIPv6 {
					cc.ExpectSome(felixes[0], w6[1])
					cc.ExpectSome(felixes[0], w6[0])
				}

				cc.CheckConnectivity()
			})

			It("should have host to host connectivity", func() {
				cc.ExpectSome(felixes[0], hostW[1])
				cc.ExpectSome(felixes[1], hostW[0])

				if enableIPv6 {
					cc.ExpectSome(felixes[0], hostW6[1])
					cc.ExpectSome(felixes[1], hostW6[0])
				}

				cc.CheckConnectivity()
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

					for _, f := range felixes {
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
					cc.ExpectNone(felixes[0], hostW[1])
					cc.ExpectNone(felixes[1], hostW[0])
					if enableIPv6 {
						cc.ExpectNone(felixes[0], hostW6[1])
						cc.ExpectNone(felixes[1], hostW6[0])
					}

					// But the rules to allow VXLAN between our hosts let the workload traffic through.
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					if enableIPv6 {
						cc.ExpectSome(w6[0], w6[1])
						cc.ExpectSome(w6[1], w6[0])
					}
					cc.CheckConnectivity()
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

					for _, f := range felixes {
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

					cc.CheckConnectivity()
				})

				It("should allow felixes[0] to reach felixes[1] if ingress and egress policies are in place", func() {
					// Create a policy selecting felix[0] that allows egress.
					policy := api.NewGlobalNetworkPolicy()
					policy.Name = "f0-egress"
					policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
					policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[0].Hostname)
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
					cc.CheckConnectivity()

					cc.ResetExpectations()

					// Now add a policy selecting felix[1] that allows ingress.
					policy = api.NewGlobalNetworkPolicy()
					policy.Name = "f1-ingress"
					policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
					policy.Spec.Selector = fmt.Sprintf("hostname == '%s'", felixes[1].Hostname)
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

					cc.CheckConnectivity()
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
						if vxlanMode == api.VXLANModeAlways && routeSource == "WorkloadIPs" {
							Skip("Skipping due to known issue with tunnel IPs not being programmed in WEP mode")
						}
						// Allocate a service IP.
						serviceIP := "10.101.0.11"
						serviceV6IP := "deca:fbad:0000:0000:0000:0000:0000:0001"
						port := 8055
						tgtPort := 8055

						createK8sServiceWithoutKubeProxy(createK8sServiceWithoutKubeProxyArgs{
							infra:     infra,
							felix:     felixes[0],
							w:         w[1],
							svcName:   "test-svc",
							serviceIP: serviceIP,
							targetIP:  w[1].IP,
							port:      port,
							tgtPort:   tgtPort,
							chain:     "OUTPUT",
							ipv6:      false,
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
						cc.CheckConnectivity()
					})
				})
			})

			Context("after removing BGP address from third node", func() {
				// Simulate having a host send VXLAN traffic from an unknown source, should get blocked.
				BeforeEach(func() {
					Eventually(func() int {
						return getNumIPSetMembers(felixes[0].Container, "cali40all-vxlan-net")
					}, "10s", "200ms").Should(Equal(len(felixes) - 1))

					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					infra.RemoveNodeAddresses(felixes[2])
					node, err := client.Nodes().Get(ctx, felixes[2].Hostname, options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())

					// Pause felix so it can't touch the dataplane!
					pid := felixes[2].GetFelixPID()
					felixes[2].Exec("kill", "-STOP", fmt.Sprint(pid))

					node.Spec.BGP = nil
					_, err = client.Nodes().Update(ctx, node, options.SetOptions{})
				})

				It("should have no connectivity from third felix and expected number of IPs in allow list", func() {
					Eventually(func() int {
						return getNumIPSetMembers(felixes[0].Container, "cali40all-vxlan-net")
					}, "5s", "200ms").Should(Equal(len(felixes) - 2))

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
					cc.CheckConnectivity()
				})
			})

			// Explicitly verify that the VXLAN allow-list IP set is doing its job (since Felix makes multiple dataplane
			// changes when the BGP IP disappears, and we want to make sure that it's the rule that's causing the
			// connectivity to drop).
			Context("after removing BGP address from third node, all felixes paused", func() {
				// Simulate having a host send VXLAN traffic from an unknown source, should get blocked.
				BeforeEach(func() {
					// Check we initially have the expected number of entries.
					for _, f := range felixes {
						// Wait for Felix to set up the allow list.
						Eventually(func() int {
							return getNumIPSetMembers(f.Container, "cali40all-vxlan-net")
						}, "5s", "200ms").Should(Equal(len(felixes) - 1))
					}

					// Wait until dataplane has settled.
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[0], w[2])
					cc.ExpectSome(w[1], w[2])
					cc.CheckConnectivity()
					cc.ResetExpectations()

					// Then pause all the felixes.
					for _, f := range felixes {
						pid := f.GetFelixPID()
						f.Exec("kill", "-STOP", fmt.Sprint(pid))
					}
				})

				if vxlanMode == api.VXLANModeAlways {
					It("after manually removing third node from allow list should have expected connectivity", func() {
						if BPFMode() {
							Skip("Skipping due to manual removal of host from ipset not breaking connectivity in BPF mode")
							return
						}

						felixes[0].Exec("ipset", "del", "cali40all-vxlan-net", felixes[2].IP)
						if enableIPv6 {
							felixes[0].Exec("ipset", "del", "cali60all-vxlan-net", felixes[2].IPv6)
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

						cc.CheckConnectivity()
					})
				}
			})

			It("should configure the vxlan device correctly", func() {
				// The VXLAN device should appear with default MTU, etc. FV environment uses MTU 1500,
				// which means that we should expect 1450 after subracting VXLAN overhead for IPv4 or 1430 for IPv6.
				mtuStr := "mtu 1450"
				mtuStrV6 := "mtu 1430"
				for _, felix := range felixes {
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
						return out
					}, "60s", "500ms").Should(ContainSubstring(mtuStr))
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
						return out
					}, "10s", "100ms").Should(ContainSubstring("vxlan id 4096"))
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
						return out
					}, "10s", "100ms").Should(ContainSubstring("dstport 4789"))
					if enableIPv6 {
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "60s", "500ms").Should(ContainSubstring(mtuStrV6))
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "10s", "100ms").Should(ContainSubstring("vxlan id 4096"))
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "10s", "100ms").Should(ContainSubstring("dstport 4789"))
					}
				}

				// Change the host device's MTU, and expect the VXLAN device to be updated.
				for _, felix := range felixes {
					Eventually(func() error {
						_, err := felix.ExecOutput("ip", "link", "set", "eth0", "mtu", "1400")
						return err
					}, "10s", "100ms").Should(BeNil())
				}

				// MTU should be auto-detected, and updated to the host MTU minus 50 bytes overhead for IPv4 or 70 bytes for IPv6.
				mtuStr = "mtu 1350"
				mtuStrV6 = "mtu 1330"
				mtuValue := "1350"
				if enableIPv6 {
					mtuValue = "1330"
				}
				for _, felix := range felixes {
					// Felix checks host MTU every 30s
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
						return out
					}, "60s", "500ms").Should(ContainSubstring(mtuStr))

					if enableIPv6 {
						// Felix checks host MTU every 30s
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "60s", "500ms").Should(ContainSubstring(mtuStrV6))
					}

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
				vni := 4097
				port := 4790
				felixConfig.Spec.VXLANMTU = &mtu
				felixConfig.Spec.VXLANMTUV6 = &mtu
				felixConfig.Spec.VXLANPort = &port
				felixConfig.Spec.VXLANVNI = &vni
				_, err := client.FelixConfigurations().Create(context.Background(), felixConfig, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Expect the settings to be changed on the device.
				for _, felix := range felixes {
					// Felix checks host MTU every 30s
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
						return out
					}, "60s", "500ms").Should(ContainSubstring("mtu 1300"))
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
						return out
					}, "10s", "100ms").Should(ContainSubstring("vxlan id 4097"))
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
						return out
					}, "10s", "100ms").Should(ContainSubstring("dstport 4790"))

					if enableIPv6 {
						// Felix checks host MTU every 30s
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "60s", "500ms").Should(ContainSubstring("mtu 1300"))
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "10s", "100ms").Should(ContainSubstring("vxlan id 4097"))
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "10s", "100ms").Should(ContainSubstring("dstport 4790"))

					}
				}

			})

			It("should delete the vxlan device when vxlan is disabled", func() {
				// Wait for the VXLAN device to be created.
				mtuStr := "mtu 1450"
				mtuStrV6 := "mtu 1430"
				for _, felix := range felixes {
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
						return out
					}, "60s", "500ms").Should(ContainSubstring(mtuStr))
					if enableIPv6 {
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "60s", "500ms").Should(ContainSubstring(mtuStrV6))
					}
				}

				// Disable VXLAN in Felix.
				felixConfig := api.NewFelixConfiguration()
				felixConfig.Name = "default"
				enabled := false
				felixConfig.Spec.VXLANEnabled = &enabled
				_, err := client.FelixConfigurations().Create(context.Background(), felixConfig, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Expect the ipv4 VXLAN device to be deleted.
				for _, felix := range felixes {
					Eventually(func() string {
						out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan.calico")
						return out
					}, "60s", "500ms").ShouldNot(ContainSubstring(mtuStr))
					// IPv6 ignores the VXLAN enabled flag and must be disabled at the pool level. As such the ipv6
					// interfaces should still exist at this point
					if enableIPv6 {
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "60s", "500ms").Should(ContainSubstring(mtuStrV6))
					}
				}

				if enableIPv6 {
					ip6pool, err := client.IPPools().Get(context.Background(), infrastructure.DefaultIPv6PoolName, options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())
					ip6pool.Spec.VXLANMode = "Never"
					_, err = client.IPPools().Update(context.Background(), ip6pool, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())

					// Expect the ipv6 VXLAN device to be deleted.
					for _, felix := range felixes {
						Eventually(func() string {
							out, _ := felix.ExecOutput("ip", "-d", "link", "show", "vxlan-v6.calico")
							return out
						}, "60s", "500ms").ShouldNot(ContainSubstring(mtuStrV6))
					}
				}
			})
		})
	}
})

func createBaseTopologyOptions(vxlanMode api.VXLANMode, enableIPv6 bool, routeSource string, brokenXSum bool) infrastructure.TopologyOptions {
	topologyOptions := infrastructure.DefaultTopologyOptions()
	topologyOptions.VXLANMode = vxlanMode
	topologyOptions.IPIPEnabled = false
	topologyOptions.EnableIPv6 = enableIPv6
	topologyOptions.ExtraEnvVars["FELIX_ROUTESOURCE"] = routeSource
	// We force the broken checksum handling on or off so that we're not dependent on kernel version
	// for these tests.  Since we're testing in containers anyway, checksum offload can't really be
	// tested but we can verify the state with ethtool.
	topologyOptions.ExtraEnvVars["FELIX_FeatureDetectOverride"] = fmt.Sprintf("ChecksumOffloadBroken=%t", brokenXSum)

	return topologyOptions
}

func setupWorkloads(infra infrastructure.DatastoreInfra, tc infrastructure.TopologyContainers, to infrastructure.TopologyOptions, client client.Interface, enableIPv6 bool) (w, w6, hostW, hostW6 [3]*workload.Workload) {
	// Install a default profile that allows all ingress and egress, in the absence of any Policy.
	infra.AddDefaultAllow()

	// Wait until the vxlan device appears.
	Eventually(func() error {
		for i, f := range tc.Felixes {
			out, err := f.ExecOutput("ip", "link")
			if err != nil {
				return err
			}
			if strings.Contains(out, "vxlan.calico") {
				continue
			}
			return fmt.Errorf("felix %d has no vxlan device", i)
		}
		return nil
	}, "10s", "100ms").ShouldNot(HaveOccurred())

	if enableIPv6 {
		Eventually(func() error {
			for i, f := range tc.Felixes {
				out, err := f.ExecOutput("ip", "link")
				if err != nil {
					return err
				}
				if strings.Contains(out, "vxlan-v6.calico") {
					continue
				}
				return fmt.Errorf("felix %d has no IPv6 vxlan device", i)
			}
			return nil
		}, "10s", "100ms").ShouldNot(HaveOccurred())
	}

	// Create workloads, using that profile.  One on each "host".
	_, IPv4CIDR, err := net.ParseCIDR(to.IPPoolCIDR)
	Expect(err).To(BeNil())
	_, IPv6CIDR, err := net.ParseCIDR(to.IPv6PoolCIDR)
	Expect(err).To(BeNil())
	for ii := range w {
		wIP := fmt.Sprintf("%d.%d.%d.2", IPv4CIDR.IP[0], IPv4CIDR.IP[1], ii)
		wName := fmt.Sprintf("w%d", ii)
		err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP:       net.MustParseIP(wIP),
			HandleID: &wName,
			Attrs: map[string]string{
				ipam.AttributeNode: tc.Felixes[ii].Hostname,
			},
			Hostname: tc.Felixes[ii].Hostname,
		})
		Expect(err).NotTo(HaveOccurred())

		w[ii] = workload.Run(tc.Felixes[ii], wName, "default", wIP, "8055", "tcp")
		w[ii].ConfigureInInfra(infra)

		if enableIPv6 {
			w6IP := fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%d:3", IPv6CIDR.IP[0], IPv6CIDR.IP[1], IPv6CIDR.IP[2], IPv6CIDR.IP[3], IPv6CIDR.IP[4], IPv6CIDR.IP[5], IPv6CIDR.IP[6], IPv6CIDR.IP[7], IPv6CIDR.IP[8], IPv6CIDR.IP[9], IPv6CIDR.IP[10], IPv6CIDR.IP[11], ii)
			w6Name := fmt.Sprintf("w6-%d", ii)
			err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       net.MustParseIP(w6IP),
				HandleID: &w6Name,
				Attrs: map[string]string{
					ipam.AttributeNode: tc.Felixes[ii].Hostname,
				},
				Hostname: tc.Felixes[ii].Hostname,
			})
			Expect(err).NotTo(HaveOccurred())

			w6[ii] = workload.Run(tc.Felixes[ii], w6Name, "default", w6IP, "8055", "tcp")
			w6[ii].ConfigureInInfra(infra)
		}

		hostW[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d", ii), "", tc.Felixes[ii].IP, "8055", "tcp")
		if enableIPv6 {
			hostW6[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d-v6", ii), "", tc.Felixes[ii].IPv6, "8055", "tcp")
		}
	}

	if BPFMode() {
		ensureAllNodesBPFProgramsAttached(tc.Felixes)
	}

	return
}
