// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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
	"os"
	"regexp"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/fv/connectivity"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const (
	resyncPeriod = 11 * time.Second
	applyPeriod  = 5 * time.Second
)

var bpfEnabled = os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ XDP tests with initialized Felix", []apiconfig.DatastoreType{apiconfig.EtcdV3 /*, apiconfig.Kubernetes*/}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra        infrastructure.DatastoreInfra
		felixes      []*infrastructure.Felix
		hostW        [4]*workload.Workload
		client       client.Interface
		ccTCP        *connectivity.Checker
		ccUDP        *connectivity.Checker
		host0HexCIDR []string
		host2HexCIDR []string
	)

	BeforeEach(func() {
		if err := bpf.SupportsXDP(); err != nil {
			Skip(fmt.Sprintf("XDP acceleration not supported: %v", err))
		}
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()

		opts.ExtraEnvVars = map[string]string{
			"FELIX_GENERICXDPENABLED":  "1",
			"FELIX_XDPREFRESHINTERVAL": "10",
			"FELIX_LOGSEVERITYSCREEN":  "debug",
		}
		felixes, client = infrastructure.StartNNodeTopology(4, opts, infra)

		err := infra.AddAllowToDatastore("host-endpoint=='true'")
		Expect(err).NotTo(HaveOccurred())

		// Start a host-networked workload on each host so we have something to connect to.
		protos := []string{"udp", "udp", "tcp", "tcp"}
		roles := []string{"client", "server", "client", "server"}
		for ii, felix := range felixes {
			hostW[ii] = workload.Run(
				felixes[ii],
				fmt.Sprintf("host%d", ii),
				"",
				felixes[ii].IP,
				"8055,8056,22,68",
				protos[ii])

			felix.Exec("apt-get", "install", "-y", "hping3")

			hostEp := api.NewHostEndpoint()
			hostEp.Name = fmt.Sprintf("host-endpoint-%d", ii)
			hostEp.Labels = map[string]string{
				"host-endpoint": "true",
				"proto":         protos[ii],
				"role":          roles[ii],
			}
			hostEp.Spec.Node = felix.Hostname
			hostEp.Spec.InterfaceName = "eth0"
			hostEp.Spec.ExpectedIPs = []string{felix.IP}
			_, err = client.HostEndpoints().Create(utils.Ctx, hostEp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		}

		ccTCP = &connectivity.Checker{Protocol: "tcp"}
		ccUDP = &connectivity.Checker{Protocol: "udp"}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		for _, wl := range hostW {
			wl.Stop()
		}
		for _, felix := range felixes {
			felix.Stop()
		}

		infra.Stop()
	})

	clientServerIndexes := func(proto string) (client, server int) {
		if proto == "udp" {
			return 0, 1
		} else if proto == "tcp" {
			return 2, 3
		} else {
			return -1, -1
		}
	}

	expectNoConnectivity := func(cc *connectivity.Checker) {
		client, server := clientServerIndexes(cc.Protocol)
		cc.ExpectNone(felixes[client], hostW[server].Port(8055))
		cc.ExpectNone(felixes[server], hostW[client].Port(8055))
		cc.ExpectNone(felixes[client], hostW[server].Port(8056))
		cc.ExpectNone(felixes[server], hostW[client].Port(8056))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectAllAllowed := func(cc *connectivity.Checker) {
		client, server := clientServerIndexes(cc.Protocol)
		cc.ExpectSome(felixes[client], hostW[server].Port(8055))
		cc.ExpectSome(felixes[client], hostW[server].Port(8056))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectBlacklisted := func(cc *connectivity.Checker) {
		client, server := clientServerIndexes(cc.Protocol)
		cc.ExpectNone(felixes[client], hostW[server].Port(8055))
		cc.ExpectNone(felixes[client], hostW[server].Port(8056))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectTCPFailsafePortsOpen := func(cc *connectivity.Checker) {
		client, server := clientServerIndexes(cc.Protocol)
		cc.ExpectNone(felixes[client], hostW[server].Port(8055))
		cc.ExpectNone(felixes[client], hostW[server].Port(8056))
		cc.ExpectSome(felixes[client], hostW[server].Port(22))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectUDPFailsafePortsOpen := func(cc *connectivity.Checker) {
		client, server := clientServerIndexes(cc.Protocol)
		cc.ExpectNone(felixes[client], hostW[server].Port(8055))
		cc.ExpectNone(felixes[client], hostW[server].Port(8056))
		cc.ExpectSome(felixes[client], hostW[server].Port(68))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectTCPSourceFailsafePortBlacklisted := func(cc *connectivity.Checker) {
		client, server := clientServerIndexes(cc.Protocol)

		fsPort := &workload.Port{
			Workload: hostW[client],
			Port:     2379, // a source failsafe port
		}

		ccTCP.ExpectNone(fsPort, hostW[server], 8055)
		ccTCP.CheckConnectivityOffset(1)
		ccTCP.ResetExpectations()
	}

	It("should have expected no connectivity at first", func() {
		expectNoConnectivity(ccUDP)
		expectNoConnectivity(ccTCP)
	})

	xdpProgramID := func(felix *infrastructure.Felix, iface string) int {
		out, err := felix.ExecCombinedOutput("ip", "link", "show", "dev", iface)
		Expect(err).NotTo(HaveOccurred())
		r := regexp.MustCompile(`prog/xdp id (\d+)`)
		matches := r.FindStringSubmatch(out)
		if len(matches) == 0 {
			return 0
		}
		id, err := strconv.Atoi(matches[1])
		Expect(err).NotTo(HaveOccurred())
		return id
	}

	xdpProgramAttached := func(felix *infrastructure.Felix, iface string) bool {
		return xdpProgramID(felix, iface) != 0
	}

	xdpProgramAttached_felix1_eth0 := func() bool {
		return xdpProgramAttached(felixes[1], "eth0")
	}

	xdpProgramID_felix1_eth0 := func() int {
		return xdpProgramID(felixes[1], "eth0")
	}

	Context("with no untracked policy", func() {

		It("should not have XDP program attached", func() {
			Eventually(xdpProgramAttached_felix1_eth0, "10s", "1s").Should(BeFalse())
			Consistently(xdpProgramAttached_felix1_eth0, "2s", "1s").Should(BeFalse())
		})
	})

	Context("with XDP blacklist on felix[1] blocking felixes[0]", func() {
		BeforeEach(func() {
			order := float64(20)

			// allow everything
			allowAllPolicy := api.NewGlobalNetworkPolicy()
			allowAllPolicy.Name = "allow-all"
			allowAllPolicy.Spec.Order = &order
			allowAllPolicy.Spec.Selector = "all()"
			allowAllPolicy.Spec.Ingress = []api.Rule{{
				Action: api.Allow,
			}}
			allowAllPolicy.Spec.Egress = []api.Rule{{
				Action: api.Allow,
			}}
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, allowAllPolicy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			expectAllAllowed(ccUDP)
			expectAllAllowed(ccTCP)

			order = float64(10)

			// apply XDP policy to felix[1] blocking felixes[0] by IP
			serverSelector := "proto == 'udp' && role=='server'"
			xdpPolicy := api.NewGlobalNetworkPolicy()
			xdpPolicy.Name = "xdp-filter-u" // keep name short, so it matches with the iptables chain name
			xdpPolicy.Spec.Order = &order
			xdpPolicy.Spec.DoNotTrack = true
			xdpPolicy.Spec.ApplyOnForward = true
			xdpPolicy.Spec.Selector = serverSelector
			xdpPolicy.Spec.Ingress = []api.Rule{{
				Action: api.Deny,
				Source: api.EntityRule{
					Selector: "xdpblacklist-set=='true'",
				},
			}}
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, xdpPolicy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			serverSelector = "proto == 'tcp' && role=='server'"
			xdpPolicy = api.NewGlobalNetworkPolicy()
			xdpPolicy.Name = "xdp-filter-t" // keep name short, so it matches with the iptables chain name
			xdpPolicy.Spec.Order = &order
			xdpPolicy.Spec.DoNotTrack = true
			xdpPolicy.Spec.ApplyOnForward = true
			xdpPolicy.Spec.Selector = serverSelector
			xdpPolicy.Spec.Ingress = []api.Rule{{
				Action: api.Deny,
				Source: api.EntityRule{
					Selector: "xdpblacklist-set=='true'",
				},
			}}
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, xdpPolicy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			_, _ = client.GlobalNetworkPolicies().Delete(utils.Ctx, "allow-all", options.DeleteOptions{})
			_, _ = client.GlobalNetworkSets().Delete(utils.Ctx, "xdpblacklistudp", options.DeleteOptions{})
			_, _ = client.GlobalNetworkSets().Delete(utils.Ctx, "xdpblacklisttcp", options.DeleteOptions{})
			_, _ = client.GlobalNetworkPolicies().Delete(utils.Ctx, "xdp-filter-t", options.DeleteOptions{})
			_, _ = client.GlobalNetworkPolicies().Delete(utils.Ctx, "xdp-filter-u", options.DeleteOptions{})
		})

		It("should have XDP program attached", func() {
			Eventually(xdpProgramAttached_felix1_eth0, "10s", "1s").Should(BeTrue())
			id := xdpProgramID(felixes[1], "eth0")
			Consistently(xdpProgramID_felix1_eth0(), "2s", "100ms").Should(Equal(id))
		})

		Context("with untracked policies deleted again", func() {
			BeforeEach(func() {
				time.Sleep(time.Second)
				_, _ = client.GlobalNetworkPolicies().Delete(utils.Ctx, "xdp-filter-t", options.DeleteOptions{})
				_, _ = client.GlobalNetworkPolicies().Delete(utils.Ctx, "xdp-filter-u", options.DeleteOptions{})
			})

			It("should not have XDP program attached", func() {
				Eventually(xdpProgramAttached_felix1_eth0, "10s", "1s").Should(BeFalse())
				Consistently(xdpProgramAttached_felix1_eth0, "2s", "1s").Should(BeFalse())
			})
		})

		applyGlobalNetworkSets := func(name string, ip string, cidrToHexSuffix string, update bool) (hexCIDR []string) {
			// create GlobalNetworkSet with IP of felixes[0]
			var srcNS *api.GlobalNetworkSet
			var err error
			if update {
				srcNS, err = client.GlobalNetworkSets().Get(utils.Ctx, name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				srcNS.Spec.Nets = []string{ip}

				_, err = client.GlobalNetworkSets().Update(utils.Ctx, srcNS, utils.NoOptions)
			} else {
				srcNS = api.NewGlobalNetworkSet()
				srcNS.Name = name
				srcNS.Spec.Nets = []string{ip}
				srcNS.Labels = map[string]string{
					"xdpblacklist-set": "true",
				}
				_, err = client.GlobalNetworkSets().Create(utils.Ctx, srcNS, utils.NoOptions)
			}
			Expect(err).NotTo(HaveOccurred())

			hexCIDR, err = bpf.CidrToHex(ip + cidrToHexSuffix)
			Expect(err).NotTo(HaveOccurred())
			return hexCIDR
		}

		Context("blocking server IP", func() {
			BeforeEach(func() {
				_, udpServer := clientServerIndexes("udp")
				_, tcpServer := clientServerIndexes("tcp")
				_ = applyGlobalNetworkSets("xdpblacklistudp", hostW[udpServer].IP, "/32", false)
				_ = applyGlobalNetworkSets("xdpblacklisttcp", hostW[tcpServer].IP, "/32", false)
			})

			It("should allow connections from other IPs to the server", func() {
				expectAllAllowed(ccTCP)
				expectAllAllowed(ccUDP)
			})
			// NJ: this is odd; no blacklist testing here.
		})

		Context("blocking full IP", func() {
			BeforeEach(func() {
				host0HexCIDR = applyGlobalNetworkSets("xdpblacklistudp", hostW[0].IP, "/32", false)
				host2HexCIDR = applyGlobalNetworkSets("xdpblacklisttcp", hostW[2].IP, "/32", false)

				time.Sleep(applyPeriod)
			})

			It("should block packets smaller than UDP", func() {
				client, server := clientServerIndexes("tcp")

				err := utils.RunMayFail("docker", "exec", felixes[client].Name, "hping3", "--rawip", "-c", "1", "-H", "254", "-d", "1", hostW[server].IP)
				Expect(err).To(HaveOccurred())
				Expect(utils.LastRunOutput).To(ContainSubstring(`100% packet loss`))

				if !bpfEnabled {
					output, err := felixes[server].ExecOutput("iptables", "-t", "raw", "-v", "-n", "-L", "cali-pi-default.xdp-filter-t")
					// the only rule that refers to a cali40-prefixed ipset should
					// have 0 packets/bytes because the raw small packets should've been
					// blocked by XDP
					Expect(err).NotTo(HaveOccurred())
					Expect(output).To(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
				}
			})

			if bpfEnabled {
				// The following test case only works for the old iptables-mode XDP
				// implementation of untracked ingress deny policy.  The BPF mode
				// and iptables chain implementations of untracked ingress policy
				// both match against both inbound and outbound failsafes - which we
				// now believe is the most correct behaviour - and it was an
				// oversight that outbound failsafes were not added to the old XDP
				// program.  It isn't worth fixing the old XDP program now, as it's
				// likely it will be replaced with the new XDP as used in BPF mode.
			} else {
				It("should block connections even if the source port is a failsafe port", func() {
					expectTCPSourceFailsafePortBlacklisted(ccTCP)
				})
			}

			It("should block ICMP too", func() {
				client, server := clientServerIndexes("tcp")

				err := utils.RunMayFail("docker", "exec", felixes[client].Name, "ping", "-c", "1", "-w", "1", hostW[server].IP)
				Expect(err).To(HaveOccurred())
				Expect(utils.LastRunOutput).To(ContainSubstring(`100% packet loss`))

				if !bpfEnabled {
					output, err := felixes[server].ExecOutput("iptables", "-t", "raw", "-v", "-n", "-L", "cali-pi-default.xdp-filter-t")
					// the only rule that refers to a cali40-prefixed ipset should
					// have 0 packets/bytes because the icmp packets should've been
					// blocked by XDP
					Expect(err).NotTo(HaveOccurred())
					Expect(output).To(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
				}
			})

			It("should have expected an XDP program attached to eth0 on felixes[1]", func() {
				utils.Run("docker", "exec", felixes[1].Name, "ip", "addr", "show", "eth0")
				Expect(utils.LastRunOutput).To(ContainSubstring("xdp"))
			})

			if !bpfEnabled {
				It("should have expected felixes[UDP client] IP in BPF blacklist", func() {
					utils.Run("docker", append([]string{"exec", felixes[1].Name, "bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, host0HexCIDR...)...)
					Expect(utils.LastRunOutput).To(ContainSubstring("value:"))
				})

				It("should have expected felixes[TCP client] IP in BPF blacklist", func() {
					utils.Run("docker", append([]string{"exec", felixes[1].Name, "bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, host2HexCIDR...)...)
					Expect(utils.LastRunOutput).To(ContainSubstring("value:"))
				})
			}

			It("should have expected no connectivity from felixes[0] with XDP blacklist", func() {
				expectBlacklisted(ccUDP)
				expectBlacklisted(ccTCP)
			})

			It("should have expected no dropped packets in iptables in UDP", func() {
				expectBlacklisted(ccUDP)

				if !bpfEnabled {
					utils.Run("docker", "exec", felixes[1].Name, "iptables", "-t", "raw", "-v", "-n", "-L", "cali-pi-default.xdp-filter-u")
					// the only rule that refers to a cali40-prefixed ipset should have 0 packets/bytes
					Expect(utils.LastRunOutput).To(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
				}
			})

			It("should have expected no dropped packets in iptables in TCP", func() {
				versionReader, err := environment.GetKernelVersionReader()
				Expect(err).NotTo(HaveOccurred())

				kernelVersion, err := environment.GetKernelVersion(versionReader)
				Expect(err).NotTo(HaveOccurred())

				if kernelVersion.Compare(environment.MustParseVersion("4.19.0")) < 0 {
					Skip(fmt.Sprintf("Skipping TCP test on Linux %v (needs 4.19)", kernelVersion))
					return
				}

				expectBlacklisted(ccTCP)

				if !bpfEnabled {
					utils.Run("docker", "exec", felixes[3].Name, "iptables", "-t", "raw", "-v", "-n", "-L", "cali-pi-default.xdp-filter-t")
					// the only rule that refers to a cali40-prefixed ipset should have 0 packets/bytes
					Expect(utils.LastRunOutput).To(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
				}
			})

			It("should have expected failsafe port 22 (TCP) and port 68 (UDP) to be open on felix[1] with XDP blacklist", func() {
				expectUDPFailsafePortsOpen(ccUDP)
				expectTCPFailsafePortsOpen(ccTCP)
			})

			It("should have expected connectivity after removing the policy", func() {
				expectBlacklisted(ccUDP)
				expectBlacklisted(ccTCP)

				_, err := client.GlobalNetworkPolicies().Delete(utils.Ctx, "xdp-filter-u", options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				_, err = client.GlobalNetworkPolicies().Delete(utils.Ctx, "xdp-filter-t", options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(applyPeriod)

				expectAllAllowed(ccUDP)
				expectAllAllowed(ccTCP)
			})

			Context("messing up with BPF maps", func() {

				if bpfEnabled {
					// BPF mode's use of XDP doesn't resync in the ways expected by the following tests.
					return
				}

				It("resync should've handled the external change of a BPF map", func() {
					utils.Run("docker", append([]string{"exec", felixes[1].Name, "bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, host0HexCIDR...)...)
					Expect(utils.LastRunOutput).To(ContainSubstring("value:"))

					err := utils.RunMayFail("docker", append([]string{"exec", felixes[1].Name, "bpftool", "map", "delete", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, host0HexCIDR...)...)
					Expect(err).NotTo(HaveOccurred())

					// wait for resync
					time.Sleep(resyncPeriod)

					utils.Run("docker", append([]string{"exec", felixes[1].Name, "bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, host0HexCIDR...)...)
					Expect(utils.LastRunOutput).To(ContainSubstring("value:"))

					expectBlacklisted(ccUDP)
					expectBlacklisted(ccTCP)
				})

				It("resync should've handled manually detaching a BPF program", func() {
					err := utils.RunMayFail("docker", "exec", felixes[1].Name, "ip", "link", "set", "dev", "eth0", "xdp", "off")
					Expect(err).NotTo(HaveOccurred())

					// Note: we can't reliably check the following here, because
					// resync may have happened _immediately_ following the
					// previous "xdp off" command.
					// utils.Run("docker", "exec", felixes[1].Name, "ip", "addr", "show", "eth0")
					// Expect(utils.LastRunOutput).NotTo(ContainSubstring("xdp"))

					// wait for resync
					time.Sleep(resyncPeriod)

					utils.Run("docker", "exec", felixes[1].Name, "ip", "addr", "show", "eth0")
					Expect(utils.LastRunOutput).To(ContainSubstring("xdp"))

					expectBlacklisted(ccUDP)
					expectBlacklisted(ccTCP)
				})
			})
		})

		Context("changing GlobalNetworkSets", func() {
			BeforeEach(func() {
				host0HexCIDR = applyGlobalNetworkSets("xdpblacklistudp", hostW[0].IP, "/32", false)
				host2HexCIDR = applyGlobalNetworkSets("xdpblacklisttcp", hostW[2].IP, "/32", false)
				time.Sleep(applyPeriod)
			})

			if bpfEnabled {
				// The following are whitebox tests that aren't valid for the
				// BPF-mode use of XDP.
				return
			}

			It("should be reflected in the BPF map", func() {
				utils.Run("docker", append([]string{"exec", felixes[1].Name, "bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, host0HexCIDR...)...)
				Expect(utils.LastRunOutput).To(ContainSubstring("value:"))

				AdditionalHostUDPHexCIDR := applyGlobalNetworkSets("xdpblacklistudp", "1.2.3.4", "/32", true)
				AdditionalHostTCPHexCIDR := applyGlobalNetworkSets("xdpblacklisttcp", "1.2.3.4", "/32", true)
				time.Sleep(applyPeriod)

				utils.Run("docker", append([]string{"exec", felixes[1].Name, "bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, AdditionalHostUDPHexCIDR...)...)
				Expect(utils.LastRunOutput).To(ContainSubstring("value:"))

				utils.Run("docker", append([]string{"exec", felixes[3].Name, "bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, AdditionalHostTCPHexCIDR...)...)
				Expect(utils.LastRunOutput).To(ContainSubstring("value:"))
			})
		})

		Context("blocking CIDR", func() {
			BeforeEach(func() {
				host0HexCIDR = applyGlobalNetworkSets("xdpblacklistudp", hostW[0].IP+"/8", "", false)
				host2HexCIDR = applyGlobalNetworkSets("xdpblacklisttcp", hostW[2].IP+"/8", "", false)
				time.Sleep(applyPeriod)
			})

			It("should have expected an XDP program attached to eth0 on felixes[1]", func() {
				utils.Run("docker", "exec", felixes[1].Name, "ip", "addr", "show", "eth0")
				Expect(utils.LastRunOutput).To(ContainSubstring("xdp"))
			})

			if !bpfEnabled {
				It("should have expected felixes[0] CIDR in BPF blacklist", func() {
					utils.Run("docker", append([]string{"exec", felixes[1].Name, "bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, host0HexCIDR...)...)
					Expect(utils.LastRunOutput).To(ContainSubstring("value:"))
				})
			}

			It("should have expected no dropped packets in iptables in UDP", func() {
				expectBlacklisted(ccUDP)

				if !bpfEnabled {
					utils.Run("docker", "exec", felixes[1].Name, "iptables", "-t", "raw", "-v", "-n", "-L", "cali-pi-default.xdp-filter-u")
					// the only rule that refers to a cali40-prefixed ipset should have 0 packets/bytes
					Expect(utils.LastRunOutput).To(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
				}
			})

			It("should have expected no dropped packets in iptables in TCP", func() {
				versionReader, err := environment.GetKernelVersionReader()
				Expect(err).NotTo(HaveOccurred())

				kernelVersion, err := environment.GetKernelVersion(versionReader)
				Expect(err).NotTo(HaveOccurred())

				if kernelVersion.Compare(environment.MustParseVersion("4.19.0")) < 0 {
					Skip(fmt.Sprintf("Skipping TCP test on Linux %v (needs 4.19)", kernelVersion))
					return
				}

				expectBlacklisted(ccTCP)

				if !bpfEnabled {
					utils.Run("docker", "exec", felixes[3].Name, "iptables", "-t", "raw", "-v", "-n", "-L", "cali-pi-default.xdp-filter-t")
					// the only rule that refers to a cali40-prefixed ipset should have 0 packets/bytes
					Expect(utils.LastRunOutput).To(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
				}
			})

			It("should have expected failsafe port 22 (TCP) and port 68 (UDP) to be open on felix[1] with XDP blacklist", func() {
				expectUDPFailsafePortsOpen(ccUDP)
				expectTCPFailsafePortsOpen(ccTCP)
			})
		})
	})
})
