// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.
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
	"strconv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const (
	resyncPeriod = 20 * time.Second
)

var (
	_ = describeXDPTests("tcp")
	_ = describeXDPTests("udp")
)

func describeXDPTests(proto string) bool {
	return infrastructure.DatastoreDescribe(
		fmt.Sprintf("_BPF-SAFE_ XDP tests with initialized Felix proto=%s", proto),
		[]apiconfig.DatastoreType{apiconfig.EtcdV3 /*, apiconfig.Kubernetes*/},
		func(getInfra infrastructure.InfraFactory) {
			xdpTest(getInfra, proto)
		})
}

func xdpTest(getInfra infrastructure.InfraFactory, proto string) {
	var (
		infra       infrastructure.DatastoreInfra
		tc          infrastructure.TopologyContainers
		hostW       [4]*workload.Workload
		client      client.Interface
		cc          *connectivity.Checker
		hostHexCIDR []string
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
			"FELIX_XDPENABLED":         "true",
			"FELIX_LOGSEVERITYSCREEN":  "debug",
			"FELIX_FAILSAFEINBOUNDHOSTPORTS": "tcp:22, udp:68, tcp:179, tcp:2379, tcp:2380, " +
				"tcp:5473, tcp:6443, tcp:6666, tcp:6667, " + proto + ":1234", // defaults + 1234
		}

		roles := []string{"client", "server"}
		tc, client = infrastructure.StartNNodeTopology(len(roles), opts, infra)

		err := infra.AddAllowToDatastore("host-endpoint=='true'")
		Expect(err).NotTo(HaveOccurred())

		// Start a host-networked workload on each host so we have something to connect to.
		for ii, felix := range tc.Felixes {
			hostW[ii] = workload.Run(
				tc.Felixes[ii],
				fmt.Sprintf("host%d", ii),
				"",
				tc.Felixes[ii].IP,
				"8055,8056,1234",
				proto)

			hostEp := v3.NewHostEndpoint()
			hostEp.Name = fmt.Sprintf("host-endpoint-%d", ii)
			hostEp.Labels = map[string]string{
				"host-endpoint": "true",
				"proto":         proto,
				"role":          roles[ii],
			}
			hostEp.Spec.Node = felix.Hostname
			hostEp.Spec.InterfaceName = "eth0"
			hostEp.Spec.ExpectedIPs = []string{felix.IP}
			_, err = client.HostEndpoints().Create(utils.Ctx, hostEp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		}

		cc = &connectivity.Checker{Protocol: proto}
	})

	clnt, srvr := 0, 1

	expectNoConnectivity := func(cc *connectivity.Checker) {
		cc.ExpectNone(tc.Felixes[clnt], hostW[srvr].Port(8055))
		cc.ExpectNone(tc.Felixes[srvr], hostW[clnt].Port(8055))
		cc.ExpectNone(tc.Felixes[clnt], hostW[srvr].Port(8056))
		cc.ExpectNone(tc.Felixes[srvr], hostW[clnt].Port(8056))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectAllAllowed := func(cc *connectivity.Checker) {
		cc.ExpectSome(tc.Felixes[clnt], hostW[srvr].Port(8055))
		cc.ExpectSome(tc.Felixes[clnt], hostW[srvr].Port(8056))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectBlocked := func(cc *connectivity.Checker) {
		cc.ExpectNone(tc.Felixes[clnt], hostW[srvr].Port(8055))
		cc.ExpectNone(tc.Felixes[clnt], hostW[srvr].Port(8056))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectFailsafePortsOpen := func(cc *connectivity.Checker) {
		cc.ExpectNone(tc.Felixes[clnt], hostW[srvr].Port(8055))
		cc.ExpectNone(tc.Felixes[clnt], hostW[srvr].Port(8056))
		cc.ExpectSome(tc.Felixes[clnt], hostW[srvr].Port(1234))
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	expectSourceFailsafePortBlocked := func(cc *connectivity.Checker) {
		fsPort := &workload.Port{
			Workload: hostW[clnt],
			Port:     1234, // a source failsafe port
		}

		cc.ExpectNone(fsPort, hostW[srvr], 8055)
		cc.CheckConnectivityOffset(1)
		cc.ResetExpectations()
	}

	It("should have expected no connectivity at first", func() {
		expectNoConnectivity(cc)
	})

	xdpProgramAttachedServerEth0 := func() bool {
		return xdpProgramAttached(tc.Felixes[srvr], "eth0")
	}

	xdpProgramIDServerEth0 := func() int {
		return xdpProgramID(tc.Felixes[srvr], "eth0")
	}

	Context("with no untracked policy", func() {
		It("should not have XDP program attached", func() {
			Eventually(xdpProgramAttachedServerEth0, "10s", "1s").Should(BeFalse())
			Consistently(xdpProgramAttachedServerEth0, "2s", "1s").Should(BeFalse())
		})

		if BPFMode() {
			It("should not program Linux IP sets", func() {
				Consistently(tc.Felixes[0].NumIPSets, "5s", "1s").Should(BeZero())
			})
		}
	})

	Context("with XDP blocklist on felix[srvr] blocking felixes[clnt]", func() {
		// The expected iptables chain name for the xdpf policy.
		xdpfChainName := rules.PolicyChainName("cali-pi-", &types.PolicyID{Name: "xdpf", Kind: v3.KindGlobalNetworkPolicy}, false)

		BeforeEach(func() {
			order := float64(20)

			// allow everything
			allowAllPolicy := v3.NewGlobalNetworkPolicy()
			allowAllPolicy.Name = "allow-all"
			allowAllPolicy.Spec.Order = &order
			allowAllPolicy.Spec.Selector = "all()"
			allowAllPolicy.Spec.Ingress = []v3.Rule{{
				Action: v3.Allow,
			}}
			allowAllPolicy.Spec.Egress = []v3.Rule{{
				Action: v3.Allow,
			}}
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, allowAllPolicy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			expectAllAllowed(cc)

			order = float64(10)

			// apply XDP policy to felix[srvr] blocking felixes[clnt] by IP
			serverSelector := "role=='server'"
			xdpPolicy := v3.NewGlobalNetworkPolicy()
			xdpPolicy.Name = "xdpf" // keep name short, so it matches with the iptables chain name
			xdpPolicy.Spec.Order = &order
			xdpPolicy.Spec.DoNotTrack = true
			xdpPolicy.Spec.ApplyOnForward = true
			xdpPolicy.Spec.Selector = serverSelector
			xdpPolicy.Spec.Ingress = []v3.Rule{{
				Action: v3.Deny,
				Source: v3.EntityRule{
					Selector: "xdpblocklist-set=='true'",
				},
			}}
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, xdpPolicy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			Eventually(xdpProgramAttachedServerEth0, "10s", "1s").Should(BeTrue())
		})

		AfterEach(func() {
			_, _ = client.GlobalNetworkPolicies().Delete(utils.Ctx, "allow-all", options.DeleteOptions{})
			_, _ = client.GlobalNetworkSets().Delete(utils.Ctx, "xdpblocklist", options.DeleteOptions{})
			_, _ = client.GlobalNetworkPolicies().Delete(utils.Ctx, "xdpf", options.DeleteOptions{})
		})

		It("should have consistent XDP program attached", func() {
			id := xdpProgramID(tc.Felixes[srvr], "eth0")
			Consistently(xdpProgramIDServerEth0(), "2s", "100ms").Should(Equal(id))
		})

		Context("with untracked policies deleted again", func() {
			BeforeEach(func() {
				_, _ = client.GlobalNetworkPolicies().Delete(utils.Ctx, "xdpf", options.DeleteOptions{})
			})

			It("should not have XDP program attached", func() {
				Eventually(xdpProgramAttachedServerEth0, "10s", "1s").Should(BeFalse())
				Consistently(xdpProgramAttachedServerEth0, "2s", "1s").Should(BeFalse())
			})
		})

		applyGlobalNetworkSets := func(name string, ip string, cidrToHexSuffix string, update bool) (hexCIDR []string) {
			// create GlobalNetworkSet with IP of felixes[clnt]
			var srcNS *v3.GlobalNetworkSet
			var err error
			if update {
				srcNS, err = client.GlobalNetworkSets().Get(utils.Ctx, name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				srcNS.Spec.Nets = []string{ip}

				_, err = client.GlobalNetworkSets().Update(utils.Ctx, srcNS, utils.NoOptions)
			} else {
				srcNS = v3.NewGlobalNetworkSet()
				srcNS.Name = name
				srcNS.Spec.Nets = []string{ip}
				srcNS.Labels = map[string]string{
					"xdpblocklist-set": "true",
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
				_ = applyGlobalNetworkSets("xdpblocklist", hostW[srvr].IP, "/32", false)
			})

			It("should allow connections from other IPs to the server", func() {
				expectAllAllowed(cc)
			})
			// NJ: this is odd; no blocklist testing here.
		})

		Context("blocking full IP", func() {
			BeforeEach(func() {
				hostHexCIDR = applyGlobalNetworkSets("xdpblocklist", hostW[clnt].IP, "/32", false)
			})

			It("should block packets smaller than UDP", func() {
				doHping := func() error {
					return utils.RunMayFail("docker", "exec", tc.Felixes[clnt].Name, "hping3", "--rawip", "-c", "1", "-H", "254", "-d", "1", hostW[srvr].IP)
				}
				Eventually(doHping, "20s", "100ms").Should(HaveOccurred())
				Expect(utils.LastRunOutput).To(ContainSubstring(`100% packet loss`))
				Expect(doHping()).To(HaveOccurred())

				if !BPFMode() && !NFTMode() {
					output, err := tc.Felixes[srvr].ExecOutput("iptables", "-t", "raw", "-v", "-n", "-L", xdpfChainName)
					// the only rule that refers to a cali40-prefixed ipset should
					// have 0 packets/bytes because the raw small packets should've been
					// blocked by XDP
					Expect(err).NotTo(HaveOccurred())
					Expect(output).To(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
				}
			})

			if BPFMode() {
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
					expectSourceFailsafePortBlocked(cc)
				})
			}

			It("should block ICMP too", func() {
				doPing := func() error {
					return utils.RunMayFail("docker", "exec", tc.Felixes[clnt].Name, "ping", "-c", "1", "-w", "1", hostW[srvr].IP)
				}
				Eventually(doPing, "20s", "100ms").Should(HaveOccurred())
				Expect(utils.LastRunOutput).To(ContainSubstring(`100% packet loss`))
				Expect(doPing()).To(HaveOccurred())

				if !BPFMode() && !NFTMode() {
					output, err := tc.Felixes[srvr].ExecOutput("iptables", "-t", "raw", "-v", "-n", "-L", xdpfChainName)
					// the only rule that refers to a cali40-prefixed ipset should
					// have 0 packets/bytes because the icmp packets should've been
					// blocked by XDP
					Expect(err).NotTo(HaveOccurred())
					Expect(output).To(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
				}
			})

			if !BPFMode() {
				It("should have expected felixes[clnt] IP in BPF blocklist", func() {
					args := append([]string{"bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, hostHexCIDR...)
					Eventually(tc.Felixes[srvr].ExecOutputFn(args...), "10s").Should(ContainSubstring("value:"))
				})
			}

			It("should have expected no connectivity from felixes[clnt] with XDP blocklist", func() {
				expectBlocked(cc)
			})

			It("should have expected no dropped packets in iptables / nftables", func() {
				versionReader, err := environment.GetKernelVersionReader()
				Expect(err).NotTo(HaveOccurred())

				kernelVersion, err := environment.GetKernelVersion(versionReader)
				Expect(err).NotTo(HaveOccurred())

				if proto == "tcp" && kernelVersion.Compare(environment.MustParseVersion("4.19.0")) < 0 {
					Skip(fmt.Sprintf("Skipping TCP test on Linux %v (needs 4.19)", kernelVersion))
					return
				}

				expectBlocked(cc)

				// The only rule that refers to a cali40-prefixed ipset should have 0 packets/bytes
				if !BPFMode() {
					if !NFTMode() {
						Eventually(func() string {
							out, _ := tc.Felixes[srvr].ExecOutput("iptables", "-t", "raw", "-v", "-n", "-L", xdpfChainName)
							return out
						}).Should(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
					} else {
						Eventually(func() string {
							out, _ := tc.Felixes[srvr].ExecOutput("nft", "list", "chain", "ip", "calico", "raw-cali-pi-gnp/xdpf")
							return out
						}).Should(MatchRegexp(`packets 0 bytes 0`))
					}
				}
			})

			It("should have expected failsafe port 1234 to be open on felix[srvr] with XDP blocklist", func() {
				expectFailsafePortsOpen(cc)
			})

			It("should have expected connectivity after removing the policy", func() {
				expectBlocked(cc)

				_, err := client.GlobalNetworkPolicies().Delete(utils.Ctx, "xdpf", options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				expectAllAllowed(cc)
			})

			Context("messing up with BPF maps", func() {
				if BPFMode() {
					// BPF mode's use of XDP doesn't resync in the ways expected by the following tests.
					return
				}

				It("resync should've handled the external change of a BPF map", func() {
					args := append([]string{"bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, hostHexCIDR...)
					Eventually(tc.Felixes[srvr].ExecOutputFn(args...), "10s").Should(ContainSubstring("value:"))

					By("Deleting the BPF map entry manually")
					tc.Felixes[srvr].Exec(append([]string{"bpftool", "map", "delete", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, hostHexCIDR...)...)

					Eventually(tc.Felixes[srvr].ExecOutputFn(args...), resyncPeriod).Should(ContainSubstring("value:"))

					expectBlocked(cc)
				})

				It("resync should've handled manually detaching a BPF program", func() {
					tc.Felixes[srvr].Exec("ip", "link", "set", "dev", "eth0", "xdp", "off")

					// Note: we can't reliably check the following here, because
					// resync may have happened _immediately_ following the
					// previous "xdp off" command.
					// felixes[srvr].Exec( "ip", "addr", "show", "eth0")
					// Expect(utils.LastRunOutput).NotTo(ContainSubstring("xdp"))

					Eventually(tc.Felixes[srvr].ExecOutputFn("ip", "addr", "show", "eth0"), resyncPeriod).Should(ContainSubstring("xdp"))

					expectBlocked(cc)
				})
			})
		})

		Context("changing GlobalNetworkSets", func() {
			BeforeEach(func() {
				hostHexCIDR = applyGlobalNetworkSets("xdpblocklist", hostW[clnt].IP, "/32", false)
			})

			if BPFMode() {
				// The following are whitebox tests that aren't valid for the
				// BPF-mode use of XDP.
				return
			}

			It("should be reflected in the BPF map", func() {
				args := append([]string{"bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex"}, hostHexCIDR...)
				Eventually(tc.Felixes[srvr].ExecOutputFn(args...), "10s").Should(ContainSubstring("value:"))

				AdditionalHostHexCIDR := applyGlobalNetworkSets("xdpblocklist", "1.2.3.4", "/32", true)
				args = append([]string{
					"bpftool", "map", "lookup", "pinned",
					"/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex",
				}, AdditionalHostHexCIDR...)
				Eventually(tc.Felixes[srvr].ExecOutputFn(args...), "5s").Should(ContainSubstring("value:"))
			})
		})

		Context("blocking CIDR", func() {
			BeforeEach(func() {
				hostHexCIDR = applyGlobalNetworkSets("xdpblocklist", hostW[clnt].IP+"/8", "", false)

				Eventually(xdpProgramAttachedServerEth0, "10s").Should(BeTrue())
			})

			if !BPFMode() {
				It("should have expected felixes[clnt] CIDR in BPF blocklist", func() {
					args := append([]string{
						"bpftool", "map", "lookup", "pinned",
						"/sys/fs/bpf/calico/xdp/eth0_ipv4_v1_blacklist", "key", "hex",
					}, hostHexCIDR...)
					Eventually(tc.Felixes[srvr].ExecOutputFn(args...), "10s").Should(ContainSubstring("value:"))
				})
			}

			It("should have expected no dropped packets in iptables", func() {
				versionReader, err := environment.GetKernelVersionReader()
				Expect(err).NotTo(HaveOccurred())

				kernelVersion, err := environment.GetKernelVersion(versionReader)
				Expect(err).NotTo(HaveOccurred())

				if proto == "tcp" && kernelVersion.Compare(environment.MustParseVersion("4.19.0")) < 0 {
					Skip(fmt.Sprintf("Skipping TCP test on Linux %v (needs 4.19)", kernelVersion))
					return
				}

				expectBlocked(cc)

				if !BPFMode() && !NFTMode() {
					// the only rule that refers to a cali40-prefixed ipset should have 0 packets/bytes
					Eventually(func() string {
						out, _ := tc.Felixes[srvr].ExecOutput("iptables", "-t", "raw", "-v", "-n", "-L", xdpfChainName)
						return out
					}).Should(MatchRegexp(`(?m)^\s+0\s+0.*cali40s:`))
				}
			})

			It("should have expected failsafe port 1234 to be open on felix[srvr] with XDP blocklist", func() {
				expectFailsafePortsOpen(cc)
			})
		})
	})
}

func xdpProgramID(felix *infrastructure.Felix, iface string) int {
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

func xdpProgramAttached(felix *infrastructure.Felix, iface string) bool {
	return xdpProgramID(felix, iface) != 0
}
