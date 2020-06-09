// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

// +build fvtests

package fv_test

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/connectivity"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/tcpdump"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
)

const (
	wireguardInterfaceNameDefault       = "wireguard.cali"
	wireguardMTUDefault                 = 1420
	wireguardRoutingRulePriorityDefault = "99"
	wireguardListeningPortDefault       = "51820"

	fakeWireguardPubKey = "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY="
)

var _ = infrastructure.DatastoreDescribe("WireGuard-Supported", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const nodeCount = 2

	var (
		infra        infrastructure.DatastoreInfra
		felixes      []*infrastructure.Felix
		client       clientv3.Interface
		tcpdumps     []*tcpdump.TCPDump
		wls          [nodeCount]*workload.Workload // simulated host workloads
		cc           *connectivity.Checker
		routeEntries [nodeCount]string
		ruleCIDRs    [nodeCount]string
	)

	BeforeEach(func() {
		// Run these tests only when the Host has Wireguard kernel module installed.
		if os.Getenv("FELIX_FV_WIREGUARD_AVAILABLE") != "true" {
			Skip("Skipping Wireguard supported tests.")
		}

		infra = getInfra()
		felixes, client = infrastructure.StartNNodeTopology(nodeCount, wireguardTopologyOptions(), infra)

		// To allow all ingress and egress, in absence of any Policy.
		infra.AddDefaultAllow()

		for i := range wls {
			wlIP := fmt.Sprintf("10.65.%d.2", i)
			wlName := fmt.Sprintf("wl%d", i)

			err := client.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
				IP:       net.MustParseIP(wlIP),
				HandleID: &wlName,
				Attrs: map[string]string{
					ipam.AttributeNode: felixes[i].Hostname,
				},
				Hostname: felixes[i].Hostname,
			})
			Expect(err).NotTo(HaveOccurred())

			wls[i] = workload.Run(felixes[i], wlName, "default", wlIP, "8055", "tcp")
			wls[i].ConfigureInDatastore(infra)

			// Prepare substring to match in rule.
			ruleCIDRs[i] = fmt.Sprintf("10.65.%d.0/26", i)
			// Prepare route entry.
			routeEntries[i] = fmt.Sprintf("10.65.%d.0/26 dev %s scope link", i, wireguardInterfaceNameDefault)

			felixes[i].TriggerDelayedStart()
		}
		// Swap route entry to match between workloads.
		routeEntries[0], routeEntries[1] = routeEntries[1], routeEntries[0]

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
				felix.Exec("ip", "addr")
				felix.Exec("ip", "rule", "list")
				felix.Exec("ip", "route", "show", "table", "all")
				felix.Exec("ip", "route", "show", "cached")
				felix.Exec("wg")
			}
		}

		for _, wl := range wls {
			wl.Stop()
		}
		for _, tcpdump := range tcpdumps {
			tcpdump.Stop()
		}
		for _, felix := range felixes {
			felix.Stop()
		}

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	Context("with Wireguard enabled", func() {
		BeforeEach(func() {
			for i, felix := range felixes {
				// Check the Wireguard device exists.
				Eventually(func() error {
					out, err := felix.ExecOutput("ip", "link", "show", wireguardInterfaceNameDefault)
					if err != nil {
						return err
					}
					if strings.Contains(out, wireguardInterfaceNameDefault) {
						return nil
					}
					return fmt.Errorf("felix %d has no Wireguard device", i)
				}, "10s", "100ms").ShouldNot(HaveOccurred())
			}
		})

		It("the Wireguard routing rule should exist", func() {
			for i, felix := range felixes {
				Eventually(func() string {
					return getWireguardRoutingRule(felix)
				}, "5s", "100ms").Should(MatchRegexp(fmt.Sprintf("\\d+:\\s+from %s fwmark 0/0x\\d+ lookup \\d+", ruleCIDRs[i])))
			}
		})

		It("the Wireguard route-table entry should exist", func() {
			for i, felix := range felixes {
				Eventually(func() string {
					return getWireguardRouteEntry(felix)
				}, "5s", "100ms").Should(ContainSubstring(routeEntries[i]))
			}
		})

		It("the Wireguard device should be configurable", func() {
			disableWireguard(client)

			// Old configuration should disappear.
			for _, felix := range felixes {
				Eventually(func() string {
					out, _ := felix.ExecOutput("ip", "-d", "link", "show", wireguardInterfaceNameDefault)
					return out
				}, "10s", "100ms").Should(BeEmpty())
				Eventually(func() string {
					out, err := felix.ExecOutput("ip", "rule", "show", "pref", wireguardRoutingRulePriorityDefault)
					Expect(err).NotTo(HaveOccurred())
					return out
				}, "10s", "100ms").Should(BeEmpty())
			}

			// Change Wireguard configuration.
			ifaceName := "wg0"
			mtu := 1400
			rule := 100
			port := 28150
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			fc, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			fc.Spec.WireguardInterfaceName = ifaceName
			fc.Spec.WireguardMTU = &mtu
			fc.Spec.WireguardListeningPort = &port
			fc.Spec.WireguardRoutingRulePriority = &rule
			_, err = client.FelixConfigurations().Update(ctx, fc, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			enableWireguard(client)

			// New Wireguard device should appear with default MTU, etc.
			for _, felix := range felixes {
				Eventually(func() string {
					out, _ := felix.ExecOutput("ip", "-d", "link", "show", ifaceName)
					return out
				}, "10s", "100ms").Should(ContainSubstring(fmt.Sprintf("mtu %d", mtu)))
			}

			// Expect the settings to be changed on the device.
			for _, felix := range felixes {
				Eventually(func() string {
					out, err := felix.ExecOutput("wg")
					Expect(err).NotTo(HaveOccurred())
					return out
				}, "10s", "100ms").Should(ContainSubstring(fmt.Sprintf("listening port: %d", port)))
				Eventually(func() string {
					out, err := felix.ExecOutput("ip", "rule", "show", "pref", fmt.Sprintf("%d", rule))
					Expect(err).NotTo(HaveOccurred())
					return out
				}, "10s", "100ms").ShouldNot(BeEmpty())
			}
		})

		It("v3 node resource annotations should contain public-keys", func() {
			for _, felix := range felixes {
				Eventually(func() string {
					node, err := client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())
					return node.Status.WireguardPublicKey
				}, "5s", "100ms").ShouldNot(BeEmpty())
			}
		})

		It("v3 node resource annotations should automatically heal", func() {
			for _, felix := range felixes {
				// Get the original public-key.
				node, err := client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				wgPubKeyOrig := node.Status.WireguardPublicKey

				// overwrite public-key by fake but valid wireguard key.
				node.Status.WireguardPublicKey = fakeWireguardPubKey
				_, err = client.Nodes().Update(context.Background(), node, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() string {
					node, err := client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())
					return node.Status.WireguardPublicKey
				}, "5s", "100ms").Should(Equal(wgPubKeyOrig))
			}
		})
	})

	Context("traffic with Wireguard enabled", func() {
		BeforeEach(func() {
			// Tunnel readiness checks.
			for i, felix := range felixes {
				// Check the Wireguard device exists.
				Eventually(func() error {
					out, err := felix.ExecOutput("ip", "link", "show", wireguardInterfaceNameDefault)
					if err != nil {
						return err
					}
					if strings.Contains(out, wireguardInterfaceNameDefault) {
						return nil
					}
					return fmt.Errorf("felix %d has no Wireguard device", i)
				}, "10s", "100ms").ShouldNot(HaveOccurred())
			}

			for i, felix := range felixes {
				// Check the rule exists.
				Eventually(func() string {
					return getWireguardRoutingRule(felix)
				}, "10s", "100ms").Should(MatchRegexp(fmt.Sprintf("\\d+:\\s+from %s fwmark 0/0x\\d+ lookup \\d+", ruleCIDRs[i])))
			}

			for i, felix := range felixes {
				// Check the route entry exists.
				Eventually(func() string {
					return getWireguardRouteEntry(felix)
				}, "10s", "100ms").Should(ContainSubstring(routeEntries[i]))
			}

			for _, felix := range felixes {
				// Felix tcpdump
				tcpdump := felix.AttachTCPDump("eth0")

				inTunnelPacketsPattern := fmt.Sprintf("IP %s\\.51820 > \\d+\\.\\d+\\.\\d+\\.\\d+\\.51820: UDP", felix.IP)
				tcpdump.AddMatcher("numInTunnelPackets", regexp.MustCompile(inTunnelPacketsPattern))
				outTunnelPacketsPattern := fmt.Sprintf("IP \\d+\\.\\d+\\.\\d+\\.\\d+\\.51820 > %s\\.51820: UDP", felix.IP)
				tcpdump.AddMatcher("numOutTunnelPackets", regexp.MustCompile(outTunnelPacketsPattern))
				workload01PacketsPattern := fmt.Sprintf("IP %s\\.\\d+ > %s\\.\\d+: ", wls[0].IP, wls[1].IP)
				tcpdump.AddMatcher("numWorkload01Packets", regexp.MustCompile(workload01PacketsPattern))
				workload10PacketsPattern := fmt.Sprintf("IP %s\\.\\d+ > %s\\.\\d+: ", wls[1].IP, wls[0].IP)
				tcpdump.AddMatcher("numWorkload10Packets", regexp.MustCompile(workload10PacketsPattern))

				tcpdump.Start()
				tcpdumps = append(tcpdumps, tcpdump)

			}
		})

		It("between pod to pod should be allowed and encrypted", func() {
			cc.ExpectSome(wls[0], wls[1])
			cc.ExpectSome(wls[1], wls[0])
			cc.CheckConnectivity()

			By("verifying tunnelled packet count is zero and no direct traffic between pod to pod exists")
			for i := range felixes {
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numInTunnelPackets")
				}, "10s", "100ms").Should(BeNumerically(">", 0))
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numOutTunnelPackets")
				}, "10s", "100ms").Should(BeNumerically(">", 0))
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numWorkload01Packets")
				}, "10s", "100ms").Should(BeNumerically("==", 0))
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numWorkload10Packets")
				}, "10s", "100ms").Should(BeNumerically("==", 0))
			}
		})

		It("between pod to pod should be encrypted using wg tunnel", func() {
			By("verifying wg stats")
			// Send 10 ping packets from/to workloads.
			err, _ := wls[0].SendPacketsTo(wls[1].IP, 10, 56)
			Expect(err).NotTo(HaveOccurred())
			err, _ = wls[1].SendPacketsTo(wls[0].IP, 10, 56)
			Expect(err).NotTo(HaveOccurred())

			// Get tunnel stats.
			xferRegExp := regexp.MustCompile(`transfer:\s+([0-9a-zA-Z. ]+)\s+received,\s+([0-9a-zA-Z. ]+)\s+sent`)
			var sent, rcvd [nodeCount]string
			for i, felix := range felixes {
				out, err := felix.ExecOutput("wg")
				Expect(err).NotTo(HaveOccurred())
				matches := xferRegExp.FindStringSubmatch(out)
				Expect(len(matches)).To(BeNumerically("==", 3))
				rcvd[i] = matches[1]
				sent[i] = matches[2]
			}
			Expect(rcvd[0]).NotTo(BeEmpty())
			Expect(rcvd[0]).To(Equal(sent[1]))
			Expect(rcvd[1]).NotTo(BeEmpty())
			Expect(rcvd[1]).To(Equal(sent[0]))
		})
	})

	Context("with Wireguard disabled", func() {
		BeforeEach(func() {
			disableWireguard(client)

			// Check Wireguard device doesn't exist.
			for _, felix := range felixes {
				Eventually(func() string {
					out, _ := felix.ExecOutput("ip", "link", "show", wireguardInterfaceNameDefault)
					return out
				}, "10s", "100ms").Should(BeEmpty())
			}

			// Check that Wireguard routing rule doesn't exist.
			for _, felix := range felixes {
				Eventually(func() string {
					return getWireguardRoutingRule(felix)
				}, "10s", "100ms").Should(BeEmpty())
			}

			// Check Wireguard route table entry doesn't exist.
			for i, felix := range felixes {
				Eventually(func() string {
					return getWireguardRouteEntry(felix)
				}, "10s", "100ms").ShouldNot(ContainSubstring(routeEntries[i]))
			}
		})

		It("v3 node resource shouldn't contain public-key", func() {
			for _, felix := range felixes {
				Eventually(func() string {
					node, err := client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())
					return node.Status.WireguardPublicKey
				}, "10s", "100ms").Should(BeEmpty())
			}
		})

		It("workload connectivity remains but uses un-encrypted tunnel", func() {
			cc.ExpectSome(wls[0], wls[1])
			cc.ExpectSome(wls[1], wls[0])
			cc.CheckConnectivity()

			for _, felix := range felixes {
				Eventually(func() string {
					// No tunnel implies un-encrypted communication.
					out, err := felix.ExecOutput("wg")
					Expect(err).NotTo(HaveOccurred())
					return out
				}, "10s", "100ms").Should(BeEmpty())
			}
		})
	})
})

var _ = infrastructure.DatastoreDescribe("WireGuard-Unsupported", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
	)

	BeforeEach(func() {
		// Setup a single node cluster.
		const nodeCount = 1

		infra = getInfra()
		felixes, _ = infrastructure.StartNNodeTopology(nodeCount, wireguardTopologyOptions(), infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		felixes[0].TriggerDelayedStart()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			felixes[0].Exec("ip", "link")
			felixes[0].Exec("wg")
		}

		felixes[0].Stop()

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	It("no Wireguard device exists", func() {
		Eventually(func() string {
			out, err := felixes[0].ExecOutput("ip", "link", "show", wireguardInterfaceNameDefault)
			Expect(err).To(HaveOccurred())
			return out
		}, "10s", "100ms").Should(BeEmpty())
	})

	It("no wg tool info exists", func() {
		Eventually(func() string {
			out, err := felixes[0].ExecOutput("wg")
			Expect(err).NotTo(HaveOccurred())
			return out
		}, "10s", "100ms").Should(BeEmpty())
	})
})

// Setup cluster toplogy options.
// mainly, enable Wireguard with delayed start option.
func wireguardTopologyOptions() infrastructure.TopologyOptions {
	topologyOptions := infrastructure.DefaultTopologyOptions()

	// Waiting for calico-node to be ready.
	topologyOptions.DelayFelixStart = true
	// Wireguard doesn't support IPv6, disable it.
	topologyOptions.EnableIPv6 = false
	// Assigning workload IPs using IPAM API.
	topologyOptions.IPIPRoutesEnabled = false

	// Enable Wireguard.
	felixConfig := api.NewFelixConfiguration()
	felixConfig.SetName("default")
	enabled := true
	felixConfig.Spec.WireguardEnabled = &enabled
	topologyOptions.InitialFelixConfiguration = felixConfig

	// Debugging.
	//topologyOptions.ExtraEnvVars["FELIX_DebugUseShortPollIntervals"] = "true"
	//topologyOptions.FelixLogSeverity = "debug"

	return topologyOptions
}

func enableWireguard(client clientv3.Interface) {
	updateWireguardEnabledConfig(client, true)
}

func disableWireguard(client clientv3.Interface) {
	updateWireguardEnabledConfig(client, false)
}

func updateWireguardEnabledConfig(client clientv3.Interface, value bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	felixConfig, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	felixConfig.Spec.WireguardEnabled = &value
	felixConfig, err = client.FelixConfigurations().Update(ctx, felixConfig, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func getWireguardRoutingRule(felix *infrastructure.Felix) string {
	rule, err := felix.ExecOutput("ip", "rule", "show", "pref", wireguardRoutingRulePriorityDefault)
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSpace(rule)
}

func getWireguardRouteEntry(felix *infrastructure.Felix) string {
	rule := getWireguardRoutingRule(felix)

	// Get route table index from rule.
	routingRuleRegExp := regexp.MustCompile(`\d+$`)
	tableId := routingRuleRegExp.FindString(rule)
	if tableId == "" {
		return ""
	}

	// Check route table entry.
	routes, err := felix.ExecOutput("ip", "route", "show", "table", tableId)
	Expect(err).NotTo(HaveOccurred())

	return routes
}
