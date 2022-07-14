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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/onsi/gomega/types"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/tcpdump"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

const (
	wireguardInterfaceNameDefault       = "wireguard.cali"
	wireguardInterfaceNameV6Default     = "wg-v6.cali"
	wireguardMTUDefault                 = 1440 // Wireguard needs an overhead of 60 bytes for IPv4.
	wireguardMTUV6Default               = 1420 // Wireguard needs an overhead of 80 bytes for IPv6.
	wireguardRoutingRulePriorityDefault = "99"
	wireguardListeningPortDefault       = 51820
	wireguardListeningPortV6Default     = 51821
	defaultWorkloadPort                 = "8055"
	fakeWireguardPubKeyV4               = "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY="
	fakeWireguardPubKeyV6               = "wTRvGspB+MEP36UJ69K5krtFndRYKJZn3YfKOCf59Es="
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ WireGuard-Supported", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const nodeCount = 2

	var (
		infra          infrastructure.DatastoreInfra
		felixes        []*infrastructure.Felix
		client         clientv3.Interface
		tcpdumps       []*tcpdump.TCPDump
		wlsV4          [nodeCount]*workload.Workload // simulated host workloads
		wlsV6          [nodeCount]*workload.Workload // simulated host workloads
		cc             *connectivity.Checker
		routeEntriesV4 [nodeCount]string
		routeEntriesV6 [nodeCount]string
		dmesgCmd       *exec.Cmd
		dmesgBuf       bytes.Buffer
		dmesgKill      func()

		wgBootstrapEvents chan struct{}
	)

	type testConf struct {
		WireguardEnabledV4 bool
		WireguardEnabledV6 bool
	}
	for _, testConfig := range []testConf{
		{true, false},
		{false, true},
		{true, true},
	} {
		wireguardEnabledV4 := testConfig.WireguardEnabledV4
		wireguardEnabledV6 := testConfig.WireguardEnabledV6

		Describe(fmt.Sprintf("wireguardEnabledV4: %v, wireguardEnabledV6: %v, ", wireguardEnabledV4, wireguardEnabledV6), func() {
			BeforeEach(func() {
				// Run these tests only when the Host has Wireguard kernel module installed.
				if os.Getenv("FELIX_FV_WIREGUARD_AVAILABLE") != "true" {
					Skip("Skipping Wireguard supported tests.")
				}

				// Enable Wireguard module debugging.
				utils.Run("sudo", "sh", "-c", "echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control")

				// Start a process tailing the dmesg log.
				ctx, cancel := context.WithCancel(context.Background())
				dmesgCmd = exec.CommandContext(ctx, "sudo", "dmesg", "-wH")
				dmesgCmd.Stdout = &dmesgBuf
				dmesgCmd.Stderr = &dmesgBuf
				err := dmesgCmd.Start()
				Expect(err).NotTo(HaveOccurred())
				dmesgKill = cancel
				log.Info("Started dmesg log capture")

				infra = getInfra()
				topologyOptions := wireguardTopologyOptions(
					"CalicoIPAM", true, wireguardEnabledV4, wireguardEnabledV6,
					map[string]string{
						"FELIX_DebugDisableLogDropping": "true",
						"FELIX_DBG_WGBOOTSTRAP":         "true",
					},
				)
				felixes, client = infrastructure.StartNNodeTopology(nodeCount, topologyOptions, infra)

				// To allow all ingress and egress, in absence of any Policy.
				infra.AddDefaultAllow()

				if wireguardEnabledV4 {
					for i := range wlsV4 {
						wlsV4[i] = createWorkloadWithAssignedIP(
							&infra,
							&topologyOptions,
							&client,
							fmt.Sprintf("10.65.%d.2", i),
							fmt.Sprintf("wlv4-%d", i),
							felixes[i])

						// Prepare route entry.
						routeEntriesV4[i] = fmt.Sprintf("10.65.%d.0/26 dev %s scope link", i, wireguardInterfaceNameDefault)
					}
					// Swap route entry to match between workloads.
					routeEntriesV4[0], routeEntriesV4[1] = routeEntriesV4[1], routeEntriesV4[0]
				}
				if wireguardEnabledV6 {
					for i := range wlsV6 {
						wlsV6[i] = createWorkloadWithAssignedIP(
							&infra,
							&topologyOptions,
							&client,
							fmt.Sprintf("dead:beef::100:%d:2", i),
							fmt.Sprintf("wlv6-%d", i),
							felixes[i])

						// Prepare route entry.
						routeEntriesV6[i] = fmt.Sprintf("dead:beef::100:%d:0/122 dev %s metric 1024 pref medium", i, wireguardInterfaceNameV6Default)

					}
					// Swap route entry to match between workloads.
					routeEntriesV6[0], routeEntriesV6[1] = routeEntriesV6[1], routeEntriesV6[0]
				}
				for i := 0; i < nodeCount; i++ {
					wgBootstrapEvents = felixes[i].WatchStdoutFor(
						regexp.MustCompile(".*(Cleared wireguard public key from datastore|Wireguard public key not set in datastore).+"),
					)
					felixes[i].TriggerDelayedStart()
				}

				cc = &connectivity.Checker{}

				// Reset the set of tcp dumps between runs.
				tcpdumps = nil
			})

			AfterEach(func() {
				if dmesgKill != nil {
					log.Info("Stop dmesg log capture")
					dmesgKill()
					log.Infof("Captured dmesg log:\n%v", dmesgBuf.String())
				}

				if CurrentGinkgoTestDescription().Failed {
					for _, felix := range felixes {
						felix.Exec("ip", "addr")
						felix.Exec("ip", "rule", "list")
						felix.Exec("ip", "route", "show", "table", "all")
						felix.Exec("ip", "route", "show", "cached")
						felix.Exec("wg")
						felix.Exec("wg", "show", "all", "private-key")
					}
				}

				if wireguardEnabledV4 {
					for _, wl := range wlsV4 {
						wl.Stop()
					}
				}
				if wireguardEnabledV6 {
					for _, wl := range wlsV6 {
						wl.Stop()
					}
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
						if wireguardEnabledV4 {
							Eventually(func() error {
								out, err := felix.ExecOutput("ip", "link", "show", wireguardInterfaceNameDefault)
								if err != nil {
									return err
								}
								if strings.Contains(out, wireguardInterfaceNameDefault) {
									return nil
								}
								return fmt.Errorf("felix %d has no IPv4 Wireguard device", i)
							}, "10s", "100ms").ShouldNot(HaveOccurred())
						}
						if wireguardEnabledV6 {
							Eventually(func() error {
								out, err := felix.ExecOutput("ip", "link", "show", wireguardInterfaceNameV6Default)
								if err != nil {
									return err
								}
								if strings.Contains(out, wireguardInterfaceNameV6Default) {
									return nil
								}
								return fmt.Errorf("felix %d has no IPv6 Wireguard device", i)
							}, "10s", "100ms").ShouldNot(HaveOccurred())
						}
					}
				})

				It("should have called bootstrap", func() {
					Eventually(wgBootstrapEvents, "5s", "100ms").Should(BeClosed())
				})

				It("the Wireguard routing rule should exist", func() {
					for _, felix := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() string {
								return getWireguardRoutingRule(felix, 4)
							}, "5s", "100ms").Should(MatchRegexp("\\d+:\\s+not from all fwmark 0x\\d+/0x\\d+ lookup \\d+"))
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								return getWireguardRoutingRule(felix, 6)
							}, "5s", "100ms").Should(MatchRegexp("\\d+:\\s+not from all fwmark 0x\\d+/0x\\d+ lookup \\d+"))
						}
					}
				})

				It("the Wireguard route-table entry should exist", func() {
					for i, felix := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() string {
								return getWireguardRouteEntry(felix, 4)
							}, "5s", "100ms").Should(ContainSubstring(routeEntriesV4[i]))
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								return getWireguardRouteEntry(felix, 6)
							}, "5s", "100ms").Should(ContainSubstring(routeEntriesV6[i]))
						}
					}
				})

				It("the Wireguard device should be configurable", func() {
					disableWireguard(client)

					// Old configuration should disappear.
					for _, felix := range felixes {
						if wireguardEnabledV4 {
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
						if wireguardEnabledV6 {
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", wireguardInterfaceNameV6Default)
								return out
							}, "10s", "100ms").Should(BeEmpty())
							Eventually(func() string {
								out, err := felix.ExecOutput("ip", "-6", "rule", "show", "pref", wireguardRoutingRulePriorityDefault)
								Expect(err).NotTo(HaveOccurred())
								return out
							}, "10s", "100ms").Should(BeEmpty())
						}
					}

					// Change Wireguard configuration.
					ifaceName := "wg0"
					ifaceNameV6 := "wg1"
					mtu := 1400
					mtuV6 := 1380
					rule := 100
					port := 28150
					portV6 := 28151
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					fc, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())
					fc.Spec.WireguardInterfaceName = ifaceName
					fc.Spec.WireguardInterfaceNameV6 = ifaceNameV6
					fc.Spec.WireguardMTU = &mtu
					fc.Spec.WireguardMTUV6 = &mtuV6
					fc.Spec.WireguardListeningPort = &port
					fc.Spec.WireguardListeningPortV6 = &portV6
					fc.Spec.WireguardRoutingRulePriority = &rule
					_, err = client.FelixConfigurations().Update(ctx, fc, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())

					updateWireguardEnabledConfig(client, wireguardEnabledV4, wireguardEnabledV6)

					// New Wireguard device should appear with default MTU, etc.
					for _, felix := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", ifaceName)
								return out
							}, "10s", "100ms").Should(ContainSubstring(fmt.Sprintf("mtu %d", mtu)))
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "-d", "link", "show", ifaceNameV6)
								return out
							}, "10s", "100ms").Should(ContainSubstring(fmt.Sprintf("mtu %d", mtuV6)))
						}
					}

					// Expect the settings to be changed on the device.
					for _, felix := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() string {
								out, err := felix.ExecOutput("wg", "show", ifaceName)
								Expect(err).NotTo(HaveOccurred())
								return out
							}, "10s", "100ms").Should(ContainSubstring(fmt.Sprintf("listening port: %d", port)))
							Eventually(func() string {
								out, err := felix.ExecOutput("ip", "rule", "show", "pref", fmt.Sprintf("%d", rule))
								Expect(err).NotTo(HaveOccurred())
								return out
							}, "10s", "100ms").ShouldNot(BeEmpty())
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								out, err := felix.ExecOutput("wg", "show", ifaceNameV6)
								Expect(err).NotTo(HaveOccurred())
								return out
							}, "10s", "100ms").Should(ContainSubstring(fmt.Sprintf("listening port: %d", portV6)))
							Eventually(func() string {
								out, err := felix.ExecOutput("ip", "-6", "rule", "show", "pref", fmt.Sprintf("%d", rule))
								Expect(err).NotTo(HaveOccurred())
								return out
							}, "10s", "100ms").ShouldNot(BeEmpty())
						}
					}
				})

				It("v3 node resource annotations should contain public-keys", func() {
					for _, felix := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() string {
								node, err := client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
								Expect(err).NotTo(HaveOccurred())
								return node.Status.WireguardPublicKey
							}, "5s", "100ms").ShouldNot(BeEmpty())
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								node, err := client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
								Expect(err).NotTo(HaveOccurred())
								return node.Status.WireguardPublicKeyV6
							}, "5s", "100ms").ShouldNot(BeEmpty())
						}
					}
				})

				It("v3 node resource annotations should automatically heal", func() {
					for _, felix := range felixes {
						if wireguardEnabledV4 {
							var wgPubKeyOrig string
							var node *v3.Node
							var err error

							// Get the original public-key.
							Eventually(func() error {
								node, err = client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
								if err != nil {
									return err
								}
								if node.Status.WireguardPublicKey == "" {
									return errors.New("node.Status.WireguardPublicKey not set yet")
								} else if wgPubKeyOrig == "" {
									// Seeing the original public key for the first time.
									wgPubKeyOrig = node.Status.WireguardPublicKey
								}

								// overwrite public-key by fake but valid Wireguard key.
								node.Status.WireguardPublicKey = fakeWireguardPubKeyV4
								_, err = client.Nodes().Update(context.Background(), node, options.SetOptions{})
								if err != nil {
									return err
								}

								return nil
							}, "5s", "300ms").ShouldNot(HaveOccurred())

							Eventually(func() string {
								node, err = client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
								if err != nil {
									return "ERROR: " + err.Error()
								}
								return node.Status.WireguardPublicKey
							}, "5s", "100ms").Should(Equal(wgPubKeyOrig))
						}
						if wireguardEnabledV6 {
							var wgPubKeyOrig string
							var node *v3.Node
							var err error

							// Get the original public-key.
							Eventually(func() error {
								node, err = client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
								if err != nil {
									return err
								}
								if node.Status.WireguardPublicKeyV6 == "" {
									return errors.New("node.Status.WireguardPublicKeyV6 not set yet")
								} else if wgPubKeyOrig == "" {
									// Seeing the original public key for the first time.
									wgPubKeyOrig = node.Status.WireguardPublicKeyV6
								}

								// overwrite public-key by fake but valid Wireguard key.
								node.Status.WireguardPublicKeyV6 = fakeWireguardPubKeyV6
								_, err = client.Nodes().Update(context.Background(), node, options.SetOptions{})
								if err != nil {
									return err
								}

								return nil
							}, "5s", "300ms").ShouldNot(HaveOccurred())

							Eventually(func() string {
								node, err = client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
								if err != nil {
									return "ERROR: " + err.Error()
								}
								return node.Status.WireguardPublicKeyV6
							}, "5s", "100ms").Should(Equal(wgPubKeyOrig))
						}
					}
				})
			})

			Context("traffic with Wireguard enabled", func() {
				// Checks the TCP dump for a count value. Retries until count is correct, or fails after 1.5s.
				waitForPackets := func(t *tcpdump.TCPDump, timeout time.Time, name string, num int) error {
					for ; ; time.Now().Before(timeout) {
						if num == 0 && t.MatchCount(name) > 0 {
							// We expect no traffic, but got some.  Error immediately.
							break
						}
						if t.MatchCount(name) >= num {
							// We expected some packets and have got at least the required number (we allow more for handshake
							// etc.)
							return nil
						}
						time.Sleep(100 * time.Millisecond)
					}
					return fmt.Errorf("incorrect packet count for %s; expected=%d actual=%d", name, num, t.MatchCount(name))
				}

				// Runs wg and extracts the received and sent packet counts.
				getWgStatistics := func(felix *infrastructure.Felix, device string) (sent, rcvd string) {
					xferRegExp := regexp.MustCompile(`transfer:\s+([0-9a-zA-Z. ]+)\s+received,\s+([0-9a-zA-Z. ]+)\s+sent`)
					out, err := felix.ExecOutput("wg", "show", device)
					Expect(err).NotTo(HaveOccurred())
					matches := xferRegExp.FindStringSubmatch(out)
					if len(matches) != 3 {
						return
					}
					return matches[2], matches[1]
				}

				// Checks connectivity between workloads 0 and 1, checking that eth0 traffic is via wireguard port and that
				// there are non-empty wireguard stats.
				checkConn := func() error {
					// Check if running on BPF dataplane to skip IPv6 in this case
					runningBPF := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

					// Reset TCP packet counts.
					By("Resetting the TCP dump counts")
					for i := range felixes {
						if wireguardEnabledV4 {
							tcpdumps[i].ResetCount("numInTunnelPackets")
							tcpdumps[i].ResetCount("numOutTunnelPackets")
							tcpdumps[i].ResetCount("numWorkload0to1Packets")
							tcpdumps[i].ResetCount("numWorkload1to0Packets")
						}
						if wireguardEnabledV6 && !runningBPF {
							tcpdumps[i].ResetCount("numInTunnelPacketsV6")
							tcpdumps[i].ResetCount("numOutTunnelPacketsV6")
							tcpdumps[i].ResetCount("numWorkload0to1PacketsV6")
							tcpdumps[i].ResetCount("numWorkload1to0PacketsV6")
						}
					}

					// Send packets to and from workloads on each felix.
					if wireguardEnabledV4 {
						By("Sending IPv4 packets W1->W2 and W2->W1")
						if err, _ := wlsV4[0].SendPacketsTo(wlsV4[1].IP, 5, 56); err != nil {
							return err
						}
						if err, _ := wlsV4[1].SendPacketsTo(wlsV4[0].IP, 5, 56); err != nil {
							return err
						}
					}
					if wireguardEnabledV6 && !runningBPF {
						By("Sending IPv6 packets W1->W2 and W2->W1")
						if err, _ := wlsV6[0].SendPacketsTo(wlsV6[1].IP, 5, 56); err != nil {
							return err
						}
						if err, _ := wlsV6[1].SendPacketsTo(wlsV6[0].IP, 5, 56); err != nil {
							return err
						}
					}

					// Now check the packet counts are as expected. We should have no WL->WL traffic visible on eth0, but
					// we should be able to see tunnel traffic. Since we want to verify
					By("Checking the packet stats from tcpdump")
					timeout := time.Now().Add(2 * time.Second)
					for i := range felixes {
						if wireguardEnabledV4 {
							if err := waitForPackets(tcpdumps[i], timeout, "numInTunnelPackets", 10); err != nil {
								return err
							} else if err := waitForPackets(tcpdumps[i], timeout, "numOutTunnelPackets", 10); err != nil {
								return err
							} else if err := waitForPackets(tcpdumps[i], timeout, "numWorkload0to1Packets", 0); err != nil {
								return err
							} else if err := waitForPackets(tcpdumps[i], timeout, "numWorkload1to0Packets", 0); err != nil {
								return err
							}
						}
						if wireguardEnabledV6 && !runningBPF {
							if err := waitForPackets(tcpdumps[i], timeout, "numInTunnelPacketsV6", 10); err != nil {
								return err
							} else if err := waitForPackets(tcpdumps[i], timeout, "numOutTunnelPacketsV6", 10); err != nil {
								return err
							} else if err := waitForPackets(tcpdumps[i], timeout, "numWorkload0to1PacketsV6", 0); err != nil {
								return err
							} else if err := waitForPackets(tcpdumps[i], timeout, "numWorkload1to0PacketsV6", 0); err != nil {
								return err
							}
						}
					}

					By("Checking the packet stats from wg")
					for i := range felixes {
						if wireguardEnabledV4 {
							rcvd, sent := getWgStatistics(felixes[i], wireguardInterfaceNameDefault)
							// TODO: counter compare sent/rcvd data from wg tunnel on each node.
							Expect(rcvd).NotTo(BeEmpty())
							Expect(sent).NotTo(BeEmpty())
						}
						if wireguardEnabledV6 && !runningBPF {
							rcvd, sent := getWgStatistics(felixes[i], wireguardInterfaceNameV6Default)
							// TODO: counter compare sent/rcvd data from wg tunnel on each node.
							Expect(rcvd).NotTo(BeEmpty())
							Expect(sent).NotTo(BeEmpty())
						}
					}
					return nil
				}

				BeforeEach(func() {
					// Tunnel readiness checks.
					for i, felix := range felixes {
						// Check the Wireguard device exists.
						deviceNames := []string{}
						if wireguardEnabledV4 {
							deviceNames = append(deviceNames, wireguardInterfaceNameDefault)
						}
						if wireguardEnabledV6 {
							deviceNames = append(deviceNames, wireguardInterfaceNameV6Default)
						}
						for _, device := range deviceNames {
							Eventually(func() error {
								out, err := felix.ExecOutput("ip", "link", "show", device)
								if err != nil {
									return err
								}
								if strings.Contains(out, device) {
									return nil
								}
								return fmt.Errorf("felix %d has no Wireguard device named %s", i, device)
							}, "10s", "100ms").ShouldNot(HaveOccurred())
						}
					}

					for _, felix := range felixes {
						// Check the rule exists.
						if wireguardEnabledV4 {
							Eventually(func() string {
								return getWireguardRoutingRule(felix, 4)
							}, "10s", "100ms").Should(MatchRegexp("\\d+:\\s+not from all fwmark 0x\\d+/0x\\d+ lookup \\d+"))
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								return getWireguardRoutingRule(felix, 6)
							}, "10s", "100ms").Should(MatchRegexp("\\d+:\\s+not from all fwmark 0x\\d+/0x\\d+ lookup \\d+"))
						}
					}

					for i, felix := range felixes {
						// Check the route entry exists.
						if wireguardEnabledV4 {
							Eventually(func() string {
								return getWireguardRouteEntry(felix, 4)
							}, "10s", "100ms").Should(ContainSubstring(routeEntriesV4[i]))
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								return getWireguardRouteEntry(felix, 6)
							}, "10s", "100ms").Should(ContainSubstring(routeEntriesV6[i]))
						}
					}

					tcpdumps = make([]*tcpdump.TCPDump, nodeCount)
					for i, felix := range felixes {
						// felix tcpdump
						tcpdump := felix.AttachTCPDump("eth0")

						if wireguardEnabledV4 {
							inTunnelPacketsPattern := fmt.Sprintf("IP %s\\.51820 > \\d+\\.\\d+\\.\\d+\\.\\d+\\.51820: UDP", felix.IP)
							tcpdump.AddMatcher("numInTunnelPackets", regexp.MustCompile(inTunnelPacketsPattern))
							outTunnelPacketsPattern := fmt.Sprintf("IP \\d+\\.\\d+\\.\\d+\\.\\d+\\.51820 > %s\\.51820: UDP", felix.IP)
							tcpdump.AddMatcher("numOutTunnelPackets", regexp.MustCompile(outTunnelPacketsPattern))
							workload01PacketsPattern := fmt.Sprintf("IP %s\\.\\d+ > %s\\.\\d+: ", wlsV4[0].IP, wlsV4[1].IP)
							tcpdump.AddMatcher("numWorkload0to1Packets", regexp.MustCompile(workload01PacketsPattern))
							workload10PacketsPattern := fmt.Sprintf("IP %s\\.\\d+ > %s\\.\\d+: ", wlsV4[1].IP, wlsV4[0].IP)
							tcpdump.AddMatcher("numWorkload1to0Packets", regexp.MustCompile(workload10PacketsPattern))
						}
						if wireguardEnabledV6 {
							inTunnelPacketsPatternV6 := fmt.Sprintf("IP6 %s\\.51821 > ([a-f0-9:]+:+)+[a-f0-9]+\\.51821: UDP", felix.IPv6)
							tcpdump.AddMatcher("numInTunnelPacketsV6", regexp.MustCompile(inTunnelPacketsPatternV6))
							outTunnelPacketsPatternV6 := fmt.Sprintf("IP6 ([a-f0-9:]+:+)+[a-f0-9]+\\.51821 > %s\\.51821: UDP", felix.IPv6)
							tcpdump.AddMatcher("numOutTunnelPacketsV6", regexp.MustCompile(outTunnelPacketsPatternV6))
							workload01PacketsPatternV6 := fmt.Sprintf("IP6 %s\\.\\d+ > %s\\.\\d+: ", wlsV6[0].IP, wlsV6[1].IP)
							tcpdump.AddMatcher("numWorkload0to1PacketsV6", regexp.MustCompile(workload01PacketsPatternV6))
							workload10PacketsPatternV6 := fmt.Sprintf("IP6 %s\\.\\d+ > %s\\.\\d+: ", wlsV6[1].IP, wlsV6[0].IP)
							tcpdump.AddMatcher("numWorkload1to0PacketsV6", regexp.MustCompile(workload10PacketsPatternV6))
						}

						tcpdump.Start()
						tcpdumps[i] = tcpdump
					}
				})

				It("between pod to pod should be allowed and encrypted using wg tunnel", func() {
					Eventually(checkConn, "10s", "100ms").ShouldNot(HaveOccurred())
				})

				tests := []struct {
					hep            string
					iptablesPolicy string
				}{
					{
						hep:            "*",
						iptablesPolicy: "ACCEPT",
					},
					{
						hep:            "*",
						iptablesPolicy: "DROP",
					},
					{
						hep:            "eth0",
						iptablesPolicy: "ACCEPT",
					},
					{
						hep:            "eth0",
						iptablesPolicy: "DROP",
					},
				}

				for _, xtc := range tests {
					tc := xtc
					desc := "wireguard traffic is allowed with a blocking host endpoint policy" +
						" (using " + tc.hep + " HostEndpoint, " + tc.iptablesPolicy + ")"
					It(desc, func() {
						By("Creating policy to deny wireguard port on main felix host endpoint.")
						policy := api.NewGlobalNetworkPolicy()
						policy.Name = "deny-wg-port"
						port := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
						policy.Spec.Egress = []api.Rule{}
						if wireguardEnabledV4 {
							policy.Spec.Egress = append(policy.Spec.Egress,
								api.Rule{
									// Deny egress UDP to the wireguard port.
									Action:   api.Deny,
									Protocol: &port,
									Destination: api.EntityRule{
										Selector: "has(host-endpoint)",
										Ports:    []numorstring.Port{numorstring.SinglePort(wireguardListeningPortDefault)},
									},
								},
							)
						}
						if wireguardEnabledV6 {
							policy.Spec.Egress = append(policy.Spec.Egress,
								api.Rule{
									// Deny egress UDP to the wireguard port.
									Action:   api.Deny,
									Protocol: &port,
									Destination: api.EntityRule{
										Selector: "has(host-endpoint)",
										Ports:    []numorstring.Port{numorstring.SinglePort(wireguardListeningPortV6Default)},
									},
								},
							)
						}
						policy.Spec.Egress = append(policy.Spec.Egress, api.Rule{Action: api.Allow})

						policy.Spec.Ingress = []api.Rule{}
						if wireguardEnabledV4 {
							policy.Spec.Ingress = append(policy.Spec.Ingress,
								api.Rule{
									// Deny all UDP traffic to the hosts.
									Action:   api.Deny,
									Protocol: &port,
									Destination: api.EntityRule{
										Selector: "has(host-endpoint)",
										Ports:    []numorstring.Port{numorstring.SinglePort(wireguardListeningPortDefault)},
									},
								},
							)
						}
						if wireguardEnabledV6 {
							policy.Spec.Ingress = append(policy.Spec.Ingress,
								api.Rule{
									// Deny all UDP traffic to the hosts.
									Action:   api.Deny,
									Protocol: &port,
									Destination: api.EntityRule{
										Selector: "has(host-endpoint)",
										Ports:    []numorstring.Port{numorstring.SinglePort(wireguardListeningPortV6Default)},
									},
								},
							)
						}
						policy.Spec.Ingress = append(policy.Spec.Ingress, api.Rule{Action: api.Allow})

						policy.Spec.Selector = "all()"
						policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
						_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
						Expect(err).NotTo(HaveOccurred())

						By("Creating a HostEndpoint for each Felix")
						for _, f := range felixes {
							hep := api.NewHostEndpoint()
							hep.Name = "hep-" + f.Name
							hep.Labels = map[string]string{
								"name":          hep.Name,
								"hostname":      f.Hostname,
								"host-endpoint": "true",
							}
							hep.Spec.Node = f.Hostname
							hep.Spec.ExpectedIPs = []string{}
							if wireguardEnabledV4 {
								hep.Spec.ExpectedIPs = append(hep.Spec.ExpectedIPs, f.IP)
							}
							if wireguardEnabledV6 {
								hep.Spec.ExpectedIPs = append(hep.Spec.ExpectedIPs, f.IPv6)
							}
							hep.Spec.InterfaceName = tc.hep
							_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
							Expect(err).NotTo(HaveOccurred())
						}

						By("Setting iptables INPUT chain policy to " + tc.iptablesPolicy)
						for _, felix := range felixes {
							_, err := felix.ExecOutput("iptables", "-w", "10", "-W", "100000", "-P", "INPUT", tc.iptablesPolicy)
							Expect(err).NotTo(HaveOccurred())
						}

						By("Waiting for the policy to apply")
						// XXX this is lame, but will have to do until we have a way do
						// XXX to confirm policy applied in BPF. Then we will fix both
						// XXX iptables and BPF properly.
						time.Sleep(30 * time.Second)

						By("Checking there is eventually and consistently connectivity between the workloads using wg")
						Eventually(checkConn, "5s", "100ms").ShouldNot(HaveOccurred())
						Consistently(checkConn, "2s", "100ms").ShouldNot(HaveOccurred())
					})
				}

				readPolicy := func(name string, action api.Action) error {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					policy, err := client.GlobalNetworkPolicies().Get(ctx, name, options.GetOptions{})
					if err == nil {
						if len(policy.Spec.Egress) > 0 &&
							policy.Spec.Egress[0].Action == action {
							return nil
						}
					}
					return fmt.Errorf("policy not applied")
				}

				It("between pod to pod should be encrypted using wg tunnel with egress policies applied", func() {
					policy := api.NewGlobalNetworkPolicy()

					policy.Name = "f01-egress-deny"
					order := float64(20)
					policy.Spec.Order = &order
					policy.Spec.Egress = []api.Rule{{Action: api.Deny}}
					if wireguardEnabledV4 && wireguardEnabledV6 {
						policy.Spec.Selector = fmt.Sprintf("name in { '%s', '%s', '%s', '%s'}", wlsV4[0].Name, wlsV4[1].Name, wlsV6[0].Name, wlsV6[1].Name)
					} else if wireguardEnabledV4 {
						policy.Spec.Selector = fmt.Sprintf("name in { '%s', '%s'}", wlsV4[0].Name, wlsV4[1].Name)
					} else if wireguardEnabledV6 {
						policy.Spec.Selector = fmt.Sprintf("name in { '%s', '%s'}", wlsV6[0].Name, wlsV6[1].Name)
					}
					_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())

					time.Sleep(5 * time.Second)
					Eventually(func() error {
						return readPolicy(policy.Name, api.Deny)
					}, "5s", "100ms").ShouldNot(HaveOccurred())

					if wireguardEnabledV4 {
						cc.ExpectNone(wlsV4[0], wlsV4[1])
						cc.ExpectNone(wlsV4[1], wlsV4[0])
					}
					if wireguardEnabledV6 {
						cc.ExpectNone(wlsV6[0], wlsV6[1])
						cc.ExpectNone(wlsV6[1], wlsV6[0])
					}
					cc.CheckConnectivity()

					By("verifying tunnelled packet count is zero")
					for i := range felixes {
						if wireguardEnabledV4 {
							Consistently(func() int {
								return tcpdumps[i].MatchCount("numInTunnelPackets")
							}, "5s", "100ms").Should(BeNumerically("==", 0))
							Consistently(func() int {
								return tcpdumps[i].MatchCount("numOutTunnelPackets")
							}, "5s", "100ms").Should(BeNumerically("==", 0))
						}
						if wireguardEnabledV6 {
							Consistently(func() int {
								return tcpdumps[i].MatchCount("numInTunnelPacketsV6")
							}, "5s", "100ms").Should(BeNumerically("==", 0))
							Consistently(func() int {
								return tcpdumps[i].MatchCount("numOutTunnelPacketsV6")
							}, "5s", "100ms").Should(BeNumerically("==", 0))
						}
					}

					cc.ResetExpectations()

					policy = api.NewGlobalNetworkPolicy()
					policy.Name = "f01-egress-allow"
					order = float64(10)
					policy.Spec.Order = &order // prioritized over deny policy above.
					policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
					if wireguardEnabledV4 && wireguardEnabledV6 {
						policy.Spec.Selector = fmt.Sprintf("name in { '%s', '%s', '%s', '%s'}", wlsV4[0].Name, wlsV4[1].Name, wlsV6[0].Name, wlsV6[1].Name)
					} else if wireguardEnabledV4 {
						policy.Spec.Selector = fmt.Sprintf("name in { '%s', '%s'}", wlsV4[0].Name, wlsV4[1].Name)
					} else if wireguardEnabledV6 {
						policy.Spec.Selector = fmt.Sprintf("name in { '%s', '%s'}", wlsV6[0].Name, wlsV6[1].Name)
					}
					_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())

					Eventually(func() error {
						return readPolicy(policy.Name, api.Allow)
					}, "5s", "100ms").ShouldNot(HaveOccurred())

					if wireguardEnabledV4 {
						cc.ExpectSome(wlsV4[0], wlsV4[1])
						cc.ExpectSome(wlsV4[1], wlsV4[0])
					}
					if wireguardEnabledV6 {
						cc.ExpectSome(wlsV6[0], wlsV6[1])
						cc.ExpectSome(wlsV6[1], wlsV6[0])
					}
					cc.CheckConnectivity()

					By("verifying tunnelled packet count is non-zero")
					for i := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() int {
								return tcpdumps[i].MatchCount("numInTunnelPackets")
							}, "10s", "100ms").Should(BeNumerically(">", 0))
							Eventually(func() int {
								return tcpdumps[i].MatchCount("numOutTunnelPackets")
							}, "10s", "100ms").Should(BeNumerically(">", 0))
						}
						if wireguardEnabledV6 {
							Eventually(func() int {
								return tcpdumps[i].MatchCount("numInTunnelPacketsV6")
							}, "10s", "100ms").Should(BeNumerically(">", 0))
							Eventually(func() int {
								return tcpdumps[i].MatchCount("numOutTunnelPacketsV6")
							}, "10s", "100ms").Should(BeNumerically(">", 0))
						}
					}
				})
			})

			Context("with Wireguard disabled", func() {
				BeforeEach(func() {
					disableWireguard(client)

					// Check Wireguard device doesn't exist.
					for _, felix := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "link", "show", wireguardInterfaceNameDefault)
								return out
							}, "10s", "100ms").Should(BeEmpty())
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								out, _ := felix.ExecOutput("ip", "link", "show", wireguardInterfaceNameV6Default)
								return out
							}, "10s", "100ms").Should(BeEmpty())
						}
					}

					// Check that Wireguard routing rule doesn't exist.
					for _, felix := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() string {
								return getWireguardRoutingRule(felix, 4)
							}, "10s", "100ms").Should(BeEmpty())
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								return getWireguardRoutingRule(felix, 6)
							}, "10s", "100ms").Should(BeEmpty())
						}
					}

					// Check Wireguard route table entry doesn't exist.
					for i, felix := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() string {
								return getWireguardRouteEntry(felix, 4)
							}, "10s", "100ms").ShouldNot(ContainSubstring(routeEntriesV4[i]))
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								return getWireguardRouteEntry(felix, 6)
							}, "10s", "100ms").ShouldNot(ContainSubstring(routeEntriesV6[i]))
						}
					}
				})

				It("v3 node resource shouldn't contain public-key", func() {
					for _, felix := range felixes {
						if wireguardEnabledV4 {
							Eventually(func() string {
								node, err := client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
								Expect(err).NotTo(HaveOccurred())
								return node.Status.WireguardPublicKey
							}, "10s", "100ms").Should(BeEmpty())
						}
						if wireguardEnabledV6 {
							Eventually(func() string {
								node, err := client.Nodes().Get(context.Background(), felix.Hostname, options.GetOptions{})
								Expect(err).NotTo(HaveOccurred())
								return node.Status.WireguardPublicKeyV6
							}, "10s", "100ms").Should(BeEmpty())
						}
					}
				})

				It("workload connectivity remains but uses un-encrypted tunnel", func() {
					if wireguardEnabledV4 {
						cc.ExpectSome(wlsV4[0], wlsV4[1])
						cc.ExpectSome(wlsV4[1], wlsV4[0])
					}
					if wireguardEnabledV6 {
						cc.ExpectSome(wlsV6[0], wlsV6[1])
						cc.ExpectSome(wlsV6[1], wlsV6[0])
					}
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
	}
})

var _ = infrastructure.DatastoreDescribe("WireGuard-Unsupported", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
	)

	type testConf struct {
		WireguardEnabledV4 bool
		WireguardEnabledV6 bool
	}
	for _, testConfig := range []testConf{
		{true, false},
		{false, true},
		{true, true},
	} {
		wireguardEnabledV4 := testConfig.WireguardEnabledV4
		wireguardEnabledV6 := testConfig.WireguardEnabledV6

		Describe(fmt.Sprintf("wireguardEnabledV4: %v, wireguardEnabledV6: %v, ", wireguardEnabledV4, wireguardEnabledV6), func() {
			BeforeEach(func() {
				// Run these tests only when the Host does not have Wireguard available.
				if os.Getenv("FELIX_FV_WIREGUARD_AVAILABLE") == "true" {
					Skip("Skipping Wireguard unsupported tests.")
				}

				// Setup a single node cluster.
				const nodeCount = 1

				infra = getInfra()
				felixes, _ = infrastructure.StartNNodeTopology(nodeCount, wireguardTopologyOptions("CalicoIPAM", true, wireguardEnabledV4, wireguardEnabledV6), infra)

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
				Eventually(func() string {
					out, err := felixes[0].ExecOutput("ip", "link", "show", wireguardInterfaceNameV6Default)
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
	}
})

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ WireGuard-Supported 3 node cluster", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const nodeCount = 3

	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  clientv3.Interface

		wls      [nodeCount]*workload.Workload // simulated host workloads
		cc       *connectivity.Checker
		tcpdumps []*tcpdump.TCPDump
	)

	BeforeEach(func() {
		//TODO: add IPv6 coverage when enabling this back
		Skip("Skipping WireGuard tests for now due to unreliability.")

		// Run these tests only when the Host has Wireguard kernel module available.
		if os.Getenv("FELIX_FV_WIREGUARD_AVAILABLE") != "true" {
			Skip("Skipping Wireguard supported tests.")
		}

		infra = getInfra()
		topologyOptions := wireguardTopologyOptions("CalicoIPAM", true, true, false)
		felixes, client = infrastructure.StartNNodeTopology(nodeCount, topologyOptions, infra)

		// To allow all ingress and egress, in absence of any Policy.
		infra.AddDefaultAllow()

		for i := range wls {
			wls[i] = createWorkloadWithAssignedIP(
				&infra,
				&topologyOptions,
				&client,
				fmt.Sprintf("10.65.%d.2", i),
				fmt.Sprintf("wl%d", i),
				felixes[i])
		}

		// Create 'borrowed' workloads e.g. create workload on felix-0 with IP
		// borrowed from IPAM block from felix-1.
		_ = createWorkloadWithAssignedIP(
			&infra,
			&topologyOptions,
			&client,
			"10.65.0.4",
			"borrowed-0",
			felixes[1])
		_ = createWorkloadWithAssignedIP(
			&infra,
			&topologyOptions,
			&client,
			"10.65.1.4",
			"borrowed-1",
			felixes[0])

		for i := range felixes {
			felixes[i].TriggerDelayedStart()
		}

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

	It("Workload with borrowed IP should be 'handled' on felix 0 and 1", func() {
		// Check that felix-0, felix-1 is ready
		// 1. by checking, Wireguard interface exist.
		Eventually(func() error {
			for i := range []int{0, 1} {
				out, err := felixes[i].ExecOutput("ip", "link")
				if err != nil {
					return err
				}
				if strings.Contains(out, wireguardInterfaceNameDefault) {
					continue
				}
				return fmt.Errorf("felix-%d has no wireguard device", i)
			}
			return nil
		}, "10s", "100ms").ShouldNot(HaveOccurred())
		// 2. by checking, Wireguard rule exist.
		for i := range []int{0, 1} {
			Eventually(func() string {
				return getWireguardRoutingRule(felixes[i], 4)
			}, "10s", "100ms").Should(MatchRegexp(fmt.Sprintf("\\d+:\\s+not from all fwmark 0x\\d+/0x\\d+ lookup \\d+")))
		}
		// 3. by checking, Wireguard route table exist.
		for i := range []int{0, 1} {
			Eventually(func() string {
				return getWireguardRouteEntry(felixes[i], 4)
			}, "10s", "100ms").Should(ContainSubstring(fmt.Sprintf("dev %s scope link", wireguardInterfaceNameDefault)))
		}

		By("verifying WireGuard route table should show 'throw' entry on felix 0 and 1")
		Eventually(func() string {
			return getWireguardRouteEntry(felixes[0], 4)
		}, "10s", "100ms").Should(ContainSubstring("throw 10.65.1.4"))
		Eventually(func() string {
			return getWireguardRouteEntry(felixes[1], 4)
		}, "10s", "100ms").Should(ContainSubstring("throw 10.65.0.4"))
	})

	Context("with Wireguard disabled in node-3", func() {
		BeforeEach(func() {
			// Disable WireGuard on felix-2.
			disableWireguardForFelix(client, "node."+felixes[2].Hostname)

			// Check felix-2 is ready with WireGuard disabled.
			Eventually(func() string {
				out, _ := felixes[2].ExecOutput("ip", "link", "show", wireguardInterfaceNameDefault)
				return out
			}, "10s", "100ms").Should(BeEmpty())

			Eventually(func() string {
				return getWireguardRoutingRule(felixes[2], 4)
			}, "10s", "100ms").Should(BeEmpty())
			Eventually(func() string {
				return getWireguardRouteEntry(felixes[2], 4)
			}, "10s", "100ms").ShouldNot(ContainSubstring(fmt.Sprintf("dev %s scope link", wireguardInterfaceNameDefault)))

			// Check felix-0, felix-1 is ready for tests.
			Eventually(func() error {
				for i := range []int{0, 1} {
					out, err := felixes[i].ExecOutput("ip", "link")
					if err != nil {
						return err
					}
					if strings.Contains(out, wireguardInterfaceNameDefault) {
						continue
					}
					return fmt.Errorf("felix-%d has no Wireguard device", i)
				}
				return nil
			}, "10s", "100ms").ShouldNot(HaveOccurred())
			for i := range []int{0, 1} {
				// Check the rule exists.
				Eventually(func() string {
					return getWireguardRoutingRule(felixes[i], 4)
				}, "10s", "100ms").Should(MatchRegexp(fmt.Sprintf("\\d+:\\s+not from all fwmark 0x\\d+/0x\\d+ lookup \\d+")))
			}
			for i := range []int{0, 1} {
				// Check the route entry exists.
				Eventually(func() string {
					return getWireguardRouteEntry(felixes[i], 4)
				}, "10s", "100ms").Should(ContainSubstring(fmt.Sprintf("dev %s scope link", wireguardInterfaceNameDefault)))
			}

			tcpdumps = nil
			for _, felix := range felixes {
				tcpdump := felix.AttachTCPDump("eth0")

				// tunnel packets.
				tunnelPackets01Pattern := fmt.Sprintf("IP %s\\.51820 > %s\\.51820: UDP", felixes[0].IP, felixes[1].IP)
				tcpdump.AddMatcher("numTunnelPackets01", regexp.MustCompile(tunnelPackets01Pattern))
				tunnelPackets10Pattern := fmt.Sprintf("IP %s\\.51820 > %s\\.51820: UDP", felixes[1].IP, felixes[0].IP)
				tcpdump.AddMatcher("numTunnelPackets10", regexp.MustCompile(tunnelPackets10Pattern))
				tunnelPackets02Pattern := fmt.Sprintf("IP %s\\.51820 > %s\\.51820: UDP", felixes[0].IP, felixes[2].IP)
				tcpdump.AddMatcher("numTunnelPackets02", regexp.MustCompile(tunnelPackets02Pattern))
				tunnelPackets20Pattern := fmt.Sprintf("IP %s\\.51820 > %s\\.51820: UDP", felixes[2].IP, felixes[0].IP)
				tcpdump.AddMatcher("numTunnelPackets20", regexp.MustCompile(tunnelPackets20Pattern))
				// direct workload packets.
				outWorkloadPacketsPattern := fmt.Sprintf("IP %s\\.\\d+ > %s\\.\\d+:", wls[0].IP, wls[2].IP)
				tcpdump.AddMatcher("numOutWorkloadPackets", regexp.MustCompile(outWorkloadPacketsPattern))
				inWorkloadPacketsPattern := fmt.Sprintf("IP %s\\.\\d+ > %s\\.\\d+:", wls[2].IP, wls[0].IP)
				tcpdump.AddMatcher("numInWorkloadPackets", regexp.MustCompile(inWorkloadPacketsPattern))

				tcpdump.Start()
				tcpdumps = append(tcpdumps, tcpdump)
			}
		})

		It("transfer should be encrypted/plain between workloads on WireGuard enabled/disabled nodes", func() {
			cc.ExpectSome(wls[0], wls[1])
			cc.ExpectSome(wls[1], wls[0])
			cc.CheckConnectivity()

			By("verifying packets between felix-0 and felix-1 is encrypted")
			for i := range []int{0, 1} {
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numTunnelPackets01")
				}, "10s", "100ms").Should(BeNumerically(">", 0))
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numTunnelPackets10")
				}, "10s", "100ms").Should(BeNumerically(">", 0))
			}

			cc.ResetExpectations()

			cc.ExpectSome(wls[2], wls[0])
			cc.ExpectSome(wls[0], wls[2])
			cc.CheckConnectivity()

			By("verifying packets between felix-0 and felix-2 are not encrypted")
			for _, f := range []int{0, 2} {
				Eventually(func() int {
					return tcpdumps[f].MatchCount("numInWorkloadPackets")
				}, "10s", "100ms").Should(BeNumerically(">", 0))
				Eventually(func() int {
					return tcpdumps[f].MatchCount("numOutWorkloadPackets")
				}, "10s", "100ms").Should(BeNumerically(">", 0))
			}
		})

		It("WireGuard should be used for host to workload connections on WireGuard enabled nodes", func() {
			cc.ExpectSome(felixes[0], wls[1])
			cc.CheckConnectivity()

			By("verifying packets between felix-0 and felix-1 is encrypted")
			for _, i := range []int{0, 1} {
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numTunnelPackets01")
				}, "10s", "100ms").Should(BeNumerically(">", 0))
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numTunnelPackets10")
				}, "10s", "100ms").Should(BeNumerically(">", 0))
			}
		})

		It("WireGuard should not be used for host to workload connections when WireGuard disabled on either node", func() {
			cc.ExpectSome(felixes[0], wls[2])
			cc.ExpectSome(felixes[2], wls[0])
			cc.CheckConnectivity()

			By("verifying packets between felix-0 and felix-2 are not encrypted")
			for _, i := range []int{0, 2} {
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numTunnelPackets02")
				}, "10s", "100ms").Should(BeNumerically("==", 0))
				Eventually(func() int {
					return tcpdumps[i].MatchCount("numTunnelPackets20")
				}, "10s", "100ms").Should(BeNumerically("==", 0))
			}
		})
	})
})

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ WireGuard-Supported 3-node cluster with WorkloadIPs", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const nodeCount, wlPerNode = 3, 2

	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  clientv3.Interface

		// simulated host workloads
		wlsByHost        [nodeCount][wlPerNode]*workload.Workload
		hostNetworkedWls [nodeCount]*workload.Workload
		externalClient   *containers.Container

		cc       *connectivity.Checker
		tcpdumps []*tcpdump.TCPDump
	)

	BeforeEach(func() {
		//TODO: add IPv6 coverage when enabling this back
		Skip("Skipping WireGuard tests for now due to unreliability.")

		// Run these tests only when the Host has Wireguard kernel module available.
		if os.Getenv("FELIX_FV_WIREGUARD_AVAILABLE") != "true" {
			Skip("Skipping Wireguard supported tests.")
		}

		infra = getInfra()
		topologyOptions := wireguardTopologyOptions("WorkloadIPs", false, true, false)
		felixes, client = infrastructure.StartNNodeTopology(nodeCount, topologyOptions, infra)

		// To allow all ingress and egress, in absence of any Policy.
		infra.AddDefaultAllow()

		// initialise pods
		for felixIdx, felixWls := range wlsByHost {
			for wlIdx := range felixWls {
				wlsByHost[felixIdx][wlIdx] = createWorkloadWithAssignedIP(
					&infra,
					&topologyOptions,
					&client,
					fmt.Sprintf("10.65.%d.%d", felixIdx, 2+wlIdx),
					fmt.Sprintf("wl-f%d-%d", felixIdx, wlIdx),
					felixes[felixIdx])
			}
		}

		// initialise host-networked pods
		for i := range hostNetworkedWls {
			hostNetworkedWls[i] = createHostNetworkedWorkload(fmt.Sprintf("wl-f%d-hn-0", i), felixes[i], 4)
		}

		// initialise external client
		externalClient = infrastructure.RunExtClient("ext-client")
		externalClient.Exec("ip", "route", "add", wlsByHost[0][0].IP, "via", felixes[0].IP)

		for i := range felixes {
			felixes[i].TriggerDelayedStart()
		}

		// Check felix Wireguard links are ready.
		for i := range felixes {
			Eventually(func() string {
				out, _ := felixes[i].ExecOutput("ip", "link", "show", wireguardInterfaceNameDefault)
				return out
			}, "10s", "100ms").Should(Not(BeEmpty()))
		}

		tcpdumps = nil
		for _, felix := range felixes {
			tcpdump := felix.AttachTCPDump("eth0")

			tunnelPacketsFelix0toFelix1Pattern := fmt.Sprintf("IP %s\\.%d > %s\\.%d: UDP", felixes[0].IP, wireguardListeningPortDefault, felixes[1].IP, wireguardListeningPortDefault)
			tcpdump.AddMatcher("numTunnelPacketsFelix0toFelix1", regexp.MustCompile(tunnelPacketsFelix0toFelix1Pattern))
			tunnelPacketsFelix1toFelix0Pattern := fmt.Sprintf("IP %s\\.%d > %s\\.%d: UDP", felixes[1].IP, wireguardListeningPortDefault, felixes[0].IP, wireguardListeningPortDefault)
			tcpdump.AddMatcher("numTunnelPacketsFelix1toFelix0", regexp.MustCompile(tunnelPacketsFelix1toFelix0Pattern))
			nonTunnelPacketsFelix0toFelix1Pattern := fmt.Sprintf("IP %s\\.%s > %s\\.%s: TCP", felixes[0].IP, defaultWorkloadPort, felixes[1].IP, defaultWorkloadPort)
			tcpdump.AddMatcher("numNonTunnelPacketsFelix0toFelix1", regexp.MustCompile(nonTunnelPacketsFelix0toFelix1Pattern))
			nonTunnelPacketsFelix1toFelix0Pattern := fmt.Sprintf("IP %s\\.%s > %s\\.%s: TCP", felixes[1].IP, defaultWorkloadPort, felixes[0].IP, defaultWorkloadPort)
			tcpdump.AddMatcher("numNonTunnelPacketsFelix1toFelix0", regexp.MustCompile(nonTunnelPacketsFelix1toFelix0Pattern))

			tcpdump.Start()
			tcpdumps = append(tcpdumps, tcpdump)
		}

		cc = &connectivity.Checker{}

		// Ping other felix nodes from each node to trigger Wireguard handshakes.
		for i, felix := range felixes {
			for j := range felixes {
				if i != j {
					if err := felix.ExecMayFail("ping", "-c", "1", "-W", "1", "-s", "1", felixes[j].IP); err != nil {
						log.WithError(err).Warning("felix.ExecMayFail returned err")
					}
				}
			}
		}

		// Check felix nodes have performed Wireguard handshakes.
		for i, felix := range felixes {
			var matchers []types.GomegaMatcher
			for j := range felixes {
				if i != j {
					matchers = append(matchers, BeNumerically(">", 0))
				}
			}
			Eventually(func() []int {
				var handshakes []int
				out, _ := felix.ExecOutput("wg", "show", wireguardInterfaceNameDefault, "latest-handshakes")
				peers := strings.Split(out, "\n")
				for _, peer := range peers {
					parts := strings.Split(peer, "\t")
					if len(parts) == 2 {
						h, _ := strconv.Atoi(parts[1])
						handshakes = append(handshakes, h)
					}
				}
				return handshakes
			}, "30s", "100ms").Should(ContainElements(matchers))
		}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
				felix.Exec("ip", "addr")
				felix.Exec("ip", "rule", "list")
				felix.Exec("ip", "route", "show", "table", "all")
				felix.Exec("ip", "route", "show", "cached")
				felix.Exec("wg")
				felix.Exec("iptables-save", "-c", "-t", "raw")
				felix.Exec("iptables", "-L", "-vx")
				felix.Exec("cat", "/proc/sys/net/ipv4/conf/all/src_valid_mark")
			}
		}

		for felixIdx, felixWls := range wlsByHost {
			for i := range felixWls {
				wlsByHost[felixIdx][i].Stop()
			}
		}

		externalClient.Stop()

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

	It("should pass basic connectivity scenarios", func() {
		By("Checking the interface exists")
		Eventually(func() error {
			for _, felix := range felixes {
				out, err := felix.ExecOutput("ip", "link")
				if err != nil {
					return err
				}
				if strings.Contains(out, wireguardInterfaceNameDefault) {
					continue
				}
				return fmt.Errorf("felix %v has no wireguard device", felix.Name)
			}
			return nil
		}, "10s", "100ms").ShouldNot(HaveOccurred())

		By("Checking the ip rule exists")
		for _, felix := range felixes {
			Eventually(func() string {
				return getWireguardRoutingRule(felix, 4)
			}, "10s", "100ms").Should(MatchRegexp(fmt.Sprintf("\\d+:\\s+not from all fwmark 0x\\d+/0x\\d+ lookup \\d+")))
		}

		By("Checking the routing table entries exist")
		for i := range wlsByHost {
			var matchers []types.GomegaMatcher
			for j, wls := range wlsByHost {
				if i != j {
					// check for routes to other felix nodes
					matchers = append(matchers, ContainSubstring(
						fmt.Sprintf("%s dev %s scope link", felixes[j].IP, wireguardInterfaceNameDefault)))
					// check for routes to pods on other felix nodes
					for _, wl := range wls {
						matchers = append(matchers, ContainSubstring(
							fmt.Sprintf("%s dev %s scope link", wl.IP, wireguardInterfaceNameDefault)))
					}
				}
			}
			Eventually(func() []string {
				return strings.Split(getWireguardRouteEntry(felixes[i], 4), "\n")
			}, "10s", "100ms").Should(ContainElements(matchers))
		}

		By("Checking the iptables raw chain cali-wireguard-incoming-mark exists")
		for _, felix := range felixes {
			Eventually(func() string {
				s, _ := felix.ExecCombinedOutput("iptables", "-L", "cali-wireguard-incoming-mark", "-t", "raw")
				return s
			}, "10s", "100ms").Should(ContainSubstring("Chain cali-wireguard-incoming-mark"))
		}

		By("Checking the proc/sys src valid mark entries")
		for _, felix := range felixes {
			Eventually(func() string {
				s, _ := felix.ExecCombinedOutput("cat", "/proc/sys/net/ipv4/conf/all/src_valid_mark")
				return s
			}, "10s", "100ms").Should(ContainSubstring("1"))
		}

		By("Checking wireguard allowed ips")
		for i := range wlsByHost {
			var matchers []types.GomegaMatcher
			for j, wls := range wlsByHost {
				if i != j {
					var allowedIPMatchers []types.GomegaMatcher
					// check for allowed IP entry for other felix nodes
					allowedIPMatchers = append(allowedIPMatchers, ContainSubstring(felixes[j].IP))
					// check for routes to pods on other felix nodes
					for _, wl := range wls {
						allowedIPMatchers = append(allowedIPMatchers, ContainSubstring(wl.IP))
					}
					matchers = append(matchers, And(allowedIPMatchers...))
				}
			}
			Eventually(func() []string {
				s, _ := felixes[i].ExecCombinedOutput("wg", "show", wireguardInterfaceNameDefault, "allowed-ips")
				return strings.Split(s, "\n")
			}, "10s", "100ms").Should(ContainElements(matchers))
		}

		By("verifying packets between felix-0 and felix-1 is encrypted")
		cc.ExpectSome(wlsByHost[0][1], wlsByHost[1][0])
		cc.ExpectSome(wlsByHost[1][0], wlsByHost[0][1])
		cc.CheckConnectivity()

		for i := range []int{0, 1} {
			numNonTunnelPacketsFelix0toFelix1Before := tcpdumps[i].MatchCount("numNonTunnelPacketsFelix0toFelix1")
			numNonTunnelPacketsFelix1toFelix0Before := tcpdumps[i].MatchCount("numNonTunnelPacketsFelix1toFelix0")
			Eventually(tcpdumps[i].MatchCountFn("numTunnelPacketsFelix0toFelix1"), "10s", "100ms").
				Should(BeNumerically(">", 0))
			Eventually(tcpdumps[i].MatchCountFn("numTunnelPacketsFelix1toFelix0"), "10s", "100ms").
				Should(BeNumerically(">", 0))

			Expect(tcpdumps[i].MatchCount("numNonTunnelPacketsFelix0toFelix1")).
				Should(BeNumerically("==", numNonTunnelPacketsFelix0toFelix1Before))
			Expect(tcpdumps[i].MatchCount("numNonTunnelPacketsFelix1toFelix0")).
				Should(BeNumerically("==", numNonTunnelPacketsFelix1toFelix0Before))
		}

		cc.ResetExpectations()

		By("checking same node pod-to-pod connectivity")
		for felixIdx := 0; felixIdx < nodeCount; felixIdx++ {
			cc.ExpectSome(wlsByHost[felixIdx][0], wlsByHost[felixIdx][1])
		}

		By("checking different node pod-to-pod connectivity")
		for i := range wlsByHost {
			for j := range wlsByHost {
				cc.ExpectSome(wlsByHost[i][0], wlsByHost[j][0])
			}
		}

		By("checking host-networked pod to regular pod connectivity")
		for _, wl := range hostNetworkedWls {
			for j := range wlsByHost {
				cc.ExpectSome(wl, wlsByHost[j][0])
			}
		}

		By("checking external node to pod connectivity")
		cc.ExpectSome(externalClient, wlsByHost[0][0])

		By("checking prometheus metrics render")
		for _, felix := range felixes {
			s, err := felix.ExecCombinedOutput("wget", "localhost:9091/metrics", "-O", "-")
			Expect(err).ToNot(HaveOccurred())
			// quick and dirty comparison to see if metrics we want exist and with correct type
			for _, expectedMetric := range []string{
				"# TYPE wireguard_meta gauge",
				"# TYPE wireguard_latest_handshake_seconds gauge",
				"# TYPE wireguard_bytes_rcvd counter",
				"# TYPE wireguard_bytes_sent counter",
			} {
				Expect(s).To(ContainSubstring(expectedMetric))
			}
		}

		cc.CheckConnectivity()
	})
})

// Setup cluster topology options.
// mainly, enable Wireguard with delayed start option.
func wireguardTopologyOptions(routeSource string, ipipEnabled, wireguardIPv4Enabled, wireguardIPv6Enabled bool, extraEnvs ...map[string]string) infrastructure.TopologyOptions {
	topologyOptions := infrastructure.DefaultTopologyOptions()

	// Waiting for calico-node to be ready.
	topologyOptions.DelayFelixStart = true
	// Enable IPv6 if IPv6 Wireguard will be enabled.
	topologyOptions.EnableIPv6 = wireguardIPv6Enabled
	// Assigning workload IPs using IPAM API.
	topologyOptions.IPIPRoutesEnabled = false
	// Indicate wireguard is enabled
	topologyOptions.WireguardEnabled = wireguardIPv4Enabled
	topologyOptions.WireguardEnabledV6 = wireguardIPv6Enabled
	// RouteSource
	if routeSource == "WorkloadIPs" {
		topologyOptions.UseIPPools = false
	}
	topologyOptions.ExtraEnvVars["FELIX_ROUTESOURCE"] = routeSource
	topologyOptions.ExtraEnvVars["FELIX_PROMETHEUSMETRICSENABLED"] = "true"
	topologyOptions.IPIPEnabled = ipipEnabled

	// With Wireguard and BPF mode the default IptablesMarkMask of 0xffff0000 isn't enough.
	topologyOptions.ExtraEnvVars["FELIX_IPTABLESMARKMASK"] = "4294934528" // 0xffff8000

	for _, envs := range extraEnvs {
		for k, v := range envs {
			topologyOptions.ExtraEnvVars[k] = v
		}
	}

	// Enable Wireguard.
	felixConfig := api.NewFelixConfiguration()
	felixConfig.SetName("default")
	enabled := true
	if wireguardIPv4Enabled {
		felixConfig.Spec.WireguardEnabled = &enabled
	}
	if wireguardIPv6Enabled {
		felixConfig.Spec.WireguardEnabledV6 = &enabled
	}
	topologyOptions.InitialFelixConfiguration = felixConfig

	return topologyOptions
}

func disableWireguard(client clientv3.Interface) {
	updateWireguardEnabledConfig(client, false, false)
}

func updateWireguardEnabledConfig(client clientv3.Interface, valueV4, valueV6 bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	felixConfig, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	felixConfig.Spec.WireguardEnabled = &valueV4
	felixConfig.Spec.WireguardEnabledV6 = &valueV6
	felixConfig, err = client.FelixConfigurations().Update(ctx, felixConfig, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func getWireguardRoutingRule(felix *infrastructure.Felix, ipVersion int) string {
	Expect(ipVersion == 4 || ipVersion == 6).To(BeTrue())
	var rule string
	var err error
	switch ipVersion {
	case 4:
		rule, err = felix.ExecOutput("ip", "rule", "show", "pref", wireguardRoutingRulePriorityDefault)
	case 6:
		rule, err = felix.ExecOutput("ip", "-6", "rule", "show", "pref", wireguardRoutingRulePriorityDefault)
	}
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSpace(rule)
}

func getWireguardRouteEntry(felix *infrastructure.Felix, ipVersion int) string {
	Expect(ipVersion == 4 || ipVersion == 6).To(BeTrue())

	rule := getWireguardRoutingRule(felix, ipVersion)

	// Get route table index from rule.
	routingRuleRegExp := regexp.MustCompile(`\d+$`)
	tableId := routingRuleRegExp.FindString(rule)
	if tableId == "" {
		return ""
	}

	// Check route table entry.
	var routes string
	var err error
	switch ipVersion {
	case 4:
		routes, err = felix.ExecOutput("ip", "route", "show", "table", tableId)
	case 6:
		routes, err = felix.ExecOutput("ip", "-6", "route", "show", "table", tableId)
	}
	Expect(err).NotTo(HaveOccurred())

	return routes
}

func disableWireguardForFelix(client clientv3.Interface, felixName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	felixConfig := api.NewFelixConfiguration()
	felixConfig.SetName(felixName)
	disabled := false
	felixConfig.Spec.WireguardEnabled = &disabled
	felixConfig.Spec.WireguardEnabledV6 = &disabled
	felixConfig, err := client.FelixConfigurations().Create(ctx, felixConfig, options.SetOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func createWorkloadWithAssignedIP(
	infra *infrastructure.DatastoreInfra,
	infraOpts *infrastructure.TopologyOptions,
	client *clientv3.Interface,
	wlIP, wlName string,
	felix *infrastructure.Felix) *workload.Workload {

	ip := net.MustParseIP(wlIP)
	mtu := wireguardMTUDefault
	if ip.To4() == nil {
		mtu = wireguardMTUV6Default
	}

	wl := workload.RunWithMTU(felix, wlName, "default", wlIP, defaultWorkloadPort, "tcp", mtu)
	wl.ConfigureInInfra(*infra)

	if infraOpts.UseIPPools {
		err := (*client).IPAM().AssignIP(utils.Ctx, ipam.AssignIPArgs{
			IP:       ip,
			HandleID: &wlName,
			Attrs: map[string]string{
				ipam.AttributeNode: felix.Hostname,
			},
			Hostname: felix.Hostname,
		})
		Expect(err).NotTo(HaveOccurred())
	}

	return wl
}

func createHostNetworkedWorkload(wlName string, felix *infrastructure.Felix, ipVersion int) *workload.Workload {
	Expect(ipVersion == 4 || ipVersion == 6).To(BeTrue())
	ip := felix.IP
	mtu := wireguardMTUDefault
	if ipVersion == 6 {
		ip = felix.IPv6
		mtu = wireguardMTUV6Default
	}
	return workload.RunWithMTU(felix, wlName, "default", ip, defaultWorkloadPort, "tcp", mtu)
}
