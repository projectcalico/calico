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

//go:build fvtests

package fv_test

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/tcpdump"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var (
	dataStoreTypes = []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}
)

type wireguard3NodeTestConf struct {
	routeSource                    string
	ipipEnabled                    bool
	borrowedIPs                    bool
	hostEncryptionEnabled          bool
	skipWireguardHostConnBootstrap bool
}

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ WireGuard-Supported three-node cluster", dataStoreTypes, func(getInfra infrastructure.InfraFactory) {
	for _, scenario := range []wireguard3NodeTestConf{
		{
			routeSource: "CalicoIPAM", ipipEnabled: false, borrowedIPs: true,
			hostEncryptionEnabled: true,
		},
		{
			routeSource: "WorkloadIPs", ipipEnabled: false, borrowedIPs: false,
			hostEncryptionEnabled: true,
		},
		{
			routeSource: "CalicoIPAM", ipipEnabled: false, borrowedIPs: true,
			hostEncryptionEnabled:          true,
			skipWireguardHostConnBootstrap: true,
		},
		{
			routeSource: "WorkloadIPs", ipipEnabled: false, borrowedIPs: false,
			hostEncryptionEnabled:          true,
			skipWireguardHostConnBootstrap: true,
		},
	} {
		Describe(
			fmt.Sprintf("WG TEST RouteSource: %v, BorrowedIPs: %v", scenario.routeSource, scenario.borrowedIPs),
			runWireguard3NodeTests(getInfra, scenario),
		)
	}
})

func runWireguard3NodeTests(getInfra infrastructure.InfraFactory, scene wireguard3NodeTestConf) func() {
	return func() {
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

			topologyOptions infrastructure.TopologyOptions

			pks [nodeCount]string
		)

		BeforeEach(func() {
			// Run these tests only when the Host has Wireguard kernel module available.
			if os.Getenv("FELIX_FV_WIREGUARD_AVAILABLE") != "true" {
				Skip("Skipping Wireguard supported tests.")
			}

			infra = getInfra()
			envs := map[string]string{}
			if scene.skipWireguardHostConnBootstrap { // discc.Checable fix for negative test
				envs["FELIX_SKIP_WIREGUARD_BOOTSTRAP"] = "true"
			}

			topologyOptions = wireguardTopologyOptions(
				scene.routeSource, scene.ipipEnabled, scene.hostEncryptionEnabled, envs,
			)
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
						felixes[felixIdx],
					)
				}
			}

			// initialise host-networked pods
			for i := range hostNetworkedWls {
				hostNetworkedWls[i] = createHostNetworkedWorkload(fmt.Sprintf("wl-f%d-hn-0", i), felixes[i])
			}

			// initialise external client
			externalClient = containers.Run("external-client",
				containers.RunOpts{AutoRemove: true},
				"--privileged", // So that we can add routes inside the container.
				utils.Config.BusyboxImage,
				"/bin/sh", "-c", "sleep 1000")
			externalClient.EnsureBinary("test-connection")
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

			// for felixIdx, felixWls := range wlsByHost {
			// 	for i := range felixWls {
			// 		wlsByHost[felixIdx][i].Stop()
			// 	}
			// }

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

		Context(
			fmt.Sprintf(
				"with HostEncryption, 2 workloads per node with bootstrap fix %s",
				func(nofix bool) string {
					if nofix {
						return "disabled"
					}
					return "enabled"
				}(scene.skipWireguardHostConnBootstrap),
			),

			func() {
				It("should have basic connectivity", func() {
					By("verifying packets between felix-0 and felix-1 is encrypted")
					cc.ExpectSome(wlsByHost[0][1], wlsByHost[1][0])
					cc.ExpectSome(wlsByHost[1][0], wlsByHost[0][1])
					cc.CheckConnectivity()
				})

				It("Dataplanes should have have a public key", func() {
					pk, err := getWgPublicKey(felixes[1])
					Expect(err).ShouldNot(HaveOccurred())
					Expect(pk).NotTo(BeEmpty())
					pks[1] = pk
				})

				When("the dataplane is restarted", func() {
					var randomlySelectedNode = 1 // selected by dice roll mod 3
					BeforeEach(func() {
						cc.ResetExpectations()
						opk, err := getWgPublicKey(felixes[1])
						Expect(err).ShouldNot(HaveOccurred())
						Expect(opk).NotTo(BeEmpty())

						// restart dataplane of a randomly-selected felix
						By("restarting the node")
						felixes[randomlySelectedNode].Container.Restart()

						// re-setup its workloads
						for _, wlIdx := range []int{0, 1} {
							wlsByHost[randomlySelectedNode][wlIdx] = createWorkloadWithAssignedIP(
								&infra,
								&topologyOptions,
								&client,
								fmt.Sprintf("10.65.%d.%d", randomlySelectedNode, 4+wlIdx),
								fmt.Sprintf("wl-f%d-%d", randomlySelectedNode, 2+wlIdx),
								felixes[randomlySelectedNode],
							)
						}

						By("checking public key difference")
						Eventually(func() error {
							pk, err := getWgPublicKey(felixes[randomlySelectedNode])
							if err != nil {
								return err
							}
							if pk == opk {
								return errors.New("same public key found")
							}
							return nil
						}, "10s", "200ms").ShouldNot(HaveOccurred(), "assert public key refreshed")
					})

					if scene.skipWireguardHostConnBootstrap {
						It("Should still not have basic connectivity", func() {
							cc.ExpectNone(wlsByHost[0][1], wlsByHost[randomlySelectedNode][0])
							cc.ExpectNone(wlsByHost[randomlySelectedNode][0], wlsByHost[0][1])
							cc.CheckConnectivity()
						})
					} else {
						It("Should still have basic connectivity", func() {
							cc.ExpectSome(wlsByHost[0][1], wlsByHost[randomlySelectedNode][0])
							cc.ExpectSome(wlsByHost[randomlySelectedNode][0], wlsByHost[0][1])
							cc.CheckConnectivity()
						})
					}
				})
			})
		// TODO: move over the rest of the 3-node cluster tests as a context here
	}
}

func getWgPublicKey(felix *infrastructure.Felix) (string, error) {
	pkRegex := regexp.MustCompile(`public key: (.+)\n`)
	out, err := felix.ExecOutput("wg")
	if err != nil {
		return "", fmt.Errorf("getWgPublicKey error: %w", err)
	}
	matches := pkRegex.FindStringSubmatch(out)
	if len(matches) < 1 {
		err := errors.New("getWgPublicKey error: no public key found")
		log.WithError(err).Debug("output: ", out)
		return "", err
	}
	return matches[0], nil
}
