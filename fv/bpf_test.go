// +build fvtests

// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/projectcalico/libcalico-go/lib/ipam"

	"github.com/projectcalico/felix/bpf/nat"

	"github.com/projectcalico/felix/bpf/conntrack"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

var testProtocols = []string{"udp", "tcp"}
var testTunnels = []string{"none", "ipip"}

func init() {
	for _, connTimeEnabled := range []bool{true, false} {
		for _, protocol := range testProtocols {
			for _, tunnel := range testTunnels {
				describeBPFTests(bpfTestOptions{
					connTimeEnabled: connTimeEnabled,
					protocol:        protocol,
					tunnel:          tunnel,
				})
			}
		}
	}
}

type bpfTestOptions struct {
	connTimeEnabled bool
	protocol        string
	tunnel          string
}

const expectedRouteDump = `10.65.0.2/32: local workload
10.65.0.3/32: local workload
10.65.1.0/26: remote workload, host IP FELIX_1
10.65.2.0/26: remote workload, host IP FELIX_2
FELIX_0/32: local host
FELIX_1/32: remote host
FELIX_2/32: remote host`

const expectedRouteDumpIPIP = `10.65.0.1/32: local host
10.65.0.2/32: local workload
10.65.0.3/32: local workload
10.65.1.0/26: remote workload, host IP FELIX_1
10.65.2.0/26: remote workload, host IP FELIX_2
FELIX_0/32: local host
FELIX_1/32: remote host
FELIX_2/32: remote host`

func describeBPFTests(testOpts bpfTestOptions) bool {
	desc := fmt.Sprintf("_BPF_ _BPF-SAFE_ BPF tests (%s, ct=%v, tunnel=%s)",
		testOpts.protocol, testOpts.connTimeEnabled, testOpts.tunnel)
	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

		var (
			infra          infrastructure.DatastoreInfra
			felixes        []*infrastructure.Felix
			calicoClient   client.Interface
			cc             *workload.ConnectivityChecker
			externalClient *containers.Container
			bpfLog         *containers.Container
			options        infrastructure.TopologyOptions
			numericProto   uint8
			expectedRoutes string
		)

		switch testOpts.protocol {
		case "tcp":
			numericProto = 6
		case "udp":
			numericProto = 17
		default:
			Fail("bad protocol option")
		}

		BeforeEach(func() {
			if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
				Skip("Skipping BPF test in non-BPF run.")
			}
			bpfLog = containers.Run("bpf-log", containers.RunOpts{AutoRemove: true}, "--privileged", "calico/bpftool:v5.3-amd64", "/bpftool", "prog", "tracelog")
			infra = getInfra()

			cc = &workload.ConnectivityChecker{}
			cc.Protocol = testOpts.protocol

			options = infrastructure.DefaultTopologyOptions()
			options.FelixLogSeverity = "debug"
			switch testOpts.tunnel {
			case "none":
				options.IPIPEnabled = false
				options.IPIPRoutesEnabled = false
				expectedRoutes = expectedRouteDump
			case "ipip":
				options.IPIPEnabled = true
				options.IPIPRoutesEnabled = true
				expectedRoutes = expectedRouteDumpIPIP
			default:
				Fail("bad tunnel option")
			}
			options.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancingEnabled"] = fmt.Sprint(testOpts.connTimeEnabled)
		})

		JustAfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				currBpfsvcs, currBpfeps := dumpNATmaps(felixes)

				for i, felix := range felixes {
					felix.Exec("iptables-save", "-c")
					felix.Exec("ip", "r")
					felix.Exec("calico-bpf", "ipsets", "dump")
					felix.Exec("calico-bpf", "routes", "dump")
					felix.Exec("calico-bpf", "nat", "dump")
					felix.Exec("calico-bpf", "conntrack", "dump")
					log.Infof("[%d]FrontendMap: %+v", i, currBpfsvcs[i])
					log.Infof("[%d]NATBackend: %+v", i, currBpfeps[i])
				}
			}
		})

		AfterEach(func() {
			log.Info("AfterEach starting")
			for _, f := range felixes {
				f.Exec("calico-bpf", "connect-time", "clean")
				f.Stop()
			}
			infra.Stop()
			externalClient.Stop()
			bpfLog.Stop()
			log.Info("AfterEach done")
		})

		createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Creating policy")
			policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}

		updatePolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Updating policy")
			policy, err := calicoClient.GlobalNetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}
		_ = updatePolicy

		Describe("with a single node and an allow-all policy", func() {
			var (
				hostW *workload.Workload
				w     [2]*workload.Workload
			)

			if !testOpts.connTimeEnabled {
				// These tests don't depend on NAT.
				return
			}

			JustBeforeEach(func() {
				felixes, calicoClient = infrastructure.StartNNodeTopology(1, options, infra)

				hostW = workload.Run(
					felixes[0],
					"host",
					"default",
					felixes[0].IP, // Same IP as felix means "run in the host's namespace"
					"8055",
					testOpts.protocol)

				// Start a couple of workloads so we can check workload-to-workload and workload-to-host.
				for i := 0; i < 2; i++ {
					wIP := fmt.Sprintf("10.65.0.%d", i+2)
					w[i] = workload.Run(felixes[0], fmt.Sprintf("w%d", i), "default", wIP, "8055", testOpts.protocol)
					w[i].WorkloadEndpoint.Labels = map[string]string{"name": w[i].Name}
					w[i].ConfigureInDatastore(infra)
				}

				err := infra.AddDefaultDeny()
				Expect(err).NotTo(HaveOccurred())

				pol := api.NewGlobalNetworkPolicy()
				pol.Namespace = "fv"
				pol.Name = "policy-1"
				pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
				pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
				pol.Spec.Selector = "all()"

				pol = createPolicy(pol)
			})

			Describe("with DefaultEndpointToHostAction=DROP", func() {
				BeforeEach(func() {
					options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "DROP"
				})
				It("should only allow traffic from workload to workload", func() {
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					cc.ExpectNone(w[1], hostW)
					cc.ExpectSome(hostW, w[0])
					cc.CheckConnectivity()
				})
			})

			getMapIDByPath := func(felix *infrastructure.Felix, filename string) (int, error) {
				out, err := felix.ExecOutput("bpftool", "map", "show", "pinned", filename, "-j")
				if err != nil {
					return 0, err
				}
				var mapMeta struct {
					ID    int    `json:"id"`
					Error string `json:"error"`
				}
				err = json.Unmarshal([]byte(out), &mapMeta)
				if err != nil {
					return 0, err
				}
				if mapMeta.Error != "" {
					return 0, errors.New(mapMeta.Error)
				}
				return mapMeta.ID, nil
			}

			mustGetMapIDByPath := func(felix *infrastructure.Felix, filename string) int {
				var mapID int
				Eventually(func() error {
					var err error
					mapID, err = getMapIDByPath(felix, filename)
					return err
				}, "5s").ShouldNot(HaveOccurred())
				return mapID
			}

			Describe("with DefaultEndpointToHostAction=ACCEPT", func() {
				BeforeEach(func() {
					options.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "ACCEPT"
				})
				It("should traffic from workload to workload and to/from host", func() {
					cc.ExpectSome(w[0], w[1])
					cc.ExpectSome(w[1], w[0])
					cc.ExpectSome(w[1], hostW)
					cc.ExpectSome(hostW, w[0])
					cc.CheckConnectivity()
				})
			})

			if testOpts.protocol != "udp" { // No need to run these tests per-protocol.
				Describe("with map repinning enabled", func() {
					BeforeEach(func() {
						options.ExtraEnvVars["FELIX_BPFMapRepinEnabled"] = "true"
					})

					It("should repin maps", func() {
						// Wait for the first felix to create its maps.
						mapID := mustGetMapIDByPath(felixes[0], "/sys/fs/bpf/tc/globals/cali_v4_ct")

						// Now, start a completely independent felix, which will get its own bpffs.  It should re-pin the
						// maps, picking up the ones from the first felix.
						extraFelix, _ := infrastructure.StartSingleNodeTopology(options, infra)
						defer extraFelix.Stop()

						secondMapID := mustGetMapIDByPath(extraFelix, "/sys/fs/bpf/tc/globals/cali_v4_ct")
						Expect(mapID).NotTo(BeNumerically("==", 0))
						Expect(mapID).To(BeNumerically("==", secondMapID))
					})
				})

				Describe("with map repinning disabled", func() {
					It("should repin maps", func() {
						// Wait for the first felix to create its maps.
						mapID := mustGetMapIDByPath(felixes[0], "/sys/fs/bpf/tc/globals/cali_v4_ct")

						// Now, start a completely independent felix, which will get its own bpffs.  It should make its own
						// maps.
						extraFelix, _ := infrastructure.StartSingleNodeTopology(options, infra)
						defer extraFelix.Stop()

						secondMapID := mustGetMapIDByPath(extraFelix, "/sys/fs/bpf/tc/globals/cali_v4_ct")
						Expect(mapID).NotTo(BeNumerically("==", 0))
						Expect(mapID).NotTo(BeNumerically("==", secondMapID))
					})
				})
			}
		})

		const numNodes = 3

		Describe(fmt.Sprintf("with a %d node cluster", numNodes), func() {
			var (
				w     [numNodes][2]*workload.Workload // 1st workload on each host
				hostW [numNodes]*workload.Workload
			)

			BeforeEach(func() {
				felixes, calicoClient = infrastructure.StartNNodeTopology(numNodes, options, infra)

				// Start a host networked workload on each host for connectivity checks.
				for ii, felix := range felixes {
					// We tell each host-networked workload to open:
					// TODO: Copied from another test
					// - its normal (uninteresting) port, 8055
					// - port 2379, which is both an inbound and an outbound failsafe port
					// - port 22, which is an inbound failsafe port.
					// This allows us to test the interaction between do-not-track policy and failsafe
					// ports.
					const portsToOpen = "8055,2379,22"
					hostW[ii] = workload.Run(
						felixes[ii],
						fmt.Sprintf("host%d", ii),
						"default",
						felixes[ii].IP, // Same IP as felix means "run in the host's namespace"
						portsToOpen,
						testOpts.protocol)

					// Two workloads on each host so we can check the same host and other host cases.
					iiStr := strconv.Itoa(ii)
					wIP := "10.65." + iiStr + ".2"
					w[ii][0] = workload.Run(felix, "w"+iiStr+"0", "default", wIP, "8055", testOpts.protocol)
					w[ii][0].WorkloadEndpoint.Labels = map[string]string{"name": w[ii][0].Name}
					w[ii][0].ConfigureInDatastore(infra)
					// Assign the workload's IP in IPAM, this will trigger calculation of routes.
					err := calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
						IP:       cnet.MustParseIP(wIP),
						HandleID: &w[ii][0].Name,
						Attrs: map[string]string{
							ipam.AttributeNode: felixes[ii].Hostname,
						},
						Hostname: felixes[ii].Hostname,
					})
					Expect(err).NotTo(HaveOccurred())
					wIP = "10.65." + iiStr + ".3"
					w[ii][1] = workload.Run(felix, "w"+iiStr+"1", "default", wIP, "8056", testOpts.protocol)
					w[ii][1].WorkloadEndpoint.Labels = map[string]string{"name": w[ii][1].Name}
					w[ii][1].ConfigureInDatastore(infra)
					// Assign the workload's IP in IPAM, this will trigger calculation of routes.
					err = calicoClient.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
						IP:       cnet.MustParseIP(wIP),
						HandleID: &w[ii][1].Name,
						Attrs: map[string]string{
							ipam.AttributeNode: felixes[ii].Hostname,
						},
						Hostname: felixes[ii].Hostname,
					})
				}

				// We will use this container to model an external client trying to connect into
				// workloads on a host.  Create a route in the container for the workload CIDR.
				// TODO: Copied from another test
				externalClient = containers.Run("external-client",
					containers.RunOpts{AutoRemove: true},
					"--privileged", // So that we can add routes inside the container.
					utils.Config.BusyboxImage,
					"/bin/sh", "-c", "sleep 1000")
				_ = externalClient

				err := infra.AddDefaultDeny()
				Expect(err).NotTo(HaveOccurred())
			})

			It("should have correct routes", func() {
				dumpRoutes := func() string {
					out, err := felixes[0].ExecOutput("calico-bpf", "routes", "dump")
					if err != nil {
						return fmt.Sprint(err)
					}

					lines := strings.Split(out, "\n")
					var filteredLines []string
					for _, l := range lines {
						l = strings.TrimLeft(l, " ")
						if len(l) == 0 {
							continue
						}
						l = strings.ReplaceAll(l, felixes[0].IP, "FELIX_0")
						l = strings.ReplaceAll(l, felixes[1].IP, "FELIX_1")
						l = strings.ReplaceAll(l, felixes[2].IP, "FELIX_2")
						filteredLines = append(filteredLines, l)
					}
					sort.Strings(filteredLines)
					return strings.Join(filteredLines, "\n")
				}
				Eventually(dumpRoutes).Should(Equal(expectedRoutes))
			})

			It("should only allow traffic from the local host by default", func() {
				// Same host, other workload.
				cc.ExpectNone(w[0][0], w[0][1])
				cc.ExpectNone(w[0][1], w[0][0])
				// Workloads on other host.
				cc.ExpectNone(w[0][0], w[1][0])
				cc.ExpectNone(w[1][0], w[0][0])
				// Hosts.
				cc.ExpectSome(felixes[0], w[0][0])
				cc.ExpectNone(felixes[1], w[0][0])
				cc.CheckConnectivity()
			})

			Context("with a policy allowing ingress to w[0][0] from all workloads", func() {
				var (
					pol       *api.GlobalNetworkPolicy
					k8sClient *kubernetes.Clientset
				)

				BeforeEach(func() {
					pol = api.NewGlobalNetworkPolicy()
					pol.Namespace = "fv"
					pol.Name = "policy-1"
					pol.Spec.Ingress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "all()",
							},
						},
					}
					pol.Spec.Egress = []api.Rule{
						{
							Action: "Allow",
							Source: api.EntityRule{
								Selector: "all()",
							},
						},
					}
					pol.Spec.Selector = "all()"

					pol = createPolicy(pol)

					k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
					_ = k8sClient
				})

				It("connectivity from all workloads via workload 0's main IP", func() {
					cc.ExpectSome(w[0][1], w[0][0])
					cc.ExpectSome(w[1][0], w[0][0])
					cc.ExpectSome(w[1][1], w[0][0])
					cc.CheckConnectivity()
				})

				Context("with test-service configured 10.101.0.10:80 -> w[0][0].IP:8055", func() {
					var (
						testSvc          *v1.Service
						testSvcNamespace string
					)

					testSvcName := "test-service"

					BeforeEach(func() {
						testSvc = k8sService(testSvcName, "10.101.0.10", w[0][0], 80, 8055, 0, testOpts.protocol)
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(testSvc)
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")
					})

					It("should have connectivity from all workloads via a service to workload 0", func() {
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						cc.ExpectSome(w[0][1], workload.IP(ip), port)
						cc.ExpectSome(w[1][0], workload.IP(ip), port)
						cc.ExpectSome(w[1][1], workload.IP(ip), port)
						cc.CheckConnectivity()
					})

					if testOpts.connTimeEnabled {
						It("should only have connectivity from from the local host via a service to workload 0", func() {
							// Local host is always white-listed (for kubelet health checks).
							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							cc.ExpectSome(felixes[0], workload.IP(ip), port)
							cc.ExpectNone(felixes[1], workload.IP(ip), port)
							cc.CheckConnectivity()
						})
					} else {
						It("should not have connectivity from from the local host via a service to workload 0", func() {
							// Local host is always white-listed (for kubelet health checks).
							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							cc.ExpectNone(felixes[0], workload.IP(ip), port)
							cc.ExpectNone(felixes[1], workload.IP(ip), port)
							cc.CheckConnectivity()
						})
					}

					if testOpts.connTimeEnabled {
						Describe("after updating the policy to allow traffic from hosts", func() {
							BeforeEach(func() {
								pol.Spec.Ingress = []api.Rule{
									{
										Action: "Allow",
										Source: api.EntityRule{
											Nets: []string{
												felixes[0].IP + "/32",
												felixes[1].IP + "/32",
											},
										},
									},
								}
								switch testOpts.tunnel {
								case "ipip":
									pol.Spec.Ingress[0].Source.Nets = append(pol.Spec.Ingress[0].Source.Nets,
										felixes[0].ExpectedIPIPTunnelAddr+"/32",
										felixes[1].ExpectedIPIPTunnelAddr+"/32",
									)
								}
								pol = updatePolicy(pol)
							})

							It("should have connectivity from the hosts via a service to workload 0", func() {
								ip := testSvc.Spec.ClusterIP
								port := uint16(testSvc.Spec.Ports[0].Port)

								cc.ExpectSome(felixes[0], workload.IP(ip), port)
								cc.ExpectSome(felixes[1], workload.IP(ip), port)
								cc.ExpectNone(w[0][1], workload.IP(ip), port)
								cc.ExpectNone(w[1][0], workload.IP(ip), port)
								cc.CheckConnectivity()
							})
						})
					}

					It("should create sane conntrack entries and clean them up", func() {
						By("Generating some traffic")
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						cc.ExpectSome(w[0][1], workload.IP(ip), port)
						cc.ExpectSome(w[1][0], workload.IP(ip), port)
						cc.CheckConnectivity()

						By("Checking timestamps on conntrack entries are sane")
						// This test verifies that we correctly interpret conntrack entry timestamps by reading them back
						// and checking that they're (a) in the past and (b) sensibly recent.
						ctDump, err := felixes[0].ExecOutput("calico-bpf", "conntrack", "dump")
						Expect(err).NotTo(HaveOccurred())
						re := regexp.MustCompile(`LastSeen:\s*(\d+)`)
						matches := re.FindAllStringSubmatch(ctDump, -1)
						Expect(matches).ToNot(BeEmpty(), "didn't find any conntrack entries")
						for _, match := range matches {
							lastSeenNanos, err := strconv.ParseInt(match[1], 10, 64)
							Expect(err).NotTo(HaveOccurred())
							nowNanos := conntrack.KTimeNanos()
							age := time.Duration(nowNanos - lastSeenNanos)
							Expect(age).To(BeNumerically(">", 0))
							Expect(age).To(BeNumerically("<", 60*time.Second))
						}

						By("Checking conntrack entries are cleaned up")
						// We have UTs that check that all kinds of entries eventually get cleaned up.  This
						// test is mainly to check that the cleanup code actually runs and is able to actually delete
						// entries.
						numWl0ConntrackEntries := func() int {
							ctDump, err := felixes[0].ExecOutput("calico-bpf", "conntrack", "dump")
							Expect(err).NotTo(HaveOccurred())
							return strings.Count(ctDump, w[0][0].IP)
						}

						startingCTEntries := numWl0ConntrackEntries()
						Expect(startingCTEntries).To(BeNumerically(">", 0))

						// TODO reduce timeouts just for this test.
						Eventually(numWl0ConntrackEntries, "180s", "5s").Should(BeNumerically("<", startingCTEntries))
					})

					Context("with test-service port updated", func() {

						var (
							testSvcUpdated      *v1.Service
							natBackBeforeUpdate []nat.BackendMapMem
							natBeforeUpdate     []nat.MapMem
						)

						BeforeEach(func() {
							natBeforeUpdate, natBackBeforeUpdate = dumpNATmaps(felixes)

							testSvcUpdated = k8sService(testSvcName, "10.101.0.10", w[0][0], 88, 8055, 0, testOpts.protocol)

							svc, err := k8sClient.CoreV1().
								Services(testSvcNamespace).
								Get(testSvcName, metav1.GetOptions{})

							testSvcUpdated.ObjectMeta.ResourceVersion = svc.ObjectMeta.ResourceVersion

							_, err = k8sClient.CoreV1().Services(testSvcNamespace).Update(testSvcUpdated)
							Expect(err).NotTo(HaveOccurred())
							Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
								"Service endpoints didn't get created? Is controller-manager happy?")
						})

						It("should have connectivity from all workloads via the new port", func() {
							ip := testSvcUpdated.Spec.ClusterIP
							port := uint16(testSvcUpdated.Spec.Ports[0].Port)

							cc.ExpectSome(w[0][1], workload.IP(ip), port)
							cc.ExpectSome(w[1][0], workload.IP(ip), port)
							cc.ExpectSome(w[1][1], workload.IP(ip), port)
							cc.CheckConnectivity()
						})

						It("should not have connectivity from all workloads via the old port", func() {
							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							cc.ExpectNone(w[0][1], workload.IP(ip), port)
							cc.ExpectNone(w[1][0], workload.IP(ip), port)
							cc.ExpectNone(w[1][1], workload.IP(ip), port)
							cc.CheckConnectivity()

							natmaps, natbacks := dumpNATmaps(felixes)
							ipv4 := net.ParseIP(ip)
							portNew := uint16(testSvcUpdated.Spec.Ports[0].Port)
							portOld := uint16(testSvc.Spec.Ports[0].Port)
							natK := nat.NewNATKey(ipv4, portNew, numericProto)
							oldK := nat.NewNATKey(ipv4, portOld, numericProto)

							for i := range felixes {

								Expect(natmaps[i]).To(HaveKey(natK))
								Expect(natmaps[i]).NotTo(HaveKey(nat.NewNATKey(ipv4, portOld, numericProto)))

								Expect(natBeforeUpdate[i]).To(HaveKey(oldK))
								oldV := natBeforeUpdate[i][oldK]

								natV := natmaps[i][natK]
								bckCnt := natV.Count()
								bckID := natV.ID()

								for ord := uint32(0); ord < bckCnt; ord++ {
									bckK := nat.NewNATBackendKey(bckID, ord)
									oldBckK := nat.NewNATBackendKey(oldV.ID(), ord)
									Expect(natbacks[i]).To(HaveKey(bckK))
									Expect(natBackBeforeUpdate[i]).To(HaveKey(oldBckK))
									Expect(natBackBeforeUpdate[i][oldBckK]).To(Equal(natbacks[i][bckK]))
								}

							}
						})

						Context("with test-service removed", func() {
							var (
								prevBpfsvcs []nat.MapMem
							)

							BeforeEach(func() {
								prevBpfsvcs, _ = dumpNATmaps(felixes)
								err := k8sClient.CoreV1().
									Services(testSvcNamespace).
									Delete(testSvcName, &metav1.DeleteOptions{})
								Expect(err).NotTo(HaveOccurred())
								Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(0))
							})

							It("should not have connectivity from workloads via a service to workload 0", func() {
								ip := testSvcUpdated.Spec.ClusterIP
								port := uint16(testSvcUpdated.Spec.Ports[0].Port)

								cc.ExpectNone(w[0][1], workload.IP(ip), port)
								cc.ExpectNone(w[1][0], workload.IP(ip), port)
								cc.ExpectNone(w[1][1], workload.IP(ip), port)
								cc.CheckConnectivity()

								for i, f := range felixes {
									natK := nat.NewNATKey(net.ParseIP(ip), port, numericProto)
									Expect(prevBpfsvcs[i]).To(HaveKey(natK))
									natV := prevBpfsvcs[i][natK]
									bckCnt := natV.Count()
									bckID := natV.ID()

									Eventually(func() bool {
										svcs := dumpNATMap(f)
										eps := dumpEPMap(f)

										if _, ok := svcs[natK]; ok {
											return false
										}

										for ord := uint32(0); ord < bckCnt; ord++ {
											bckK := nat.NewNATBackendKey(bckID, ord)
											if _, ok := eps[bckK]; ok {
												return false
											}
										}

										return true
									}).
										Should(BeTrue())
								}
							})
						})
					})
				})

				npPort := uint16(30333)

				Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort)), func() {
					var (
						testSvc          *v1.Service
						testSvcNamespace string
					)

					testSvcName := "test-service"

					BeforeEach(func() {
						k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
						testSvc = k8sService(testSvcName, "10.101.0.10",
							w[0][0], 80, 8055, int32(npPort), testOpts.protocol)
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(testSvc)
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")
					})

					It("should have connectivity from all workloads via a service to workload 0", func() {
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						cc.ExpectSome(w[0][1], workload.IP(ip), port)
						cc.ExpectSome(w[1][0], workload.IP(ip), port)
						cc.ExpectSome(w[1][1], workload.IP(ip), port)
						cc.CheckConnectivity()

					})

					It("should have connectivity from all workloads via a nodeport to workload 0", func() {
						ip := felixes[1].IP

						cc.ExpectSome(w[0][1], workload.IP(ip), npPort)
						cc.ExpectSome(w[1][0], workload.IP(ip), npPort)
						cc.ExpectSome(w[1][1], workload.IP(ip), npPort)
						cc.CheckConnectivity()

					})

					It("should have connectivity from a workload via a nodeport on another node to workload 0", func() {
						ip := felixes[1].IP

						cc.ExpectSome(w[2][1], workload.IP(ip), npPort)
						cc.CheckConnectivity()

					})

					Describe("after updating the policy to allow traffic from externalClient", func() {
						BeforeEach(func() {
							pol.Spec.Ingress = []api.Rule{
								{
									Action: "Allow",
									Source: api.EntityRule{
										Nets: []string{
											externalClient.IP + "/32",
										},
									},
								},
							}
							pol = updatePolicy(pol)
						})

						It("should have connectivity from external to w[0] via node1->node0 fwd", func() {
							if testOpts.connTimeEnabled {
								Skip("FIXME externalClient also does conntime balancing")
							}

							log.WithFields(log.Fields{
								"externalClientIP": externalClient.IP,
								"nodePortIP":       felixes[1].IP,
							}).Infof("external->nodeport connection")

							cc.ExpectSome(externalClient, workload.IP(felixes[1].IP), npPort)
							cc.CheckConnectivity()
						})

						It("should have connectivity from external to w[0] via node0", func() {
							if testOpts.connTimeEnabled {
								Skip("FIXME externalClient also does conntime balancing")
							}

							log.WithFields(log.Fields{
								"externalClientIP": externalClient.IP,
								"nodePortIP":       felixes[1].IP,
							}).Infof("external->nodeport connection")

							cc.ExpectSome(externalClient, workload.IP(felixes[0].IP), npPort)
							cc.CheckConnectivity()
						})
					})
				})
			})
		})
	})
}

func typeMetaV1(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{
		Kind:       kind,
		APIVersion: "v1",
	}
}

func objectMetaV1(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: "default",
	}
}

func dumpNATmaps(felixes []*infrastructure.Felix) ([]nat.MapMem, []nat.BackendMapMem) {
	bpfsvcs := make([]nat.MapMem, len(felixes))
	bpfeps := make([]nat.BackendMapMem, len(felixes))

	for i, felix := range felixes {
		bpfsvcs[i], bpfeps[i] = dumpNATMaps(felix)
	}

	return bpfsvcs, bpfeps
}

func dumpNATMaps(felix *infrastructure.Felix) (nat.MapMem, nat.BackendMapMem) {
	return dumpNATMap(felix), dumpEPMap(felix)
}

func dumpNATMap(felix *infrastructure.Felix) nat.MapMem {
	bm := nat.FrontendMap(&bpf.MapContext{})
	cmd, err := bpf.DumpMapCmd(bm)
	Expect(err).NotTo(HaveOccurred())
	bpfsvcs := make(nat.MapMem)
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred())
	err = bpf.IterMapCmdOutput([]byte(out), nat.MapMemIter(bpfsvcs))
	Expect(err).NotTo(HaveOccurred())
	return bpfsvcs
}

func dumpEPMap(felix *infrastructure.Felix) nat.BackendMapMem {
	bb := nat.BackendMap(&bpf.MapContext{})
	cmd, err := bpf.DumpMapCmd(bb)
	Expect(err).NotTo(HaveOccurred())
	bpfeps := make(nat.BackendMapMem)
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred())
	err = bpf.IterMapCmdOutput([]byte(out), nat.BackendMapMemIter(bpfeps))
	Expect(err).NotTo(HaveOccurred())
	return bpfeps
}

func k8sService(name, clusterIP string, w *workload.Workload, port,
	tgtPort int, nodePort int32, protocol string) *v1.Service {
	k8sProto := v1.ProtocolTCP
	if protocol == "udp" {
		k8sProto = v1.ProtocolUDP
	}

	svcType := v1.ServiceTypeClusterIP
	if nodePort != 0 {
		svcType = v1.ServiceTypeNodePort
	}

	return &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1(name),
		Spec: v1.ServiceSpec{
			ClusterIP: clusterIP,
			Type:      svcType,
			Selector: map[string]string{
				"name": w.Name,
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   k8sProto,
					Port:       int32(port),
					NodePort:   nodePort,
					Name:       fmt.Sprintf("port-%d", tgtPort),
					TargetPort: intstr.FromInt(tgtPort),
				},
			},
		},
	}
}

func k8sGetEpsForService(k8s kubernetes.Interface, svc *v1.Service) []v1.EndpointSubset {
	ep, _ := k8s.CoreV1().
		Endpoints(svc.ObjectMeta.Namespace).
		Get(svc.ObjectMeta.Name, metav1.GetOptions{})
	log.WithField("endpoints",
		spew.Sprint(ep)).Infof("Got endpoints for %s", svc.ObjectMeta.Name)
	return ep.Subsets
}

func k8sGetEpsForServiceFunc(k8s kubernetes.Interface, svc *v1.Service) func() []v1.EndpointSubset {
	return func() []v1.EndpointSubset {
		return k8sGetEpsForService(k8s, svc)
	}
}
