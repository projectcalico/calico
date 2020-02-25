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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	options2 "github.com/projectcalico/libcalico-go/lib/options"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/nat"
	. "github.com/projectcalico/felix/fv/connectivity"
	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
)

// We run with and without connection-time load balancing for a couple of reasons:
// - We can only test the non-connection time NAT logic (and node ports) with it disabled.
// - Since the connection time program applies to the whole host, the different felix nodes actually share the
//   connection-time program.  This is a bit of a broken test but it's better than nothing since all felix nodes
//   should be programming the same NAT mappings.
var _ = describeBPFTests(withProto("tcp"), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withProto("udp"), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withProto("udp"), withConnTimeLoadBalancingEnabled(), withUDPUnConnected())
var _ = describeBPFTests(withProto("tcp"))
var _ = describeBPFTests(withProto("udp"))
var _ = describeBPFTests(withProto("udp"), withUDPUnConnected())
var _ = describeBPFTests(withProto("udp"), withUDPConnectedRecvMsg(), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withTunnel("ipip"), withProto("tcp"), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withTunnel("ipip"), withProto("udp"), withConnTimeLoadBalancingEnabled())
var _ = describeBPFTests(withTunnel("ipip"), withProto("tcp"))
var _ = describeBPFTests(withTunnel("ipip"), withProto("udp"))
var _ = describeBPFTests(withProto("tcp"), withDSR())
var _ = describeBPFTests(withProto("udp"), withDSR())
var _ = describeBPFTests(withTunnel("ipip"), withProto("tcp"), withDSR())
var _ = describeBPFTests(withTunnel("ipip"), withProto("udp"), withDSR())

// Run a stripe of tests with BPF logging disabled since the compiler tends to optimise the code differently
// with debug disabled and that can lead to verifier issues.
var _ = describeBPFTests(withProto("tcp"),
	withConnTimeLoadBalancingEnabled(),
	withBPFLogLevel("info"))

type bpfTestOptions struct {
	connTimeEnabled bool
	protocol        string
	udpUnConnected  bool
	bpfLogLevel     string
	tunnel          string
	dsr             bool
	udpConnRecvMsg  bool
}

type bpfTestOpt func(opts *bpfTestOptions)

func withProto(proto string) bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.protocol = proto
	}
}

func withConnTimeLoadBalancingEnabled() bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.connTimeEnabled = true
	}
}

func withBPFLogLevel(level string) bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.bpfLogLevel = level
	}
}

func withTunnel(tunnel string) bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.tunnel = tunnel
	}
}

func withUDPUnConnected() bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.udpUnConnected = true
	}
}

func withDSR() bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.dsr = true
	}
}

func withUDPConnectedRecvMsg() bpfTestOpt {
	return func(opts *bpfTestOptions) {
		opts.udpConnRecvMsg = true
	}
}

const expectedRouteDump = `10.65.0.2/32: local workload in-pool nat-out idx -
10.65.0.3/32: local workload in-pool nat-out idx -
10.65.1.0/26: remote workload in-pool nh FELIX_1
10.65.2.0/26: remote workload in-pool nh FELIX_2
FELIX_0/32: local host
FELIX_1/32: remote host
FELIX_2/32: remote host`

const expectedRouteDumpIPIP = `10.65.0.1/32: local host in-pool nat-out
10.65.0.2/32: local workload in-pool nat-out idx -
10.65.0.3/32: local workload in-pool nat-out idx -
10.65.1.0/26: remote workload in-pool nh FELIX_1
10.65.2.0/26: remote workload in-pool nh FELIX_2
FELIX_0/32: local host
FELIX_1/32: remote host
FELIX_2/32: remote host`

func describeBPFTests(opts ...bpfTestOpt) bool {
	testOpts := bpfTestOptions{
		bpfLogLevel: "debug",
		tunnel:      "none",
	}
	for _, o := range opts {
		o(&testOpts)
	}

	protoExt := ""
	if testOpts.udpUnConnected {
		protoExt = "-unconnected"
	}
	if testOpts.udpConnRecvMsg {
		protoExt = "-conn-recvmsg"
	}

	desc := fmt.Sprintf("_BPF_ _BPF-SAFE_ BPF tests (%s%s, ct=%v, log=%s, tunnel=%s, dsr=%v)",
		testOpts.protocol, protoExt, testOpts.connTimeEnabled,
		testOpts.bpfLogLevel, testOpts.tunnel, testOpts.dsr,
	)

	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

		var (
			infra          infrastructure.DatastoreInfra
			felixes        []*infrastructure.Felix
			calicoClient   client.Interface
			cc             *Checker
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
			bpfLog = containers.Run("bpf-log", containers.RunOpts{AutoRemove: true}, "--privileged",
				"calico/bpftool:v5.3-amd64", "/bpftool", "prog", "tracelog")
			infra = getInfra()

			cc = &Checker{
				CheckSNAT: true,
			}
			cc.Protocol = testOpts.protocol
			if testOpts.protocol == "udp" && testOpts.udpUnConnected {
				cc.Protocol += "-noconn"
			}
			if testOpts.protocol == "udp" && testOpts.udpConnRecvMsg {
				cc.Protocol += "-recvmsg"
			}

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
			options.ExtraEnvVars["FELIX_BPFLogLevel"] = fmt.Sprint(testOpts.bpfLogLevel)
			if testOpts.dsr {
				options.ExtraEnvVars["FELIX_BPFExternalServiceMode"] = "dsr"
			}
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
					log.Infof("[%d]SendRecvMap: %+v", i, dumpSendRecvMap(felix))
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
						options.ExtraEnvVars["FELIX_DebugBPFMapRepinEnabled"] = "true"
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
				w     [numNodes][2]*workload.Workload
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
					const portsToOpen = "8055"
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
					w[ii][0].WorkloadEndpoint.Labels = map[string]string{
						"name": w[ii][0].Name,
						"port": "8055",
					}
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
					idxRE := regexp.MustCompile(`idx \d+`)
					for _, l := range lines {
						l = strings.TrimLeft(l, " ")
						if len(l) == 0 {
							continue
						}
						l = strings.ReplaceAll(l, felixes[0].IP, "FELIX_0")
						l = strings.ReplaceAll(l, felixes[1].IP, "FELIX_1")
						l = strings.ReplaceAll(l, felixes[2].IP, "FELIX_2")
						l = idxRE.ReplaceAllLiteralString(l, "idx -")
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

				It("should handle NAT outgoing", func() {
					By("SNATting outgoing traffic with the flag set")
					cc.ExpectSNAT(w[0][0], felixes[0].IP, hostW[1])
					cc.CheckConnectivity()

					if testOpts.tunnel == "none" {
						By("Leaving traffic alone with the flag clear")
						pool, err := calicoClient.IPPools().Get(context.TODO(), "test-pool", options2.GetOptions{})
						Expect(err).NotTo(HaveOccurred())
						pool.Spec.NATOutgoing = false
						pool, err = calicoClient.IPPools().Update(context.TODO(), pool, options2.SetOptions{})
						Expect(err).NotTo(HaveOccurred())
						cc.ResetExpectations()
						cc.ExpectSNAT(w[0][0], w[0][0].IP, hostW[1])
						cc.CheckConnectivity()

						By("SNATting again with the flag set")
						pool.Spec.NATOutgoing = true
						pool, err = calicoClient.IPPools().Update(context.TODO(), pool, options2.SetOptions{})
						Expect(err).NotTo(HaveOccurred())
						cc.ResetExpectations()
						cc.ExpectSNAT(w[0][0], felixes[0].IP, hostW[1])
						cc.CheckConnectivity()
					}
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
					tgtPort := 8055

					BeforeEach(func() {
						testSvc = k8sService(testSvcName, "10.101.0.10", w[0][0], 80, tgtPort, 0, testOpts.protocol)
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(testSvc)
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")
					})

					It("should have connectivity from all workloads via a service to workload 0", func() {
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						cc.ExpectSome(w[0][1], TargetIP(ip), port)
						cc.ExpectSome(w[1][0], TargetIP(ip), port)
						cc.ExpectSome(w[1][1], TargetIP(ip), port)
						cc.CheckConnectivity()
					})

					if testOpts.connTimeEnabled {
						It("workload should have connectivity to self via a service", func() {
							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							cc.ExpectSome(w[0][0], TargetIP(ip), port)
							cc.CheckConnectivity()
						})

						It("should only have connectivity from from the local host via a service to workload 0", func() {
							// Local host is always white-listed (for kubelet health checks).
							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							cc.ExpectSome(felixes[0], TargetIP(ip), port)
							cc.ExpectNone(felixes[1], TargetIP(ip), port)
							cc.CheckConnectivity()
						})
					} else {
						It("should not have connectivity from from the local host via a service to workload 0", func() {
							// Local host is always white-listed (for kubelet health checks).
							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							cc.ExpectNone(felixes[0], TargetIP(ip), port)
							cc.ExpectNone(felixes[1], TargetIP(ip), port)
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

								cc.ExpectSome(felixes[0], TargetIP(ip), port)
								cc.ExpectSome(felixes[1], TargetIP(ip), port)
								cc.ExpectNone(w[0][1], TargetIP(ip), port)
								cc.ExpectNone(w[1][0], TargetIP(ip), port)
								cc.CheckConnectivity()
							})
						})
					}

					It("should create sane conntrack entries and clean them up", func() {
						By("Generating some traffic")
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						cc.ExpectSome(w[0][1], TargetIP(ip), port)
						cc.ExpectSome(w[1][0], TargetIP(ip), port)
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
							nowNanos := bpf.KTimeNanos()
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
							ip := testSvc.Spec.ClusterIP
							portOld := uint16(testSvc.Spec.Ports[0].Port)
							ipv4 := net.ParseIP(ip)
							oldK := nat.NewNATKey(ipv4, portOld, numericProto)

							// Wait for the NAT maps to converge...
							log.Info("Waiting for NAT maps to converge...")
							startTime := time.Now()
							for {
								if time.Since(startTime) > 5*time.Second {
									Fail("NAT maps failed to converge")
								}
								natBeforeUpdate, natBackBeforeUpdate = dumpNATmaps(felixes)
								for i, m := range natBeforeUpdate {
									if natV, ok := m[oldK]; !ok {
										goto retry
									} else {
										bckCnt := natV.Count()
										if bckCnt != 1 {
											log.Debugf("Expected single backend, not %d; retrying...", bckCnt)
											goto retry
										}
										bckID := natV.ID()
										bckK := nat.NewNATBackendKey(bckID, 0)
										if _, ok := natBackBeforeUpdate[i][bckK]; !ok {
											log.Debugf("Backend not found %v; retrying...", bckK)
											goto retry
										}
									}
								}

								break
							retry:
								time.Sleep(100 * time.Millisecond)
							}
							log.Info("NAT maps converged.")

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

							cc.ExpectSome(w[0][1], TargetIP(ip), port)
							cc.ExpectSome(w[1][0], TargetIP(ip), port)
							cc.ExpectSome(w[1][1], TargetIP(ip), port)
							cc.CheckConnectivity()
						})

						It("should not have connectivity from all workloads via the old port", func() {
							ip := testSvc.Spec.ClusterIP
							port := uint16(testSvc.Spec.Ports[0].Port)

							cc.ExpectNone(w[0][1], TargetIP(ip), port)
							cc.ExpectNone(w[1][0], TargetIP(ip), port)
							cc.ExpectNone(w[1][1], TargetIP(ip), port)
							cc.CheckConnectivity()

							natmaps, natbacks := dumpNATmaps(felixes)
							ipv4 := net.ParseIP(ip)
							portOld := uint16(testSvc.Spec.Ports[0].Port)
							oldK := nat.NewNATKey(ipv4, portOld, numericProto)
							portNew := uint16(testSvcUpdated.Spec.Ports[0].Port)
							natK := nat.NewNATKey(ipv4, portNew, numericProto)

							for i := range felixes {
								Expect(natmaps[i]).To(HaveKey(natK))
								Expect(natmaps[i]).NotTo(HaveKey(nat.NewNATKey(ipv4, portOld, numericProto)))

								Expect(natBeforeUpdate[i]).To(HaveKey(oldK))
								oldV := natBeforeUpdate[i][oldK]

								natV := natmaps[i][natK]
								bckCnt := natV.Count()
								bckID := natV.ID()

								log.WithField("backCnt", bckCnt).Debug("Backend count.")
								for ord := uint32(0); ord < uint32(bckCnt); ord++ {
									bckK := nat.NewNATBackendKey(bckID, ord)
									oldBckK := nat.NewNATBackendKey(oldV.ID(), ord)
									Expect(natbacks[i]).To(HaveKey(bckK))
									Expect(natBackBeforeUpdate[i]).To(HaveKey(oldBckK))
									Expect(natBackBeforeUpdate[i][oldBckK]).To(Equal(natbacks[i][bckK]))
								}

							}
						})

						It("after removing service, should not have connectivity from workloads via a service to workload 0", func() {
							ip := testSvcUpdated.Spec.ClusterIP
							port := uint16(testSvcUpdated.Spec.Ports[0].Port)
							natK := nat.NewNATKey(net.ParseIP(ip), port, numericProto)
							var prevBpfsvcs []nat.MapMem
							Eventually(func() bool {
								prevBpfsvcs, _ = dumpNATmaps(felixes)
								for _, m := range prevBpfsvcs {
									if _, ok := m[natK]; !ok {
										return false
									}
								}
								return true
							}, "5s").Should(BeTrue(), "service NAT key didn't show up")

							err := k8sClient.CoreV1().
								Services(testSvcNamespace).
								Delete(testSvcName, &metav1.DeleteOptions{})
							Expect(err).NotTo(HaveOccurred())
							Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(0))

							cc.ExpectNone(w[0][1], TargetIP(ip), port)
							cc.ExpectNone(w[1][0], TargetIP(ip), port)
							cc.ExpectNone(w[1][1], TargetIP(ip), port)
							cc.CheckConnectivity()

							for i, f := range felixes {
								natV := prevBpfsvcs[i][natK]
								bckCnt := natV.Count()
								bckID := natV.ID()

								Eventually(func() bool {
									svcs := dumpNATMap(f)
									eps := dumpEPMap(f)

									if _, ok := svcs[natK]; ok {
										return false
									}

									for ord := uint32(0); ord < uint32(bckCnt); ord++ {
										bckK := nat.NewNATBackendKey(bckID, ord)
										if _, ok := eps[bckK]; ok {
											return false
										}
									}

									return true
								}, "5s").Should(BeTrue(), "service NAT key wasn't removed correctly")
							}
						})
					})
				})

				Context("with test-service configured 10.101.0.10:80 -> w[*][0].IP:8055 and affinity", func() {
					var (
						testSvc          *v1.Service
						testSvcNamespace string
					)

					testSvcName := "test-service"

					BeforeEach(func() {
						testSvc = k8sService(testSvcName, "10.101.0.10", w[0][0], 80, 8055, 0, testOpts.protocol)
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						// select all pods with port 8055
						testSvc.Spec.Selector = map[string]string{"port": "8055"}
						testSvc.Spec.SessionAffinity = "ClientIP"
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(testSvc)
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")
					})

					It("should have connectivity from a workload to a service with multiple backends", func() {
						ip := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						cc.ExpectSome(w[1][1], TargetIP(ip), port)
						cc.ExpectSome(w[1][1], TargetIP(ip), port)
						cc.ExpectSome(w[1][1], TargetIP(ip), port)
						cc.CheckConnectivity()

						if !testOpts.connTimeEnabled {
							// FIXME we can only do the test with regular NAT as
							// cgroup shares one random affinity map
							aff := dumpAffMap(felixes[1])
							Expect(aff).To(HaveLen(1))
						}
					})
				})

				npPort := uint16(30333)

				nodePortsTest := func(localOnly bool) {
					var (
						testSvc          *v1.Service
						testSvcNamespace string
					)

					testSvcName := "test-service"

					BeforeEach(func() {
						k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
						testSvc = k8sService(testSvcName, "10.101.0.10",
							w[0][0], 80, 8055, int32(npPort), testOpts.protocol)
						if localOnly {
							testSvc.Spec.ExternalTrafficPolicy = "Local"
						}
						testSvcNamespace = testSvc.ObjectMeta.Namespace
						_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(testSvc)
						Expect(err).NotTo(HaveOccurred())
						Eventually(k8sGetEpsForServiceFunc(k8sClient, testSvc), "10s").Should(HaveLen(1),
							"Service endpoints didn't get created? Is controller-manager happy?")
					})

					It("should have connectivity from all workloads via a service to workload 0", func() {
						clusterIP := testSvc.Spec.ClusterIP
						port := uint16(testSvc.Spec.Ports[0].Port)

						cc.ExpectSome(w[0][1], TargetIP(clusterIP), port)
						cc.ExpectSome(w[1][0], TargetIP(clusterIP), port)
						cc.ExpectSome(w[1][1], TargetIP(clusterIP), port)
						cc.CheckConnectivity()
					})

					if localOnly {
						It("should not have connectivity from all workloads via a nodeport to non-local workload 0", func() {
							node0IP := felixes[0].IP
							node1IP := felixes[1].IP
							// Via remote nodeport, should fail.
							cc.ExpectNone(w[0][1], TargetIP(node1IP), npPort)
							cc.ExpectNone(w[1][0], TargetIP(node1IP), npPort)
							cc.ExpectNone(w[1][1], TargetIP(node1IP), npPort)
							// Include a check that goes via the local nodeport to make sure the dataplane has converged.
							cc.ExpectSome(w[0][1], TargetIP(node0IP), npPort)
							cc.CheckConnectivity()
						})
					} else {
						It("should have connectivity from all workloads via a nodeport to workload 0", func() {
							node1IP := felixes[1].IP

							cc.ExpectSome(w[0][1], TargetIP(node1IP), npPort)
							cc.ExpectSome(w[1][0], TargetIP(node1IP), npPort)
							cc.ExpectSome(w[1][1], TargetIP(node1IP), npPort)
							cc.CheckConnectivity()
						})
					}

					if !localOnly {
						It("should have connectivity from a workload via a nodeport on another node to workload 0", func() {
							ip := felixes[1].IP

							cc.ExpectSome(w[2][1], TargetIP(ip), npPort)
							cc.CheckConnectivity()

						})
					}

					It("workload should have connectivity to self via local/remote node", func() {
						if !testOpts.connTimeEnabled {
							Skip("FIXME pod cannot connect to self without connect time lb")
						}
						cc.ExpectSome(w[0][0], TargetIP(felixes[1].IP), npPort)
						cc.ExpectSome(w[0][0], TargetIP(felixes[0].IP), npPort)
						cc.CheckConnectivity()
					})

					It("should not have connectivity from external to w[0] via local/remote node", func() {
						cc.ExpectNone(externalClient, TargetIP(felixes[1].IP), npPort)
						cc.ExpectNone(externalClient, TargetIP(felixes[0].IP), npPort)
						// Include a check that goes via the local nodeport to make sure the dataplane has converged.
						cc.ExpectSome(w[0][1], TargetIP(felixes[0].IP), npPort)
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

						if localOnly {
							It("should not have connectivity from external to w[0] via node1->node0 fwd", func() {
								if testOpts.connTimeEnabled {
									Skip("FIXME externalClient also does conntime balancing")
								}

								cc.ExpectNone(externalClient, TargetIP(felixes[1].IP), npPort)
								// Include a check that goes via the nodeport with a local backing pod to make sure the dataplane has converged.
								cc.ExpectSome(externalClient, TargetIP(felixes[0].IP), npPort)
								cc.CheckConnectivity()
							})
						} else {
							It("should have connectivity from external to w[0] via node1->node0 fwd", func() {
								if testOpts.connTimeEnabled {
									Skip("FIXME externalClient also does conntime balancing")
								}

								cc.ExpectSome(externalClient, TargetIP(felixes[1].IP), npPort)
								cc.CheckConnectivity()
							})
						}

						It("should have connectivity from external to w[0] via node0", func() {
							if testOpts.connTimeEnabled {
								Skip("FIXME externalClient also does conntime balancing")
							}

							log.WithFields(log.Fields{
								"externalClientIP": externalClient.IP,
								"nodePortIP":       felixes[1].IP,
							}).Infof("external->nodeport connection")

							cc.ExpectSome(externalClient, TargetIP(felixes[0].IP), npPort)
							cc.CheckConnectivity()
						})
					})
				}

				Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort)), func() {
					nodePortsTest(false)
				})

				// FIXME connect time shares the same NAT table and it is a loterry whic one is gets
				if !testOpts.connTimeEnabled {
					Context("with test-service being a nodeport @ "+strconv.Itoa(int(npPort))+
						" ExternalTrafficPolicy=local", func() {
						nodePortsTest(true)
					})
				}
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

func dumpBPFMap(felix *infrastructure.Felix, m bpf.Map, iter bpf.MapIter) {
	cmd, err := bpf.DumpMapCmd(m)
	Expect(err).NotTo(HaveOccurred())
	log.WithField("cmd", cmd).Debug("dumpBPFMap")
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred())
	err = bpf.IterMapCmdOutput([]byte(out), iter)
	Expect(err).NotTo(HaveOccurred())
}

func dumpNATMap(felix *infrastructure.Felix) nat.MapMem {
	bm := nat.FrontendMap(&bpf.MapContext{})
	m := make(nat.MapMem)
	dumpBPFMap(felix, bm, nat.MapMemIter(m))
	return m
}

func dumpEPMap(felix *infrastructure.Felix) nat.BackendMapMem {
	bm := nat.BackendMap(&bpf.MapContext{})
	m := make(nat.BackendMapMem)
	dumpBPFMap(felix, bm, nat.BackendMapMemIter(m))
	return m
}

func dumpAffMap(felix *infrastructure.Felix) nat.AffinityMapMem {
	bm := nat.AffinityMap(&bpf.MapContext{})
	m := make(nat.AffinityMapMem)
	dumpBPFMap(felix, bm, nat.AffinityMapMemIter(m))
	return m
}

func dumpSendRecvMap(felix *infrastructure.Felix) nat.SendRecvMsgMapMem {
	bm := nat.SendRecvMsgMap(&bpf.MapContext{})
	m := make(nat.SendRecvMsgMapMem)
	dumpBPFMap(felix, bm, nat.SendRecvMsgMapMemIter(m))
	return m
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
