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
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

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

var _ = describeBPFTests(bpfTestOptions{protocol: "tcp", connTimeEnabled: true})
var _ = describeBPFTests(bpfTestOptions{protocol: "udp", connTimeEnabled: true})
var _ = describeBPFTests(bpfTestOptions{protocol: "tcp"})
var _ = describeBPFTests(bpfTestOptions{protocol: "udp"})

type bpfTestOptions struct {
	connTimeEnabled bool
	protocol        string
}

const expectedRouteDump = `10.65.0.1/32: local host
10.65.0.2/32: local workload
10.65.0.3/32: local workload
10.65.1.0/26: remote workload, host IP FELIX_1
FELIX_0/32: local host
FELIX_1/32: remote host
`

func describeBPFTests(testOpts bpfTestOptions) bool {
	desc := fmt.Sprintf("_BPF_ _BPF-SAFE_ BPF tests (%s, ct=%v)", testOpts.protocol, testOpts.connTimeEnabled)
	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

		var (
			infra          infrastructure.DatastoreInfra
			felixes        []*infrastructure.Felix
			calicoClient   client.Interface
			cc             *workload.ConnectivityChecker
			externalClient *containers.Container
			bpfLog         *containers.Container
			options        infrastructure.TopologyOptions
		)

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
		})

		Describe("with a two node cluster", func() {
			var (
				w     [2][2]*workload.Workload // 1st workload on each host
				hostW [2]*workload.Workload
			)

			BeforeEach(func() {
				felixes, calicoClient = infrastructure.StartNNodeTopology(2, options, infra)

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
					for i := range lines {
						lines[i] = strings.TrimLeft(lines[i], " ")
						lines[i] = strings.ReplaceAll(lines[i], felixes[0].IP, "FELIX_0")
						lines[i] = strings.ReplaceAll(lines[i], felixes[1].IP, "FELIX_1")
					}

					return strings.Join(lines, "\n")
				}
				Eventually(dumpRoutes).Should(Equal(expectedRouteDump))
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
						testSvc = k8sService(testSvcName, "10.101.0.10", w[0][0], 80, 8055, testOpts.protocol)
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
												felixes[0].ExpectedIPIPTunnelAddr + "/32",
												felixes[1].ExpectedIPIPTunnelAddr + "/32",
											},
										},
									},
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
						)

						BeforeEach(func() {
							_, natBackBeforeUpdate = dumpNATmaps(felixes)

							testSvcUpdated = k8sService(testSvcName, "10.101.0.10", w[0][0], 88, 8055, testOpts.protocol)

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
							for i := range felixes {
								Expect(equalNATBackendMapVals(natbacks[i], natBackBeforeUpdate[i])).To(BeTrue())
								ipv4 := net.ParseIP(ip)
								portNew := uint16(testSvcUpdated.Spec.Ports[0].Port)
								numericProto := uint8(6)
								if testOpts.protocol == "udp" {
									numericProto = 17
								}
								Expect(natmaps[i]).To(HaveKey(nat.NewNATKey(ipv4, portNew, numericProto)))
								portOld := uint16(testSvc.Spec.Ports[0].Port)
								Expect(natmaps[i]).NotTo(HaveKey(nat.NewNATKey(ipv4, portOld, numericProto)))
							}
						})

						Context("with test-service removed", func() {
							var (
								prevBpfsvcs []nat.MapMem
								prevBpfeps  []nat.BackendMapMem
							)

							BeforeEach(func() {
								prevBpfsvcs, prevBpfeps = dumpNATmaps(felixes)
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
									Eventually(func() nat.MapMem { return dumpNATMap(f) }).Should(HaveLen(len(prevBpfsvcs[i]) - 1))
									Eventually(func() nat.BackendMapMem { return dumpEPMap(f) }).Should(HaveLen(len(prevBpfeps[i]) - 1))
								}
							})
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
	bm := nat.FrontendMap()
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
	bb := nat.BackendMap()
	cmd, err := bpf.DumpMapCmd(bb)
	Expect(err).NotTo(HaveOccurred())
	bpfeps := make(nat.BackendMapMem)
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred())
	err = bpf.IterMapCmdOutput([]byte(out), nat.BackendMapMemIter(bpfeps))
	Expect(err).NotTo(HaveOccurred())
	return bpfeps
}

func k8sService(name, clusterIP string, w *workload.Workload, port, tgtPort int, protocol string) *v1.Service {
	k8sProto := v1.ProtocolTCP
	if protocol == "udp" {
		k8sProto = v1.ProtocolUDP
	}
	return &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1(name),
		Spec: v1.ServiceSpec{
			ClusterIP: clusterIP,
			Type:      v1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"name": w.Name,
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   k8sProto,
					Port:       int32(port),
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

func equalNATBackendMapVals(m1, m2 nat.BackendMapMem) bool {
	if len(m1) != len(m2) {
		return false
	}

	mm1 := make(map[nat.BackendValue]int)
	mm2 := make(map[nat.BackendValue]int)

	for _, v := range m1 {
		c := mm1[v]
		mm1[v] = c + 1
	}

	for _, v := range m2 {
		c := mm2[v]
		mm2[v] = c + 1
	}

	if len(mm1) != len(mm2) {
		return false
	}

	for k1, v1 := range mm1 {
		if v2, ok := mm2[k1]; !ok {
			return false
		} else if v1 != v2 {
			return false
		}
	}

	return true
}
