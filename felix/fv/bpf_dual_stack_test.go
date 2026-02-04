// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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
	"regexp"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/nat"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var (
	_ = describeBPFDualStackTests(false, true)
	_ = describeBPFDualStackTests(true, true)
	_ = describeBPFDualStackTests(false, false)

	_ = describeBPFDualStackProxyHealthTests()
)

func describeBPFDualStackTests(ctlbEnabled, ipv6Dataplane bool) bool {
	if !BPFMode() {
		return true
	}
	desc := fmt.Sprintf("_BPF_ _BPF-SAFE_ BPF dual stack basic in-cluster connectivity tests (ct=%v)", ctlbEnabled)
	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		var (
			infra        infrastructure.DatastoreInfra
			tc           infrastructure.TopologyContainers
			w            [2][2]*workload.Workload
			hostW        [2]*workload.Workload
			calicoClient client.Interface
			cc           *Checker
			pol          *api.GlobalNetworkPolicy
			k8sClient    *kubernetes.Clientset
		)

		felixIP := func(f int) string {
			return tc.Felixes[f].IP
		}

		felixIP6 := func(f int) string {
			return tc.Felixes[f].IPv6
		}

		BeforeEach(func() {
			iOpts := []infrastructure.CreateOption{
				infrastructure.K8sWithDualStack(),
				infrastructure.K8sWithAPIServerBindAddress("::"),
				infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112,10.101.0.0/16"),
			}
			infra = getInfra(iOpts...)
			cc = &Checker{
				CheckSNAT: true,
			}
			cc.Protocol = "tcp"
			opts := infrastructure.DefaultTopologyOptions()
			opts.EnableIPv6 = true
			opts.NATOutgoingEnabled = true
			opts.AutoHEPsEnabled = false
			opts.IPIPMode = api.IPIPModeNever
			opts.DelayFelixStart = true

			if ipv6Dataplane {
				opts.ExtraEnvVars["FELIX_IPV6SUPPORT"] = "true"
			} else {
				opts.ExtraEnvVars["FELIX_IPV6SUPPORT"] = "false"
			}
			opts.ExtraEnvVars["FELIX_BPFLogLevel"] = "debug"
			opts.ExtraEnvVars["FELIX_HEALTHENABLED"] = "true"
			opts.ExtraEnvVars["FELIX_HEALTHHOST"] = "::"

			if !ctlbEnabled {
				opts.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBDisabled)
				opts.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATEnabled)
			} else {
				opts.ExtraEnvVars["FELIX_BPFHostNetworkedNATWithoutCTLB"] = string(api.BPFHostNetworkedNATDisabled)
				opts.ExtraEnvVars["FELIX_BPFConnectTimeLoadBalancing"] = string(api.BPFConnectTimeLBTCP)
			}

			opts.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "RETURN"

			tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)

			addWorkload := func(run bool, ii, wi, port int, labels map[string]string) *workload.Workload {
				if labels == nil {
					labels = make(map[string]string)
				}

				wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2)
				wIPv6 := fmt.Sprintf("dead:beef::%d:%d", ii, wi+2)
				wName := fmt.Sprintf("w%d%d", ii, wi)

				infrastructure.AssignIP(wName, wIP, tc.Felixes[ii].Hostname, calicoClient)
				infrastructure.AssignIP(wName, wIPv6, tc.Felixes[ii].Hostname, calicoClient)

				w := workload.New(tc.Felixes[ii], wName, "default",
					wIP, strconv.Itoa(port), "tcp", workload.WithIPv6Address(wIPv6))

				labels["name"] = w.Name
				labels["workload"] = "regular"

				w.WorkloadEndpoint.Labels = labels
				if run {
					err := w.Start(infra)
					Expect(err).NotTo(HaveOccurred())
					w.ConfigureInInfra(infra)
				}

				return w
			}

			createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
				log.WithField("policy", dumpResource(policy)).Info("Creating policy")
				policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
				return policy
			}

			for ii := range tc.Felixes {
				hostW[ii] = workload.Run(
					tc.Felixes[ii],
					fmt.Sprintf("host%d", ii),
					"default",
					felixIP(ii), // Same IP as felix means "run in the host's namespace"
					"8055",
					"tcp", workload.WithIPv6Address(net.ParseIP(felixIP6(ii)).String()))

				hostW[ii].WorkloadEndpoint.Labels = map[string]string{"name": hostW[ii].Name}
				// Two workloads on each host so we can check the same host and other host cases.
				w[ii][0] = addWorkload(true, ii, 0, 8055, map[string]string{"port": "8055"})
				w[ii][1] = addWorkload(true, ii, 1, 8056, nil)
			}

			err := infra.AddDefaultDeny()
			Expect(err).NotTo(HaveOccurred())
			pol = api.NewGlobalNetworkPolicy()
			pol.Namespace = "fv"
			pol.Name = "policy-1"
			pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
			pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
			pol.Spec.Selector = "all()"
			pol = createPolicy(pol)
		})

		JustAfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				var (
					currBpfsvcs   []nat.MapMem
					currBpfeps    []nat.BackendMapMem
					currBpfsvcsV6 []nat.MapMemV6
					currBpfepsV6  []nat.BackendMapMemV6
				)

				currBpfsvcsV6, currBpfepsV6, _ = dumpNATmapsV6(tc.Felixes)
				currBpfsvcs, currBpfeps, _ = dumpNATmaps(tc.Felixes)

				for i, felix := range tc.Felixes {
					log.Infof("[%d]FrontendMapV6: %+v", i, currBpfsvcsV6[i])
					log.Infof("[%d]NATBackendV6: %+v", i, currBpfepsV6[i])
					log.Infof("[%d]SendRecvMapV6: %+v", i, dumpSendRecvMapV6(felix))
					log.Infof("[%d]FrontendMap: %+v", i, currBpfsvcs[i])
					log.Infof("[%d]NATBackend: %+v", i, currBpfeps[i])
					log.Infof("[%d]SendRecvMap: %+v", i, dumpSendRecvMap(felix))
				}
			}
		})

		if !ipv6Dataplane {
			JustBeforeEach(func() {
				tc.TriggerDelayedStart()
				ensureRightIFStateFlags(tc.Felixes[0], ifstate.FlgIPv4Ready, ifstate.FlgHEP, nil)
				ensureRightIFStateFlags(tc.Felixes[1], ifstate.FlgIPv4Ready, ifstate.FlgHEP, nil)
			})
			It("should drop ipv6 packets at workload interface and allow ipv6 packets at host interface when in IPv4 only mode", func() {
				cc.ResetExpectations()
				// IPv4 connectivity must work.
				cc.Expect(Some, hostW[0], w[0][0])
				cc.Expect(Some, hostW[0], hostW[1])
				// Host to workload IPv6 connectivity must fail
				cc.Expect(None, w[0][0], w[1][0], ExpectWithIPVersion(6))
				// Host to Host IPv6 connectivity must pass.
				cc.Expect(Some, hostW[0], hostW[1], ExpectWithIPVersion(6))
				cc.CheckConnectivity()
			})

			return
		}

		var (
			testSvc          *v1.Service
			testSvcNamespace string
		)

		npPort := uint16(30333)
		clusterIPs := []string{"10.101.0.10", "dead:beef::abcd:0:0:10"}
		Context("with IPv4 and IPv6 enabled", func() {
			JustBeforeEach(func() {
				tc.TriggerDelayedStart()
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
			})
			BeforeEach(func() {
				k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				_ = k8sClient
				testSvc = k8sServiceForDualStack("test-svc", clusterIPs, w[0][0], 80, 8055, int32(npPort), "tcp")
				testSvcNamespace = testSvc.Namespace
				_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(k8sClient, testSvc), "10s").Should(Equal(2),
					"Service endpoints didn't get created? Is controller-manager happy?")
			})
			It("Should connect to w[0][0] from all other workloads with IPv4 and IPv6", func() {
				cc.ResetExpectations()
				cc.ExpectSome(w[0][1], w[0][0])
				cc.ExpectSome(w[1][0], w[0][0])
				cc.ExpectSome(w[1][1], w[0][0])

				cc.Expect(Some, w[0][1], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(Some, w[1][0], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(Some, w[1][1], w[0][0], ExpectWithIPVersion(6))
				cc.CheckConnectivity()
			})

			It("Should connect to w[0][0] via clusterIP (IPv4 and IPv6)", func() {
				cc.ResetExpectations()
				port := uint16(testSvc.Spec.Ports[0].Port)
				cc.ExpectSome(w[1][0], TargetIP(clusterIPs[0]), port)
				cc.ExpectSome(w[1][0], TargetIP(clusterIPs[1]), port)

				cc.ExpectSome(w[0][1], TargetIP(clusterIPs[0]), port)
				cc.ExpectSome(w[0][1], TargetIP(clusterIPs[1]), port)
				cc.CheckConnectivity()
			})

			It("Should connect to w[0][0] via nodePort (IPv4 and IPv6)", func() {
				cc.ResetExpectations()
				cc.ExpectSome(w[1][0], TargetIP(felixIP(0)), npPort)
				cc.ExpectSome(w[0][1], TargetIP(felixIP(0)), npPort)

				cc.ExpectSome(w[1][0], TargetIP(felixIP6(0)), npPort)
				cc.ExpectSome(w[0][1], TargetIP(felixIP6(0)), npPort)
				cc.CheckConnectivity()
			})
		})

		// Running this test once should be enough as this test doesn't depend on CTLB.
		if !ctlbEnabled {
			It("Should connect to w[0][0] using IPv6 after IPv6 host IP is added", func() {
				k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				_ = k8sClient

				// Remove Node IPv6 address.
				node, err := k8sClient.CoreV1().Nodes().Get(context.Background(), tc.Felixes[0].Hostname, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				delete(node.Annotations, "projectcalico.org/IPv6Address")
				_, err = k8sClient.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())

				node, err = k8sClient.CoreV1().Nodes().Get(context.Background(), tc.Felixes[0].Hostname, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				node.Status.Addresses = []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: felixIP(0)}}
				_, err = k8sClient.CoreV1().Nodes().UpdateStatus(context.Background(), node, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())

				tc.TriggerDelayedStart()

				ensureRightIFStateFlags(tc.Felixes[0], ifstate.FlgIPv4Ready, ifstate.FlgHEP, nil)
				ensureRightIFStateFlags(tc.Felixes[1], ifstate.FlgIPv4Ready|ifstate.FlgIPv6Ready, ifstate.FlgHEP, nil)
				cc.ResetExpectations()
				cc.ExpectSome(w[0][1], w[0][0])
				cc.ExpectSome(w[1][0], w[0][0])
				cc.ExpectSome(w[1][1], w[0][0])

				cc.Expect(None, w[0][1], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(None, w[1][0], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(None, w[1][1], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(Some, hostW[0], hostW[1], ExpectWithIPVersion(6))

				cc.CheckConnectivity()

				// Since we allow the IPv6 packets through IPv4 programs, a stale neighbor entry might get created
				// when trying to reach w[0][0] from workloads in felix-1. This will impact subsequent
				// tests. This does not seem to be a problem with ubuntu 22+ but is on ubuntu 20.
				// Hence cleaning up the neighbor entry.
				_ = tc.Felixes[0].ExecMayFail("ip", "-6", "neigh", "del", w[0][0].IP6, "dev", w[0][0].InterfaceName)

				// Add the node IPv6 address
				node, err = k8sClient.CoreV1().Nodes().Get(context.Background(), tc.Felixes[0].Hostname, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				node.Annotations["projectcalico.org/IPv6Address"] = fmt.Sprintf("%s/%s", felixIP6(0), tc.Felixes[0].IPv6Prefix)
				_, err = k8sClient.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())

				node, err = k8sClient.CoreV1().Nodes().Get(context.Background(), tc.Felixes[0].Hostname, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				node.Status.Addresses = []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: felixIP(0)}, {Type: v1.NodeInternalIP, Address: felixIP6(0)}}
				_, err = k8sClient.CoreV1().Nodes().UpdateStatus(context.Background(), node, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())

				ensureRightIFStateFlags(tc.Felixes[0], ifstate.FlgIPv4Ready|ifstate.FlgIPv6Ready, ifstate.FlgHEP, nil)
				cc.ResetExpectations()
				cc.ExpectSome(w[0][1], w[0][0])
				cc.ExpectSome(w[1][0], w[0][0])
				cc.ExpectSome(w[1][1], w[0][0])

				cc.Expect(Some, w[0][1], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(Some, w[1][0], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(Some, w[1][1], w[0][0], ExpectWithIPVersion(6))
				cc.CheckConnectivity()
			})

			It("should be able to ping external client from w[0][0]", func() {
				tc.TriggerDelayedStart()
				externalClient := infrastructure.RunExtClient(infra, "ext-client")
				_ = externalClient
				ensureRightIFStateFlags(tc.Felixes[0], ifstate.FlgIPv4Ready|ifstate.FlgIPv6Ready, ifstate.FlgHEP, nil)
				ensureRightIFStateFlags(tc.Felixes[1], ifstate.FlgIPv4Ready|ifstate.FlgIPv6Ready, ifstate.FlgHEP, nil)

				tcpdump := externalClient.AttachTCPDump("any")
				tcpdump.SetLogEnabled(true)
				matcher := fmt.Sprintf("IP6 %s > %s: ICMP6, echo request",
					felixIP6(0), externalClient.IPv6)

				tcpdump.AddMatcher("ICMP", regexp.MustCompile(matcher))
				tcpdump.Start(infra)

				_, err := w[0][0].ExecCombinedOutput("ping6", "-c", "2", externalClient.IPv6)
				Expect(err).NotTo(HaveOccurred())
				Eventually(func() int { return tcpdump.MatchCount("ICMP") }).
					Should(BeNumerically(">", 0), matcher)
			})

			It("should have both IPv4 and IPv6 routes for a dual stack UDP service", func() {
				tc.TriggerDelayedStart()
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
				k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				_ = k8sClient
				testSvc = k8sServiceForDualStack("test-svc", clusterIPs, w[0][0], 80, 8055, int32(npPort), "udp")
				testSvcNamespace = testSvc.Namespace
				_, err := k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(k8sClient, testSvc), "10s").Should(Equal(2),
					"Service endpoints didn't get created? Is controller-manager happy?")
				Eventually(func() bool {
					return checkServiceRoute(tc.Felixes[0], testSvc.Spec.ClusterIPs[0])
				}, 10*time.Second, 300*time.Millisecond).Should(BeTrue(), "Failed to sync with udp service")
				Eventually(func() bool {
					return checkServiceRoute(tc.Felixes[0], testSvc.Spec.ClusterIPs[1])
				}, 10*time.Second, 300*time.Millisecond).Should(BeTrue(), "Failed to sync with udp service")
			})
		}

		Context("with IPv6 addresses only", func() {
			BeforeEach(func() {
				k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				for _, f := range tc.Felixes {
					removeIPv4Address(k8sClient, f)
				}
				tc.TriggerDelayedStart()
			})

			It("should be ready and have connectivity to w[0][0] from all other workloads with IPv6 only", func() {
				for _, f := range tc.Felixes {
					ensureBPFProgramsAttachedOffsetWithIPVersion(1, f, false, true, "eth0")
				}

				for _, f := range tc.Felixes {
					felixReady := func() int {
						return healthStatus(f.IPv6, "9099", "readiness")
					}
					Eventually(felixReady, "10s", "330ms").Should(BeGood())
					Consistently(felixReady, "10s", "1s").Should(BeGood())
				}

				cc.ResetExpectations()
				cc.Expect(None, w[0][1], w[0][0])
				cc.Expect(None, w[1][0], w[0][0])
				cc.Expect(None, w[1][1], w[0][0])

				cc.Expect(Some, w[0][1], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(Some, w[1][0], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(Some, w[1][1], w[0][0], ExpectWithIPVersion(6))

				cc.CheckConnectivity()
			})
		})

		Context("with IPv4 addresses only", func() {
			BeforeEach(func() {
				k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				for _, f := range tc.Felixes {
					removeIPv6Address(k8sClient, f)
					f.SetEnv(map[string]string{"FELIX_HEALTHHOST": "0.0.0.0"})
				}
				tc.TriggerDelayedStart()
			})

			It("should be ready and have connectivity to w[0][0] from all other workloads with IPv4 only", func() {
				for _, f := range tc.Felixes {
					ensureBPFProgramsAttachedOffsetWithIPVersion(1, f, true, false, "eth0")
				}

				for _, f := range tc.Felixes {
					felixReady := func() int {
						return healthStatus(f.IP, "9099", "readiness")
					}
					Eventually(felixReady, "10s", "330ms").Should(BeGood())
					Consistently(felixReady, "10s", "1s").Should(BeGood())
				}

				cc.ResetExpectations()
				cc.Expect(None, w[0][1], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(None, w[1][0], w[0][0], ExpectWithIPVersion(6))
				cc.Expect(None, w[1][1], w[0][0], ExpectWithIPVersion(6))

				cc.Expect(Some, w[0][1], w[0][0])
				cc.Expect(Some, w[1][0], w[0][0])
				cc.Expect(Some, w[1][1], w[0][0])

				cc.CheckConnectivity()
			})
		})
	})
}

func describeBPFDualStackProxyHealthTests() bool {
	if !BPFMode() {
		return true
	}
	desc := "_BPF_ _BPF-SAFE_ BPF dual stack kube-proxy health checking tests"
	return infrastructure.DatastoreDescribe(desc, []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
		var (
			infra     infrastructure.DatastoreInfra
			tc        infrastructure.TopologyContainers
			k8sClient *kubernetes.Clientset
		)

		BeforeEach(func() {
			iOpts := []infrastructure.CreateOption{
				infrastructure.K8sWithDualStack(),
				infrastructure.K8sWithAPIServerBindAddress("::"),
				infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112,10.101.0.0/16"),
			}
			infra = getInfra(iOpts...)
			opts := infrastructure.DefaultTopologyOptions()
			opts.EnableIPv6 = true
			opts.IPIPMode = api.IPIPModeNever
			opts.NATOutgoingEnabled = true
			opts.BPFProxyHealthzPort = 10256
			opts.IPIPMode = api.IPIPModeNever

			tc, _ = infrastructure.StartNNodeTopology(2, opts, infra)
			k8sClient = infra.(*infrastructure.K8sDatastoreInfra).K8sClient
		})

		AfterEach(func() {
			tc.Stop()
			infra.Stop()
		})

		It("should have kube-proxy health check working over both IPv4 and IPv6", func() {
			felix := tc.Felixes[0]

			felixReady := func(ip string) int {
				return healthStatus(ip, "10256", "healthz")
			}

			Eventually(func() int { return felixReady(felix.IP) }, "10s", "330ms").Should(BeGood())
			Eventually(func() int { return felixReady(felix.IPv6) }, "10s", "330ms").Should(BeGood())
		})

		It("should have nodeport health probe working over both IPv4 and IPv6", func() {
			// Create a workload on node 0
			w0 := workload.Run(
				tc.Felixes[0],
				"w0",
				"default",
				"10.65.0.2",
				"8055",
				"tcp",
				workload.WithIPv6Address("dead:beef::0:2"),
			)
			w0.WorkloadEndpoint.Labels = map[string]string{"name": w0.Name, "app": "test"}
			w0.ConfigureInInfra(infra)

			// Create a NodePort service with ExternalTrafficPolicy=Local
			// This will automatically get a HealthCheckNodePort allocated
			clusterIPs := []string{"10.101.0.20", "dead:beef::abcd:0:0:20"}
			testSvc := k8sServiceForDualStack("test-np-health", clusterIPs, w0, 80, 8055, 30080, "tcp")
			testSvc.Spec.Type = v1.ServiceTypeLoadBalancer
			testSvc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeLocal
			healthCheckNodePort := int32(30081)
			testSvc.Spec.HealthCheckNodePort = healthCheckNodePort
			_, err := k8sClient.CoreV1().Services("default").Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(checkSvcEndpoints(k8sClient, testSvc), "10s").Should(Equal(2),
				"Service endpoints didn't get created? Is controller-manager happy?")

			// Check health probe on node 0 (has local endpoint) - should return 200
			Eventually(func() int {
				return healthStatus(tc.Felixes[0].IP, strconv.Itoa(int(healthCheckNodePort)), "")
			}, "10s", "330ms").Should(Equal(200))

			Eventually(func() int {
				return healthStatus(tc.Felixes[0].IPv6, strconv.Itoa(int(healthCheckNodePort)), "")
			}, "10s", "330ms").Should(Equal(200))

			// Check health probe on node 1 (no local endpoint) - should return 503
			Eventually(func() int {
				return healthStatus(tc.Felixes[1].IP, strconv.Itoa(int(healthCheckNodePort)), "")
			}, "10s", "330ms").Should(Equal(503))

			Eventually(func() int {
				return healthStatus(tc.Felixes[1].IPv6, strconv.Itoa(int(healthCheckNodePort)), "")
			}, "10s", "330ms").Should(Equal(503))

			// Clean up
			w0.Stop()
			err = k8sClient.CoreV1().Services("default").Delete(context.Background(), "test-np-health", metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
		})
	})
}

func removeIPv4Address(k8sClient *kubernetes.Clientset, felix *infrastructure.Felix) {
	node, err := k8sClient.CoreV1().Nodes().Get(context.Background(), felix.Hostname, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	delete(node.Annotations, "projectcalico.org/IPv4Address")
	_, err = k8sClient.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())

	node, err = k8sClient.CoreV1().Nodes().Get(context.Background(), felix.Hostname, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	node.Status.Addresses = []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: felix.IPv6}}
	_, err = k8sClient.CoreV1().Nodes().UpdateStatus(context.Background(), node, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())

	felix.Exec("ip", "addr", "del", felix.IP, "dev", "eth0")
}

func removeIPv6Address(k8sClient *kubernetes.Clientset, felix *infrastructure.Felix) {
	node, err := k8sClient.CoreV1().Nodes().Get(context.Background(), felix.Hostname, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	delete(node.Annotations, "projectcalico.org/IPv6Address")
	_, err = k8sClient.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())

	node, err = k8sClient.CoreV1().Nodes().Get(context.Background(), felix.Hostname, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	node.Status.Addresses = []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: felix.IP}}
	_, err = k8sClient.CoreV1().Nodes().UpdateStatus(context.Background(), node, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())

	felix.Exec("ip", "-6", "addr", "del", felix.IPv6+"/64", "dev", "eth0")
}

func ensureRightIFStateFlags(felix *infrastructure.Felix, ready uint32, hostIfType uint32, additionalInterfaces map[string]uint32) {
	expectedIfacesToFlags := map[string]uint32{
		"eth0": hostIfType | ready,
	}

	for k, v := range additionalInterfaces {
		expectedIfacesToFlags[k] = v
	}

	for _, w := range felix.Workloads {
		if w.Runs() {
			if iface := w.GetInterfaceName(); iface != "" {
				expectedIfacesToFlags[iface] = ifstate.FlgWEP | ready
			}
		}
	}

	EventuallyWithOffset(1, func() bool {
		m := dumpIfStateMap(felix)
		numIfaces := 0
		for _, v := range m {
			val, ok := expectedIfacesToFlags[v.IfName()]
			if ok {
				if val != v.Flags() {
					return false
				}
				numIfaces++
			}
		}
		return numIfaces == len(expectedIfacesToFlags)
	}, "1m", "1s").Should(BeTrue())
}

func k8sServiceForDualStack(name string, clusterIPs []string, w *workload.Workload, port,
	tgtPort int, nodePort int32, protocol string,
) *v1.Service {
	k8sProto := v1.ProtocolTCP
	if protocol == "udp" {
		k8sProto = v1.ProtocolUDP
	}

	ipFamilyPolicyStr := v1.IPFamilyPolicyRequireDualStack
	svcType := v1.ServiceTypeClusterIP
	if nodePort != 0 {
		svcType = v1.ServiceTypeNodePort
	}

	return &v1.Service{
		TypeMeta:   typeMetaV1("Service"),
		ObjectMeta: objectMetaV1(name),
		Spec: v1.ServiceSpec{
			ClusterIP:  clusterIPs[0],
			ClusterIPs: clusterIPs,
			Type:       svcType,
			Selector: map[string]string{
				"name": w.Name,
			},
			IPFamilies:     []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol},
			IPFamilyPolicy: &ipFamilyPolicyStr,
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
