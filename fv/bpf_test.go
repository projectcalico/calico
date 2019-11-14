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
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	bpfm "github.com/projectcalico/felix/bpf/proxy/maps"
	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

var _ = describeBPFTests("tcp")

var _ = describeBPFTests("udp")

func describeBPFTests(protocol string) bool {
	return infrastructure.DatastoreDescribe(fmt.Sprintf("_BPF-NAT_ _BPF-SAFE_ BPF NAT tests (%s)", protocol), []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

		var (
			infra          infrastructure.DatastoreInfra
			felixes        []*infrastructure.Felix
			w              [2][2]*workload.Workload // 1st workload on each host
			hostW          [2]*workload.Workload
			client         client.Interface
			cc             *workload.ConnectivityChecker
			externalClient *containers.Container
		)

		BeforeEach(func() {
			if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
				Skip("Skipping BPF test in non-BPF run.")
			}

			var err error
			infra = getInfra()

			options := infrastructure.DefaultTopologyOptions()
			options.FelixLogSeverity = "debug"
			felixes, client = infrastructure.StartNNodeTopology(2, options, infra)
			cc = &workload.ConnectivityChecker{}
			cc.Protocol = protocol

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
					protocol)

				// Two workloads on each host so we can check the same host and other host cases.
				iiStr := strconv.Itoa(ii)
				w[ii][0] = workload.Run(felix, "w"+iiStr+"0", "default", "10.65."+iiStr+".2", "8055", protocol)
				w[ii][0].WorkloadEndpoint.Labels = map[string]string{"name": w[ii][0].Name}
				w[ii][0].ConfigureInDatastore(infra)
				w[ii][1] = workload.Run(felix, "w"+iiStr+"1", "default", "10.65."+iiStr+".3", "8056", protocol)
				w[ii][1].WorkloadEndpoint.Labels = map[string]string{"name": w[ii][1].Name}
				w[ii][1].ConfigureInDatastore(infra)
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

			err = infra.AddDefaultDeny()
			Expect(err).To(BeNil())
		})

		JustAfterEach(func() {
			if CurrentGinkgoTestDescription().Failed {
				currBpfsvcs, currBpfeps := dumpNATmaps(felixes)

				for i, felix := range felixes {
					felix.Exec("iptables-save", "-c")
					felix.Exec("ip", "r")
					felix.Exec("calico-bpf", "ipsets", "dump")
					log.Infof("[%d]NATMap: %+v", i, currBpfsvcs[i])
					log.Infof("[%d]NATBackend: %+v", i, currBpfeps[i])
				}
			}
		})

		AfterEach(func() {
			for _, f := range felixes {
				f.Stop()
			}
			infra.Stop()
			externalClient.Stop()
		})

		It("should deny all by default", func() {
			// Same host, other workload.
			cc.ExpectNone(w[0][0], w[0][1])
			cc.ExpectNone(w[0][1], w[0][0])
			// Other host.
			cc.ExpectNone(w[0][0], w[1][0])
			cc.ExpectNone(w[1][0], w[0][0])
			cc.CheckConnectivity()
		})

		createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Creating policy")
			policy, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}

		updatePolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
			log.WithField("policy", dumpResource(policy)).Info("Updating policy")
			policy, err := client.GlobalNetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
			return policy
		}
		_ = updatePolicy

		Context("with a policy allowing ingress to w[0][0]", func() {
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
					testSvc = k8sService(testSvcName, "10.101.0.10", w[0][0], 80, 8055, protocol)
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

				It("should create sane conntrack entries and clean them up", func() {
					By("Generating some traffic")
					ip := testSvc.Spec.ClusterIP
					port := uint16(testSvc.Spec.Ports[0].Port)

					cc.ExpectSome(w[0][1], workload.IP(ip), port)
					cc.ExpectSome(w[1][0], workload.IP(ip), port)
					cc.CheckConnectivity()

					By("Checking tiemstamps on conntrack entries are sane")
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
						natBackBeforeUpdate []bpfm.NATBackendMapMem
					)

					BeforeEach(func() {
						_, natBackBeforeUpdate = dumpNATmaps(felixes)

						testSvcUpdated = k8sService(testSvcName, "10.101.0.10", w[0][0], 88, 8055, protocol)

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
							if protocol == "udp" {
								numericProto = 17
							}
							Expect(natmaps[i]).To(HaveKey(bpfm.NewNATKey(ipv4, portNew, numericProto)))
							portOld := uint16(testSvc.Spec.Ports[0].Port)
							Expect(natmaps[i]).NotTo(HaveKey(bpfm.NewNATKey(ipv4, portOld, numericProto)))
						}
					})

					Context("with test-service removed", func() {
						var (
							prevBpfsvcs []bpfm.NATMapMem
							prevBpfeps  []bpfm.NATBackendMapMem
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
								Eventually(func() bpfm.NATMapMem { return dumpNATMap(f) }).Should(HaveLen(len(prevBpfsvcs[i]) - 1))
								Eventually(func() bpfm.NATBackendMapMem { return dumpEPMap(f) }).Should(HaveLen(len(prevBpfeps[i]) - 1))
							}
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

func dumpNATmaps(felixes []*infrastructure.Felix) ([]bpfm.NATMapMem, []bpfm.NATBackendMapMem) {
	bpfsvcs := make([]bpfm.NATMapMem, len(felixes))
	bpfeps := make([]bpfm.NATBackendMapMem, len(felixes))

	for i, felix := range felixes {
		bpfsvcs[i], bpfeps[i] = dumpNATMaps(felix)
	}

	return bpfsvcs, bpfeps
}

func dumpNATMaps(felix *infrastructure.Felix) (bpfm.NATMapMem, bpfm.NATBackendMapMem) {
	return dumpNATMap(felix), dumpEPMap(felix)
}

func dumpNATMap(felix *infrastructure.Felix) bpfm.NATMapMem {
	bm := bpfm.NATMap()
	cmd, err := bpf.DumpMapCmd(bm)
	Expect(err).NotTo(HaveOccurred())
	bpfsvcs := make(bpfm.NATMapMem)
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred())
	err = bpf.IterMapCmdOutput([]byte(out), bpfm.NATMapMemIter(bpfsvcs))
	Expect(err).NotTo(HaveOccurred())
	return bpfsvcs
}

func dumpEPMap(felix *infrastructure.Felix) bpfm.NATBackendMapMem {
	bb := bpfm.BackendMap()
	cmd, err := bpf.DumpMapCmd(bb)
	Expect(err).NotTo(HaveOccurred())
	bpfeps := make(bpfm.NATBackendMapMem)
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred())
	err = bpf.IterMapCmdOutput([]byte(out), bpfm.NATBackendMapMemIter(bpfeps))
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

func equalNATBackendMapVals(m1, m2 bpfm.NATBackendMapMem) bool {
	if len(m1) != len(m2) {
		return false
	}

	mm1 := make(map[bpfm.NATBackendValue]int)
	mm2 := make(map[bpfm.NATBackendValue]int)

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
