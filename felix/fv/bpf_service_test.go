// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/proxy"
	. "github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/tcpdump"
	"github.com/projectcalico/calico/felix/fv/workload"
)

func describeBPFServiceTests(s *bpfTestContext, clusterIP, extIP, excludeSvcIP, loIP string) {
	Describe("Test advertised IP's with maglev enabled", func() {
		if s.testOpts.connTimeEnabled {
			// FIXME s.externalClient also does conntime balancing
			return
		}

		var (
			testSvc          *v1.Service
			testSvcNamespace string
			port             uint16
			proto            uint8
		)
		if numNodes < 3 {
			panic("need 3 nodes")
		}

		tgtPort := 8055
		externalIP := extIP
		testSvcName := "test-maglev-service"

		familyInt := 4
		if s.family == "ipv6" {
			familyInt = 6
		}

		felixWithMaglevBackend := 0
		initialIngressFelix := 1
		failoverIngressFelix := 2

		newConntrackKey := func(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, family string) conntrack.KeyInterface {
			var key conntrack.KeyInterface
			// cmp := bytes.Compare(srcIP, dstIP)
			// srcLTDst := cmp < 0 || (cmp == 0 && srcPort < dstPort)

			ipA, ipB := srcIP, dstIP
			portA, portB := uint16(srcPort), dstPort
			// if !srcLTDst {
			// 	ipB, ipA = srcIP, dstIP
			// 	portB, portA = uint16(srcPort), port
			// }
			switch family {
			case "ipv4":
				key = conntrack.NewKey(proto, ipA, portA, ipB, portB)
			case "ipv6":
				key = conntrack.NewKeyV6(proto, ipA, portA, ipB, portB)
			}
			return key
		}
		checkConntrackExists := func(f *infrastructure.Felix, ctK conntrack.KeyInterface) (conntrack.ValueInterface, bool) {
			ctMap := dumpCTMapsAny(familyInt, f)
			log.Infof("Dumping CT map for felix %s, searching for key: %s", f.Name, ctK.String())

			for k, v := range ctMap {
				log.Infof("key: %s\n\tval: %s", k.String(), v.String())
			}
			v, ok := ctMap[ctK]
			return v, ok
		}
		checkConntrackExistsAnyDirection := func(f *infrastructure.Felix, ipA net.IP, portA uint16, ipB net.IP, portB uint16, family string) (conntrack.ValueInterface, bool) {
			keyAB := newConntrackKey(ipA, portA, ipB, portB, family)
			keyBA := newConntrackKey(ipB, portB, ipA, portA, family)

			val, exists := checkConntrackExists(f, keyAB)
			if !exists {
				val, exists = checkConntrackExists(f, keyBA)
			}

			return val, exists
		}
		maglevMapAnySearch := func(val nat.BackendValueInterface, family string, felix *infrastructure.Felix) nat.BackendValueInterface {
			Expect(family).To(Or(Equal("ipv4"), Equal("ipv6")))

			switch family {
			case "ipv4":
				vType := nat.BackendValue{}
				Expect(val).To(BeAssignableToTypeOf(vType))
				kvs := dumpMaglevMap(felix)
				valParsed, _ := val.(nat.BackendValue)

				for _, v := range kvs {
					if v.Addr().Equal(valParsed.Addr()) && v.Port() == valParsed.Port() {
						return v
					}
				}

			case "ipv6":
				vType := nat.BackendValueV6{}
				Expect(val).To(BeAssignableToTypeOf(vType))
				kvs := dumpMaglevMapV6(felix)
				valParsed, _ := val.(nat.BackendValueV6)

				for _, v := range kvs {
					if v.Addr().Equal(valParsed.Addr()) && v.Port() == valParsed.Port() {
						return v
					}
				}
			}
			return nil
		}
		maglevMapAnySearchFunc := func(val nat.BackendValueInterface, family string, felix *infrastructure.Felix) func() nat.BackendValueInterface {
			return func() nat.BackendValueInterface {
				return maglevMapAnySearch(val, family, felix)
			}
		}

		probeMaglevConntrackMetric := func(metricName string, felixes ...*infrastructure.Felix) []int {
			counts := make([]int, 0)
			for _, f := range felixes {
				ctCount, err := f.PromMetric(metricName).Int()
				if err != nil {
					log.WithError(err).WithField("felix", f.Name).Warn("Error while probing Felix metric. Skipping this felix")
					continue
				}
				counts = append(counts, ctCount)
			}
			return counts
		}

		BeforeEach(func() {
			switch s.testOpts.protocol {
			case "udp":
				proto = 17
			case "tcp":
				proto = 6
			case "sctp":
				proto = 132
			default:
				log.WithField("protocol", s.testOpts.protocol).Panic("unknown test protocol")
			}
			log.WithFields(log.Fields{"number": proto, "name": s.testOpts.protocol}).Info("parsed protocol")

			pTCP := numorstring.ProtocolFromString("tcp")
			promPinhole := api.Rule{
				Action:   "Allow",
				Protocol: &pTCP,
				Destination: api.EntityRule{
					Ports: []numorstring.Port{
						{MinPort: 9091, MaxPort: 9091},
					},
					Nets: []string{},
				},
			}

			// Create policy allowing ingress from external client
			allowIngressFromExtClient := api.NewGlobalNetworkPolicy()
			allowIngressFromExtClient.Namespace = "fv"
			allowIngressFromExtClient.Name = "policy-ext-client"
			allowIngressFromExtClient.Spec.Ingress = []api.Rule{
				promPinhole,
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: []string{
							s.containerIP(s.externalClient) + "/" + s.ipMask(),
						},
					},
				},
			}

			allowIngressFromExtClientSelector := "all()"
			allowIngressFromExtClient.Spec.Selector = allowIngressFromExtClientSelector
			allowIngressFromExtClient = s.createPolicy(allowIngressFromExtClient)

			// Create service with maglev annotation
			testSvc = k8sServiceWithExtIP(testSvcName, clusterIP, s.w[felixWithMaglevBackend][0], 80, tgtPort, 0,
				s.testOpts.protocol, []string{externalIP})
			testSvc.Annotations = map[string]string{
				"lb.projectcalico.org/external-traffic-strategy": "maglev",
			}

			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
				"Service endpoint didn't get created. Is controller-manager happy?")
			Expect(k8sGetEpsForService(s.k8sClient, testSvc)[0].Endpoints[0].Addresses).Should(HaveLen(1),
				"Service endpoint didn't have the expected number of addresses.")

			Expect(testSvc.Spec.ExternalIPs).To(HaveLen(1))
			Expect(testSvc.Spec.ExternalIPs[0]).To(Equal(externalIP))
			Expect(testSvc.Spec.Ports).To(HaveLen(1))
			port = uint16(testSvc.Spec.Ports[0].Port)

			conntrackFlushWorkloadEntries(s.tc.Felixes)

			eps := k8sGetEpsForService(s.k8sClient, testSvc)
			Expect(eps).NotTo(HaveLen(0), "Expected endpoints for the service")
			Expect(eps[0].Endpoints).NotTo(HaveLen(0), "Endpointslice had no endpoints")
			Expect(eps[0].Endpoints[0].Addresses).NotTo(BeEmpty(), "No addresses in endpointslice item")
			Expect(net.ParseIP(eps[0].Endpoints[0].Addresses[0])).NotTo(BeNil(), "Endpoint address was not parseable as an IP")

			var testMaglevMapVal nat.BackendValueInterface
			switch s.family {
			case "ipv4":
				testMaglevMapVal = nat.NewNATBackendValue(net.ParseIP(eps[0].Endpoints[0].Addresses[0]), uint16(tgtPort))
			case "ipv6":
				testMaglevMapVal = nat.NewNATBackendValueV6(net.ParseIP(eps[0].Endpoints[0].Addresses[0]), uint16(tgtPort))
			default:
				log.Panicf("Unexpected IP family %s", s.family)
			}

			log.Info("Waiting for Maglev map to converge...")
			Eventually(maglevMapAnySearchFunc(testMaglevMapVal, s.family, s.tc.Felixes[0]), "10s").ShouldNot(BeNil(), "A maglev map entry never showed up (Felix[0]). Looked for backend: %v", testMaglevMapVal)
			Eventually(maglevMapAnySearchFunc(testMaglevMapVal, s.family, s.tc.Felixes[1]), "10s").ShouldNot(BeNil(), "A maglev map entry never showed up (Felix[1]). Looked for backend: %v", testMaglevMapVal)
			Eventually(maglevMapAnySearchFunc(testMaglevMapVal, s.family, s.tc.Felixes[2]), "10s").ShouldNot(BeNil(), "A maglev map entry never showed up (Felix[2]). Looked for backend: %v", testMaglevMapVal)

			Expect(maglevMapAnySearch(testMaglevMapVal, s.family, s.tc.Felixes[1]).Addr().String()).Should(Equal(s.w[0][0].IP))

			// Configure routes on external client and Felix nodes.
			// Use Felix[1] as a middlebox initially.
			ipRoute := []string{"ip"}
			if s.testOpts.ipv6 {
				ipRoute = append(ipRoute, "-6")
			}

			cmdCleanRt := append(ipRoute, "route", "del", clusterIP)
			_ = s.externalClient.ExecMayFail(strings.Join(cmdCleanRt, ""))
			cmdCleanRt = append(ipRoute, "route", "del", externalIP)
			_ = s.externalClient.ExecMayFail(strings.Join(cmdCleanRt, ""))

			cmdCIP := append(ipRoute, "route", "add", clusterIP, "via", s.felixIP(initialIngressFelix))
			s.externalClient.Exec(cmdCIP...)
			cmdEIP := append(ipRoute, "route", "add", externalIP, "via", s.felixIP(initialIngressFelix))
			s.externalClient.Exec(cmdEIP...)
		})

		It("should have connectivity from external client to maglev backend via cluster IP and external IP", func() {
			probeMaglevLocalConntrackMetricFunc := func(felixes ...*infrastructure.Felix) func() []int {
				return func() []int {
					return probeMaglevConntrackMetric(fmt.Sprintf("felix_bpf_conntrack_maglev_entries_total{destination=\"local\",ip_family=\"%d\"}", familyInt), felixes...)
				}
			}
			probeMaglevRemoteConntrackMetricFunc := func(felixes ...*infrastructure.Felix) func() []int {
				return func() []int {
					return probeMaglevConntrackMetric(fmt.Sprintf("felix_bpf_conntrack_maglev_entries_total{destination=\"remote\",ip_family=\"%d\"}", familyInt), felixes...)
				}
			}

			Eventually(probeMaglevLocalConntrackMetricFunc(s.tc.Felixes...), "10s", "1s").Should(Equal([]int{0, 0, 0}), "Expected maglev local-conntrack metric to start at 0 for all Felixes")
			Eventually(probeMaglevRemoteConntrackMetricFunc(s.tc.Felixes...), "10s", "1s").Should(Equal([]int{0, 0, 0}), "Expected maglev remote-conntrack metric to start at 0 for all Felixes")

			s.cc.ExpectSome(s.externalClient, TargetIP(clusterIP), port)
			s.cc.ExpectSome(s.externalClient, TargetIP(externalIP), port)
			s.cc.CheckConnectivity()

			// There is a 10-second interval between iterations of Felix's conntrack scanner (where we export the maglev conntrack metrics).
			// This means we must be very pessimistic about timeouts when searching for the prom values we're after.
			Eventually(probeMaglevRemoteConntrackMetricFunc(s.tc.Felixes[initialIngressFelix]), "12s", "1s").Should(Equal([]int{2}), "Expected maglev-ingress felix to increment the remote-conntracks metric")
			Eventually(probeMaglevLocalConntrackMetricFunc(s.tc.Felixes[felixWithMaglevBackend]), "12s", "1s").Should(Equal([]int{2}), "Expected felix with maglev backend to increment the local-conntracks metric")
			Consistently(probeMaglevLocalConntrackMetricFunc(s.tc.Felixes[initialIngressFelix])).Should(Equal([]int{0}), "Expected ingress-felix to only have remote maglev conntracks, but saw metric for local maglev conntracks go up")
			Consistently(probeMaglevRemoteConntrackMetricFunc(s.tc.Felixes[felixWithMaglevBackend])).Should(Equal([]int{0}), "Expected backing felix to only have local maglev conntracks, but saw metric for remote maglev conntracks go up")
			Consistently(probeMaglevLocalConntrackMetricFunc(s.tc.Felixes[failoverIngressFelix])).Should(Equal([]int{0}), "No failover occurred, but an unrelated Felix's local maglev prom metrics went up")
			Consistently(probeMaglevRemoteConntrackMetricFunc(s.tc.Felixes[failoverIngressFelix])).Should(Equal([]int{0}), "No failover occurred, but an unrelated Felix's remote maglev prom metrics went up")
		})

		testFailover := func(serviceIP string) {
			By("making a connection over a loadbalancer and then switching off routing to it")
			pc := &PersistentConnection{
				Runtime:              s.externalClient,
				RuntimeName:          s.externalClient.Name,
				IP:                   serviceIP,
				Port:                 int(port),
				SourcePort:           50000,
				Protocol:             s.testOpts.protocol,
				MonitorConnectivity:  true,
				ProbeLoopFileTimeout: 15 * time.Second,
			}
			err := pc.Start()
			Expect(err).NotTo(HaveOccurred())
			defer pc.Stop()

			Eventually(pc.PongCount, "5s", "100ms").Should(BeNumerically(">", 0), "Connection failed")

			backingPodIPAddr := net.ParseIP(s.w[0][0].IP)
			clientIPAddr := net.ParseIP(s.containerIP(s.externalClient))

			ctVal, ctExists := checkConntrackExistsAnyDirection(s.tc.Felixes[1], clientIPAddr, uint16(pc.SourcePort), backingPodIPAddr, uint16(tgtPort), s.family)
			Expect(ctExists).To(BeTrue(), "No conntrack (src->dst / dst->src) existed for the connection on Felix[1]")
			Expect(ctVal.OrigIP().String()).To(Equal(serviceIP), "Unexpected OrigIP on loadbalancer Felix service connection")

			ctVal, ctExists = checkConntrackExistsAnyDirection(s.tc.Felixes[2], clientIPAddr, uint16(pc.SourcePort), backingPodIPAddr, uint16(tgtPort), s.family)
			Expect(ctExists).To(BeFalse(), "Conntrack existed for the connection on Felix[2] before Felix[2] should have handled the connection: %v", ctVal)

			// Traffic is flowing over LB 1. Change ExtClient's serviceIP route to go via LB 2.
			ipRoute := []string{"ip"}
			if s.testOpts.ipv6 {
				ipRoute = append(ipRoute, "-6")
			}
			ipRouteReplace := append(ipRoute, "route", "replace", serviceIP, "via", s.felixIP(2))
			s.externalClient.Exec(ipRouteReplace...)

			lastPongCount := pc.PongCount()

			checkCTExistsFn := func() bool {
				_, ctExists = checkConntrackExistsAnyDirection(s.tc.Felixes[2], clientIPAddr, uint16(pc.SourcePort), backingPodIPAddr, uint16(tgtPort), s.family)
				return ctExists
			}
			Eventually(checkCTExistsFn, "10s").Should(BeTrue(), "Conntrack didn't exist on Felix[2] for failover traffic. Did the failover actually occur?")

			// Check the backing node updated conntrack tun_ip to the new loadbalancer node.
			ctVal, ctExists = checkConntrackExistsAnyDirection(s.tc.Felixes[0], clientIPAddr, uint16(pc.SourcePort), backingPodIPAddr, uint16(tgtPort), s.family)
			Expect(ctExists).To(BeTrue(), "Conntrack didn't exist on backing Felix[0].")
			Expect(ctVal.Data().TunIP.String()).To(Equal(s.felixIP(2)), "Backing node did not update its conntrack tun_ip to the new loadbalancer IP")

			// Connection should persist after the changeover.
			Eventually(pc.PongCount, "5s", "100ms").Should(BeNumerically(">", lastPongCount), "Connection is no longer ponging after route failover")
		}

		It("should maintain connections to a cluster IP across loadbalancer failover using maglev", func() { testFailover(clusterIP) })
		It("should maintain connections to an external IP across loadbalancer failover using maglev", func() { testFailover(externalIP) })
	})

	Describe("Test Load balancer service with external IP", func() {
		if s.testOpts.connTimeEnabled {
			// FIXME s.externalClient also does conntime balancing
			return
		}

		srcIPRange := []string{}
		externalIP := []string{extIP}
		testSvcName := "test-lb-service-extip"
		tgtPort := 8055
		var testSvc *v1.Service
		var ip []string
		var port uint16
		BeforeEach(func() {
			s.externalClient.Exec("ip", "route", "add", extIP, "via", s.felixIP(0))
			testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, s.w[0][0], 80, tgtPort,
				s.testOpts.protocol, externalIP, srcIPRange)
			// when we point Load Balancer to a node in GCE it adds local routes to the external IP on the hosts.
			// Similarity add local routes for externalIP on testContainers.Felix[0], testContainers.Felix[1]
			s.tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			ip = testSvc.Spec.ExternalIPs
			port = uint16(testSvc.Spec.Ports[0].Port)
			s.pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: []string{
							s.containerIP(s.externalClient) + "/" + s.ipMask(),
							s.w[0][1].IP + "/" + s.ipMask(),
							s.w[1][0].IP + "/" + s.ipMask(),
							s.w[1][1].IP + "/" + s.ipMask(),
						},
					},
				},
			}
			s.pol = s.updatePolicy(s.pol)
		})

		It("should have connectivity from workloads[1][0],[1][1], [0][1] and external client via external IP to workload 0", func() {
			s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
			s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
			s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
			s.cc.ExpectSome(s.externalClient, TargetIP(ip[0]), port)
			s.cc.CheckConnectivity()
		})

		It("should handle temporary overlap of external IPs", func() {
			By("Having connectivity to external IP initially")
			s.cc.ExpectSome(s.externalClient, TargetIP(ip[0]), port)
			s.cc.CheckConnectivity()

			By("Adding second service with same external IP")
			clusterIP2 := "10.101.0.11"

			if s.testOpts.ipv6 {
				clusterIP2 = "dead:beef::abcd:0:0:11"
			}
			testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName+"-2", clusterIP2, s.w[0][0], 80, tgtPort,
				s.testOpts.protocol, externalIP, srcIPRange)

			By("Deleting first service")
			err := s.k8sClient.CoreV1().Services(testSvc.Namespace).Delete(context.Background(), testSvcName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Sleeping")
			time.Sleep(20 * time.Second)
			By("And still having connectivity...")
			s.cc.ExpectSome(s.externalClient, TargetIP(ip[0]), port)
			s.cc.CheckConnectivity()
		})
	})

	Context("Test load balancer service with src ranges", func() {
		var testSvc *v1.Service
		tgtPort := 8055
		externalIP := []string{extIP}
		srcIPRange := []string{"10.65.1.3/24"}
		if s.testOpts.ipv6 {
			srcIPRange = []string{"dead:beef::1:3/120"}
		}
		testSvcName := "test-lb-service-extip"
		var ip []string
		var port uint16
		BeforeEach(func() {
			testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, s.w[0][0], 80, tgtPort,
				s.testOpts.protocol, externalIP, srcIPRange)
			s.tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			ip = testSvc.Spec.ExternalIPs
			port = uint16(testSvc.Spec.Ports[0].Port)
		})
		It("should have connectivity from workloads[1][0],[1][1] via external IP to workload 0", func() {
			s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
			s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
			s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)
			s.cc.CheckConnectivity()
		})
	})

	Context("Test load balancer service with no backend", func() {
		if s.testOpts.connTimeEnabled || s.testOpts.udpUnConnected {
			// Skip UDP unconnected, connecttime load balancing cases as s.externalClient also does conntime balancing
			return
		}

		var testSvc *v1.Service
		tgtPort := 8055
		externalIP := []string{extIP}
		srcIPRange := []string{}
		testSvcName := "test-lb-service-extip"
		var port uint16
		var ip []string

		BeforeEach(func() {
			s.externalClient.Exec("ip", "route", "add", extIP, "via", s.felixIP(0))
			// create a service workload as nil, so that the service has no backend
			testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, nil, 80, tgtPort,
				s.testOpts.protocol, externalIP, srcIPRange)
			s.tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			ip = testSvc.Spec.ExternalIPs
			port = uint16(testSvc.Spec.Ports[0].Port)
			s.pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: []string{
							s.externalClient.IP + "/32",
						},
					},
				},
			}
			s.pol = s.updatePolicy(s.pol)
		})

		It("should not have connectivity from external client, and return connection refused", func() {
			icmpProto := "icmp"
			if s.testOpts.ipv6 {
				icmpProto = "icmp6"
			}

			tcpdump := s.externalClient.AttachTCPDump("any")
			tcpdump.SetLogEnabled(true)
			if s.testOpts.ipv6 {
				tcpdump.AddMatcher("unreach", regexp.MustCompile(`destination unreachable`))
				tcpdump.AddMatcher("bad csum", regexp.MustCompile(`bad icmp6 cksum`))
			} else {
				tcpdump.AddMatcher("unreach", regexp.MustCompile(`port \d+ unreachable`))
				tcpdump.AddMatcher("bad csum", regexp.MustCompile(`wrong icmp cksum`))
			}

			tcpdump.Start(s.infra, "-vv", s.testOpts.protocol, "port", strconv.Itoa(int(port)), "or", icmpProto)

			s.cc.Expect(None, s.externalClient, TargetIP(ip[0]),
				ExpectWithPorts(port),
				ExpectNoneWithError("connection refused"),
			)
			s.cc.CheckConnectivity()

			Eventually(func() int { return tcpdump.MatchCount("unreach") }, "5s", "300ms").
				Should(BeNumerically(">", 0))
			// XXX
			// Expect(tcpdump.MatchCount("bad csum")).To(Equal(0))
		})
	})

	Describe("Test load balancer service with external Client,src ranges", func() {
		if s.testOpts.connTimeEnabled {
			// FIXME s.externalClient also does conntime balancing
			return
		}

		var testSvc *v1.Service
		tgtPort := 8055
		externalIP := []string{extIP}
		testSvcName := "test-lb-service-extip"
		var ip []string
		var port uint16
		var srcIPRange []string
		BeforeEach(func() {
			ipRoute := []string{"ip"}
			srcIPRange = []string{"10.65.1.3/24"}
			if s.testOpts.ipv6 {
				ipRoute = append(ipRoute, "-6")
				srcIPRange = []string{"dead:beef::1:3/120"}
			}

			cmd := append(ipRoute[:len(ipRoute):len(ipRoute)],
				"route", "add", extIP, "via", s.felixIP(0))
			s.externalClient.Exec(cmd...)
			s.pol.Spec.Ingress = []api.Rule{
				{
					Action: "Allow",
					Source: api.EntityRule{
						Nets: []string{
							s.containerIP(s.externalClient) + "/" + s.ipMask(),
						},
					},
				},
			}
			s.pol = s.updatePolicy(s.pol)
			cmd = append(ipRoute[:len(ipRoute):len(ipRoute)],
				"route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[1].Exec(cmd...)
			s.tc.Felixes[0].Exec(cmd...)
		})
		Context("Test LB-service with external Client's IP not in src range", func() {
			BeforeEach(func() {
				testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, s.w[0][0], 80, tgtPort,
					s.testOpts.protocol, externalIP, srcIPRange)
				ip = testSvc.Spec.ExternalIPs
				port = uint16(testSvc.Spec.Ports[0].Port)
			})
			It("should not have connectivity from external Client via external IP to workload 0", func() {
				s.cc.ExpectNone(s.externalClient, TargetIP(ip[0]), port)
				s.cc.CheckConnectivity()
			})
		})
		Context("Test LB-service with external Client's IP in src range", func() {
			BeforeEach(func() {
				srcIPRange = []string{s.externalClient.IP + "/32"}
				testSvc = k8sCreateLBServiceWithEndPoints(s.k8sClient, testSvcName, clusterIP, s.w[0][0], 80, tgtPort,
					s.testOpts.protocol, externalIP, srcIPRange)
				ip = testSvc.Spec.ExternalIPs
				port = uint16(testSvc.Spec.Ports[0].Port)
			})
			It("should have connectivity from external Client via external IP to workload 0", func() {
				s.cc.ExpectSome(s.externalClient, TargetIP(ip[0]), port)
				s.cc.CheckConnectivity()
			})
		})
	})

	Context("Test Service type transitions", func() {
		if s.testOpts.protocol != "tcp" {
			// Skip tests for UDP, UDP-Unconnected
			return
		}

		var (
			testSvc          *v1.Service
			testSvcNamespace string
		)
		testSvcName := "test-service"
		tgtPort := 8055
		externalIP := []string{extIP}

		// Create a service of type clusterIP
		BeforeEach(func() {
			testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
				"Service endpoints didn't get created. Is controller-manager happy?")
			s.tc.Felixes[1].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
			s.tc.Felixes[0].Exec("ip", "route", "add", "local", extIP, "dev", "eth0")
		})

		It("should have connectivity from all workloads via a service to workload 0", func() {
			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			w00Expects := []ExpectationOption{ExpectWithPorts(port)}
			hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
			if s.testOpts.ipv6 {
				hostW0SrcIP = ExpectWithSrcIPs(s.felixIP(0))
				switch s.testOpts.tunnel {
				case "vxlan":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
				case "wireguard":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
				}
			}
			switch s.testOpts.tunnel {
			case "ipip":
				hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
			}

			if !s.testOpts.connTimeEnabled {
				w00Expects = append(w00Expects, hostW0SrcIP)
			}

			s.cc.Expect(Some, s.w[0][0], TargetIP(ip), w00Expects...)
			s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
			s.cc.ExpectSome(s.w[1][0], TargetIP(ip), port)
			s.cc.ExpectSome(s.w[1][1], TargetIP(ip), port)
			s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
		})

		/* Below Context handles the following transitions.
		   Cluster IP -> External IP
		   External IP -> LoadBalancer
		   External IP -> NodePort
		   External IP -> Cluster IP
		*/
		Context("change service from cluster IP to external IP", func() {
			var testSvcWithExtIP *v1.Service
			BeforeEach(func() {
				testSvcWithExtIP = k8sServiceWithExtIP(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol, externalIP)
				k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithExtIP)
			})

			It("should have connectivity from all workloads via external IP to workload 0", func() {
				ip := testSvcWithExtIP.Spec.ExternalIPs
				port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
				s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
				s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
				s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
			})
			Context("change service type from external IP to LoadBalancer", func() {
				srcIPRange := []string{}
				var testSvcLB *v1.Service
				BeforeEach(func() {
					testSvcLB = k8sLBService(testSvcName, clusterIP, s.w[0][0].Name, 80, tgtPort, s.testOpts.protocol,
						externalIP, srcIPRange)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcLB)
				})
				It("should have connectivity from workload 0 to service via external IP", func() {
					ip := testSvcLB.Spec.ExternalIPs
					port := uint16(testSvcLB.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)
				})
			})

			Context("change Service type from external IP to nodeport", func() {
				var testSvcNodePort *v1.Service
				npPort := uint16(30333)
				BeforeEach(func() {
					testSvcNodePort = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, int32(npPort), s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcNodePort)
				})
				It("should have connectivity via the node port to workload 0", func() {
					node1IP := s.felixIP(1)
					s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)

					ip := testSvcWithExtIP.Spec.ExternalIPs
					port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
					s.cc.ExpectNone(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.CheckConnectivity()
				})
			})
			Context("change service from external IP to cluster IP", func() {
				var testSvcWithoutExtIP *v1.Service
				BeforeEach(func() {
					testSvcWithoutExtIP = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithoutExtIP)
				})
				It("should not have connectivity to workload 0 via external IP", func() {
					ip := testSvcWithExtIP.Spec.ExternalIPs
					port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
					s.cc.ExpectNone(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)

					clusterIP = testSvcWithoutExtIP.Spec.ClusterIP
					s.cc.ExpectSome(s.w[0][1], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(clusterIP), port)
					s.cc.CheckConnectivity()
				})
			})
		})

		/* Below Context handles the following transitions.
		   Cluster IP -> LoadBalancer
		   LoadBalancer -> External IP
		   LoadBalancer -> NodePort
		   LoadBalancer -> Cluster IP
		*/
		Context("change service type to LoadBalancer", func() {
			srcIPRange := []string{}
			var testSvcLB *v1.Service
			BeforeEach(func() {
				testSvcLB = k8sLBService(testSvcName, clusterIP, s.w[0][0].Name, 80, tgtPort, s.testOpts.protocol,
					externalIP, srcIPRange)
				k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcLB)
			})
			It("should have connectivity from workload 0 to service via external IP", func() {
				ip := testSvcLB.Spec.ExternalIPs
				port := uint16(testSvcLB.Spec.Ports[0].Port)
				s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
				s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
				s.cc.CheckConnectivity()
			})

			Context("change service from Loadbalancer to external IP", func() {
				var testSvcWithExtIP *v1.Service
				BeforeEach(func() {
					testSvcWithExtIP = k8sServiceWithExtIP(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol, externalIP)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithExtIP)
				})

				It("should have connectivity from all workloads via external IP to workload 0", func() {
					ip := testSvcWithExtIP.Spec.ExternalIPs
					port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.CheckConnectivity()
				})
			})

			Context("change Service type from Loadbalancer to nodeport", func() {
				var testSvcNodePort *v1.Service
				npPort := uint16(30333)
				BeforeEach(func() {
					testSvcNodePort = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, int32(npPort), s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcNodePort)
				})
				It("should have connectivity via the node port to workload 0 and not via external IP", func() {
					ip := testSvcLB.Spec.ExternalIPs
					port := uint16(testSvcLB.Spec.Ports[0].Port)
					s.cc.ExpectNone(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)
					node1IP := s.felixIP(1)
					s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)
					s.cc.CheckConnectivity()
				})
			})
			Context("Change service type from LoadBalancer to cluster IP", func() {
				var testSvcClusterIP *v1.Service
				BeforeEach(func() {
					testSvcClusterIP = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcClusterIP)
				})
				It("should have connectivity to workload 0 via cluster IP and not external IP", func() {
					ip := testSvcLB.Spec.ExternalIPs
					port := uint16(testSvcLB.Spec.Ports[0].Port)
					s.cc.ExpectNone(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectNone(s.w[0][1], TargetIP(ip[0]), port)

					clusterIP = testSvcClusterIP.Spec.ClusterIP

					s.cc.ExpectSome(s.w[0][1], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(clusterIP), port)
					s.cc.CheckConnectivity()
				})
			})
		})

		/* Below Context handles the following transitions.
		   Cluster IP -> NodePort
		   NodePort -> External IP
		   NodePort -> LoadBalancer
		   NodePort -> Cluster IP
		*/
		Context("change Service type to nodeport", func() {
			var testSvcNodePort *v1.Service
			npPort := uint16(30333)
			BeforeEach(func() {
				testSvcNodePort = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, int32(npPort), s.testOpts.protocol)
				k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcNodePort)
			})
			It("should have connectivity via the node port to workload 0", func() {
				node1IP := s.felixIP(1)
				node1IPExt := s.tc.Felixes[1].ExternalIP
				s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)
				s.cc.ExpectSome(s.w[0][1], TargetIP(node1IPExt), npPort)
				s.cc.ExpectSome(s.w[1][0], TargetIP(node1IPExt), npPort)
				s.cc.ExpectSome(s.w[1][1], TargetIP(node1IPExt), npPort)
				s.cc.CheckConnectivity()
			})

			Context("change service type from nodeport to external IP", func() {
				var testSvcWithExtIP *v1.Service
				BeforeEach(func() {
					testSvcWithExtIP = k8sServiceWithExtIP(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol, externalIP)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcWithExtIP)
				})
				It("should have connectivity via external IP to workload 0 and not node port", func() {
					ip := testSvcWithExtIP.Spec.ExternalIPs
					port := uint16(testSvcWithExtIP.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)

					node1IP := s.felixIP(1)
					s.cc.ExpectNone(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectNone(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectNone(s.w[1][1], TargetIP(node1IP), npPort)
					s.cc.CheckConnectivity()
				})
			})
			Context("change service type from nodeport to LoadBalancer", func() {
				srcIPRange := []string{}
				var testSvcLB *v1.Service
				BeforeEach(func() {
					testSvcLB = k8sLBService(testSvcName, clusterIP, s.w[0][0].Name, 80, tgtPort, s.testOpts.protocol,
						externalIP, srcIPRange)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcLB)
				})
				It("should have connectivity from workload 0 to service via external IP and via nodeport", func() {
					node1IP := s.felixIP(1)

					// Note: the behaviour expected here changed around k8s v1.20.  Previously, the API
					// server would allocate a new node port when we applied the load balancer update.
					// Now, it merges the two so the service keeps its existing NodePort.
					s.cc.ExpectSome(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectSome(s.w[1][1], TargetIP(node1IP), npPort)

					// Either way, we expect the load balancer to show up.
					ip := testSvcLB.Spec.ExternalIPs
					port := uint16(testSvcLB.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(ip[0]), port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(ip[0]), port)
					s.cc.CheckConnectivity()
				})
			})
			Context("Change service type from nodeport to cluster IP", func() {
				var testSvcClusterIP *v1.Service
				BeforeEach(func() {
					testSvcClusterIP = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
					k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvcClusterIP)
				})
				It("should have connectivity to workload 0 via cluster IP and not via nodeport", func() {
					node1IP := s.felixIP(1)
					s.cc.ExpectNone(s.w[0][1], TargetIP(node1IP), npPort)
					s.cc.ExpectNone(s.w[1][0], TargetIP(node1IP), npPort)
					s.cc.ExpectNone(s.w[1][1], TargetIP(node1IP), npPort)

					clusterIP = testSvcClusterIP.Spec.ClusterIP
					port := uint16(testSvcClusterIP.Spec.Ports[0].Port)
					s.cc.ExpectSome(s.w[0][1], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][0], TargetIP(clusterIP), port)
					s.cc.ExpectSome(s.w[1][1], TargetIP(clusterIP), port)
					s.cc.CheckConnectivity()
				})
			})
		})
	})

	Context("with test-service configured "+clusterIP+":80 -> s.w[0][0].IP:8055", func() {
		var (
			testSvc          *v1.Service
			testSvcNamespace string
		)

		testSvcName := "test-service"
		tgtPort := 8055

		BeforeEach(func() {
			testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, tgtPort, 0, s.testOpts.protocol)
			testSvcNamespace = testSvc.Namespace
			_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
				"Service endpoints didn't get created. Is controller-manager happy?")
		})

		It("should have connectivity from all workloads via a service to workload 0", func() {
			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			w00Expects := []ExpectationOption{ExpectWithPorts(port)}
			hostW0SrcIP := ExpectWithSrcIPs(s.felixIP(0))
			if s.testOpts.ipv6 {
				hostW0SrcIP = ExpectWithSrcIPs(s.felixIP(0))
				switch s.testOpts.tunnel {
				case "vxlan":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedVXLANV6TunnelAddr)
				case "wireguard":
					hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedWireguardV6TunnelAddr)
				}
			}
			switch s.testOpts.tunnel {
			case "ipip":
				hostW0SrcIP = ExpectWithSrcIPs(s.tc.Felixes[0].ExpectedIPIPTunnelAddr)
			}

			if !s.testOpts.connTimeEnabled {
				w00Expects = append(w00Expects, hostW0SrcIP)
			}

			s.cc.Expect(Some, s.w[0][0], TargetIP(ip), w00Expects...)
			s.cc.Expect(Some, s.w[0][1], TargetIP(ip), ExpectWithPorts(port))
			s.cc.Expect(Some, s.w[1][0], TargetIP(ip), ExpectWithPorts(port))
			s.cc.Expect(Some, s.w[1][1], TargetIP(ip), ExpectWithPorts(port))
			s.cc.CheckConnectivity()
		})

		It("should only have connectivity from the local host via a service to workload 0", func() {
			// Local host is always allowed (for kubelet health checks).
			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			s.cc.ExpectSome(s.tc.Felixes[0], TargetIP(ip), port)
			s.cc.ExpectNone(s.tc.Felixes[1], TargetIP(ip), port)
			s.cc.CheckConnectivity()
		})

		Describe("after updating the policy to allow traffic from hosts", func() {
			BeforeEach(func() {
				s.pol.Spec.Ingress = []api.Rule{
					{
						Action: "Allow",
						Source: api.EntityRule{
							Selector: "ep-type == 'host'",
						},
					},
				}
				s.pol = s.updatePolicy(s.pol)
			})

			It("should have connectivity from the hosts via a service to workload 0", func() {
				ip := testSvc.Spec.ClusterIP
				port := uint16(testSvc.Spec.Ports[0].Port)

				s.cc.ExpectSome(s.tc.Felixes[0], TargetIP(ip), port)
				s.cc.ExpectSome(s.tc.Felixes[1], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][0], TargetIP(ip), port)
				s.cc.CheckConnectivity()
			})
		})

		It("should have connectivity from workload via a service IP to a host-process listening on that IP", func() {
			By("Setting up a dummy service " + excludeSvcIP)
			svc := k8sService("dummy-service", excludeSvcIP, s.w[0][0] /* unimportant */, 8066, 8077, 0, s.testOpts.protocol)
			svc.Annotations = map[string]string{
				proxy.ExcludeServiceAnnotation: "true",
			}
			_, err := s.k8sClient.CoreV1().Services(testSvc.Namespace).
				Create(context.Background(), svc, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			natFtKey := fmt.Sprintf("%s port %d proto %d", excludeSvcIP, 8066, s.numericProto)
			Eventually(func() map[string][]string {
				return s.tc.Felixes[0].BPFNATDump(s.testOpts.ipv6)
			}, "5s", "300ms").Should(HaveKey(natFtKey))

			By("Adding the service IP to the host")
			// Sort of what node-local-dns does
			s.tc.Felixes[0].Exec("ip", "link", "add", "dummy1", "type", "dummy")
			s.tc.Felixes[0].Exec("ip", "link", "set", "dummy1", "up")
			s.tc.Felixes[0].Exec("ip", "addr", "add", excludeSvcIP+"/"+s.ipMask(), "dev", "dummy1")

			By("Starting host workload")
			hostW := workload.Run(s.tc.Felixes[0], "dummy", "default",
				excludeSvcIP, "8066", s.testOpts.protocol, workload.WithHostNetworked())
			defer hostW.Stop()

			s.cc.Expect(Some, s.w[0][0], TargetIP(excludeSvcIP), ExpectWithPorts(8066))
			s.cc.CheckConnectivity()
		})

		It("should create sane conntrack entries and clean them up", func() {
			By("Generating some traffic")
			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
			s.cc.ExpectSome(s.w[1][0], TargetIP(ip), port)
			s.cc.CheckConnectivity(conntrackChecks(s.tc.Felixes)...)

			By("Checking timestamps on conntrack entries are sane")
			// This test verifies that we correctly interpret conntrack entry timestamps by reading them back
			// and checking that they're (a) in the past and (b) sensibly recent.
			var (
				err    error
				ctDump string
			)

			if s.testOpts.ipv6 {
				ctDump, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "-6", "dump", "--raw")
			} else {
				ctDump, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "dump", "--raw")
			}
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
				if s.testOpts.ipv6 {
					ctDump, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "-6", "dump", "--raw")
				} else {
					ctDump, err = s.tc.Felixes[0].ExecOutput("calico-bpf", "conntrack", "dump", "--raw")
				}
				Expect(err).NotTo(HaveOccurred())
				return strings.Count(ctDump, s.w[0][0].IP)
			}

			startingCTEntries := numWl0ConntrackEntries()
			Expect(startingCTEntries).To(BeNumerically(">", 0))

			// TODO reduce timeouts just for this test.
			Eventually(numWl0ConntrackEntries, "180s", "5s").Should(BeNumerically("<", startingCTEntries))
		})

		Context("with test-service port updated", func() {
			var (
				testSvcUpdated      *v1.Service
				natBackBeforeUpdate []map[nat.BackendKey]nat.BackendValueInterface
				natBeforeUpdate     []map[nat.FrontendKeyInterface]nat.FrontendValue
			)

			BeforeEach(func() {
				family := 4

				var oldK nat.FrontendKeyInterface

				ip := testSvc.Spec.ClusterIP
				portOld := uint16(testSvc.Spec.Ports[0].Port)

				if s.testOpts.ipv6 {
					family = 6
					ipv6 := net.ParseIP(ip)
					oldK = nat.NewNATKeyV6(ipv6, portOld, s.numericProto)
				} else {
					ipv4 := net.ParseIP(ip)
					oldK = nat.NewNATKey(ipv4, portOld, s.numericProto)
				}

				// Wait for the NAT maps to converge...
				log.Info("Waiting for NAT maps to converge...")
				startTime := time.Now()
				for {
					if time.Since(startTime) > 5*time.Second {
						Fail("NAT maps failed to converge")
					}
					natBeforeUpdate, natBackBeforeUpdate, _ = dumpNATmapsAny(family, s.tc.Felixes)
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

					log.Infof("NAT maps converge took %v", time.Since(startTime))
					break
				retry:
					time.Sleep(100 * time.Millisecond)
					log.Info("NAT maps converge retry")
				}
				log.Info("NAT maps converged.")

				testSvcUpdated = k8sService(testSvcName, clusterIP, s.w[0][0], 88, 8055, 0, s.testOpts.protocol)

				svc, err := s.k8sClient.CoreV1().
					Services(testSvcNamespace).
					Get(context.Background(), testSvcName, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				testSvcUpdated.ResourceVersion = svc.ResourceVersion

				_, err = s.k8sClient.CoreV1().Services(testSvcNamespace).Update(context.Background(), testSvcUpdated, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
					"Service endpoints didn't get created. Is controller-manager happy?")
			})

			It("should have connectivity from all workloads via the new port", func() {
				ip := testSvcUpdated.Spec.ClusterIP
				port := uint16(testSvcUpdated.Spec.Ports[0].Port)

				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectSome(s.w[1][0], TargetIP(ip), port)
				s.cc.ExpectSome(s.w[1][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()
			})

			It("should not have connectivity from all workloads via the old port", func() {
				family := 4

				var oldK, natK nat.FrontendKeyInterface

				ip := testSvc.Spec.ClusterIP
				port := uint16(testSvc.Spec.Ports[0].Port)

				s.cc.ExpectNone(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][0], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()

				portOld := uint16(testSvc.Spec.Ports[0].Port)
				portNew := uint16(testSvcUpdated.Spec.Ports[0].Port)

				if s.testOpts.ipv6 {
					family = 6
					ipv6 := net.ParseIP(ip)
					oldK = nat.NewNATKeyV6(ipv6, portOld, s.numericProto)
					natK = nat.NewNATKeyV6(ipv6, portNew, s.numericProto)
				} else {
					ipv4 := net.ParseIP(ip)
					oldK = nat.NewNATKey(ipv4, portOld, s.numericProto)
					natK = nat.NewNATKey(ipv4, portNew, s.numericProto)
				}

				natmaps, natbacks, _ := dumpNATmapsAny(family, s.tc.Felixes)

				for i := range s.tc.Felixes {
					Expect(natmaps[i]).To(HaveKey(natK))
					Expect(natmaps[i]).NotTo(HaveKey(oldK))

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
				var natK nat.FrontendKeyInterface

				ip := testSvcUpdated.Spec.ClusterIP
				port := uint16(testSvcUpdated.Spec.Ports[0].Port)

				family := 4
				if s.testOpts.ipv6 {
					family = 6
					natK = nat.NewNATKeyV6(net.ParseIP(ip), port, s.numericProto)
				} else {
					natK = nat.NewNATKey(net.ParseIP(ip), port, s.numericProto)
				}

				var prevBpfsvcs []map[nat.FrontendKeyInterface]nat.FrontendValue

				Eventually(func() bool {
					prevBpfsvcs, _, _ = dumpNATmapsAny(family, s.tc.Felixes)
					for _, m := range prevBpfsvcs {
						if _, ok := m[natK]; !ok {
							return false
						}
					}
					return true
				}, "5s").Should(BeTrue(), "service NAT key didn't show up")

				err := s.k8sClient.CoreV1().
					Services(testSvcNamespace).
					Delete(context.Background(), testSvcName, metav1.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(0))

				s.cc.ExpectNone(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][0], TargetIP(ip), port)
				s.cc.ExpectNone(s.w[1][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()

				for i, f := range s.tc.Felixes {
					natV := prevBpfsvcs[i][natK]
					bckCnt := natV.Count()
					bckID := natV.ID()

					Eventually(func() bool {
						svcs, eps, _ := dumpNATMapsAny(family, f)

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

	Context("with test-service configured "+clusterIP+":80 -> w[*][0].IP:8055", func() {
		testMultiBackends := func(setAffinity bool) {
			var (
				testSvc          *v1.Service
				testSvcNamespace string
			)

			testSvcName := "test-service"

			BeforeEach(func() {
				testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, 8055, 0, s.testOpts.protocol)
				testSvcNamespace = testSvc.Namespace
				// select all pods with port 8055
				testSvc.Spec.Selector = map[string]string{"port": "8055"}
				if setAffinity {
					testSvc.Spec.SessionAffinity = "ClientIP"
				}
				_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				// We have 3 backends all listening on port 8055.
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(3),
					"Service endpoints didn't get created? Is controller-manager happy?")
			})

			// Since the affinity map is shared by cgroup programs on
			// all nodes, we must be careful to use only client(s) on a
			// single node for the experiments.
			It("should have connectivity from a workload to a service with multiple backends", func() {
				affKV := func() (nat.AffinityKeyInterface, nat.AffinityValueInterface) {
					if s.testOpts.ipv6 {
						aff := dumpAffMapV6(s.tc.Felixes[0])
						ExpectWithOffset(1, aff).To(HaveLen(1))

						// get the only key
						for k, v := range aff {
							return k, v
						}
					} else {
						aff := dumpAffMap(s.tc.Felixes[0])
						ExpectWithOffset(1, aff).To(HaveLen(1))

						// get the only key
						for k, v := range aff {
							return k, v
						}
					}

					Fail("no value in aff map")
					return nil, nil
				}

				ip := testSvc.Spec.ClusterIP
				port := uint16(testSvc.Spec.Ports[0].Port)

				if setAffinity {
					// Sync with NAT tables to prevent creating extra entry when
					// CTLB misses but regular DNAT hits, but connection fails and
					// then CTLB succeeds.
					var (
						family   int
						natFtKey nat.FrontendKeyInterface
					)

					if s.testOpts.ipv6 {
						natFtKey = nat.NewNATKeyV6Intf(net.ParseIP(ip), port, s.numericProto)
						family = 6
					} else {
						natFtKey = nat.NewNATKeyIntf(net.ParseIP(ip), port, s.numericProto)
						family = 4
					}

					Eventually(func() bool {
						m, be, _ := dumpNATMapsAny(family, s.tc.Felixes[0])

						v, ok := m[natFtKey]
						if !ok || v.Count() == 0 {
							return false
						}

						beKey := nat.NewNATBackendKey(v.ID(), 0)

						_, ok = be[beKey]
						return ok
					}, 5*time.Second).Should(BeTrue())
				}

				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()

				_, val1 := affKV()

				s.cc.CheckConnectivity()

				_, v2 := affKV()

				// This should happen consistently, but that may take quite some time.
				Expect(val1.Backend()).To(Equal(v2.Backend()))

				s.cc.ResetExpectations()

				// N.B. Client must be on felix-0 to be subject to ctlb!
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
				s.cc.CheckConnectivity()

				mkey, mVal := affKV()
				Expect(val1.Backend()).To(Equal(mVal.Backend()))

				netIP := net.ParseIP(ip)
				if s.testOpts.ipv6 {
					Expect(mkey.FrontendAffinityKey().AsBytes()).
						To(Equal(nat.NewNATKeyV6(netIP, port, s.numericProto).AsBytes()[4:24]))
				} else {
					Expect(mkey.FrontendAffinityKey().AsBytes()).
						To(Equal(nat.NewNATKey(netIP, port, s.numericProto).AsBytes()[4:12]))
				}

				Eventually(func() nat.BackendValueInterface {
					// Remove the affinity entry to emulate timer
					// expiring / no prior affinity.
					var m maps.Map
					if s.testOpts.ipv6 {
						m = nat.AffinityMapV6()
					} else {
						m = nat.AffinityMap()
					}
					cmd, err := maps.MapDeleteKeyCmd(m, mkey.AsBytes())
					Expect(err).NotTo(HaveOccurred())
					err = s.tc.Felixes[0].ExecMayFail(cmd...)
					if err != nil {
						Expect(err.Error()).To(ContainSubstring("No such file or directory"))
					}

					if s.testOpts.ipv6 {
						aff := dumpAffMapV6(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(0))

						s.cc.CheckConnectivity()

						aff = dumpAffMapV6(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(1))
						Expect(aff).To(HaveKey(mkey.(nat.AffinityKeyV6)))

						return aff[mkey.(nat.AffinityKeyV6)].Backend()
					}

					if s.testOpts.ipv6 {
						aff := dumpAffMapV6(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(0))
					} else {
						aff := dumpAffMap(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(0))
					}

					s.cc.CheckConnectivity()

					if s.testOpts.ipv6 {
						aff := dumpAffMapV6(s.tc.Felixes[0])
						Expect(aff).To(HaveLen(1))
						Expect(aff).To(HaveKey(mkey.(nat.AffinityKeyV6)))
						return aff[mkey.(nat.AffinityKeyV6)].Backend()
					}

					aff := dumpAffMap(s.tc.Felixes[0])
					Expect(aff).To(HaveLen(1))
					Expect(aff).To(HaveKey(mkey.(nat.AffinityKey)))
					return aff[mkey.(nat.AffinityKey)].Backend()
				}, 60*time.Second, time.Second).ShouldNot(Equal(mVal.Backend()))
			})
		}

		Context("with affinity", func() {
			testMultiBackends(true)
		})

		if s.testOpts.protocol == "udp" && s.testOpts.udpUnConnected && s.testOpts.connTimeEnabled {
			// We enforce affinity for unconnected UDP
			Context("without affinity", func() {
				testMultiBackends(false)
			})
		}

		It("should have connectivity with affinity after a backend is gone", func() {
			var (
				testSvc          *v1.Service
				testSvcNamespace string
				family           int
				natFtKey         nat.FrontendKeyInterface
			)

			testSvcName := "test-service"

			By("Setting up the service", func() {
				testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, 8055, 0, s.testOpts.protocol)
				testSvcNamespace = testSvc.Namespace
				// select all pods with port 8055
				testSvc.Spec.Selector = map[string]string{"port": "8055"}
				testSvc.Spec.SessionAffinity = "ClientIP"
				_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(3),
					"Service endpoints didn't get created? Is controller-manager happy?")
			})

			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			By("Syncing with NAT tables", func() {
				// Sync with NAT tables to prevent creating extra entry when
				// CTLB misses but regular DNAT hits, but connection fails and
				// then CTLB succeeds.
				if s.testOpts.ipv6 {
					natFtKey = nat.NewNATKeyV6(net.ParseIP(ip), port, s.numericProto)
					family = 6
				} else {
					natFtKey = nat.NewNATKey(net.ParseIP(ip), port, s.numericProto)
					family = 4
				}
				Eventually(func() bool {
					m, be, _ := dumpNATMapsAny(family, s.tc.Felixes[0])
					v, ok := m[natFtKey]
					if !ok || v.Count() == 0 {
						return false
					}

					beKey := nat.NewNATBackendKey(v.ID(), 0)

					_, ok = be[beKey]
					return ok
				}, 5*time.Second).Should(BeTrue())
			})

			By("make connection to a service and set affinity")
			s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
			s.cc.CheckConnectivity()

			By("checking that affinity was created")
			if s.testOpts.ipv6 {
				aff := dumpAffMapV6(s.tc.Felixes[0])
				Expect(aff).To(HaveLen(1))
			} else {
				aff := dumpAffMap(s.tc.Felixes[0])
				Expect(aff).To(HaveLen(1))
			}

			// Stop the original backends so that they are not
			// reachable with the set affinity.
			s.w[0][0].Stop()
			s.w[1][0].Stop()

			By("changing the service backend to completely different ones")
			testSvc8056 := k8sService(testSvcName, clusterIP, s.w[1][1], 80, 8056, 0, s.testOpts.protocol)
			testSvc8056.Spec.SessionAffinity = "ClientIP"
			k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvc8056)

			By("checking the affinity is cleaned up")
			Eventually(func() int {
				if s.testOpts.ipv6 {
					aff := dumpAffMapV6(s.tc.Felixes[0])
					return len(aff)
				} else {
					aff := dumpAffMap(s.tc.Felixes[0])
					return len(aff)
				}
			}).Should(Equal(0))

			By("making another connection to a new backend")
			ip = testSvc.Spec.ClusterIP
			port = uint16(testSvc.Spec.Ports[0].Port)

			s.cc.ResetExpectations()
			ip = testSvc8056.Spec.ClusterIP
			port = uint16(testSvc8056.Spec.Ports[0].Port)

			s.cc.ExpectSome(s.w[0][1], TargetIP(ip), port)
			s.cc.CheckConnectivity()
		})

		It("should have connectivity after a backend is replaced by a new one", func() {
			if s.testOpts.protocol == "udp" && s.testOpts.connTimeEnabled {
				return
			}
			var (
				testSvc          *v1.Service
				testSvcNamespace string
			)

			testSvcName := "test-service"

			By("Setting up the service", func() {
				testSvc = k8sService(testSvcName, clusterIP, s.w[0][0], 80, 8055, 0, s.testOpts.protocol)
				testSvcNamespace = testSvc.Namespace
				_, err := s.k8sClient.CoreV1().Services(testSvcNamespace).Create(context.Background(), testSvc, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Eventually(checkSvcEndpoints(s.k8sClient, testSvc), "10s").Should(Equal(1),
					"Service endpoints didn't get created? Is controller-manager happy?")
			})

			ip := testSvc.Spec.ClusterIP
			port := uint16(testSvc.Spec.Ports[0].Port)

			By("Syncing with NAT tables", func() {
				// Sync with NAT tables to prevent creating extra entry when
				// CTLB misses but regular DNAT hits, but connection fails and
				// then CTLB succeeds.
				var (
					natFtKey nat.FrontendKeyInterface
					family   int
				)

				if s.testOpts.ipv6 {
					natFtKey = nat.NewNATKeyV6(net.ParseIP(ip), port, s.numericProto)
					family = 6
				} else {
					natFtKey = nat.NewNATKey(net.ParseIP(ip), port, s.numericProto)
					family = 4
				}
				Eventually(func() bool {
					m, be, _ := dumpNATMapsAny(family, s.tc.Felixes[1])

					v, ok := m[natFtKey]
					if !ok || v.Count() == 0 {
						return false
					}

					beKey := nat.NewNATBackendKey(v.ID(), 0)

					_, ok = be[beKey]
					return ok
				}, 5*time.Second).Should(BeTrue())
			})

			By("Making sure that backend is ready")
			s.cc.Expect(Some, s.w[1][1], s.w[0][0], ExpectWithPorts(8055))
			s.cc.CheckConnectivity()

			By("Starting a persistent connection to the service")
			pc := s.w[1][1].StartPersistentConnection(ip, int(port),
				workload.PersistentConnectionOpts{
					MonitorConnectivity: true,
					Timeout:             60 * time.Second,
				},
			)
			if s.testOpts.protocol != "tcp" {
				defer pc.Stop()
			}

			By("Testing connectivity")
			prevCount := pc.PongCount()
			Eventually(pc.PongCount, "5s").Should(BeNumerically(">", prevCount),
				"Expected to see pong responses on the connection but didn't receive any")

			By("changing the service backend to completely different ones")
			testSvc2 := k8sService(testSvcName, clusterIP, s.w[1][0], 80, 8055, 0, s.testOpts.protocol)
			k8sUpdateService(s.k8sClient, testSvcNamespace, testSvcName, testSvc, testSvc2)

			var tcpd *tcpdump.TCPDump
			if s.testOpts.protocol == "tcp" {
				iface := s.w[1][1].InterfaceName
				srcIP := clusterIP
				tcpdHost := s.tc.Felixes[1]
				if s.testOpts.connTimeEnabled {
					iface = "eth0"
					switch s.testOpts.tunnel {
					case "vxlan":
						iface = "vxlan.calico"
					case "wireguard":
						iface = "wireguard.cali"
						if s.testOpts.ipv6 {
							iface = "wireguard.cali-v6"
						}
					case "ipip":
						iface = "tunl0"
					}
					srcIP = s.w[0][0].IP
					tcpdHost = s.tc.Felixes[0]
				}
				tcpd = tcpdHost.AttachTCPDump(iface)
				tcpd.SetLogEnabled(true)

				ipRegex := "IP"
				if s.testOpts.ipv6 {
					ipRegex = "IP6"
				}
				tcpd.AddMatcher("tcp-rst",
					regexp.MustCompile(fmt.Sprintf(`%s %s\.\d+ > %s\.\d+: Flags \[[^\]]*R[^\]]*\]`, ipRegex, srcIP, s.w[1][1].IP)))
				tcpd.Start(s.infra)
			}

			By("Stopping the original backend to make sure it is not reachable")
			s.w[0][0].Stop()
			By("removing the old workload from infra")
			s.w[0][0].RemoveFromInfra(s.infra)

			By("Testing connectivity continues")
			if s.testOpts.protocol == "tcp" {
				Eventually(func() int { return tcpd.MatchCount("tcp-rst") }, "25s").ShouldNot(BeZero(),
					"Expected to see TCP RSTs on the connection after backend change")
				Expect(pc.IsConnectionReset()).To(BeTrue())
			} else {
				prevCount = pc.PongCount()
				Eventually(pc.PongCount, "15s").Should(BeNumerically(">", prevCount),
					"Expected to see pong responses on the connection but didn't receive any")
			}
		})
	})

}
