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

package proxy_test

import (
	"fmt"
	"net"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/mock"
	"github.com/projectcalico/calico/felix/bpf/nat"
	proxy "github.com/projectcalico/calico/felix/bpf/proxy"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
)

func init() {
	logrus.SetOutput(GinkgoWriter)
	logrus.SetLevel(logrus.DebugLevel)
}

var _ = Describe("BPF Syncer", func() {
	var (
		svcs *mockNATMap
		eps  *mockNATBackendMap
		aff  *mockAffinityMap
		ct   *mock.Map

		s        *proxy.Syncer
		connScan *conntrack.Scanner
		state    proxy.DPSyncerState
		rt       *proxy.RTCache
	)

	nodeIPs := []net.IP{net.IPv4(192, 168, 0, 1), net.IPv4(10, 123, 0, 1)}

	svcKey := k8sp.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "test-service",
		},
	}

	BeforeEach(func() {
		svcs = newMockNATMap()
		eps = newMockNATBackendMap()
		aff = newMockAffinityMap()
		ct = mock.NewMockMap(conntrack.MapParams)

		rt = proxy.NewRTCache()

		s, _ = proxy.NewSyncer(4, nodeIPs, svcs, eps, aff, rt, nil)

		ep := proxy.NewEndpointInfo("10.1.0.1", 5555, proxy.EndpointInfoOptIsReady(true))
		state = proxy.DPSyncerState{
			SvcMap: k8sp.ServicePortMap{
				svcKey: proxy.NewK8sServicePort(
					net.IPv4(10, 0, 0, 1),
					1234,
					v1.ProtocolTCP,
				),
			},
			EpsMap: k8sp.EndpointsMap{
				svcKey: []k8sp.Endpoint{ep},
			},
		}
	})

	makestep := func(step func()) func() {
		return func() {
			defer func() {
				log("svcs = %+v\n", svcs)
				log("eps = %+v\n", eps)
			}()

			step()
		}
	}

	It("should make the right test transitions", func() {
		By("inserting a service with endpoint", makestep(func() {
			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(1))
			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 1), 1234, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(1)))
			Expect(val.AffinityTimeout()).To(Equal(time.Duration(0)))

			Expect(eps.m).To(HaveLen(1))
			bval, ok := eps.m[nat.NewNATBackendKey(val.ID(), 0)]
			Expect(ok).To(BeTrue())
			Expect(bval).To(Equal(nat.NewNATBackendValue(net.IPv4(10, 1, 0, 1), 5555)))
		}))

		svcKey2 := k8sp.ServicePortName{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "second-service",
			},
		}
		svcKey3 := k8sp.ServicePortName{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "third-service",
			},
		}

		svcKey4 := k8sp.ServicePortName{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "fourth-service",
			},
		}

		By("inserting another service with multiple endpoints", makestep(func() {
			state.SvcMap[svcKey2] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
			)
			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.0.0", 1111),
				proxy.NewEndpointInfo("10.2.0.1", 1111, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.2.0.1", 2222, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.2.0.3", 1111),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(2))
			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 1), 1234, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(1)))
			val, ok = svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(2)))

			Expect(eps.m).To(HaveLen(3))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val.ID(), 1)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 1111)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
		}))

		By("creating a CT scanner", func() {
			connScan = conntrack.NewScanner(ct,
				conntrack.KeyFromBytes, conntrack.ValueFromBytes, nil, "Disabled", conntrack.NewStaleNATScanner(s))
		})

		By("creating conntrack entries for test-service", makestep(func() {
			svc := state.SvcMap[svcKey]
			ep := state.EpsMap[svcKey][0]
			ctEntriesForSvc(ct, svc.Protocol(), svc.ClusterIP(), uint16(svc.Port()), ep, net.IPv4(5, 6, 7, 8), 123)
		}))

		By("creating conntrack entries for second-service", makestep(func() {
			svc := state.SvcMap[svcKey2]
			ep := state.EpsMap[svcKey2][1]
			ctEntriesForSvc(ct, svc.Protocol(), svc.ClusterIP(), uint16(svc.Port()), ep, net.IPv4(5, 6, 7, 8), 123)
			ep = state.EpsMap[svcKey2][2]
			ctEntriesForSvc(ct, svc.Protocol(), svc.ClusterIP(), uint16(svc.Port()), ep, net.IPv4(5, 6, 7, 8), 321)
		}))

		By("deleting the test-service", makestep(func() {
			delete(state.SvcMap, svcKey)
			delete(state.EpsMap, svcKey)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(1))
			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(2)))

			Expect(eps.m).To(HaveLen(2))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val.ID(), 1)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 1111)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
		}))

		By("creating UDP CT entry to somethng not a service", func() {
			key := conntrack.NewKey(conntrack.ProtoUDP, net.IPv4(10, 66, 0, 1), 12345, net.IPv4(20, 0, 0, 111), 30666)
			val := conntrack.NewValueNormal(0, 0, conntrack.Leg{}, conntrack.Leg{})
			err := ct.Update(key.AsBytes(), val.AsBytes())
			Expect(err).NotTo(HaveOccurred(), "Test failed to populate ct map")
		})

		By("checking that a CT entry pair is cleaned up by connScan, the UDP normal entry remains", makestep(func() {

			connScan.Scan()

			cnt := 0

			err := ct.Iter(func(k, v []byte) maps.IteratorAction {
				cnt++
				key := conntrack.KeyFromBytes(k)
				val := conntrack.ValueFromBytes(v)
				log("key = %s\n", key)
				log("val = %s\n", val)
				return maps.IterNone
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(cnt).To(Equal(5))
		}))

		udpSvcKey := k8sp.ServicePortName{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "udp-service",
			},
		}

		By("creating a UDP service", makestep(func() {
			state.SvcMap[udpSvcKey] = proxy.NewK8sServicePort(
				net.IPv4(20, 0, 0, 111),
				30666,
				v1.ProtocolUDP,
			)
			// Needs at least one endpoint to be considered and active service
			state.EpsMap[udpSvcKey] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.6.0.0", 1666, proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
		}))

		By("checking that the UDP normal entry gets cleaned", makestep(func() {

			connScan.Scan()

			cnt := 0

			err := ct.Iter(func(k, v []byte) maps.IteratorAction {
				cnt++
				key := conntrack.KeyFromBytes(k)
				val := conntrack.ValueFromBytes(v)
				log("key = %s\n", key)
				log("val = %s\n", val)
				return maps.IterNone
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(cnt).To(Equal(4))
		}))

		By("deleting the udp-service backend", makestep(func() {
			delete(state.SvcMap, udpSvcKey)
			delete(state.EpsMap, udpSvcKey)
			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
		}))

		By("deleting one second-service backend", makestep(func() {
			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.0.1", 2222, proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(1))
			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(1)))

			Expect(eps.m).To(HaveLen(1))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
		}))

		By("terminating second-service backend", makestep(func() {
			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.0.1", 2222, proxy.EndpointInfoOptIsTerminating(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(01))
			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(0)))

			Expect(eps.m).To(HaveLen(0))
		}))

		// Just that the rest of the test has the expected conditions.
		By("reviving one second-service backend", makestep(func() {
			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.0.1", 2222, proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(1))
			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(1)))

			Expect(eps.m).To(HaveLen(1))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
		}))

		By("checking that another CT entry pair is cleaned up by connScan", makestep(func() {

			connScan.Scan()

			cnt := 0

			err := ct.Iter(func(k, v []byte) maps.IteratorAction {
				cnt++
				key := conntrack.KeyFromBytes(k)
				val := conntrack.ValueFromBytes(v)
				log("key = %s\n", key)
				log("val = %s\n", val)
				return maps.IterNone
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(cnt).To(Equal(2))
		}))

		By("not programming eps without a service - non reachables", makestep(func() {
			nosvcKey := k8sp.ServicePortName{
				NamespacedName: types.NamespacedName{
					Namespace: "default",
					Name:      "noservice",
				},
			}

			state.EpsMap[nosvcKey] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.0.1", 6666, proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(1))
			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(1)))

			Expect(eps.m).To(HaveLen(1))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))

			delete(state.EpsMap, nosvcKey)
		}))

		By("adding ExternalIP for existing service", makestep(func() {
			state.SvcMap[svcKey2] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithExternalIPs([]net.IP{net.IPv4(35, 0, 0, 2)}),
			)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(2))

			val1, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1.Count()).To(Equal(uint32(1)))

			val2, ok := svcs.m[nat.NewNATKey(net.IPv4(35, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1).To(Equal(val2))

			Expect(eps.m).To(HaveLen(1))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val1.ID(), 0)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
		}))

		By("adding and removing overlapping external IP", makestep(func() {
			state.SvcMap[svcKey3] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithExternalIPs([]net.IP{net.IPv4(35, 0, 0, 2)}),
			)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			// At this (invalid) point the dataplane may have one service or the other...

			// After cleaning up the overlap, we should get back to a good state.
			delete(state.SvcMap, svcKey3)
			err = s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(2))

			val1, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1.Count()).To(Equal(uint32(1)))

			val2, ok := svcs.m[nat.NewNATKey(net.IPv4(35, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1).To(Equal(val2))

			Expect(eps.m).To(HaveLen(1))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val1.ID(), 0)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
		}))

		By("removing ExternalIP for existing service", makestep(func() {
			state.SvcMap[svcKey2] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
			)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(1))

			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(1)))

			Expect(eps.m).To(HaveLen(1))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
			Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
		}))

		var checkAfterResync func()

		By("turning existing service into a NodePort", makestep(func() {
			state.SvcMap[svcKey2] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithNodePort(2222),
			)

			checkAfterResync = func() {
				err := s.Apply(state)
				Expect(err).NotTo(HaveOccurred())

				Expect(svcs.m).To(HaveLen(3))

				val1, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
				Expect(ok).To(BeTrue())
				Expect(val1.Count()).To(Equal(uint32(1)))

				val2, ok := svcs.m[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
				Expect(ok).To(BeTrue())
				Expect(val1).To(Equal(val2))

				val3, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
				Expect(ok).To(BeTrue())
				Expect(val1).To(Equal(val3))

				Expect(eps.m).To(HaveLen(1))
				Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val1.ID(), 0)))
				Expect(eps.m).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
			}

			checkAfterResync()
		}))

		By("resyncing after creating a new syncer with the same result", makestep(func() {
			s, _ = proxy.NewSyncer(4, nodeIPs, svcs, eps, aff, rt, nil)
			checkAfterResync()
		}))

		By("resyncing after creating a new syncer and delete stale entries", makestep(func() {
			svcs.m[nat.NewNATKey(net.IPv4(5, 5, 5, 5), 1111, 6)] = nat.NewNATValue(0xdeadbeef, 2, 2, 0)
			eps.m[nat.NewNATBackendKey(0xdeadbeef, 0)] = nat.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 666)
			eps.m[nat.NewNATBackendKey(0xdeadbeef, 1)] = nat.NewNATBackendValue(net.IPv4(7, 7, 7, 7), 777)
			s, _ = proxy.NewSyncer(4, nodeIPs, svcs, eps, aff, rt, nil)
			checkAfterResync()
		}))

		By("inserting another service after resync", makestep(func() {
			state.SvcMap[svcKey3] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 3),
				3333,
				v1.ProtocolUDP,
				proxy.K8sSvcWithNodePort(3232),
			)
			state.EpsMap[svcKey3] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.3.0.1", 3434, proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(6))
			Expect(eps.m).To(HaveLen(2))

			val1, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1.Count()).To(Equal(uint32(1)))

			val2, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3333, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
			Expect(ok).To(BeTrue())
			Expect(val2.ID()).To(Equal(val1.ID()+1), "wrongly recycled svc ID?")

			val3, ok := svcs.m[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
			Expect(ok).To(BeTrue())
			Expect(val3).To(Equal(val2))

			val4, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
			Expect(ok).To(BeTrue())
			Expect(val4).To(Equal(val2))
		}))

		By("updating a port of a service", makestep(func() {
			state.SvcMap[svcKey3] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 3),
				3355,
				v1.ProtocolUDP,
				proxy.K8sSvcWithNodePort(3232),
			)
			state.EpsMap[svcKey3] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.3.0.1", 3434, proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(6))
			Expect(eps.m).To(HaveLen(2))

			Expect(svcs.m).NotTo(HaveKey(
				nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3333, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))))

			val2, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3355, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
			Expect(ok).To(BeTrue())

			val3, ok := svcs.m[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
			Expect(ok).To(BeTrue())
			Expect(val3).To(Equal(val2))

			val4, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
			Expect(ok).To(BeTrue())
			Expect(val4).To(Equal(val2))
		}))

		By("updating a NodePort of a service", makestep(func() {
			state.SvcMap[svcKey3] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 3),
				3355,
				v1.ProtocolUDP,
				proxy.K8sSvcWithNodePort(1212),
			)
			state.EpsMap[svcKey3] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.3.0.1", 3434, proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(6))
			Expect(eps.m).To(HaveLen(2))

			Expect(svcs.m).NotTo(HaveKey(
				nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3333, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))))

			val2, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3355, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
			Expect(ok).To(BeTrue())

			val3, ok := svcs.m[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 1212, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
			Expect(ok).To(BeTrue())
			Expect(val3).To(Equal(val2))

			val4, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 1212, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
			Expect(ok).To(BeTrue())
			Expect(val4).To(Equal(val2))
		}))

		By("deleting backends if there are none for a service BPF-147", makestep(func() {
			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			count := val.Count()
			for i := uint32(0); i < count; i++ {
				Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val.ID(), i)))
			}

			// This testcase assumes there are at least as many backends in the
			// EpsMap for other services left than the original number of services
			// for the one being updated.`
			delete(state.EpsMap, svcKey2)
			Expect(int(count)).To(BeNumerically(">=", func() int {
				cnt := 0
				for _, v := range state.EpsMap {
					cnt += len(v)
				}
				return cnt
			}()))

			log("state.SvcMap = %+v\n", state.SvcMap)
			log("state.EpsMap = %+v\n", state.EpsMap)
			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			val, ok = svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.Count()).To(Equal(uint32(0)))
			for i := uint32(0); i < count; i++ {
				Expect(eps.m).NotTo(HaveKey(nat.NewNATBackendKey(val.ID(), i)))
			}
		}))

		By("deleting the services", makestep(func() {
			delete(state.SvcMap, svcKey2)
			delete(state.SvcMap, svcKey3)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(0))
			Expect(eps.m).To(HaveLen(0))
		}))

		By("inserting non-local eps for a NodePort - no route", makestep(func() {
			// use the meta node IP for nodeports as well
			s, _ = proxy.NewSyncer(4, append(nodeIPs, net.IPv4(255, 255, 255, 255)), svcs, eps, aff, rt, nil)
			state.SvcMap[svcKey2] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithNodePort(4444),
				proxy.K8sSvcWithLocalOnly(),
			)

			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.1.1", 2222, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.2.2.1", 2222, proxy.EndpointInfoOptIsLocal(true), proxy.EndpointInfoOptIsReady(true)), // isLocal == true.
				proxy.NewEndpointInfo("10.2.3.1", 2222, proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(3))
			Expect(eps.m).To(HaveLen(3))
			k := nat.NewNATKey(net.IPv4(10, 123, 0, 111), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).NotTo(HaveKey(k))
			k = nat.NewNATKey(net.IPv4(10, 123, 0, 113), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).NotTo(HaveKey(k))

			k = nat.NewNATKey(net.IPv4(192, 168, 0, 1), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(k))
			k = nat.NewNATKey(net.IPv4(10, 123, 0, 1), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(k))
		}))

		By("adding a route should fix one missing expanded NP", makestep(func() {
			s.SetTriggerFn(func() {
				go func() {
					logrus.Info("Syncer triggered")
					err := s.Apply(state)
					logrus.WithError(err).Info("Syncer result")
				}()
			})
			rt.Update(
				routes.NewKey(ip.CIDRFromAddrAndPrefix(ip.FromString("10.2.1.0"), 24).(ip.V4CIDR)),
				routes.NewValueWithNextHop(
					routes.FlagsRemoteWorkload,
					ip.FromString("10.123.0.111").(ip.V4Addr)),
			)

			Eventually(func() int {
				svcs.Lock()
				defer svcs.Unlock()
				return len(svcs.m)
			}).Should(Equal(4))

			Expect(eps.m).To(HaveLen(4))

			k := nat.NewNATKey(net.IPv4(10, 123, 0, 111), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(k))
			remote := svcs.m[k]
			Expect(remote.Count()).To(Equal(uint32(1)))
			Expect(remote.LocalCount()).To(Equal(uint32(0)))

			k = nat.NewNATKey(net.IPv4(10, 123, 0, 1), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(k))
			local := svcs.m[k]
			Expect(local.Count()).To(Equal(uint32(3)))
			Expect(local.LocalCount()).To(Equal(uint32(1)))
			Expect(local.Flags()).To(Equal(uint32(nat.NATFlgInternalLocal | nat.NATFlgExternalLocal)))

			k = nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(k))
			cluster := svcs.m[k]
			Expect(cluster.Count()).To(Equal(uint32(3)))
			Expect(cluster.LocalCount()).To(Equal(uint32(1)))
		}))

		By("adding an unrelated route does not change anything", makestep(func() {
			rt.Update(
				routes.NewKey(ip.CIDRFromAddrAndPrefix(ip.FromString("10.2.55.0"), 24).(ip.V4CIDR)),
				routes.NewValueWithNextHop(
					routes.FlagsRemoteWorkload,
					ip.FromString("10.123.0.111").(ip.V4Addr)),
			)

			// XXX we do not have quite a good sync with the fixer in Syncer, we
			// XXX just do it speculatively and to introduce some fuzziness. If this
			// XXX or the next test fails, something is wrong and should be fixed
			svcs.Lock()
			defer svcs.Unlock()
			Expect(svcs.m).To(HaveLen(4))
			k := nat.NewNATKey(net.IPv4(10, 123, 0, 111), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(k))
		}))

		By("adding route should fix another missing expanded NP", makestep(func() {
			rt.Update(
				routes.NewKey(ip.CIDRFromAddrAndPrefix(ip.FromString("10.2.3.0"), 24).(ip.V4CIDR)),
				routes.NewValueWithNextHop(
					routes.FlagsRemoteWorkload,
					ip.FromString("10.123.0.113").(ip.V4Addr)),
			)

			Eventually(func() int {
				svcs.Lock()
				defer svcs.Unlock()
				return len(svcs.m)
			}).Should(Equal(5))
			k := nat.NewNATKey(net.IPv4(10, 123, 0, 111), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(k))
			k = nat.NewNATKey(net.IPv4(10, 123, 0, 113), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(k))
			Expect(eps.m).To(HaveLen(5))
		}))

		By("checking frontend-backend mapping", makestep(func() {
			s.StopExpandNPFixup()
			s.ConntrackScanStart()
			defer s.ConntrackScanEnd()

			// Any backend is valid for the ClusterIP
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 0, 0, 2), 2222, net.IPv4(10, 2, 1, 1), 2222, 6)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 0, 0, 2), 2222, net.IPv4(10, 2, 2, 1), 2222, 6)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 0, 0, 2), 2222, net.IPv4(10, 2, 3, 1), 2222, 6)).To(BeTrue())

			// Not all backends are reachable through the NodePort, but there is
			// no harm in not cleaning connections that cannot exist. Even if
			// they existed, why would we break them?

			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(192, 168, 0, 1), 4444, net.IPv4(10, 2, 1, 1), 2222, 6)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(192, 168, 0, 1), 4444, net.IPv4(10, 2, 2, 1), 2222, 6)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(192, 168, 0, 1), 4444, net.IPv4(10, 2, 3, 1), 2222, 6)).To(BeTrue())

			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 123, 0, 111), 4444, net.IPv4(10, 2, 1, 1), 2222, 6)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 123, 0, 111), 4444, net.IPv4(10, 2, 2, 1), 2222, 6)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 123, 0, 111), 4444, net.IPv4(10, 2, 3, 1), 2222, 6)).To(BeTrue())

			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 123, 0, 113), 4444, net.IPv4(10, 2, 1, 1), 2222, 6)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 123, 0, 113), 4444, net.IPv4(10, 2, 2, 1), 2222, 6)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 123, 0, 113), 4444, net.IPv4(10, 2, 3, 1), 2222, 6)).To(BeTrue())
		}))

		By("inserting only non-local eps for a NodePort - multiple nodes & pods/node", makestep(func() {
			// use the meta node IP for nodeports as well
			s, _ = proxy.NewSyncer(4, append(nodeIPs, net.IPv4(255, 255, 255, 255)), svcs, eps, aff, rt, nil)
			state.SvcMap[svcKey2] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithNodePort(4444),
				proxy.K8sSvcWithLocalOnly(),
			)

			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.1.1", 2222, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.2.2.1", 2222, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.2.2.2", 2222, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.2.3.1", 2222, proxy.EndpointInfoOptIsReady(true)),
			}

			rt.Update(
				routes.NewKey(ip.CIDRFromAddrAndPrefix(ip.FromString("10.2.2.0"), 24).(ip.V4CIDR)),
				routes.NewValueWithNextHop(
					routes.FlagsRemoteWorkload,
					ip.FromString("10.123.0.112").(ip.V4Addr)),
			)
			rt.Update(
				routes.NewKey(ip.CIDRFromAddrAndPrefix(ip.FromString("10.2.3.0"), 24).(ip.V4CIDR)),
				routes.NewValueWithNextHop(
					routes.FlagsRemoteWorkload,
					ip.FromString("10.123.0.113").(ip.V4Addr)),
			)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			checkAfterResync = func() {
				Expect(svcs.m).To(HaveLen(6))

				val1, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
				Expect(ok).To(BeTrue())
				Expect(val1.Count()).To(Equal(uint32(4)))

				val2, ok := svcs.m[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
				Expect(ok).To(BeTrue())
				Expect(val2.ID()).To(Equal(val1.ID()))
				Expect(val2.Count()).To(Equal(uint32(4)))
				Expect(val2.LocalCount()).To(Equal(uint32(0)))

				val3, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
				Expect(ok).To(BeTrue())
				Expect(val2).To(Equal(val3))

				Expect(eps.m).To(HaveLen(8))

				all := make([]nat.BackendValue, 0, 4)
				for i := uint32(0); i < val1.Count(); i++ {
					bk := nat.NewNATBackendKey(val1.ID(), i)
					Expect(eps.m).To(HaveKey(bk))
					all = append(all, eps.m[bk])
				}

				Expect(all).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 1, 1), 2222)))
				Expect(all).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 2, 1), 2222)))
				Expect(all).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 2, 2), 2222)))
				Expect(all).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 3, 1), 2222)))

				checkRemote := func(a net.IP, count uint32) {
					k := nat.NewNATKey(a, 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
					Expect(svcs.m).To(HaveKey(k))
					v := svcs.m[k]
					Expect(v.Count()).To(Equal(count))
				}

				checkRemote(net.IPv4(10, 123, 0, 111), 1)
				checkRemote(net.IPv4(10, 123, 0, 112), 2)
				checkRemote(net.IPv4(10, 123, 0, 113), 1)
			}

			checkAfterResync()
		}))

		By("restarting Syncer to check if NodePortRemotes are picked up correctly", makestep(func() {
			// use the meta node IP for nodeports as well
			s, _ = proxy.NewSyncer(4, append(nodeIPs, net.IPv4(255, 255, 255, 255)), svcs, eps, aff, rt, nil)
			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			checkAfterResync()
		}))

		By("inserting a local ep for a NodePort", makestep(func() {
			state.SvcMap[svcKey2] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithNodePort(4444),
				proxy.K8sSvcWithLocalOnly(),
			)

			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.0.1", 2222, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.3.0.1", 2222, proxy.EndpointInfoOptIsLocal(true), proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.4.0.1", 2222, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.5.0.1", 2222, proxy.EndpointInfoOptIsLocal(true), proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(3))

			val1, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1.Count()).To(Equal(uint32(4)))
			Expect(val1.LocalCount()).To(Equal(uint32(2)))
			// ClusterIP only reflects internal traffic policy, not the external one
			Expect(val1.Flags()).To(Equal(uint32(nat.NATFlgInternalLocal)))

			val2, ok := svcs.m[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val2.ID()).To(Equal(val1.ID()))
			Expect(val2.Count()).To(Equal(uint32(4)))
			Expect(val2.LocalCount()).To(Equal(uint32(2)))
			Expect(val2.Flags()).To(Equal(uint32(nat.NATFlgInternalLocal | nat.NATFlgExternalLocal)))

			val3, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val2).To(Equal(val3))

			Expect(svcs.m).NotTo(
				HaveKey(nat.NewNATKey(net.IPv4(255, 255, 255, 255), 4444, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))))

			Expect(eps.m).To(HaveLen(4))

			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val1.ID(), 0)))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val1.ID(), 1)))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val1.ID(), 2)))
			Expect(eps.m).To(HaveKey(nat.NewNATBackendKey(val1.ID(), 3)))

			Expect(eps.m[nat.NewNATBackendKey(val1.ID(), 0)]).To(Or(
				Equal(nat.NewNATBackendValue(net.IPv4(10, 3, 0, 1), 2222)),
				Equal(nat.NewNATBackendValue(net.IPv4(10, 5, 0, 1), 2222))))
			Expect(eps.m[nat.NewNATBackendKey(val1.ID(), 1)]).To(Or(
				Equal(nat.NewNATBackendValue(net.IPv4(10, 3, 0, 1), 2222)),
				Equal(nat.NewNATBackendValue(net.IPv4(10, 5, 0, 1), 2222))))
			Expect(eps.m[nat.NewNATBackendKey(val1.ID(), 0)]).
				NotTo(Equal(eps.m[nat.NewNATBackendKey(val1.ID(), 1)]))

			Expect(eps.m[nat.NewNATBackendKey(val1.ID(), 2)]).To(Or(
				Equal(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)),
				Equal(nat.NewNATBackendValue(net.IPv4(10, 4, 0, 1), 2222))))
			Expect(eps.m[nat.NewNATBackendKey(val1.ID(), 3)]).To(Or(
				Equal(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)),
				Equal(nat.NewNATBackendValue(net.IPv4(10, 4, 0, 1), 2222))))
			Expect(eps.m[nat.NewNATBackendKey(val1.ID(), 2)]).
				NotTo(Equal(eps.m[nat.NewNATBackendKey(val1.ID(), 3)]))
		}))

		By("inserting service with affinity v1.ServiceAffinityClientIP", makestep(func() {
			state.SvcMap[svcKey2] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithStickyClientIP(5),
			)

			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.0.1", 2222, proxy.EndpointInfoOptIsReady(true)),
			}

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(1))
			Expect(eps.m).To(HaveLen(1))

			val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val.AffinityTimeout()).To(Equal(5 * time.Second))
		}))

		By("inserting another ep for service with affinity v1.ServiceAffinityClientIP", makestep(func() {
			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.2.0.1", 2222, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.3.0.1", 3333, proxy.EndpointInfoOptIsReady(true)),
			}

			// add active affinity entry
			err := aff.Update(
				nat.NewAffinityKey(
					net.IPv4(5, 5, 5, 5),
					nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP)),
				).AsBytes(),
				nat.NewAffinityValue(
					uint64(bpf.KTimeNanos()),
					nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222),
				).AsBytes(),
			)
			Expect(err).NotTo(HaveOccurred())

			// add expired affinity entry
			err = aff.Update(
				nat.NewAffinityKey(
					net.IPv4(5, 5, 4, 4),
					nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP)),
				).AsBytes(),
				nat.NewAffinityValue(
					uint64(bpf.KTimeNanos())-uint64(10*time.Second),
					nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222),
				).AsBytes(),
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(aff.m).To(HaveLen(2))

			err = s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(1))
			Expect(eps.m).To(HaveLen(2))
			Expect(aff.m).To(HaveLen(1))
		}))

		By("deleting an ep for service with affinity v1.ServiceAffinityClientIP", makestep(func() {
			state.EpsMap[svcKey2] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.3.0.1", 3333, proxy.EndpointInfoOptIsReady(true)),
			}

			err := aff.Update(
				nat.NewAffinityKey(
					net.IPv4(6, 6, 6, 6),
					nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP)),
				).AsBytes(),
				nat.NewAffinityValue(
					uint64(bpf.KTimeNanos()),
					nat.NewNATBackendValue(net.IPv4(10, 3, 0, 1), 3333),
				).AsBytes(),
			)
			Expect(err).NotTo(HaveOccurred())

			err = aff.Update(
				nat.NewAffinityKey(
					net.IPv4(7, 7, 7, 7),
					nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP)),
				).AsBytes(),
				nat.NewAffinityValue(
					uint64(bpf.KTimeNanos()),
					nat.NewNATBackendValue(net.IPv4(10, 3, 0, 1), 3333),
				).AsBytes(),
			)
			Expect(err).NotTo(HaveOccurred())

			Expect(aff.m).To(HaveLen(3))

			err = s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(1))
			Expect(eps.m).To(HaveLen(1))
			Expect(aff.m).To(HaveLen(2))
		}))

		By("by removing all services and cleaning affinity table", makestep(func() {
			delete(state.SvcMap, svcKey2)
			delete(state.EpsMap, svcKey2)

			err := aff.Update(
				nat.NewAffinityKey(
					net.IPv4(5, 5, 5, 5),
					nat.NewNATKey(net.IPv4(10, 1, 0, 1), 123, 6),
				).AsBytes(),
				nat.NewAffinityValue(
					uint64(bpf.KTimeNanos()),
					nat.NewNATBackendValue(net.IPv4(111, 1, 1, 1), 111),
				).AsBytes(),
			)
			Expect(err).NotTo(HaveOccurred())

			err = s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(0))
			Expect(eps.m).To(HaveLen(0))
			Expect(aff.m).To(HaveLen(0))
		}))

		By("recreating a CT scanner for the actual syncer", func() {
			connScan = conntrack.NewScanner(ct,
				conntrack.KeyFromBytes, conntrack.ValueFromBytes, nil, "Disabled", conntrack.NewStaleNATScanner(s))
		})

		By("checking that CT table emptied by connScan", makestep(func() {

			connScan.Scan()

			cnt := 0

			err := ct.Iter(func(k, v []byte) maps.IteratorAction {
				cnt++
				key := conntrack.KeyFromBytes(k)
				val := conntrack.ValueFromBytes(v)
				log("key = %s\n", key)
				log("val = %s\n", val)
				return maps.IterNone
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(cnt).To(Equal(0))
		}))

		By("checking topology aware hints auto in service with multiple endpoints match first zone", makestep(func() {
			state.SvcMap[svcKey] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 1),
				1234,
				v1.ProtocolTCP,
				proxy.K8sSvcWithHintsAnnotation("auto"),
			)
			state.EpsMap[svcKey] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.1.0.1", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2a"))),
				proxy.NewEndpointInfo("10.2.0.2", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2b"))),
			}
			state.NodeZone = "us-west-2a"

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(eps.m).To(HaveLen(1))
		}))

		By("checking topology aware hints auto in service with multiple endpoints match second zone", makestep(func() {
			state.SvcMap[svcKey] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 1),
				1234,
				v1.ProtocolTCP,
				proxy.K8sSvcWithHintsAnnotation("auto"),
			)
			state.EpsMap[svcKey] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.1.0.1", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2a"))),
				proxy.NewEndpointInfo("10.2.0.2", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2b"))),
			}
			state.NodeZone = "us-west-2b"

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(eps.m).To(HaveLen(1))
		}))

		By("checking topology aware hints disabled in service with multiple endpoints match all zones", makestep(func() {
			state.SvcMap[svcKey] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 1),
				1234,
				v1.ProtocolTCP,
				proxy.K8sSvcWithHintsAnnotation("disabled"),
			)
			state.EpsMap[svcKey] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.1.0.1", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2a"))),
				proxy.NewEndpointInfo("10.2.0.2", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2b"))),
			}
			state.NodeZone = "us-west-2b"

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(eps.m).To(HaveLen(2))
		}))

		By("checking topology aware hints empty in service with multiple endpoints match all zones", makestep(func() {
			state.SvcMap[svcKey] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 1),
				1234,
				v1.ProtocolTCP,
			)
			state.EpsMap[svcKey] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.1.0.1", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2a"))),
				proxy.NewEndpointInfo("10.2.0.2", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2b"))),
			}
			state.NodeZone = "us-west-2b"

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(eps.m).To(HaveLen(2))
		}))

		By("checking topology aware hints auto in service with multiple endpoints without node zone match all zones", makestep(func() {
			state.SvcMap[svcKey] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 1),
				1234,
				v1.ProtocolTCP,
				proxy.K8sSvcWithHintsAnnotation("auto"),
			)
			state.EpsMap[svcKey] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.1.0.1", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2a"))),
				proxy.NewEndpointInfo("10.2.0.2", 5555, proxy.EndpointInfoOptIsReady(true), proxy.EndpointInfoOptZoneHints(sets.New[string]("us-west-2b"))),
			}
			state.NodeZone = ""

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(eps.m).To(HaveLen(2))
		}))

		By("checking endpointslice terminating status should be included in endpointslice collection for processing", makestep(func() {

			// Clean up all prior state.
			delete(state.SvcMap, svcKey)
			delete(state.SvcMap, svcKey2)
			delete(state.SvcMap, svcKey3)
			delete(state.EpsMap, svcKey)
			delete(state.EpsMap, svcKey2)
			delete(state.EpsMap, svcKey3)

			// Apply new SvcMap and Eps state.
			state.SvcMap[svcKey4] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 1),
				1234,
				v1.ProtocolTCP,
			)
			state.EpsMap[svcKey4] = []k8sp.Endpoint{
				proxy.NewEndpointInfo("10.1.0.1", 5555, proxy.EndpointInfoOptIsReady(true)),
				proxy.NewEndpointInfo("10.1.0.2", 6666, proxy.EndpointInfoOptIsTerminating(true)),
				proxy.NewEndpointInfo("10.1.0.3", 7777, proxy.EndpointInfoOptIsReady(true)),
			}

			// Expect 2x new map entries for Ready pods only; Terminating pods not added to map.
			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(eps.m).To(HaveLen(2))
		}))

		By("checking that conntrack scan does not remove the terminating endpoint connection", makestep(func() {

			// Unroll conntrack entries for service additions following convention in unit test above.
			svc := state.SvcMap[svcKey4]
			ep := state.EpsMap[svcKey4][0]
			ctEntriesForSvc(ct, svc.Protocol(), svc.ClusterIP(), uint16(svc.Port()), ep, net.IPv4(5, 6, 7, 8), 111)
			ep = state.EpsMap[svcKey4][1]
			ctEntriesForSvc(ct, svc.Protocol(), svc.ClusterIP(), uint16(svc.Port()), ep, net.IPv4(5, 6, 7, 8), 222)
			ep = state.EpsMap[svcKey4][2]
			ctEntriesForSvc(ct, svc.Protocol(), svc.ClusterIP(), uint16(svc.Port()), ep, net.IPv4(5, 6, 7, 8), 333)

			connScan.Scan()

			cnt := 0
			err := ct.Iter(func(k, v []byte) maps.IteratorAction {
				cnt++
				key := conntrack.KeyFromBytes(k)
				val := conntrack.ValueFromBytes(v)
				log("key = %s\n", key)
				log("val = %s\n", val)
				return maps.IterNone
			})

			// Expect 6x new conntrack entries from 3x pods NAT forward and 3x pods NAT reverse total.
			Expect(err).NotTo(HaveOccurred())
			Expect(cnt).To(Equal(6))
		}))

	})

	It("should remove conntrack of terminating UDP backed if service annotated as such", func() {
		state = proxy.DPSyncerState{
			SvcMap: k8sp.ServicePortMap{
				svcKey: proxy.NewK8sServicePort(
					net.IPv4(10, 0, 0, 1),
					1234,
					v1.ProtocolUDP,
					proxy.K8sSvcWithReapTerminatingUDP(),
				),
			},
			EpsMap: k8sp.EndpointsMap{
				svcKey: []k8sp.Endpoint{
					proxy.NewEndpointInfo("10.1.0.1", 5555, proxy.EndpointInfoOptIsReady(true)),
					proxy.NewEndpointInfo("10.1.0.2", 5555, proxy.EndpointInfoOptIsTerminating(true)),
				},
			},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs.m).To(HaveLen(1))
		val, ok := svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 1), 1234, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1))) // only the ready endpoint

		By("running ct scan - expect terminating to be reaped", func() {
			s.StopExpandNPFixup()
			s.ConntrackScanStart()
			defer s.ConntrackScanEnd()

			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 0, 0, 1), 1234, net.IPv4(10, 1, 0, 1), 5555, 17)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 0, 0, 1), 1234, net.IPv4(10, 1, 0, 2), 5555, 17)).To(BeFalse())
		})

		By("removing the annotation")

		state = proxy.DPSyncerState{
			SvcMap: k8sp.ServicePortMap{
				svcKey: proxy.NewK8sServicePort(
					net.IPv4(10, 0, 0, 1),
					1234,
					v1.ProtocolUDP,
				),
			},
			EpsMap: k8sp.EndpointsMap{
				svcKey: []k8sp.Endpoint{
					proxy.NewEndpointInfo("10.1.0.1", 5555, proxy.EndpointInfoOptIsReady(true)),
					proxy.NewEndpointInfo("10.1.0.2", 5555, proxy.EndpointInfoOptIsTerminating(true)),
				},
			},
		}

		err = s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		By("running ct scan again - expect terminating not to be reaped", func() {
			s.StopExpandNPFixup()
			s.ConntrackScanStart()
			defer s.ConntrackScanEnd()

			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 0, 0, 1), 1234, net.IPv4(10, 1, 0, 1), 5555, 17)).To(BeTrue())
			Expect(s.ConntrackFrontendHasBackend(
				net.IPv4(10, 0, 0, 1), 1234, net.IPv4(10, 1, 0, 2), 5555, 17)).To(BeTrue())
		})

	})
})

type mockNATMap struct {
	mock.DummyMap
	sync.Mutex
	m map[nat.FrontendKey]nat.FrontendValue
}

func (m *mockNATMap) MapFD() maps.FD {
	panic("implement me")
}

func newMockNATMap() *mockNATMap {
	return &mockNATMap{
		m: make(map[nat.FrontendKey]nat.FrontendValue),
	}
}

func (m *mockNATMap) GetName() string {
	return "nat"
}

func (m *mockNATMap) Path() string {
	return "/sys/fs/bpf/tc/nat"
}

func (m *mockNATMap) Iter(iter maps.IterCallback) error {
	m.Lock()
	defer m.Unlock()

	ks := len(nat.FrontendKey{})
	vs := len(nat.FrontendValue{})
	for k, v := range m.m {
		action := iter(k[:ks], v[:vs])
		if action == maps.IterDelete {
			delete(m.m, k)
		}
	}

	return nil
}

func (m *mockNATMap) Update(k, v []byte) error {
	logrus.WithFields(logrus.Fields{
		"k": k, "v": v,
	}).Debug("mockNATMap.Update()")

	m.Lock()
	defer m.Unlock()

	ks := len(nat.FrontendKey{})
	if len(k) != ks {
		return fmt.Errorf("expected key size %d got %d", ks, len(k))
	}
	vs := len(nat.FrontendValue{})
	if len(v) != vs {
		return fmt.Errorf("expected value size %d got %d", vs, len(v))
	}

	var key nat.FrontendKey
	copy(key[:ks], k[:ks])

	var val nat.FrontendValue
	copy(val[:vs], v[:vs])

	m.m[key] = val

	return nil
}

func (m *mockNATMap) Get(k []byte) ([]byte, error) {
	panic("not implemented")
}

func (m *mockNATMap) Delete(k []byte) error {
	logrus.WithFields(logrus.Fields{
		"k": k,
	}).Debug("mockNATMap.Delete()")

	m.Lock()
	defer m.Unlock()

	ks := len(nat.FrontendKey{})
	if len(k) != ks {
		return fmt.Errorf("expected key size %d got %d", ks, len(k))
	}

	var key nat.FrontendKey
	copy(key[:ks], k[:ks])

	delete(m.m, key)

	return nil
}

type mockNATBackendMap struct {
	mock.DummyMap
	sync.Mutex
	m map[nat.BackendKey]nat.BackendValue
}

func (m *mockNATBackendMap) MapFD() maps.FD {
	panic("implement me")
}

func newMockNATBackendMap() *mockNATBackendMap {
	return &mockNATBackendMap{
		m: make(map[nat.BackendKey]nat.BackendValue),
	}
}

func (m *mockNATBackendMap) GetName() string {
	return "natbe"
}

func (m *mockNATBackendMap) Path() string {
	return "/sys/fs/bpf/tc/natbe"
}

func (m *mockNATBackendMap) Iter(iter maps.IterCallback) error {
	m.Lock()
	defer m.Unlock()

	ks := len(nat.BackendKey{})
	vs := len(nat.BackendValue{})
	for k, v := range m.m {
		action := iter(k[:ks], v[:vs])
		if action == maps.IterDelete {
			delete(m.m, k)
		}
	}

	return nil
}

func (m *mockNATBackendMap) Update(k, v []byte) error {
	logrus.WithFields(logrus.Fields{
		"k": k, "v": v,
	}).Debug("mockNATBackendMap.Update()")

	m.Lock()
	defer m.Unlock()

	ks := len(nat.BackendKey{})
	if len(k) != ks {
		return fmt.Errorf("expected key size %d got %d", ks, len(k))
	}
	vs := len(nat.BackendValue{})
	if len(v) != vs {
		return fmt.Errorf("expected value size %d got %d", vs, len(v))
	}

	var key nat.BackendKey
	copy(key[:ks], k[:ks])

	var val nat.BackendValue
	copy(val[:vs], v[:vs])

	m.m[key] = val

	return nil
}

func (m *mockNATBackendMap) Get(k []byte) ([]byte, error) {
	panic("not implemented")
}

func (m *mockNATBackendMap) Delete(k []byte) error {
	logrus.WithFields(logrus.Fields{
		"k": k,
	}).Debug("mockNATBackendMap.Delete()")

	m.Lock()
	defer m.Unlock()

	ks := len(nat.BackendKey{})
	if len(k) != ks {
		return fmt.Errorf("expected key size %d got %d", ks, len(k))
	}

	var key nat.BackendKey
	copy(key[:ks], k[:ks])

	delete(m.m, key)

	return nil
}

type mockAffinityMap struct {
	mock.DummyMap
	sync.Mutex
	m map[nat.AffinityKey]nat.AffinityValue
}

func newMockAffinityMap() *mockAffinityMap {
	return &mockAffinityMap{
		m: make(map[nat.AffinityKey]nat.AffinityValue),
	}
}

func (m *mockAffinityMap) GetName() string {
	return "aff"
}

func (m *mockAffinityMap) Path() string {
	return "/sys/fs/bpf/tc/aff"
}

func (m *mockAffinityMap) Iter(iter maps.IterCallback) error {
	m.Lock()
	defer m.Unlock()

	ks := len(nat.AffinityKey{})
	vs := len(nat.AffinityValue{})
	for k, v := range m.m {
		action := iter(k[:ks], v[:vs])
		if action == maps.IterDelete {
			delete(m.m, k)
		}
	}

	return nil
}

func (m *mockAffinityMap) Update(k, v []byte) error {
	m.Lock()
	defer m.Unlock()

	ks := len(nat.AffinityKey{})
	if len(k) != ks {
		return fmt.Errorf("expected key size %d got %d", ks, len(k))
	}
	vs := len(nat.AffinityValue{})
	if len(v) != vs {
		return fmt.Errorf("expected value size %d got %d", vs, len(v))
	}

	var key nat.AffinityKey
	copy(key[:ks], k[:ks])

	var val nat.AffinityValue
	copy(val[:vs], v[:vs])

	m.m[key] = val

	return nil
}

func (m *mockAffinityMap) Get(k []byte) ([]byte, error) {
	panic("not implemented")
}

func (m *mockAffinityMap) Delete(k []byte) error {
	m.Lock()
	defer m.Unlock()

	ks := len(nat.AffinityKey{})
	if len(k) != ks {
		return fmt.Errorf("expected key size %d got %d", ks, len(k))
	}

	var key nat.AffinityKey
	copy(key[:ks], k[:ks])

	delete(m.m, key)

	return nil
}

func (m *mockAffinityMap) MapFD() maps.FD {
	panic("implement me")
}

func ctEntriesForSvc(ct maps.Map, proto v1.Protocol,
	svcIP net.IP, svcPort uint16, ep k8sp.Endpoint, srcIP net.IP, srcPort uint16) {

	p, err := proxy.ProtoV1ToInt(proto)
	if err != nil {
		p, _ = proxy.ProtoV1ToInt(v1.ProtocolTCP)
	}

	// REVIEWER TODO: looking for sign-off on this adaptation.
	epPort := ep.Port()
	Expect(epPort).NotTo(BeNumerically("<=", 0), "Test failed to parse EP port")

	key := conntrack.NewKey(p, srcIP, srcPort, svcIP, svcPort)
	revKey := conntrack.NewKey(p, srcIP, srcPort, net.ParseIP(ep.IP()), uint16(epPort))
	val := conntrack.NewValueNATForward(0, 0, revKey)

	err = ct.Update(key.AsBytes(), val.AsBytes())
	Expect(err).NotTo(HaveOccurred(), "Test failed to populate ct map with FWD entry")

	val = conntrack.NewValueNATReverse(0, 0, conntrack.Leg{}, conntrack.Leg{},
		net.IPv4(0, 0, 0, 0), svcIP, svcPort)

	err = ct.Update(revKey.AsBytes(), val.AsBytes())
	Expect(err).NotTo(HaveOccurred(), "Test failed to populate ct map with REV")
}
