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

package proxy_test

import (
	"net"

	"github.com/projectcalico/felix/bpf/nat"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	//"github.com/projectcalico/felix/bpf"
	proxy "github.com/projectcalico/felix/bpf/proxy"
	//"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/ip"
)

func init() {
	logrus.SetOutput(GinkgoWriter)
	logrus.SetLevel(logrus.DebugLevel)
}

var _ = Describe("BPF Load Balancer source range", func() {
	svcs := newMockNATMap()
	eps := newMockNATBackendMap()
	aff := newMockAffinityMap()

	nodeIPs := []net.IP{net.IPv4(192, 168, 0, 1), net.IPv4(10, 123, 0, 1)}
	rt := proxy.NewRTCache()

	s, _ := proxy.NewSyncer(nodeIPs, svcs, eps, aff, rt)

	svcKey := k8sp.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "test-service",
		},
	}
	state := proxy.DPSyncerState{
		SvcMap: k8sp.ServiceMap{
			svcKey: proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithExternalIPs([]string{"35.0.0.2"}),
				proxy.K8sSvcWithLBSourceRangeIPs([]string{"35.0.1.2/24", "33.0.1.2/16"}),
			),
		},
		EpsMap: k8sp.EndpointsMap{
			svcKey: []k8sp.Endpoint{&k8sp.BaseEndpointInfo{Endpoint: "10.1.0.1:5555"}},
		},
	}
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

		By("adding LBSourceRangeIP for existing service", makestep(func() {

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(4))

			saddr := ip.MustParseCIDROrIP("35.0.1.2/24").(ip.V4CIDR)
			key1 := nat.NewNATKeySrc(net.IPv4(10, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).NotTo(HaveKey(key1))

			saddr = ip.MustParseCIDROrIP("33.0.1.2/16").(ip.V4CIDR)
			key1 = nat.NewNATKeySrc(net.IPv4(10, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).NotTo(HaveKey(key1))

			key1 = nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(key1))

			saddr = ip.MustParseCIDROrIP("35.0.1.2/24").(ip.V4CIDR)
			key1 = nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).To(HaveKey(key1))

			saddr = ip.MustParseCIDROrIP("33.0.1.2/16").(ip.V4CIDR)
			key1 = nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).To(HaveKey(key1))

			key1 = nat.NewNATKey(net.IPv4(35, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
			Expect(svcs.m).To(HaveKey(key1))

			val1 := nat.NewNATValue(uint32(0), uint32(nat.BlackHoleCount), 0, 0)
			val2, ok := svcs.m[key1]
			Expect(ok).To(BeTrue())
			Expect(val1).To(Equal(val2))

		}))

		By("updating LBSourceRangeIP for existing service", makestep(func() {
			Expect(svcs.m).To(HaveLen(4))
			state.SvcMap[svcKey] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithExternalIPs([]string{"35.0.0.2"}),
				proxy.K8sSvcWithLBSourceRangeIPs([]string{"35.0.1.2/24", "23.0.1.2/16"}),
			)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(svcs.m).To(HaveLen(4))

			saddr := ip.MustParseCIDROrIP("35.0.1.2/24").(ip.V4CIDR)
			key1 := nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).To(HaveKey(key1))

			saddr = ip.MustParseCIDROrIP("33.0.1.2/16").(ip.V4CIDR)
			key1 = nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).NotTo(HaveKey(key1))

			saddr = ip.MustParseCIDROrIP("23.0.1.2/16").(ip.V4CIDR)
			key1 = nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).To(HaveKey(key1))

		}))

		By("Deleting one LBSourceRangeIP for existing service", makestep(func() {
			state.SvcMap[svcKey] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithExternalIPs([]string{"35.0.0.2"}),
				proxy.K8sSvcWithLBSourceRangeIPs([]string{"35.0.1.2/24"}),
			)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(svcs.m).To(HaveLen(3))

			saddr := ip.MustParseCIDROrIP("35.0.1.2/24").(ip.V4CIDR)
			key1 := nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).To(HaveKey(key1))

			saddr = ip.MustParseCIDROrIP("23.0.1.2/16").(ip.V4CIDR)
			key1 = nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).NotTo(HaveKey(key1))

		}))

		By("Deleting LBSourceRangeIP for existing service", makestep(func() {
			state.SvcMap[svcKey] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithExternalIPs([]string{"35.0.0.2"}),
				proxy.K8sSvcWithLBSourceRangeIPs([]string{}),
			)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(svcs.m).To(HaveLen(2))

			saddr := ip.MustParseCIDROrIP("35.0.1.2/24").(ip.V4CIDR)
			key1 := nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).NotTo(HaveKey(key1))

			saddr = ip.MustParseCIDROrIP("23.0.1.2/16").(ip.V4CIDR)
			key1 = nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222,
				proxy.ProtoV1ToIntPanic(v1.ProtocolTCP), saddr)
			Expect(svcs.m).NotTo(HaveKey(key1))

		}))

		By("deleting the services", makestep(func() {
			delete(state.SvcMap, svcKey)

			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs.m).To(HaveLen(0))
			Expect(eps.m).To(HaveLen(0))
		}))

		By("resyncing after creating a new syncer and delete stale entries", makestep(func() {
			svcs.m[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 1111, 6)] = nat.NewNATValue(0xdeadbeef, 2, 2, 0)
			svcs.m[nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222, 6, ip.MustParseCIDROrIP("33.0.1.2/24").(ip.V4CIDR))] = nat.NewNATValue(0xdeadbeef, 2, 2, 0)
			svcs.m[nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222, 6, ip.MustParseCIDROrIP("38.0.1.2/16").(ip.V4CIDR))] = nat.NewNATValue(0xdeadbeef, 2, 2, 0)
			svcs.m[nat.NewNATKeySrc(net.IPv4(35, 0, 0, 2), 2222, 6, ip.MustParseCIDROrIP("40.0.1.2/32").(ip.V4CIDR))] = nat.NewNATValue(0xdeadbeef, 2, 2, 0)
			eps.m[nat.NewNATBackendKey(0xdeadbeef, 0)] = nat.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 666)
			eps.m[nat.NewNATBackendKey(0xdeadbeef, 1)] = nat.NewNATBackendValue(net.IPv4(7, 7, 7, 7), 777)
			s, _ = proxy.NewSyncer(nodeIPs, svcs, eps, aff, rt)
			Expect(svcs.m).To(HaveLen(4))

		}))

		By("Recreate the service with stale entries", makestep(func() {
			state.SvcMap[svcKey] = proxy.NewK8sServicePort(
				net.IPv4(10, 0, 0, 2),
				2222,
				v1.ProtocolTCP,
				proxy.K8sSvcWithExternalIPs([]string{"35.0.0.2"}),
				proxy.K8sSvcWithLBSourceRangeIPs([]string{"35.0.1.2/24"}),
			)
			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())
			Expect(svcs.m).To(HaveLen(3))
		}))

	})
})
