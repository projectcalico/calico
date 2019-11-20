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

package proxy_test

import (
	"net"

	"github.com/projectcalico/felix/bpf/nat"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/felix/bpf"
	proxy "github.com/projectcalico/felix/bpf/proxy"
)

func init() {
	logrus.SetOutput(GinkgoWriter)
	logrus.SetLevel(logrus.DebugLevel)
}

var _ = Describe("BPF Syncer", func() {
	svcs := make(mockNATMap)
	eps := make(mockNATBackendMap)

	nodeIPs := []net.IP{net.IPv4(192, 168, 0, 1), net.IPv4(10, 123, 0, 1)}

	s, _ := proxy.NewSyncer(nodeIPs, svcs, eps)

	svcKey := k8sp.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "test-service",
		},
	}

	state := proxy.DPSyncerState{
		SvcMap: k8sp.ServiceMap{
			svcKey: &k8sp.BaseServiceInfo{
				ClusterIP: net.IPv4(10, 0, 0, 1),
				Port:      1234,
				Protocol:  v1.ProtocolTCP,
			},
		},
		EpsMap: k8sp.EndpointsMap{
			svcKey: []k8sp.Endpoint{&k8sp.BaseEndpointInfo{Endpoint: "10.1.0.1:5555"}},
		},
	}

	JustAfterEach(func() {
		log("svcs = %+v\n", svcs)
		log("eps = %+v\n", eps)
	})

	It("should be possible to insert a service with endpoint", func() {
		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(1))
		val, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 1), 1234, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))

		Expect(eps).To(HaveLen(1))
		bval, ok := eps[nat.NewNATBackendKey(val.ID(), 0)]
		Expect(ok).To(BeTrue())
		Expect(bval).To(Equal(nat.NewNATBackendValue(net.IPv4(10, 1, 0, 1), 5555)))
	})

	svcKey2 := k8sp.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "second-service",
		},
	}

	It("should be possible to insert another service with multiple endpoints", func() {
		state.SvcMap[svcKey2] = &k8sp.BaseServiceInfo{
			ClusterIP: net.IPv4(10, 0, 0, 2),
			Port:      2222,
			Protocol:  v1.ProtocolTCP,
		}
		state.EpsMap[svcKey2] = []k8sp.Endpoint{
			&k8sp.BaseEndpointInfo{Endpoint: "10.2.0.1:1111"},
			&k8sp.BaseEndpointInfo{Endpoint: "10.2.0.1:2222"},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(2))
		val, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 1), 1234, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))
		val, ok = svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(2)))

		Expect(eps).To(HaveLen(3))
		Expect(eps).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(HaveKey(nat.NewNATBackendKey(val.ID(), 1)))
		Expect(eps).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 1111)))
		Expect(eps).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
	})

	It("should be possible to delete the test-service", func() {
		delete(state.SvcMap, svcKey)
		delete(state.EpsMap, svcKey)

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(1))
		val, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(2)))

		Expect(eps).To(HaveLen(2))
		Expect(eps).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(HaveKey(nat.NewNATBackendKey(val.ID(), 1)))
		Expect(eps).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 1111)))
		Expect(eps).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
	})

	It("should be possible to delete one second-service backend", func() {
		state.EpsMap[svcKey2] = []k8sp.Endpoint{
			&k8sp.BaseEndpointInfo{Endpoint: "10.2.0.1:2222"},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(1))
		val, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))

		Expect(eps).To(HaveLen(1))
		Expect(eps).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
	})

	It("should should not programm eps without a service - non reachables", func() {
		nosvcKey := k8sp.ServicePortName{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "noservice",
			},
		}

		state.EpsMap[nosvcKey] = []k8sp.Endpoint{
			&k8sp.BaseEndpointInfo{Endpoint: "10.2.0.1:6666"},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(1))
		val, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))

		Expect(eps).To(HaveLen(1))
		Expect(eps).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))

		delete(state.EpsMap, nosvcKey)
	})

	It("should add ExternalIP for existing service", func() {
		state.SvcMap[svcKey2] = &k8sp.BaseServiceInfo{
			ClusterIP:   net.IPv4(10, 0, 0, 2),
			Port:        2222,
			Protocol:    v1.ProtocolTCP,
			ExternalIPs: []string{"35.0.0.2"},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(2))

		val1, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val1.Count()).To(Equal(uint32(1)))

		val2, ok := svcs[nat.NewNATKey(net.IPv4(35, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val1).To(Equal(val2))

		Expect(eps).To(HaveLen(1))
		Expect(eps).To(HaveKey(nat.NewNATBackendKey(val1.ID(), 0)))
		Expect(eps).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
	})

	It("should remove ExternalIP for existing service", func() {
		state.SvcMap[svcKey2] = &k8sp.BaseServiceInfo{
			ClusterIP: net.IPv4(10, 0, 0, 2),
			Port:      2222,
			Protocol:  v1.ProtocolTCP,
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(1))

		val, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))

		Expect(eps).To(HaveLen(1))
		Expect(eps).To(HaveKey(nat.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
	})

	var checkAfterResync func()

	It("should turn existing service into a NodePort", func() {
		state.SvcMap[svcKey2] = &k8sp.BaseServiceInfo{
			ClusterIP: net.IPv4(10, 0, 0, 2),
			Port:      2222,
			NodePort:  2222,
			Protocol:  v1.ProtocolTCP,
		}

		checkAfterResync = func() {
			err := s.Apply(state)
			Expect(err).NotTo(HaveOccurred())

			Expect(svcs).To(HaveLen(3))

			val1, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1.Count()).To(Equal(uint32(1)))

			val2, ok := svcs[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1).To(Equal(val2))

			val3, ok := svcs[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1).To(Equal(val3))

			Expect(eps).To(HaveLen(1))
			Expect(eps).To(HaveKey(nat.NewNATBackendKey(val1.ID(), 0)))
			Expect(eps).To(ContainElement(nat.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
		}

		checkAfterResync()
	})

	It("should resync after creating a new syncer with the same result", func() {
		s, _ = proxy.NewSyncer(nodeIPs, svcs, eps)
		checkAfterResync()
	})

	It("should resync after creating a new syncer and delete stale entries", func() {
		svcs[nat.NewNATKey(net.IPv4(5, 5, 5, 5), 1111, 6)] = nat.NewNATValue(0xdeadbeef, 2)
		eps[nat.NewNATBackendKey(0xdeadbeef, 0)] = nat.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 666)
		eps[nat.NewNATBackendKey(0xdeadbeef, 1)] = nat.NewNATBackendValue(net.IPv4(7, 7, 7, 7), 777)
		s, _ = proxy.NewSyncer(nodeIPs, svcs, eps)
		checkAfterResync()
	})

	svcKey3 := k8sp.ServicePortName{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "third-service",
		},
	}

	It("should be possible to insert another service after resync", func() {
		state.SvcMap[svcKey3] = &k8sp.BaseServiceInfo{
			ClusterIP: net.IPv4(10, 0, 0, 3),
			Port:      3333,
			NodePort:  3232,
			Protocol:  v1.ProtocolUDP,
		}
		state.EpsMap[svcKey3] = []k8sp.Endpoint{
			&k8sp.BaseEndpointInfo{Endpoint: "10.3.0.1:3434"},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(6))
		Expect(eps).To(HaveLen(2))

		val1, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val1.Count()).To(Equal(uint32(1)))

		val2, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3333, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val2.ID()).To(Equal(val1.ID()+1), "wrongly recycled svc ID?")

		val3, ok := svcs[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val3).To(Equal(val2))

		val4, ok := svcs[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val4).To(Equal(val2))
	})

	It("should be possible to update a port of a service", func() {
		state.SvcMap[svcKey3] = &k8sp.BaseServiceInfo{
			ClusterIP: net.IPv4(10, 0, 0, 3),
			Port:      3355,
			NodePort:  3232,
			Protocol:  v1.ProtocolUDP,
		}
		state.EpsMap[svcKey3] = []k8sp.Endpoint{
			&k8sp.BaseEndpointInfo{Endpoint: "10.3.0.1:3434"},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(6))
		Expect(eps).To(HaveLen(2))

		Expect(svcs).NotTo(HaveKey(
			nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3333, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))))

		val2, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3355, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())

		val3, ok := svcs[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val3).To(Equal(val2))

		val4, ok := svcs[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val4).To(Equal(val2))
	})

	It("should be possible to update a NodePort of a service", func() {
		state.SvcMap[svcKey3] = &k8sp.BaseServiceInfo{
			ClusterIP: net.IPv4(10, 0, 0, 3),
			Port:      3355,
			NodePort:  1212,
			Protocol:  v1.ProtocolUDP,
		}
		state.EpsMap[svcKey3] = []k8sp.Endpoint{
			&k8sp.BaseEndpointInfo{Endpoint: "10.3.0.1:3434"},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(6))
		Expect(eps).To(HaveLen(2))

		Expect(svcs).NotTo(HaveKey(
			nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3333, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))))

		val2, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 3), 3355, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())

		val3, ok := svcs[nat.NewNATKey(net.IPv4(192, 168, 0, 1), 1212, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val3).To(Equal(val2))

		val4, ok := svcs[nat.NewNATKey(net.IPv4(10, 123, 0, 1), 1212, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val4).To(Equal(val2))
	})

	It("should delete backends if there are none for a service BPF-147", func() {
		val, ok := svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		count := val.Count()
		for i := uint32(0); i < count; i++ {
			Expect(eps).To(HaveKey(nat.NewNATBackendKey(val.ID(), i)))
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

		val, ok = svcs[nat.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(0)))
		for i := uint32(0); i < count; i++ {
			Expect(eps).NotTo(HaveKey(nat.NewNATBackendKey(val.ID(), i)))
		}
	})

	It("should delete the services", func() {
		delete(state.SvcMap, svcKey2)
		delete(state.SvcMap, svcKey3)

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(0))
		Expect(eps).To(HaveLen(0))
	})
})

type mockNATMap map[nat.FrontendKey]nat.FrontendValue

func (m mockNATMap) EnsureExists() error {
	return nil
}

func (m mockNATMap) Path() string {
	return "/sys/fs/bpf/tc/nat"
}

func (m mockNATMap) Iter(iter bpf.MapIter) error {
	ks := len(nat.FrontendKey{})
	vs := len(nat.FrontendValue{})
	for k, v := range m {
		iter(k[:ks], v[:vs])
	}

	return nil
}

func (m mockNATMap) Update(k, v []byte) error {
	ks := len(nat.FrontendKey{})
	if len(k) != ks {
		return errors.Errorf("expected key size %d got %d", ks, len(k))
	}
	vs := len(nat.FrontendValue{})
	if len(v) != vs {
		return errors.Errorf("expected value size %d got %d", vs, len(k))
	}

	var key nat.FrontendKey
	copy(key[:ks], k[:ks])

	var val nat.FrontendValue
	copy(val[:vs], v[:vs])

	m[key] = val

	return nil
}

func (m mockNATMap) Get(k []byte) ([]byte, error) {
	panic("not implemented")
}

func (m mockNATMap) Delete(k []byte) error {
	ks := len(nat.FrontendKey{})
	if len(k) != ks {
		return errors.Errorf("expected key size %d got %d", ks, len(k))
	}

	var key nat.FrontendKey
	copy(key[:ks], k[:ks])

	delete(m, key)

	return nil
}

type mockNATBackendMap map[nat.BackendKey]nat.BackendValue

func (m mockNATBackendMap) EnsureExists() error {
	return nil
}

func (m mockNATBackendMap) Path() string {
	return "/sys/fs/bpf/tc/natbe"
}

func (m mockNATBackendMap) Iter(iter bpf.MapIter) error {
	ks := len(nat.FrontendKey{})
	vs := len(nat.FrontendValue{})
	for k, v := range m {
		iter(k[:ks], v[:vs])
	}

	return nil
}

func (m mockNATBackendMap) Update(k, v []byte) error {
	ks := len(nat.BackendKey{})
	if len(k) != ks {
		return errors.Errorf("expected key size %d got %d", ks, len(k))
	}
	vs := len(nat.BackendValue{})
	if len(v) != vs {
		return errors.Errorf("expected value size %d got %d", vs, len(k))
	}

	var key nat.BackendKey
	copy(key[:ks], k[:ks])

	var val nat.BackendValue
	copy(val[:vs], v[:vs])

	m[key] = val

	return nil
}

func (m mockNATBackendMap) Get(k []byte) ([]byte, error) {
	panic("not implemented")
}

func (m mockNATBackendMap) Delete(k []byte) error {
	ks := len(nat.BackendKey{})
	if len(k) != ks {
		return errors.Errorf("expected key size %d got %d", ks, len(k))
	}

	var key nat.BackendKey
	copy(key[:ks], k[:ks])

	delete(m, key)

	return nil
}
