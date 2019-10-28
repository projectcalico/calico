package proxy_test

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/felix/bpf"
	proxy "github.com/projectcalico/felix/bpf/proxy"
	bpfm "github.com/projectcalico/felix/bpf/proxy/maps"
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
			svcKey: []k8sp.Endpoint{&k8sp.BaseEndpointInfo{"10.1.0.1:5555", false}},
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
		val, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 1), 1234, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))

		Expect(eps).To(HaveLen(1))
		bval, ok := eps[bpfm.NewNATBackendKey(val.ID(), 0)]
		Expect(ok).To(BeTrue())
		Expect(bval).To(Equal(bpfm.NewNATBackendValue(net.IPv4(10, 1, 0, 1), 5555)))
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
			&k8sp.BaseEndpointInfo{"10.2.0.1:1111", false},
			&k8sp.BaseEndpointInfo{"10.2.0.1:2222", false},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(2))
		val, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 1), 1234, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))
		val, ok = svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(2)))

		Expect(eps).To(HaveLen(3))
		Expect(eps).To(HaveKey(bpfm.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(HaveKey(bpfm.NewNATBackendKey(val.ID(), 1)))
		Expect(eps).To(ContainElement(bpfm.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 1111)))
		Expect(eps).To(ContainElement(bpfm.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
	})

	It("should be possible to delete the test-service", func() {
		delete(state.SvcMap, svcKey)
		delete(state.EpsMap, svcKey)

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(1))
		val, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(2)))

		Expect(eps).To(HaveLen(2))
		Expect(eps).To(HaveKey(bpfm.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(HaveKey(bpfm.NewNATBackendKey(val.ID(), 1)))
		Expect(eps).To(ContainElement(bpfm.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 1111)))
		Expect(eps).To(ContainElement(bpfm.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
	})

	It("should be possible to delete one second-service backend", func() {
		state.EpsMap[svcKey2] = []k8sp.Endpoint{
			&k8sp.BaseEndpointInfo{"10.2.0.1:2222", false},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(1))
		val, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))

		Expect(eps).To(HaveLen(1))
		Expect(eps).To(HaveKey(bpfm.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(ContainElement(bpfm.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
	})

	It("should should not programm eps without a service - non reachables", func() {
		nosvcKey := k8sp.ServicePortName{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "noservice",
			},
		}

		state.EpsMap[nosvcKey] = []k8sp.Endpoint{
			&k8sp.BaseEndpointInfo{"10.2.0.1:6666", false},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(1))
		val, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))

		Expect(eps).To(HaveLen(1))
		Expect(eps).To(HaveKey(bpfm.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(ContainElement(bpfm.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))

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

		val1, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val1.Count()).To(Equal(uint32(1)))

		val2, ok := svcs[bpfm.NewNATKey(net.IPv4(35, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val1).To(Equal(val2))

		Expect(eps).To(HaveLen(1))
		Expect(eps).To(HaveKey(bpfm.NewNATBackendKey(val1.ID(), 0)))
		Expect(eps).To(ContainElement(bpfm.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
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

		val, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val.Count()).To(Equal(uint32(1)))

		Expect(eps).To(HaveLen(1))
		Expect(eps).To(HaveKey(bpfm.NewNATBackendKey(val.ID(), 0)))
		Expect(eps).To(ContainElement(bpfm.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
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

			val1, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1.Count()).To(Equal(uint32(1)))

			val2, ok := svcs[bpfm.NewNATKey(net.IPv4(192, 168, 0, 1), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1).To(Equal(val2))

			val3, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 123, 0, 1), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
			Expect(ok).To(BeTrue())
			Expect(val1).To(Equal(val3))

			Expect(eps).To(HaveLen(1))
			Expect(eps).To(HaveKey(bpfm.NewNATBackendKey(val1.ID(), 0)))
			Expect(eps).To(ContainElement(bpfm.NewNATBackendValue(net.IPv4(10, 2, 0, 1), 2222)))
		}

		checkAfterResync()
	})

	It("should resync after creating a new syncer with the same result", func() {
		s, _ = proxy.NewSyncer(nodeIPs, svcs, eps)
		checkAfterResync()
	})

	It("should resync after creating a new syncer and delete stale entries", func() {
		svcs[bpfm.NewNATKey(net.IPv4(5, 5, 5, 5), 1111, 6)] = bpfm.NewNATValue(0xdeadbeef, 2)
		eps[bpfm.NewNATBackendKey(0xdeadbeef, 0)] = bpfm.NewNATBackendValue(net.IPv4(6, 6, 6, 6), 666)
		eps[bpfm.NewNATBackendKey(0xdeadbeef, 1)] = bpfm.NewNATBackendValue(net.IPv4(7, 7, 7, 7), 777)
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
			&k8sp.BaseEndpointInfo{"10.3.0.1:3434", false},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(6))
		Expect(eps).To(HaveLen(2))

		val1, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 2), 2222, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))]
		Expect(ok).To(BeTrue())
		Expect(val1.Count()).To(Equal(uint32(1)))

		val2, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 3), 3333, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val2.ID()).To(Equal(val1.ID()+1), "wrongly recycled svc ID?")

		val3, ok := svcs[bpfm.NewNATKey(net.IPv4(192, 168, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val3).To(Equal(val2))

		val4, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 123, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
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
			&k8sp.BaseEndpointInfo{"10.3.0.1:3434", false},
		}

		err := s.Apply(state)
		Expect(err).NotTo(HaveOccurred())

		Expect(svcs).To(HaveLen(6))
		Expect(eps).To(HaveLen(2))

		Expect(svcs).NotTo(HaveKey(
			bpfm.NewNATKey(net.IPv4(10, 0, 0, 3), 3333, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))))

		val2, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 0, 0, 3), 3355, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())

		val3, ok := svcs[bpfm.NewNATKey(net.IPv4(192, 168, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val3).To(Equal(val2))

		val4, ok := svcs[bpfm.NewNATKey(net.IPv4(10, 123, 0, 1), 3232, proxy.ProtoV1ToIntPanic(v1.ProtocolUDP))]
		Expect(ok).To(BeTrue())
		Expect(val4).To(Equal(val2))
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

type mockNATMap map[bpfm.NATKey]bpfm.NATValue

func (m mockNATMap) EnsureExists() error {
	return nil
}

func (m mockNATMap) Iter(iter bpf.MapIter) error {
	ks := len(bpfm.NATKey{})
	vs := len(bpfm.NATValue{})
	for k, v := range m {
		iter(k[:ks], v[:vs])
	}

	return nil
}

func (m mockNATMap) Update(k, v []byte) error {
	ks := len(bpfm.NATKey{})
	if len(k) != ks {
		return errors.Errorf("expected key size %d got %d", ks, len(k))
	}
	vs := len(bpfm.NATValue{})
	if len(v) != vs {
		return errors.Errorf("expected value size %d got %d", vs, len(k))
	}

	var key bpfm.NATKey
	copy(key[:ks], k[:ks])

	var val bpfm.NATValue
	copy(val[:vs], v[:vs])

	m[key] = val

	return nil
}

func (m mockNATMap) Delete(k []byte) error {
	ks := len(bpfm.NATKey{})
	if len(k) != ks {
		return errors.Errorf("expected key size %d got %d", ks, len(k))
	}

	var key bpfm.NATKey
	copy(key[:ks], k[:ks])

	delete(m, key)

	return nil
}

type mockNATBackendMap map[bpfm.NATBackendKey]bpfm.NATBackendValue

func (m mockNATBackendMap) EnsureExists() error {
	return nil
}

func (m mockNATBackendMap) Iter(iter bpf.MapIter) error {
	ks := len(bpfm.NATKey{})
	vs := len(bpfm.NATValue{})
	for k, v := range m {
		iter(k[:ks], v[:vs])
	}

	return nil
}

func (m mockNATBackendMap) Update(k, v []byte) error {
	ks := len(bpfm.NATBackendKey{})
	if len(k) != ks {
		return errors.Errorf("expected key size %d got %d", ks, len(k))
	}
	vs := len(bpfm.NATBackendValue{})
	if len(v) != vs {
		return errors.Errorf("expected value size %d got %d", vs, len(k))
	}

	var key bpfm.NATBackendKey
	copy(key[:ks], k[:ks])

	var val bpfm.NATBackendValue
	copy(val[:vs], v[:vs])

	m[key] = val

	return nil
}

func (m mockNATBackendMap) Delete(k []byte) error {
	ks := len(bpfm.NATBackendKey{})
	if len(k) != ks {
		return errors.Errorf("expected key size %d got %d", ks, len(k))
	}

	var key bpfm.NATBackendKey
	copy(key[:ks], k[:ks])

	delete(m, key)

	return nil
}
