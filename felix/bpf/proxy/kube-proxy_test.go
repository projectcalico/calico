// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/mock"
	"github.com/projectcalico/calico/felix/bpf/nat"
	proxy "github.com/projectcalico/calico/felix/bpf/proxy"
	"github.com/projectcalico/calico/felix/proto"
)

var _ = Describe("BPF kube-proxy", func() {
	initIP := net.IPv4(1, 1, 1, 1)

	maps := new(bpfmap.IPMaps)
	maps.FrontendMap = newMockNATMap()
	maps.BackendMap = newMockNATBackendMap()
	maps.AffinityMap = newMockAffinityMap()
	maps.MaglevMap = newMockMaglevMap()
	maps.CtMap = mock.NewMockMap(conntrack.MapParams)
	front := maps.FrontendMap.(*mockNATMap)

	var p *proxy.KubeProxy

	healthCheckNodePort := 1212

	BeforeEach(func() {
		testSvc := &v1.Service{
			TypeMeta:   typeMetaV1("Service"),
			ObjectMeta: objectMetaV1("testService"),
			Spec: v1.ServiceSpec{
				ClusterIP: "10.1.0.1",
				Type:      v1.ServiceTypeLoadBalancer,
				Selector: map[string]string{
					"app": "test",
				},
				ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
				HealthCheckNodePort:   int32(healthCheckNodePort),
				Ports: []v1.ServicePort{
					{
						Protocol: v1.ProtocolTCP,
						Port:     1234,
						NodePort: 666,
					},
				},
			},
		}

		testSvcEps := &discoveryv1.EndpointSlice{
			TypeMeta:    typeMetaV1("EndpointSlice"),
			ObjectMeta:  objectMetaV1("testService"),
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"10.1.2.1"},
				},
			},
			Ports: []discoveryv1.EndpointPort{
				{
					Port:     ptr.To(int32(1234)),
					Name:     ptr.To("http"),
					Protocol: ptr.To(v1.ProtocolTCP),
				},
			},
		}

		k8s := fake.NewClientset(testSvc, testSvcEps)
		p, _ = proxy.StartKubeProxy(k8s, "test-node", maps, proxy.WithImmediateSync(), proxy.WithMaglevLUTSize(maglevLUTSize))
		// Unblock start(), which blocks on the initial host metadata update.
		p.OnUpdate(&proto.HostMetadataUpdate{Hostname: "dummy"})
		Expect(p.CompleteDeferredWork()).To(Succeed())
	})

	AfterEach(func() {
		p.Stop()
	})

	It("should update nodeports after host ip changes", func() {
		By("checking nodeport has the initial IP", func() {
			p.OnHostIPsUpdate([]net.IP{initIP})
			Eventually(func() bool {
				front.Lock()
				defer front.Unlock()

				for k := range front.m {
					if k.Addr().String() == initIP.String() {
						return true
					}
				}
				return false
			}).Should(BeTrue())
		})

		updatedIP := net.IPv4(2, 2, 2, 2)

		By("checking nodeport has the updated IP and not the initial IP", func() {
			p.OnHostIPsUpdate([]net.IP{updatedIP})

			Eventually(func() bool {
				front.Lock()
				defer front.Unlock()

				for k := range front.m {
					if k.Addr().String() == initIP.String() {
						return false
					}
					if k.Addr().String() == updatedIP.String() {
						return true
					}
				}
				return false
			}).Should(BeTrue())
		})

		By("checking nodeport has 2 updated IPs", func() {
			ip1 := net.IPv4(3, 3, 3, 3)
			ip2 := net.IPv4(4, 4, 4, 4)
			p.OnHostIPsUpdate([]net.IP{ip1, ip2})

			Eventually(func() bool {
				front.Lock()
				defer front.Unlock()

				ip1ok := false
				ip2ok := false

				for k := range front.m {
					if k.Addr().String() == ip1.String() {
						ip1ok = true
					} else if k.Addr().String() == ip2.String() {
						ip2ok = true
					}
				}
				return ip1ok && ip2ok
			}).Should(BeTrue())
		})
	})
})

// Regression for projectcalico/calico#12192. Felix restart on a node
// receiving NodePort traffic was breaking new TCP connections for ~500ms
// — the bootstrap window between kube-proxy starting up and receiving
// the first hostIPs. In that window, kube-proxy.go:start() used to
// construct the proxy with a stub Syncer (only podNPIP, no real host
// IPs). proxy.New() spins up the k8s informer goroutines synchronously;
// once they sync, an Apply runs against the stub Syncer. The cachingmap
// computes desired state without any (realHostIP, nodePort) FE entry
// and erases pre-existing real-host-IP NodePort FE entries left by the
// previous Felix run. New external TCP connections to the NodePort
// during the gap miss the FE map, ascend to the host stack with no
// listener, and get RST by the kernel.
//
// The fix defers proxy construction until both the first hostIPUpdates
// and the first hostMetadataUpdates have arrived — i.e. until run()
// is called with real host IPs. This test pre-populates the front map
// with a real-host-IP NodePort FE entry, fires the host-metadata
// in-sync gate but withholds the host IPs (mimicking the bootstrap
// window), and asserts the entry survives.
var _ = Describe("BPF kube-proxy bootstrap window — regression #12192", func() {
	var (
		bpfMaps *bpfmap.IPMaps
		front   *mockNATMap
		p       *proxy.KubeProxy
	)

	realHostIP := net.IPv4(10, 0, 0, 99)
	const nodePort = uint16(30000)

	BeforeEach(func() {
		bpfMaps = new(bpfmap.IPMaps)
		bpfMaps.FrontendMap = newMockNATMap()
		bpfMaps.BackendMap = newMockNATBackendMap()
		bpfMaps.AffinityMap = newMockAffinityMap()
		bpfMaps.MaglevMap = newMockMaglevMap()
		bpfMaps.CtMap = mock.NewMockMap(conntrack.MapParams)
		front = bpfMaps.FrontendMap.(*mockNATMap)

		// Marker entry simulating leftover state from the previous
		// Felix run. Value is not meaningful — only presence matters.
		markerKey := nat.NewNATKey(realHostIP, nodePort, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))
		front.m[markerKey] = nat.NewNATValue(0xdeadbeef, 1, 0, 0)
	})

	AfterEach(func() {
		if p != nil {
			p.Stop()
		}
	})

	It("does not erase pre-existing real-host-IP NodePort FE entries during the bootstrap window", func() {
		testSvc := &v1.Service{
			TypeMeta:   typeMetaV1("Service"),
			ObjectMeta: objectMetaV1("regression-12192-svc"),
			Spec: v1.ServiceSpec{
				ClusterIP: "10.1.0.1",
				Type:      v1.ServiceTypeNodePort,
				Selector:  map[string]string{"app": "test"},
				Ports: []v1.ServicePort{{
					Protocol: v1.ProtocolTCP,
					Port:     1234,
					NodePort: int32(nodePort),
				}},
			},
		}
		testSvcEps := &discoveryv1.EndpointSlice{
			TypeMeta:    typeMetaV1("EndpointSlice"),
			ObjectMeta:  objectMetaV1("regression-12192-svc"),
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.1.2.1"}}},
			Ports: []discoveryv1.EndpointPort{{
				Port:     ptr.To(int32(1234)),
				Name:     ptr.To("http"),
				Protocol: ptr.To(v1.ProtocolTCP),
			}},
		}
		k8s := fake.NewClientset(testSvc, testSvcEps)

		markerKey := nat.NewNATKey(realHostIP, nodePort, proxy.ProtoV1ToIntPanic(v1.ProtocolTCP))

		var err error
		p, err = proxy.StartKubeProxy(k8s, "test-node", bpfMaps,
			proxy.WithImmediateSync(),
			proxy.WithMaglevLUTSize(maglevLUTSize),
		)
		Expect(err).NotTo(HaveOccurred())

		// Fire the host-metadata in-sync gate but NOT the host IPs.
		// In the bootstrap window with the buggy code, the proxy is
		// already constructed and informers are syncing — they'll
		// trigger an Apply on the stub Syncer that erases the marker.
		p.OnUpdate(&proto.HostMetadataUpdate{Hostname: "test-node"})
		Expect(p.CompleteDeferredWork()).To(Succeed())

		// The marker must survive the bootstrap window. With
		// WithImmediateSync the fake-client informers sync and
		// schedule an Apply within tens of ms, so 500ms is a
		// generous bound.
		Consistently(func() bool {
			front.Lock()
			defer front.Unlock()
			_, ok := front.m[markerKey]
			return ok
		}, "500ms", "20ms").Should(BeTrue(),
			"pre-existing (realHostIP, nodePort) FE entry was erased during the kube-proxy bootstrap window")

		// Now release the host-IPs gate. The proxy is constructed
		// with real host IPs and informers fire their first Apply
		// against a Syncer whose desired state includes the
		// (realHostIP, nodePort) FE entry, so the entry stays
		// (cachingmap updates it in place to the proxy-computed
		// value).
		p.OnHostIPsUpdate([]net.IP{realHostIP})

		Eventually(func() bool {
			front.Lock()
			defer front.Unlock()
			_, ok := front.m[markerKey]
			return ok
		}, "5s", "50ms").Should(BeTrue(),
			"after host IPs propagated, real (realHostIP, nodePort) FE entry should remain")
	})
})
