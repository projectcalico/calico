// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package discovery

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

var _ = Describe("Typha address discovery", func() {
	var (
		endpointsTyphaService         *discoveryv1.EndpointSlice
		endpointsTyphaServiceV2       *discoveryv1.EndpointSlice
		k8sClient                     *fake.Clientset
		localNodeName, remoteNodeName string
		noTyphas                      []Typha
	)

	refreshClient := func() {
		k8sClient = fake.NewClientset(endpointsTyphaService, endpointsTyphaServiceV2)
	}

	BeforeEach(func() {
		localNodeName = "felix-local"
		remoteNodeName = "felix-remote"
		udp := v1.ProtocolUDP
		tcp := v1.ProtocolTCP

		endpointsTyphaService = &discoveryv1.EndpointSlice{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Endpoints",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-typha-service-abcde",
				Namespace: "kube-system",
				Labels:    map[string]string{"kubernetes.io/service-name": "calico-typha-service"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"10.0.0.4"},
					NodeName:  &localNodeName,
				},
			},
			Ports: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("calico-typha-v2"),
					Port:     ptr.To(int32(8157)),
					Protocol: &udp,
				},
			},
		}

		endpointsTyphaServiceV2 = &discoveryv1.EndpointSlice{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Endpoints",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-typha-service-fghij",
				Namespace: "kube-system",
				Labels:    map[string]string{"kubernetes.io/service-name": "calico-typha-service"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{
					Addresses: []string{"10.0.0.2"},
					NodeName:  &remoteNodeName,
				},
				{
					Addresses: []string{"10.0.0.5"},
					NodeName:  &remoteNodeName,
					Conditions: discoveryv1.EndpointConditions{
						Ready:   ptr.To(false),
						Serving: ptr.To(false),
					},
				},
			},
			Ports: []discoveryv1.EndpointPort{
				{
					Name:     ptr.To("calico-typha-v2"),
					Port:     ptr.To(int32(8157)),
					Protocol: &udp,
				},
				{
					Name:     ptr.To("calico-typha"),
					Port:     ptr.To(int32(8156)),
					Protocol: &tcp,
				},
			},
		}

		refreshClient()
	})

	It("should return address if configured", func() {
		typhaAddr, err := DiscoverTyphaAddrs(WithAddrOverride("10.0.0.1:8080"))
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal([]Typha{{Addr: "10.0.0.1:8080"}}))
	})

	It("should apply a filter", func() {
		typhaAddr, err := DiscoverTyphaAddrs(
			WithAddrOverride("10.0.0.1:8080"),
			WithPostDiscoveryFilter(func(typhaAddresses []Typha) ([]Typha, error) {
				return append(typhaAddresses, Typha{Addr: "10.0.0.2:8080"}), nil
			}),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal([]Typha{
			{Addr: "10.0.0.1:8080"},
			{Addr: "10.0.0.2:8080"},
		}))
	})
	It("should return error from filter", func() {
		_, err := DiscoverTyphaAddrs(
			WithAddrOverride("10.0.0.1:8080"),
			WithPostDiscoveryFilter(func(typhaAddresses []Typha) ([]Typha, error) {
				return nil, fmt.Errorf("BANG")
			}),
		)
		Expect(err).To(HaveOccurred())
	})

	It("should return nothing if no service name and no client", func() {
		typhaAddr, err := DiscoverTyphaAddrs()
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal(noTyphas))
	})

	It("should return nothing if no service name with client", func() {
		typhaAddr, err := DiscoverTyphaAddrs(WithKubeClient(k8sClient))
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal(noTyphas))
	})

	It("should return IP from endpoints", func() {
		discoverer := New(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
		)
		typhaAddr, err := discoverer.LoadTyphaAddrs()
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal([]Typha{
			{Addr: "10.0.0.2:8156", IP: "10.0.0.2", NodeName: &remoteNodeName},
		}))
		By("Returning the same result from the cache")
		typhaAddr = discoverer.CachedTyphaAddrs()
		Expect(typhaAddr).To(Equal([]Typha{
			{Addr: "10.0.0.2:8156", IP: "10.0.0.2", NodeName: &remoteNodeName},
		}))
	})

	It("should return v2 IP from endpoints if port name override is used, ordered with local endpoint first", func() {
		typhaAddr, err := DiscoverTyphaAddrs(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
			WithKubeServicePortNameOverride("calico-typha-v2"),
			WithNodeAffinity(localNodeName),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal([]Typha{
			{Addr: "10.0.0.4:8157", IP: "10.0.0.4", NodeName: &localNodeName},
			{Addr: "10.0.0.2:8157", IP: "10.0.0.2", NodeName: &remoteNodeName},
		}))
	})

	It("should bracket an IPv6 Typha address", func() {
		endpointsTyphaServiceV2.Endpoints[0].Addresses[0] = "fd5f:65af::2"
		refreshClient()
		typhaAddr, err := DiscoverTyphaAddrs(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal([]Typha{
			{Addr: "[fd5f:65af::2]:8156", IP: "fd5f:65af::2", NodeName: &remoteNodeName},
		}))
	})

	It("should error if no Typhas", func() {
		endpointsTyphaService.Endpoints = nil
		endpointsTyphaService.Ports = nil
		endpointsTyphaServiceV2.Endpoints = nil
		endpointsTyphaServiceV2.Ports = nil
		refreshClient()
		_, err := DiscoverTyphaAddrs(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
		)
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(ErrServiceNotReady))
	})

	It("should shuffle local and remote endpointsTyphaService and have local first", func() {
		udp := v1.ProtocolUDP
		tcp := v1.ProtocolTCP

		endpointsTyphaService.Endpoints = append(endpointsTyphaService.Endpoints, []discoveryv1.Endpoint{
			{
				Addresses: []string{"10.0.0.5"},
				NodeName:  &localNodeName,
			},
			{
				Addresses: []string{"10.0.0.6"},
				NodeName:  &localNodeName,
			},
			{
				Addresses: []string{"10.0.0.3"},
			},
			{
				Addresses: []string{"10.0.0.7"},
				NodeName:  &remoteNodeName,
			},
		}...,
		)

		endpointsTyphaService.Ports = append(endpointsTyphaService.Ports, []discoveryv1.EndpointPort{
			{
				Name:     ptr.To("calico-typha-v2"),
				Port:     ptr.To(int32(8157)),
				Protocol: &udp,
			},
			{
				Name:     ptr.To("calico-typha"),
				Port:     ptr.To(int32(8156)),
				Protocol: &tcp,
			},
		}...)
		refreshClient()

		typhaAddr, err := DiscoverTyphaAddrs(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
			WithKubeServicePortNameOverride("calico-typha-v2"),
			WithNodeAffinity(localNodeName),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(HaveLen(6))

		// First 3 should always be the local ones.  Last 3 the remote ones.
		Expect(typhaAddr[:3]).To(ConsistOf([]Typha{
			{Addr: "10.0.0.4:8157", IP: "10.0.0.4", NodeName: &localNodeName},
			{Addr: "10.0.0.5:8157", IP: "10.0.0.5", NodeName: &localNodeName},
			{Addr: "10.0.0.6:8157", IP: "10.0.0.6", NodeName: &localNodeName},
		}))
		Expect(typhaAddr[3:]).To(ConsistOf([]Typha{
			{Addr: "10.0.0.2:8157", IP: "10.0.0.2", NodeName: &remoteNodeName},
			{Addr: "10.0.0.3:8157", IP: "10.0.0.3"},
			{Addr: "10.0.0.7:8157", IP: "10.0.0.7", NodeName: &remoteNodeName},
		}))

		// Check that multiple calls to discover the addresses shuffles the order.
		var shuffledLocal bool
		var shuffledRemote bool
		for i := 0; i < 10; i++ {
			newTyphaAddr, err := DiscoverTyphaAddrs(
				WithKubeService("kube-system", "calico-typha-service"),
				WithKubeClient(k8sClient),
				WithKubeServicePortNameOverride("calico-typha-v2"),
				WithNodeAffinity(localNodeName),
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(newTyphaAddr).To(HaveLen(6))
			Expect(newTyphaAddr[:3]).To(ConsistOf(typhaAddr[:3]))
			Expect(newTyphaAddr[3:]).To(ConsistOf(typhaAddr[3:]))

			shuffledLocal = shuffledLocal || !reflect.DeepEqual(newTyphaAddr[:3], typhaAddr[:3])
			shuffledRemote = shuffledRemote || !reflect.DeepEqual(newTyphaAddr[3:], typhaAddr[3:])
		}

		Expect(shuffledLocal).To(BeTrue())
		Expect(shuffledRemote).To(BeTrue())
	})
})

func DiscoverTyphaAddrs(opts ...Option) ([]Typha, error) {
	discoverer := New(opts...)
	return discoverer.LoadTyphaAddrs()
}

var _ = Describe("ConnectionAttemptTracker", func() {
	var (
		cat        *ConnectionAttemptTracker
		discoverer *mockDiscoverer

		typha1 = Typha{Addr: "10.0.0.1:8157", IP: "10.0.0.1"}
		typha2 = Typha{Addr: "10.0.0.2:8157", IP: "10.0.0.2"}
		typha3 = Typha{Addr: "10.0.0.3:8157", IP: "10.0.0.3"}
		typha4 = Typha{Addr: "10.0.0.4:8157", IP: "10.0.0.4"}
	)

	BeforeEach(func() {
		discoverer = &mockDiscoverer{}
		cat = NewConnAttemptTracker(discoverer)
	})

	It("should expire cached last seen entries", func() {
		By("Recording the last seen time in the map")
		cat.pickNextTypha([]Typha{
			typha1,
			typha2,
		})
		Expect(cat.triedAddrsLastSeen).To(HaveLen(1))
		lastSeen := cat.triedAddrsLastSeen[typha1.dedupeKey()]
		Expect(lastSeen).To(BeTemporally("~", time.Now(), 100*time.Millisecond))

		By("Refreshing last seen if the particular typha is still present")
		cat.triedAddrsLastSeen[typha1.dedupeKey()] = time.Now().Add(-6 * time.Minute)
		cat.pickNextTypha([]Typha{
			typha1,
			typha2,
		})
		lastSeen = cat.triedAddrsLastSeen[typha1.dedupeKey()]
		Expect(lastSeen).To(BeTemporally("~", time.Now(), 100*time.Millisecond))

		By("Not expiring typha1 straight away")
		cat.pickNextTypha([]Typha{
			typha2,
			typha3,
			typha4,
		})
		Expect(cat.triedAddrsLastSeen[typha1.dedupeKey()]).To(Equal(lastSeen))

		By("Expiring typha1 once it times out")
		cat.triedAddrsLastSeen[typha1.dedupeKey()] = time.Now().Add(-6 * time.Minute)
		cat.pickNextTypha([]Typha{
			typha2,
			typha3,
			typha4,
		})
		Expect(cat.triedAddrsLastSeen).NotTo(HaveKey(typha1.dedupeKey()))
	})

	Describe("with same addrs each time", func() {
		BeforeEach(func() {
			addrs := []Typha{typha1, typha2}
			discoverer.TyphaAddrsToReturn = []typhaAddrsResp{
				{ts: addrs},
			}
			discoverer.CachedAddrs = addrs
		})
		It("should return the addresses in order", func() {
			Expect(cat.NextAddr()).To(Equal(typha1))
			Expect(cat.NextAddr()).To(Equal(typha2))

			// After returning all addresses, it should reset.
			Expect(cat.NextAddr()).To(Equal(typha1))
			Expect(cat.NextAddr()).To(Equal(typha2))
		})
	})

	Describe("with changing addrs", func() {
		BeforeEach(func() {
			discoverer.TyphaAddrsToReturn = []typhaAddrsResp{
				{ts: []Typha{typha1, typha3}},
				{ts: []Typha{typha3, typha4}},
				{ts: []Typha{typha3, typha4}},
				{ts: []Typha{typha3, typha4}},
			}
			discoverer.CachedAddrs = []Typha{typha1, typha2}
		})
		It("should return the addresses in order", func() {
			Expect(cat.NextAddr()).To(Equal(typha1)) // From cache
			// typha2 never returned due to forced reload.
			// typha1 returned again but it gets skipped due to already being seen.
			Expect(cat.NextAddr()).To(Equal(typha3))
			// Reloads again, typha3 gets skipped this time.
			Expect(cat.NextAddr()).To(Equal(typha4))
			// Reloads again, no fresh typhas, so we get typha3 again.
			Expect(cat.NextAddr()).To(Equal(typha3))
		})
	})

	Describe("with an error", func() {
		mockErr := fmt.Errorf("BANG")
		BeforeEach(func() {
			discoverer.TyphaAddrsToReturn = []typhaAddrsResp{
				{err: mockErr},
			}
			discoverer.CachedAddrs = []Typha{typha1, typha2}
		})
		It("should return the cached address and then an error", func() {
			Expect(cat.NextAddr()).To(Equal(typha1))
			_, err := cat.NextAddr()
			Expect(errors.Is(err, mockErr)).To(BeTrue(), "wrong/no error returned")
		})
	})
})

type typhaAddrsResp struct {
	ts  []Typha
	err error
}

type mockDiscoverer struct {
	TyphaAddrsToReturn []typhaAddrsResp
	n                  int
	CachedAddrs        []Typha
}

func (m *mockDiscoverer) LoadTyphaAddrs() (ts []Typha, err error) {
	ts = m.TyphaAddrsToReturn[m.n].ts
	err = m.TyphaAddrsToReturn[m.n].err
	m.n = (m.n + 1) % len(m.TyphaAddrsToReturn)
	m.CachedAddrs = ts
	return
}

func (m *mockDiscoverer) CachedTyphaAddrs() []Typha {
	return m.CachedAddrs
}
