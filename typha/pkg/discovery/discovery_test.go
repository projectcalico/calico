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
	"math/rand"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Typha address discovery", func() {
	var (
		endpoints                     *v1.Endpoints
		k8sClient                     *fake.Clientset
		localNodeName, remoteNodeName string
		noTyphas                      []Typha
	)

	refreshClient := func() {
		k8sClient = fake.NewSimpleClientset(endpoints)
	}

	BeforeEach(func() {
		localNodeName = "felix-local"
		remoteNodeName = "felix-remote"

		rand.Seed(time.Now().UTC().UnixNano())
		endpoints = &v1.Endpoints{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Endpoints",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-typha-service",
				Namespace: "kube-system",
			},
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{
						{IP: "10.0.0.4", NodeName: &localNodeName},
					},
					NotReadyAddresses: []v1.EndpointAddress{},
					Ports: []v1.EndpointPort{
						{Name: "calico-typha-v2", Port: 8157, Protocol: v1.ProtocolUDP},
					},
				},
				{
					Addresses: []v1.EndpointAddress{
						{IP: "10.0.0.2", NodeName: &remoteNodeName},
					},
					NotReadyAddresses: []v1.EndpointAddress{
						{IP: "10.0.0.5", NodeName: &remoteNodeName},
					},
					Ports: []v1.EndpointPort{
						{Name: "calico-typha-v2", Port: 8157, Protocol: v1.ProtocolUDP},
						{Name: "calico-typha", Port: 8156, Protocol: v1.ProtocolTCP},
					},
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
		typhaAddr, err := DiscoverTyphaAddrs(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
		)
		Expect(err).NotTo(HaveOccurred())
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
		endpoints.Subsets[1].Addresses[0].IP = "fd5f:65af::2"
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
		endpoints.Subsets = nil
		refreshClient()
		_, err := DiscoverTyphaAddrs(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
		)
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(ErrServiceNotReady))
	})

	It("should shuffle local and remote endpoints and have local first", func() {
		endpoints.Subsets = append(endpoints.Subsets, []v1.EndpointSubset{
			// Unrealistic, but have multiple endpoints on the same node, just with different IPs. This is to
			// test the local and remote endpoint shuffling.
			{
				Addresses: []v1.EndpointAddress{
					{IP: "10.0.0.5", NodeName: &localNodeName},
				},
				NotReadyAddresses: []v1.EndpointAddress{},
				Ports: []v1.EndpointPort{
					{Name: "calico-typha-v2", Port: 8157, Protocol: v1.ProtocolUDP},
				},
			},
			{
				Addresses: []v1.EndpointAddress{
					{IP: "10.0.0.6", NodeName: &localNodeName},
				},
				NotReadyAddresses: []v1.EndpointAddress{},
				Ports: []v1.EndpointPort{
					{Name: "calico-typha-v2", Port: 8157, Protocol: v1.ProtocolUDP},
				},
			},
			{
				Addresses: []v1.EndpointAddress{
					{IP: "10.0.0.3"},
					{IP: "10.0.0.7", NodeName: &remoteNodeName},
				},
				Ports: []v1.EndpointPort{
					{Name: "calico-typha-v2", Port: 8157, Protocol: v1.ProtocolUDP},
				},
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
