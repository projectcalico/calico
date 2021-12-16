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
	"fmt"
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Typha address discovery", func() {
	var (
		endpoints *v1.Endpoints
		k8sClient *fake.Clientset
	)

	refreshClient := func() {
		k8sClient = fake.NewSimpleClientset(endpoints)
	}

	BeforeEach(func() {
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
						{IP: "10.0.0.4"},
					},
					NotReadyAddresses: []v1.EndpointAddress{},
					Ports: []v1.EndpointPort{
						{Name: "calico-typha-v2", Port: 8157, Protocol: v1.ProtocolUDP},
					},
				},
				{
					Addresses: []v1.EndpointAddress{
						{IP: "10.0.0.2"},
					},
					NotReadyAddresses: []v1.EndpointAddress{
						{IP: "10.0.0.5"},
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
		typhaAddr, err := DiscoverTyphaAddr(WithAddrOverride("10.0.0.1:8080"))
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal("10.0.0.1:8080"))
	})

	It("should return nothing if no service name and no client", func() {
		typhaAddr, err := DiscoverTyphaAddr()
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal(""))
	})

	It("should return nothing if no service name with client", func() {
		typhaAddr, err := DiscoverTyphaAddr(WithKubeClient(k8sClient))
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal(""))
	})

	It("should return IP from endpoints", func() {
		typhaAddr, err := DiscoverTyphaAddr(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal("10.0.0.2:8156"))
	})

	It("should return v2 IP from endpoints if port name override is used", func() {
		typhaAddr, err := DiscoverTyphaAddr(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
			WithKubeServicePortNameOverride("calico-typha-v2"),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Or(Equal("10.0.0.4:8157"), Equal("10.0.0.2:8157")))
	})

	It("should bracket an IPv6 Typha address", func() {
		endpoints.Subsets[1].Addresses[0].IP = "fd5f:65af::2"
		refreshClient()
		typhaAddr, err := DiscoverTyphaAddr(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal("[fd5f:65af::2]:8156"))
	})

	It("should error if no Typhas", func() {
		endpoints.Subsets = nil
		refreshClient()
		_, err := DiscoverTyphaAddr(
			WithKubeService("kube-system", "calico-typha-service"),
			WithKubeClient(k8sClient),
		)
		Expect(err).To(HaveOccurred())
	})

	It("should choose random Typhas", func() {
		seenAddresses := set.New()
		expected := set.From("10.0.0.2:8156", "10.0.0.6:8156")
		endpoints.Subsets[1].Addresses = append(endpoints.Subsets[1].Addresses, v1.EndpointAddress{IP: "10.0.0.6"})
		refreshClient()

		for i := 0; i < 32; i++ {
			addr, err := DiscoverTyphaAddr(
				WithKubeService("kube-system", "calico-typha-service"),
				WithKubeClient(k8sClient),
			)
			Expect(err).NotTo(HaveOccurred())
			seenAddresses.Add(addr)
			if seenAddresses.ContainsAll(expected) {
				return
			}
		}
		Fail(fmt.Sprintf("Didn't get expected values; got %v", seenAddresses))
	})
})
