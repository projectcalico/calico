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

package daemon

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/typha/pkg/discovery"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Typha address discovery", func() {
	var (
		configParams *config.Config
		endpoints    *v1.Endpoints
		k8sClient    *fake.Clientset
	)

	refreshClient := func() {
		k8sClient = fake.NewSimpleClientset(endpoints)
	}

	BeforeEach(func() {
		configParams = config.New()
		_, err := configParams.UpdateFrom(map[string]string{
			"TyphaK8sServiceName": "calico-typha-service",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

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
		configParams.TyphaAddr = "10.0.0.1:8080"
		typhaAddr, err := discoverTyphaAddrs(configParams, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal([]discovery.Typha{{Addr: "10.0.0.1:8080"}}))
	})

	It("should return nothing if no service name", func() {
		configParams.TyphaK8sServiceName = ""
		typhaAddr, err := discoverTyphaAddrs(configParams, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(BeNil())
	})

	It("should return IP from endpoints", func() {
		typhaAddr, err := discoverTyphaAddrs(configParams, k8sClient)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(ConsistOf(
			discovery.Typha{Addr: "10.0.0.2:8156", IP: "10.0.0.2"},
		))
	})

	It("should bracket an IPv6 Typha address", func() {
		endpoints.Subsets[1].Addresses[0].IP = "fd5f:65af::2"
		refreshClient()
		typhaAddr, err := discoverTyphaAddrs(configParams, k8sClient)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(ConsistOf(
			discovery.Typha{Addr: "[fd5f:65af::2]:8156", IP: "fd5f:65af::2"},
		))
	})

	It("should error if no Typhas", func() {
		endpoints.Subsets = nil
		refreshClient()
		_, err := discoverTyphaAddrs(configParams, k8sClient)
		Expect(err).To(HaveOccurred())
	})

	It("should choose random Typhas", func() {
		endpoints.Subsets[1].Addresses = append(endpoints.Subsets[1].Addresses, v1.EndpointAddress{IP: "10.0.0.6"})
		refreshClient()

		addr, err := discoverTyphaAddrs(configParams, k8sClient)
		Expect(err).NotTo(HaveOccurred())
		Expect(addr).To(
			ContainElements(
				discovery.Typha{Addr: "10.0.0.2:8156", IP: "10.0.0.2"},
				discovery.Typha{Addr: "10.0.0.6:8156", IP: "10.0.0.6"},
			),
		)
	})
})
