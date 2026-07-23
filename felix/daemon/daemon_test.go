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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/typha/pkg/discovery"
)

var _ = Describe("Typha address discovery", func() {
	var (
		configParams *config.Config
		endpoints1   *discoveryv1.EndpointSlice
		endpoints2   *discoveryv1.EndpointSlice
		k8sClient    *fake.Clientset
	)

	refreshClient := func() {
		k8sClient = fake.NewClientset(endpoints1, endpoints2)
	}

	BeforeEach(func() {
		configParams = config.New()
		_, err := configParams.UpdateFrom(map[string]string{
			"TyphaK8sServiceName": "calico-typha-service",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		udp := v1.ProtocolUDP
		tcp := v1.ProtocolTCP

		endpoints1 = &discoveryv1.EndpointSlice{
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

		endpoints2 = &discoveryv1.EndpointSlice{
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
				},
				{
					Addresses: []string{"10.0.0.5"},
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
		endpoints2.Endpoints[0].Addresses[0] = "fd5f:65af::2"
		refreshClient()
		typhaAddr, err := discoverTyphaAddrs(configParams, k8sClient)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(ConsistOf(
			discovery.Typha{Addr: "[fd5f:65af::2]:8156", IP: "fd5f:65af::2"},
		))
	})

	It("should error if no Typhas", func() {
		endpoints2.Endpoints = nil
		endpoints1.Endpoints = nil
		refreshClient()
		_, err := discoverTyphaAddrs(configParams, k8sClient)
		Expect(err).To(HaveOccurred())
	})

	It("should choose random Typhas", func() {
		endpoints2.Endpoints[0].Addresses = append(endpoints2.Endpoints[0].Addresses, "10.0.0.6")
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

func discoverTyphaAddrs(params *config.Config, sClient *fake.Clientset) ([]discovery.Typha, error) {
	disc := createTyphaDiscoverer(params, sClient)
	return disc.LoadTyphaAddrs()
}

var _ = Describe("applyBPFOverrides", func() {
	var configParams *config.Config

	bpfSupported := func() error { return nil }
	bpfNotSupported := func() error { return fmt.Errorf("BPF not supported") }

	BeforeEach(func() {
		configParams = config.New()
	})

	It("should be a no-op when BPF is not enabled", func() {
		// IPForwarding defaults to Enabled; set to Disabled to detect unwanted override.
		_, err := configParams.UpdateFrom(map[string]string{
			"IPForwarding": "Disabled",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		applyBPFOverrides(configParams, bpfSupported)

		Expect(configParams.BPFEnabled).To(BeFalse())
		Expect(configParams.IPForwarding).To(Equal("Disabled"))
	})

	It("should disable BPF when not supported by kernel", func() {
		_, err := configParams.UpdateFrom(map[string]string{
			"BPFEnabled": "true",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		applyBPFOverrides(configParams, bpfNotSupported)

		Expect(configParams.BPFEnabled).To(BeFalse())
	})

	It("should override BPFConntrackCleanupMode to Userspace", func() {
		_, err := configParams.UpdateFrom(map[string]string{
			"BPFEnabled": "true",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		applyBPFOverrides(configParams, bpfSupported)

		Expect(configParams.BPFConntrackCleanupMode).To(Equal("Userspace"))
	})

	It("should override BPFRedirectToPeer from L2Only to Enabled", func() {
		_, err := configParams.UpdateFrom(map[string]string{
			"BPFEnabled":        "true",
			"BPFRedirectToPeer": "L2Only",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		applyBPFOverrides(configParams, bpfSupported)

		Expect(configParams.BPFRedirectToPeer).To(Equal("Enabled"))
	})

	It("should not override BPFRedirectToPeer when not L2Only", func() {
		_, err := configParams.UpdateFrom(map[string]string{
			"BPFEnabled":        "true",
			"BPFRedirectToPeer": "Disabled",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		applyBPFOverrides(configParams, bpfSupported)

		Expect(configParams.BPFRedirectToPeer).To(Equal("Disabled"))
	})

	It("should force IPForwarding to Enabled when Disabled with RPF enabled", func() {
		_, err := configParams.UpdateFrom(map[string]string{
			"BPFEnabled":    "true",
			"IPForwarding":  "Disabled",
			"BPFEnforceRPF": "Strict",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		applyBPFOverrides(configParams, bpfSupported)

		Expect(configParams.IPForwarding).To(Equal("Enabled"))
	})

	It("should not force IPForwarding when RPF is Disabled", func() {
		_, err := configParams.UpdateFrom(map[string]string{
			"BPFEnabled":    "true",
			"IPForwarding":  "Disabled",
			"BPFEnforceRPF": "Disabled",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		applyBPFOverrides(configParams, bpfSupported)

		Expect(configParams.IPForwarding).To(Equal("Disabled"))
	})

	It("should not override IPForwarding when already Enabled", func() {
		_, err := configParams.UpdateFrom(map[string]string{
			"BPFEnabled":   "true",
			"IPForwarding": "Enabled",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		applyBPFOverrides(configParams, bpfSupported)

		Expect(configParams.IPForwarding).To(Equal("Enabled"))
	})

	It("should not apply other overrides when BPF is not supported", func() {
		_, err := configParams.UpdateFrom(map[string]string{
			"BPFEnabled":        "true",
			"IPForwarding":      "Disabled",
			"BPFRedirectToPeer": "L2Only",
		}, config.EnvironmentVariable)
		Expect(err).NotTo(HaveOccurred())

		applyBPFOverrides(configParams, bpfNotSupported)

		// BPF disabled, but no other overrides should have been applied.
		Expect(configParams.BPFEnabled).To(BeFalse())
		Expect(configParams.IPForwarding).To(Equal("Disabled"))
		Expect(configParams.BPFRedirectToPeer).To(Equal("L2Only"))
	})
})
