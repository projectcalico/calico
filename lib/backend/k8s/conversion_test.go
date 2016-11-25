// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package k8s

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	k8sapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

var _ = Describe("Test parsing strings", func() {

	// Use a single instance of the converter for these tests.
	c := converter{}

	It("should parse workloadIDs", func() {
		workloadName := "Namespace.podName"
		ns, podName := c.parseWorkloadID(workloadName)
		Expect(ns).To(Equal("Namespace"))
		Expect(podName).To(Equal("podName"))
	})

	It("should parse policy names", func() {
		name := "Namespace.policyName"
		ns, polName := c.parsePolicyName(name)
		Expect(ns).To(Equal("Namespace"))
		Expect(polName).To(Equal("policyName"))
	})

	It("should parse profile names", func() {
		name := "k8s_ns.default"
		ns, err := c.parseProfileName(name)
		Expect(ns).To(Equal("default"))
		Expect(err).NotTo(HaveOccurred())
	})

})

var _ = Describe("Test Pod conversion", func() {

	// Use a single instance of the converter for these tests.
	c := converter{}

	It("should parse a Pod with an IP to a WorkloadEndpoint", func() {
		pod := k8sapi.Pod{
			ObjectMeta: k8sapi.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Annotations: map[string]string{
					"arbitrary": "annotation",
				},
				Labels: map[string]string{
					"labelA": "valueA",
					"labelB": "valueB",
				},
				ResourceVersion: "1234",
			},
			Spec: k8sapi.PodSpec{
				NodeName: "nodeA",
			},
			Status: k8sapi.PodStatus{
				PodIP: "192.168.0.1",
			},
		}

		wep, err := c.podToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields.
		Expect(wep.Key.(model.WorkloadEndpointKey).WorkloadID).To(Equal("default.podA"))
		Expect(wep.Key.(model.WorkloadEndpointKey).Hostname).To(Equal("nodeA"))
		Expect(wep.Key.(model.WorkloadEndpointKey).EndpointID).To(Equal("eth0"))
		Expect(wep.Key.(model.WorkloadEndpointKey).OrchestratorID).To(Equal("k8s"))

		// Assert value fields.
		Expect(len(wep.Value.(*model.WorkloadEndpoint).IPv6Nets)).To(Equal(0))
		Expect(len(wep.Value.(*model.WorkloadEndpoint).IPv4Nets)).To(Equal(1))
		Expect(wep.Value.(*model.WorkloadEndpoint).IPv4Nets[0].String()).To(Equal("192.168.0.1/32"))
		Expect(wep.Value.(*model.WorkloadEndpoint).State).To(Equal("active"))
		expectedLabels := map[string]string{"labelA": "valueA", "labelB": "valueB", "calico/k8s_ns": "default"}
		Expect(wep.Value.(*model.WorkloadEndpoint).Labels).To(Equal(expectedLabels))

		// Assert ResourceVersion is present.
		Expect(wep.Revision.(string)).To(Equal("1234"))
	})

	It("should parse a Pod without an IP to a WorkloadEndpoint", func() {
		pod := k8sapi.Pod{
			ObjectMeta: k8sapi.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Annotations: map[string]string{
					"arbitrary": "annotation",
				},
				Labels: map[string]string{
					"labelA": "valueA",
					"labelB": "valueB",
				},
			},
			Spec: k8sapi.PodSpec{
				NodeName: "nodeA",
			},
			Status: k8sapi.PodStatus{},
		}

		wep, err := c.podToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields.
		Expect(wep.Key.(model.WorkloadEndpointKey).WorkloadID).To(Equal("default.podA"))
		Expect(wep.Key.(model.WorkloadEndpointKey).Hostname).To(Equal("nodeA"))
		Expect(wep.Key.(model.WorkloadEndpointKey).EndpointID).To(Equal("eth0"))
		Expect(wep.Key.(model.WorkloadEndpointKey).OrchestratorID).To(Equal("k8s"))

		// Assert value fields.
		Expect(len(wep.Value.(*model.WorkloadEndpoint).IPv6Nets)).To(Equal(0))
		Expect(len(wep.Value.(*model.WorkloadEndpoint).IPv4Nets)).To(Equal(0))
		Expect(wep.Value.(*model.WorkloadEndpoint).State).To(Equal("active"))
		expectedLabels := map[string]string{"labelA": "valueA", "labelB": "valueB", "calico/k8s_ns": "default"}
		Expect(wep.Value.(*model.WorkloadEndpoint).Labels).To(Equal(expectedLabels))
	})

	It("should parse a Pod with no labels", func() {
		pod := k8sapi.Pod{
			ObjectMeta: k8sapi.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
			},
			Spec: k8sapi.PodSpec{
				NodeName: "nodeA",
			},
			Status: k8sapi.PodStatus{
				PodIP: "192.168.0.1",
			},
		}

		wep, err := c.podToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields.
		Expect(wep.Key.(model.WorkloadEndpointKey).WorkloadID).To(Equal("default.podA"))
		Expect(wep.Key.(model.WorkloadEndpointKey).Hostname).To(Equal("nodeA"))
		Expect(wep.Key.(model.WorkloadEndpointKey).EndpointID).To(Equal("eth0"))
		Expect(wep.Key.(model.WorkloadEndpointKey).OrchestratorID).To(Equal("k8s"))

		// Assert value fields.
		Expect(len(wep.Value.(*model.WorkloadEndpoint).IPv6Nets)).To(Equal(0))
		Expect(len(wep.Value.(*model.WorkloadEndpoint).IPv4Nets)).To(Equal(1))
		Expect(wep.Value.(*model.WorkloadEndpoint).State).To(Equal("active"))
		Expect(wep.Value.(*model.WorkloadEndpoint).Labels).To(Equal(map[string]string{"calico/k8s_ns": "default"}))
	})
})

var _ = Describe("Test NetworkPolicy conversion", func() {

	// Use a single instance of the converter for these tests.
	c := converter{}

	It("should parse a basic NetworkPolicy to a Policy", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: k8sapi.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: unversioned.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []extensions.NetworkPolicyIngressRule{
					extensions.NetworkPolicyIngressRule{
						Ports: []extensions.NetworkPolicyPort{
							extensions.NetworkPolicyPort{},
						},
						From: []extensions.NetworkPolicyPeer{
							extensions.NetworkPolicyPeer{
								PodSelector: &unversioned.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
						},
					},
				},
			},
		}

		// Parse the policy.
		pol, err := c.networkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default' && label == 'value'"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(1))
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))
		Expect(pol.Value.(*model.Policy).InboundRules[0].SrcSelector).To(Equal("calico/k8s_ns == 'default' && k == 'v'"))
	})
})

var _ = Describe("Test Namespace conversion", func() {

	// Use a single instance of the converter for these tests.
	c := converter{}

	It("should parse a Namespace to a Profile with allow rules", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name:        "default",
				Annotations: map[string]string{},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		p, err := c.namespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())

		// Ensure rules are correct.
		inboundRules := p.Value.(*model.Profile).Rules.InboundRules
		outboundRules := p.Value.(*model.Profile).Rules.OutboundRules
		Expect(len(inboundRules)).To(Equal(1))
		Expect(len(outboundRules)).To(Equal(1))
		Expect(inboundRules[0].Action).To(Equal("allow"))
		Expect(outboundRules[0].Action).To(Equal("allow"))
	})

	It("should parse a Namespace to a Profile with deny rules", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{\"ingress\": {\"isolation\": \"DefaultDeny\"}}",
				},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		p, err := c.namespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())

		// Ensure rules are correct.
		inboundRules := p.Value.(*model.Profile).Rules.InboundRules
		outboundRules := p.Value.(*model.Profile).Rules.OutboundRules
		Expect(len(inboundRules)).To(Equal(1))
		Expect(len(outboundRules)).To(Equal(1))
		Expect(inboundRules[0].Action).To(Equal("deny"))
		Expect(outboundRules[0].Action).To(Equal("allow"))
	})

	It("should fail for invalid annotation", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "invalidJSON",
				},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		_, err := c.namespaceToProfile(&ns)
		Expect(err).To(HaveOccurred())
	})

	It("should handle a valid but not DefaultDeny annotation", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{}",
				},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		p, err := c.namespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())

		// Ensure rules are correct.
		inboundRules := p.Value.(*model.Profile).Rules.InboundRules
		outboundRules := p.Value.(*model.Profile).Rules.OutboundRules
		Expect(len(inboundRules)).To(Equal(1))
		Expect(len(outboundRules)).To(Equal(1))
		Expect(inboundRules[0].Action).To(Equal("allow"))
		Expect(outboundRules[0].Action).To(Equal("allow"))
	})
})
