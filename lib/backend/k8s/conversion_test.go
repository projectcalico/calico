// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/libcalico-go/lib/numorstring"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8sapi "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

var _ = Describe("Test parsing strings", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse workloadIDs", func() {
		workloadName := "Namespace.podName"
		ns, podName := c.parseWorkloadID(workloadName)
		Expect(ns).To(Equal("Namespace"))
		Expect(podName).To(Equal("podName"))
	})

	It("should parse valid policy names", func() {
		// Parse a NetworkPolicy backed Policy.
		name := "knp.default.Namespace.policyName"
		ns, polName, err := c.parsePolicyNameNetworkPolicy(name)
		Expect(err).NotTo(HaveOccurred())
		Expect(ns).To(Equal("Namespace"))
		Expect(polName).To(Equal("policyName"))
	})

	It("should not parse invalid policy names", func() {
		name := "something.projectcalico.org/Namespace.Name"

		// As a NetworkPolicy.
		ns, polName, err := c.parsePolicyNameNetworkPolicy(name)
		Expect(err).To(HaveOccurred())
		Expect(ns).To(Equal(""))
		Expect(polName).To(Equal(""))
	})

	It("should parse valid profile names", func() {
		name := "k8s_ns.default"
		ns, err := c.parseProfileName(name)
		Expect(ns).To(Equal("default"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not parse invalid profile names", func() {
		name := "ns.projectcalico.org/default"
		ns, err := c.parseProfileName(name)
		Expect(err).To(HaveOccurred())
		Expect(ns).To(Equal(""))
	})
})

var _ = Describe("Test Pod conversion", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse a Pod with an IP to a WorkloadEndpoint", func() {
		pod := k8sapi.Pod{
			ObjectMeta: metav1.ObjectMeta{
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
				Containers: []k8sapi.Container{
					{
						Ports: []k8sapi.ContainerPort{
							{
								ContainerPort: 5678,
							},
							{
								Name:          "no-proto",
								ContainerPort: 1234,
							},
						},
					},
					{
						Ports: []k8sapi.ContainerPort{
							{
								Name:          "tcp-proto",
								Protocol:      k8sapi.ProtocolTCP,
								ContainerPort: 1024,
							},
							{
								Name:          "tcp-proto-with-host-port",
								Protocol:      k8sapi.ProtocolTCP,
								ContainerPort: 8080,
								HostPort:      5678,
							},
							{
								Name:          "udp-proto",
								Protocol:      k8sapi.ProtocolUDP,
								ContainerPort: 432,
							},
							{
								Name:          "unkn-proto",
								Protocol:      k8sapi.Protocol("unknown"),
								ContainerPort: 567,
							},
						},
					},
				},
			},
			Status: k8sapi.PodStatus{
				PodIP: "192.168.0.1",
			},
		}

		wep, err := c.PodToWorkloadEndpoint(&pod)
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

		nsProtoTCP := numorstring.ProtocolFromString("tcp")
		nsProtoUDP := numorstring.ProtocolFromString("udp")
		Expect(wep.Value.(*model.WorkloadEndpoint).Ports).To(ConsistOf(
			// No proto defaults to TCP (as defined in k8s API spec)
			model.EndpointPort{Name: "no-proto", Port: 1234, Protocol: nsProtoTCP},
			// Explicit TCP proto is OK too.
			model.EndpointPort{Name: "tcp-proto", Port: 1024, Protocol: nsProtoTCP},
			// Host port should be ignored.
			model.EndpointPort{Name: "tcp-proto-with-host-port", Port: 8080, Protocol: nsProtoTCP},
			// UDP is also an option.
			model.EndpointPort{Name: "udp-proto", Port: 432, Protocol: nsProtoUDP},
			// Unknown protocol port is ignored.
		))

		// Assert ResourceVersion is present.
		Expect(wep.Revision).To(Equal("1234"))
	})

	It("should not parse a Pod without an IP to a WorkloadEndpoint", func() {
		pod := k8sapi.Pod{
			ObjectMeta: metav1.ObjectMeta{
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

		_, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should parse a Pod with no labels", func() {
		pod := k8sapi.Pod{
			ObjectMeta: metav1.ObjectMeta{
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

		wep, err := c.PodToWorkloadEndpoint(&pod)
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

	It("should Parse a Pod with no NodeName", func() {
		pod := k8sapi.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
			},
			Spec: k8sapi.PodSpec{},
			Status: k8sapi.PodStatus{
				PodIP: "192.168.0.1",
			},
		}

		_, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())
	})

})

var _ = Describe("Test NetworkPolicy conversion", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse a basic NetworkPolicy to a Policy", func() {
		port80 := intstr.FromInt(80)
		portFoo := intstr.FromString("foo")
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"label":  "value",
						"label2": "value2",
					},
				},
				Ingress: []extensions.NetworkPolicyIngressRule{
					{
						Ports: []extensions.NetworkPolicyPort{
							{Port: &port80},
							{Port: &portFoo},
						},
						From: []extensions.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k":  "v",
										"k2": "v2",
									},
								},
							},
						},
					},
				},
			},
		}

		// Parse the policy.
		pol, err := c.NetworkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("knp.default.default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		// Check the selector is correct, and that the matches are sorted.
		Expect(pol.Value.(*model.Policy).Selector).To(Equal(
			"calico/k8s_ns == 'default' && label == 'value' && label2 == 'value2'"))
		protoTCP := numorstring.ProtocolFromString("tcp")
		Expect(pol.Value.(*model.Policy).InboundRules).To(ConsistOf(
			model.Rule{
				Action:      "allow",
				Protocol:    &protoTCP, // Defaulted to TCP.
				SrcSelector: "calico/k8s_ns == 'default' && k == 'v' && k2 == 'v2'",
				DstPorts:    []numorstring.Port{numorstring.SinglePort(80)},
			},
			model.Rule{
				Action:      "allow",
				Protocol:    &protoTCP, // Defaulted to TCP.
				SrcSelector: "calico/k8s_ns == 'default' && k == 'v' && k2 == 'v2'",
				DstPorts:    []numorstring.Port{numorstring.NamedPort("foo")},
			},
		))

		// There should be no OutboundRules
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*model.Policy).Types)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).Types[0]).To(Equal("ingress"))
	})

	It("should parse a NetworkPolicy with no rules", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
			},
		}

		// Parse the policy.
		pol, err := c.NetworkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("knp.default.default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default' && label == 'value'"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(0))

		// There should be no OutboundRules
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*model.Policy).Types)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).Types[0]).To(Equal("ingress"))
	})

	It("should parse a NetworkPolicy with multiple peers", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []extensions.NetworkPolicyIngressRule{
					extensions.NetworkPolicyIngressRule{
						Ports: []extensions.NetworkPolicyPort{
							extensions.NetworkPolicyPort{},
						},
						From: []extensions.NetworkPolicyPeer{
							extensions.NetworkPolicyPeer{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							extensions.NetworkPolicyPeer{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k2": "v2",
									},
								},
							},
						},
					},
				},
			},
		}

		var pol *model.KVPair
		var err error
		By("parsing the policy", func() {
			pol, err = c.NetworkPolicyToPolicy(&np)
			Expect(err).NotTo(HaveOccurred())
			Expect(pol.Key.(model.PolicyKey).Name).To(Equal("knp.default.default.testPolicy"))
			Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		})

		By("having the correct endpoint selector", func() {
			Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default' && label == 'value'"))
		})

		By("having the correct peer selectors", func() {
			Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(2))

			// There should be no OutboundRules
			Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))

			// Check that Types field exists and has only 'ingress'
			Expect(len(pol.Value.(*model.Policy).Types)).To(Equal(1))
			Expect(pol.Value.(*model.Policy).Types[0]).To(Equal("ingress"))

			Expect(pol.Value.(*model.Policy).InboundRules[0].SrcSelector).To(Equal("calico/k8s_ns == 'default' && k == 'v'"))
			Expect(pol.Value.(*model.Policy).InboundRules[1].SrcSelector).To(Equal("calico/k8s_ns == 'default' && k2 == 'v2'"))
		})
	})

	It("should parse a NetworkPolicy with multiple peers and ports", func() {
		tcp := k8sapi.ProtocolTCP
		udp := k8sapi.ProtocolUDP
		eighty := intstr.FromInt(80)
		ninety := intstr.FromInt(90)

		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []extensions.NetworkPolicyIngressRule{
					extensions.NetworkPolicyIngressRule{
						Ports: []extensions.NetworkPolicyPort{
							extensions.NetworkPolicyPort{
								Port:     &ninety,
								Protocol: &udp,
							},
							extensions.NetworkPolicyPort{
								Port:     &eighty,
								Protocol: &tcp,
							},
						},
						From: []extensions.NetworkPolicyPeer{
							extensions.NetworkPolicyPeer{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							extensions.NetworkPolicyPeer{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k2": "v2",
									},
								},
							},
						},
					},
				},
			},
		}

		var pol *model.KVPair
		var err error
		By("parsing the policy", func() {
			pol, err = c.NetworkPolicyToPolicy(&np)
			Expect(err).NotTo(HaveOccurred())
			Expect(pol.Key.(model.PolicyKey).Name).To(Equal("knp.default.default.testPolicy"))
			Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		})

		By("having the correct endpoint selector", func() {
			Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default' && label == 'value'"))
		})

		By("having the correct peer selectors", func() {
			eighty, _ := numorstring.PortFromString("80")
			ninety, _ := numorstring.PortFromString("90")
			Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(4))

			// There should be no OutboundRules
			Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))

			// Check that Types field exists and has only 'ingress'
			Expect(len(pol.Value.(*model.Policy).Types)).To(Equal(1))
			Expect(pol.Value.(*model.Policy).Types[0]).To(Equal("ingress"))

			Expect(pol.Value.(*model.Policy).InboundRules[0].SrcSelector).To(Equal("calico/k8s_ns == 'default' && k == 'v'"))
			Expect(pol.Value.(*model.Policy).InboundRules[0].DstPorts).To(Equal([]numorstring.Port{ninety}))

			Expect(pol.Value.(*model.Policy).InboundRules[1].SrcSelector).To(Equal("calico/k8s_ns == 'default' && k2 == 'v2'"))
			Expect(pol.Value.(*model.Policy).InboundRules[1].DstPorts).To(Equal([]numorstring.Port{ninety}))

			Expect(pol.Value.(*model.Policy).InboundRules[2].SrcSelector).To(Equal("calico/k8s_ns == 'default' && k == 'v'"))
			Expect(pol.Value.(*model.Policy).InboundRules[2].DstPorts).To(Equal([]numorstring.Port{eighty}))

			Expect(pol.Value.(*model.Policy).InboundRules[3].SrcSelector).To(Equal("calico/k8s_ns == 'default' && k2 == 'v2'"))
			Expect(pol.Value.(*model.Policy).InboundRules[3].DstPorts).To(Equal([]numorstring.Port{eighty}))
		})
	})

	It("should parse a NetworkPolicy with empty podSelector", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
			},
		}

		// Parse the policy.
		pol, err := c.NetworkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("knp.default.default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default'"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(0))

		// There should be no OutboundRules
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*model.Policy).Types)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).Types[0]).To(Equal("ingress"))
	})

	It("should parse a NetworkPolicy with an empty namespaceSelector", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []extensions.NetworkPolicyIngressRule{
					extensions.NetworkPolicyIngressRule{
						From: []extensions.NetworkPolicyPeer{
							extensions.NetworkPolicyPeer{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{},
								},
							},
						},
					},
				},
			},
		}

		// Parse the policy.
		pol, err := c.NetworkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("knp.default.default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default' && label == 'value'"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).InboundRules[0].SrcSelector).To(Equal("has(calico/k8s_ns)"))

		// There should be no OutboundRules
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*model.Policy).Types)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).Types[0]).To(Equal("ingress"))
	})

	It("should parse a NetworkPolicy with podSelector.MatchExpressions", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						metav1.LabelSelectorRequirement{
							Key:      "k",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"v1", "v2"},
						},
					},
				},
			},
		}

		// Parse the policy.
		pol, err := c.NetworkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("knp.default.default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default' && k in { 'v1', 'v2' }"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(0))

		// There should be no OutboundRules
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*model.Policy).Types)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).Types[0]).To(Equal("ingress"))
	})

	It("should parse a NetworkPolicy with Ports only", func() {
		protocol := k8sapi.ProtocolTCP
		port := intstr.FromInt(80)
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				Ingress: []extensions.NetworkPolicyIngressRule{
					extensions.NetworkPolicyIngressRule{
						Ports: []extensions.NetworkPolicyPort{
							extensions.NetworkPolicyPort{
								Protocol: &protocol,
								Port:     &port,
							},
						},
					},
				},
			},
		}

		// Parse the policy.
		pol, err := c.NetworkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("knp.default.default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default'"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).InboundRules[0].Protocol.String()).To(Equal("tcp"))
		Expect(len(pol.Value.(*model.Policy).InboundRules[0].DstPorts)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).InboundRules[0].DstPorts[0].String()).To(Equal("80"))

		// There should be no OutboundRules
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*model.Policy).Types)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).Types[0]).To(Equal("ingress"))
	})
})

var _ = Describe("Test Namespace conversion", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse a Namespace to a Profile", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Labels: map[string]string{
					"foo":   "bar",
					"roger": "rabbit",
				},
				Annotations: map[string]string{},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		p, err := c.NamespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())

		// Ensure rules are correct for profile.
		inboundRules := p.Value.(*model.Profile).Rules.InboundRules
		outboundRules := p.Value.(*model.Profile).Rules.OutboundRules
		Expect(len(inboundRules)).To(Equal(1))
		Expect(len(outboundRules)).To(Equal(1))

		// Ensure both inbound and outbound rules are set to allow.
		Expect(inboundRules[0]).To(Equal(model.Rule{Action: "allow"}))
		Expect(outboundRules[0]).To(Equal(model.Rule{Action: "allow"}))

		// Check labels.
		labels := p.Value.(*model.Profile).Labels
		Expect(labels["pcns.foo"]).To(Equal("bar"))
		Expect(labels["pcns.roger"]).To(Equal("rabbit"))
	})

	It("should parse a Namespace to a Profile with no labels", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "default",
				Annotations: map[string]string{},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		p, err := c.NamespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())

		// Ensure rules are correct.
		inboundRules := p.Value.(*model.Profile).Rules.InboundRules
		outboundRules := p.Value.(*model.Profile).Rules.OutboundRules
		Expect(len(inboundRules)).To(Equal(1))
		Expect(len(outboundRules)).To(Equal(1))

		// Ensure both inbound and outbound rules are set to allow.
		Expect(inboundRules[0]).To(Equal(model.Rule{Action: "allow"}))
		Expect(outboundRules[0]).To(Equal(model.Rule{Action: "allow"}))

		// Check labels.
		labels := p.Value.(*model.Profile).Labels
		Expect(len(labels)).To(Equal(0))
	})

	It("should ignore the network-policy Namespace annotation", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{\"ingress\": {\"isolation\": \"DefaultDeny\"}}",
				},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		// Ensure it generates the correct Profile.
		p, err := c.NamespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())
		// Ensure rules are correct for profile.
		inboundRules := p.Value.(*model.Profile).Rules.InboundRules
		outboundRules := p.Value.(*model.Profile).Rules.OutboundRules
		Expect(len(inboundRules)).To(Equal(1))
		Expect(len(outboundRules)).To(Equal(1))

		// Ensure both inbound and outbound rules are set to allow.
		Expect(inboundRules[0]).To(Equal(model.Rule{Action: "allow"}))
		Expect(outboundRules[0]).To(Equal(model.Rule{Action: "allow"}))

	})

	It("should not fail for malformed annotation", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "invalidJSON",
				},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		By("converting to a Profile", func() {
			_, err := c.NamespaceToProfile(&ns)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("should handle a valid but not DefaultDeny annotation", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{}",
				},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		By("converting to a Profile", func() {
			p, err := c.NamespaceToProfile(&ns)
			Expect(err).NotTo(HaveOccurred())

			// Ensure rules are correct.
			inboundRules := p.Value.(*model.Profile).Rules.InboundRules
			outboundRules := p.Value.(*model.Profile).Rules.OutboundRules
			Expect(len(inboundRules)).To(Equal(1))
			Expect(len(outboundRules)).To(Equal(1))

			// Ensure both inbound and outbound rules are set to allow.
			Expect(inboundRules[0]).To(Equal(model.Rule{Action: "allow"}))
			Expect(outboundRules[0]).To(Equal(model.Rule{Action: "allow"}))
		})
	})
})
