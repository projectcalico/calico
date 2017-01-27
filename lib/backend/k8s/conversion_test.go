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
	k8sapi "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	metav1 "k8s.io/client-go/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/util/intstr"
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

	It("should parse valid policy names", func() {
		// Parse a NetworkPolicy backed Policy.
		name := "np.projectcalico.org/Namespace.policyName"
		ns, polName, err := c.parsePolicyNameNetworkPolicy(name)
		Expect(err).NotTo(HaveOccurred())
		Expect(ns).To(Equal("Namespace"))
		Expect(polName).To(Equal("policyName"))

		// Parse a Namespace backed Policy.
		name = "ns.projectcalico.org/Namespace"
		ns, err = c.parsePolicyNameNamespace(name)
		Expect(err).NotTo(HaveOccurred())
		Expect(ns).To(Equal("Namespace"))

	})

	It("should not parse invalid policy names", func() {
		name := "something.projectcalico.org/Namespace.Name"

		// As a NetworkPolicy.
		ns, polName, err := c.parsePolicyNameNetworkPolicy(name)
		Expect(err).To(HaveOccurred())
		Expect(ns).To(Equal(""))
		Expect(polName).To(Equal(""))

		// As a Namespace.
		ns, err = c.parsePolicyNameNamespace(name)
		Expect(err).To(HaveOccurred())
		Expect(ns).To(Equal(""))
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
						},
					},
				},
			},
		}

		// Parse the policy.
		pol, err := c.networkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("np.projectcalico.org/default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default' && label == 'value'"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(1))
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))
		Expect(pol.Value.(*model.Policy).InboundRules[0].SrcSelector).To(Equal("calico/k8s_ns == 'default' && k == 'v'"))
	})

	It("should parse a NetworkPolicy with no rules", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: k8sapi.ObjectMeta{
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
		pol, err := c.networkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("np.projectcalico.org/default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default' && label == 'value'"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(0))
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))
	})

	It("should parse a NetworkPolicy with empty podSelector", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: k8sapi.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
			},
		}

		// Parse the policy.
		pol, err := c.networkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("np.projectcalico.org/default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default'"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(0))
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))
	})

	It("should parse a NetworkPolicy with podSelector.MatchExpressions", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: k8sapi.ObjectMeta{
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
		pol, err := c.networkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("np.projectcalico.org/default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default' && k in { 'v1', 'v2' }"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(0))
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))
	})

	It("should parse a NetworkPolicy with Ports only", func() {
		protocol := k8sapi.ProtocolTCP
		port := intstr.FromInt(80)
		np := extensions.NetworkPolicy{
			ObjectMeta: k8sapi.ObjectMeta{
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
		pol, err := c.networkPolicyToPolicy(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.PolicyKey).Name).To(Equal("np.projectcalico.org/default.testPolicy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*model.Policy).Order)).To(Equal(1000))
		Expect(pol.Value.(*model.Policy).Selector).To(Equal("calico/k8s_ns == 'default'"))
		Expect(len(pol.Value.(*model.Policy).InboundRules)).To(Equal(1))
		Expect(len(pol.Value.(*model.Policy).OutboundRules)).To(Equal(0))
		Expect(pol.Value.(*model.Policy).InboundRules[0].Protocol.String()).To(Equal("tcp"))
		Expect(len(pol.Value.(*model.Policy).InboundRules[0].DstPorts)).To(Equal(1))
		Expect(pol.Value.(*model.Policy).InboundRules[0].DstPorts[0].String()).To(Equal("80"))
	})
})

var _ = Describe("Test Namespace conversion", func() {

	// Use a single instance of the converter for these tests.
	c := converter{}

	It("should parse a Namespace to a Profile", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "default",
				Labels: map[string]string{
					"foo":   "bar",
					"roger": "rabbit",
				},
				Annotations: map[string]string{},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		p, err := c.namespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())

		// Ensure rules are correct for profile.
		inboundRules := p.Value.(*model.Profile).Rules.InboundRules
		outboundRules := p.Value.(*model.Profile).Rules.OutboundRules
		Expect(len(inboundRules)).To(Equal(0))
		Expect(len(outboundRules)).To(Equal(0))

		// Check labels.
		labels := p.Value.(*model.Profile).Labels
		Expect(labels["k8s_ns/label/foo"]).To(Equal("bar"))
		Expect(labels["k8s_ns/label/roger"]).To(Equal("rabbit"))
	})

	It("should parse a Namespace to a Policy", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "default",
				Labels: map[string]string{
					"foo":   "bar",
					"roger": "rabbit",
				},
				Annotations: map[string]string{},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		// Ensure it generates the correct Policy.
		kvp, err := c.namespaceToPolicy(&ns)
		Expect(err).NotTo(HaveOccurred())
		key := kvp.Key.(model.PolicyKey)
		policy := kvp.Value.(*model.Policy)
		Expect(key.Name).To(Equal("ns.projectcalico.org/default"))
		Expect(policy.Selector).To(Equal("calico/k8s_ns == 'default'"))
		Expect(len(policy.InboundRules)).To(Equal(1))
		Expect(len(policy.OutboundRules)).To(Equal(1))

		allow := model.Rule{Action: "allow"}
		Expect(policy.InboundRules[0]).To(Equal(allow))
		Expect(policy.OutboundRules[0]).To(Equal(allow))
	})

	It("should parse a Namespace to a Profile with no labels", func() {
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
		Expect(len(inboundRules)).To(Equal(0))
		Expect(len(outboundRules)).To(Equal(0))

		// Check labels.
		labels := p.Value.(*model.Profile).Labels
		Expect(len(labels)).To(Equal(0))
	})

	It("should parse a Namespace to Policy (DefaultDeny)", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{\"ingress\": {\"isolation\": \"DefaultDeny\"}}",
				},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		// Ensure it generates the correct Policy.
		kvp, err := c.namespaceToPolicy(&ns)
		Expect(err).NotTo(HaveOccurred())
		key := kvp.Key.(model.PolicyKey)
		policy := kvp.Value.(*model.Policy)
		Expect(key.Name).To(Equal("ns.projectcalico.org/default"))
		Expect(policy.Selector).To(Equal("calico/k8s_ns == 'default'"))
		Expect(len(policy.InboundRules)).To(Equal(1))
		Expect(len(policy.OutboundRules)).To(Equal(1))

		allow := model.Rule{Action: "allow"}
		deny := model.Rule{Action: "deny"}
		Expect(policy.InboundRules[0]).To(Equal(deny))
		Expect(policy.OutboundRules[0]).To(Equal(allow))

	})

	It("should not fail for malformed annotation", func() {
		ns := k8sapi.Namespace{
			ObjectMeta: k8sapi.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "invalidJSON",
				},
			},
			Spec: k8sapi.NamespaceSpec{},
		}

		By("converting to a Profile", func() {
			_, err := c.namespaceToProfile(&ns)
			Expect(err).NotTo(HaveOccurred())
		})

		By("converting to a Policy", func() {
			_, err := c.namespaceToPolicy(&ns)
			Expect(err).NotTo(HaveOccurred())
		})

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

		By("converting to a Profile", func() {
			p, err := c.namespaceToProfile(&ns)
			Expect(err).NotTo(HaveOccurred())

			// Ensure rules are correct.
			inboundRules := p.Value.(*model.Profile).Rules.InboundRules
			outboundRules := p.Value.(*model.Profile).Rules.OutboundRules
			Expect(len(inboundRules)).To(Equal(0))
			Expect(len(outboundRules)).To(Equal(0))
		})

		By("converting to a Policy", func() {
			_, err := c.namespaceToPolicy(&ns)
			Expect(err).NotTo(HaveOccurred())
		})

	})
})
