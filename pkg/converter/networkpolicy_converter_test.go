// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package converter_test

import (
	"github.com/projectcalico/kube-controllers/pkg/converter"
	api "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/numorstring"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/api/extensions"
	"k8s.io/client-go/tools/cache"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NetworkPolicy conversion tests", func() {

	npConverter := converter.NewPolicyConverter()

	It("should parse a basic NetworkPolicy", func() {
		port80 := intstr.FromInt(80)
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
				PolicyTypes: []extensions.PolicyType{extensions.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.Policy).Metadata.Name).To(Equal("knp.default.default.testPolicy"))
		})

		// Assert policy order.
		By("returning calico policy with correct order", func() {
			Expect(int(*pol.(api.Policy).Spec.Order)).To(Equal(1000))
		})

		// Check the selector is correct, and that the matches are sorted.
		By("returning a calico policy with correct selector", func() {
			Expect(pol.(api.Policy).Spec.Selector).To(Equal(
				"calico/k8s_ns == 'default' && label == 'value' && label2 == 'value2'"))
		})

		protoTCP := numorstring.ProtocolFromString("tcp")
		By("returning a calico policy with correct ingress rules", func() {
			Expect(pol.(api.Policy).Spec.IngressRules).To(ConsistOf(api.Rule{
				Action:      "allow",
				Protocol:    &protoTCP, // Defaulted to TCP.
				Source:      api.EntityRule{Selector: "calico/k8s_ns == 'default' && k == 'v' && k2 == 'v2'"},
				Destination: api.EntityRule{Ports: []numorstring.Port{numorstring.SinglePort(80)}},
			}))
		})

		// There should be one OutboundRule
		By("returning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.Policy).Spec.EgressRules)).To(Equal(1))
		})

		// Check that Types field exists and has only 'ingress'
		var policyType api.PolicyType = "ingress"
		By("returning a calico policy with ingress type", func() {
			Expect(len(pol.(api.Policy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.Policy).Spec.Types[0]).To(Equal(policyType))
		})
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
				PolicyTypes: []extensions.PolicyType{extensions.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.Policy).Metadata.Name).To(Equal("knp.default.default.testPolicy"))
		})

		// Assert policy order.
		By("reteurning a calico policy with correct order", func() {
			Expect(int(*pol.(api.Policy).Spec.Order)).To(Equal(1000))
		})

		// Assert selectors
		By("reteurning a calico policy with correct selector", func() {
			Expect(pol.(api.Policy).Spec.Selector).To(Equal(
				"calico/k8s_ns == 'default' && label == 'value'"))
		})

		// There should be no inboundRules
		By("reteurning a calico policy with no ingress rules", func() {
			Expect(len(pol.(api.Policy).Spec.IngressRules)).To(Equal(0))
		})

		// There should be one OutboundRule
		By("reteurning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.Policy).Spec.EgressRules)).To(Equal(1))
		})

		var policyType api.PolicyType = "ingress"
		// Check that Types field exists and has only 'ingress'
		By("reteurning a calico policy with ingress type", func() {
			Expect(len(pol.(api.Policy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.Policy).Spec.Types[0]).To(Equal(policyType))
		})
	})

	It("should parse a NetworkPolicy with an empty podSelector", func() {
		np := extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []extensions.PolicyType{extensions.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("reteurning a calico policy with expected name", func() {
			Expect(pol.(api.Policy).Metadata.Name).To(Equal("knp.default.default.testPolicy"))
		})

		// Assert policy order.
		By("reteurning a calico policy with correct order", func() {
			Expect(int(*pol.(api.Policy).Spec.Order)).To(Equal(1000))
		})

		// Assert selectors
		By("reteurning a calico policy with correct selector", func() {
			Expect(pol.(api.Policy).Spec.Selector).To(Equal("calico/k8s_ns == 'default'"))
		})

		// There should be no inboundRules
		By("reteurning a calico policy with no ingress rules", func() {
			Expect(len(pol.(api.Policy).Spec.IngressRules)).To(Equal(0))
		})

		// There should be one OutboundRule
		By("reteurning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.Policy).Spec.EgressRules)).To(Equal(1))
		})

		var policyType api.PolicyType = "ingress"
		// Check that Types field exists and has only 'ingress'
		By("reteurning a calico policy with ingress type", func() {
			Expect(len(pol.(api.Policy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.Policy).Spec.Types[0]).To(Equal(policyType))
		})
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
				PolicyTypes: []extensions.PolicyType{extensions.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("reteurning a calico policy with expected name", func() {
			Expect(pol.(api.Policy).Metadata.Name).To(Equal("knp.default.default.testPolicy"))
		})

		// Assert policy order.
		By("reteurning a calico policy with correct order", func() {
			Expect(int(*pol.(api.Policy).Spec.Order)).To(Equal(1000))
		})

		// Assert selectors
		By("reteurning a calico policy with correct selector", func() {
			Expect(pol.(api.Policy).Spec.Selector).To(Equal(
				"calico/k8s_ns == 'default' && label == 'value'"))
		})

		// Assert ingress rules
		By("reteurning a calico policy with ingress rules", func() {
			Expect(len(pol.(api.Policy).Spec.IngressRules)).To(Equal(1))
			Expect(pol.(api.Policy).Spec.IngressRules[0].Source.Selector).To(Equal("has(calico/k8s_ns)"))
		})

		// There should be one OutboundRule
		By("reteurning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.Policy).Spec.EgressRules)).To(Equal(1))
		})

		var policyType api.PolicyType = "ingress"
		// Check that Types field exists and has only 'ingress'
		By("reteurning a calico policy with ingress type", func() {
			Expect(len(pol.(api.Policy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.Policy).Spec.Types[0]).To(Equal(policyType))
		})
	})

	It("should handle cache.DeletedFinalStateUnknown conversion", func() {
		np := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: &extensions.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testPolicy",
					Namespace: "default",
				},
				Spec: extensions.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
				},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("reteurning a calico policy with expected name", func() {
			Expect(pol.(api.Policy).Metadata.Name).To(Equal("knp.default.default.testPolicy"))
		})
	})

	It("should handle cache.DeletedFinalStateUnknown with non-NetworkPolicy Obj", func() {
		np := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: "just a string",
		}

		_, err := npConverter.Convert(np)
		By("generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should handle conversion of an invalid type", func() {
		np := "anything"

		// Parse the policy.
		_, err := npConverter.Convert(np)
		By("generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should return the correct key", func() {
		policyName := "allow-all"
		policy := api.Policy{
			Metadata: api.PolicyMetadata{
				Name: policyName,
			},
			Spec: api.PolicySpec{},
		}

		// Get key
		key := npConverter.GetKey(policy)
		By("returning the name of the policy", func() {
			Expect(key).To(Equal(policyName))
		})
	})

	It("should parse a NetworkPolicy with an Egress rule", func() {
		port80 := intstr.FromInt(80)
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
				Egress: []extensions.NetworkPolicyEgressRule{
					{
						Ports: []extensions.NetworkPolicyPort{
							{Port: &port80},
						},
						To: []extensions.NetworkPolicyPeer{
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
				PolicyTypes: []extensions.PolicyType{extensions.PolicyTypeEgress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.Policy).Metadata.Name).To(Equal("knp.default.default.testPolicy"))
		})

		// Assert policy order.
		By("returning a calico policy with correct order", func() {
			Expect(int(*pol.(api.Policy).Spec.Order)).To(Equal(1000))
		})

		// Check the selector is correct, and that the matches are sorted.
		By("returning a calico policy with correct selector", func() {
			Expect(pol.(api.Policy).Spec.Selector).To(Equal(
				"calico/k8s_ns == 'default' && label == 'value' && label2 == 'value2'"))
		})

		protoTCP := numorstring.ProtocolFromString("tcp")
		By("returning a calico policy with correct egress rules", func() {
			Expect(pol.(api.Policy).Spec.EgressRules).To(ConsistOf(api.Rule{
				Action:   "allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Destination: api.EntityRule{Selector: "calico/k8s_ns == 'default' && k == 'v' && k2 == 'v2'",
					Ports: []numorstring.Port{numorstring.SinglePort(80)}},
			}))
		})

		// There should be no InboundRules
		By("returning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.Policy).Spec.IngressRules)).To(Equal(0))
		})

		// Check that Types field exists and has only 'egress'
		var policyType api.PolicyType = "egress"
		By("returning a calico policy with ingress type", func() {
			Expect(len(pol.(api.Policy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.Policy).Spec.Types[0]).To(Equal(policyType))
		})
	})
})

var _ = Describe("Kubernetes 1.7 NetworkPolicy conversion tests", func() {

	npConverter := converter.NewPolicyConverter()

	It("should parse a k8s v1.7 NetworkPolicy with an ingress rule", func() {
		// <= v1.7 didn't include a polityTypes field, so it always comes back as an
		// empty list.
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
					{
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
		pol, err := npConverter.Convert(&np)
		By("not generating an error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("generating the expected name", func() {
			Expect(pol.(api.Policy).Metadata.Name).To(Equal("knp.default.default.testPolicy"))
		})

		// Assert policy order.
		By("generating the correct order", func() {
			Expect(int(*pol.(api.Policy).Spec.Order)).To(Equal(1000))
		})

		// Assert selectors
		By("generating the correct selector", func() {
			Expect(pol.(api.Policy).Spec.Selector).To(Equal(
				"calico/k8s_ns == 'default' && label == 'value'"))
		})

		// There should be one inbound rule.
		By("returning a policy with a single ingress rule", func() {
			Expect(len(pol.(api.Policy).Spec.IngressRules)).To(Equal(1))
		})

		// There should be one OutboundRule to allow all egress traffic.
		By("returning a policy with a single egress rule", func() {
			Expect(len(pol.(api.Policy).Spec.EgressRules)).To(Equal(1))
		})

		var policyType api.PolicyType = "ingress"
		// Check that Types field exists and has only 'ingress'
		By("returning a policy with types=[ingress]", func() {
			Expect(len(pol.(api.Policy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.Policy).Spec.Types[0]).To(Equal(policyType))
		})
	})
})
