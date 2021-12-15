// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/calico/kube-controllers/pkg/converter"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/tools/cache"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NetworkPolicy conversion tests", func() {

	npConverter := converter.NewPolicyConverter()

	It("should parse a basic NetworkPolicy", func() {
		port80 := intstr.FromInt(80)
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"label":  "value",
						"label2": "value2",
					},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{Port: &port80},
						},
						From: []networkingv1.NetworkPolicyPeer{
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
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.NetworkPolicy).Name).To(Equal("knp.default.testPolicy"))
		})

		// Assert policy order.
		By("returning calico policy with correct order", func() {
			Expect(int(*pol.(api.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		// Check the selector is correct, and that the matches are sorted.
		By("returning a calico policy with correct selector", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Selector).To(Equal(
				"projectcalico.org/orchestrator == 'k8s' && label == 'value' && label2 == 'value2'"))
		})

		protoTCP := numorstring.ProtocolFromString("TCP")
		By("returning a calico policy with correct ingress rules", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Ingress).To(ConsistOf(api.Rule{
				Action:      "Allow",
				Protocol:    &protoTCP, // Defaulted to TCP.
				Source:      api.EntityRule{Selector: "projectcalico.org/orchestrator == 'k8s' && k == 'v' && k2 == 'v2'"},
				Destination: api.EntityRule{Ports: []numorstring.Port{numorstring.SinglePort(80)}},
			}))
		})

		// There should be no egress rules.
		By("returning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Egress)).To(Equal(0))
		})

		// Check that Types field exists and has only 'ingress'
		By("returning a calico policy with ingress type", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.NetworkPolicy).Spec.Types[0]).To(Equal(api.PolicyTypeIngress))
		})
	})

	It("should parse a NetworkPolicy with no rules", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.NetworkPolicy).Name).To(Equal("knp.default.testPolicy"))
		})

		// Assert policy order.
		By("returning a calico policy with correct order", func() {
			Expect(int(*pol.(api.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		// Assert selectors
		By("returning a calico policy with correct selector", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Selector).To(Equal(
				"projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		})

		// There should be no egress rules.
		By("returning a calico policy with no ingress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Ingress)).To(Equal(0))
		})

		// There should be no egress rules.
		By("returning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Egress)).To(Equal(0))
		})

		// Check that Types field exists and has only 'ingress'
		By("returning a calico policy with ingress type", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.NetworkPolicy).Spec.Types[0]).To(Equal(api.PolicyTypeIngress))
		})
	})

	It("should parse a NetworkPolicy with an empty podSelector", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.NetworkPolicy).Name).To(Equal("knp.default.testPolicy"))
		})

		// Assert policy order.
		By("returning a calico policy with correct order", func() {
			Expect(int(*pol.(api.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		// Assert selectors
		By("returning a calico policy with correct selector", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		})

		// There should be no ingress rules.
		By("returning a calico policy with no ingress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Ingress)).To(Equal(0))
		})

		// There should be no egress rules.
		By("returning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Egress)).To(Equal(0))
		})

		// Check that Types field exists and has only 'ingress'
		By("returning a calico policy with ingress type", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.NetworkPolicy).Spec.Types[0]).To(Equal(api.PolicyTypeIngress))
		})
	})

	It("should parse a NetworkPolicy with an empty namespaceSelector", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					networkingv1.NetworkPolicyIngressRule{
						From: []networkingv1.NetworkPolicyPeer{
							networkingv1.NetworkPolicyPeer{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.NetworkPolicy).Name).To(Equal("knp.default.testPolicy"))
		})

		// Assert policy order.
		By("returning a calico policy with correct order", func() {
			Expect(int(*pol.(api.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		// Assert selectors
		By("returning a calico policy with correct selector", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Selector).To(Equal(
				"projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		})

		// Assert ingress rules
		By("returning a calico policy with ingress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Ingress)).To(Equal(1))
			Expect(pol.(api.NetworkPolicy).Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		})

		// There should be no egress rules.
		By("returning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Egress)).To(Equal(0))
		})

		// Check that Types field exists and has only 'ingress'
		By("returning a calico policy with ingress type", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.NetworkPolicy).Spec.Types[0]).To(Equal(api.PolicyTypeIngress))
		})
	})

	It("should handle cache.DeletedFinalStateUnknown conversion", func() {
		np := cache.DeletedFinalStateUnknown{
			Key: "cache.DeletedFinalStateUnknown",
			Obj: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testPolicy",
					Namespace: "default",
				},
				Spec: networkingv1.NetworkPolicySpec{
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
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.NetworkPolicy).Name).To(Equal("knp.default.testPolicy"))
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
		policyNS := "default"
		policy := api.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      policyName,
				Namespace: policyNS,
			},
			Spec: api.NetworkPolicySpec{},
		}

		// Get key
		key := npConverter.GetKey(policy)
		By("returning the name of the policy", func() {
			Expect(key).To(Equal("default/allow-all"))
		})

		By("parsing the returned key back into component fields", func() {
			ns, name := npConverter.DeleteArgsFromKey(key)
			Expect(ns).To(Equal("default"))
			Expect(name).To(Equal("allow-all"))
		})
	})

	It("should parse a NetworkPolicy with an Egress rule", func() {
		port80 := intstr.FromInt(80)
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"label":  "value",
						"label2": "value2",
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{Port: &port80},
						},
						To: []networkingv1.NetworkPolicyPeer{
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
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.NetworkPolicy).Name).To(Equal("knp.default.testPolicy"))
		})

		// Assert policy order.
		By("returning a calico policy with correct order", func() {
			Expect(int(*pol.(api.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		// Check the selector is correct, and that the matches are sorted.
		By("returning a calico policy with correct selector", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Selector).To(Equal(
				"projectcalico.org/orchestrator == 'k8s' && label == 'value' && label2 == 'value2'"))
		})

		protoTCP := numorstring.ProtocolFromString("TCP")
		By("returning a calico policy with correct egress rules", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Egress).To(ConsistOf(api.Rule{
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Destination: api.EntityRule{Selector: "projectcalico.org/orchestrator == 'k8s' && k == 'v' && k2 == 'v2'",
					Ports: []numorstring.Port{numorstring.SinglePort(80)}},
			}))
		})

		// There should be no InboundRules
		By("returning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Ingress)).To(Equal(0))
		})

		// Check that Types field exists and has only 'egress'
		By("returning a calico policy with ingress type", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.NetworkPolicy).Spec.Types[0]).To(Equal(api.PolicyTypeEgress))
		})
	})

	It("should parse a NetworkPolicy with an Egress rule and Port Range", func() {
		port32000 := intstr.FromInt(32000)
		port32768 := int32(32768)
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"label":  "value",
						"label2": "value2",
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Port:    &port32000,
								EndPort: &port32768,
							},
						},
						To: []networkingv1.NetworkPolicyPeer{
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
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}

		// Parse the policy.
		pol, err := npConverter.Convert(&np)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert policy name.
		By("returning a calico policy with expected name", func() {
			Expect(pol.(api.NetworkPolicy).Name).To(Equal("knp.default.testPolicy"))
		})

		// Assert policy order.
		By("returning a calico policy with correct order", func() {
			Expect(int(*pol.(api.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		// Check the selector is correct, and that the matches are sorted.
		By("returning a calico policy with correct selector", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Selector).To(Equal(
				"projectcalico.org/orchestrator == 'k8s' && label == 'value' && label2 == 'value2'"))
		})

		protoTCP := numorstring.ProtocolFromString("TCP")
		By("returning a calico policy with correct egress rules", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Egress).To(ConsistOf(api.Rule{
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Destination: api.EntityRule{Selector: "projectcalico.org/orchestrator == 'k8s' && k == 'v' && k2 == 'v2'",
					Ports: []numorstring.Port{numorstring.Port{MinPort: 32000, MaxPort: 32768}}},
			}))
		})

		// There should be no InboundRules
		By("returning a calico policy with no egress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Ingress)).To(Equal(0))
		})

		// Check that Types field exists and has only 'egress'
		By("returning a calico policy with ingress type", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.NetworkPolicy).Spec.Types[0]).To(Equal(api.PolicyTypeEgress))
		})
	})
})

var _ = Describe("Kubernetes 1.7 NetworkPolicy conversion tests", func() {

	npConverter := converter.NewPolicyConverter()

	It("should parse a k8s v1.7 NetworkPolicy with an ingress rule", func() {
		// <= v1.7 didn't include a polityTypes field, so it always comes back as an
		// empty list.
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
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
			Expect(pol.(api.NetworkPolicy).Name).To(Equal("knp.default.testPolicy"))
		})

		// Assert policy order.
		By("generating the correct order", func() {
			Expect(int(*pol.(api.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		// Assert selectors
		By("generating the correct selector", func() {
			Expect(pol.(api.NetworkPolicy).Spec.Selector).To(Equal(
				"projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		})

		// There should be one inbound rule.
		By("returning a policy with a single ingress rule", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Ingress)).To(Equal(1))
		})

		// There should be no egress rules.
		By("returning a policy with no egress rules", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Egress)).To(Equal(0))
		})

		// Check that Types field exists and has only 'ingress'
		By("returning a policy with types=[ingress]", func() {
			Expect(len(pol.(api.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.(api.NetworkPolicy).Spec.Types[0]).To(Equal(api.PolicyTypeIngress))
		})
	})
})
