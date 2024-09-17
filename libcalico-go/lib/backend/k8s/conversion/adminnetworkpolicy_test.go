// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package conversion

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	adminpolicy "sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

var _ = Describe("Test AdminNetworkPolicy conversion", func() {
	// Use a single instance of the Converter for these tests.
	c := NewConverter()

	convertToGNP := func(
		anp *adminpolicy.AdminNetworkPolicy,
		order float64,
		expectedErr *cerrors.ErrorAdminPolicyConversion,
	) *apiv3.GlobalNetworkPolicy {
		// Parse the policy.
		pol, err := c.K8sAdminNetworkPolicyToCalico(anp)

		if expectedErr == nil {
			Expect(err).To(BeNil())
		} else {
			Expect(err).To(Equal(*expectedErr))
		}

		// Assert key fields are correct.
		policyName := fmt.Sprintf("%v%v", names.K8sAdminNetworkPolicyNamePrefix, anp.Name)
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal(policyName))

		gnp, ok := pol.Value.(*apiv3.GlobalNetworkPolicy)
		Expect(ok).To(BeTrue())

		// Make sure the type information is correct.
		Expect(gnp.Kind).To(Equal(apiv3.KindGlobalNetworkPolicy))
		Expect(gnp.APIVersion).To(Equal(apiv3.GroupVersionCurrent))

		// Assert value fields are correct.
		Expect(*gnp.Spec.Order).To(Equal(order))
		Expect(gnp.Spec.Tier).To(Equal(names.AdminNetworkPolicyTierName))

		return gnp
	}

	It("should parse a basic k8s AdminNetworkPolicy to a GlobalNetworkPolicy", func() {
		ports := []adminpolicy.AdminNetworkPolicyPort{{
			PortNumber: &adminpolicy.Port{
				Port: 80,
			},
		}}
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 100,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "The first ingress rule",
						Action: "Allow",
						Ports:  &ports,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
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

		// Convert the policy
		gnp := convertToGNP(&anp, float64(100.0), nil)

		// Check the selector is correct, and that the matches are sorted.
		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))
		protoTCP := numorstring.ProtocolFromString("TCP")
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sAdminNetworkPolicyToCalicoMetadata("The first ingress rule"),
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					NamespaceSelector: "k == 'v' && k2 == 'v2'",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(80)},
				},
			},
		))

		// There should be no Egress rules
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should drop rules with invalid action in a k8s AdminNetworkPolicy", func() {
		ports := []adminpolicy.AdminNetworkPolicyPort{
			{
				PortNumber: &adminpolicy.Port{Port: 80},
			},
			{
				PortRange: &adminpolicy.PortRange{Start: 2000, End: 3000},
			},
		}
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 300,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Log",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k":  "v",
										"k2": "v2",
									},
								},
							},
						},
					},
					{
						Name:   "A random ingress rule 2",
						Action: "Allow",
						Ports:  &ports,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k10": "v10",
										"k20": "v20",
									},
								},
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						Ports:  &ports,
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
										"k4": "v4",
									},
								},
							},
						},
					},
					{
						Name:   "A random egress rule 2",
						Action: "Drop",
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k30": "v30",
										"k40": "v40",
									},
								},
							},
						},
					},
				},
			},
		}

		expectedErr := cerrors.ErrorAdminPolicyConversion{
			PolicyName: "test.policy",
			Rules: []cerrors.ErrorAdminPolicyConversionRule{
				{
					EgressRule: nil,
					IngressRule: &adminpolicy.AdminNetworkPolicyIngressRule{
						Name:   "A random ingress rule",
						Action: "Log",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k2": "v2", "k": "v"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: unsupported admin network policy action Log",
				},
				{
					IngressRule: nil,
					EgressRule: &adminpolicy.AdminNetworkPolicyEgressRule{
						Name:   "A random egress rule 2",
						Action: "Drop",
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k30": "v30", "k40": "v40"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: unsupported admin network policy action Drop",
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&anp, float64(300.0), &expectedErr)

		protoTCP := numorstring.ProtocolFromString("TCP")

		Expect(len(gnp.Spec.Ingress)).To(Equal(1))
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sAdminNetworkPolicyToCalicoMetadata("A random ingress rule 2"),
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					NamespaceSelector: "k10 == 'v10' && k20 == 'v20'",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(80), {MinPort: 2000, MaxPort: 3000}},
				},
			},
		))

		Expect(len(gnp.Spec.Egress)).To(Equal(1))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sAdminNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:   "Deny",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source:   apiv3.EntityRule{},
				Destination: apiv3.EntityRule{
					NamespaceSelector: "k3 == 'v3' && k4 == 'v4'",
					Ports:             []numorstring.Port{numorstring.SinglePort(80), {MinPort: 2000, MaxPort: 3000}},
				},
			},
		))
	})

	It("should parse a k8s AdminNetworkPolicy with no ports", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 200,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k":  "v",
										"k2": "v2",
									},
								},
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
										"k4": "v4",
									},
								},
							},
						},
					},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&anp, float64(200.0), nil)

		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata:    k8sAdminNetworkPolicyToCalicoMetadata("A random ingress rule"),
				Action:      "Pass",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{NamespaceSelector: "k == 'v' && k2 == 'v2'"},
				Destination: apiv3.EntityRule{},
			},
		))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Metadata:    k8sAdminNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:      "Deny",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{},
				Destination: apiv3.EntityRule{NamespaceSelector: "k3 == 'v3' && k4 == 'v4'"},
			},
		))
	})

	It("should drop rules with invalid ports in a k8s AdminNetworkPolicy", func() {
		goodPorts := []adminpolicy.AdminNetworkPolicyPort{
			{
				PortNumber: &adminpolicy.Port{Port: 80},
			},
			{
				PortRange: &adminpolicy.PortRange{Start: 2000, End: 3000},
			},
		}
		badPorts := []adminpolicy.AdminNetworkPolicyPort{
			{
				PortNumber: &adminpolicy.Port{Port: 80},
			},
			{
				PortRange: &adminpolicy.PortRange{Start: 1000, End: 10},
			},
		}

		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 300,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						Ports:  &badPorts,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k":  "v",
										"k2": "v2",
									},
								},
							},
						},
					},
					{
						Name:   "A random ingress rule 2",
						Action: "Allow",
						Ports:  &goodPorts,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k10": "v10",
										"k20": "v20",
									},
								},
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						Ports:  &goodPorts,
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
										"k4": "v4",
									},
								},
							},
						},
					},
					{
						Name:   "A random egress rule 2",
						Action: "Pass",
						Ports:  &badPorts,
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k30": "v30",
										"k40": "v40",
									},
								},
							},
						},
					},
				},
			},
		}

		expectedErr := cerrors.ErrorAdminPolicyConversion{
			PolicyName: "test.policy",
			Rules: []cerrors.ErrorAdminPolicyConversionRule{
				{
					EgressRule: nil,
					IngressRule: &adminpolicy.AdminNetworkPolicyIngressRule{
						Name:   "A random ingress rule",
						Action: "Pass",
						Ports:  &badPorts,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k2": "v2", "k": "v"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: failed to parse k8s port: minimum port number (1000) is greater than maximum port number (10) in port range",
				},
				{
					IngressRule: nil,
					EgressRule: &adminpolicy.AdminNetworkPolicyEgressRule{
						Name:   "A random egress rule 2",
						Action: "Pass",
						Ports:  &badPorts,
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k30": "v30", "k40": "v40"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: failed to parse k8s port: minimum port number (1000) is greater than maximum port number (10) in port range",
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&anp, float64(300.0), &expectedErr)

		protoTCP := numorstring.ProtocolFromString("TCP")

		Expect(len(gnp.Spec.Ingress)).To(Equal(1))
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sAdminNetworkPolicyToCalicoMetadata("A random ingress rule 2"),
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					NamespaceSelector: "k10 == 'v10' && k20 == 'v20'",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(80), {MinPort: 2000, MaxPort: 3000}},
				},
			},
		))

		Expect(len(gnp.Spec.Egress)).To(Equal(1))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sAdminNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:   "Deny",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source:   apiv3.EntityRule{},
				Destination: apiv3.EntityRule{
					NamespaceSelector: "k3 == 'v3' && k4 == 'v4'",
					Ports:             []numorstring.Port{numorstring.SinglePort(80), {MinPort: 2000, MaxPort: 3000}},
				},
			},
		))
	})

	It("should parse an AdminNetworkPolicy with no rules", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 500,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&anp, float64(500.0), nil)

		// Assert value fields are correct.
		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))
		Expect(gnp.Spec.Ingress).To(HaveLen(0))

		// There should be no Egress rules
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should parse an AdminNetworkPolicy with Namespaces subject and multiple peers", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								Pods: &adminpolicy.NamespacedPod{
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k2": "v2",
										},
									},
								},
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Pods: &adminpolicy.NamespacedPod{
									NamespaceSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k4": "v4",
										},
									},
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k5": "v5",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), nil)

		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))
		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))

		Expect(len(gnp.Spec.Ingress)).To(Equal(2))
		Expect(gnp.Spec.Ingress[0].Source.NamespaceSelector).To(Equal("k == 'v'"))
		Expect(gnp.Spec.Ingress[1].Source.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Ingress[1].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))

		Expect(gnp.Spec.Egress).To(HaveLen(2))
		Expect(gnp.Spec.Egress[0].Destination.NamespaceSelector).To(Equal("k3 == 'v3'"))
		Expect(gnp.Spec.Egress[1].Destination.NamespaceSelector).To(Equal("k4 == 'v4'"))
		Expect(gnp.Spec.Egress[1].Destination.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k5 == 'v5'"))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(2))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
		Expect(gnp.Spec.Types[1]).To(Equal(apiv3.PolicyTypeEgress))
	})

	It("should parse an AdminNetworkPolicy with Pods subject and multiple peers", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Pods: &adminpolicy.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label2": "value2",
							},
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								Pods: &adminpolicy.NamespacedPod{
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k2": "v2",
										},
									},
								},
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Pods: &adminpolicy.NamespacedPod{
									NamespaceSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k4": "v4",
										},
									},
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k5": "v5",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), nil)

		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label2 == 'value2'"))

		Expect(len(gnp.Spec.Ingress)).To(Equal(2))
		Expect(gnp.Spec.Ingress[0].Source.NamespaceSelector).To(Equal("k == 'v'"))
		Expect(gnp.Spec.Ingress[1].Source.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Ingress[1].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))

		Expect(gnp.Spec.Egress).To(HaveLen(2))
		Expect(gnp.Spec.Egress[0].Destination.NamespaceSelector).To(Equal("k3 == 'v3'"))
		Expect(gnp.Spec.Egress[1].Destination.NamespaceSelector).To(Equal("k4 == 'v4'"))
		Expect(gnp.Spec.Egress[1].Destination.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k5 == 'v5'"))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(2))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
		Expect(gnp.Spec.Types[1]).To(Equal(apiv3.PolicyTypeEgress))
	})

	It("should parse a k8s AdminNetworkPolicy with a DoesNotExist expression ", func() {
		ports := []adminpolicy.AdminNetworkPolicyPort{
			{
				PortNumber: &adminpolicy.Port{Port: 80},
			},
		}
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Pods: &adminpolicy.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label":  "value",
								"label2": "value2",
							},
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Allow",
						Ports:  &ports,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Pods: &adminpolicy.NamespacedPod{
									PodSelector: metav1.LabelSelector{
										MatchExpressions: []metav1.LabelSelectorRequirement{
											{Key: "toast", Operator: metav1.LabelSelectorOpDoesNotExist},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), nil)

		// Check the selector is correct, and that the matches are sorted.
		Expect(gnp.Spec.Selector).To(Equal(
			"projectcalico.org/orchestrator == 'k8s' && label == 'value' && label2 == 'value2'"))
		protoTCP := numorstring.ProtocolFromString("TCP")
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Action:   "Allow",
				Metadata: k8sAdminNetworkPolicyToCalicoMetadata("A random ingress rule"),
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					NamespaceSelector: "all()",
					Selector:          "projectcalico.org/orchestrator == 'k8s' && ! has(toast)",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(80)},
				},
			},
		))

		// There should be no Egress rules
		Expect(gnp.Spec.Egress).To(HaveLen(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(1))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse an AdminNetworkPolicy with multiple peers and ports", func() {
		ports := []adminpolicy.AdminNetworkPolicyPort{
			{
				PortNumber: &adminpolicy.Port{Port: 80},
			},
			{
				PortRange: &adminpolicy.PortRange{Start: 20, End: 30, Protocol: kapiv1.ProtocolUDP},
			},
		}
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						Ports:  &ports,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								Pods: &adminpolicy.NamespacedPod{
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k2": "v2",
										},
									},
								},
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						Ports:  &ports,
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Pods: &adminpolicy.NamespacedPod{
									NamespaceSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k4": "v4",
										},
									},
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"k5": "v5",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), nil)

		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))

		Expect(len(gnp.Spec.Ingress)).To(Equal(4))
		Expect(gnp.Spec.Ingress[0].Source.NamespaceSelector).To(Equal("k == 'v'"))
		Expect(gnp.Spec.Ingress[0].Destination.Ports).To(Equal([]numorstring.Port{numorstring.SinglePort(80)}))

		Expect(gnp.Spec.Ingress[1].Source.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Ingress[1].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))
		Expect(gnp.Spec.Ingress[1].Destination.Ports).To(Equal([]numorstring.Port{numorstring.SinglePort(80)}))

		Expect(gnp.Spec.Ingress[2].Source.NamespaceSelector).To(Equal("k == 'v'"))
		Expect(gnp.Spec.Ingress[2].Destination.Ports).To(Equal([]numorstring.Port{{MinPort: 20, MaxPort: 30}}))

		Expect(gnp.Spec.Ingress[3].Source.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Ingress[3].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))
		Expect(gnp.Spec.Ingress[3].Destination.Ports).To(Equal([]numorstring.Port{{MinPort: 20, MaxPort: 30}}))

		Expect(gnp.Spec.Egress).To(HaveLen(4))
		Expect(gnp.Spec.Egress[0].Destination.NamespaceSelector).To(Equal("k3 == 'v3'"))
		Expect(gnp.Spec.Egress[0].Destination.Ports).To(Equal([]numorstring.Port{numorstring.SinglePort(80)}))

		Expect(gnp.Spec.Egress[1].Destination.NamespaceSelector).To(Equal("k4 == 'v4'"))
		Expect(gnp.Spec.Egress[1].Destination.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k5 == 'v5'"))
		Expect(gnp.Spec.Egress[1].Destination.Ports).To(Equal([]numorstring.Port{numorstring.SinglePort(80)}))

		Expect(gnp.Spec.Egress[2].Destination.NamespaceSelector).To(Equal("k3 == 'v3'"))
		Expect(gnp.Spec.Egress[2].Destination.Ports).To(Equal([]numorstring.Port{{MinPort: 20, MaxPort: 30}}))

		Expect(gnp.Spec.Egress[3].Destination.NamespaceSelector).To(Equal("k4 == 'v4'"))
		Expect(gnp.Spec.Egress[3].Destination.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k5 == 'v5'"))
		Expect(gnp.Spec.Egress[3].Destination.Ports).To(Equal([]numorstring.Port{{MinPort: 20, MaxPort: 30}}))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(2))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
		Expect(gnp.Spec.Types[1]).To(Equal(apiv3.PolicyTypeEgress))
	})

	It("should parse an AdminNetworkPolicy with empty namespaces in Subject", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 500,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&anp, float64(500.0), nil)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Ingress).To(HaveLen(0))
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should parse an AdminNetworkPolicy with empty podSelector in Subject", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Pods: &adminpolicy.NamespacedPod{
						PodSelector: metav1.LabelSelector{},
					},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&anp, float64(600.0), nil)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Ingress).To(HaveLen(0))
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should parse an AdminNetworkPolicy with a rule with namespaceSelector", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Pods: &adminpolicy.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Allow",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"namespaceRole": "dev",
										"namespaceFoo":  "bar",
									},
								},
							},
						},
					},
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), nil)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))

		Expect(len(gnp.Spec.Ingress)).To(Equal(1))
		Expect(gnp.Spec.Ingress[0].Source.Selector).To(BeZero())
		Expect(gnp.Spec.Ingress[0].Source.NamespaceSelector).To(Equal("namespaceFoo == 'bar' && namespaceRole == 'dev'"))

		// There should be no Egress rules.
		Expect(gnp.Spec.Egress).To(HaveLen(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(1))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse an AdminNetworkPolicy with a rule with podSelector", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Pods: &adminpolicy.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Allow",
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Pods: &adminpolicy.NamespacedPod{
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"namespaceRole": "dev",
											"namespaceFoo":  "bar",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), nil)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))

		Expect(len(gnp.Spec.Egress)).To(Equal(1))
		Expect(gnp.Spec.Egress[0].Destination.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Egress[0].Destination.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && namespaceFoo == 'bar' && namespaceRole == 'dev'"))

		// There should be no Ingress rules.
		Expect(gnp.Spec.Ingress).To(HaveLen(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(1))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeEgress))
	})

	It("should faild parsing an AdminNetworkPolicy with a rule with neither namespaces or pods set", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Pods: &adminpolicy.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Allow",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: nil,
								Pods:       nil,
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Pass",
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: nil,
								Pods:       nil,
							},
						},
					},
				},
			},
		}

		expectedErr := cerrors.ErrorAdminPolicyConversion{
			PolicyName: "test.policy",
			Rules: []cerrors.ErrorAdminPolicyConversionRule{
				{
					EgressRule: nil,
					IngressRule: &adminpolicy.AdminNetworkPolicyIngressRule{
						Name:   "A random ingress rule",
						Action: "Allow",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: nil,
								Pods:       nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: none of supported fields in 'From' is set.",
				},
				{
					IngressRule: nil,
					EgressRule: &adminpolicy.AdminNetworkPolicyEgressRule{
						Name:   "A random egress rule",
						Action: "Pass",
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: nil,
								Pods:       nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: none of supported fields in 'To' is set.",
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), &expectedErr)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))

		// There should be no rules.
		Expect(gnp.Spec.Ingress).To(HaveLen(0))
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should parse an AdminNetworkPolicy with a rule with empty namespaceSelector", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Pods: &adminpolicy.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Allow",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{},
								},
							},
						},
					},
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), nil)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))

		Expect(len(gnp.Spec.Ingress)).To(Equal(1))
		Expect(gnp.Spec.Ingress[0].Source.Selector).To(BeZero())
		Expect(gnp.Spec.Ingress[0].Source.NamespaceSelector).To(Equal("all()"))

		// There should be no Egress rules.
		Expect(gnp.Spec.Egress).To(HaveLen(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(1))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse an AdminNetworkPolicy with a rule with empty podSelector", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Pods: &adminpolicy.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Pass",
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Pods: &adminpolicy.NamespacedPod{
									NamespaceSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{},
									},
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{},
									},
								},
							},
						},
					},
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), nil)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))

		Expect(len(gnp.Spec.Egress)).To(Equal(1))
		Expect(gnp.Spec.Egress[0].Destination.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(gnp.Spec.Egress[0].Destination.NamespaceSelector).To(Equal("all()"))

		// There should be no Ingress rules.
		Expect(gnp.Spec.Ingress).To(HaveLen(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(1))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeEgress))
	})

	It("should parse an AdminNetworkPolicy with a rule with a rule with both Namespaces and Pods", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 1000,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Pods: &adminpolicy.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Deny",
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Pods: &adminpolicy.NamespacedPod{
									NamespaceSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"namespaceRole": "dev",
											"namespaceFoo":  "bar",
										},
									},
									PodSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{
											"podA": "B",
											"podC": "D",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		gnp := convertToGNP(&anp, float64(1000.0), nil)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))

		Expect(len(gnp.Spec.Ingress)).To(Equal(1))
		Expect(gnp.Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && podA == 'B' && podC == 'D'"))
		Expect(gnp.Spec.Ingress[0].Source.NamespaceSelector).To(Equal("namespaceFoo == 'bar' && namespaceRole == 'dev'"))

		// There should be no Egress rules.
		Expect(gnp.Spec.Egress).To(HaveLen(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(1))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse an AdminNetworkPolicy with a Subject with MatchExpressions", func() {
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 500,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "k",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"v1", "v2"},
							},
						},
					},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&anp, float64(500.0), nil)

		// Assert value fields are correct.
		Expect(gnp.Spec.NamespaceSelector).To(Equal("k in { 'v1', 'v2' }"))
		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(gnp.Spec.Ingress).To(HaveLen(0))

		// There should be no Egress rules
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should replace an unsupported AdminNeworkPolicy rule with Deny action with a deny-all one", func() {
		ports := []adminpolicy.AdminNetworkPolicyPort{{
			PortNumber: &adminpolicy.Port{Port: 80},
		}}

		badPorts := []adminpolicy.AdminNetworkPolicyPort{{
			PortRange: &adminpolicy.PortRange{Start: 40, End: 20, Protocol: kapiv1.ProtocolUDP},
		}}
		anp := adminpolicy.AdminNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: adminpolicy.AdminNetworkPolicySpec{
				Priority: 600,
				Subject: adminpolicy.AdminNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []adminpolicy.AdminNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						Ports:  &ports,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
						},
					},
					{
						Name:   "A random ingress rule 2",
						Action: "Pass",
						Ports:  &badPorts,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
						},
					},
				},
				Egress: []adminpolicy.AdminNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						Ports:  &badPorts,
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
						},
					},
					{
						Name:   "A random egress rule 2",
						Action: "Deny",
						Ports:  &ports,
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k4": "v4",
									},
								},
							},
						},
					},
				},
			},
		}

		expectedErr := cerrors.ErrorAdminPolicyConversion{
			PolicyName: "test.policy",
			Rules: []cerrors.ErrorAdminPolicyConversionRule{
				{
					EgressRule: nil,
					IngressRule: &adminpolicy.AdminNetworkPolicyIngressRule{
						Name:   "A random ingress rule 2",
						Action: "Pass",
						Ports:  &badPorts,
						From: []adminpolicy.AdminNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k": "v"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: failed to parse k8s port: minimum port number (40) is greater than maximum port number (20) in port range",
				},
				{
					IngressRule: nil,
					EgressRule: &adminpolicy.AdminNetworkPolicyEgressRule{
						Name:   "A random egress rule",
						Action: "Deny",
						Ports:  &badPorts,
						To: []adminpolicy.AdminNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k3": "v3"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: failed to parse k8s port: minimum port number (40) is greater than maximum port number (20) in port range",
				},
			},
		}

		gnp := convertToGNP(&anp, float64(600.0), &expectedErr)

		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))

		Expect(len(gnp.Spec.Ingress)).To(Equal(1))
		Expect(gnp.Spec.Ingress[0].Source.NamespaceSelector).To(Equal("k == 'v'"))
		Expect(gnp.Spec.Ingress[0].Destination.Ports).To(Equal([]numorstring.Port{numorstring.SinglePort(80)}))

		Expect(gnp.Spec.Egress).To(HaveLen(2))
		Expect(gnp.Spec.Egress[0].Destination.NamespaceSelector).To(BeZero())
		Expect(gnp.Spec.Egress[0]).To(Equal(apiv3.Rule{
			Action: apiv3.Deny,
		}))

		Expect(gnp.Spec.Egress[1].Destination.NamespaceSelector).To(Equal("k4 == 'v4'"))
		Expect(gnp.Spec.Egress[1].Destination.Selector).To(BeZero())
		Expect(gnp.Spec.Egress[1].Destination.Ports).To(Equal([]numorstring.Port{numorstring.SinglePort(80)}))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(2))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
		Expect(gnp.Spec.Types[1]).To(Equal(apiv3.PolicyTypeEgress))
	})
})
