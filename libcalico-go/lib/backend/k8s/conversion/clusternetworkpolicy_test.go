// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clusternetpol "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var _ = Describe("Test ClusterNetworkPolicy conversion - Admin tier", func() {
	It("should parse a basic k8s ClusterNetworkPolicy to a GlobalNetworkPolicy", func() {
		protocols := []clusternetpol.ClusterNetworkPolicyProtocol{{
			TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
				DestinationPort: &clusternetpol.Port{
					Number: 80,
				},
			},
		}}
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 100,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:      "The first ingress rule",
						Action:    "Accept",
						Protocols: protocols,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
		gnp := convertToGNP(&cnp, nil)

		// Check the selector is correct, and that the matches are sorted.
		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))
		protoTCP := numorstring.ProtocolFromString("TCP")
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("The first ingress rule"),
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

	It("should drop rules with invalid action in a k8s ClusterNetworkPolicy", func() {
		protocols := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Range: &clusternetpol.PortRange{Start: 2000, End: 3000},
					},
				},
			},
		}
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 300,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Log",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
						Name:      "A random ingress rule 2",
						Action:    "Accept",
						Protocols: protocols,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: protocols,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
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
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
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

		expectedErr := cerrors.ErrorClusterNetworkPolicyConversion{
			PolicyName: "test.policy",
			Rules: []cerrors.ErrorClusterNetworkPolicyConversionRule{
				{
					EgressRule: nil,
					IngressRule: &clusternetpol.ClusterNetworkPolicyIngressRule{
						Name:   "A random ingress rule",
						Action: "Log",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k2": "v2", "k": "v"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: unsupported cluster network policy action Log",
				},
				{
					IngressRule: nil,
					EgressRule: &clusternetpol.ClusterNetworkPolicyEgressRule{
						Name:   "A random egress rule 2",
						Action: "Drop",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k30": "v30", "k40": "v40"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: unsupported cluster network policy action Drop",
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&cnp, &expectedErr)

		protoTCP := numorstring.ProtocolFromString("TCP")

		Expect(len(gnp.Spec.Ingress)).To(Equal(1))
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("A random ingress rule 2"),
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
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("A random egress rule"),
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

	It("should parse a k8s ClusterNetworkPolicy with no ports", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 200,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
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
		gnp := convertToGNP(&cnp, nil)

		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata:    k8sClusterNetworkPolicyToCalicoMetadata("A random ingress rule"),
				Action:      "Pass",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{NamespaceSelector: "k == 'v' && k2 == 'v2'"},
				Destination: apiv3.EntityRule{},
			},
		))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Metadata:    k8sClusterNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:      "Deny",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{},
				Destination: apiv3.EntityRule{NamespaceSelector: "k3 == 'v3' && k4 == 'v4'"},
			},
		))
	})

	It("should drop rules with invalid ports in a k8s ClusterNetworkPolicy", func() {
		goodProtos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Range: &clusternetpol.PortRange{Start: 2000, End: 3000},
					},
				},
			},
		}
		badProtos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Range: &clusternetpol.PortRange{Start: 1000, End: 10},
					},
				},
			},
		}

		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 300,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:      "A random ingress rule",
						Action:    "Accept",
						Protocols: badProtos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
						Name:      "A random ingress rule 2",
						Action:    "Pass",
						Protocols: goodProtos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: goodProtos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
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
						Name:      "A random egress rule 2",
						Action:    "Accept",
						Protocols: badProtos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
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

		expectedErr := cerrors.ErrorClusterNetworkPolicyConversion{
			PolicyName: "test.policy",
			Rules: []cerrors.ErrorClusterNetworkPolicyConversionRule{
				{
					EgressRule: nil,
					IngressRule: &clusternetpol.ClusterNetworkPolicyIngressRule{
						Name:      "A random ingress rule",
						Action:    "Accept",
						Protocols: badProtos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k2": "v2", "k": "v"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: failed to parse k8s protocol: minimum port number (1000) is greater than maximum port number (10) in port range",
				},
				{
					IngressRule: nil,
					EgressRule: &clusternetpol.ClusterNetworkPolicyEgressRule{
						Name:      "A random egress rule 2",
						Action:    "Accept",
						Protocols: badProtos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k30": "v30", "k40": "v40"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: failed to parse k8s protocol: minimum port number (1000) is greater than maximum port number (10) in port range",
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&cnp, &expectedErr)

		protoTCP := numorstring.ProtocolFromString("TCP")

		Expect(len(gnp.Spec.Ingress)).To(Equal(1))
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("A random ingress rule 2"),
				Action:   "Pass",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					NamespaceSelector: "k10 == 'v10' && k20 == 'v20'",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{
						numorstring.SinglePort(80),
						{MinPort: 2000, MaxPort: 3000},
					},
				},
			},
		))

		Expect(len(gnp.Spec.Egress)).To(Equal(1))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:   "Deny",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source:   apiv3.EntityRule{},
				Destination: apiv3.EntityRule{
					NamespaceSelector: "k3 == 'v3' && k4 == 'v4'",
					Ports: []numorstring.Port{
						numorstring.SinglePort(80),
						{MinPort: 2000, MaxPort: 3000},
					},
				},
			},
		))
	})

	It("should parse an ClusterNetworkPolicy with no rules", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 500,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
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
		gnp := convertToGNP(&cnp, nil)

		// Assert value fields are correct.
		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))
		Expect(gnp.Spec.Ingress).To(HaveLen(0))

		// There should be no Egress rules
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should parse an ClusterNetworkPolicy with Namespaces subject and multiple peers", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 600,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								Pods: &clusternetpol.NamespacedPod{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Pods: &clusternetpol.NamespacedPod{
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

		gnp := convertToGNP(&cnp, nil)

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

	It("should parse an ClusterNetworkPolicy with Pods subject and multiple peers", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 600,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label2": "value2",
							},
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								Pods: &clusternetpol.NamespacedPod{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Pods: &clusternetpol.NamespacedPod{
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

		gnp := convertToGNP(&cnp, nil)

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

	It("should parse a k8s ClusterNetworkPolicy with a DoesNotExist expression ", func() {
		protos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
		}
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 600,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label":  "value",
								"label2": "value2",
							},
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:      "A random ingress rule",
						Action:    "Accept",
						Protocols: protos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Pods: &clusternetpol.NamespacedPod{
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

		gnp := convertToGNP(&cnp, nil)

		// Check the selector is correct, and that the matches are sorted.
		Expect(gnp.Spec.Selector).To(Equal(
			"projectcalico.org/orchestrator == 'k8s' && label == 'value' && label2 == 'value2'"))
		protoTCP := numorstring.ProtocolFromString("TCP")
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Action:   "Allow",
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("A random ingress rule"),
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

	It("should parse an ClusterNetworkPolicy with multiple peers and ports", func() {
		protos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
			{
				UDP: &clusternetpol.ClusterNetworkPolicyProtocolUDP{
					DestinationPort: &clusternetpol.Port{
						Range: &clusternetpol.PortRange{Start: 20, End: 30},
					},
				},
			},
		}
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 600,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:      "A random ingress rule",
						Action:    "Pass",
						Protocols: protos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								Pods: &clusternetpol.NamespacedPod{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: protos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Pods: &clusternetpol.NamespacedPod{
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

		gnp := convertToGNP(&cnp, nil)

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

	It("should parse an ClusterNetworkPolicy with empty namespaces in Subject", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 500,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&cnp, nil)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Ingress).To(HaveLen(0))
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should parse an ClusterNetworkPolicy with empty podSelector in Subject", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 600,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						PodSelector: metav1.LabelSelector{},
					},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&cnp, nil)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))
		Expect(gnp.Spec.Ingress).To(HaveLen(0))
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should parse an ClusterNetworkPolicy with a rule with namespaceSelector", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 600,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Accept",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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

		gnp := convertToGNP(&cnp, nil)

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

	It("should parse an ClusterNetworkPolicy with a rule with podSelector", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 600,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Accept",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Pods: &clusternetpol.NamespacedPod{
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

		gnp := convertToGNP(&cnp, nil)

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

	It("should faild parsing an ClusterNetworkPolicy with a rule with neither namespaces or pods set", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 600,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Accept",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Namespaces: nil,
								Pods:       nil,
							},
						},
					},
				},
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Pass",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: nil,
								Pods:       nil,
							},
						},
					},
				},
			},
		}

		expectedErr := cerrors.ErrorClusterNetworkPolicyConversion{
			PolicyName: "test.policy",
			Rules: []cerrors.ErrorClusterNetworkPolicyConversionRule{
				{
					EgressRule: nil,
					IngressRule: &clusternetpol.ClusterNetworkPolicyIngressRule{
						Name:   "A random ingress rule",
						Action: "Accept",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
					EgressRule: &clusternetpol.ClusterNetworkPolicyEgressRule{
						Name:   "A random egress rule",
						Action: "Pass",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
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

		gnp := convertToGNP(&cnp, &expectedErr)

		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(gnp.Spec.NamespaceSelector).To(Equal("all()"))

		Expect(gnp.Spec.Egress).To(HaveLen(1))
		Expect(gnp.Spec.Egress[0].Destination.NamespaceSelector).To(BeZero())
		Expect(gnp.Spec.Egress[0]).To(Equal(apiv3.Rule{Action: apiv3.Deny}))

		// There should be no ingress rules.
		Expect(gnp.Spec.Ingress).To(HaveLen(0))
	})

	It("should parse an ClusterNetworkPolicy with a rule with empty namespaceSelector", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Priority: 600,
				Tier:     clusternetpol.AdminTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Accept",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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

		gnp := convertToGNP(&cnp, nil)

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

	It("should parse an ClusterNetworkPolicy with a rule with empty podSelector", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 600,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Pass",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Pods: &clusternetpol.NamespacedPod{
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

		gnp := convertToGNP(&cnp, nil)

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

	It("should parse an ClusterNetworkPolicy with a rule with a rule with both Namespaces and Pods", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 1000,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label": "value",
							},
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Deny",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Pods: &clusternetpol.NamespacedPod{
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

		gnp := convertToGNP(&cnp, nil)

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

	It("should parse an ClusterNetworkPolicy with a Subject with MatchExpressions", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 500,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
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
		gnp := convertToGNP(&cnp, nil)

		// Assert value fields are correct.
		Expect(gnp.Spec.NamespaceSelector).To(Equal("k in { 'v1', 'v2' }"))
		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(gnp.Spec.Ingress).To(HaveLen(0))

		// There should be no Egress rules
		Expect(gnp.Spec.Egress).To(HaveLen(0))
	})

	It("should replace an unsupported ClusterNetworkPolicy rule with Deny action with a deny-all one", func() {
		goodProtos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
		}
		badProtos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				UDP: &clusternetpol.ClusterNetworkPolicyProtocolUDP{
					DestinationPort: &clusternetpol.Port{
						Range: &clusternetpol.PortRange{Start: 40, End: 20},
					},
				},
			},
		}
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 600,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:      "A random ingress rule",
						Action:    "Pass",
						Protocols: badProtos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
						Name:      "A random ingress rule 2",
						Action:    "Accept",
						Protocols: badProtos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: badProtos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
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
						Name:      "A random egress rule 2",
						Action:    "Deny",
						Protocols: goodProtos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
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

		expectedErr := cerrors.ErrorClusterNetworkPolicyConversion{
			PolicyName: "test.policy",
			Rules: []cerrors.ErrorClusterNetworkPolicyConversionRule{
				{
					EgressRule: nil,
					IngressRule: &clusternetpol.ClusterNetworkPolicyIngressRule{
						Name:      "A random ingress rule",
						Action:    "Pass",
						Protocols: badProtos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k": "v"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: failed to parse k8s protocol: minimum port number (40) is greater than maximum port number (20) in port range",
				},
				{
					EgressRule: nil,
					IngressRule: &clusternetpol.ClusterNetworkPolicyIngressRule{
						Name:      "A random ingress rule 2",
						Action:    "Accept",
						Protocols: badProtos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k": "v"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: failed to parse k8s protocol: minimum port number (40) is greater than maximum port number (20) in port range",
				},
				{
					IngressRule: nil,
					EgressRule: &clusternetpol.ClusterNetworkPolicyEgressRule{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: badProtos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k3": "v3"},
									MatchExpressions: nil,
								},
								Pods: nil,
							},
						},
					},
					Reason: "k8s rule couldn't be converted: failed to parse k8s protocol: minimum port number (40) is greater than maximum port number (20) in port range",
				},
			},
		}

		gnp := convertToGNP(&cnp, &expectedErr)

		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))

		Expect(len(gnp.Spec.Ingress)).To(Equal(1))
		Expect(gnp.Spec.Egress[0].Destination.NamespaceSelector).To(BeZero())
		Expect(gnp.Spec.Egress[0]).To(Equal(apiv3.Rule{Action: apiv3.Deny}))

		Expect(gnp.Spec.Egress).To(HaveLen(2))
		Expect(gnp.Spec.Egress[0].Destination.NamespaceSelector).To(BeZero())
		Expect(gnp.Spec.Egress[0]).To(Equal(apiv3.Rule{Action: apiv3.Deny}))

		Expect(gnp.Spec.Egress[1].Destination.NamespaceSelector).To(Equal("k4 == 'v4'"))
		Expect(gnp.Spec.Egress[1].Destination.Selector).To(BeZero())
		Expect(gnp.Spec.Egress[1].Destination.Ports).To(Equal([]numorstring.Port{numorstring.SinglePort(80)}))

		// Check that Types field exists and has only 'ingress'
		Expect(len(gnp.Spec.Types)).To(Equal(2))
		Expect(gnp.Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
		Expect(gnp.Spec.Types[1]).To(Equal(apiv3.PolicyTypeEgress))
	})

	It("should parse a k8s ClusterNetworkPolicy with a Networks peer", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 200,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Networks: []clusternetpol.CIDR{"10.10.10.0/24", "1.1.1.1/32"},
							},
						},
					},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&cnp, nil)

		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata:    k8sClusterNetworkPolicyToCalicoMetadata("A random ingress rule"),
				Action:      "Pass",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{NamespaceSelector: "k == 'v'"},
				Destination: apiv3.EntityRule{},
			},
		))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Metadata:    k8sClusterNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:      "Deny",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{},
				Destination: apiv3.EntityRule{NamespaceSelector: "k3 == 'v3'"},
			},
			apiv3.Rule{
				Metadata:    k8sClusterNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:      "Deny",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{},
				Destination: apiv3.EntityRule{Nets: []string{"10.10.10.0/24", "1.1.1.1/32"}},
			},
		))
	})

	It("should parse a k8s ClusterNetworkPolicy with an any address Network peer", func() {
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 200,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:   "A random ingress rule",
						Action: "Pass",
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:   "A random egress rule",
						Action: "Deny",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Networks: []clusternetpol.CIDR{"0.0.0.0/0", "::/0"},
							},
						},
					},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&cnp, nil)

		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata:    k8sClusterNetworkPolicyToCalicoMetadata("A random ingress rule"),
				Action:      "Pass",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{NamespaceSelector: "k == 'v'"},
				Destination: apiv3.EntityRule{},
			},
		))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Metadata:    k8sClusterNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:      "Deny",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{},
				Destination: apiv3.EntityRule{NamespaceSelector: "k3 == 'v3'"},
			},
			apiv3.Rule{
				Metadata:    k8sClusterNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:      "Deny",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{},
				Destination: apiv3.EntityRule{Nets: []string{"0.0.0.0/0", "::/0"}},
			},
		))
	})

	It("should parse a k8s ClusterNetworkPolicy with a Networks peer and ports", func() {
		protos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
		}
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 200,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:      "A random ingress rule",
						Action:    "Pass",
						Protocols: protos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: protos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Networks: []clusternetpol.CIDR{"10.10.10.0/24", "1.1.1.1/32"},
							},
						},
					},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&cnp, nil)

		protocolTCP := numorstring.ProtocolFromString(numorstring.ProtocolTCP)
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("A random ingress rule"),
				Action:   "Pass",
				Protocol: &protocolTCP,
				Source:   apiv3.EntityRule{NamespaceSelector: "k == 'v'"},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{
						numorstring.SinglePort(80),
					},
				},
			},
		))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:   "Deny",
				Protocol: &protocolTCP,
				Source:   apiv3.EntityRule{},
				Destination: apiv3.EntityRule{
					NamespaceSelector: "k3 == 'v3'",
					Ports: []numorstring.Port{
						numorstring.SinglePort(80),
					},
				},
			},
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("A random egress rule"),
				Action:   "Deny",
				Protocol: &protocolTCP,
				Source:   apiv3.EntityRule{},
				Destination: apiv3.EntityRule{
					Nets: []string{"10.10.10.0/24", "1.1.1.1/32"},
					Ports: []numorstring.Port{
						numorstring.SinglePort(80),
					},
				},
			},
		))
	})

	It("should parse a k8s ClusterNetworkPolicy with an invalid networks peer", func() {
		protos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
		}
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test.policy",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier:     clusternetpol.AdminTier,
				Priority: 200,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:      "A random ingress rule",
						Action:    "Pass",
						Protocols: protos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: protos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Networks: []clusternetpol.CIDR{"10.10.10.0/24", "1.1.1.1/66"},
							},
						},
					},
				},
			},
		}

		expectedErr := cerrors.ErrorClusterNetworkPolicyConversion{
			PolicyName: "test.policy",
			Rules: []cerrors.ErrorClusterNetworkPolicyConversionRule{
				{
					IngressRule: nil,
					EgressRule: &clusternetpol.ClusterNetworkPolicyEgressRule{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: protos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k3": "v3"},
									MatchExpressions: nil,
								},
							},
							{
								Networks: []clusternetpol.CIDR{"10.10.10.0/24", "1.1.1.1/66"},
							},
						},
					},
					Reason: "k8s rule couldn't be converted: invalid CIDR in ANP rule: invalid CIDR address: 1.1.1.1/66",
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&cnp, &expectedErr)

		protocolTCP := numorstring.ProtocolFromString(numorstring.ProtocolTCP)
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("A random ingress rule"),
				Action:   "Pass",
				Protocol: &protocolTCP,
				Source:   apiv3.EntityRule{NamespaceSelector: "k == 'v'"},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{
						numorstring.SinglePort(80),
					},
				},
			},
		))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Action: "Deny", // The invalid rule is replaced with a deny-all rule.
			},
		))
	})
})

// Most of the conversion logic is shared with ANP, so only testing a few
// cases for BANP.
var _ = Describe("Test ClusterNetworkPolicy conversion - Baseline tier", func() {
	It("should parse a basic k8s ClusterNetworkPolicy to a GlobalNetworkPolicy", func() {
		protos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
		}
		bcnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier: clusternetpol.BaselineTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Pods: &clusternetpol.NamespacedPod{
						NamespaceSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"label":  "value",
								"label2": "value2",
							},
						},
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"foo": "bar",
							},
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Name:      "The first ingress rule",
						Action:    "Accept",
						Protocols: protos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
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
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:   "The first egress rule",
						Action: "Deny",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Networks: []clusternetpol.CIDR{"10.0.0.0/8"},
							},
						},
					},
					{
						Action: "Accept",
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Networks: []clusternetpol.CIDR{"0.0.0.0/0"},
							},
						},
					},
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&bcnp, nil)

		// Check the selector is correct, and that the matches are sorted.
		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))
		Expect(gnp.Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && foo == 'bar'"))
		protoTCP := numorstring.ProtocolFromString("TCP")
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("The first ingress rule"),
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
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata("The first egress rule"),
				Action:   "Deny",
				Destination: apiv3.EntityRule{
					Nets: []string{"10.0.0.0/8"},
				},
			},
			apiv3.Rule{
				Action: "Allow",
				Destination: apiv3.EntityRule{
					Nets: []string{"0.0.0.0/0"},
				},
			},
		))
	})

	It("should parse a k8s ClusterNetworkPolicy with an invalid networks peer", func() {
		protos := []clusternetpol.ClusterNetworkPolicyProtocol{
			{
				TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
					DestinationPort: &clusternetpol.Port{
						Number: 80,
					},
				},
			},
		}
		cnp := clusternetpol.ClusterNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				UID:  types.UID("30316465-6365-4463-ad63-3564622d3638"),
			},
			Spec: clusternetpol.ClusterNetworkPolicySpec{
				Tier: clusternetpol.BaselineTier,
				Subject: clusternetpol.ClusterNetworkPolicySubject{
					Namespaces: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"label":  "value",
							"label2": "value2",
						},
					},
				},
				Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
					{
						Action:    "Deny",
						Protocols: protos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{},
						},
					},
				},
				Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
					{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: protos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k3": "v3",
									},
								},
							},
							{
								Networks: []clusternetpol.CIDR{"10.10.10.0/24", "1.1.1.1/66"},
							},
						},
					},
				},
			},
		}

		expectedErr := cerrors.ErrorClusterNetworkPolicyConversion{
			PolicyName: "default",
			Rules: []cerrors.ErrorClusterNetworkPolicyConversionRule{
				{
					IngressRule: &clusternetpol.ClusterNetworkPolicyIngressRule{
						Action:    "Deny",
						Protocols: protos,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
							{},
						},
					},
					Reason: "k8s rule couldn't be converted: none of supported fields in 'From' is set.",
				},
				{
					EgressRule: &clusternetpol.ClusterNetworkPolicyEgressRule{
						Name:      "A random egress rule",
						Action:    "Deny",
						Protocols: protos,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
							{
								Namespaces: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k3": "v3"},
									MatchExpressions: nil,
								},
							},
							{
								Networks: []clusternetpol.CIDR{"10.10.10.0/24", "1.1.1.1/66"},
							},
						},
					},
					Reason: "k8s rule couldn't be converted: invalid CIDR in ANP rule: invalid CIDR address: 1.1.1.1/66",
				},
			},
		}

		// Convert the policy
		gnp := convertToGNP(&cnp, &expectedErr)

		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Action: "Deny", // The invalid rule is replaced with a deny-all rule.
			},
		))
		Expect(gnp.Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Action: "Deny", // The invalid rule is replaced with a deny-all rule.
			},
		))
	})
})

func convertToGNP(
	cnp *clusternetpol.ClusterNetworkPolicy,
	expectedErr *cerrors.ErrorClusterNetworkPolicyConversion,
) *apiv3.GlobalNetworkPolicy {
	// Use a single instance of the Converter for these tests.
	c := NewConverter()

	// Parse the policy.
	pol, err := c.K8sClusterNetworkPolicyToCalico(cnp)

	if expectedErr == nil {
		ExpectWithOffset(1, err).To(BeNil())
	} else {
		ExpectWithOffset(1, err).To(Equal(*expectedErr))
	}

	// Assert key fields are correct.
	tier := clusterNetworkPolicyTier(cnp)

	gnp, ok := pol.Value.(*apiv3.GlobalNetworkPolicy)
	Expect(ok).To(BeTrue())

	// Make sure the type information is correct.
	Expect(gnp.Kind).To(Equal(apiv3.KindGlobalNetworkPolicy))
	Expect(gnp.APIVersion).To(Equal(apiv3.GroupVersionCurrent))

	// Assert value fields are correct.
	Expect(*gnp.Spec.Order).To(Equal(float64(cnp.Spec.Priority)))
	Expect(gnp.Spec.Tier).To(Equal(tier))

	return gnp
}
