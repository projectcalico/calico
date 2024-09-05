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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	adminpolicy "sigs.k8s.io/network-policy-api/apis/v1alpha1"
)

var _ = Describe("Test AdminNetworkPolicy conversion", func() {
	// Use a single instance of the Converter for these tests.
	c := NewConverter()

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

		// Parse the policy.
		pol, err := c.K8sAdminNetworkPolicyToCalico(&anp)
		Expect(err).NotTo(HaveOccurred())
		gnp, ok := pol.Value.(*apiv3.GlobalNetworkPolicy)
		Expect(ok).To(BeTrue())

		// Make sure the type information is correct.
		Expect(pol.Value.(*apiv3.GlobalNetworkPolicy).Kind).To(Equal(apiv3.KindGlobalNetworkPolicy))
		Expect(pol.Value.(*apiv3.GlobalNetworkPolicy).APIVersion).To(Equal(apiv3.GroupVersionCurrent))

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("kanp.anp.test.policy"))

		// Assert value fields are correct.
		Expect(*gnp.Spec.Order).To(Equal(float64(100.0)))
		// Check the selector is correct, and that the matches are sorted.
		Expect(gnp.Spec.NamespaceSelector).To(Equal("label == 'value' && label2 == 'value2'"))
		protoTCP := numorstring.ProtocolFromString("TCP")
		Expect(gnp.Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Name:     "The first ingress rule",
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

		// Parse the policy.
		pol, err := c.K8sAdminNetworkPolicyToCalico(&anp)
		Expect(err).NotTo(HaveOccurred())

		Expect(pol.Value.(*apiv3.GlobalNetworkPolicy).Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Name:        "A random ingress rule",
				Action:      "Pass",
				Protocol:    nil, // We only default to TCP when ports exist
				Source:      apiv3.EntityRule{NamespaceSelector: "k == 'v' && k2 == 'v2'"},
				Destination: apiv3.EntityRule{},
			},
		))
		Expect(pol.Value.(*apiv3.GlobalNetworkPolicy).Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Name:        "A random egress rule",
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
				PortNumber: &adminpolicy.Port{Port: -10},
			},
			{
				PortRange: &adminpolicy.PortRange{Start: -50, End: -1},
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
				},
			},
		}

		expectedErr1 := cerrors.ErrorAdminPolicyConversion{
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
			},
		}

		// Parse the policy.
		pol1, err := c.K8sAdminNetworkPolicyToCalico(&anp)
		Expect(err).To(Equal(expectedErr1))

		protoTCP := numorstring.ProtocolFromString("TCP")

		Expect(len(pol1.Value.(*apiv3.GlobalNetworkPolicy).Spec.Ingress)).To(Equal(0))
		Expect(len(pol1.Value.(*apiv3.GlobalNetworkPolicy).Spec.Egress)).To(Equal(1))

		Expect(pol1.Value.(*apiv3.GlobalNetworkPolicy).Spec.Egress).To(ConsistOf(
			apiv3.Rule{
				Name:     "A random egress rule",
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
})
