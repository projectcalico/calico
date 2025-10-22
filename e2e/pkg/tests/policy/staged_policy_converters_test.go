// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestPolicyConverters(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Policy Converters Suite")
}

var _ = Describe("Policy Converters", func() {
	Describe("ConvertStagedPolicyToEnforced", func() {
		It("should properly convert StagedNetworkPolicy to NetworkPolicy", func() {
			v4 := 4
			itype := 1
			icode := 4
			iproto := numorstring.ProtocolFromString("TCP")
			port80 := numorstring.SinglePort(uint16(80))
			port443 := numorstring.SinglePort(uint16(443))

			irule := v3.Rule{
				Action:    v3.Allow,
				IPVersion: &v4,
				Protocol:  &iproto,
				ICMP: &v3.ICMPFields{
					Type: &itype,
					Code: &icode,
				},
				Source: v3.EntityRule{
					Nets:     []string{"10.100.10.1"},
					Selector: "mylabel = value1",
					Ports:    []numorstring.Port{port80},
				},
				Destination: v3.EntityRule{
					Nets:     []string{"10.100.1.1"},
					Selector: "",
					Ports:    []numorstring.Port{port443},
				},
			}

			order := float64(101)
			selector := "mylabel == selectme"
			tier := "my-tier"

			staged := v3.NewStagedNetworkPolicy()
			staged.Name = tier + ".test-policy"
			staged.Namespace = "default"
			staged.Spec.Tier = tier
			staged.Spec.Order = &order
			staged.Spec.Ingress = []v3.Rule{irule}
			staged.Spec.Selector = selector
			staged.Spec.Types = []v3.PolicyType{v3.PolicyTypeIngress}
			staged.Spec.StagedAction = v3.StagedActionSet

			stagedAction, enforced := ConvertStagedPolicyToEnforced(staged)

			Expect(stagedAction).To(Equal(staged.Spec.StagedAction))
			Expect(enforced.Spec.Tier).To(Equal(staged.Spec.Tier))
			Expect(enforced.Spec.Ingress).To(Equal(staged.Spec.Ingress))
			Expect(enforced.Spec.Selector).To(Equal(staged.Spec.Selector))
			Expect(enforced.Spec.Order).To(Equal(staged.Spec.Order))
			Expect(enforced.Spec.Types).To(Equal(staged.Spec.Types))
			Expect(enforced.Namespace).To(Equal(staged.Namespace))
			Expect(enforced.Name).To(Equal(staged.Name))
			Expect(enforced.ResourceVersion).To(BeEmpty(), "ResourceVersion should be cleared")
			Expect(enforced.UID).To(BeEmpty(), "UID should be cleared")
		})

		It("should handle egress rules", func() {
			erule := v3.Rule{
				Action: v3.Deny,
				Destination: v3.EntityRule{
					Nets: []string{"192.168.1.0/24"},
				},
			}

			order := float64(200)
			staged := v3.NewStagedNetworkPolicy()
			staged.Name = "default.deny-egress"
			staged.Namespace = "test-ns"
			staged.Spec.Order = &order
			staged.Spec.Egress = []v3.Rule{erule}
			staged.Spec.Selector = "app == backend"
			staged.Spec.Types = []v3.PolicyType{v3.PolicyTypeEgress}

			_, enforced := ConvertStagedPolicyToEnforced(staged)

			Expect(enforced.Spec.Egress).To(Equal(staged.Spec.Egress))
			Expect(enforced.Spec.Types).To(Equal(staged.Spec.Types))
		})
	})

	Describe("ConvertStagedGlobalPolicyToEnforced", func() {
		It("should properly convert StagedGlobalNetworkPolicy to GlobalNetworkPolicy", func() {
			v4 := 4
			iproto := numorstring.ProtocolFromString("UDP")
			port53 := numorstring.SinglePort(uint16(53))

			irule := v3.Rule{
				Action:    v3.Allow,
				IPVersion: &v4,
				Protocol:  &iproto,
				Source: v3.EntityRule{
					Nets:     []string{"10.0.0.0/8"},
					Selector: "role == dns-client",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{port53},
				},
			}

			order := float64(50)
			selector := "role == dns-server"
			tier := "security"

			staged := v3.NewStagedGlobalNetworkPolicy()
			staged.Name = tier + ".allow-dns"
			staged.Spec.Tier = tier
			staged.Spec.Order = &order
			staged.Spec.Ingress = []v3.Rule{irule}
			staged.Spec.Selector = selector
			staged.Spec.Types = []v3.PolicyType{v3.PolicyTypeIngress}
			staged.Spec.StagedAction = v3.StagedActionLearn

			stagedAction, enforced := ConvertStagedGlobalPolicyToEnforced(staged)

			Expect(stagedAction).To(Equal(staged.Spec.StagedAction))
			Expect(enforced.Spec.Tier).To(Equal(staged.Spec.Tier))
			Expect(enforced.Spec.Ingress).To(Equal(staged.Spec.Ingress))
			Expect(enforced.Spec.Selector).To(Equal(staged.Spec.Selector))
			Expect(enforced.Spec.Order).To(Equal(staged.Spec.Order))
			Expect(enforced.Spec.Types).To(Equal(staged.Spec.Types))
			Expect(enforced.Name).To(Equal(staged.Name))
			Expect(enforced.ResourceVersion).To(BeEmpty(), "ResourceVersion should be cleared")
			Expect(enforced.UID).To(BeEmpty(), "UID should be cleared")
		})

		It("should handle both ingress and egress rules", func() {
			irule := v3.Rule{Action: v3.Allow}
			erule := v3.Rule{Action: v3.Deny}

			order := float64(100)
			staged := v3.NewStagedGlobalNetworkPolicy()
			staged.Name = "default.mixed-policy"
			staged.Spec.Order = &order
			staged.Spec.Ingress = []v3.Rule{irule}
			staged.Spec.Egress = []v3.Rule{erule}
			staged.Spec.Selector = "all()"
			staged.Spec.Types = []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress}

			_, enforced := ConvertStagedGlobalPolicyToEnforced(staged)

			Expect(enforced.Spec.Ingress).To(Equal(staged.Spec.Ingress))
			Expect(enforced.Spec.Egress).To(Equal(staged.Spec.Egress))
			Expect(enforced.Spec.Types).To(HaveLen(2))
		})
	})

	Describe("ConvertStagedKubernetesPolicyToK8SEnforced", func() {
		It("should properly convert StagedKubernetesNetworkPolicy to K8s NetworkPolicy", func() {
			podSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "web",
				},
			}

			peerSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{
					"role": "frontend",
				},
			}

			port80 := networkingv1.NetworkPolicyPort{
				Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
			}

			staged := v3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-frontend",
					Namespace: "production",
				},
				Spec: v3.StagedKubernetesNetworkPolicySpec{
					PodSelector: podSelector,
					Ingress: []networkingv1.NetworkPolicyIngressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{port80},
							From: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &peerSelector,
								},
							},
						},
					},
					PolicyTypes:  []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					StagedAction: v3.StagedActionSet,
				},
			}

			stagedAction, enforced := ConvertStagedKubernetesPolicyToK8SEnforced(&staged)

			Expect(stagedAction).To(Equal(staged.Spec.StagedAction))
			Expect(enforced.Spec.Ingress).To(Equal(staged.Spec.Ingress))
			Expect(enforced.Spec.PodSelector).To(Equal(staged.Spec.PodSelector))
			Expect(enforced.Spec.PolicyTypes).To(Equal(staged.Spec.PolicyTypes))
			Expect(enforced.Namespace).To(Equal(staged.Namespace))
			Expect(enforced.Name).To(Equal(staged.Name))
			Expect(enforced.TypeMeta.APIVersion).To(Equal("networking.k8s.io/v1"))
			Expect(enforced.TypeMeta.Kind).To(Equal("NetworkPolicy"))
			Expect(enforced.ResourceVersion).To(BeEmpty(), "ResourceVersion should be cleared")
			Expect(enforced.UID).To(BeEmpty(), "UID should be cleared")
		})

		It("should handle egress rules", func() {
			podSelector := metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "database",
				},
			}

			staged := v3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "db-egress",
					Namespace: "backend",
				},
				Spec: v3.StagedKubernetesNetworkPolicySpec{
					PodSelector: podSelector,
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"environment": "prod",
										},
									},
								},
							},
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				},
			}

			_, enforced := ConvertStagedKubernetesPolicyToK8SEnforced(&staged)

			Expect(enforced.Spec.Egress).To(Equal(staged.Spec.Egress))
			Expect(enforced.Spec.PolicyTypes).To(Equal(staged.Spec.PolicyTypes))
		})

		It("should clear ResourceVersion and UID from staged policy", func() {
			staged := v3.StagedKubernetesNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "test-policy",
					Namespace:       "test",
					ResourceVersion: "12345",
					UID:             "abc-def-ghi",
				},
				Spec: v3.StagedKubernetesNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
				},
			}

			_, enforced := ConvertStagedKubernetesPolicyToK8SEnforced(&staged)

			Expect(enforced.ResourceVersion).To(BeEmpty())
			Expect(enforced.UID).To(BeEmpty())
		})
	})
})
