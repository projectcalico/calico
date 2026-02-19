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
package defaults_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/defaults"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Default", func() {
	Context("for unsupported types", func() {
		It("should return an error", func() {
			obj := &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
			_, err := defaults.Default(obj)
			Expect(err).To(HaveOccurred())
		})
	})

	// policyTypeTests defines shared test cases for types/policyTypes defaulting.
	// Each test case is {description, ingressRules, egressRules, expectedTypes}.
	type policyTypeTest struct {
		description   string
		ingress       []v3.Rule
		egress        []v3.Rule
		expectedTypes []v3.PolicyType
	}

	policyTypeTests := []policyTypeTest{
		{
			description:   "no rules - defaults to Ingress",
			expectedTypes: []v3.PolicyType{v3.PolicyTypeIngress},
		},
		{
			description:   "ingress only - defaults to Ingress",
			ingress:       []v3.Rule{{}},
			expectedTypes: []v3.PolicyType{v3.PolicyTypeIngress},
		},
		{
			description:   "egress only - defaults to Egress",
			egress:        []v3.Rule{{}},
			expectedTypes: []v3.PolicyType{v3.PolicyTypeEgress},
		},
		{
			description:   "both ingress and egress - defaults to both",
			ingress:       []v3.Rule{{}},
			egress:        []v3.Rule{{}},
			expectedTypes: []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
		},
	}

	// tierLabelTests defines shared test cases for tier label defaulting.
	type tierLabelTest struct {
		description   string
		tier          string
		existingLabel string
		expectedLabel string
		expectChanged bool
	}

	tierLabelTests := []tierLabelTest{
		{
			description:   "empty tier defaults label to 'default'",
			tier:          "",
			expectedLabel: "default",
			expectChanged: true,
		},
		{
			description:   "explicit tier sets label",
			tier:          "net-sec",
			expectedLabel: "net-sec",
			expectChanged: true,
		},
		{
			description:   "label already correct returns no change",
			tier:          "net-sec",
			existingLabel: "net-sec",
			expectedLabel: "net-sec",
			expectChanged: false,
		},
		{
			description:   "label already 'default' with empty tier returns no change",
			tier:          "",
			existingLabel: "default",
			expectedLabel: "default",
			expectChanged: false,
		},
	}

	Context("NetworkPolicy", func() {
		for _, tt := range policyTypeTests {
			tt := tt
			It("types: "+tt.description, func() {
				p := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test"},
					Spec: v3.NetworkPolicySpec{
						Ingress: tt.ingress,
						Egress:  tt.egress,
					},
				}
				changed, err := defaults.Default(p)
				Expect(err).NotTo(HaveOccurred())
				Expect(changed).To(BeTrue())
				Expect(p.Spec.Types).To(Equal(tt.expectedTypes))
			})
		}

		It("types: already set - not overwritten", func() {
			p := &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: v3.NetworkPolicySpec{
					Types: []v3.PolicyType{v3.PolicyTypeEgress},
				},
			}
			changed, err := defaults.Default(p)
			Expect(err).NotTo(HaveOccurred())
			// Still changed because tier label is set.
			Expect(p.Spec.Types).To(Equal([]v3.PolicyType{v3.PolicyTypeEgress}))
			_ = changed
		})

		for _, tt := range tierLabelTests {
			tt := tt
			It("tier label: "+tt.description, func() {
				p := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test"},
					Spec: v3.NetworkPolicySpec{
						Tier:  tt.tier,
						Types: []v3.PolicyType{v3.PolicyTypeIngress}, // pre-set to isolate tier label change
					},
				}
				if tt.existingLabel != "" {
					p.Labels = map[string]string{v3.LabelTier: tt.existingLabel}
				}
				changed, err := defaults.Default(p)
				Expect(err).NotTo(HaveOccurred())
				Expect(changed).To(Equal(tt.expectChanged))
				Expect(p.Labels[v3.LabelTier]).To(Equal(tt.expectedLabel))
			})
		}
	})

	Context("GlobalNetworkPolicy", func() {
		for _, tt := range policyTypeTests {
			tt := tt
			It("types: "+tt.description, func() {
				p := &v3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test"},
					Spec: v3.GlobalNetworkPolicySpec{
						Ingress: tt.ingress,
						Egress:  tt.egress,
					},
				}
				changed, err := defaults.Default(p)
				Expect(err).NotTo(HaveOccurred())
				Expect(changed).To(BeTrue())
				Expect(p.Spec.Types).To(Equal(tt.expectedTypes))
			})
		}

		for _, tt := range tierLabelTests {
			tt := tt
			It("tier label: "+tt.description, func() {
				p := &v3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test"},
					Spec: v3.GlobalNetworkPolicySpec{
						Tier:  tt.tier,
						Types: []v3.PolicyType{v3.PolicyTypeIngress},
					},
				}
				if tt.existingLabel != "" {
					p.Labels = map[string]string{v3.LabelTier: tt.existingLabel}
				}
				changed, err := defaults.Default(p)
				Expect(err).NotTo(HaveOccurred())
				Expect(changed).To(Equal(tt.expectChanged))
				Expect(p.Labels[v3.LabelTier]).To(Equal(tt.expectedLabel))
			})
		}
	})

	Context("StagedNetworkPolicy", func() {
		for _, tt := range policyTypeTests {
			tt := tt
			It("types: "+tt.description, func() {
				p := &v3.StagedNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test"},
					Spec: v3.StagedNetworkPolicySpec{
						Ingress: tt.ingress,
						Egress:  tt.egress,
					},
				}
				changed, err := defaults.Default(p)
				Expect(err).NotTo(HaveOccurred())
				Expect(changed).To(BeTrue())
				Expect(p.Spec.Types).To(Equal(tt.expectedTypes))
			})
		}

		for _, tt := range tierLabelTests {
			tt := tt
			It("tier label: "+tt.description, func() {
				p := &v3.StagedNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test"},
					Spec: v3.StagedNetworkPolicySpec{
						Tier:  tt.tier,
						Types: []v3.PolicyType{v3.PolicyTypeIngress},
					},
				}
				if tt.existingLabel != "" {
					p.Labels = map[string]string{v3.LabelTier: tt.existingLabel}
				}
				changed, err := defaults.Default(p)
				Expect(err).NotTo(HaveOccurred())
				Expect(changed).To(Equal(tt.expectChanged))
				Expect(p.Labels[v3.LabelTier]).To(Equal(tt.expectedLabel))
			})
		}
	})

	Context("StagedGlobalNetworkPolicy", func() {
		for _, tt := range policyTypeTests {
			tt := tt
			It("types: "+tt.description, func() {
				p := &v3.StagedGlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test"},
					Spec: v3.StagedGlobalNetworkPolicySpec{
						Ingress: tt.ingress,
						Egress:  tt.egress,
					},
				}
				changed, err := defaults.Default(p)
				Expect(err).NotTo(HaveOccurred())
				Expect(changed).To(BeTrue())
				Expect(p.Spec.Types).To(Equal(tt.expectedTypes))
			})
		}

		for _, tt := range tierLabelTests {
			tt := tt
			It("tier label: "+tt.description, func() {
				p := &v3.StagedGlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test"},
					Spec: v3.StagedGlobalNetworkPolicySpec{
						Tier:  tt.tier,
						Types: []v3.PolicyType{v3.PolicyTypeIngress},
					},
				}
				if tt.existingLabel != "" {
					p.Labels = map[string]string{v3.LabelTier: tt.existingLabel}
				}
				changed, err := defaults.Default(p)
				Expect(err).NotTo(HaveOccurred())
				Expect(changed).To(Equal(tt.expectChanged))
				Expect(p.Labels[v3.LabelTier]).To(Equal(tt.expectedLabel))
			})
		}
	})
})
