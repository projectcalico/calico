// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

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

package v3_test

import (
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// stagedkubernetesnpExtraFields is the set of fields that should be in StagedKubernetesNetworkPolicy but not
	// K8s NetworkPolicy.
	stagedkubernetesnpExtraFields = From("StagedAction")

	// k8snpExtraFields is the set of fields that should be in K8s NetworkPolicy but not
	// StagedKubernetesNetworkPolicy.
	k8snpExtraFields = From()
)

// These tests verify that the StagedKubernetesNetworkPolicySpec struct and the K8s NetworkPolicySpec struct
// are kept in sync.
var _ = Describe("StagedKubernetesNetworkPolicySpec", func() {
	var sknpFieldsByName map[string]reflect.StructField
	var k8snpFieldsByName map[string]reflect.StructField

	BeforeEach(func() {
		sknpFieldsByName = fieldsByName(apiv3.StagedKubernetesNetworkPolicySpec{})
		k8snpFieldsByName = fieldsByName(networkingv1.NetworkPolicySpec{})
	})

	It("and K8s NetworkPolicySpec shared fields should have the same tags", func() {
		for n, f := range sknpFieldsByName {
			if gf, ok := k8snpFieldsByName[n]; ok {
				if f.Name != "PodSelector" { //podSelector tags are not same. podSelector is not required for staged policy
					Expect(f.Tag).To(Equal(gf.Tag), "Field "+n+" had different tag")
				}
			}
		}
	})

	It("and K8s NetworkPolicySpec shared fields should have the same types", func() {
		for n, f := range sknpFieldsByName {
			if gf, ok := k8snpFieldsByName[n]; ok {
				Expect(f.Type).To(Equal(gf.Type), "Field "+n+" had different type")
			}
		}
	})

	It("should not have any unexpected fields that K8s NetworkPolicySpec doesn't have", func() {
		for n := range sknpFieldsByName {
			if stagedkubernetesnpExtraFields.Contains(n) {
				continue
			}
			Expect(k8snpFieldsByName).To(HaveKey(n))
		}
	})

	It("should contain all expected fields of K8s NetworkPolicySpec", func() {
		for n := range k8snpFieldsByName {
			if k8snpExtraFields.Contains(n) {
				continue
			}
			Expect(sknpFieldsByName).To(HaveKey(n))
		}
	})

	It("should be able to properly convert from staged to enforced", func() {
		staged := apiv3.StagedKubernetesNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "zinedine",
				Namespace: "zidane",
			},
			Spec: apiv3.StagedKubernetesNetworkPolicySpec{
				StagedAction: apiv3.StagedActionSet,
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
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

		stagedAction, enforced := apiv3.ConvertStagedKubernetesPolicyToK8SEnforced(&staged)

		//TODO: mgianluc all common fields should be checked, though following is good enough coverage
		Expect(stagedAction).To(Equal(staged.Spec.StagedAction))
		Expect(enforced.Spec.Ingress).To(Equal(staged.Spec.Ingress))
		Expect(enforced.Spec.PodSelector).To(Equal(staged.Spec.PodSelector))
		Expect(enforced.Namespace).To(Equal(staged.Namespace))
		Expect(enforced.Name).To(Equal(staged.Name))
	})
})
