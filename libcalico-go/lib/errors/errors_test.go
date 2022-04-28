// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package errors_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var _ = DescribeTable(
	"error types",
	func(err error, expected string) {
		Expect(err.Error()).To(Equal(expected))
	},
	Entry(
		"Operation not supported without reason",
		errors.ErrorOperationNotSupported{
			Operation: "create",
			Identifier: model.ResourceKey{
				Kind:      v3.KindNetworkPolicy,
				Namespace: "namespace1",
				Name:      "knp.default.k8spolicy",
			},
		},
		"operation create is not supported on NetworkPolicy(namespace1/knp.default.k8spolicy)",
	),
	Entry(
		"Operation not supported with reason",
		errors.ErrorOperationNotSupported{
			Operation:  "apply",
			Identifier: "foo.bar.baz",
			Reason:     "cannot mix foobar with baz",
		},
		"operation apply is not supported on foo.bar.baz: cannot mix foobar with baz",
	),
	Entry(
		"Policy conversion with no rules",
		errors.ErrorPolicyConversion{
			PolicyName: "test-policy1",
			Rules:      []errors.ErrorPolicyConversionRule{},
		},
		"policy: test-policy1: unknown policy conversion error",
	),
	Entry(
		"Policy conversion with one rule and no reason",
		errors.ErrorPolicyConversion{
			PolicyName: "test-policy2",
			Rules: []errors.ErrorPolicyConversionRule{
				{
					EgressRule: &networkingv1.NetworkPolicyEgressRule{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: nil,
								Port:     &intstr.IntOrString{Type: 0, IntVal: 80, StrVal: ""},
								EndPort:  nil,
							},
							{
								Protocol: nil,
								Port:     &intstr.IntOrString{Type: 1, IntVal: 0, StrVal: "-22:-3"},
								EndPort:  nil,
							},
						},
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k2": "v2", "k": "v"},
									MatchExpressions: nil,
								},
								NamespaceSelector: nil,
								IPBlock:           nil,
							},
						},
					},
					IngressRule: nil,
				},
			},
		},
		"policy: test-policy2: error with rule &NetworkPolicyEgressRule{Ports:[]NetworkPolicyPort{NetworkPolicyPort{Protocol:nil,Port:80,EndPort:nil,},NetworkPolicyPort{Protocol:nil,Port:-22:-3,EndPort:nil,},},To:[]NetworkPolicyPeer{NetworkPolicyPeer{PodSelector:&v1.LabelSelector{MatchLabels:map[string]string{k: v,k2: v2,},MatchExpressions:[]LabelSelectorRequirement{},},NamespaceSelector:nil,IPBlock:nil,},},}",
	),
	Entry(
		"Policy conversion with multiple rules and reasons",
		errors.ErrorPolicyConversion{
			PolicyName: "test-policy3",
			Rules: []errors.ErrorPolicyConversionRule{
				{
					EgressRule: &networkingv1.NetworkPolicyEgressRule{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: nil,
								Port:     &intstr.IntOrString{Type: 0, IntVal: 80, StrVal: ""},
								EndPort:  nil,
							},
							{
								Protocol: nil,
								Port:     &intstr.IntOrString{Type: 1, IntVal: 0, StrVal: "-22:-3"},
								EndPort:  nil,
							},
						},
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k2": "v2", "k": "v"},
									MatchExpressions: nil,
								},
								NamespaceSelector: nil,
								IPBlock:           nil,
							},
						},
					},
					Reason: "reason1",
				},
				{
					IngressRule: &networkingv1.NetworkPolicyIngressRule{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: nil,
								Port:     &intstr.IntOrString{Type: 0, IntVal: 80, StrVal: ""},
								EndPort:  nil,
							},
							{
								Protocol: nil,
								Port:     &intstr.IntOrString{Type: 1, IntVal: 0, StrVal: "-50:-1"},
								EndPort:  nil,
							},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels:      map[string]string{"k2": "v2", "k": "v"},
									MatchExpressions: nil,
								},
								NamespaceSelector: nil,
								IPBlock:           nil,
							},
						},
					},
					Reason: "reason2",
				},
				{
					Reason: "reason3",
				},
			},
		},
		"policy: test-policy3: error with the following rules:\n-  &NetworkPolicyEgressRule{Ports:[]NetworkPolicyPort{NetworkPolicyPort{Protocol:nil,Port:80,EndPort:nil,},NetworkPolicyPort{Protocol:nil,Port:-22:-3,EndPort:nil,},},To:[]NetworkPolicyPeer{NetworkPolicyPeer{PodSelector:&v1.LabelSelector{MatchLabels:map[string]string{k: v,k2: v2,},MatchExpressions:[]LabelSelectorRequirement{},},NamespaceSelector:nil,IPBlock:nil,},},} (reason1)\n-  &NetworkPolicyIngressRule{Ports:[]NetworkPolicyPort{NetworkPolicyPort{Protocol:nil,Port:80,EndPort:nil,},NetworkPolicyPort{Protocol:nil,Port:-50:-1,EndPort:nil,},},From:[]NetworkPolicyPeer{NetworkPolicyPeer{PodSelector:&v1.LabelSelector{MatchLabels:map[string]string{k: v,k2: v2,},MatchExpressions:[]LabelSelectorRequirement{},},NamespaceSelector:nil,IPBlock:nil,},},} (reason2)\n-  unknown rule (reason3)\n",
	),
)
