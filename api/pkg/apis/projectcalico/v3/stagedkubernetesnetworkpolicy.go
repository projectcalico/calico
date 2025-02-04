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

package v3

import (
	"github.com/jinzhu/copier"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindStagedKubernetesNetworkPolicy     = "StagedKubernetesNetworkPolicy"
	KindStagedKubernetesNetworkPolicyList = "StagedKubernetesNetworkPolicyList"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// StagedKubernetesNetworkPolicy is a staged GlobalNetworkPolicy.
type StagedKubernetesNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the Policy.
	Spec StagedKubernetesNetworkPolicySpec `json:"spec,omitempty"`
}

type StagedKubernetesNetworkPolicySpec struct {
	// The staged action. If this is omitted, the default is Set.
	StagedAction StagedAction `json:"stagedAction,omitempty" validate:"omitempty,stagedAction"`

	// Selects the pods to which this NetworkPolicy object applies. The array of
	// ingress rules is applied to any pods selected by this field. Multiple network
	// policies can select the same set of pods. In this case, the ingress rules for
	// each are combined additively. This field is NOT optional and follows standard
	// label selector semantics. An empty podSelector matches all pods in this
	// namespace.
	PodSelector metav1.LabelSelector `json:"podSelector,omitempty" protobuf:"bytes,1,opt,name=podSelector"`

	// List of ingress rules to be applied to the selected pods. Traffic is allowed to
	// a pod if there are no NetworkPolicies selecting the pod
	// (and cluster policy otherwise allows the traffic), OR if the traffic source is
	// the pod's local node, OR if the traffic matches at least one ingress rule
	// across all of the NetworkPolicy objects whose podSelector matches the pod. If
	// this field is empty then this NetworkPolicy does not allow any traffic (and serves
	// solely to ensure that the pods it selects are isolated by default)
	// +optional
	Ingress []networkingv1.NetworkPolicyIngressRule `json:"ingress,omitempty" protobuf:"bytes,2,rep,name=ingress"`

	// List of egress rules to be applied to the selected pods. Outgoing traffic is
	// allowed if there are no NetworkPolicies selecting the pod (and cluster policy
	// otherwise allows the traffic), OR if the traffic matches at least one egress rule
	// across all of the NetworkPolicy objects whose podSelector matches the pod. If
	// this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
	// solely to ensure that the pods it selects are isolated by default).
	// This field is beta-level in 1.8
	// +optional
	Egress []networkingv1.NetworkPolicyEgressRule `json:"egress,omitempty" protobuf:"bytes,3,rep,name=egress"`

	// List of rule types that the NetworkPolicy relates to.
	// Valid options are Ingress, Egress, or Ingress,Egress.
	// If this field is not specified, it will default based on the existence of Ingress or Egress rules;
	// policies that contain an Egress section are assumed to affect Egress, and all policies
	// (whether or not they contain an Ingress section) are assumed to affect Ingress.
	// If you want to write an egress-only policy, you must explicitly specify policyTypes [ "Egress" ].
	// Likewise, if you want to write a policy that specifies that no egress is allowed,
	// you must specify a policyTypes value that include "Egress" (since such a policy would not include
	// an Egress section and would otherwise default to just [ "Ingress" ]).
	// This field is beta-level in 1.8
	// +optional
	PolicyTypes []networkingv1.PolicyType `json:"policyTypes,omitempty" protobuf:"bytes,4,rep,name=policyTypes,casttype=PolicyType"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// StagedKubernetesNetworkPolicyList contains a list of StagedKubernetesNetworkPolicy resources.
type StagedKubernetesNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []StagedKubernetesNetworkPolicy `json:"items"`
}

// NewStagedKubernetesNetworkPolicy creates a new (zeroed) StagedKubernetesNetworkPolicy struct with the TypeMetadata initialised to the current
// version.
func NewStagedKubernetesNetworkPolicy() *StagedKubernetesNetworkPolicy {
	return &StagedKubernetesNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindStagedKubernetesNetworkPolicy,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// NewStagedKubernetesNetworkPolicyList creates a new (zeroed) StagedKubernetesNetworkPolicyList struct with the TypeMetadata initialised to the current
// version.
func NewStagedKubernetesNetworkPolicyList() *StagedKubernetesNetworkPolicyList {
	return &StagedKubernetesNetworkPolicyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindStagedKubernetesNetworkPolicyList,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// ConvertStagedKubernetesPolicyToK8SEnforced converts a StagedKubernetesNetworkPolicy into a StagedAction, networkingv1 NetworkPolicy pair
func ConvertStagedKubernetesPolicyToK8SEnforced(staged *StagedKubernetesNetworkPolicy) (StagedAction, *networkingv1.NetworkPolicy) {
	//Convert StagedKubernetesNetworkPolicy to networkingv1.NetworkPolicy
	enforced := networkingv1.NetworkPolicy{}
	_ = copier.Copy(&enforced.ObjectMeta, &staged.ObjectMeta)
	_ = copier.Copy(&enforced.Spec, &staged.Spec)
	enforced.TypeMeta = metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}
	return staged.Spec.StagedAction, &enforced
}
