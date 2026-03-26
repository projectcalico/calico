// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	KindTier     = "Tier"
	KindTierList = "TierList"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Order",type="integer",JSONPath=".spec.order",description="Order in which the tier is applied"
// +kubebuilder:printcolumn:name="DefaultAction",type="string",JSONPath=".spec.defaultAction",description="Default action for the tier"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].reason",description="Current status of the tier"

// Tier contains a set of policies that are applied to packets.  Multiple tiers may
// be created and each tier is applied in the order specified in the tier specification.
// Tier is globally-scoped (i.e. not Namespaced).
//
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'kube-admin' ? (has(self.spec.defaultAction) && self.spec.defaultAction == 'Pass') : true", message="The 'kube-admin' tier must have default action 'Pass'",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'kube-baseline' ? (has(self.spec.defaultAction) && self.spec.defaultAction == 'Pass') : true", message="The 'kube-baseline' tier must have default action 'Pass'",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default' ? (has(self.spec.defaultAction) && self.spec.defaultAction == 'Deny') : true", message="The 'default' tier must have default action 'Deny'",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name != 'default' || (has(self.spec.order) && self.spec.order == 1000000.0)",message="default tier order must be 1000000",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name != 'kube-admin' || (has(self.spec.order) && self.spec.order == 1000.0)",message="kube-admin tier order must be 1000",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name != 'kube-baseline' || (has(self.spec.order) && self.spec.order == 10000000.0)",message="kube-baseline tier order must be 10000000",reason=FieldValueInvalid
type Tier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`
	Spec              TierSpec   `json:"spec" protobuf:"bytes,2,rep,name=spec"`
	Status            TierStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

const (
	KubeAdminTierOrder    = float64(1_000)      // 1K
	DefaultTierOrder      = float64(1_000_000)  // 1Million
	KubeBaselineTierOrder = float64(10_000_000) // 10Million

	// TierFinalizer is set on tiers to ensure policies are cleaned up before the tier is deleted.
	TierFinalizer = "projectcalico.org/tier-controller"
)

// TierStatus contains the status of a Tier resource.
type TierStatus struct {
	// Conditions represents the latest observed set of conditions for the resource. A tier with a
	// "Ready" condition set to "True" is operating as expected.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// TierSpec contains the specification for a security policy tier resource.
type TierSpec struct {
	// Order is an optional field that specifies the order in which the tier is applied.
	// Tiers with higher "order" are applied after those with lower order.  If the order
	// is omitted, it may be considered to be "infinite" - i.e. the tier will be applied
	// last.  Tiers with identical order will be applied in alphanumerical order based
	// on the Tier "Name".
	Order *float64 `json:"order,omitempty" protobuf:"bytes,1,opt,name=order"`
	// DefaultAction specifies the action applied to workloads selected by a policy in the tier,
	// but not rule matched the workload's traffic.
	// [Default: Deny]
	// +kubebuilder:default=Deny
	// +kubebuilder:validation:Enum=Pass;Deny
	DefaultAction *Action `json:"defaultAction,omitempty" validate:"omitempty,oneof=Deny Pass"`
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TierList contains a list of Tier resources.
type TierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`
	Items           []Tier `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// NewTier creates a new (zeroed) Tier struct with the TypeMetadata initialised to the current
// version.
func NewTier() *Tier {
	return &Tier{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindTier,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// NewTierList creates a new (zeroed) TierList struct with the TypeMetadata initialised to the current
// version.
func NewTierList() *TierList {
	return &TierList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindTierList,
			APIVersion: GroupVersionCurrent,
		},
	}
}
