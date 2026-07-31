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

package v1

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// +k8s:openapi-gen=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'kube-admin' ? (has(self.spec.defaultAction) && self.spec.defaultAction == 'Pass') : true", message="The 'kube-admin' tier must have default action 'Pass'",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'kube-baseline' ? (has(self.spec.defaultAction) && self.spec.defaultAction == 'Pass') : true", message="The 'kube-baseline' tier must have default action 'Pass'",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default' ? (has(self.spec.defaultAction) && self.spec.defaultAction == 'Deny') : true", message="The 'default' tier must have default action 'Deny'",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name != 'default' || (has(self.spec.order) && self.spec.order == 1000000.0)",message="default tier order must be 1000000",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name != 'kube-admin' || (has(self.spec.order) && self.spec.order == 1000.0)",message="kube-admin tier order must be 1000",reason=FieldValueInvalid
// +kubebuilder:validation:XValidation:rule="self.metadata.name != 'kube-baseline' || (has(self.spec.order) && self.spec.order == 10000000.0)",message="kube-baseline tier order must be 10000000",reason=FieldValueInvalid
// +kubebuilder:subresource:status
type Tier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              v3.TierSpec   `json:"spec"`
	Status            v3.TierStatus `json:"status,omitempty"`
}
