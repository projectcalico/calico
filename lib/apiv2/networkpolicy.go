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

package apiv2

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	KindNetworkPolicy     = "NetworkPolicy"
	KindNetworkPolicyList = "NetworkPolicyList"
)

// NetworkPolicy is the Namespaced-equivalent of the GlobalNetworkPolicy.
type NetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the Policy.
	Spec PolicySpec `json:"spec,omitempty"`
}

// NetworkPolicyList contains a list of NetworkPolicy resources.
type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []NetworkPolicy `json:"items"`
}

// NewNetworkPolicy creates a new (zeroed) NetworkPolicy struct with the TypeMetadata initialised to the current
// version.
func NewNetworkPolicy() *NetworkPolicy {
	return &NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindNetworkPolicy,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// NewNetworkPolicyList creates a new (zeroed) NetworkPolicyList struct with the TypeMetadata initialised to the current
// version.
func NewNetworkPolicyList() *NetworkPolicyList {
	return &NetworkPolicyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindNetworkPolicyList,
			APIVersion: GroupVersionCurrent,
		},
	}
}
