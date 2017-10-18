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

package v2

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	KindGlobalNetworkPolicy     = "GlobalNetworkPolicy"
	KindGlobalNetworkPolicyList = "GlobalNetworkPolicyList"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GlobalNetworkPolicy contains information about a security Policy resource.  This contains a set of
// security rules to apply.  Security policies allow a selector-based security model which can override
// the security profiles directly referenced by an endpoint.
//
// Each policy must do one of the following:
//
//  	- Match the packet and apply an “allow” action; this immediately accepts the packet, skipping
//        all further policies and profiles. This is not recommended in general, because it prevents
//        further policy from being executed.
// 	- Match the packet and apply a “deny” action; this drops the packet immediately, skipping all
//        further policy and profiles.
// 	- Fail to match the packet; in which case the packet proceeds to the next policy. If there
// 	  are no more policies then the packet is dropped.
//
// Calico implements the security policy for each endpoint individually and only the policies that
// have matching selectors are implemented. This ensures that the number of rules that actually need
// to be inserted into the kernel is proportional to the number of local endpoints rather than the
// total amount of policy.
//
// GlobalNetworkPolicy is globally-scoped (i.e. not Namespaced).
type GlobalNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the Policy.
	Spec PolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GlobalNetworkPolicyList contains a list of GlobalNetworkPolicy resources.
type GlobalNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []GlobalNetworkPolicy `json:"items"`
}

// NewGlobalNetworkPolicy creates a new (zeroed) GlobalNetworkPolicy struct with the TypeMetadata initialised to the current
// version.
func NewGlobalNetworkPolicy() *GlobalNetworkPolicy {
	return &GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindGlobalNetworkPolicy,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// NewGlobalNetworkPolicyList creates a new (zeroed) GlobalNetworkPolicyList struct with the TypeMetadata initialised to the current
// version.
func NewGlobalNetworkPolicyList() *GlobalNetworkPolicyList {
	return &GlobalNetworkPolicyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindGlobalNetworkPolicyList,
			APIVersion: GroupVersionCurrent,
		},
	}
}
