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

package v3

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	KindTier     = "Tier"
	KindTierList = "TierList"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Tier contains a set of policies that are applied to packets.  Multiple tiers may
// be created and each tier is applied in the order specified in the tier specification.
// Tier is globally-scoped (i.e. not Namespaced).
type Tier struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the Tier.
	Spec TierSpec `json:"spec,omitempty"`
}

const (
	DefaultTierOrder = float64(1_000_000) // 1 Million
)

// TierSpec contains the specification for a security policy tier resource.
type TierSpec struct {
	// Order is an optional field that specifies the order in which the tier is applied.
	// Tiers with higher "order" are applied after those with lower order.  If the order
	// is omitted, it may be considered to be "infinite" - i.e. the tier will be applied
	// last.  Tiers with identical order will be applied in alphanumerical order based
	// on the Tier "Name".
	Order *float64 `json:"order,omitempty"`
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TierList contains a list of Tier resources.
type TierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Tier `json:"items"`
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
