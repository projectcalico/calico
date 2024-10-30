// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.

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
	"fmt"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
)

// Tier contains the details of a security policy tier resource.  A tier contains a set of
// policies that are applied to packets. Multiple tiers may be created and each tier is applied
// in the order specified in the tier specification.
//
// See Policy for more information.
type Tier struct {
	unversioned.TypeMetadata
	Metadata TierMetadata `json:"metadata,omitempty"`
	Spec     TierSpec     `json:"spec,omitempty"`
}

func (t Tier) GetResourceMetadata() unversioned.ResourceMetadata {
	return t.Metadata
}

// String() returns the human-readable string representation of a Tier instance
// which is defined by its Name.
func (t Tier) String() string {
	return fmt.Sprintf("Tier(Name=%s)", t.Metadata.Name)
}

// TierMetadata contains the metadata for a security policy Tier.
type TierMetadata struct {
	unversioned.ObjectMetadata
	Name string `json:"name,omitempty" validate:"omitempty,name"`
}

// TierSpec contains the specification for a security policy Tier.
type TierSpec struct {
	// Order is an optional field that specifies the order in which the tier is applied.
	// Tiers with higher "order" are applied after those with lower order.  If the order
	// is omitted, it may be considered to be "infinite" - i.e. the tier will be applied
	// last.  Tiers with identical order will be applied in alphanumerical order based
	// on the Tier "Name".
	Order *float64 `json:"order,omitempty"`
}

// NewTier creates a new (zeroed) Tier struct with the TypeMetadata initialised to the current
// version.
func NewTier() *Tier {
	return &Tier{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       "tier",
			APIVersion: unversioned.VersionCurrent,
		},
	}
}

// A TierList contains a list of tier resources.  List types are returned from List()
// enumerations in the client interface.
type TierList struct {
	unversioned.TypeMetadata
	Metadata unversioned.ListMetadata `json:"metadata,omitempty"`
	Items    []Tier                   `json:"items" validate:"dive"`
}

// NewTier creates a new (zeroed) Tier struct with the TypeMetadata initialised to the current
// version.
func NewTierList() *TierList {
	return &TierList{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       "tierList",
			APIVersion: unversioned.VersionCurrent,
		},
	}
}
