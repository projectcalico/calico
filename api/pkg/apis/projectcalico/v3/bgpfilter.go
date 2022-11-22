// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindBGPFilter     = "BGPFilter"
	KindBGPFilterList = "BGPFilterList"
)

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BGPFilterList is a list of BGPFilter resources.
type BGPFilterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []BGPFilter `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type BGPFilter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec BGPFilterSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

// BGPFilterSpec contains the filter rules of the BGP Filter.
type BGPFilterSpec struct {
	// The ordered set of BGPFilter rules acting on exporting routes to a peer.
	Export []BGPFilterRule `json:"export,omitempty" validate:"omitempty"`

	// The ordered set of BGPFilter rules acting on importing routes from a peer.
	Import []BGPFilterRule `json:"import,omitempty" validate:"omitempty"`
}

// BGPFilterRule defines BGP filter rule consisting a single IP CIDR block and an filter action on this CIDR.
type BGPFilterRule struct {
	CIDR string `json:"cidr,omitempty" validate:"required,net"`

	Action BGPFilterAction `json:"action" validate:"required"`
}

type BGPFilterAction string

const (
	Accept BGPFilterAction = "Accept"
	Reject                 = "Reject"
)

// New BGPFilter creates a new (zeroed) BGPFilter struct with the TypeMetadata
// initialized to the current version.
func NewBGPFilter() *BGPFilter {
	return &BGPFilter{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindBGPFilter,
			APIVersion: GroupVersionCurrent,
		},
	}
}
