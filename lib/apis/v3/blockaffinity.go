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

package v3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KindBlockAffinity     = "BlockAffinity"
	KindBlockAffinityList = "BlockAffinityList"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BGPPeer contains information about a BGPPeer resource that is a peer of a Calico
// compute node.
type BlockAffinity struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the BGPPeer.
	Spec BlockAffinitySpec `json:"spec,omitempty"`
}

// BGPPeerSpec contains the specification for a BGPPeer resource.
type BlockAffinitySpec struct {
	State string `json:"state"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BGPPeerList contains a list of BGPPeer resources.
type BlockAffinityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []BlockAffinity `json:"items"`
}

// NewBGPPeer creates a new (zeroed) BGPPeer struct with the TypeMetadata initialised to the current
// version.
func NewBlockAffinity() *BlockAffinity {
	return &BlockAffinity{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindBlockAffinity,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// NewBGPPeerList creates a new (zeroed) BGPPeerList struct with the TypeMetadata initialised to the current
// version.
func NewBlockAffinityList() *BlockAffinityList {
	return &BlockAffinityList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindBlockAffinityList,
			APIVersion: GroupVersionCurrent,
		},
	}
}
