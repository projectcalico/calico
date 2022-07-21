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
	KindIPAMConfig     = "IPAMConfig"
	KindIPAMConfigList = "IPAMConfigList"
)

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPAMConfigList contains a list of IPAMConfig resources.
type IPAMConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Items []IPAMConfig `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPAMConfig contains information about a block for IP address assignment.
type IPAMConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	Spec IPAMConfigSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

// IPAMConfigSpec contains the specification for an IPPool resource.
type IPAMConfigSpec struct {
	// When StrictAffinity is true, borrowing IP addresses is not allowed.
	StrictAffinity bool `json:"strictAffinity" validate:"required"`

	// MaxBlocksPerHost, if non-zero, is the max number of blocks that can be
	// affine to each host.
	MaxBlocksPerHost int `json:"maxBlocksPerHost,omitempty"`
}

// NewIPAMConfig creates a new (zeroed) IPAMConfig struct with the TypeMetadata initialised to the current
// version.
func NewIPAMConfig() *IPAMConfig {
	return &IPAMConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindIPPool,
			APIVersion: GroupVersionCurrent,
		},
	}
}
