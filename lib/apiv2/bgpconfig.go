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

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

const (
	KindBGPConfiguration     = "BGPConfiguration"
	KindBGPConfigurationList = "BGPConfigurationList"
)

// BGPConfiguration contains the configuration for any BGP routing.
type BGPConfiguration struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the BGPConfiguration.
	Spec BGPConfigurationSpec `json:"spec,omitempty"`
}

// TODO: Add validation on LogSeverityScreen for valid values
// BGPConfigurationSpec contains the values of the BGP configuration.
type BGPConfigurationSpec struct {
	LogSeverityScreen     string                `json:"logSeverityScreen,omitempty" validate:"omitempty"`
	NodeToNodeMeshEnabled *bool                 `json:"nodeToNodeMeshEnabled,omitempty" validate:"omitempty"`
	DefaultNodeASNumber   *numorstring.ASNumber `json:"defaultNodeASNumber,omitempty" validate:"omitempty"`
}

// BGPConfigurationList contains a list of BGPConfiguration resources.
type BGPConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []BGPConfiguration `json:"items"`
}

// New BGPConfiguration creates a new (zeroed) BGPConfiguration struct with the TypeMetadata
// initialized to the current version.
func NewBGPConfiguration() *BGPConfiguration {
	return &BGPConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindBGPConfiguration,
			APIVersion: GroupVersionCurrent,
		},
	}
}

// NewBGPConfigurationList creates a new 9zeroed) BGPConfigurationList struct with the TypeMetadata
// initialized to the current version.
func NewBGPConfigurationLits() *BGPConfigurationList {
	return &BGPConfigurationList{
		TypeMeta: metav1.TypeMeta{
			Kind:       KindBGPConfigurationList,
			APIVersion: GroupVersionCurrent,
		},
	}
}
