// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package api

import (
	. "github.com/tigera/libcalico-go/lib/api/unversioned"
	. "github.com/tigera/libcalico-go/lib/common"
)

type HostEndpointMetadata struct {
	ObjectMetadata
	Hostname string            `json:"hostname,omitempty" valid:"omitempty,hostname"`
	Labels   map[string]string `json:"labels,omitempty" validate:"omitempty,labels"`
}

type HostEndpointSpec struct {
	InterfaceName string   `json:"interfaceName,omitempty" validate:"omitempty,interface"`
	ExpectedIPs   []IP     `json:"expectedIPs,omitempty" validate:"omitempty,dive,ip"`
	Profiles      []string `json:"profiles,omitempty" validate:"omitempty,dive,name"`
}

type HostEndpoint struct {
	TypeMetadata
	Metadata HostEndpointMetadata `json:"metadata,omitempty"`
	Spec     HostEndpointSpec     `json:"spec,omitempty"`
}

func NewHostEndpoint() *HostEndpoint {
	return &HostEndpoint{TypeMetadata: TypeMetadata{Kind: "hostEndpoint", APIVersion: "v1"}}
}

type HostEndpointList struct {
	TypeMetadata
	Metadata ListMetadata   `json:"metadata,omitempty"`
	Items    []HostEndpoint `json:"items" validate:"dive"`
}

func NewHostEndpointList() *HostEndpointList {
	return &HostEndpointList{TypeMetadata: TypeMetadata{Kind: "hostEndpointList", APIVersion: "v1"}}
}
