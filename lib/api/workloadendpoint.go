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
	. "github.com/tigera/libcalico-go/lib/net"
)

type WorkloadEndpointMetadata struct {
	ObjectMetadata
	Name           string            `json:"name,omitempty" validate:"omitempty,name"`
	WorkloadID     string            `json:"workloadID,omitempty" valid:"omitempty,name"`
	OrchestratorID string            `json:"orchestratorID,omitempty" valid:"omitempty,name"`
	Hostname       string            `json:"hostname,omitempty" valid:"omitempty,name"`
	Labels         map[string]string `json:"labels,omitempty" validate:"omitempty,labels"`
}

type WorkloadEndpointSpec struct {
	IPNetworks    []IPNet  `json:"ipNetworks,omitempty" validate:"omitempty"`
	Profiles      []string `json:"profiles,omitempty" validate:"omitempty,dive,name"`
	InterfaceName string   `json:"interfaceName,omitempty" validate:"omitempty,interface"`
	MAC           MAC      `json:"mac,omitempty" validate:"omitempty"`
}

type WorkloadEndpoint struct {
	TypeMetadata
	Metadata WorkloadEndpointMetadata `json:"metadata,omitempty"`
	Spec     WorkloadEndpointSpec     `json:"spec,omitempty"`
}

func NewWorkloadEndpoint() *WorkloadEndpoint {
	return &WorkloadEndpoint{TypeMetadata: TypeMetadata{Kind: "workloadEndpoint", APIVersion: "v1"}}
}

type WorkloadEndpointList struct {
	TypeMetadata
	Metadata ListMetadata       `json:"metadata,omitempty"`
	Items    []WorkloadEndpoint `json:"items" validate:"dive"`
}

func NewWorkloadEndpointList() *WorkloadEndpointList {
	return &WorkloadEndpointList{TypeMetadata: TypeMetadata{Kind: "workloadEndpointList", APIVersion: "v1"}}
}
