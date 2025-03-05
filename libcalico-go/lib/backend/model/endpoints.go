// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package model

import "github.com/projectcalico/api/pkg/lib/numorstring"

// EndpointKey gives a shared interface to workload and host endpoint keys.
type EndpointKey interface {
	Key

	// WorkloadOrHostEndpointKey is a no-op marker method for workload/host endpoint keys.
	WorkloadOrHostEndpointKey()

	// Host returns the name of the host that this endpoint is on.
	Host() string
}

// Endpoint is an interface that represents the common function between
// workload and host endpoints.
type Endpoint interface {
	// WorkloadOrHostEndpoint is a no-op marker method for workload/host endpoints.
	WorkloadOrHostEndpoint()

	GetLabels() map[string]string
	GetProfileIDs() []string
	GetPorts() []EndpointPort
}

type EndpointPort struct {
	Name     string               `json:"name" validate:"name"`
	Protocol numorstring.Protocol `json:"protocol"`
	Port     uint16               `json:"port" validate:"gt=0"`
}
