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
	"gopkg.in/go-playground/validator.v8"
)

type PoolMetadata struct {
	ObjectMetadata
	CIDR IPNet `json:"cidr"`
}

type PoolSpec struct {
	IPIP        bool `json:"ipip,omitempty"`
	NATOutgoing bool `json:"nat-outgoing"`
	Ipam        bool `json:"ipam"`
	Disabled    bool `json:"disabled"`
}

type Pool struct {
	TypeMetadata
	Metadata PoolMetadata `json:"metadata,omitempty"`
	Spec     PoolSpec     `json:"spec,omitempty"`
}

func NewPool() *Pool {
	return &Pool{TypeMetadata: TypeMetadata{Kind: "pool", APIVersion: "v1"}}
}

type PoolList struct {
	TypeMetadata
	Metadata ListMetadata `json:"metadata,omitempty"`
	Items    []Pool       `json:"items" validate:"dive"`
}

func NewPoolList() *PoolList {
	return &PoolList{TypeMetadata: TypeMetadata{Kind: "poolList", APIVersion: "v1"}}
}

// Register v1 structure validators to validate cross-field dependencies in any of the
// required structures.
func init() {
	RegisterStructValidator(validatePool, Pool{})
}

func validatePool(v *validator.Validate, structLevel *validator.StructLevel) {
	// pool := structLevel.CurrentStruct.Interface().(Pool)
	// TODO: Ensure that the size of the pool is valid?
}
