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
	// Contains configuration for ipip tunneling
	// for this pool. If not specified, then ipip
	// tunneling is disabled for this pool.
	IPIP *IPIPConfiguration `json:"ipip,omitempty"`

	// When nat-outgoing is true, packets sent from Calico networked
	// containers in this pool to destinations outside of this pool
	// will be masqueraded.
	NATOutgoing bool `json:"nat-outgoing,omitempty"`

	// When disabled is true, Calico IPAM will not assign
	// addreses from this pool.
	Disabled bool `json:"disabled,omitempty"`
}

type IPIPConfiguration struct {
	// When enabled is true, ipip tunneling will be
	// used to deliver packets to destinations within this
	// pool.
	Enabled bool `json:"enabled,omitempty"`
}

type Pool struct {
	TypeMetadata

	// Metadata for a Pool.
	Metadata PoolMetadata `json:"metadata,omitempty"`

	// Specification for a Pool.
	Spec PoolSpec `json:"spec,omitempty"`
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
