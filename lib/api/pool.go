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
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/net"
)

// Pool contains the details of a Calico IP pool resource.
// A pool resource is used by Calico in two ways:
// 	- to provide a set of IP addresses from which Calico IPAM assigns addresses
// 	  for workloads.
// 	- to provide configuration specific to IP address range, such as configuration
// 	  for the BGP daemon (e.g. when to use a GRE tunnel to encapsulate packets
// 	  between compute hosts).
type Pool struct {
	unversioned.TypeMetadata
	Metadata PoolMetadata `json:"metadata,omitempty"`
	Spec     PoolSpec     `json:"spec,omitempty"`
}

// PoolMetadata contains the metadata for an IP pool resource.
type PoolMetadata struct {
	unversioned.ObjectMetadata
	CIDR net.IPNet `json:"cidr"`
}

// PoolSpec contains the specification for an IP pool resource.
type PoolSpec struct {
	// Contains configuration for ipip tunneling for this pool. If not specified,
	// then ipip tunneling is disabled for this pool.
	IPIP *IPIPConfiguration `json:"ipip,omitempty"`

	// When nat-outgoing is true, packets sent from Calico networked containers in
	// this pool to destinations outside of this pool will be masqueraded.
	NATOutgoing bool `json:"nat-outgoing,omitempty"`

	// When disabled is true, Calico IPAM will not assign addresses from this pool.
	Disabled bool `json:"disabled,omitempty"`
}

type IPIPConfiguration struct {
	// When enabled is true, ipip tunneling will be used to deliver packets to
	// destinations within this pool.
	Enabled bool `json:"enabled,omitempty"`
}

// NewPool creates a new (zeroed) Pool struct with the TypeMetadata initialised to the current
// version.
func NewPool() *Pool {
	return &Pool{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       "pool",
			APIVersion: unversioned.VersionCurrent,
		},
	}
}

// PoolList contains a list of IP pool resources.  List types are returned from List()
// enumerations in the client interface.
type PoolList struct {
	unversioned.TypeMetadata
	Metadata unversioned.ListMetadata `json:"metadata,omitempty"`
	Items    []Pool                   `json:"items" validate:"dive"`
}

// NewPool creates a new (zeroed) PoolList struct with the TypeMetadata initialised to the current
// version.
func NewPoolList() *PoolList {
	return &PoolList{
		TypeMetadata: unversioned.TypeMetadata{
			Kind:       "poolList",
			APIVersion: unversioned.VersionCurrent,
		},
	}
}
