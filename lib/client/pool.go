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

package client

import (
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend"
)

// PoolInterface has methods to work with Pool resources.
type PoolInterface interface {
	List(api.PoolMetadata) (*api.PoolList, error)
	Get(api.PoolMetadata) (*api.Pool, error)
	Create(*api.Pool) (*api.Pool, error)
	Update(*api.Pool) (*api.Pool, error)
	Apply(*api.Pool) (*api.Pool, error)
	Delete(api.PoolMetadata) error
}

// pools implements PoolInterface
type pools struct {
	c *Client
}

// newPools returns a pools
func newPools(c *Client) *pools {
	return &pools{c}
}

// Create creates a new pool.
func (h *pools) Create(a *api.Pool) (*api.Pool, error) {
	return a, h.c.create(*a, h)
}

// Create creates a new pool.
func (h *pools) Update(a *api.Pool) (*api.Pool, error) {
	return a, h.c.update(*a, h)
}

// Create creates a new pool.
func (h *pools) Apply(a *api.Pool) (*api.Pool, error) {
	return a, h.c.apply(*a, h)
}

// Delete deletes an existing pool.
func (h *pools) Delete(metadata api.PoolMetadata) error {
	return h.c.delete(metadata, h)
}

// Get returns information about a particular pool.
func (h *pools) Get(metadata api.PoolMetadata) (*api.Pool, error) {
	if a, err := h.c.get(metadata, h); err != nil {
		return nil, err
	} else {
		return a.(*api.Pool), nil
	}
}

// List takes a Metadata, and returns the list of pools that match that Metadata
// (wildcarding missing fields)
func (h *pools) List(metadata api.PoolMetadata) (*api.PoolList, error) {
	l := api.NewPoolList()
	err := h.c.list(metadata, h, l)
	return l, err
}

// Convert a PoolMetadata to a PoolListInterface
func (h *pools) convertMetadataToListInterface(m interface{}) (backend.ListInterface, error) {
	pm := m.(api.PoolMetadata)
	l := backend.PoolListOptions{
		Cidr: pm.Cidr,
	}
	return l, nil
}

// Convert a PoolMetadata to a PoolKeyInterface
func (h *pools) convertMetadataToKeyInterface(m interface{}) (backend.KeyInterface, error) {
	pm := m.(api.PoolMetadata)
	k := backend.PoolKey{
		Cidr: pm.Cidr,
	}
	return k, nil
}

// Convert an API Pool structure to a Backend Pool structure
func (h *pools) convertAPIToDatastoreObject(a interface{}) (*backend.DatastoreObject, error) {
	ap := a.(api.Pool)
	k, err := h.convertMetadataToKeyInterface(ap.Metadata)
	if err != nil {
		return nil, err
	}

	d := backend.DatastoreObject{
		Key: k,
		Object: backend.Pool{
			Cidr:          ap.Metadata.Cidr,
			IPIPInterface: ap.Spec.IPIPInterface,
			Masquerade:    ap.Spec.Masquerade,
			Ipam:          ap.Spec.Ipam,
			Disabled:      ap.Spec.Disabled,
		},
	}

	return &d, nil
}

// Convert a Backend Pool structure to an API Pool structure
func (h *pools) convertDatastoreObjectToAPI(d *backend.DatastoreObject) (interface{}, error) {
	backendPool := d.Object.(backend.Pool)
	//bk := d.Key.(backend.PoolKey)

	apiPool := api.NewPool()
	apiPool.Metadata.Cidr = backendPool.Cidr
	apiPool.Spec.IPIPInterface = backendPool.IPIPInterface
	apiPool.Spec.Masquerade = backendPool.Masquerade
	apiPool.Spec.Ipam = backendPool.Ipam
	apiPool.Spec.Disabled = backendPool.Disabled

	return apiPool, nil
}
