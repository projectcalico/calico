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
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
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

// newPools returns a new PoolInterface bound to the supplied client.
func newPools(c *Client) PoolInterface {
	return &pools{c}
}

// Create creates a new pool.
func (h *pools) Create(a *api.Pool) (*api.Pool, error) {
	return a, h.c.create(*a, h)
}

// Update updates an existing pool.
func (h *pools) Update(a *api.Pool) (*api.Pool, error) {
	return a, h.c.update(*a, h)
}

// Apply updates a pool if it exists, or creates a new pool if it does not exist.
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

// List takes a Metadata, and returns a PoolList that contains the list of pools
// that match the Metadata (wildcarding missing fields).
func (h *pools) List(metadata api.PoolMetadata) (*api.PoolList, error) {
	l := api.NewPoolList()
	err := h.c.list(metadata, h, l)
	return l, err
}

// convertMetadataToListInterface converts a PoolMetadata to a PoolListOptions.
// This is part of the conversionHelper interface.
func (h *pools) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	pm := m.(api.PoolMetadata)
	l := model.PoolListOptions{
		CIDR: pm.CIDR,
	}
	return l, nil
}

// convertMetadataToKey converts a PoolMetadata to a PoolKey
// This is part of the conversionHelper interface.
func (h *pools) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	pm := m.(api.PoolMetadata)
	k := model.PoolKey{
		CIDR: pm.CIDR,
	}
	return k, nil
}

// convertAPIToKVPair converts an API Pool structure to a KVPair containing a
// backend Pool and PoolKey.
// This is part of the conversionHelper interface.
func (h *pools) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	ap := a.(api.Pool)
	k, err := h.convertMetadataToKey(ap.Metadata)
	if err != nil {
		return nil, err
	}

	// Only valid interface for now is tunl0.
	var ipipInterface string
	if ap.Spec.IPIP != nil && ap.Spec.IPIP.Enabled {
		ipipInterface = "tunl0"
	} else {
		ipipInterface = ""
	}

	d := model.KVPair{
		Key: k,
		Value: &model.Pool{
			CIDR:          ap.Metadata.CIDR,
			IPIPInterface: ipipInterface,
			Masquerade:    ap.Spec.NATOutgoing,
			IPAM:          !ap.Spec.Disabled,
			Disabled:      ap.Spec.Disabled,
		},
	}

	return &d, nil
}

// convertKVPairToAPI converts a KVPair containing a backend Pool and PoolKey
// to an API Pool structure.
// This is part of the conversionHelper interface.
func (h *pools) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	backendPool := d.Value.(*model.Pool)

	apiPool := api.NewPool()
	apiPool.Metadata.CIDR = backendPool.CIDR
	apiPool.Spec.NATOutgoing = backendPool.Masquerade
	apiPool.Spec.Disabled = backendPool.Disabled

	// If an IPIP interface is specified, then IPIP is enabled.
	if backendPool.IPIPInterface != "" {
		apiPool.Spec.IPIP = &api.IPIPConfiguration{Enabled: true}
	}

	return apiPool, nil
}
