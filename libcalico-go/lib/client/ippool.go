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
	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/converter"
)

// PoolInterface has methods to work with Pool resources.
type IPPoolInterface interface {
	List(api.IPPoolMetadata) (*api.IPPoolList, error)
	Get(api.IPPoolMetadata) (*api.IPPool, error)
	Create(*api.IPPool) (*api.IPPool, error)
	Update(*api.IPPool) (*api.IPPool, error)
	Apply(*api.IPPool) (*api.IPPool, error)
	Delete(api.IPPoolMetadata) error
}

// ipPools implements IPPoolInterface
type ipPools struct {
	converter.IPPoolConverter
	c *Client
}

// newIPPools returns a new IPPoolInterface bound to the supplied client.
func newIPPools(c *Client) IPPoolInterface {
	return &ipPools{c: c}
}

// Create creates a new IP pool.
func (h *ipPools) Create(a *api.IPPool) (*api.IPPool, error) {
	err := h.c.create(*a, h)
	return a, err
}

// Update updates an existing IP pool.
func (h *ipPools) Update(a *api.IPPool) (*api.IPPool, error) {
	err := h.c.update(*a, h)
	return a, err
}

// Apply updates an IP pool if it exists, or creates a new pool if it does not exist.
func (h *ipPools) Apply(a *api.IPPool) (*api.IPPool, error) {
	err := h.c.apply(*a, h)
	return a, err
}

// Delete deletes an existing IP pool.
func (h *ipPools) Delete(metadata api.IPPoolMetadata) error {
	// Deleting a pool requires a little care because of existing endpoints
	// using IP addresses allocated in the pool.  We do the deletion in
	// the following steps:
	// -  disable the pool so no more IPs are assigned from it
	// -  remove all affinities associated with the pool
	// -  delete the pool

	// Start by getting the current pool data and then setting the disabled
	// flag.
	if pool, err := h.Get(metadata); err != nil {
		return err
	} else {
		log.Debugf("Disabling pool %s", metadata.CIDR)
		pool.Spec.Disabled = true
		if _, err := h.Update(pool); err != nil {
			return err
		}
	}

	// And finally, delete the pool.
	log.Debugf("Deleting pool %s", metadata.CIDR)
	return h.c.delete(metadata, h)
}

// Get returns information about a particular IP pool.
func (h *ipPools) Get(metadata api.IPPoolMetadata) (*api.IPPool, error) {
	if a, err := h.c.get(metadata, h); err != nil {
		return nil, err
	} else {
		return a.(*api.IPPool), nil
	}
}

// List takes a Metadata, and returns an IPPoolList that contains the list of IP pools
// that match the Metadata (wildcarding missing fields).
func (h *ipPools) List(metadata api.IPPoolMetadata) (*api.IPPoolList, error) {
	l := api.NewIPPoolList()
	err := h.c.list(metadata, h, l)
	return l, err
}

// convertMetadataToListInterface converts an IPPoolMetadata to an IPPoolListOptions.
// This is part of the conversionHelper interface.
func (h *ipPools) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	pm := m.(api.IPPoolMetadata)
	l := model.IPPoolListOptions{
		CIDR: pm.CIDR,
	}
	return l, nil
}

// convertMetadataToKey converts an IPPoolMetadata to an IPPoolKey
// This is part of the conversionHelper interface.
func (h *ipPools) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	return h.IPPoolConverter.ConvertMetadataToKey(m)
}

// convertAPIToKVPair converts an API IPPool structure to a KVPair containing a
// backend IPPool and IPPoolKey.
// This is part of the conversionHelper interface.
func (h *ipPools) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	return h.IPPoolConverter.ConvertAPIToKVPair(a)
}

// convertKVPairToAPI converts a KVPair containing a backend IPPool and IPPoolKey
// to an API IPPool structure.
// This is part of the conversionHelper interface.
func (h *ipPools) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	return h.IPPoolConverter.ConvertKVPairToAPI(d)
}
