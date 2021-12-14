// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/converter"
)

// ProfileInterface has methods to work with Profile resources.
type ProfileInterface interface {
	List(api.ProfileMetadata) (*api.ProfileList, error)
	Get(api.ProfileMetadata) (*api.Profile, error)
	Create(*api.Profile) (*api.Profile, error)
	Update(*api.Profile) (*api.Profile, error)
	Apply(*api.Profile) (*api.Profile, error)
	Delete(api.ProfileMetadata) error
}

// profiles implements ProfileInterface
type profiles struct {
	converter.ProfileConverter
	c *Client
}

// newProfiles returns a new ProfileInterface bound to the supplied client.
func newProfiles(c *Client) ProfileInterface {
	return &profiles{c: c}
}

// Create creates a new profile.
func (h *profiles) Create(a *api.Profile) (*api.Profile, error) {
	return a, h.c.create(*a, h)
}

// Update updates an existing profile.
func (h *profiles) Update(a *api.Profile) (*api.Profile, error) {
	return a, h.c.update(*a, h)
}

// Apply updates a profile if it exists, or creates a new profile if it does not exist.
func (h *profiles) Apply(a *api.Profile) (*api.Profile, error) {
	return a, h.c.apply(*a, h)
}

// Delete deletes an existing profile.
func (h *profiles) Delete(metadata api.ProfileMetadata) error {
	return h.c.delete(metadata, h)
}

// Get returns information about a particular profile.
func (h *profiles) Get(metadata api.ProfileMetadata) (*api.Profile, error) {
	if a, err := h.c.get(metadata, h); err != nil {
		return nil, err
	} else {
		return a.(*api.Profile), nil
	}
}

// List takes a Metadata, and returns a ProfileList that contains the list of profiles
// that match the Metadata (wildcarding missing fields).
func (h *profiles) List(metadata api.ProfileMetadata) (*api.ProfileList, error) {
	l := api.NewProfileList()
	err := h.c.list(metadata, h, l)
	return l, err
}

// convertMetadataToListInterface converts a ProfileMetadata to a ProfileListOptions.
// This is part of the conversionHelper interface.  Call through to the shared
// converter (embedded in the profiles struct).
func (h *profiles) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	hm := m.(api.ProfileMetadata)
	l := model.ProfileListOptions{
		Name: hm.Name,
	}
	return l, nil
}

// convertMetadataToKey converts a ProfileMetadata to a ProfileKey
// This is part of the conversionHelper interface.  Call through to the shared
// converter (embedded in the profiles struct).
func (h *profiles) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	return h.ConvertMetadataToKey(m)
}

// convertMetadataToKey converts a ProfileMetadata to a ProfileKey
// This is part of the conversionHelper interface.  Call through to the shared
// converter (embedded in the profiles struct).
func (h *profiles) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	return h.ConvertAPIToKVPair(a)
}

// convertKVPairToAPI converts a KVPair containing a backend Profile and ProfileKey
// to an API Profile structure.
// This is part of the conversionHelper interface.  Call through to the shared
// converter (embedded in the profiles struct).
func (h *profiles) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	return h.ConvertKVPairToAPI(d)
}
