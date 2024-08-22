// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

var (
	defaultTier = api.Tier{
		Metadata: api.TierMetadata{Name: names.DefaultTierName},
	}
)

// PolicyInterface has methods to work with Policy resources.
type PolicyInterface interface {
	List(api.PolicyMetadata) (*api.PolicyList, error)
	Get(api.PolicyMetadata) (*api.Policy, error)
	Create(*api.Policy) (*api.Policy, error)
	Update(*api.Policy) (*api.Policy, error)
	Apply(*api.Policy) (*api.Policy, error)
	Delete(api.PolicyMetadata) error
}

// policies implements PolicyInterface
type policies struct {
	converter.PolicyConverter
	c *Client
}

// newPolicies returns a new PolicyInterface bound to the supplied client.
func newPolicies(c *Client) *policies {
	return &policies{c: c}
}

// Create creates a new policy.
func (h *policies) Create(a *api.Policy) (*api.Policy, error) {
	// Before creating the policy, check that the tier exists, and if this is the
	// default tier, create it if it doesn't.
	if a.Metadata.Tier == "" {
		if _, err := h.c.Tiers().Create(&defaultTier); err != nil {
			if _, ok := err.(errors.ErrorResourceAlreadyExists); !ok {
				return nil, err
			}
		}
	} else if _, err := h.c.Tiers().Get(api.TierMetadata{Name: a.Metadata.Tier}); err != nil {
		return nil, err
	}

	return a, h.c.create(*a, h)
}

// Update updates an existing policy.
func (h *policies) Update(a *api.Policy) (*api.Policy, error) {
	return a, h.c.update(*a, h)
}

// Apply updates a policy if it exists, or creates a new policy if it does not exist.
func (h *policies) Apply(a *api.Policy) (*api.Policy, error) {
	// Before creating the policy, check that the tier exists, and if this is the
	// default tier, create it if it doesn't.
	if a.Metadata.Tier == "" {
		if _, err := h.c.Tiers().Create(&defaultTier); err != nil {
			if _, ok := err.(errors.ErrorResourceAlreadyExists); !ok {
				return nil, err
			}
		}
	} else if _, err := h.c.Tiers().Get(api.TierMetadata{Name: a.Metadata.Tier}); err != nil {
		return nil, err
	}

	return a, h.c.apply(*a, h)
}

// Delete deletes an existing policy.
func (h *policies) Delete(metadata api.PolicyMetadata) error {
	return h.c.delete(metadata, h)
}

// Get returns information about a particular policy.
func (h *policies) Get(metadata api.PolicyMetadata) (*api.Policy, error) {
	if a, err := h.c.get(metadata, h); err != nil {
		return nil, err
	} else {
		return a.(*api.Policy), nil
	}
}

// List takes a Metadata, and returns a PolicyList that contains the list of policies
// that match the Metadata (wildcarding missing fields).
func (h *policies) List(metadata api.PolicyMetadata) (*api.PolicyList, error) {
	l := api.NewPolicyList()
	err := h.c.list(metadata, h, l)
	return l, err
}

// convertMetadataToListInterface converts a PolicyMetadata to a PolicyListOptions.
// This is part of the conversionHelper interface.
func (h *policies) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	pm := m.(api.PolicyMetadata)
	l := model.PolicyListOptions{
		Name: pm.Name,
		Tier: pm.Tier,
	}
	return l, nil
}

// convertMetadataToKey converts a PolicyMetadata to a PolicyKey
// This is part of the conversionHelper interface.  Call through to the shared
// converter (embedded in the policies struct).
func (h *policies) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	return h.ConvertMetadataToKey(m)
}

// convertAPIToKVPair converts an API Policy structure to a KVPair containing a
// backend Policy and PolicyKey.
// This is part of the conversionHelper interface.  Call through to the shared
// converter (embedded in the policies struct).
func (h *policies) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	return h.ConvertAPIToKVPair(a)
}

// convertKVPairToAPI converts a KVPair containing a backend Policy and PolicyKey
// to an API Policy structure.
// This is part of the conversionHelper interface.  Call through to the shared
// converter (embedded in the policies struct).
func (h *policies) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	return h.ConvertKVPairToAPI(d)
}
