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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/golang/glog"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend"
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
	c *Client
}

// newProfiles returns a profiles
func newProfiles(c *Client) *profiles {
	return &profiles{c}
}

// List takes a Metadata, and returns the list of profiles that match that Metadata
// (wildcarding missing fields)
func (h *profiles) List(metadata api.ProfileMetadata) (*api.ProfileList, error) {
	if l, err := h.c.list(backend.Profile{}, metadata, h, h); err != nil {
		return nil, err
	} else {
		hl := api.NewProfileList()
		hl.Items = make([]api.Profile, 0, len(l))
		for _, h := range l {
			hl.Items = append(hl.Items, *h.(*api.Profile))
		}
		return hl, nil
	}
}

// Get returns information about a particular profile.
func (h *profiles) Get(metadata api.ProfileMetadata) (*api.Profile, error) {
	if a, err := h.c.get(backend.Profile{}, metadata, h, h); err != nil {
		return nil, err
	} else {
		h := a.(api.Profile)
		return &h, nil
	}
}

// Create creates a new profile.
func (h *profiles) Create(a *api.Profile) (*api.Profile, error) {
	return a, h.c.create(*a, h, h)
}

// Update updates an existing profile.
func (h *profiles) Update(a *api.Profile) (*api.Profile, error) {
	return a, h.c.update(*a, h, h)
}

// Apply creates a new or replaces an existing profile.
func (h *profiles) Apply(a *api.Profile) (*api.Profile, error) {
	return a, h.c.apply(*a, h, h)
}

// Delete deletes an existing profile.
func (h *profiles) Delete(metadata api.ProfileMetadata) error {
	return h.c.delete(metadata, h)
}

// Convert a ProfileMetadata to a ProfileListInterface
func (h *profiles) convertMetadataToListInterface(m interface{}) (backend.ListInterface, error) {
	hm := m.(api.ProfileMetadata)
	l := backend.ProfileListOptions{
		Name: hm.Name,
	}
	return l, nil
}

// Convert a ProfileMetadata to a ProfileKeyInterface
func (h *profiles) convertMetadataToKeyInterface(m interface{}) (backend.KeyInterface, error) {
	hm := m.(api.ProfileMetadata)
	k := backend.ProfileKey{
		Name: hm.Name,
	}
	return k, nil
}

// Convert an API Profile structure to a Backend Profile structure
func (h *profiles) convertAPIToBackend(a interface{}) (interface{}, error) {
	ap := a.(api.Profile)
	k, err := h.convertMetadataToKeyInterface(ap.Metadata)
	if err != nil {
		return nil, err
	}
	pk := k.(backend.ProfileKey)

	bp := backend.Profile{
		ProfileKey: pk,
		Rules: backend.ProfileRules{
			InboundRules:  rulesAPIToBackend(ap.Spec.IngressRules),
			OutboundRules: rulesAPIToBackend(ap.Spec.EgressRules),
		},
		Tags:   ap.Spec.Tags,
		Labels: ap.Metadata.Labels,
	}

	return bp, nil
}

// Convert a Backend Profile structure to an API Profile structure
func (h *profiles) convertBackendToAPI(b interface{}) (interface{}, error) {
	bp := *b.(*backend.Profile)
	ap := api.NewProfile()

	ap.Metadata.Name = bp.Name
	ap.Metadata.Labels = bp.Labels

	ap.Spec.IngressRules = rulesBackendToAPI(bp.Rules.InboundRules)
	ap.Spec.EgressRules = rulesBackendToAPI(bp.Rules.OutboundRules)
	ap.Spec.Tags = bp.Tags

	return ap, nil
}

func (h *profiles) backendCreate(k backend.KeyInterface, obj interface{}) error {
	p := obj.(backend.Profile)
	pk := k.(backend.ProfileKey)
	if err := h.c.backendCreate(backend.ProfileTagsKey{pk}, p.Tags); err != nil {
		return err
	} else if err := h.c.backendCreate(backend.ProfileLabelsKey{pk}, p.Labels); err != nil {
		return err
	} else {
		return h.c.backendCreate(backend.ProfileRulesKey{pk}, p.Rules)
	}
}

func (h *profiles) backendUpdate(k backend.KeyInterface, obj interface{}) error {
	p := obj.(backend.Profile)
	pk := k.(backend.ProfileKey)
	if err := h.c.backendUpdate(backend.ProfileTagsKey{pk}, p.Tags); err != nil {
		return err
	} else if err := h.c.backendApply(backend.ProfileLabelsKey{pk}, p.Labels); err != nil {
		return err
	} else {
		return h.c.backendApply(backend.ProfileRulesKey{pk}, p.Rules)
	}
}

func (h *profiles) backendApply(k backend.KeyInterface, obj interface{}) error {
	p := obj.(backend.Profile)
	pk := k.(backend.ProfileKey)
	if err := h.c.backendApply(backend.ProfileTagsKey{pk}, p.Tags); err != nil {
		return err
	} else if err := h.c.backendApply(backend.ProfileLabelsKey{pk}, p.Labels); err != nil {
		return err
	} else {
		return h.c.backendApply(backend.ProfileRulesKey{pk}, p.Rules)
	}
}

func (h *profiles) backendGet(k backend.KeyInterface, objp interface{}) (interface{}, error) {
	pk := k.(backend.ProfileKey)
	kvs := []backend.KeyValue{}
	if kv, err := h.c.backend.Get(backend.ProfileTagsKey{pk}); err != nil {
		return nil, err
	} else {
		kvs = append(kvs, kv)
	}
	if kv, err := h.c.backend.Get(backend.ProfileLabelsKey{pk}); err != nil {
		kvs = append(kvs, kv)
	}
	if kv, err := h.c.backend.Get(backend.ProfileRulesKey{pk}); err != nil {
		kvs = append(kvs, kv)
	}
	return h.c.unmarshalIntoNewBackendStruct(kvs, objp)
}

// Convert the list of enumerated key-values into a list of groups of key-value each
// belonging to a single resource.
func (h *profiles) backendListConvert(in []backend.KeyValue) [][]backend.KeyValue {
	groups := make(map[string][]backend.KeyValue)
	var name string
	for _, kv := range in {
		switch t := kv.Key.(type) {
		case backend.ProfileRulesKey:
			name = t.Name
		case backend.ProfileTagsKey:
			name = t.Name
		case backend.ProfileLabelsKey:
			name = t.Name
		default:
			panic(fmt.Errorf("Unexpected KV type: %v", kv))
		}
		groups[name] = append(groups[name], kv)
	}

	// To store the keys in slice in sorted order
	var keys []string
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([][]backend.KeyValue, len(keys))
	for i, k := range keys {
		out[i] = groups[k]
	}

	glog.V(2).Infof("Sorted groups of key/values: %v", out)

	return out
}

// Unmarshall a list of backend data values into a new instance of the supplied backend type.
// Returns an interface containing the a pointer to the new instance.
func (h *profiles) unmarshalIntoNewBackendStruct(kvs []backend.KeyValue, backendObjectp interface{}) (interface{}, error) {
	new := backend.Profile{}
	for _, kv := range kvs {
		switch kv.Key.(type) {
		case backend.ProfileRulesKey:
			glog.V(2).Infof("Unmarshal rules: %v", string(kv.Value))
			if err := json.Unmarshal(kv.Value, &new.Rules); err != nil {
				return nil, err
			}
		case backend.ProfileTagsKey:
			glog.V(2).Infof("Unmarshal tags: %v", string(kv.Value))
			if err := json.Unmarshal(kv.Value, &new.Tags); err != nil {
				return nil, err
			}
		case backend.ProfileLabelsKey:
			glog.V(2).Infof("Unmarshal labels: %v", string(kv.Value))
			if err := json.Unmarshal(kv.Value, &new.Labels); err != nil {
				return nil, err
			}
		}
	}
	return &new, nil
}

func (h *profiles) copyKeyValues(kvs []backend.KeyValue, b interface{}) {
	bp := b.(*backend.Profile)
	kv := kvs[0]
	switch t := kv.Key.(type) {
	case backend.ProfileRulesKey:
		bp.ProfileKey = t.ProfileKey
	case backend.ProfileTagsKey:
		bp.ProfileKey = t.ProfileKey
	case backend.ProfileLabelsKey:
		bp.ProfileKey = t.ProfileKey
	}
}
