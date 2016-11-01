// Copyright (c) 2016 Tigera, Inc. All rights reserved.
//
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

package compat

import (
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

type ModelAdaptor struct {
	client api.Client
}

var _ api.Client = (*ModelAdaptor)(nil)

func NewAdaptor(c api.Client) *ModelAdaptor {
	return &ModelAdaptor{client: c}
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *ModelAdaptor) Create(d *model.KVPair) (*model.KVPair, error) {
	var err error
	switch d.Key.(type) {
	case model.ProfileKey:
		t, l, r := toTagsLabelsRules(d)
		if t, err = c.client.Create(t); err != nil {
			return nil, err
		} else if _, err := c.client.Create(l); err != nil {
			return nil, err
		} else if _, err := c.client.Create(r); err != nil {
			return nil, err
		} else {
			d.Revision = t.Revision
			return d, nil
		}
	case model.NodeKey:
		p, o := toNodeComponents(d)
		if p, err = c.client.Create(p); err != nil {
			return nil, err
		}
		if err = c.applyOrDeleteSubcomponents(o); err != nil {
			return nil, err
		}
		d.Revision = p.Revision
		return d, nil
	default:
		return c.client.Create(d)
	}
}

// Update an existing entry in the datastore.  This errors if the entry does
// not exist.
func (c *ModelAdaptor) Update(d *model.KVPair) (*model.KVPair, error) {
	var err error
	switch d.Key.(type) {
	case model.ProfileKey:
		t, l, r := toTagsLabelsRules(d)
		if t, err = c.client.Update(t); err != nil {
			return nil, err
		} else if _, err := c.client.Apply(l); err != nil {
			return nil, err
		} else if _, err := c.client.Apply(r); err != nil {
			return nil, err
		} else {
			d.Revision = t.Revision
			return d, nil
		}
	case model.NodeKey:
		p, o := toNodeComponents(d)
		if p, err = c.client.Update(p); err != nil {
			return nil, err
		}
		if err = c.applyOrDeleteSubcomponents(o); err != nil {
			return nil, err
		}
		d.Revision = p.Revision
		return d, nil
	default:
		return c.client.Update(d)
	}
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *ModelAdaptor) Apply(d *model.KVPair) (*model.KVPair, error) {
	var err error
	switch d.Key.(type) {
	case model.ProfileKey:
		t, l, r := toTagsLabelsRules(d)
		if t, err = c.client.Apply(t); err != nil {
			return nil, err
		} else if _, err := c.client.Apply(l); err != nil {
			return nil, err
		} else if _, err := c.client.Apply(r); err != nil {
			return nil, err
		} else {
			d.Revision = t.Revision
			return d, nil
		}
	case model.NodeKey:
		p, o := toNodeComponents(d)
		if p, err = c.client.Apply(p); err != nil {
			return nil, err
		}
		if err = c.applyOrDeleteSubcomponents(o); err != nil {
			return nil, err
		}
		d.Revision = p.Revision
		return d, nil
	default:
		return c.client.Apply(d)
	}
}

// Delete an entry in the datastore.  This errors if the entry does not exists.
func (c *ModelAdaptor) Delete(d *model.KVPair) error {
	var err error
	switch d.Key.(type) {
	case model.NodeKey:
		p, o := toNodeDeleteComponents(d)
		if err = c.applyOrDeleteSubcomponents(o); err != nil {
			return err
		}
		if err = c.client.Delete(p); err != nil {
			return err
		}
		return nil
	default:
		return c.client.Delete(d)
	}
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *ModelAdaptor) Get(k model.Key) (*model.KVPair, error) {
	switch kt := k.(type) {
	case model.ProfileKey:
		return c.getProfile(k)
	case model.NodeKey:
		return c.getNode(kt)
	default:
		return c.client.Get(k)
	}
}

// List entries in the datastore.  This may return an empty list of there are
// no entries matching the request in the ListInterface.
func (c *ModelAdaptor) List(l model.ListInterface) ([]*model.KVPair, error) {
	switch lt := l.(type) {
	case model.NodeListOptions:
		return c.listNodes(lt)
	default:
		return c.client.List(l)
	}
}

func (c *ModelAdaptor) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	return c.client.Syncer(callbacks)
}

// getProfile gets the composite profile by getting the individual components
// and joining the results together.
func (c *ModelAdaptor) getProfile(k model.Key) (*model.KVPair, error) {
	var t, l, r *model.KVPair
	var err error
	pk := k.(model.ProfileKey)

	if t, err = c.client.Get(model.ProfileTagsKey{pk}); err != nil {
		return nil, err
	}
	d := model.KVPair{
		Key: k,
		Value: &model.Profile{
			Tags: t.Value.([]string),
		},
		Revision: t.Revision,
	}
	p := d.Value.(*model.Profile)
	if l, err = c.client.Get(model.ProfileLabelsKey{pk}); err == nil {
		p.Labels = l.Value.(map[string]string)
	}
	if r, err = c.client.Get(model.ProfileRulesKey{pk}); err == nil {
		p.Rules = *r.Value.(*model.ProfileRules)
	}
	return &d, nil
}

// getNode gets the composite node by getting the individual components
// and joining the results together.
func (c *ModelAdaptor) getNode(nk model.NodeKey) (*model.KVPair, error) {
	var err error

	// Fill in the Metadata specific part of the node configuration.  At the
	// moment, there is nothing to fill in.
	if _, err = c.client.Get(model.HostMetadataKey{nk.Hostname}); err != nil {
		return nil, err
	}
	nv := model.Node{}

	err = c.getNodeSubcomponents(nk, &nv)
	if err != nil {
		return nil, err
	}

	return &model.KVPair{Key: nk, Value: &nv}, nil
}

// listNodes lists the composite node resources by listing the primary node
// object and then getting the remaining components through additional queries.
// Note that enumeration of the primary component is horribly inefficient
// because of the way we do our list queries - we'll enumerate all endpoints on
// host as well!
func (c *ModelAdaptor) listNodes(l model.NodeListOptions) ([]*model.KVPair, error) {
	hml := model.HostMetadataListOptions{Hostname: l.Hostname}
	hmr, err := c.client.List(hml)
	if err != nil {
		return nil, err
	}

	results := make([]*model.KVPair, len(hmr))
	for idx, hmkv := range hmr {
		hmk := hmkv.Key.(model.HostMetadataKey)

		// Fill in the metadata part of the node - at the moment there is
		// nothing to fill in.
		nk := model.NodeKey{Hostname: hmk.Hostname}
		nv := model.Node{}

		err = c.getNodeSubcomponents(nk, &nv)
		if err != nil {
			return nil, err
		}

		results[idx] = &model.KVPair{Key: nk, Value: &nv}
	}

	return results, nil
}

// Get the node sub components and fill in the details in the supplied node
// struct.
func (c *ModelAdaptor) getNodeSubcomponents(nk model.NodeKey, nv *model.Node) error {
	var component *model.KVPair
	var err error

	// Fill in the Metadata specific part of the node configuration.
	if component, err = c.client.Get(model.HostBGPIPKey{nk.Hostname, 4}); err == nil {
		nv.BGPIPv4 = component.Value.(*net.IP)
	} else if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
		return err
	}

	if component, err = c.client.Get(model.HostBGPIPKey{nk.Hostname, 6}); err == nil {
		nv.BGPIPv6 = component.Value.(*net.IP)
	} else if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
		return err
	}

	if component, err = c.client.Get(model.HostBGPASNumberKey{nk.Hostname}); err == nil {
		asn := component.Value.(numorstring.ASNumber)
		nv.BGPASNumber = &asn
	} else if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
		return err
	}

	return nil
}

// applyOrDeleteSubcomponents applies the configuration if the value is non-nil
// or deletes the entry if the value is nil.
func (c *ModelAdaptor) applyOrDeleteSubcomponents(components []*model.KVPair) error {
	for _, component := range components {
		// If there is a value, apply it to either create or update.  Otherwise
		// delete the entry, ignoring error indicating the entry does not exist.
		if component.Value != nil {
			if _, err := c.client.Apply(component); err != nil {
				return err
			}
		} else if err := c.client.Delete(component); err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				return err
			}
		}
	}

	return nil
}

// toTagsLabelsRules converts a Profile KVPair to separate KVPair types for Keys,
// Labels and Rules. These separate KVPairs are used to write three separate objects
// that make up a single profile.
func toTagsLabelsRules(d *model.KVPair) (t, l, r *model.KVPair) {
	p := d.Value.(*model.Profile)
	pk := d.Key.(model.ProfileKey)

	t = &model.KVPair{
		Key:      model.ProfileTagsKey{pk},
		Value:    p.Tags,
		Revision: d.Revision,
	}
	l = &model.KVPair{
		Key:   model.ProfileLabelsKey{pk},
		Value: p.Labels,
	}
	r = &model.KVPair{
		Key:   model.ProfileRulesKey{pk},
		Value: &p.Rules,
	}

	return t, l, r
}

// toNodeComponents converts a Node KVPair to separate KVPair types that make up the
// Node.  This includes:
// -  The host metadata (the primary component)
// -  The host IPv4 address (used by Felix to filter IPIP traffic)
// -  The BGP AS Number
// -  The BGP IPv4 address
// -  The BGP IPv6 address
//
// A nil value is used to indicate that the entry should be deleted rather than
// configured.
func toNodeComponents(d *model.KVPair) (primary *model.KVPair, optional []*model.KVPair) {
	n := d.Value.(*model.Node)
	nk := d.Key.(model.NodeKey)

	primary = &model.KVPair{
		Key:      model.HostMetadataKey{nk.Hostname},
		Value:    &model.HostMetadata{},
		Revision: d.Revision,
	}

	// Handle nil values separately so we can put an interface{} value of
	// nil (since it is different type of nil that a nil IP).
	optional = []*model.KVPair{}
	if n.BGPIPv4 != nil {
		optional = append(optional, &model.KVPair{
			Key:   model.HostIPKey{nk.Hostname},
			Value: n.BGPIPv4,
		}, &model.KVPair{
			Key:   model.HostBGPIPKey{nk.Hostname, 4},
			Value: n.BGPIPv4,
		})
	} else {
		optional = append(optional, &model.KVPair{
			Key: model.HostIPKey{nk.Hostname},
		}, &model.KVPair{
			Key: model.HostBGPIPKey{nk.Hostname, 4},
		})
	}

	if n.BGPIPv6 != nil {
		optional = append(optional, &model.KVPair{
			Key:   model.HostBGPIPKey{nk.Hostname, 6},
			Value: n.BGPIPv6,
		})
	} else {
		optional = append(optional, &model.KVPair{
			Key: model.HostBGPIPKey{nk.Hostname, 6},
		})
	}

	if n.BGPASNumber == nil {
		optional = append(optional, &model.KVPair{
			Key: model.HostBGPASNumberKey{nk.Hostname},
		})
	} else {
		optional = append(optional, &model.KVPair{
			Key:   model.HostBGPASNumberKey{nk.Hostname},
			Value: *n.BGPASNumber,
		})
	}

	return primary, optional
}

// toNodeDeleteComponents is similar to function toNodeComponents, but returns nil
// interface values which the applyOrDeleteSubcomponents method will treat as a delete.
func toNodeDeleteComponents(d *model.KVPair) (primary *model.KVPair, optional []*model.KVPair) {
	nk := d.Key.(model.NodeKey)

	primary = &model.KVPair{
		Key:      model.HostMetadataKey{nk.Hostname},
		Revision: d.Revision,
	}
	optional = []*model.KVPair{
		&model.KVPair{
			Key: model.HostIPKey{nk.Hostname},
		},
		&model.KVPair{
			Key: model.HostBGPIPKey{nk.Hostname, 4},
		},
		&model.KVPair{
			Key: model.HostBGPIPKey{nk.Hostname, 6},
		},
		&model.KVPair{
			Key: model.HostBGPASNumberKey{nk.Hostname},
		},
	}

	return primary, optional
}
