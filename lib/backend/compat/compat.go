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
	"encoding/json"
	goerrors "errors"

	log "github.com/sirupsen/logrus"

	"context"

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

func (c *ModelAdaptor) EnsureInitialized() error {
	return c.client.EnsureInitialized()
}

func (c *ModelAdaptor) Clean() error {
	return c.client.Clean()
}

// Create an entry in the datastore.  This errors if the entry already exists.
func (c *ModelAdaptor) Create(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	var err error
	switch k := d.Key.(type) {
	case model.ProfileKey:
		t, l, r := ToTagsLabelsRules(d)
		if t, err = c.client.Create(ctx, t); err != nil {
			return nil, err
		} else if _, err := c.client.Create(ctx, l); err != nil {
			return nil, err
		} else if _, err := c.client.Create(ctx, r); err != nil {
			return nil, err
		} else {
			d.Revision = t.Revision
			return d, nil
		}
	case model.NodeKey:
		p, o := toNodeComponents(d)
		if p, err = c.client.Create(ctx, p); err != nil {
			return nil, err
		}
		if err = c.applyOrDeleteSubcomponents(ctx, o); err != nil {
			return nil, err
		}
		d.Revision = p.Revision
		return d, nil
	case model.BlockKey:
		if err = validateBlockValue(d); err != nil {
			return nil, err
		}
		b, err := c.client.Create(ctx, d)
		if err != nil {
			return nil, err
		}
		d.Revision = b.Revision
		return d, nil
	case model.GlobalBGPConfigKey:
		nd := toDatastoreGlobalBGPConfig(*d)
		b, err := c.client.Create(ctx, nd)
		if err != nil {
			return nil, errors.UpdateErrorIdentifier(err, k)
		}
		d.Revision = b.Revision
		return d, nil
	default:
		return c.client.Create(ctx, d)
	}
}

// Update an existing entry in the datastore.  This errors if the entry does
// not exist.
func (c *ModelAdaptor) Update(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	var err error
	switch d.Key.(type) {
	case model.ProfileKey:
		t, l, r := ToTagsLabelsRules(d)
		if t, err = c.client.Update(ctx, t); err != nil {
			return nil, err
		} else if _, err := c.client.Apply(ctx, l); err != nil {
			return nil, err
		} else if _, err := c.client.Apply(ctx, r); err != nil {
			return nil, err
		} else {
			d.Revision = t.Revision
			return d, nil
		}
	case model.NodeKey:
		p, o := toNodeComponents(d)
		if p, err = c.client.Update(ctx, p); err != nil {
			return nil, err
		}
		if err = c.applyOrDeleteSubcomponents(ctx, o); err != nil {
			return nil, err
		}
		d.Revision = p.Revision
		return d, nil
	case model.BlockKey:
		if err = validateBlockValue(d); err != nil {
			return nil, err
		}
		b, err := c.client.Update(ctx, d)
		if err != nil {
			return nil, err
		}
		d.Revision = b.Revision
		return d, nil
	case model.GlobalBGPConfigKey:
		nd := toDatastoreGlobalBGPConfig(*d)
		b, err := c.client.Update(ctx, nd)
		if err != nil {
			return nil, errors.UpdateErrorIdentifier(err, d.Key)
		}
		d.Revision = b.Revision
		return d, nil
	default:
		return c.client.Update(ctx, d)
	}
}

// Set an existing entry in the datastore.  This ignores whether an entry already
// exists.
func (c *ModelAdaptor) Apply(ctx context.Context, d *model.KVPair) (*model.KVPair, error) {
	var err error
	switch d.Key.(type) {
	case model.ProfileKey:
		t, l, r := ToTagsLabelsRules(d)
		if t, err = c.client.Apply(ctx, t); err != nil {
			return nil, err
		} else if _, err := c.client.Apply(ctx, l); err != nil {
			return nil, err
		} else if _, err := c.client.Apply(ctx, r); err != nil {
			return nil, errors.UpdateErrorIdentifier(err, d.Key)
		} else {
			d.Revision = t.Revision
			return d, nil
		}
	case model.NodeKey:
		p, o := toNodeComponents(d)
		if p, err = c.client.Apply(ctx, p); err != nil {
			return nil, err
		}
		if err = c.applyOrDeleteSubcomponents(context.Background(), o); err != nil {
			return nil, err
		}
		d.Revision = p.Revision
		return d, nil
	case model.BlockKey:
		if err = validateBlockValue(d); err != nil {
			return nil, err
		}
		b, err := c.client.Apply(ctx, d)
		if err != nil {
			return nil, err
		}
		d.Revision = b.Revision
		return d, nil
	case model.GlobalBGPConfigKey:
		nd := toDatastoreGlobalBGPConfig(*d)
		b, err := c.client.Apply(ctx, nd)
		if err != nil {
			return nil, errors.UpdateErrorIdentifier(err, d.Key)
		}
		d.Revision = b.Revision
		return d, nil
	default:
		return c.client.Apply(ctx, d)
	}
}

// Delete an entry in the datastore.  This errors if the entry does not exists.
func (c *ModelAdaptor) Delete(ctx context.Context, k model.Key, rev string) (*model.KVPair, error) {
	var err error
	switch key := k.(type) {
	case model.NodeKey:
		p, o := toNodeDeleteComponents(key)
		if err = c.applyOrDeleteSubcomponents(ctx, o); err != nil {
			return nil, err
		}
		if _, err = c.client.Delete(ctx, p.Key, rev); err != nil {
			return nil, err
		}
		return nil, nil
	case model.GlobalBGPConfigKey:
		nd := toDatastoreGlobalBGPConfig(model.KVPair{Key: k})
		_, err := c.client.Delete(ctx, nd.Key, rev)
		return nil, errors.UpdateErrorIdentifier(err, k)
	default:
		return c.client.Delete(ctx, k, rev)
	}
}

func (c *ModelAdaptor) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, errors.ErrorOperationNotSupported{Operation: "DeleteKVP", Identifier: kvp.Key}
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *ModelAdaptor) Get(ctx context.Context, k model.Key, rev string) (*model.KVPair, error) {
	switch kt := k.(type) {
	case model.ProfileKey:
		return c.getProfile(ctx, k)
	case model.NodeKey:
		return c.getNode(ctx, kt)
	case model.BlockKey:
		return c.getBlock(ctx, k, rev)
	case model.GlobalBGPConfigKey:
		nk := toDatastoreGlobalBGPConfigKey(kt)
		if kvp, err := c.client.Get(ctx, nk, rev); err != nil {
			return nil, errors.UpdateErrorIdentifier(err, k)
		} else {
			return fromDatastoreGlobalBGPConfig(*kvp), nil
		}
	default:
		return c.client.Get(ctx, k, rev)
	}
}

// List entries in the datastore.  This may return an empty list of there are
// no entries matching the request in the ListInterface.
func (c *ModelAdaptor) List(ctx context.Context, l model.ListInterface, rev string) (*model.KVPairList, error) {
	switch lt := l.(type) {
	case model.NodeListOptions:
		return c.listNodes(ctx, lt)
	case model.BlockListOptions:
		return c.listBlock(ctx, lt)
	case model.GlobalBGPConfigListOptions:
		nl := toDatastoreGlobalBGPConfigList(lt)
		if kvps, err := c.client.List(ctx, nl, ""); err != nil {
			return nil, errors.UpdateErrorIdentifier(err, l)
		} else {
			for i, kvp := range kvps.KVPairs {
				kvps.KVPairs[i] = fromDatastoreGlobalBGPConfig(*kvp)
			}
			return kvps, nil
		}
	default:
		return c.client.List(ctx, l, "")
	}
}

func (c *ModelAdaptor) Watch(ctx context.Context, l model.ListInterface, revision string) (api.WatchInterface, error) {
	return c.client.Watch(ctx, l, revision)
}

// getProfile gets the composite profile by getting the individual components
// and joining the results together.
func (c *ModelAdaptor) getProfile(ctx context.Context, k model.Key) (*model.KVPair, error) {
	var t, l, r *model.KVPair
	var err error
	pk := k.(model.ProfileKey)

	if t, err = c.client.Get(ctx, model.ProfileTagsKey{pk}, ""); err != nil {
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
	if l, err = c.client.Get(ctx, model.ProfileLabelsKey{pk}, ""); err == nil {
		p.Labels = l.Value.(map[string]string)
	}
	if r, err = c.client.Get(ctx, model.ProfileRulesKey{pk}, ""); err == nil {
		p.Rules = *r.Value.(*model.ProfileRules)
	}
	return &d, nil
}

// getBlock gets KVPair for Block. It gets the block value first,
// then checks for `Affinity` field first, then `HostAffinity` as a backup.
// For more details see: https://github.com/projectcalico/libcalico-go/issues/226
func (c *ModelAdaptor) getBlock(ctx context.Context, k model.Key, rev string) (*model.KVPair, error) {
	bk := k.(model.BlockKey)

	v, err := c.client.Get(ctx, model.BlockKey{CIDR: bk.CIDR}, rev)
	if err != nil {
		return nil, err
	}

	// Make sure Affinity field has a proper value,
	// and map the value to Affinity if the deprecated HostAffinity field is used
	// by calling ensureBlockAffinity, and update the KVPair to return.
	return ensureBlockAffinity(v), nil
}

// getNode gets the composite node by getting the individual components
// and joining the results together.
func (c *ModelAdaptor) getNode(ctx context.Context, nk model.NodeKey) (*model.KVPair, error) {
	var err error

	// Fill in the Metadata specific part of the node configuration.  At the
	// moment, there is nothing to fill in.
	if _, err = c.client.Get(ctx, model.HostMetadataKey{nk.Hostname}, ""); err != nil {
		return nil, err
	}
	nv := model.Node{}

	err = c.getNodeSubcomponents(ctx, nk, &nv)
	if err != nil {
		return nil, err
	}

	return &model.KVPair{Key: nk, Value: &nv}, nil
}

// validateBlockValue validates the AllocationBlock fields (specifically Affinity) to
// make sure the deprecated HostAffinity field is not used.
func validateBlockValue(kvp *model.KVPair) error {
	if kvp.Value.(*model.AllocationBlock).HostAffinity != nil {
		return goerrors.New("AllocationBlock.HostAffinity is deprecated, please use Affinity instead.")
	}
	return nil
}

// listNodes lists the composite node resources by listing the primary node
// object and then getting the remaining components through additional queries.
// Note that enumeration of the primary component is horribly inefficient
// because of the way we do our list queries - we'll enumerate all endpoints on
// host as well!
func (c *ModelAdaptor) listNodes(ctx context.Context, l model.NodeListOptions) (*model.KVPairList, error) {
	hml := model.HostMetadataListOptions{Hostname: l.Hostname}
	hmr, err := c.client.List(ctx, hml, "")
	if err != nil {
		return nil, err
	}

	results := make([]*model.KVPair, len(hmr.KVPairs))
	for idx, hmkv := range hmr.KVPairs {
		hmk := hmkv.Key.(model.HostMetadataKey)

		// Fill in the metadata part of the node - at the moment there is
		// nothing to fill in.
		nk := model.NodeKey{Hostname: hmk.Hostname}
		nv := model.Node{}

		err = c.getNodeSubcomponents(ctx, nk, &nv)
		if err != nil {
			return nil, err
		}

		results[idx] = &model.KVPair{Key: nk, Value: &nv}
	}

	return &model.KVPairList{KVPairs: results}, nil
}

// listBlock returns list of KVPairs for Block, includes making sure
// backwards compatiblity. See getBlock for more details.
func (c *ModelAdaptor) listBlock(ctx context.Context, l model.BlockListOptions) (*model.KVPairList, error) {

	// Get a list of block KVPairs.
	blockList, err := c.client.List(ctx, l, "")
	if err != nil {
		return nil, err
	}

	// Create an empty slice of KVPair.
	results := make([]*model.KVPair, len(blockList.KVPairs))

	// Go through the list to make sure Affinity field has a proper value,
	// and maps the value to Affinity if the deprecated HostAffinity field is used
	// by calling ensureBlockAffinity, and populate the KVPair slice to return.
	for i, bkv := range blockList.KVPairs {
		results[i] = ensureBlockAffinity(bkv)
	}

	return &model.KVPairList{KVPairs: results}, nil
}

// ensureBlockAffinity ensures Affinity field has a proper value,
// and maps the value to Affinity if the deprecated HostAffinity field is used.
func ensureBlockAffinity(kvp *model.KVPair) *model.KVPair {
	val := kvp.Value.(*model.AllocationBlock)

	// Check for `Affinity` field first (this is to make sure we're
	// compatible with Python version etcd data-model).
	if val.Affinity == nil && val.HostAffinity != nil {
		// Convert HostAffinity=hostname into Affinity=host:hostname format.
		hostAffinityStr := "host:" + *val.HostAffinity
		val.Affinity = &hostAffinityStr

		// Set AllocationBlock.HostAffinity to nil so it's never non-nil for the clients.
		val.HostAffinity = nil
	}
	return &model.KVPair{Key: kvp.Key, Value: val, Revision: kvp.Revision, TTL: kvp.TTL}
}

// Get the node sub components and fill in the details in the supplied node
// struct.
func (c *ModelAdaptor) getNodeSubcomponents(ctx context.Context, nk model.NodeKey, nv *model.Node) error {
	var component *model.KVPair
	var err error
	var strval string

	// Fill in the Metadata specific part of the node configuration.
	if component, err = c.client.Get(ctx, model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "ip_addr_v4"}, ""); err == nil {
		strval = component.Value.(string)
		if strval != "" {
			nv.BGPIPv4Addr = &net.IP{}
			err = nv.BGPIPv4Addr.UnmarshalText([]byte(strval))
			if err != nil {
				log.WithError(err).Warning("Error unmarshalling IPv4")
				nv.BGPIPv4Addr = nil
			}
		}
	} else if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
		return err
	}

	if component, err = c.client.Get(ctx, model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "network_v4"}, ""); err == nil {
		strval = component.Value.(string)
		if strval != "" {
			_, nv.BGPIPv4Net, err = net.ParseCIDR(strval)
			if err != nil {
				log.WithError(err).Warning("Error unmarshalling IPv4Net")
				nv.BGPIPv4Net = nil
			}
		}
	} else if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
		return err
	}

	if component, err = c.client.Get(ctx, model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "ip_addr_v6"}, ""); err == nil {
		strval = component.Value.(string)
		if strval != "" {
			nv.BGPIPv6Addr = &net.IP{}
			err = nv.BGPIPv6Addr.UnmarshalText([]byte(strval))
			if err != nil {
				log.WithError(err).Warning("Error unmarshalling IPv6")
				nv.BGPIPv6Addr = nil
			}
		}
	} else if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
		return err
	}

	if component, err = c.client.Get(ctx, model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "network_v6"}, ""); err == nil {
		strval = component.Value.(string)
		if strval != "" {
			_, nv.BGPIPv6Net, err = net.ParseCIDR(strval)
			if err != nil {
				log.WithError(err).Warning("Error unmarshalling IPv6Net")
				nv.BGPIPv6Net = nil
			}
		}
	} else if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
		return err
	}

	if component, err = c.client.Get(ctx, model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "as_num"}, ""); err == nil {
		strval = component.Value.(string)
		if strval != "" {
			asn, err := numorstring.ASNumberFromString(strval)
			if err != nil {
				log.WithError(err).Warning("Error unmarshalling AS Number")
			} else {
				nv.BGPASNumber = &asn
			}
		}
	} else if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
		return err
	}

	if component, err := c.client.Get(ctx, model.OrchRefKey{Hostname: nk.Hostname}, ""); err == nil {
		nv.OrchRefs = component.Value.([]model.OrchRef)
	}

	return nil
}

// applyOrDeleteSubcomponents applies the configuration if the value is non-nil
// or deletes the entry if the value is nil.
func (c *ModelAdaptor) applyOrDeleteSubcomponents(ctx context.Context, components []*model.KVPair) error {
	for _, component := range components {
		// If there is a value, apply it to either create or update.  Otherwise
		// delete the entry, ignoring error indicating the entry does not exist.
		if component.Value != nil {
			if _, err := c.client.Apply(ctx, component); err != nil {
				return err
			}
		} else if _, err := c.client.Delete(ctx, component.Key, component.Revision); err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				return err
			}
		}
	}

	return nil
}

// ToTagsLabelsRules converts a Profile KVPair to separate KVPair types for Keys,
// Labels and Rules. These separate KVPairs are used to write three separate objects
// that make up a single profile.
func ToTagsLabelsRules(d *model.KVPair) (t, l, r *model.KVPair) {
	p := d.Value.(*model.Profile)
	pk := d.Key.(model.ProfileKey)

	t = &model.KVPair{
		Key:   model.ProfileTagsKey{pk},
		Value: p.Tags,
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

	// The calico/node image always expects the BGP IP keys to be present
	// when running BGP even if they are not specified (the value in that
	// case should be a blank string).  Felix on the other hand deals
	// with values not existing.
	ipv4Str := ""
	if n.BGPIPv4Addr != nil {
		ipv4Str = n.BGPIPv4Addr.String()
	}
	ipv6Str := ""
	if n.BGPIPv6Addr != nil {
		ipv6Str = n.BGPIPv6Addr.String()
	}

	// Add the BGP IPv4 and IPv6 values - these are always present.
	optional = []*model.KVPair{
		&model.KVPair{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "ip_addr_v4",
			},
			Value: ipv4Str,
		},
		&model.KVPair{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "ip_addr_v6",
			},
			Value: ipv6Str,
		},
	}

	// Now add the entries that may or may not exist:  the Felix ipv4
	// address and the host ASN.  If either config is not specified, set
	// the value to be nil to indicate to our default processing to delete
	// the entry rather than set it.
	if n.BGPIPv4Addr != nil {
		optional = append(optional, &model.KVPair{
			Key:   model.HostIPKey{nk.Hostname},
			Value: n.BGPIPv4Addr,
		})
	} else {
		optional = append(optional, &model.KVPair{
			Key: model.HostIPKey{nk.Hostname},
		})
	}

	if n.BGPASNumber != nil {
		optional = append(optional, &model.KVPair{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "as_num",
			},
			Value: n.BGPASNumber.String(),
		})
	} else {
		optional = append(optional, &model.KVPair{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "as_num",
			},
		})
	}
	if n.BGPIPv4Net != nil {
		optional = append(optional, &model.KVPair{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "network_v4",
			},
			Value: n.BGPIPv4Net.String(),
		})
	} else {
		optional = append(optional, &model.KVPair{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "network_v4",
			},
		})
	}
	if n.BGPIPv6Net != nil {
		optional = append(optional, &model.KVPair{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "network_v6",
			},
			Value: n.BGPIPv6Net.String(),
		})
	} else {
		optional = append(optional, &model.KVPair{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "network_v6",
			},
		})
	}
	if len(n.OrchRefs) > 0 {
		optional = append(optional, &model.KVPair{
			Key:   model.OrchRefKey{Hostname: nk.Hostname},
			Value: n.OrchRefs,
		})
	}

	return primary, optional
}

// toNodeDeleteComponents is similar to function toNodeComponents, but returns nil
// interface values which the applyOrDeleteSubcomponents method will treat as a delete.
func toNodeDeleteComponents(nk model.NodeKey) (primary *model.KVPair, optional []*model.KVPair) {

	primary = &model.KVPair{
		Key: model.HostMetadataKey{nk.Hostname},
	}
	optional = []*model.KVPair{
		{
			Key: model.HostIPKey{nk.Hostname},
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "ip_addr_v4",
			},
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "ip_addr_v6",
			},
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "as_num",
			},
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "network_v4",
			},
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: nk.Hostname,
				Name:     "network_v6",
			},
		},
		&model.KVPair{
			Key: model.OrchRefKey{
				Hostname: nk.Hostname,
			},
		},
	}

	return primary, optional
}

// toDatastoreGlobalBGPConfigKey modifies the Global BGP Config key to the one required by
// the datastore (for back-compatibility).
func toDatastoreGlobalBGPConfigKey(key model.GlobalBGPConfigKey) model.GlobalBGPConfigKey {
	switch key.Name {
	case "AsNumber":
		key = model.GlobalBGPConfigKey{Name: "as_num"}
	case "LogLevel":
		key = model.GlobalBGPConfigKey{Name: "loglevel"}
	case "NodeMeshEnabled":
		key = model.GlobalBGPConfigKey{Name: "node_mesh"}
	}
	return key
}

// toDatastoreGlobalBGPConfigList modifies the Global BGP Config List interface to the one required by
// the datastore (for back-compatibility with what is expected in the etcdv2 datastore driver).
func toDatastoreGlobalBGPConfigList(l model.GlobalBGPConfigListOptions) model.GlobalBGPConfigListOptions {
	switch l.Name {
	case "AsNumber":
		l = model.GlobalBGPConfigListOptions{Name: "as_num"}
	case "LogLevel":
		l = model.GlobalBGPConfigListOptions{Name: "loglevel"}
	case "NodeMeshEnabled":
		l = model.GlobalBGPConfigListOptions{Name: "node_mesh"}
	}
	return l
}

// fromDatastoreGlobalBGPKey modifies the Global BGP Config key from the one required by
// the datastore (for back-compatibility with what is expected in the etcdv2 datastore driver).
func fromDatastoreGlobalBGPKey(key model.GlobalBGPConfigKey) model.GlobalBGPConfigKey {
	switch key.Name {
	case "as_num":
		key = model.GlobalBGPConfigKey{Name: "AsNumber"}
	case "loglevel":
		key = model.GlobalBGPConfigKey{Name: "LogLevel"}
	case "node_mesh":
		key = model.GlobalBGPConfigKey{Name: "NodeMeshEnabled"}
	}
	return key
}

// toDatastoreGlobalBGPConfig modifies the Global BGP Config KVPair to the format required in the
// datastore (for back-compatibility with what is expected in the etcdv2 datastore driver).
func toDatastoreGlobalBGPConfig(d model.KVPair) *model.KVPair {
	// Copy the KVPair, so we aren't modifying the original.
	modifiedKey := toDatastoreGlobalBGPConfigKey(d.Key.(model.GlobalBGPConfigKey))
	d.Key = modifiedKey

	switch modifiedKey.Name {
	case "node_mesh":
		// In the datastore the node_mesh parm is expected to be a JSON object with an
		// enabled field, but the new value just uses a boolean string.
		if d.Value != nil {
			enabled := d.Value.(string) == "true"
			v, _ := json.Marshal(nodeToNodeMesh{Enabled: enabled})
			d.Value = string(v)
		}
	}

	return &d
}

// fromDatastoreGlobalBGPConfig modifies the Global BGP Config KVPair from the format required in the
// datastore (for back-compatibility with what is expected in the etcdv2 datastore driver).
func fromDatastoreGlobalBGPConfig(d model.KVPair) *model.KVPair {
	modifiedKey := fromDatastoreGlobalBGPKey(d.Key.(model.GlobalBGPConfigKey))
	d.Key = modifiedKey

	switch modifiedKey.Name {
	case "NodeMeshEnabled":
		// In the datastore the node_mesh parm is expected to be a JSON object with an
		// enabled field, but the new value just uses a boolean string.
		if d.Value != nil {
			var n nodeToNodeMesh
			if err := json.Unmarshal([]byte(d.Value.(string)), &n); err != nil {
				log.Info("Error parsing node to node mesh")
				v, _ := json.Marshal(false)
				d.Value = string(v)
			} else {
				log.Info("Returning configured node to node mesh")
				v, _ := json.Marshal(n.Enabled)
				d.Value = string(v)
			}
		}
	}

	return &d
}

// nodeToNodeMesh is a struct containing whether node-to-node mesh is enabled.  It can be
// JSON marshalled into the correct structure that is understood by the Calico BGP component.
type nodeToNodeMesh struct {
	Enabled bool `json:"enabled"`
}
