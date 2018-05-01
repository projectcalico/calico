// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.
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

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator/clients/v1/etcdv2"
)

type ModelAdaptor struct {
	client *etcdv2.EtcdClient
}

func NewAdaptor(c *etcdv2.EtcdClient) *ModelAdaptor {
	return &ModelAdaptor{client: c}
}

// IsKDD() returns true if this backend is KDD.  Since the compat module is only
// used for etcdv2, this returns false.
func (c *ModelAdaptor) IsKDD() bool {
	return false
}

func (c *ModelAdaptor) Update(d *model.KVPair) (*model.KVPair, error) {
	return c.client.Update(d)
}

// Apply - this just calls through to the datastore driver (the upgrade code only
// needs Apply to set the Ready flag, so we don't need any of the complicated conversion
// code here).
func (c *ModelAdaptor) Apply(d *model.KVPair) (*model.KVPair, error) {
	return c.client.Apply(d)
}

// Get an entry from the datastore.  This errors if the entry does not exist.
func (c *ModelAdaptor) Get(k model.Key) (*model.KVPair, error) {
	switch kt := k.(type) {
	case model.ProfileKey:
		return c.getProfile(k)
	case model.NodeKey:
		return c.getNode(kt)
	case model.BlockKey:
		return c.getBlock(k)
	case model.GlobalBGPConfigKey:
		nk := toDatastoreGlobalBGPConfigKey(kt)
		if kvp, err := c.client.Get(nk); err != nil {
			return nil, errors.UpdateErrorIdentifier(err, k)
		} else {
			return fromDatastoreGlobalBGPConfig(*kvp), nil
		}
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
	case model.BlockListOptions:
		return c.listBlock(lt)
	case model.GlobalBGPConfigListOptions:
		nl := toDatastoreGlobalBGPConfigList(lt)
		if kvps, err := c.client.List(nl); err != nil {
			return nil, errors.UpdateErrorIdentifier(err, l)
		} else {
			for i, kvp := range kvps {
				kvps[i] = fromDatastoreGlobalBGPConfig(*kvp)
			}
			return kvps, nil
		}
	default:
		return c.client.List(l)
	}
}

// getProfile gets the composite profile by getting the individual components
// and joining the results together.
func (c *ModelAdaptor) getProfile(k model.Key) (*model.KVPair, error) {
	var t, l, r *model.KVPair
	var err error
	pk := k.(model.ProfileKey)

	if t, err = c.client.Get(model.ProfileTagsKey{ProfileKey: pk}); err != nil {
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
	if l, err = c.client.Get(model.ProfileLabelsKey{ProfileKey: pk}); err == nil {
		p.Labels = l.Value.(map[string]string)
	}
	if r, err = c.client.Get(model.ProfileRulesKey{ProfileKey: pk}); err == nil {
		p.Rules = *r.Value.(*model.ProfileRules)
	}
	return &d, nil
}

// getBlock gets KVPair for Block. It gets the block value first,
// then checks for `Affinity` field first, then `HostAffinity` as a backup.
// For more details see: https://github.com/projectcalico/libcalico-go/issues/226
func (c *ModelAdaptor) getBlock(k model.Key) (*model.KVPair, error) {
	bk := k.(model.BlockKey)

	v, err := c.client.Get(model.BlockKey{CIDR: bk.CIDR})
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
func (c *ModelAdaptor) getNode(nk model.NodeKey) (*model.KVPair, error) {
	var err error

	// Fill in the Metadata specific part of the node configuration.  At the
	// moment, there is nothing to fill in.
	if _, err = c.client.Get(model.HostMetadataKey{Hostname: nk.Hostname}); err != nil {
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

// listBlock returns list of KVPairs for Block, includes making sure
// backwards compatiblity. See getBlock for more details.
func (c *ModelAdaptor) listBlock(l model.BlockListOptions) ([]*model.KVPair, error) {

	// Get a list of block KVPairs.
	blockList, err := c.client.List(l)
	if err != nil {
		return nil, err
	}

	// Create an empty slice of KVPair.
	results := make([]*model.KVPair, len(blockList))

	// Go through the list to make sure Affinity field has a proper value,
	// and maps the value to Affinity if the deprecated HostAffinity field is used
	// by calling ensureBlockAffinity, and populate the KVPair slice to return.
	for i, bkv := range blockList {
		results[i] = ensureBlockAffinity(bkv)
	}

	return results, nil
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
func (c *ModelAdaptor) getNodeSubcomponents(nk model.NodeKey, nv *model.Node) error {
	var component *model.KVPair
	var err error
	var strval string

	// Fill in the Metadata specific part of the node configuration.
	if component, err = c.client.Get(model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "ip_addr_v4"}); err == nil {
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

	if component, err = c.client.Get(model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "network_v4"}); err == nil {
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

	if component, err = c.client.Get(model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "ip_addr_v6"}); err == nil {
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

	if component, err = c.client.Get(model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "network_v6"}); err == nil {
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

	if component, err = c.client.Get(model.NodeBGPConfigKey{Nodename: nk.Hostname, Name: "as_num"}); err == nil {
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

	if component, err := c.client.Get(model.OrchRefKey{Hostname: nk.Hostname}); err == nil {
		nv.OrchRefs = component.Value.([]model.OrchRef)
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
		Key:   model.ProfileTagsKey{ProfileKey: pk},
		Value: p.Tags,
	}
	l = &model.KVPair{
		Key:   model.ProfileLabelsKey{ProfileKey: pk},
		Value: p.Labels,
	}
	r = &model.KVPair{
		Key:   model.ProfileRulesKey{ProfileKey: pk},
		Value: &p.Rules,
	}

	return t, l, r
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
// the datastore (for back-compatibility with what is expected in teh etcdv2 datastore driver).
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
// the datastore (for back-compatibility with what is expected in teh etcdv2 datastore driver).
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

// fromDatastoreGlobalBGPConfig modifies the Global BGP Config KVPair from the format required in the
// datastore (for back-compatibility with what is expected in teh etcdv2 datastore driver).
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
