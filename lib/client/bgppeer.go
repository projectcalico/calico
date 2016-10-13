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

// BGPPeerInterface has methods to work with BGPPeer resources.
type BGPPeerInterface interface {
	List(api.BGPPeerMetadata) (*api.BGPPeerList, error)
	Get(api.BGPPeerMetadata) (*api.BGPPeer, error)
	Create(*api.BGPPeer) (*api.BGPPeer, error)
	Update(*api.BGPPeer) (*api.BGPPeer, error)
	Apply(*api.BGPPeer) (*api.BGPPeer, error)
	Delete(api.BGPPeerMetadata) error
}

// bgpPeers implements BGPPeerInterface
type bgpPeers struct {
	c *Client
}

// newBGPPeers returns a new BGPPeerInterface bound to the supplied client.
func newBGPPeers(c *Client) BGPPeerInterface {
	return &bgpPeers{c}
}

// Create creates a new BGP peer.
func (h *bgpPeers) Create(a *api.BGPPeer) (*api.BGPPeer, error) {
	return a, h.c.create(*a, h)
}

// Update updates an existing BGP peer.
func (h *bgpPeers) Update(a *api.BGPPeer) (*api.BGPPeer, error) {
	return a, h.c.update(*a, h)
}

// Apply updates a BGP peer if it exists, or creates a new BGP peer if it does not exist.
func (h *bgpPeers) Apply(a *api.BGPPeer) (*api.BGPPeer, error) {
	return a, h.c.apply(*a, h)
}

// Delete deletes an existing BGP peer.
func (h *bgpPeers) Delete(metadata api.BGPPeerMetadata) error {
	return h.c.delete(metadata, h)
}

// Get returns information about a particular BGP peer.
func (h *bgpPeers) Get(metadata api.BGPPeerMetadata) (*api.BGPPeer, error) {
	if a, err := h.c.get(metadata, h); err != nil {
		return nil, err
	} else {
		return a.(*api.BGPPeer), nil
	}
}

// List takes a Metadata, and returns a BGPPeerList that contains the list of BGP peers
// that match the Metadata (wildcarding missing fields).
func (h *bgpPeers) List(metadata api.BGPPeerMetadata) (*api.BGPPeerList, error) {
	l := api.NewBGPPeerList()
	err := h.c.list(metadata, h, l)
	return l, err
}

// convertMetadataToListInterface converts a BGPPeerMetadata to a BGPPeerListOptions.
// This is part of the conversionHelper interface.
func (h *bgpPeers) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	pm := m.(api.BGPPeerMetadata)
	l := model.BGPPeerListOptions{
		Scope:    pm.Scope,
		PeerIP:   pm.PeerIP,
		Hostname: pm.Hostname,
	}
	return l, nil
}

// convertMetadataToKey converts a BGPPeerMetadata to a BGPPeerKey
// This is part of the conversionHelper interface.
func (h *bgpPeers) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	pm := m.(api.BGPPeerMetadata)
	k := model.BGPPeerKey{
		Scope:    pm.Scope,
		PeerIP:   pm.PeerIP,
		Hostname: pm.Hostname,
	}
	return k, nil
}

// convertAPIToKVPair converts an API BGPPeer structure to a KVPair containing a
// backend BGPPeer and BGPPeerKey.
// This is part of the conversionHelper interface.
func (h *bgpPeers) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	ap := a.(api.BGPPeer)
	k, err := h.convertMetadataToKey(ap.Metadata)
	if err != nil {
		return nil, err
	}

	d := model.KVPair{
		Key: k,
		Value: &model.BGPPeer{
			PeerIP: ap.Metadata.PeerIP,
			ASNum:  ap.Spec.ASNumber,
		},
	}

	return &d, nil
}

// convertKVPairToAPI converts a KVPair containing a backend BGPPeer and BGPPeerKey
// to an API BGPPeer structure.
// This is part of the conversionHelper interface.
func (h *bgpPeers) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	backendBGPPeer := d.Value.(*model.BGPPeer)
	backendBGPPeerKey := d.Key.(model.BGPPeerKey)

	apiBGPPeer := api.NewBGPPeer()
	apiBGPPeer.Metadata.Scope = backendBGPPeerKey.Scope
	apiBGPPeer.Metadata.PeerIP = backendBGPPeerKey.PeerIP
	apiBGPPeer.Metadata.Hostname = backendBGPPeerKey.Hostname
	apiBGPPeer.Spec.ASNumber = backendBGPPeer.ASNum

	return apiBGPPeer, nil
}
