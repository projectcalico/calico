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
	"github.com/projectcalico/calico/libcalico-go/lib/scope"
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
	converter.BGPPeerConverter
	c *Client
}

// newBGPPeers returns a new BGPPeerInterface bound to the supplied client.
func newBGPPeers(c *Client) BGPPeerInterface {
	return &bgpPeers{c: c}
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

	// Global and host peers are listed separately.  Work out which we need
	// to list.
	listGlobal := metadata.Scope == scope.Global || (metadata.Scope == scope.Undefined && metadata.Node == "")
	listNode := metadata.Scope == scope.Node || metadata.Scope == scope.Undefined

	// Tweak the scope of the Metadata so that we are performing a list within
	// a specific scope.
	if listGlobal {
		metadata.Scope = scope.Global
		if err := h.c.list(metadata, h, l); err != nil {
			return nil, err
		}
	}
	if listNode {
		metadata.Scope = scope.Node
		if err := h.c.list(metadata, h, l); err != nil {
			return nil, err
		}
	}

	return l, nil
}

// convertMetadataToListInterface converts a BGPPeerMetadata to a BGPPeerListOptions.
// This is part of the conversionHelper interface.
func (h *bgpPeers) convertMetadataToListInterface(m unversioned.ResourceMetadata) (model.ListInterface, error) {
	pm := m.(api.BGPPeerMetadata)
	if pm.Scope == scope.Global {
		return model.GlobalBGPPeerListOptions{
			PeerIP: pm.PeerIP,
		}, nil
	} else {
		return model.NodeBGPPeerListOptions{
			PeerIP:   pm.PeerIP,
			Nodename: pm.Node,
		}, nil
	}
}

// convertMetadataToKey converts a BGPPeerMetadata to a HostBGPPeerKey/GlobalBGPPeerKey
// This is part of the conversionHelper interface.
func (h *bgpPeers) convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	return h.ConvertMetadataToKey(m)
}

// convertAPIToKVPair converts an API BGPPeer structure to a KVPair containing a
// backend BGPPeer and HostBGPPeerKey/GlobalBGPPeerKey.
// This is part of the conversionHelper interface.
func (h *bgpPeers) convertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	return h.ConvertAPIToKVPair(a)
}

// convertKVPairToAPI converts a KVPair containing a backend BGPPeer and HostBGPPeerKey/GlobalBGPPeerKey
// to an API BGPPeer structure.
// This is part of the conversionHelper interface.
func (h *bgpPeers) convertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	return h.ConvertKVPairToAPI(d)
}
