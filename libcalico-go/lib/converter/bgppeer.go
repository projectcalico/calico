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

package converter

import (
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/scope"
)

// BGPPeerConverter implements a set of functions used for converting between
// API and backend representations of the BGPPeer resource.
type BGPPeerConverter struct{}

// ConvertMetadataToKey converts a BGPPeerMetadata to a GlobalBGPPeerKey or HostBGPPeerKey.
func (p BGPPeerConverter) ConvertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	pm := m.(api.BGPPeerMetadata)

	if pm.Scope == scope.Global {
		return model.GlobalBGPPeerKey{
			PeerIP: pm.PeerIP,
		}, nil
	} else if pm.Scope == scope.Node {
		return model.NodeBGPPeerKey{
			PeerIP:   pm.PeerIP,
			Nodename: pm.Node,
		}, nil
	} else {
		return nil, errors.ErrorInsufficientIdentifiers{
			Name: "scope",
		}
	}
}

// ConvertAPIToKVPair converts an API Policy structure to a KVPair containing a
// backend BGPPeer and GlobalBGPPeerKey/HostBGPPeerKey.
func (p BGPPeerConverter) ConvertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	ap := a.(api.BGPPeer)
	k, err := p.ConvertMetadataToKey(ap.Metadata)
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

// ConvertKVPairToAPI converts a KVPair containing a backend BGPPeer and GlobalBGPPeerKey/HostBGPPeerKey
// to an API BGPPeer structure.
func (p BGPPeerConverter) ConvertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	apiBGPPeer := api.NewBGPPeer()

	switch k := d.Key.(type) {
	case model.GlobalBGPPeerKey:
		apiBGPPeer.Metadata.Scope = scope.Global
		apiBGPPeer.Metadata.PeerIP = k.PeerIP
		apiBGPPeer.Metadata.Node = ""
	case model.NodeBGPPeerKey:
		apiBGPPeer.Metadata.Scope = scope.Node
		apiBGPPeer.Metadata.PeerIP = k.PeerIP
		apiBGPPeer.Metadata.Node = k.Nodename
	}

	backendBGPPeer := d.Value.(*model.BGPPeer)
	apiBGPPeer.Spec.ASNumber = backendBGPPeer.ASNum

	return apiBGPPeer, nil
}
