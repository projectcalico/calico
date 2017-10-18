// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package updateprocessors

import (
	"errors"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync IPPool data in v1 format for
// consumption by both Felix and the BGP daemon.
func NewBGPPeerUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewConflictResolvingCacheUpdateProcessor(apiv2.KindBGPPeer, convertBGPPeerV2ToV1)
}

// Convert v2 KVPair to the equivalent v1 KVPair.
func convertBGPPeerV2ToV1(kvp *model.KVPair) (*model.KVPair, error) {
	// Validate against incorrect key/value kinds.  This indicates a code bug rather
	// than a user error.
	v2key, ok := kvp.Key.(model.ResourceKey)
	if !ok || v2key.Kind != apiv2.KindBGPPeer {
		return nil, errors.New("Key is not a valid IPPool resource key")
	}
	v2res, ok := kvp.Value.(*apiv2.BGPPeer)
	if !ok {
		return nil, errors.New("Value is not a valid IPPool resource key")
	}

	// Correct data types.  Handle the conversion.  Start with the v1 key.  The PeerIP and
	// the Node are now in the Spec - if a Node is not specified then this is a global
	// peer.
	ip := cnet.ParseIP(v2res.Spec.PeerIP)
	if ip == nil {
		return nil, errors.New("PeerIP is not assigned or is malformed")
	}
	var v1key model.Key
	if node := v2res.Spec.Node; len(node) == 0 {
		v1key = model.GlobalBGPPeerKey{
			PeerIP: *ip,
		}
	} else {
		v1key = model.NodeBGPPeerKey{
			PeerIP:   *ip,
			Nodename: node,
		}
	}

	return &model.KVPair{
		Key: v1key,
		Value: &model.BGPPeer{
			PeerIP: *ip,
			ASNum:  v2res.Spec.ASNumber,
		},
		Revision: kvp.Revision,
	}, nil
}
