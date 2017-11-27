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

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync IPPool data in v1 format for
// consumption by both Felix and the BGP daemon.
func NewBGPPeerUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewConflictResolvingCacheUpdateProcessor(apiv3.KindBGPPeer, convertBGPPeerV2ToV1)
}

// Convert v3 KVPair to the equivalent v1 KVPair.
func convertBGPPeerV2ToV1(kvp *model.KVPair) (*model.KVPair, error) {
	// Validate against incorrect key/value kinds.  This indicates a code bug rather
	// than a user error.
	v3key, ok := kvp.Key.(model.ResourceKey)
	if !ok || v3key.Kind != apiv3.KindBGPPeer {
		return nil, errors.New("Key is not a valid BGPPeer resource key")
	}
	v3res, ok := kvp.Value.(*apiv3.BGPPeer)
	if !ok {
		return nil, errors.New("Value is not a valid BGPPeer resource value")
	}

	// Correct data types.  Handle the conversion.  Start with the v1 key.  The PeerIP and
	// the Node are now in the Spec - if a Node is not specified then this is a global
	// peer.
	ip := cnet.ParseIP(v3res.Spec.PeerIP)
	if ip == nil {
		return nil, errors.New("PeerIP is not assigned or is malformed")
	}
	var v1key model.Key
	if node := v3res.Spec.Node; len(node) == 0 {
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
			ASNum:  v3res.Spec.ASNumber,
		},
		Revision: kvp.Revision,
	}, nil
}
