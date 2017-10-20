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
	"github.com/projectcalico/libcalico-go/lib/ipip"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync IPPool data in v1 format for
// consumption by both Felix and the BGP daemon.
func NewIPPoolUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewConflictResolvingCacheUpdateProcessor(apiv2.KindIPPool, convertIPPoolV2ToV1)
}

// Convert v2 KVPair to the equivalent v1 KVPair.
func convertIPPoolV2ToV1(kvp *model.KVPair) (*model.KVPair, error) {
	// Validate against incorrect key/value kinds.  This indicates a code bug rather
	// than a user error.
	v2key, ok := kvp.Key.(model.ResourceKey)
	if !ok || v2key.Kind != apiv2.KindIPPool {
		return nil, errors.New("Key is not a valid BGPPeer resource key")
	}
	v2res, ok := kvp.Value.(*apiv2.IPPool)
	if !ok {
		return nil, errors.New("Value is not a valid BGPPeer resource key")
	}

	// Correct data types.  Handle the conversion.
	_, cidr, err := cnet.ParseCIDR(v2res.Spec.CIDR)
	if err != nil {
		return nil, err
	}
	v1key := model.IPPoolKey{
		CIDR: *cidr,
	}
	var ipipInterface string
	var ipipMode ipip.Mode
	switch v2res.Spec.IPIPMode {
	case apiv2.IPIPModeAlways:
		ipipInterface = "tunl0"
		ipipMode = ipip.Always
	case apiv2.IPIPModeCrossSubnet:
		ipipInterface = "tunl0"
		ipipMode = ipip.CrossSubnet
	default:
		ipipInterface = ""
		ipipMode = ipip.Undefined
	}

	return &model.KVPair{
		Key: v1key,
		Value: &model.IPPool{
			CIDR:          *cidr,
			IPIPInterface: ipipInterface,
			IPIPMode:      ipipMode,
			Masquerade:    v2res.Spec.NATOutgoing,
			IPAM:          !v2res.Spec.Disabled,
			Disabled:      v2res.Spec.Disabled,
		},
		Revision: kvp.Revision,
	}, nil
}
