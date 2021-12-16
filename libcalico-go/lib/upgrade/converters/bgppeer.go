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

package converters

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/scope"
)

// BGPPeer implements the Converter interface.
type BGPPeer struct{}

// APIV1ToBackendV1 converts v1 BGPPeer API to v1 BGPPeer KVPair.
func (bp BGPPeer) APIV1ToBackendV1(rIn unversioned.Resource) (*model.KVPair, error) {
	ap, ok := rIn.(*apiv1.BGPPeer)
	if !ok {
		return nil, fmt.Errorf("Conversion to BGPPeer is not possible with %v", rIn)
	}

	if len(ap.Metadata.PeerIP.IP) == 0 {
		return nil, fmt.Errorf("no PeerIP is set, invalid BGPPeer: %v", rIn)
	}

	k, err := bp.convertMetadataToKey(ap.Metadata)
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

	log.WithFields(log.Fields{
		"APIV1":  rIn,
		"KVPair": d,
	}).Debug("Converted BGPPeer")

	return &d, nil
}

func (_ BGPPeer) convertMetadataToKey(bpm apiv1.BGPPeerMetadata) (model.Key, error) {
	if bpm.Scope == scope.Global {
		if bpm.Node != "" {
			return nil, fmt.Errorf("With Global scope having a Node is invalid: %v", bpm)
		}
		return model.GlobalBGPPeerKey{
			PeerIP: bpm.PeerIP,
		}, nil
	} else if bpm.Scope == scope.Node {
		if bpm.Node == "" {
			return nil, fmt.Errorf("With Node scope a Node must be defined: %v", bpm)
		}
		return model.NodeBGPPeerKey{
			PeerIP:   bpm.PeerIP,
			Nodename: bpm.Node,
		}, nil
	} else {
		return nil, errors.ErrorInsufficientIdentifiers{
			Name: "scope",
		}
	}
}

// BackendV1ToAPIV3 converts v1 BGPPeer KVPair to v3 API.
func (bp BGPPeer) BackendV1ToAPIV3(kvp *model.KVPair) (Resource, error) {
	peer, ok := kvp.Value.(*model.BGPPeer)
	if !ok {
		return nil, fmt.Errorf("value is not a valid BGPPeer resource Value: %v", kvp.Value)
	}

	r := apiv3.NewBGPPeer()
	r.Spec = apiv3.BGPPeerSpec{
		PeerIP:   peer.PeerIP.String(),
		ASNumber: peer.ASNum,
	}

	switch kvp.Key.(type) {
	case model.GlobalBGPPeerKey:
		r.ObjectMeta = v1.ObjectMeta{Name: convertIpToName(peer.PeerIP.IP)}
	case model.NodeBGPPeerKey:
		nk := kvp.Key.(model.NodeBGPPeerKey)

		// Node names are normalized but we don't add any qualifying hashes (so we just use
		// the normalizeName function to convert).
		n := ConvertNodeName(nk.Nodename)
		r.Spec.Node = n
		r.ObjectMeta = v1.ObjectMeta{Name: n + "." + convertIpToName(peer.PeerIP.IP)}
	default:
		return nil, fmt.Errorf("Invalid key for BGPPeer: %v", kvp.Key)
	}

	log.WithFields(log.Fields{
		"KVPair": *kvp,
		"APIV3":  r,
	}).Debug("Converted BGPPeer")
	return r, nil
}
