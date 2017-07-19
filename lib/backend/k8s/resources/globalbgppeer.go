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

package resources

import (
	"reflect"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/converter"
	"github.com/projectcalico/libcalico-go/lib/scope"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	GlobalBGPPeerResourceName = "globalbgppeers"
	GlobalBGPPeerTPRName      = "global-bgp-peer.projectcalico.org"
)

func NewGlobalBGPPeerClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            GlobalBGPPeerTPRName,
		resource:        GlobalBGPPeerResourceName,
		description:     "Calico Global BGP Peers",
		k8sResourceType: reflect.TypeOf(thirdparty.GlobalBgpPeer{}),
		k8sListType:     reflect.TypeOf(thirdparty.GlobalBgpPeerList{}),
		converter:       GlobalBGPPeerConverter{},
	}
}

// GlobalBGPPeerConverter implements the CustomK8sResourceConverter interface.
type GlobalBGPPeerConverter struct {
	// Since the Spec is identical to the Calico API Spec, we use the
	// API converter to convert to and from the model representation.
	converter.BGPPeerConverter
}

func (_ GlobalBGPPeerConverter) ListInterfaceToKey(l model.ListInterface) model.Key {
	pl := l.(model.GlobalBGPPeerListOptions)
	if pl.PeerIP.IP != nil {
		return model.GlobalBGPPeerKey{PeerIP: pl.PeerIP}
	}
	return nil
}

func (_ GlobalBGPPeerConverter) KeyToName(k model.Key) (string, error) {
	pk := k.(model.GlobalBGPPeerKey)

	// Convert the IP address to a k8s compatible name by replacing periods
	// and colons with dashes.
	return IPToResourceName(pk.PeerIP), nil
}

func (_ GlobalBGPPeerConverter) NameToKey(name string) (model.Key, error) {
	ip, err := ResourceNameToIP(name)
	if err != nil {
		return nil, err
	}

	return model.GlobalBGPPeerKey{
		PeerIP: *ip,
	}, nil
}

func (c GlobalBGPPeerConverter) ToKVPair(r CustomK8sResource) (*model.KVPair, error) {
	// Since we are using the Calico API Spec definition to store the Calico
	// BGP Peer, use the client conversion helper to convert between KV and API.
	t := r.(*thirdparty.GlobalBgpPeer)
	ip, err := ResourceNameToIP(t.Metadata.Name)
	if err != nil {
		return nil, err
	}

	peer := api.BGPPeer{
		Metadata: api.BGPPeerMetadata{
			PeerIP: *ip,
			Scope:  scope.Global,
		},
		Spec: t.Spec,
	}
	kvp, err := c.ConvertAPIToKVPair(peer)
	if err != nil {
		return nil, err
	}
	kvp.Revision = t.Metadata.ResourceVersion

	return kvp, nil
}

func (c GlobalBGPPeerConverter) FromKVPair(kvp *model.KVPair) (CustomK8sResource, error) {
	r, err := c.ConvertKVPairToAPI(kvp)
	if err != nil {
		return nil, err
	}

	tprName, err := c.KeyToName(kvp.Key)
	if err != nil {
		return nil, err
	}

	tpr := thirdparty.GlobalBgpPeer{
		Metadata: metav1.ObjectMeta{
			Name: tprName,
		},
		Spec: r.(*api.BGPPeer).Spec,
	}
	if kvp.Revision != nil {
		tpr.Metadata.ResourceVersion = kvp.Revision.(string)
	}
	return &tpr, nil
}
