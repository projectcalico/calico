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
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	"k8s.io/client-go/kubernetes"
)

const (
	perNodeBgpPeerAnnotationNamespace = "peer.bgp.projectcalico.org"
)

func NewNodeBGPPeerClient(c *kubernetes.Clientset) K8sResourceClient {
	return NewCustomK8sNodeResourceClient(CustomK8sNodeResourceClientConfig{
		ClientSet:    c,
		ResourceType: "NodeBGPPeer",
		Converter:    NodeBGPPeerConverter{},
		Namespace:    perNodeBgpPeerAnnotationNamespace,
	})
}

// NodeBGPPeerConverter implements the CustomK8sNodeResourceConverter interface.
type NodeBGPPeerConverter struct{}

func (_ NodeBGPPeerConverter) ListInterfaceToNodeAndName(l model.ListInterface) (string, string, error) {
	pl := l.(model.NodeBGPPeerListOptions)
	if pl.PeerIP.IP == nil {
		return pl.Nodename, "", nil
	} else {
		return pl.Nodename, IPToResourceName(pl.PeerIP), nil
	}
}

func (_ NodeBGPPeerConverter) KeyToNodeAndName(k model.Key) (string, string, error) {
	pk := k.(model.NodeBGPPeerKey)
	return pk.Nodename, IPToResourceName(pk.PeerIP), nil
}

func (_ NodeBGPPeerConverter) NodeAndNameToKey(node, name string) (model.Key, error) {
	ip, err := ResourceNameToIP(name)
	if err != nil {
		return nil, err
	}

	return model.NodeBGPPeerKey{
		Nodename: node,
		PeerIP:   *ip,
	}, nil
}
