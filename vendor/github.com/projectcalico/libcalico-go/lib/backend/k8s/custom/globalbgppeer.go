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

package custom

import (
	"encoding/json"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/scope"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// BGPPeer is the CustomResourceDefinition of a Calico BGP Peer resource in
// the Kubernetes API.
type BGPPeer struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`
	Spec            BGPPeerSpec       `json:"spec"`
}

type BGPPeerSpec struct {
	api.BGPPeerSpec
	Scope  scope.Scope `json:"scope"`
	Node   string      `json:"node,omitempty"`
	PeerIP net.IP      `json:"peerIP"`
}

// BGPPeerList is a list of Calico Global BGP Peer resources.
type BGPPeerList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta `json:"metadata"`
	Items           []BGPPeer       `json:"items"`
}

// GetObjectKind returns the kind of this object.  Required to satisfy Object interface
func (e *BGPPeer) GetObjectKind() schema.ObjectKind {
	return &e.TypeMeta
}

// GetObjectMeta returns the object metadata of this object. Required to satisfy ObjectMetaAccessor interface
func (e *BGPPeer) GetObjectMeta() metav1.Object {
	return &e.Metadata
}

// GetObjectKind returns the kind of this object. Required to satisfy Object interface
func (el *BGPPeerList) GetObjectKind() schema.ObjectKind {
	return &el.TypeMeta
}

// GetListMeta returns the list metadata of this object. Required to satisfy ListMetaAccessor interface
func (el *BGPPeerList) GetListMeta() metav1.List {
	return &el.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type BGPPeerListCopy BGPPeerList
type BGPPeerCopy BGPPeer

func (g *BGPPeer) UnmarshalJSON(data []byte) error {
	tmp := BGPPeerCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := BGPPeer(tmp)
	*g = tmp2
	return nil
}

func (l *BGPPeerList) UnmarshalJSON(data []byte) error {
	tmp := BGPPeerListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := BGPPeerList(tmp)
	*l = tmp2
	return nil
}
