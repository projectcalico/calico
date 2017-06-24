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

package thirdparty

import (
	"encoding/json"

	"github.com/projectcalico/libcalico-go/lib/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GlobalBGPPeer is the ThirdPartyResource definition of a Calico Global BGP Peer resource in
// the Kubernetes API.
type GlobalBGPPeer struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`
	Spec            api.BGPPeerSpec   `json:"spec"`
}

// GlobalBGPPeer is a list of Calico Global BGP Peer resources.
type GlobalBGPPeerList struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ListMeta `json:"metadata"`
	Items           []GlobalBGPPeer `json:"items"`
}

// GetObjectKind returns the kind of this object.  Required to satisfy Object interface
func (e *GlobalBGPPeer) GetObjectKind() schema.ObjectKind {
	return &e.TypeMeta
}

// GetObjectMeta returns the object metadata of this object. Required to satisfy ObjectMetaAccessor interface
func (e *GlobalBGPPeer) GetObjectMeta() metav1.Object {
	return &e.Metadata
}

// GetObjectKind returns the kind of this object. Required to satisfy Object interface
func (el *GlobalBGPPeerList) GetObjectKind() schema.ObjectKind {
	return &el.TypeMeta
}

// GetListMeta returns the list metadata of this object. Required to satisfy ListMetaAccessor interface
func (el *GlobalBGPPeerList) GetListMeta() metav1.List {
	return &el.Metadata
}

// The code below is used only to work around a known problem with third-party
// resources and ugorji. If/when these issues are resolved, the code below
// should no longer be required.

type GlobalBGPPeerListCopy GlobalBGPPeerList
type GlobalBGPPeerCopy GlobalBGPPeer

func (g *GlobalBGPPeer) UnmarshalJSON(data []byte) error {
	tmp := GlobalBGPPeerCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := GlobalBGPPeer(tmp)
	*g = tmp2
	return nil
}

func (l *GlobalBGPPeerList) UnmarshalJSON(data []byte) error {
	tmp := GlobalBGPPeerListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := GlobalBGPPeerList(tmp)
	*l = tmp2
	return nil
}
