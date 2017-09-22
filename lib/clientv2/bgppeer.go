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

package clientv2

import (
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
)

// BGPPeerInterface has methods to work with BGPPeer resources.
type BGPPeerInterface interface {
	Create(res *apiv2.BGPPeer, opts options.SetOptions) (*apiv2.BGPPeer, error)
	Update(res *apiv2.BGPPeer, opts options.SetOptions) (*apiv2.BGPPeer, error)
	Delete(name string, opts options.DeleteOptions) error
	Get(name string, opts options.GetOptions) (*apiv2.BGPPeer, error)
	List(opts options.ListOptions) (*apiv2.BGPPeerList, error)
	Watch(opts options.ListOptions) (watch.Interface, error)
}

// bgpPeers implements BGPPeerInterface
type bgpPeers struct {
	client client
}

// Create takes the representation of a BGPPeer and creates it.  Returns the stored
// representation of the BGPPeer, and an error, if there is any.
func (r bgpPeers) Create(res *apiv2.BGPPeer, opts options.SetOptions) (*apiv2.BGPPeer, error) {
	out, err := r.client.resources.Create(opts, apiv2.KindBGPPeer, NoNamespace, res)
	if out != nil {
		return out.(*apiv2.BGPPeer), err
	}
	return nil, err
}

// Update takes the representation of a BGPPeer and updates it. Returns the stored
// representation of the BGPPeer, and an error, if there is any.
func (r bgpPeers) Update(res *apiv2.BGPPeer, opts options.SetOptions) (*apiv2.BGPPeer, error) {
	out, err := r.client.resources.Update(opts, apiv2.KindBGPPeer, NoNamespace, res)
	if out != nil {
		return out.(*apiv2.BGPPeer), err
	}
	return nil, err
}

// Delete takes name of the BGPPeer and deletes it. Returns an error if one occurs.
func (r bgpPeers) Delete(name string, opts options.DeleteOptions) error {
	err := r.client.resources.Delete(opts, apiv2.KindBGPPeer, NoNamespace, name)
	return err
}

// Get takes name of the BGPPeer, and returns the corresponding BGPPeer object,
// and an error if there is any.
func (r bgpPeers) Get(name string, opts options.GetOptions) (*apiv2.BGPPeer, error) {
	out, err := r.client.resources.Get(opts, apiv2.KindBGPPeer, NoNamespace, name)
	if out != nil {
		return out.(*apiv2.BGPPeer), err
	}
	return nil, err
}

// List returns the list of BGPPeer objects that match the supplied options.
func (r bgpPeers) List(opts options.ListOptions) (*apiv2.BGPPeerList, error) {
	res := &apiv2.BGPPeerList{}
	if err := r.client.resources.List(opts, apiv2.KindBGPPeer, apiv2.KindBGPPeerList, NoNamespace, AllNames, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the BGPPeers that match the
// supplied options.
func (r bgpPeers) Watch(opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(opts, apiv2.KindBGPPeer, NoNamespace, AllNames)
}
