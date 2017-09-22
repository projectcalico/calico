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

// NetworkPolicyInterface has methods to work with NetworkPolicy resources.
type NetworkPolicyInterface interface {
	Create(peer *apiv2.NetworkPolicy, opts options.SetOptions) (*apiv2.NetworkPolicy, error)
	Update(peer *apiv2.NetworkPolicy, opts options.SetOptions) (*apiv2.NetworkPolicy, error)
	Delete(name string, opts options.DeleteOptions) error
	Get(name string, opts options.GetOptions) (*apiv2.NetworkPolicy, error)
	List(opts options.ListOptions) (*apiv2.NetworkPolicyList, error)
	Watch(opts options.ListOptions) (watch.Interface, error)
}

// networkPolicies implements NetworkPolicyInterface
type networkPolicies struct {
	client    client
	namespace string
}

// Create takes the representation of a NetworkPolicy and creates it.  Returns the stored
// representation of the NetworkPolicy, and an error, if there is any.
func (r networkPolicies) Create(res *apiv2.NetworkPolicy, opts options.SetOptions) (*apiv2.NetworkPolicy, error) {
	out, err := r.client.resources.Create(opts, apiv2.KindNetworkPolicy, r.namespace, res)
	if out != nil {
		return out.(*apiv2.NetworkPolicy), err
	}
	return nil, err
}

// Update takes the representation of a NetworkPolicy and updates it. Returns the stored
// representation of the NetworkPolicy, and an error, if there is any.
func (r networkPolicies) Update(res *apiv2.NetworkPolicy, opts options.SetOptions) (*apiv2.NetworkPolicy, error) {
	out, err := r.client.resources.Update(opts, apiv2.KindNetworkPolicy, r.namespace, res)
	if out != nil {
		return out.(*apiv2.NetworkPolicy), err
	}
	return nil, err
}

// Delete takes name of the NetworkPolicy and deletes it. Returns an error if one occurs.
func (r networkPolicies) Delete(name string, opts options.DeleteOptions) error {
	err := r.client.resources.Delete(opts, apiv2.KindNetworkPolicy, r.namespace, name)
	return err
}

// Get takes name of the NetworkPolicy, and returns the corresponding NetworkPolicy object,
// and an error if there is any.
func (r networkPolicies) Get(name string, opts options.GetOptions) (*apiv2.NetworkPolicy, error) {
	out, err := r.client.resources.Get(opts, apiv2.KindNetworkPolicy, r.namespace, name)
	if out != nil {
		return out.(*apiv2.NetworkPolicy), err
	}
	return nil, err
}

// List returns the list of NetworkPolicy objects that match the supplied options.
func (r networkPolicies) List(opts options.ListOptions) (*apiv2.NetworkPolicyList, error) {
	res := &apiv2.NetworkPolicyList{}
	if err := r.client.resources.List(opts, apiv2.KindNetworkPolicy, apiv2.KindNetworkPolicyList, r.namespace, AllNames, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the NetworkPolicies that match the
// supplied options.
func (r networkPolicies) Watch(opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(opts, apiv2.KindNetworkPolicy, r.namespace, AllNames)
}
