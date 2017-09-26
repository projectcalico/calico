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
	"context"

	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
)

// NetworkPolicyInterface has methods to work with NetworkPolicy resources.
type NetworkPolicyInterface interface {
	Create(ctx context.Context, res *apiv2.NetworkPolicy, opts options.SetOptions) (*apiv2.NetworkPolicy, error)
	Update(ctx context.Context, res *apiv2.NetworkPolicy, opts options.SetOptions) (*apiv2.NetworkPolicy, error)
	Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*apiv2.NetworkPolicy, error)
	Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*apiv2.NetworkPolicy, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv2.NetworkPolicyList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// networkPolicies implements NetworkPolicyInterface
type networkPolicies struct {
	client client
}

// Create takes the representation of a NetworkPolicy and creates it.  Returns the stored
// representation of the NetworkPolicy, and an error, if there is any.
func (r networkPolicies) Create(ctx context.Context, res *apiv2.NetworkPolicy, opts options.SetOptions) (*apiv2.NetworkPolicy, error) {
	out, err := r.client.resources.Create(ctx, opts, apiv2.KindNetworkPolicy, res)
	if out != nil {
		return out.(*apiv2.NetworkPolicy), err
	}
	return nil, err
}

// Update takes the representation of a NetworkPolicy and updates it. Returns the stored
// representation of the NetworkPolicy, and an error, if there is any.
func (r networkPolicies) Update(ctx context.Context, res *apiv2.NetworkPolicy, opts options.SetOptions) (*apiv2.NetworkPolicy, error) {
	out, err := r.client.resources.Update(ctx, opts, apiv2.KindNetworkPolicy, res)
	if out != nil {
		return out.(*apiv2.NetworkPolicy), err
	}
	return nil, err
}

// Delete takes name of the NetworkPolicy and deletes it. Returns an error if one occurs.
func (r networkPolicies) Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*apiv2.NetworkPolicy, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv2.KindNetworkPolicy, namespace, name)
	if out != nil {
		return out.(*apiv2.NetworkPolicy), err
	}
	return nil, err
}

// Get takes name of the NetworkPolicy, and returns the corresponding NetworkPolicy object,
// and an error if there is any.
func (r networkPolicies) Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*apiv2.NetworkPolicy, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv2.KindNetworkPolicy, namespace, name)
	if out != nil {
		return out.(*apiv2.NetworkPolicy), err
	}
	return nil, err
}

// List returns the list of NetworkPolicy objects that match the supplied options.
func (r networkPolicies) List(ctx context.Context, opts options.ListOptions) (*apiv2.NetworkPolicyList, error) {
	res := &apiv2.NetworkPolicyList{}
	if err := r.client.resources.List(ctx, opts, apiv2.KindNetworkPolicy, apiv2.KindNetworkPolicyList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the NetworkPolicies that match the
// supplied options.
func (r networkPolicies) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv2.KindNetworkPolicy)
}
