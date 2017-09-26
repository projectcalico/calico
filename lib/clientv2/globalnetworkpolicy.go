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

// GlobalNetworkPolicyInterface has methods to work with GlobalNetworkPolicy resources.
type GlobalNetworkPolicyInterface interface {
	Create(ctx context.Context, res *apiv2.GlobalNetworkPolicy, opts options.SetOptions) (*apiv2.GlobalNetworkPolicy, error)
	Update(ctx context.Context, res *apiv2.GlobalNetworkPolicy, opts options.SetOptions) (*apiv2.GlobalNetworkPolicy, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv2.GlobalNetworkPolicy, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.GlobalNetworkPolicy, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv2.GlobalNetworkPolicyList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// globalnetworkpolicies implements GlobalNetworkPolicyInterface
type globalnetworkpolicies struct {
	client client
}

// Create takes the representation of a GlobalNetworkPolicy and creates it.  Returns the stored
// representation of the GlobalNetworkPolicy, and an error, if there is any.
func (r globalnetworkpolicies) Create(ctx context.Context, res *apiv2.GlobalNetworkPolicy, opts options.SetOptions) (*apiv2.GlobalNetworkPolicy, error) {
	out, err := r.client.resources.Create(ctx, opts, apiv2.KindGlobalNetworkPolicy, res)
	if out != nil {
		return out.(*apiv2.GlobalNetworkPolicy), err
	}
	return nil, err
}

// Update takes the representation of a GlobalNetworkPolicy and updates it. Returns the stored
// representation of the GlobalNetworkPolicy, and an error, if there is any.
func (r globalnetworkpolicies) Update(ctx context.Context, res *apiv2.GlobalNetworkPolicy, opts options.SetOptions) (*apiv2.GlobalNetworkPolicy, error) {
	out, err := r.client.resources.Update(ctx, opts, apiv2.KindGlobalNetworkPolicy, res)
	if out != nil {
		return out.(*apiv2.GlobalNetworkPolicy), err
	}
	return nil, err
}

// Delete takes name of the GlobalNetworkPolicy and deletes it. Returns an error if one occurs.
func (r globalnetworkpolicies) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv2.GlobalNetworkPolicy, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv2.KindGlobalNetworkPolicy, noNamespace, name)
	if out != nil {
		return out.(*apiv2.GlobalNetworkPolicy), err
	}
	return nil, err
}

// Get takes name of the GlobalNetworkPolicy, and returns the corresponding GlobalNetworkPolicy object,
// and an error if there is any.
func (r globalnetworkpolicies) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.GlobalNetworkPolicy, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv2.KindGlobalNetworkPolicy, noNamespace, name)
	if out != nil {
		return out.(*apiv2.GlobalNetworkPolicy), err
	}
	return nil, err
}

// List returns the list of GlobalNetworkPolicy objects that match the supplied options.
func (r globalnetworkpolicies) List(ctx context.Context, opts options.ListOptions) (*apiv2.GlobalNetworkPolicyList, error) {
	res := &apiv2.GlobalNetworkPolicyList{}
	if err := r.client.resources.List(ctx, opts, apiv2.KindGlobalNetworkPolicy, apiv2.KindGlobalNetworkPolicyList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the globalnetworkpolicies that match the
// supplied options.
func (r globalnetworkpolicies) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv2.KindGlobalNetworkPolicy)
}
