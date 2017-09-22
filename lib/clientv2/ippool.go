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

// IPPoolInterface has methods to work with IPPool resources.
type IPPoolInterface interface {
	Create(ctx context.Context, res *apiv2.IPPool, opts options.SetOptions) (*apiv2.IPPool, error)
	Update(ctx context.Context, res *apiv2.IPPool, opts options.SetOptions) (*apiv2.IPPool, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) error
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.IPPool, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv2.IPPoolList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// ipPools implements IPPoolInterface
type ipPools struct {
	client client
}

// Create takes the representation of a IPPool and creates it.  Returns the stored
// representation of the IPPool, and an error, if there is any.
func (r ipPools) Create(ctx context.Context, res *apiv2.IPPool, opts options.SetOptions) (*apiv2.IPPool, error) {
	out, err := r.client.resources.Create(ctx, opts, apiv2.KindIPPool, NoNamespace, res)
	if out != nil {
		return out.(*apiv2.IPPool), err
	}
	return nil, err
}

// Update takes the representation of a IPPool and updates it. Returns the stored
// representation of the IPPool, and an error, if there is any.
func (r ipPools) Update(ctx context.Context, res *apiv2.IPPool, opts options.SetOptions) (*apiv2.IPPool, error) {
	out, err := r.client.resources.Update(ctx, opts, apiv2.KindIPPool, NoNamespace, res)
	if out != nil {
		return out.(*apiv2.IPPool), err
	}
	return nil, err
}

// Delete takes name of the IPPool and deletes it. Returns an error if one occurs.
func (r ipPools) Delete(ctx context.Context, name string, opts options.DeleteOptions) error {
	err := r.client.resources.Delete(ctx, opts, apiv2.KindIPPool, NoNamespace, name)
	return err
}

// Get takes name of the IPPool, and returns the corresponding IPPool object,
// and an error if there is any.
func (r ipPools) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.IPPool, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv2.KindIPPool, NoNamespace, name)
	if out != nil {
		return out.(*apiv2.IPPool), err
	}
	return nil, err
}

// List returns the list of IPPool objects that match the supplied options.
func (r ipPools) List(ctx context.Context, opts options.ListOptions) (*apiv2.IPPoolList, error) {
	res := &apiv2.IPPoolList{}
	if err := r.client.resources.List(ctx, opts, apiv2.KindIPPool, apiv2.KindIPPoolList, NoNamespace, AllNames, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the IPPools that match the
// supplied options.
func (r ipPools) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv2.KindIPPool, NoNamespace, AllNames)
}
