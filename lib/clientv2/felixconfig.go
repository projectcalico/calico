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

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
)

// FelixConfigurationInterface has methods to work with FelixConfiguration resources.
type FelixConfigurationInterface interface {
	Create(ctx context.Context, res *apiv2.FelixConfiguration, opts options.SetOptions) (*apiv2.FelixConfiguration, error)
	Update(ctx context.Context, res *apiv2.FelixConfiguration, opts options.SetOptions) (*apiv2.FelixConfiguration, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv2.FelixConfiguration, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.FelixConfiguration, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv2.FelixConfigurationList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// felixConfigurations implements FelixConfigurationInterface
type felixConfigurations struct {
	client client
}

// Create takes the representation of a FelixConfiguration and creates it.
// Returns the stored representation of the FelixConfiguration, and an error
// if there is any.
func (r felixConfigurations) Create(ctx context.Context, res *apiv2.FelixConfiguration, opts options.SetOptions) (*apiv2.FelixConfiguration, error) {
	out, err := r.client.resources.Create(ctx, opts, apiv2.KindFelixConfiguration, res)
	if out != nil {
		return out.(*apiv2.FelixConfiguration), err
	}
	return nil, err
}

// Update takes the representation of a FelixConfiguration and updates it.
// Returns the stored representation of the FelixConfiguration, and an error
// if there is any.
func (r felixConfigurations) Update(ctx context.Context, res *apiv2.FelixConfiguration, opts options.SetOptions) (*apiv2.FelixConfiguration, error) {
	out, err := r.client.resources.Update(ctx, opts, apiv2.KindFelixConfiguration, res)
	if out != nil {
		return out.(*apiv2.FelixConfiguration), err
	}
	return nil, err
}

// Delete takes name of the FelixConfiguration and deletes it. Returns an
// error if one occurs.
func (r felixConfigurations) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv2.FelixConfiguration, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv2.KindFelixConfiguration, noNamespace, name)
	if out != nil {
		return out.(*apiv2.FelixConfiguration), err
	}
	return nil, err
}

// Get takes name of the FelixConfiguration, and returns the corresponding
// FelixConfiguration object, and an error if there is any.
func (r felixConfigurations) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.FelixConfiguration, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv2.KindFelixConfiguration, noNamespace, name)
	if out != nil {
		return out.(*apiv2.FelixConfiguration), err
	}
	return nil, err
}

// List returns the list of FelixConfiguration objects that match the supplied options.
func (r felixConfigurations) List(ctx context.Context, opts options.ListOptions) (*apiv2.FelixConfigurationList, error) {
	res := &apiv2.FelixConfigurationList{}
	if err := r.client.resources.List(ctx, opts, apiv2.KindFelixConfiguration, apiv2.KindFelixConfigurationList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the FelixConfiguration that
// match the supplied options.
func (r felixConfigurations) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv2.KindFelixConfiguration)
}
