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

// HostEndpointInterface has methods to work with HostEndpoint resources.
type HostEndpointInterface interface {
	Create(ctx context.Context, res *apiv2.HostEndpoint, opts options.SetOptions) (*apiv2.HostEndpoint, error)
	Update(ctx context.Context, res *apiv2.HostEndpoint, opts options.SetOptions) (*apiv2.HostEndpoint, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) error
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.HostEndpoint, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv2.HostEndpointList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// hostEndpoints implements HostEndpointInterface
type hostEndpoints struct {
	client client
}

// Create takes the representation of a HostEndpoint and creates it.  Returns the stored
// representation of the HostEndpoint, and an error, if there is any.
func (r hostEndpoints) Create(ctx context.Context, res *apiv2.HostEndpoint, opts options.SetOptions) (*apiv2.HostEndpoint, error) {
	out, err := r.client.resources.Create(ctx, opts, apiv2.KindHostEndpoint, NoNamespace, res)
	if out != nil {
		return out.(*apiv2.HostEndpoint), err
	}
	return nil, err
}

// Update takes the representation of a HostEndpoint and updates it. Returns the stored
// representation of the HostEndpoint, and an error, if there is any.
func (r hostEndpoints) Update(ctx context.Context, res *apiv2.HostEndpoint, opts options.SetOptions) (*apiv2.HostEndpoint, error) {
	out, err := r.client.resources.Update(ctx, opts, apiv2.KindHostEndpoint, NoNamespace, res)
	if out != nil {
		return out.(*apiv2.HostEndpoint), err
	}
	return nil, err
}

// Delete takes name of the HostEndpoint and deletes it. Returns an error if one occurs.
func (r hostEndpoints) Delete(ctx context.Context, name string, opts options.DeleteOptions) error {
	err := r.client.resources.Delete(ctx, opts, apiv2.KindHostEndpoint, NoNamespace, name)
	return err
}

// Get takes name of the HostEndpoint, and returns the corresponding HostEndpoint object,
// and an error if there is any.
func (r hostEndpoints) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.HostEndpoint, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv2.KindHostEndpoint, NoNamespace, name)
	if out != nil {
		return out.(*apiv2.HostEndpoint), err
	}
	return nil, err
}

// List returns the list of HostEndpoint objects that match the supplied options.
func (r hostEndpoints) List(ctx context.Context, opts options.ListOptions) (*apiv2.HostEndpointList, error) {
	res := &apiv2.HostEndpointList{}
	if err := r.client.resources.List(ctx, opts, apiv2.KindHostEndpoint, apiv2.KindHostEndpointList, NoNamespace, AllNames, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the HostEndpoints that match the
// supplied options.
func (r hostEndpoints) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv2.KindHostEndpoint, NoNamespace, AllNames)
}
