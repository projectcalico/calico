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

// WorkloadEndpointInterface has methods to work with WorkloadEndpoint resources.
type WorkloadEndpointInterface interface {
	Create(ctx context.Context, res *apiv2.WorkloadEndpoint, opts options.SetOptions) (*apiv2.WorkloadEndpoint, error)
	Update(ctx context.Context, res *apiv2.WorkloadEndpoint, opts options.SetOptions) (*apiv2.WorkloadEndpoint, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) error
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.WorkloadEndpoint, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv2.WorkloadEndpointList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// workloadEndpoints implements WorkloadEndpointInterface
type workloadEndpoints struct {
	client    client
	namespace string
}

// Create takes the representation of a WorkloadEndpoint and creates it.  Returns the stored
// representation of the WorkloadEndpoint, and an error, if there is any.
func (r workloadEndpoints) Create(ctx context.Context, res *apiv2.WorkloadEndpoint, opts options.SetOptions) (*apiv2.WorkloadEndpoint, error) {
	out, err := r.client.resources.Create(ctx, opts, apiv2.KindWorkloadEndpoint, r.namespace, res)
	if out != nil {
		return out.(*apiv2.WorkloadEndpoint), err
	}
	return nil, err
}

// Update takes the representation of a WorkloadEndpoint and updates it. Returns the stored
// representation of the WorkloadEndpoint, and an error, if there is any.
func (r workloadEndpoints) Update(ctx context.Context, res *apiv2.WorkloadEndpoint, opts options.SetOptions) (*apiv2.WorkloadEndpoint, error) {
	out, err := r.client.resources.Update(ctx, opts, apiv2.KindWorkloadEndpoint, r.namespace, res)
	if out != nil {
		return out.(*apiv2.WorkloadEndpoint), err
	}
	return nil, err
}

// Delete takes name of the WorkloadEndpoint and deletes it. Returns an error if one occurs.
func (r workloadEndpoints) Delete(ctx context.Context, name string, opts options.DeleteOptions) error {
	err := r.client.resources.Delete(ctx, opts, apiv2.KindWorkloadEndpoint, r.namespace, name)
	return err
}

// Get takes name of the WorkloadEndpoint, and returns the corresponding WorkloadEndpoint object,
// and an error if there is any.
func (r workloadEndpoints) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.WorkloadEndpoint, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv2.KindWorkloadEndpoint, r.namespace, name)
	if out != nil {
		return out.(*apiv2.WorkloadEndpoint), err
	}
	return nil, err
}

// List returns the list of WorkloadEndpoint objects that match the supplied options.
func (r workloadEndpoints) List(ctx context.Context, opts options.ListOptions) (*apiv2.WorkloadEndpointList, error) {
	res := &apiv2.WorkloadEndpointList{}
	if err := r.client.resources.List(ctx, opts, apiv2.KindWorkloadEndpoint, apiv2.KindWorkloadEndpointList, r.namespace, AllNames, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the NetworkPolicies that match the
// supplied options.
func (r workloadEndpoints) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv2.KindWorkloadEndpoint, r.namespace, AllNames)
}
