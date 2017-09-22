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

// WorkloadEndpointInterface has methods to work with WorkloadEndpoint resources.
type WorkloadEndpointInterface interface {
	Create(peer *apiv2.WorkloadEndpoint, opts options.SetOptions) (*apiv2.WorkloadEndpoint, error)
	Update(peer *apiv2.WorkloadEndpoint, opts options.SetOptions) (*apiv2.WorkloadEndpoint, error)
	Delete(name string, opts options.DeleteOptions) error
	Get(name string, opts options.GetOptions) (*apiv2.WorkloadEndpoint, error)
	List(opts options.ListOptions) (*apiv2.WorkloadEndpointList, error)
	Watch(opts options.ListOptions) (watch.Interface, error)
}

// workloadEndpoints implements WorkloadEndpointInterface
type workloadEndpoints struct {
	client    client
	namespace string
}

// Create takes the representation of a WorkloadEndpoint and creates it.  Returns the stored
// representation of the WorkloadEndpoint, and an error, if there is any.
func (r workloadEndpoints) Create(peer *apiv2.WorkloadEndpoint, opts options.SetOptions) (*apiv2.WorkloadEndpoint, error) {
	panic("Create not implemented for WorkloadEndpointInterface")
	return nil, nil
}

// Update takes the representation of a WorkloadEndpoint and updates it. Returns the stored
// representation of the WorkloadEndpoint, and an error, if there is any.
func (r workloadEndpoints) Update(peer *apiv2.WorkloadEndpoint, opts options.SetOptions) (*apiv2.WorkloadEndpoint, error) {
	panic("Update not implemented for WorkloadEndpointInterface")
	return nil, nil
}

// Delete takes name of the WorkloadEndpoint and deletes it. Returns an error if one occurs.
func (r workloadEndpoints) Delete(name string, opts options.DeleteOptions) error {
	panic("Delete not implemented for WorkloadEndpointInterface")
	return nil
}

// Get takes name of the WorkloadEndpoint, and returns the corresponding WorkloadEndpoint object,
// and an error if there is any.
func (r workloadEndpoints) Get(name string, opts options.GetOptions) (*apiv2.WorkloadEndpoint, error) {
	panic("Get not implemented for WorkloadEndpointInterface")
	return nil, nil
}

// List returns the list of WorkloadEndpoint objects that match the supplied options.
func (r workloadEndpoints) List(opts options.ListOptions) (*apiv2.WorkloadEndpointList, error) {
	panic("List not implemented for WorkloadEndpointInterface")
	return nil, nil
}

// Watch returns a watch.Interface that watches the WorkloadEndpoints that match the
// supplied options.
func (r workloadEndpoints) Watch(opts options.ListOptions) (watch.Interface, error) {
	panic("Watch not implemented for WorkloadEndpointInterface")
	return nil, nil
}
