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

// HostEndpointInterface has methods to work with HostEndpoint resources.
type HostEndpointInterface interface {
	Create(peer *apiv2.HostEndpoint, opts options.SetOptions) (*apiv2.HostEndpoint, error)
	Update(peer *apiv2.HostEndpoint, opts options.SetOptions) (*apiv2.HostEndpoint, error)
	Delete(name string, opts options.DeleteOptions) error
	Get(name string, opts options.GetOptions) (*apiv2.HostEndpoint, error)
	List(opts options.ListOptions) (*apiv2.HostEndpointList, error)
	Watch(opts options.ListOptions) (watch.Interface, error)
}

// hostEndpoints implements HostEndpointInterface
type hostEndpoints struct {
	client client
}

// Create takes the representation of a HostEndpoint and creates it.  Returns the stored
// representation of the HostEndpoint, and an error, if there is any.
func (r hostEndpoints) Create(peer *apiv2.HostEndpoint, opts options.SetOptions) (*apiv2.HostEndpoint, error) {
	panic("Create not implemented for HostEndpointInterface")
	return nil, nil
}

// Update takes the representation of a HostEndpoint and updates it. Returns the stored
// representation of the HostEndpoint, and an error, if there is any.
func (r hostEndpoints) Update(peer *apiv2.HostEndpoint, opts options.SetOptions) (*apiv2.HostEndpoint, error) {
	panic("Update not implemented for HostEndpointInterface")
	return nil, nil
}

// Delete takes name of the HostEndpoint and deletes it. Returns an error if one occurs.
func (r hostEndpoints) Delete(name string, opts options.DeleteOptions) error {
	panic("Delete not implemented for HostEndpointInterface")
	return nil
}

// Get takes name of the HostEndpoint, and returns the corresponding HostEndpoint object,
// and an error if there is any.
func (r hostEndpoints) Get(name string, opts options.GetOptions) (*apiv2.HostEndpoint, error) {
	panic("Get not implemented for HostEndpointInterface")
	return nil, nil
}

// List returns the list of HostEndpoint objects that match the supplied options.
func (r hostEndpoints) List(opts options.ListOptions) (*apiv2.HostEndpointList, error) {
	panic("List not implemented for HostEndpointInterface")
	return nil, nil
}

// Watch returns a watch.Interface that watches the HostEndpoints that match the
// supplied options.
func (r hostEndpoints) Watch(opts options.ListOptions) (watch.Interface, error) {
	panic("Watch not implemented for HostEndpointInterface")
	return nil, nil
}
