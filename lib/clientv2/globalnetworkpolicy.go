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

// GlobalNetworkPolicyInterface has methods to work with GlobalNetworkPolicy resources.
type GlobalNetworkPolicyInterface interface {
	Create(peer *apiv2.GlobalNetworkPolicy, opts options.SetOptions) (*apiv2.GlobalNetworkPolicy, error)
	Update(peer *apiv2.GlobalNetworkPolicy, opts options.SetOptions) (*apiv2.GlobalNetworkPolicy, error)
	Delete(name string, opts options.DeleteOptions) error
	Get(name string, opts options.GetOptions) (*apiv2.GlobalNetworkPolicy, error)
	List(opts options.ListOptions) (*apiv2.GlobalNetworkPolicyList, error)
	Watch(opts options.ListOptions) (watch.Interface, error)
}

// globalnetworkpolicies implements GlobalNetworkPolicyInterface
type globalnetworkpolicies struct {
	client client
}

// Create takes the representation of a GlobalNetworkPolicy and creates it.  Returns the stored
// representation of the GlobalNetworkPolicy, and an error, if there is any.
func (r globalnetworkpolicies) Create(peer *apiv2.GlobalNetworkPolicy, opts options.SetOptions) (*apiv2.GlobalNetworkPolicy, error) {
	panic("Create not implemented for GlobalNetworkPolicyInterface")
	return nil, nil
}

// Update takes the representation of a GlobalNetworkPolicy and updates it. Returns the stored
// representation of the GlobalNetworkPolicy, and an error, if there is any.
func (r globalnetworkpolicies) Update(peer *apiv2.GlobalNetworkPolicy, opts options.SetOptions) (*apiv2.GlobalNetworkPolicy, error) {
	panic("Update not implemented for GlobalNetworkPolicyInterface")
	return nil, nil
}

// Delete takes name of the GlobalNetworkPolicy and deletes it. Returns an error if one occurs.
func (r globalnetworkpolicies) Delete(name string, opts options.DeleteOptions) error {
	panic("Delete not implemented for GlobalNetworkPolicyInterface")
	return nil
}

// Get takes name of the GlobalNetworkPolicy, and returns the corresponding GlobalNetworkPolicy object,
// and an error if there is any.
func (r globalnetworkpolicies) Get(name string, opts options.GetOptions) (*apiv2.GlobalNetworkPolicy, error) {
	panic("Get not implemented for GlobalNetworkPolicyInterface")
	return nil, nil
}

// List returns the list of GlobalNetworkPolicy objects that match the supplied options.
func (r globalnetworkpolicies) List(opts options.ListOptions) (*apiv2.GlobalNetworkPolicyList, error) {
	panic("List not implemented for GlobalNetworkPolicyInterface")
	return nil, nil
}

// Watch returns a watch.Interface that watches the GlobalNetworkPolicys that match the
// supplied options.
func (r globalnetworkpolicies) Watch(opts options.ListOptions) (watch.Interface, error) {
	panic("Watch not implemented for GlobalNetworkPolicyInterface")
	return nil, nil
}
