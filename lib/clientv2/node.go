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

// NodeInterface has methods to work with Node resources.
type NodeInterface interface {
	Create(peer *apiv2.Node, opts options.SetOptions) (*apiv2.Node, error)
	Update(peer *apiv2.Node, opts options.SetOptions) (*apiv2.Node, error)
	Delete(name string, opts options.DeleteOptions) error
	Get(name string, opts options.GetOptions) (*apiv2.Node, error)
	List(opts options.ListOptions) (*apiv2.NodeList, error)
	Watch(opts options.ListOptions) (watch.Interface, error)
}

// nodes implements NodeInterface
type nodes struct {
	client client
}

// Create takes the representation of a Node and creates it.  Returns the stored
// representation of the Node, and an error, if there is any.
func (r nodes) Create(peer *apiv2.Node, opts options.SetOptions) (*apiv2.Node, error) {
	panic("Create not implemented for NodeInterface")
	return nil, nil
}

// Update takes the representation of a Node and updates it. Returns the stored
// representation of the Node, and an error, if there is any.
func (r nodes) Update(peer *apiv2.Node, opts options.SetOptions) (*apiv2.Node, error) {
	panic("Update not implemented for NodeInterface")
	return nil, nil
}

// Delete takes name of the Node and deletes it. Returns an error if one occurs.
func (r nodes) Delete(name string, opts options.DeleteOptions) error {
	panic("Delete not implemented for NodeInterface")
	return nil
}

// Get takes name of the Node, and returns the corresponding Node object,
// and an error if there is any.
func (r nodes) Get(name string, opts options.GetOptions) (*apiv2.Node, error) {
	panic("Get not implemented for NodeInterface")
	return nil, nil
}

// List returns the list of Node objects that match the supplied options.
func (r nodes) List(opts options.ListOptions) (*apiv2.NodeList, error) {
	panic("List not implemented for NodeInterface")
	return nil, nil
}

// Watch returns a watch.Interface that watches the Nodes that match the
// supplied options.
func (r nodes) Watch(opts options.ListOptions) (watch.Interface, error) {
	panic("Watch not implemented for NodeInterface")
	return nil, nil
}
