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

// NodeInterface has methods to work with Node resources.
type NodeInterface interface {
	Create(ctx context.Context, res *apiv2.Node, opts options.SetOptions) (*apiv2.Node, error)
	Update(ctx context.Context, res *apiv2.Node, opts options.SetOptions) (*apiv2.Node, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv2.Node, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.Node, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv2.NodeList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// nodes implements NodeInterface
type nodes struct {
	client client
}

// Create takes the representation of a Node and creates it.  Returns the stored
// representation of the Node, and an error, if there is any.
func (r nodes) Create(ctx context.Context, res *apiv2.Node, opts options.SetOptions) (*apiv2.Node, error) {
	out, err := r.client.resources.Create(ctx, opts, apiv2.KindNode, res)
	if out != nil {
		return out.(*apiv2.Node), err
	}
	return nil, err
}

// Update takes the representation of a Node and updates it. Returns the stored
// representation of the Node, and an error, if there is any.
func (r nodes) Update(ctx context.Context, res *apiv2.Node, opts options.SetOptions) (*apiv2.Node, error) {
	out, err := r.client.resources.Update(ctx, opts, apiv2.KindNode, res)
	if out != nil {
		return out.(*apiv2.Node), err
	}
	return nil, err
}

// Delete takes name of the Node and deletes it. Returns an error if one occurs.
func (r nodes) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv2.Node, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv2.KindNode, noNamespace, name)
	if out != nil {
		return out.(*apiv2.Node), err
	}
	return nil, err
}

// Get takes name of the Node, and returns the corresponding Node object,
// and an error if there is any.
func (r nodes) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.Node, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv2.KindNode, noNamespace, name)
	if out != nil {
		return out.(*apiv2.Node), err
	}
	return nil, err
}

// List returns the list of Node objects that match the supplied options.
func (r nodes) List(ctx context.Context, opts options.ListOptions) (*apiv2.NodeList, error) {
	res := &apiv2.NodeList{}
	if err := r.client.resources.List(ctx, opts, apiv2.KindNode, apiv2.KindNodeList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the Nodes that match the
// supplied options.
func (r nodes) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv2.KindNode)
}
