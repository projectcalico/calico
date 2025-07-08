// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package clientv3

import (
	"context"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// QoSPolicyInterface has methods to work with QoSPolicy resources.
type QoSPolicyInterface interface {
	Create(ctx context.Context, res *apiv3.QoSPolicy, opts options.SetOptions) (*apiv3.QoSPolicy, error)
	Update(ctx context.Context, res *apiv3.QoSPolicy, opts options.SetOptions) (*apiv3.QoSPolicy, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.QoSPolicy, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.QoSPolicy, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv3.QoSPolicyList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// qosPolicies implements QoSPolicyInterface
type qosPolicies struct {
	client client
}

// Create takes the representation of a QoSPolicy and creates it.  Returns the stored
// representation of the QoSPolicy, and an error, if there is any.
func (r qosPolicies) Create(ctx context.Context, res *apiv3.QoSPolicy, opts options.SetOptions) (*apiv3.QoSPolicy, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, apiv3.KindQoSPolicy, res)
	if out != nil {
		return out.(*apiv3.QoSPolicy), err
	}
	return nil, err
}

// Update takes the representation of a QoSPolicy and updates it. Returns the stored
// representation of the QoSPolicy, and an error, if there is any.
func (r qosPolicies) Update(ctx context.Context, res *apiv3.QoSPolicy, opts options.SetOptions) (*apiv3.QoSPolicy, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, apiv3.KindQoSPolicy, res)
	if out != nil {
		return out.(*apiv3.QoSPolicy), err
	}
	return nil, err
}

// Delete takes name of the QoSPolicy and deletes it. Returns an error if one occurs.
func (r qosPolicies) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.QoSPolicy, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv3.KindQoSPolicy, noNamespace, name)
	if out != nil {
		return out.(*apiv3.QoSPolicy), err
	}
	return nil, err
}

// Get takes name of the QoSPolicy, and returns the corresponding QoSPolicy object,
// and an error if there is any.
func (r qosPolicies) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.QoSPolicy, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv3.KindQoSPolicy, noNamespace, name)
	if out != nil {
		return out.(*apiv3.QoSPolicy), err
	}
	return nil, err
}

// List returns the list of QoSPolicy objects that match the supplied options.
func (r qosPolicies) List(ctx context.Context, opts options.ListOptions) (*apiv3.QoSPolicyList, error) {
	res := &apiv3.QoSPolicyList{}
	if err := r.client.resources.List(ctx, opts, apiv3.KindQoSPolicy, apiv3.KindQoSPolicyList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the QoSPolicys that match the
// supplied options.
func (r qosPolicies) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv3.KindQoSPolicy, nil)
}
