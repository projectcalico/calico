// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

// CalicoNodeStatusInterface has methods to work with CalicoNodeStatus resources.
type CalicoNodeStatusInterface interface {
	Create(ctx context.Context, res *apiv3.CalicoNodeStatus, opts options.SetOptions) (*apiv3.CalicoNodeStatus, error)
	Update(ctx context.Context, res *apiv3.CalicoNodeStatus, opts options.SetOptions) (*apiv3.CalicoNodeStatus, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.CalicoNodeStatus, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.CalicoNodeStatus, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv3.CalicoNodeStatusList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// calicoNodeStatus implements CalicoNodeStatusInterface
type calicoNodeStatus struct {
	client client
}

// Create takes the representation of a CalicoNodeStatus and creates it.  Returns the stored
// representation of the CalicoNodeStatus, and an error, if there is any.
func (r calicoNodeStatus) Create(ctx context.Context, res *apiv3.CalicoNodeStatus, opts options.SetOptions) (*apiv3.CalicoNodeStatus, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, apiv3.KindCalicoNodeStatus, res)
	if out != nil {
		return out.(*apiv3.CalicoNodeStatus), err
	}
	return nil, err
}

// Update takes the representation of a CalicoNodeStatus and updates it. Returns the stored
// representation of the CalicoNodeStatus, and an error, if there is any.
func (r calicoNodeStatus) Update(ctx context.Context, res *apiv3.CalicoNodeStatus, opts options.SetOptions) (*apiv3.CalicoNodeStatus, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, apiv3.KindCalicoNodeStatus, res)
	if out != nil {
		return out.(*apiv3.CalicoNodeStatus), err
	}
	return nil, err
}

// Delete takes name of the CalicoNodeStatus and deletes it. Returns an error if one occurs.
func (r calicoNodeStatus) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.CalicoNodeStatus, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv3.KindCalicoNodeStatus, noNamespace, name)
	if out != nil {
		return out.(*apiv3.CalicoNodeStatus), err
	}
	return nil, err
}

// Get takes name of the CalicoNodeStatus, and returns the corresponding CalicoNodeStatus object,
// and an error if there is any.
func (r calicoNodeStatus) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.CalicoNodeStatus, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv3.KindCalicoNodeStatus, noNamespace, name)
	if out != nil {
		return out.(*apiv3.CalicoNodeStatus), err
	}
	return nil, err
}

// List returns the list of CalicoNodeStatus objects that match the supplied options.
func (r calicoNodeStatus) List(ctx context.Context, opts options.ListOptions) (*apiv3.CalicoNodeStatusList, error) {
	res := &apiv3.CalicoNodeStatusList{}
	if err := r.client.resources.List(ctx, opts, apiv3.KindCalicoNodeStatus, apiv3.KindCalicoNodeStatusList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the BGPPeers that match the
// supplied options.
func (r calicoNodeStatus) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv3.KindCalicoNodeStatus, nil)
}
