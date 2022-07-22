// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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
	"fmt"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// BlockAffinityInterface has methods to work with BlockAffinity resources.
type BlockAffinityInterface interface {
	Create(ctx context.Context, res *libapiv3.BlockAffinity, opts options.SetOptions) (*libapiv3.BlockAffinity, error)
	Update(ctx context.Context, res *libapiv3.BlockAffinity, opts options.SetOptions) (*libapiv3.BlockAffinity, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*libapiv3.BlockAffinity, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*libapiv3.BlockAffinity, error)
	List(ctx context.Context, opts options.ListOptions) (*libapiv3.BlockAffinityList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// BlockAffinities implements BlockAffinityInterface
type blockAffinities struct {
	client client
}

// Create takes the representation of a BlockAffinity and creates it.  Returns the stored
// representation of the BlockAffinity, and an error, if there is any.
func (r blockAffinities) Create(ctx context.Context, res *libapiv3.BlockAffinity, opts options.SetOptions) (*libapiv3.BlockAffinity, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, libapiv3.KindBlockAffinity, res)
	if out != nil {
		return out.(*libapiv3.BlockAffinity), err
	}
	return nil, err
}

// Update takes the representation of a BlockAffinity and updates it. Returns the stored
// representation of the BlockAffinity, and an error, if there is any.
func (r blockAffinities) Update(ctx context.Context, res *libapiv3.BlockAffinity, opts options.SetOptions) (*libapiv3.BlockAffinity, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, libapiv3.KindBlockAffinity, res)
	if out != nil {
		return out.(*libapiv3.BlockAffinity), err
	}
	return nil, err
}

// Delete takes name of the BlockAffinity and deletes it. Returns an error if one occurs.
func (r blockAffinities) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*libapiv3.BlockAffinity, error) {
	out, err := r.client.resources.Delete(ctx, opts, libapiv3.KindBlockAffinity, noNamespace, name)
	if out != nil {
		return out.(*libapiv3.BlockAffinity), err
	}
	return nil, err
}

// Get takes name of the BlockAffinity, and returns the corresponding BlockAffinity object,
// and an error if there is any.
func (r blockAffinities) Get(ctx context.Context, name string, opts options.GetOptions) (*libapiv3.BlockAffinity, error) {
	out, err := r.client.resources.Get(ctx, opts, libapiv3.KindBlockAffinity, noNamespace, name)
	if out != nil {
		if out.(*libapiv3.BlockAffinity).Spec.Deleted != fmt.Sprintf("%t", true) {
			// Filter out block affinities that are being deleted.
			return out.(*libapiv3.BlockAffinity), err
		}
	}
	return nil, err
}

// List returns the list of BlockAffinity objects that match the supplied options.
func (r blockAffinities) List(ctx context.Context, opts options.ListOptions) (*libapiv3.BlockAffinityList, error) {
	res := &libapiv3.BlockAffinityList{}
	if err := r.client.resources.List(ctx, opts, libapiv3.KindBlockAffinity, libapiv3.KindBlockAffinityList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the BlockAffinities that match the
// supplied options.
func (r blockAffinities) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, libapiv3.KindBlockAffinity, nil)
}
