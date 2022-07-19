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

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// IPAMConfigInterface has methods to work with IPAMConfig resources.
type IPAMConfigInterface interface {
	Create(ctx context.Context, res *libapiv3.IPAMConfig, opts options.SetOptions) (*libapiv3.IPAMConfig, error)
	Update(ctx context.Context, res *libapiv3.IPAMConfig, opts options.SetOptions) (*libapiv3.IPAMConfig, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*libapiv3.IPAMConfig, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*libapiv3.IPAMConfig, error)
	List(ctx context.Context, opts options.ListOptions) (*libapiv3.IPAMConfigList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// IPAMConfigs implements IPAMConfigInterface
type IPAMConfigs struct {
	client client
}

// Create takes the representation of a IPAMConfig and creates it.  Returns the stored
// representation of the IPAMConfig, and an error, if there is any.
func (r IPAMConfigs) Create(ctx context.Context, res *libapiv3.IPAMConfig, opts options.SetOptions) (*libapiv3.IPAMConfig, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, libapiv3.KindIPAMConfig, res)
	if out != nil {
		return out.(*libapiv3.IPAMConfig), err
	}
	return nil, err
}

// Update takes the representation of a IPAMConfig and updates it. Returns the stored
// representation of the IPAMConfig, and an error, if there is any.
func (r IPAMConfigs) Update(ctx context.Context, res *libapiv3.IPAMConfig, opts options.SetOptions) (*libapiv3.IPAMConfig, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, libapiv3.KindIPAMConfig, res)
	if out != nil {
		return out.(*libapiv3.IPAMConfig), err
	}
	return nil, err
}

// Delete takes name of the IPAMConfig and deletes it. Returns an error if one occurs.
func (r IPAMConfigs) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*libapiv3.IPAMConfig, error) {
	out, err := r.client.resources.Delete(ctx, opts, libapiv3.KindIPAMConfig, noNamespace, name)
	if out != nil {
		return out.(*libapiv3.IPAMConfig), err
	}
	return nil, err
}

// Get takes name of the IPAMConfig, and returns the corresponding IPAMConfig object,
// and an error if there is any.
func (r IPAMConfigs) Get(ctx context.Context, name string, opts options.GetOptions) (*libapiv3.IPAMConfig, error) {
	out, err := r.client.resources.Get(ctx, opts, libapiv3.KindIPAMConfig, noNamespace, name)
	if out != nil {
		return out.(*libapiv3.IPAMConfig), err
	}
	return nil, err
}

// List returns the list of IPAMConfig objects that match the supplied options.
func (r IPAMConfigs) List(ctx context.Context, opts options.ListOptions) (*libapiv3.IPAMConfigList, error) {
	res := &libapiv3.IPAMConfigList{}
	if err := r.client.resources.List(ctx, opts, libapiv3.KindIPAMConfig, libapiv3.KindIPAMConfigList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the IPAMConfigs that match the
// supplied options.
func (r IPAMConfigs) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, libapiv3.KindIPAMConfig, nil)
}
