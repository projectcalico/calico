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
	"errors"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

const (
	GlobalIPAMConfigName = "default"
)

// IPAMConfigurationInterface has methods to work with IPAMConfiguration resources.
type IPAMConfigurationInterface interface {
	Create(ctx context.Context, res *v3.IPAMConfiguration, opts options.SetOptions) (*v3.IPAMConfiguration, error)
	Update(ctx context.Context, res *v3.IPAMConfiguration, opts options.SetOptions) (*v3.IPAMConfiguration, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*v3.IPAMConfiguration, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*v3.IPAMConfiguration, error)
	List(ctx context.Context, opts options.ListOptions) (*v3.IPAMConfigurationList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// IPAMConfigurations implements IPAMConfigurationInterface
type IPAMConfigurations struct {
	client client
}

func validateMetadata(res *v3.IPAMConfiguration) error {
	if res.ObjectMeta.GetName() != GlobalIPAMConfigName {
		return errors.New("Cannot create an IPAMConfiguration resource with a name other than \"default\"")
	}
	return nil
}

// Create takes the representation of a IPAMConfiguration and creates it.  Returns the stored
// representation of the IPAMConfiguration, and an error, if there is any.
func (r IPAMConfigurations) Create(ctx context.Context, res *v3.IPAMConfiguration, opts options.SetOptions) (*v3.IPAMConfiguration, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	} else if err := validateMetadata(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, v3.KindIPAMConfiguration, res)
	if out != nil {
		return out.(*v3.IPAMConfiguration), err
	}
	return nil, err
}

// Update takes the representation of a IPAMConfiguration and updates it. Returns the stored
// representation of the IPAMConfiguration, and an error, if there is any.
func (r IPAMConfigurations) Update(ctx context.Context, res *v3.IPAMConfiguration, opts options.SetOptions) (*v3.IPAMConfiguration, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	} else if err := validateMetadata(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, v3.KindIPAMConfiguration, res)
	if out != nil {
		return out.(*v3.IPAMConfiguration), err
	}
	return nil, err
}

// Delete takes name of the IPAMConfiguration and deletes it. Returns an error if one occurs.
func (r IPAMConfigurations) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*v3.IPAMConfiguration, error) {
	out, err := r.client.resources.Delete(ctx, opts, v3.KindIPAMConfiguration, noNamespace, name)
	if out != nil {
		return out.(*v3.IPAMConfiguration), err
	}
	return nil, err
}

// Get takes name of the IPAMConfiguration, and returns the corresponding IPAMConfiguration object,
// and an error if there is any.
func (r IPAMConfigurations) Get(ctx context.Context, name string, opts options.GetOptions) (*v3.IPAMConfiguration, error) {
	out, err := r.client.resources.Get(ctx, opts, v3.KindIPAMConfiguration, noNamespace, name)
	if out != nil {
		return out.(*v3.IPAMConfiguration), err
	}
	return nil, err
}

// List returns the list of IPAMConfiguration objects that match the supplied options.
func (r IPAMConfigurations) List(ctx context.Context, opts options.ListOptions) (*v3.IPAMConfigurationList, error) {
	res := &v3.IPAMConfigurationList{}
	if err := r.client.resources.List(ctx, opts, v3.KindIPAMConfiguration, v3.KindIPAMConfigurationList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the IPAMConfigurations that match the
// supplied options.
func (r IPAMConfigurations) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, v3.KindIPAMConfiguration, nil)
}
