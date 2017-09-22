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

	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/watch"
)

// ProfileInterface has methods to work with Profile resources.
type ProfileInterface interface {
	Create(ctx context.Context, res *apiv2.Profile, opts options.SetOptions) (*apiv2.Profile, error)
	Update(ctx context.Context, res *apiv2.Profile, opts options.SetOptions) (*apiv2.Profile, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) error
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.Profile, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv2.ProfileList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// profiles implements ProfileInterface
type profiles struct {
	client client
}

// Create takes the representation of a Profile and creates it.  Returns the stored
// representation of the Profile, and an error, if there is any.
func (r profiles) Create(ctx context.Context, res *apiv2.Profile, opts options.SetOptions) (*apiv2.Profile, error) {
	panic("Create not implemented for ProfileInterface")
	return nil, nil
}

// Update takes the representation of a Profile and updates it. Returns the stored
// representation of the Profile, and an error, if there is any.
func (r profiles) Update(ctx context.Context, res *apiv2.Profile, opts options.SetOptions) (*apiv2.Profile, error) {
	panic("Update not implemented for ProfileInterface")
	return nil, nil
}

// Delete takes name of the Profile and deletes it. Returns an error if one occurs.
func (r profiles) Delete(ctx context.Context, name string, opts options.DeleteOptions) error {
	panic("Delete not implemented for ProfileInterface")
	return nil
}

// Get takes name of the Profile, and returns the corresponding Profile object,
// and an error if there is any.
func (r profiles) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv2.Profile, error) {
	panic("Get not implemented for ProfileInterface")
	return nil, nil
}

// List returns the list of Profile objects that match the supplied options.
func (r profiles) List(ctx context.Context, opts options.ListOptions) (*apiv2.ProfileList, error) {
	panic("List not implemented for ProfileInterface")
	return nil, nil
}

// Watch returns a watch.Interface that watches the Profiles that match the
// supplied options.
func (r profiles) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	panic("Watch not implemented for ProfileInterface")
	return nil, nil
}
