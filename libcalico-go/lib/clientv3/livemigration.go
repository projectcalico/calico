// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// LiveMigrationInterface has methods to work with LiveMigration resources.
type LiveMigrationInterface interface {
	Create(ctx context.Context, res *internalapi.LiveMigration, opts options.SetOptions) (*internalapi.LiveMigration, error)
	Update(ctx context.Context, res *internalapi.LiveMigration, opts options.SetOptions) (*internalapi.LiveMigration, error)
	Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*internalapi.LiveMigration, error)
	Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*internalapi.LiveMigration, error)
	List(ctx context.Context, opts options.ListOptions) (*internalapi.LiveMigrationList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// liveMigrations implements LiveMigrationInterface
type liveMigrations struct {
	client client
}

// Create takes the representation of a LiveMigration and creates it.  Returns the stored
// representation of the LiveMigration, and an error, if there is any.
func (r liveMigrations) Create(ctx context.Context, res *internalapi.LiveMigration, opts options.SetOptions) (*internalapi.LiveMigration, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, internalapi.KindLiveMigration, res)
	if out != nil {
		return out.(*internalapi.LiveMigration), err
	}
	return nil, err
}

// Update takes the representation of a LiveMigration and updates it.  Returns the stored
// representation of the LiveMigration, and an error, if there is any.
func (r liveMigrations) Update(ctx context.Context, res *internalapi.LiveMigration, opts options.SetOptions) (*internalapi.LiveMigration, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, internalapi.KindLiveMigration, res)
	if out != nil {
		return out.(*internalapi.LiveMigration), err
	}
	return nil, err
}

// Delete takes name of the LiveMigration and deletes it.  Returns an error if one occurs.
func (r liveMigrations) Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*internalapi.LiveMigration, error) {
	out, err := r.client.resources.Delete(ctx, opts, internalapi.KindLiveMigration, namespace, name)
	if out != nil {
		return out.(*internalapi.LiveMigration), err
	}
	return nil, err
}

// Get takes name of the LiveMigration, and returns the corresponding LiveMigration object,
// and an error if there is any.
func (r liveMigrations) Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*internalapi.LiveMigration, error) {
	out, err := r.client.resources.Get(ctx, opts, internalapi.KindLiveMigration, namespace, name)
	if out != nil {
		return out.(*internalapi.LiveMigration), err
	}
	return nil, err
}

// List returns the list of LiveMigration objects that match the supplied options.
func (r liveMigrations) List(ctx context.Context, opts options.ListOptions) (*internalapi.LiveMigrationList, error) {
	res := &internalapi.LiveMigrationList{}
	if err := r.client.resources.List(ctx, opts, internalapi.KindLiveMigration, internalapi.KindLiveMigrationList, res); err != nil {
		return nil, err
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the LiveMigrations that match the
// supplied options.
func (r liveMigrations) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Operation:  "Watch",
		Identifier: internalapi.KindLiveMigration,
		Reason:     "Watch is not supported for LiveMigration resources",
	}
}
