// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

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

	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// IPReservationInterface has methods to work with IPReservation resources.
type IPReservationInterface interface {
	Create(ctx context.Context, res *apiv3.IPReservation, opts options.SetOptions) (*apiv3.IPReservation, error)
	Update(ctx context.Context, res *apiv3.IPReservation, opts options.SetOptions) (*apiv3.IPReservation, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.IPReservation, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.IPReservation, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv3.IPReservationList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// ipReservations implements IPReservationInterface
type ipReservations struct {
	client client
}

// Create takes the representation of an IPReservation and creates it.  Returns the stored
// representation of the IPReservation, and an error, if there is any.
func (r ipReservations) Create(ctx context.Context, res *apiv3.IPReservation, opts options.SetOptions) (*apiv3.IPReservation, error) {
	// Validate the IPReservation before creating the resource.
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, apiv3.KindIPReservation, res)
	if out != nil {
		return out.(*apiv3.IPReservation), err
	}
	return nil, err

}

// Update takes the representation of an IPReservation and updates it. Returns the stored
// representation of the IPReservation, and an error, if there is any.
func (r ipReservations) Update(ctx context.Context, res *apiv3.IPReservation, opts options.SetOptions) (*apiv3.IPReservation, error) {
	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, apiv3.KindIPReservation, res)
	if out != nil {
		return out.(*apiv3.IPReservation), err
	}
	return nil, err
}

// Delete takes name of the IPReservation and deletes it. Returns an error if one occurs.
func (r ipReservations) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.IPReservation, error) {
	log.WithField("name", name).Info("Deleting reservation")
	out, err := r.client.resources.Delete(ctx, opts, apiv3.KindIPReservation, noNamespace, name)
	if out != nil {
		return out.(*apiv3.IPReservation), err
	}
	return nil, err
}

// Get takes name of the IPReservation, and returns the corresponding IPReservation object,
// and an error if there is any.
func (r ipReservations) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.IPReservation, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv3.KindIPReservation, noNamespace, name)
	if out != nil {
		return out.(*apiv3.IPReservation), err
	}

	return nil, err
}

// List returns the list of IPReservation objects that match the supplied options.
func (r ipReservations) List(ctx context.Context, opts options.ListOptions) (*apiv3.IPReservationList, error) {
	res := &apiv3.IPReservationList{}
	if err := r.client.resources.List(ctx, opts, apiv3.KindIPReservation, apiv3.KindIPReservationList, res); err != nil {
		return nil, err
	}

	return res, nil
}

// Watch returns a watch.Interface that watches the IPReservations that match the
// supplied options.
func (r ipReservations) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv3.KindIPReservation, nil)
}
