// Copyright (c) 2016-2017,2021 Tigera, Inc. All rights reserved.

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

package resourcemgr

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewIPReservation(),
		newIPReservationList(),
		false,
		[]string{"ipreservation", "ipreservations", "reservation", "reservations"},
		[]string{"NAME"},
		[]string{"NAME", "CIDRS"},
		map[string]string{
			"NAME":  "{{.ObjectMeta.Name}}",
			"CIDRS": "{{joinAndTruncate .Spec.ReservedCIDRs \",\" 80}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPReservation)
			return client.IPReservations().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPReservation)
			return client.IPReservations().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPReservation)
			return client.IPReservations().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPReservation)
			return client.IPReservations().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.IPReservation)
			return client.IPReservations().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}

// newIPReservationList creates a new (zeroed) IPReservationList struct with the TypeMetadata initialised to the current
// version.
func newIPReservationList() *api.IPReservationList {
	return &api.IPReservationList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindIPReservationList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
