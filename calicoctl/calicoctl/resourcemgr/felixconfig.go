// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.

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
		api.NewFelixConfiguration(),
		newFelixConfigurationList(),
		false,
		[]string{"felixconfiguration", "felixconfigurations", "felixconfig", "felixconfigs"},
		[]string{"NAME"},
		[]string{"NAME"},
		map[string]string{
			"NAME": "{{.ObjectMeta.Name}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.FelixConfiguration)
			return client.FelixConfigurations().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.FelixConfiguration)
			return client.FelixConfigurations().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.FelixConfiguration)
			return client.FelixConfigurations().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.FelixConfiguration)
			return client.FelixConfigurations().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.FelixConfiguration)
			return client.FelixConfigurations().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}

// newFelixConfigurationList creates a new (zeroed) FelixConfigurationList struct with the TypeMetadata
// initialized to the current version.
func newFelixConfigurationList() *api.FelixConfigurationList {
	return &api.FelixConfigurationList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindFelixConfigurationList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
