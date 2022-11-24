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

package resourcemgr

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewBGPFilter(),
		newBGPFilterList(),
		false,
		[]string{"bgpfilter", "bgpfilter", "bgpf", "bgpfs", "bf", "bfs"},
		[]string{"NAME", "NUMEXPORT", "NUMIMPORT"},
		[]string{"NAME", "NUMEXPORT", "NUMIMPORT"},
		map[string]string{
			"NAME":      "{{.ObjectMeta.Name}}",
			"NUMEXPORT": "{{ len .Spec.Export}}",
			"NUMIMPORT": "{{ len .Spec.Import}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.BGPFilter)
			return client.BGPFilter().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.BGPFilter)
			return client.BGPFilter().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.BGPFilter)
			return client.BGPFilter().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.BGPFilter)
			return client.BGPFilter().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.BGPFilter)
			return client.BGPFilter().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}

// newBGPFilterList creates a new (zeroed) BGPFilterList struct with the TypeMetadata initialised to the current
// version.
func newBGPFilterList() *api.BGPFilterList {
	return &api.BGPFilterList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindBGPFilterList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
