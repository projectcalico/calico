// Copyright (c) 2019,2021 Tigera, Inc. All rights reserved.

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
		api.NewNetworkSet(),
		newNetworkSetList(),
		true,
		[]string{"networkset", "networksets", "netsets"},
		[]string{"NAME"},
		[]string{"NAME", "NETS"},
		map[string]string{
			"NAME":      "{{.ObjectMeta.Name}}",
			"NAMESPACE": "{{.ObjectMeta.Namespace}}",
			"NETS":      "{{joinAndTruncate .Spec.Nets \",\" 80}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkSet)
			return client.NetworkSets().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkSet)
			return client.NetworkSets().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkSet)
			return client.NetworkSets().Delete(ctx, r.Namespace, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkSet)
			return client.NetworkSets().Get(ctx, r.Namespace, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.NetworkSet)
			return client.NetworkSets().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Namespace: r.Namespace, Name: r.Name})
		},
	)
}

// newNetworkSetList creates a new (zeroed) NetworkSetList struct with the TypeMetadata initialised to the current
// version.
func newNetworkSetList() *api.NetworkSetList {
	return &api.NetworkSetList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindNetworkSetList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
