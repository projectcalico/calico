// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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
		api.NewKubeControllersConfiguration(),
		newKubeControllersConfigurationList(),
		false,
		[]string{"kubecontrollersconfiguration", "kubecontrollersconfigurations", "kubecontrollersconfig", "kubecontrollersconfigs"},
		[]string{"NAME"},
		[]string{"NAME"},
		map[string]string{
			"NAME": "{{.ObjectMeta.Name}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.KubeControllersConfiguration)
			return client.KubeControllersConfiguration().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.KubeControllersConfiguration)
			return client.KubeControllersConfiguration().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.KubeControllersConfiguration)
			return client.KubeControllersConfiguration().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.KubeControllersConfiguration)
			return client.KubeControllersConfiguration().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.KubeControllersConfiguration)
			return client.KubeControllersConfiguration().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}

// newKubeControllersConfigurationList creates a new (zeroed) KubeControllersConfigurationList struct with the TypeMetadata
// initialized to the current version.
func newKubeControllersConfigurationList() *api.KubeControllersConfigurationList {
	return &api.KubeControllersConfigurationList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindKubeControllersConfigurationList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
