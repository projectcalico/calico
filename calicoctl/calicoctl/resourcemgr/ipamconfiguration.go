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

package resourcemgr

import (
	"context"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewIPAMConfiguration(),
		newIPAMConfigurationList(),
		false,
		[]string{"ipamconfiguration", "ipamconfigurations", "ipamconfig", "ipamconfigs"},
		[]string{"NAME", "STRICTAFFINITY", "AUTOALLOCATEBLOCKS"},
		[]string{"NAME", "STRICTAFFINITY", "AUTOALLOCATEBLOCKS", "MAXBLOCKSPERHOST"},
		map[string]string{
			"NAME":               "{{.ObjectMeta.Name}}",
			"STRICTAFFINITY":     "{{.Spec.StrictAffinity}}",
			"AUTOALLOCATEBLOCKS": "{{.Spec.AutoAllocateBlocks}}",
			"MAXBLOCKSPERHOST":   "{{.Spec.MaxBlocksPerHost}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPAMConfiguration)
			return client.IPAMConfiguration().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPAMConfiguration)
			return client.IPAMConfiguration().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPAMConfiguration)
			return client.IPAMConfiguration().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPAMConfiguration)
			return client.IPAMConfiguration().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.IPAMConfiguration)
			return client.IPAMConfiguration().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}

// newIPAMConfigurationList creates a new (zeroed) IPAMConfigurationList struct with the
// TypeMetadata initialised to the current version.
func newIPAMConfigurationList() *api.IPAMConfigurationList {
	return &api.IPAMConfigurationList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindIPAMConfigurationList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
