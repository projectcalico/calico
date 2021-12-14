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
		api.NewIPPool(),
		newIPPoolList(),
		false,
		[]string{"ippool", "ippools", "ipp", "ipps", "pool", "pools"},
		[]string{"NAME", "CIDR", "SELECTOR"},
		[]string{"NAME", "CIDR", "NAT", "IPIPMODE", "VXLANMODE", "DISABLED", "DISABLEBGPEXPORT", "SELECTOR"},
		map[string]string{
			"NAME":             "{{.ObjectMeta.Name}}",
			"CIDR":             "{{.Spec.CIDR}}",
			"NAT":              "{{.Spec.NATOutgoing}}",
			"IPIPMODE":         "{{if .Spec.IPIPMode}}{{.Spec.IPIPMode}}{{else}}Never{{end}}",
			"VXLANMODE":        "{{if .Spec.VXLANMode}}{{.Spec.VXLANMode}}{{else}}Never{{end}}",
			"DISABLED":         "{{.Spec.Disabled}}",
			"DISABLEBGPEXPORT": "{{.Spec.DisableBGPExport}}",
			"SELECTOR":         "{{.Spec.NodeSelector}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPPool)
			return client.IPPools().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPPool)
			return client.IPPools().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPPool)
			return client.IPPools().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.IPPool)
			return client.IPPools().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.IPPool)
			return client.IPPools().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}

// newIPPoolList creates a new (zeroed) IPPoolList struct with the TypeMetadata initialised to the current
// version.
func newIPPoolList() *api.IPPoolList {
	return &api.IPPoolList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindIPPoolList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
