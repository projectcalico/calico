// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewNode(),
		api.NewNodeList(),
		false,
		[]string{"node", "nodes", "no", "nos"},
		[]string{"NAME"},
		[]string{"NAME", "ASN", "IPV4", "IPV6"},
		map[string]string{
			"NAME": "{{.ObjectMeta.Name}}",
			"ASN":  "{{if .Spec.BGP}}{{if .Spec.BGP.ASNumber}}{{.Spec.BGP.ASNumber}}{{else}}({{config \"asnumber\"}}){{end}}{{end}}",
			"IPV4": "{{if .Spec.BGP}}{{if .Spec.BGP.IPv4Address}}{{.Spec.BGP.IPv4Address}}{{end}}{{end}}",
			"IPV6": "{{if .Spec.BGP}}{{if .Spec.BGP.IPv6Address}}{{.Spec.BGP.IPv6Address}}{{end}}{{end}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.Node)
			return client.Nodes().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.Node)
			return client.Nodes().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.Node)
			return client.Nodes().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.Node)
			return client.Nodes().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.Node)
			return client.Nodes().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}
