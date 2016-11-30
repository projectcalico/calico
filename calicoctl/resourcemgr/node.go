// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/client"
)

func init() {
	registerResource(
		api.NewNode(),
		api.NewNodeList(),
		[]string{"NAME"},
		[]string{"NAME", "ASN", "IPV4", "IPV6"},
		map[string]string{
			"NAME": "{{.Metadata.Name}}",
			"ASN":  "{{if .Spec.BGP}}{{if .Spec.BGP.ASNumber}}{{.Spec.BGP.ASNumber}}{{else}}({{config \"asnumber\"}}){{end}}{{end}}",
			"IPV4": "{{if .Spec.BGP}}{{if .Spec.BGP.IPv4Address}}{{.Spec.BGP.IPv4Address}}{{end}}{{end}}",
			"IPV6": "{{if .Spec.BGP}}{{if .Spec.BGP.IPv6Address}}{{.Spec.BGP.IPv6Address}}{{end}}{{end}}",
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Node)
			return client.Nodes().Apply(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Node)
			return client.Nodes().Create(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Node)
			return client.Nodes().Update(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Node)
			return nil, client.Nodes().Delete(r.Metadata)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Node)
			return client.Nodes().List(r.Metadata)
		},
	)
}
