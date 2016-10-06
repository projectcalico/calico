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
		api.NewPool(),
		api.NewPoolList(),
		[]string{"CIDR"},
		[]string{"CIDR", "NAT", "IPIP"},
		map[string]string{
			"CIDR": "{{.Metadata.CIDR}}",
			"NAT":  "{{.Spec.NATOutgoing}}",
			"IPIP": "{{if .Spec.IPIP}}{{.Spec.IPIP.Enabled}}{{else}}false{{end}}",
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Pool)
			return client.Pools().Apply(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Pool)
			return client.Pools().Create(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Pool)
			return client.Pools().Update(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Pool)
			return nil, client.Pools().Delete(r.Metadata)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Pool)
			return client.Pools().List(r.Metadata)
		},
	)
}
