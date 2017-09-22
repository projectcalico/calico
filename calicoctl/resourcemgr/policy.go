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
	"strings"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/client"
	calicoErrors "github.com/projectcalico/libcalico-go/lib/errors"
)

func init() {
	registerResource(
		api.NewPolicy(),
		api.NewPolicyList(),
		[]string{"NAME"},
		[]string{"NAME", "ORDER", "SELECTOR"},
		map[string]string{
			"NAME":     "{{.Metadata.Name}}",
			"ORDER":    "{{.Spec.Order}}",
			"SELECTOR": "{{.Spec.Selector}}",
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Policy)
			if strings.HasPrefix(r.Metadata.Name, "knp.default.") {
				return nil, calicoErrors.ErrorOperationNotSupported{
					Identifier: r.Metadata.Name,
					Operation:  "Apply",
				}
			}
			return client.Policies().Apply(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Policy)
			if strings.HasPrefix(r.Metadata.Name, "knp.default.") {
				return nil, calicoErrors.ErrorOperationNotSupported{
					Identifier: r.Metadata.Name,
					Operation:  "Create",
				}
			}
			return client.Policies().Create(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Policy)
			if strings.HasPrefix(r.Metadata.Name, "knp.default.") {
				return nil, calicoErrors.ErrorOperationNotSupported{
					Identifier: r.Metadata.Name,
					Operation:  "Update",
				}
			}
			return client.Policies().Update(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Policy)
			if strings.HasPrefix(r.Metadata.Name, "knp.default.") {
				return nil, calicoErrors.ErrorOperationNotSupported{
					Identifier: r.Metadata.Name,
					Operation:  "Delete",
				}
			}
			return nil, client.Policies().Delete(r.Metadata)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.Policy)
			return client.Policies().List(r.Metadata)
		},
	)
}
