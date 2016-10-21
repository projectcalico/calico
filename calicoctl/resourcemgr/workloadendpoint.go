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
		api.NewWorkloadEndpoint(),
		api.NewWorkloadEndpointList(),
		[]string{"NODE", "ORCHESTRATOR", "WORKLOAD", "NAME"},
		[]string{"NODE", "ORCHESTRATOR", "WORKLOAD", "NAME", "NETWORKS", "NATS", "INTERFACE", "PROFILES"},
		map[string]string{
			"NODE":         "{{.Metadata.Node}}",
			"ORCHESTRATOR": "{{.Metadata.Orchestrator}}",
			"WORKLOAD":     "{{.Metadata.Workload}}",
			"NAME":         "{{.Metadata.Name}}",
			"NETWORKS":     "{{join .Spec.IPNetworks \",\"}}",
			"NATS":         "{{join .Spec.IPNATs \",\"}}",
			"IPV4GATEWAY":  "{{.Spec.IPv4Gateway}}",
			"IPV6GATEWAY":  "{{.Spec.IPv4Gateway}}",
			"PROFILES":     "{{join .Spec.Profiles \",\"}}",
			"INTERFACE":    "{{.Spec.InterfaceName}}",
			"MAC":          "{{.Spec.MAC}}",
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.WorkloadEndpoint)
			return client.WorkloadEndpoints().Apply(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.WorkloadEndpoint)
			return client.WorkloadEndpoints().Create(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.WorkloadEndpoint)
			return client.WorkloadEndpoints().Update(&r)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.WorkloadEndpoint)
			return nil, client.WorkloadEndpoints().Delete(r.Metadata)
		},
		func(client *client.Client, resource unversioned.Resource) (unversioned.Resource, error) {
			r := resource.(api.WorkloadEndpoint)
			return client.WorkloadEndpoints().List(r.Metadata)
		},
	)
}
