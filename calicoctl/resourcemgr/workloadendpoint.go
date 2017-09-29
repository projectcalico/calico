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
	"context"

	api "github.com/projectcalico/libcalico-go/lib/apiv2"
	client "github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewWorkloadEndpoint(),
		api.NewWorkloadEndpointList(),
		true,
		[]string{"workloadendpoint", "workloadendpoints", "wep", "weps"},
		[]string{"NAME", "NODE", "WORKLOAD", "INTERFACE"},
		[]string{"NAME", "NODE", "NAMESPACE", "WORKLOAD", "NETWORKS", "INTERFACE", "PROFILES", "NATS"},
		map[string]string{
			"NAME":         "{{.ObjectMeta.Name}}",
			"NAMESPACE":    "{{.ObjectMeta.Namespace}}",
			"NODE":         "{{.Spec.Node}}",
			"ORCHESTRATOR": "{{.Spec.Orchestrator}}",
			"WORKLOAD":     "{{.Spec.Workload}}",
			"NETWORKS":     "{{join .Spec.IPNetworks \",\"}}",
			"NATS":         "{{join .Spec.IPNATs \",\"}}",
			"PROFILES":     "{{join .Spec.Profiles \",\"}}",
			"INTERFACE":    "{{.Spec.InterfaceName}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.WorkloadEndpoint)
			return client.WorkloadEndpoints().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.WorkloadEndpoint)
			return client.WorkloadEndpoints().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.WorkloadEndpoint)
			return client.WorkloadEndpoints().Delete(ctx, r.Namespace, r.Name, options.DeleteOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.WorkloadEndpoint)
			return client.WorkloadEndpoints().Get(ctx, r.Namespace, r.Name, options.GetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			return client.WorkloadEndpoints().List(ctx, options.ListOptions{Namespace: resource.GetObjectMeta().GetNamespace()})
		},
	)
}
