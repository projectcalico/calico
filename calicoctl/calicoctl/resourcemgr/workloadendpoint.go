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
		api.NewWorkloadEndpoint(),
		api.NewWorkloadEndpointList(),
		true,
		[]string{"workloadendpoint", "workloadendpoints", "wep", "weps"},
		[]string{"WORKLOAD", "NODE", "NETWORKS", "INTERFACE"},
		[]string{"NAME", "WORKLOAD", "NODE", "NETWORKS", "INTERFACE", "PROFILES", "NATS"},
		// NAMESPACE may be prepended in GrabTableTemplate so needs to remain in the map below
		map[string]string{
			"NAME":         "{{.ObjectMeta.Name}}",
			"NAMESPACE":    "{{.ObjectMeta.Namespace}}",
			"NODE":         "{{.Spec.Node}}",
			"ORCHESTRATOR": "{{.Spec.Orchestrator}}",
			"WORKLOAD":     "{{if .Spec.Workload}}{{.Spec.Workload}}{{else}}{{.Spec.Pod}}{{end}}",
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
			return client.WorkloadEndpoints().Delete(ctx, r.Namespace, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.WorkloadEndpoint)
			return client.WorkloadEndpoints().Get(ctx, r.Namespace, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.WorkloadEndpoint)
			return client.WorkloadEndpoints().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Namespace: r.Namespace, Name: r.Name})
		},
	)
}
