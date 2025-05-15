// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

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

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewStagedGlobalNetworkPolicy(),
		api.NewStagedGlobalNetworkPolicyList(),
		false,
		[]string{"stagedglobalnetworkpolicy", "stagedglobalnetworkpolicies", "sgnp", "sgnps"},
		[]string{"NAME", "TIER"},
		[]string{"NAME", "TIER", "ORDER", "SELECTOR"},
		map[string]string{
			"NAME":     "{{.ObjectMeta.Name}}",
			"ORDER":    "{{.Spec.Order}}",
			"SELECTOR": "{{.Spec.Selector}}",
			"TIER":     "{{.Spec.Tier}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.StagedGlobalNetworkPolicy)
			return client.StagedGlobalNetworkPolicies().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.StagedGlobalNetworkPolicy)
			return client.StagedGlobalNetworkPolicies().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.StagedGlobalNetworkPolicy)
			return client.StagedGlobalNetworkPolicies().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.StagedGlobalNetworkPolicy)
			return client.StagedGlobalNetworkPolicies().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.StagedGlobalNetworkPolicy)
			return client.StagedGlobalNetworkPolicies().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}
