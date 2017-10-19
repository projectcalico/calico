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

	api "github.com/projectcalico/libcalico-go/lib/apis/v2"
	client "github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewNetworkPolicy(),
		api.NewNetworkPolicyList(),
		true,
		[]string{"networkpolicy", "networkpolicies", "policy", "np", "policies", "pol", "pols"},
		[]string{"NAME"},
		[]string{"NAME", "ORDER", "SELECTOR", "NAMESPACE"},
		map[string]string{
			"NAME":      "{{.ObjectMeta.Name}}",
			"NAMESPACE": "{{.ObjectMeta.Namespace}}",
			"ORDER":     "{{.Spec.Order}}",
			"SELECTOR":  "{{.Spec.Selector}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkPolicy)
			return client.NetworkPolicies().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkPolicy)
			return client.NetworkPolicies().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkPolicy)
			return client.NetworkPolicies().Delete(ctx, r.Namespace, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkPolicy)
			return client.NetworkPolicies().Get(ctx, r.Namespace, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.NetworkPolicy)
			return client.NetworkPolicies().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Namespace: r.Namespace, Name: r.Name})
		},
	)
}
