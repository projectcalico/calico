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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewNetworkPolicy(),
		newNetworkPolicyList(),
		true,
		[]string{"networkpolicy", "networkpolicies", "policy", "np", "policies", "pol", "pols"},
		[]string{"NAME"},
		[]string{"NAME", "ORDER", "SELECTOR"},
		// NAMESPACE may be prepended in GrabTableTemplate so needs to remain in the map below
		map[string]string{
			"NAME":      "{{.ObjectMeta.Name}}",
			"NAMESPACE": "{{.ObjectMeta.Namespace}}",
			"ORDER":     "{{.Spec.Order}}",
			"SELECTOR":  "{{.Spec.Selector}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkPolicy)
			if strings.HasPrefix(r.Name, conversion.K8sNetworkPolicyNamePrefix) {
				return nil, cerrors.ErrorOperationNotSupported{
					Operation:  "create or apply",
					Identifier: resource,
					Reason:     "kubernetes network policies must be managed through the kubernetes API",
				}
			}
			return client.NetworkPolicies().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkPolicy)
			if strings.HasPrefix(r.Name, conversion.K8sNetworkPolicyNamePrefix) {
				return nil, cerrors.ErrorOperationNotSupported{
					Operation:  "apply or replace",
					Identifier: resource,
					Reason:     "kubernetes network policies must be managed through the kubernetes API",
				}
			}
			return client.NetworkPolicies().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.NetworkPolicy)
			if strings.HasPrefix(r.Name, conversion.K8sNetworkPolicyNamePrefix) {
				return nil, cerrors.ErrorOperationNotSupported{
					Operation:  "delete",
					Identifier: resource,
					Reason:     "kubernetes network policies must be managed through the kubernetes API",
				}
			}
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

// newNetworkPolicyList creates a new (zeroed) NetworkPolicyList struct with the TypeMetadata initialised to the current
// version.
func newNetworkPolicyList() *api.NetworkPolicyList {
	return &api.NetworkPolicyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindNetworkPolicyList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
