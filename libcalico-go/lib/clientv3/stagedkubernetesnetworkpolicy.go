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

package clientv3

import (
	"context"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// StagedKubernetesNetworkPolicyInterface has methods to work with StagedKubernetesNetworkPolicy resources.
type StagedKubernetesNetworkPolicyInterface interface {
	Create(ctx context.Context, res *apiv3.StagedKubernetesNetworkPolicy, opts options.SetOptions) (*apiv3.StagedKubernetesNetworkPolicy, error)
	Update(ctx context.Context, res *apiv3.StagedKubernetesNetworkPolicy, opts options.SetOptions) (*apiv3.StagedKubernetesNetworkPolicy, error)
	Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*apiv3.StagedKubernetesNetworkPolicy, error)
	Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*apiv3.StagedKubernetesNetworkPolicy, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv3.StagedKubernetesNetworkPolicyList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// stagedKubernetesNetworkPolicies implements StagedKubernetesNetworkPolicyInterface
type stagedKubernetesNetworkPolicies struct {
	client client
}

// Create takes the representation of a StagedKubernetesNetworkPolicy and creates it.  Returns the stored
// representation of the StagedKubernetesNetworkPolicy, and an error, if there is any.
func (r stagedKubernetesNetworkPolicies) Create(ctx context.Context, res *apiv3.StagedKubernetesNetworkPolicy, opts options.SetOptions) (*apiv3.StagedKubernetesNetworkPolicy, error) {
	if res != nil {
		// Since we're about to default some fields, take a (shallow) copy of the input data
		// before we do so.
		resCopy := *res
		res = &resCopy
	}

	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, apiv3.KindStagedKubernetesNetworkPolicy, res)
	if out != nil {
		return out.(*apiv3.StagedKubernetesNetworkPolicy), err
	}

	return nil, err
}

// Update takes the representation of a StagedKubernetesNetworkPolicy and updates it. Returns the stored
// representation of the StagedKubernetesNetworkPolicy, and an error, if there is any.
func (r stagedKubernetesNetworkPolicies) Update(ctx context.Context, res *apiv3.StagedKubernetesNetworkPolicy, opts options.SetOptions) (*apiv3.StagedKubernetesNetworkPolicy, error) {
	if res != nil {
		// Since we're about to default some fields, take a (shallow) copy of the input data
		// before we do so.
		resCopy := *res
		res = &resCopy
	}

	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, apiv3.KindStagedKubernetesNetworkPolicy, res)
	if out != nil {
		return out.(*apiv3.StagedKubernetesNetworkPolicy), err
	}

	return nil, err
}

// Delete takes name of the StagedKubernetesNetworkPolicy and deletes it. Returns an error if one occurs.
func (r stagedKubernetesNetworkPolicies) Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*apiv3.StagedKubernetesNetworkPolicy, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv3.KindStagedKubernetesNetworkPolicy, namespace, name)
	if out != nil {
		return out.(*apiv3.StagedKubernetesNetworkPolicy), err
	}
	return nil, err
}

// Get takes name of the StagedKubernetesNetworkPolicy, and returns the corresponding StagedKubernetesNetworkPolicy object,
// and an error if there is any.
func (r stagedKubernetesNetworkPolicies) Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*apiv3.StagedKubernetesNetworkPolicy, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv3.KindStagedKubernetesNetworkPolicy, namespace, name)

	if out != nil {
		resOut := out.(*apiv3.StagedKubernetesNetworkPolicy)

		return resOut, err
	}
	return nil, err
}

// List returns the list of StagedKubernetesNetworkPolicy objects that match the supplied options.
func (r stagedKubernetesNetworkPolicies) List(ctx context.Context, opts options.ListOptions) (*apiv3.StagedKubernetesNetworkPolicyList, error) {
	res := &apiv3.StagedKubernetesNetworkPolicyList{}

	if err := r.client.resources.List(ctx, opts, apiv3.KindStagedKubernetesNetworkPolicy, apiv3.KindStagedKubernetesNetworkPolicyList, res); err != nil {
		return nil, err
	}

	return res, nil
}

// Watch returns a watch.Interface that watches the stagedKubernetesNetworkPolicies that match the
// supplied options.
func (r stagedKubernetesNetworkPolicies) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv3.KindStagedKubernetesNetworkPolicy, nil)
}
