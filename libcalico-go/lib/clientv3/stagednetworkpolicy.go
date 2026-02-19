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
	"github.com/projectcalico/api/pkg/defaults"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// StagedNetworkPolicyInterface has methods to work with StagedNetworkPolicy resources.
type StagedNetworkPolicyInterface interface {
	Create(ctx context.Context, res *apiv3.StagedNetworkPolicy, opts options.SetOptions) (*apiv3.StagedNetworkPolicy, error)
	Update(ctx context.Context, res *apiv3.StagedNetworkPolicy, opts options.SetOptions) (*apiv3.StagedNetworkPolicy, error)
	Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*apiv3.StagedNetworkPolicy, error)
	Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*apiv3.StagedNetworkPolicy, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv3.StagedNetworkPolicyList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// stagedNetworkPolicies implements StagedNetworkPolicyInterface
type stagedNetworkPolicies struct {
	client client
}

// Create takes the representation of a StagedNetworkPolicy and creates it.  Returns the stored
// representation of the StagedNetworkPolicy, and an error, if there is any.
func (r stagedNetworkPolicies) Create(ctx context.Context, res *apiv3.StagedNetworkPolicy, opts options.SetOptions) (*apiv3.StagedNetworkPolicy, error) {
	// Before creating the policy, check that the tier exists.
	tier := names.TierOrDefault(res.Spec.Tier)
	if _, err := r.client.resources.Get(ctx, options.GetOptions{}, apiv3.KindTier, noNamespace, tier); err != nil {
		log.WithError(err).Infof("Tier %v does not exist", tier)
		return nil, err
	}

	if res != nil {
		// Since we're about to default some fields, take a (shallow) copy of the input data
		// before we do so.
		resCopy := *res
		res = &resCopy
	}
	// Run defaulting logic.
	if _, err := defaults.Default(res); err != nil {
		return nil, err
	}
	if res.Spec.StagedAction == apiv3.StagedActionDelete {
		res.Spec.Types = nil
	}

	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Create(ctx, opts, apiv3.KindStagedNetworkPolicy, res)
	if out != nil {
		return out.(*apiv3.StagedNetworkPolicy), err
	}

	return nil, err
}

// Update takes the representation of a StagedNetworkPolicy and updates it. Returns the stored
// representation of the StagedNetworkPolicy, and an error, if there is any.
func (r stagedNetworkPolicies) Update(ctx context.Context, res *apiv3.StagedNetworkPolicy, opts options.SetOptions) (*apiv3.StagedNetworkPolicy, error) {
	if res != nil {
		// Since we're about to default some fields, take a (shallow) copy of the input data
		// before we do so.
		resCopy := *res
		res = &resCopy
	}

	// Run defaulting logic.
	if _, err := defaults.Default(res); err != nil {
		return nil, err
	}
	if res.Spec.StagedAction == apiv3.StagedActionDelete {
		res.Spec.Types = nil
	}

	if err := validator.Validate(res); err != nil {
		return nil, err
	}

	out, err := r.client.resources.Update(ctx, opts, apiv3.KindStagedNetworkPolicy, res)
	if out != nil {
		return out.(*apiv3.StagedNetworkPolicy), err
	}

	return nil, err
}

// Delete takes name of the StagedNetworkPolicy and deletes it. Returns an error if one occurs.
func (r stagedNetworkPolicies) Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*apiv3.StagedNetworkPolicy, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv3.KindStagedNetworkPolicy, namespace, name)
	if out != nil {
		// Add the tier labels if necessary
		out.GetObjectMeta().SetLabels(defaultTierLabelIfMissing(out.GetObjectMeta().GetLabels()))
		return out.(*apiv3.StagedNetworkPolicy), err
	}
	return nil, err
}

// Get takes name of the StagedNetworkPolicy, and returns the corresponding StagedNetworkPolicy object,
// and an error if there is any.
func (r stagedNetworkPolicies) Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*apiv3.StagedNetworkPolicy, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv3.KindStagedNetworkPolicy, namespace, name)
	if out != nil {
		// Add the tier labels if necessary
		out.GetObjectMeta().SetLabels(defaultTierLabelIfMissing(out.GetObjectMeta().GetLabels()))
		return out.(*apiv3.StagedNetworkPolicy), err
	}
	return nil, err
}

// List returns the list of StagedNetworkPolicy objects that match the supplied options.
func (r stagedNetworkPolicies) List(ctx context.Context, opts options.ListOptions) (*apiv3.StagedNetworkPolicyList, error) {
	res := &apiv3.StagedNetworkPolicyList{}
	if err := r.client.resources.List(ctx, opts, apiv3.KindStagedNetworkPolicy, apiv3.KindStagedNetworkPolicyList, res); err != nil {
		return nil, err
	}

	// Make sure the tier labels are added
	for i := range res.Items {
		res.Items[i].GetObjectMeta().SetLabels(defaultTierLabelIfMissing(res.Items[i].GetObjectMeta().GetLabels()))
	}

	return res, nil
}

// Watch returns a watch.Interface that watches the stagedNetworkPolicies that match the
// supplied options.
func (r stagedNetworkPolicies) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv3.KindStagedNetworkPolicy, &policyConverter{})
}
