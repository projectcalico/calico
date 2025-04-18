// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

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
	"fmt"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NetworkPolicyInterface has methods to work with NetworkPolicy resources.
type NetworkPolicyInterface interface {
	Create(ctx context.Context, res *apiv3.NetworkPolicy, opts options.SetOptions) (*apiv3.NetworkPolicy, error)
	Update(ctx context.Context, res *apiv3.NetworkPolicy, opts options.SetOptions) (*apiv3.NetworkPolicy, error)
	Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*apiv3.NetworkPolicy, error)
	Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*apiv3.NetworkPolicy, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv3.NetworkPolicyList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// networkPolicies implements NetworkPolicyInterface
type networkPolicies struct {
	client client
}

// Create takes the representation of a NetworkPolicy and creates it.  Returns the stored
// representation of the NetworkPolicy, and an error, if there is any.
func (r networkPolicies) Create(ctx context.Context, res *apiv3.NetworkPolicy, opts options.SetOptions) (*apiv3.NetworkPolicy, error) {
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
	defaultPolicyTypesField(res.Spec.Ingress, res.Spec.Egress, &res.Spec.Types)

	if err := validator.Validate(res); err != nil {
		return nil, err
	}
	err := names.ValidateTieredPolicyName(res.Name, tier)
	if err != nil {
		return nil, err
	}

	// Add tier labels to policy for lookup.
	if tier != "default" {
		res.GetObjectMeta().SetLabels(addTierLabel(res.GetObjectMeta().GetLabels(), tier))
	}

	out, err := r.client.resources.Create(ctx, opts, apiv3.KindNetworkPolicy, res)
	if out != nil {
		// Add the tier labels if necessary
		out.GetObjectMeta().SetLabels(defaultTierLabelIfMissing(out.GetObjectMeta().GetLabels()))
		return out.(*apiv3.NetworkPolicy), err
	}

	// Add the tier labels if necessary
	res.GetObjectMeta().SetLabels(defaultTierLabelIfMissing(res.GetObjectMeta().GetLabels()))

	return nil, err
}

// Update takes the representation of a NetworkPolicy and updates it. Returns the stored
// representation of the NetworkPolicy, and an error, if there is any.
func (r networkPolicies) Update(ctx context.Context, res *apiv3.NetworkPolicy, opts options.SetOptions) (*apiv3.NetworkPolicy, error) {
	if res != nil {
		// Since we're about to default some fields, take a (shallow) copy of the input data
		// before we do so.
		resCopy := *res
		res = &resCopy
	}
	defaultPolicyTypesField(res.Spec.Ingress, res.Spec.Egress, &res.Spec.Types)

	if err := validator.Validate(res); err != nil {
		return nil, err
	}
	err := names.ValidateTieredPolicyName(res.Name, res.Spec.Tier)
	if err != nil {
		return nil, err
	}

	// Add tier labels to policy for lookup.
	tier := names.TierOrDefault(res.Spec.Tier)
	if tier != "default" {
		res.GetObjectMeta().SetLabels(addTierLabel(res.GetObjectMeta().GetLabels(), tier))
	}

	out, err := r.client.resources.Update(ctx, opts, apiv3.KindNetworkPolicy, res)
	if out != nil {
		// Add the tier labels if necessary
		out.GetObjectMeta().SetLabels(defaultTierLabelIfMissing(out.GetObjectMeta().GetLabels()))
		return out.(*apiv3.NetworkPolicy), err
	}

	// Add the tier labels if necessary
	res.GetObjectMeta().SetLabels(defaultTierLabelIfMissing(res.GetObjectMeta().GetLabels()))

	return nil, err
}

// Delete takes name of the NetworkPolicy and deletes it. Returns an error if one occurs.
func (r networkPolicies) Delete(ctx context.Context, namespace, name string, opts options.DeleteOptions) (*apiv3.NetworkPolicy, error) {
	out, err := r.client.resources.Delete(ctx, opts, apiv3.KindNetworkPolicy, namespace, name)
	if out != nil {
		// Add the tier labels if necessary
		out.GetObjectMeta().SetLabels(defaultTierLabelIfMissing(out.GetObjectMeta().GetLabels()))
		return out.(*apiv3.NetworkPolicy), err
	}
	return nil, err
}

// Get takes name of the NetworkPolicy, and returns the corresponding NetworkPolicy object,
// and an error if there is any.
func (r networkPolicies) Get(ctx context.Context, namespace, name string, opts options.GetOptions) (*apiv3.NetworkPolicy, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv3.KindNetworkPolicy, namespace, name)
	if out != nil {
		// Add the tier labels if necessary
		out.GetObjectMeta().SetLabels(defaultTierLabelIfMissing(out.GetObjectMeta().GetLabels()))
		// Fill in the tier information from the policy name if we find it missing.
		// We expect backend policies to have the right name (prefixed with tier name).
		res_out := out.(*apiv3.NetworkPolicy)
		if res_out.Spec.Tier == "" {
			tier, tierErr := names.TierFromPolicyName(res_out.Name)
			if tierErr != nil {
				log.WithError(tierErr).Infof("Skipping setting tier for name %v", res_out.Name)
				return res_out, tierErr
			}
			res_out.Spec.Tier = tier
		}
		if res_out.Name != name {
			return nil, fmt.Errorf("resource not found NetworkPolicy(%s/%s)", namespace, name)
		}
		return res_out, err
	}
	return nil, err
}

// List returns the list of NetworkPolicy objects that match the supplied options.
func (r networkPolicies) List(ctx context.Context, opts options.ListOptions) (*apiv3.NetworkPolicyList, error) {
	res := &apiv3.NetworkPolicyList{}
	// Add the name prefix if name is provided
	if opts.Name != "" && !opts.Prefix {
		opts.Name = names.TieredPolicyName(opts.Name)
	}

	if err := r.client.resources.List(ctx, opts, apiv3.KindNetworkPolicy, apiv3.KindNetworkPolicyList, res); err != nil {
		return nil, err
	}

	// Make sure the tier labels are added
	for i := range res.Items {
		res.Items[i].GetObjectMeta().SetLabels(defaultTierLabelIfMissing(res.Items[i].GetObjectMeta().GetLabels()))
		// Fill in the tier information from the policy name if we find it missing.
		// We expect backend policies to have the right name (prefixed with tier name).
		if res.Items[i].Spec.Tier == "" {
			tier, tierErr := names.TierFromPolicyName(res.Items[i].Name)
			if tierErr != nil {
				log.WithError(tierErr).Infof("Skipping setting tier for name %v", res.Items[i].Name)
				continue
			}
			res.Items[i].Spec.Tier = tier
		}
	}

	return res, nil
}

// Watch returns a watch.Interface that watches the NetworkPolicies that match the
// supplied options.
func (r networkPolicies) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	// Add the name prefix if name is provided
	if opts.Name != "" {
		opts.Name = names.TieredPolicyName(opts.Name)
	}

	return r.client.resources.Watch(ctx, opts, apiv3.KindNetworkPolicy, &policyConverter{})
}
