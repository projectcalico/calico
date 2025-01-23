// Copyright (c) 2017-2024 Tigera, Inc. All rights reserved.

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

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	cresources "github.com/projectcalico/calico/libcalico-go/lib/resources"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// TierInterface has methods to work with Tier resources.
type TierInterface interface {
	Create(ctx context.Context, res *apiv3.Tier, opts options.SetOptions) (*apiv3.Tier, error)
	Update(ctx context.Context, res *apiv3.Tier, opts options.SetOptions) (*apiv3.Tier, error)
	Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.Tier, error)
	Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.Tier, error)
	List(ctx context.Context, opts options.ListOptions) (*apiv3.TierList, error)
	Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// tiers implements TierInterface
type tiers struct {
	client client
}

// Create takes the representation of a Tier and creates it.  Returns the stored
// representation of the Tier, and an error, if there is any.
func (r tiers) Create(ctx context.Context, res *apiv3.Tier, opts options.SetOptions) (*apiv3.Tier, error) {
	if res != nil {
		// Since we're about to default some fields, take a (shallow) copy of the input data
		// before we do so.
		resCopy := *res
		res = &resCopy
	}
	cresources.DefaultTierFields(res)
	if err := validator.Validate(res); err != nil {
		return nil, err
	}
	out, err := r.client.resources.Create(ctx, opts, apiv3.KindTier, res)
	if out != nil {
		return out.(*apiv3.Tier), err
	}
	return nil, err
}

// Update takes the representation of a Tier and updates it. Returns the stored
// representation of the Tier, and an error, if there is any.
func (r tiers) Update(ctx context.Context, res *apiv3.Tier, opts options.SetOptions) (*apiv3.Tier, error) {
	if res != nil {
		// Since we're about to default some fields, take a (shallow) copy of the input data
		// before we do so.
		resCopy := *res
		res = &resCopy
	}
	cresources.DefaultTierFields(res)
	if err := validator.Validate(res); err != nil {
		return nil, err
	}
	out, err := r.client.resources.Update(ctx, opts, apiv3.KindTier, res)
	if out != nil {
		return out.(*apiv3.Tier), err
	}
	return nil, err
}

// Delete takes name of the Tier and deletes it. Returns an error if one occurs.
func (r tiers) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.Tier, error) {
	if name == names.DefaultTierName || name == names.AdminNetworkPolicyTierName {
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: name,
			Operation:  "Delete",
			Reason:     fmt.Sprintf("Cannot delete %v tier", name),
		}
	}

	// List the (Staged)NetworkPolicy and (Staged)GlobalNetworkPolicy resources that are prefixed with this tier name.  Note that
	// a prefix matching may return additional results that are not actually in this tier, so we also need to check
	// the spec field to be certain.
	policyListOptions := options.ListOptions{
		Prefix: true,
		Name:   name + ".",
	}

	// Check NetworkPolicy resources.
	if npList, err := r.client.NetworkPolicies().List(ctx, policyListOptions); err != nil {
		return nil, err
	} else {
		for _, np := range npList.Items {
			if np.Spec.Tier == name {
				log.WithField("name", np.Name).Debug("Enumerated NetworkPolicy is in this tier")
				return nil, cerrors.ErrorOperationNotSupported{
					Operation:  "delete",
					Identifier: name,
					Reason:     "Cannot delete a non-empty tier",
				}
			}
		}
	}

	// Check GlobalNetworkPolicy resources.
	if gnpList, err := r.client.GlobalNetworkPolicies().List(ctx, policyListOptions); err != nil {
		return nil, err
	} else {
		for _, gnp := range gnpList.Items {
			if gnp.Spec.Tier == name {
				log.WithField("name", gnp.Name).Debug("Enumerated GlobalNetworkPolicy is in this tier")
				return nil, cerrors.ErrorOperationNotSupported{
					Operation:  "delete",
					Identifier: name,
					Reason:     "Cannot delete a non-empty tier",
				}
			}
		}
	}

	// Check StagedNetworkPolicy resources.
	if snpList, err := r.client.StagedNetworkPolicies().List(ctx, policyListOptions); err != nil {
		return nil, err
	} else {
		for _, snp := range snpList.Items {
			if snp.Spec.Tier == name {
				log.WithField("name", snp.Name).Debug("Enumerated StagedNetworkPolicy is in this tier")
				return nil, cerrors.ErrorOperationNotSupported{
					Operation:  "delete",
					Identifier: name,
					Reason:     "Cannot delete a non-empty tier",
				}
			}
		}
	}

	//TODO: mgianluc StagedKubernetesNetworkPolicy are part or default tier. Is same check needed for StagedKubernetesNetworkPolicy. Seems no.

	// Check StagedGlobalNetworkPolicy resources.
	if sgnpList, err := r.client.StagedGlobalNetworkPolicies().List(ctx, policyListOptions); err != nil {
		return nil, err
	} else {
		for _, sgnp := range sgnpList.Items {
			if sgnp.Spec.Tier == name {
				log.WithField("name", sgnp.Name).Debug("Enumerated GlobalNetworkPolicy is in this tier")
				return nil, cerrors.ErrorOperationNotSupported{
					Operation:  "delete",
					Identifier: name,
					Reason:     "Cannot delete a non-empty tier",
				}
			}
		}
	}

	out, err := r.client.resources.Delete(ctx, opts, apiv3.KindTier, noNamespace, name)
	if out != nil {
		return out.(*apiv3.Tier), err
	}
	return nil, err
}

// Get takes name of the Tier, and returns the corresponding Tier object,
// and an error if there is any.
func (r tiers) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.Tier, error) {
	out, err := r.client.resources.Get(ctx, opts, apiv3.KindTier, noNamespace, name)
	if out != nil {
		res := out.(*apiv3.Tier)
		return res, err
	}
	return nil, err
}

// List returns the list of Tier objects that match the supplied options.
func (r tiers) List(ctx context.Context, opts options.ListOptions) (*apiv3.TierList, error) {
	res := &apiv3.TierList{}
	if err := r.client.resources.List(ctx, opts, apiv3.KindTier, apiv3.KindTierList, res); err != nil {
		return nil, err
	}
	// Default values when reading from backend.
	for i := range res.Items {
		cresources.DefaultTierFields(&res.Items[i])
	}
	return res, nil
}

// Watch returns a watch.Interface that watches the tiers that match the
// supplied options.
func (r tiers) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	return r.client.resources.Watch(ctx, opts, apiv3.KindTier, nil)
}
