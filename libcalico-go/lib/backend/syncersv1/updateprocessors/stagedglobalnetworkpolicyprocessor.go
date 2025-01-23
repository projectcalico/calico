// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

package updateprocessors

import (
	"errors"
	"fmt"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// NewStagedGlobalNetworkPolicyUpdateProcessor create a new SyncerUpdateProcessor to sync StagedGlobalNetworkPolicy data in v1 format for
// consumption by Felix.
func NewStagedGlobalNetworkPolicyUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(apiv3.KindStagedGlobalNetworkPolicy, ConvertStagedGlobalNetworkPolicyV3ToV1Key, ConvertStagedGlobalNetworkPolicyV3ToV1Value)
}

func ConvertStagedGlobalNetworkPolicyV3ToV1Key(v3key model.ResourceKey) (model.Key, error) {
	if v3key.Name == "" {
		return model.PolicyKey{}, errors.New("Missing Name field to create a v1 NetworkPolicy Key")
	}
	tier, err := names.TierFromPolicyName(v3key.Name)
	if err != nil {
		return model.PolicyKey{}, err
	}
	return model.PolicyKey{
		Name: model.PolicyNamePrefixStaged + v3key.Name,
		Tier: tier,
	}, nil

}

func ConvertStagedGlobalNetworkPolicyV3ToV1Value(val interface{}) (interface{}, error) {
	staged, ok := val.(*apiv3.StagedGlobalNetworkPolicy)
	if !ok {
		return nil, errors.New("Value is not a valid StagedGlobalNetworkPolicy resource value")
	}

	// If the update type is delete return nil so the resource is not sent to felix.
	if staged.Spec.StagedAction == apiv3.StagedActionDelete {
		return nil, nil
	}

	// convert v3 staged to v3 enforced
	stagedAction, enforced := apiv3.ConvertStagedGlobalPolicyToEnforced(staged)

	// convert v3 enforced to v1 model
	policy, err := ConvertGlobalNetworkPolicyV3ToV1Value(enforced)
	if err != nil {
		return nil, err
	}

	// Type assert and update stagedAction
	if p, ok := policy.(*model.Policy); ok && stagedAction != "" {
		p.StagedAction = &stagedAction
	} else if !ok {
		// Handle the case where policy is not of type *model.Policy
		return nil, fmt.Errorf("unexpected policy type: %T", policy)
	}

	return policy, nil
}
