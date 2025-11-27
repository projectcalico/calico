// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
)

// Create a new SyncerUpdateProcessor to sync Tiers data in v1 format for
// consumption by Felix.
func NewTierUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(
		apiv3.KindTier,
		ConvertTierV3ToV1Key,
		ConvertTierV3ToV1Value,
	)
}

func ConvertTierV3ToV1Key(v3key model.ResourceKey) (model.Key, error) {
	if v3key.Name == "" {
		return model.PolicyKey{}, errors.New("Missing Name or Namespace field to create a v1 Tier Key")
	}
	return model.TierKey{
		Name: v3key.Name,
	}, nil
}

func ConvertTierV3ToV1Value(val interface{}) (interface{}, error) {
	v3res, ok := val.(*apiv3.Tier)
	if !ok {
		return nil, errors.New("Value is not a valid Tier resource value")
	}
	// Any value except Pass is interpreted as Deny.
	action := apiv3.Deny
	if v3res.Spec.DefaultAction != nil && *v3res.Spec.DefaultAction == apiv3.Pass {
		action = apiv3.Pass
	}
	return &model.Tier{
		Order:         v3res.Spec.Order,
		DefaultAction: action,
	}, nil
}
