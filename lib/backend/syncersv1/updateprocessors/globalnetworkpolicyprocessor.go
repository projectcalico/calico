// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
)

// Create a new SyncerUpdateProcessor to sync GlobalNetworkPolicy data in v1 format for
// consumption by Felix.
func NewGlobalNetworkPolicyUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(apiv2.KindGlobalNetworkPolicy, convertGlobalNetworkPolicyV2ToV1Key, convertGlobalNetworkPolicyV2ToV1Value)
}

func convertGlobalNetworkPolicyV2ToV1Key(v2key model.ResourceKey) (model.Key, error) {
	if v2key.Name == "" {
		return model.PolicyKey{}, errors.New("Missing Name field to create a v1 NetworkPolicy Key")
	}
	return model.PolicyKey{
		Name: v2key.Name,
	}, nil

}

func convertGlobalNetworkPolicyV2ToV1Value(val interface{}) (interface{}, error) {
	v2res, ok := val.(*apiv2.GlobalNetworkPolicy)
	if !ok {
		return nil, errors.New("Value is not a valid GlobalNetworkPolicy resource value")
	}
	return convertPolicyV2ToV1Spec(v2res.Spec)
}
