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

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
)

// Create a new SyncerUpdateProcessor to sync IPPool data in v1 format for
// consumption by both Felix and the BGP daemon.
func NewIPPoolUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewConflictResolvingCacheUpdateProcessor(apiv3.KindIPPool, convertIPPoolV2ToV1)
}

// Convert v3 KVPair to the equivalent v1 KVPair.
func convertIPPoolV2ToV1(kvp *model.KVPair) (*model.KVPair, error) {
	// Validate against incorrect key/value kinds.  This indicates a code bug rather
	// than a user error.
	v3key, ok := kvp.Key.(model.ResourceKey)
	if !ok || v3key.Kind != apiv3.KindIPPool {
		return nil, errors.New("Key is not a valid IPPool resource key")
	}
	_, ok = kvp.Value.(*apiv3.IPPool)
	if !ok {
		return nil, errors.New("Value is not a valid IPPool resource value")
	}

	// Correct data types.  Handle the conversion.
	v1res, err := resources.IPPoolV3ToV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1res, nil
}
