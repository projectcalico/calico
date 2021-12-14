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
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
)

// NewSimpleUpdateProcessor implements an update processor that only needs to take in
// a conversion function. This is only meant to be used in cases where the Process and
// OnSyncerStarting methods do not have any special handling.
//
// One of the main differences between the simple update processor and the conflict
// resolving name cache processor is that the conflict resolving name cache processor
// uses a cache to handle conflicts when v1 objects cannot be built up using only the
// resource key. The simple update processor is for converting objects that can create
// the v1 key using only the information available in the resource key.

// Function signature to convert a v3 model.ResourceKey to a v1 model.Key type
type ConvertV2ToV1Key func(v3Key model.ResourceKey) (model.Key, error)

// Function to convert a v3 resource to the v1 value.  The converter may filter out
// results by returning nil.  The generic watchersyncer will handle filtered out events
// by either sending no event or sending delete events depending on whether the entry
// is currently in the cache.
type ConvertV2ToV1Value func(interface{}) (interface{}, error)

func NewSimpleUpdateProcessor(v3Kind string, kConverter ConvertV2ToV1Key, vConverter ConvertV2ToV1Value) watchersyncer.SyncerUpdateProcessor {
	return &simpleUpdateProcessor{
		v3Kind:         v3Kind,
		keyConverter:   kConverter,
		valueConverter: vConverter,
	}
}

type simpleUpdateProcessor struct {
	v3Kind         string
	keyConverter   ConvertV2ToV1Key
	valueConverter ConvertV2ToV1Value
}

func (sup *simpleUpdateProcessor) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	// Check the v3 resource is the correct type.
	rk, ok := kvp.Key.(model.ResourceKey)
	if !ok || rk.Kind != sup.v3Kind {
		return nil, fmt.Errorf("Incorrect key type - expecting resource of kind %s", sup.v3Kind)
	}

	// Convert the v3 resource to the equivalent v1 resource type.
	v3key, ok := kvp.Key.(model.ResourceKey)
	if !ok {
		return nil, errors.New("Key is not a valid V2 resource key")
	}
	v1key, err := sup.keyConverter(v3key)
	if err != nil {
		return nil, err
	}

	var v1value interface{}
	// Deletion events will have a value of nil. Do not convert anything for a deletion event.
	if kvp.Value != nil {
		v1value, err = sup.valueConverter(kvp.Value)
		if err != nil {
			// Currently treat any values that fail to convert properly as a deletion event.
			log.WithField("Resource", kvp.Key).Warn("Unable to process resource data - treating as deleted")
			return []*model.KVPair{{Key: v1key}}, nil
		}
		if v1value == nil {
			// If the value is filtered out by the processor, treat as a delete.
			log.WithField("Resource", kvp.Key).Debug("Filtering out resource - treating as deleted")
			return []*model.KVPair{{Key: v1key}}, nil
		}
	}

	return []*model.KVPair{
		{
			Key:      v1key,
			Value:    v1value,
			Revision: kvp.Revision,
		},
	}, nil
}

func (sup *simpleUpdateProcessor) OnSyncerStarting() {
	// Do nothing
}
