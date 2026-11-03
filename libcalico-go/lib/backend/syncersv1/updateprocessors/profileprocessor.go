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

package updateprocessors

import (
	"errors"
	"fmt"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
)

// Create a new SyncerUpdateProcessor to sync Profile data in model and v3 formats for
// consumption by Felix.
func NewProfileUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return &profileUpdateProcessor{
		v3Kind: apiv3.KindProfile,
	}
}

// Profile needs custom logic because it emits two KV pairs: the v1 rules and the whole v3 resource.
type profileUpdateProcessor struct {
	v3Kind string
}

func (pup *profileUpdateProcessor) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	// Check the v3 resource is the correct type.
	v3key, ok := kvp.Key.(model.ResourceKey)
	if !ok || v3key.Kind != pup.v3Kind {
		return nil, fmt.Errorf("Incorrect key type - expecting resource of kind %s", pup.v3Kind)
	}

	if v3key.Name == "" {
		return nil, errors.New("Missing Name field to create a v1 Profile Key")
	}

	v3kvp := *kvp
	ruleskvp := &model.KVPair{
		Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: v3key.Name}},
	}

	// Deletion events will have a value of nil. Do not convert anything for a deletion event.
	if kvp.Value != nil {
		if profile, ok := kvp.Value.(*apiv3.Profile); ok {
			ruleskvp.Value = ProfileRulesAPIV3ToBackend(profile)
			ruleskvp.Revision = kvp.Revision
		} else {
			// Treat a value of the wrong type as a deletion.
			log.WithField("Resource", kvp.Key).Warn("Unable to process resource data - treating as deleted")
			v3kvp.Value = nil
		}
	}

	return []*model.KVPair{ruleskvp, &v3kvp}, nil
}

func (pup *profileUpdateProcessor) OnSyncerStarting() {
	// Do nothing
}

func ProfileRulesAPIV3ToBackend(profile *apiv3.Profile) *model.ProfileRules {
	var irules []model.Rule
	for _, irule := range profile.Spec.Ingress {
		irules = append(irules, RuleAPIV3ToBackend(irule, ""))
	}

	var erules []model.Rule
	for _, erule := range profile.Spec.Egress {
		erules = append(erules, RuleAPIV3ToBackend(erule, ""))
	}

	return &model.ProfileRules{
		InboundRules:  irules,
		OutboundRules: erules,
	}
}
