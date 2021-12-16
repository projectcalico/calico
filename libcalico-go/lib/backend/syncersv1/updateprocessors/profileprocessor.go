// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

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

// Need to create custom logic for Profile since it breaks the values into 3 separate KV Pairs:
// Tags, Labels, and Rules.
type profileUpdateProcessor struct {
	v3Kind string
}

func (pup *profileUpdateProcessor) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	// Check the v3 resource is the correct type.
	rk, ok := kvp.Key.(model.ResourceKey)
	if !ok || rk.Kind != pup.v3Kind {
		return nil, fmt.Errorf("Incorrect key type - expecting resource of kind %s", pup.v3Kind)
	}

	// Convert the v3 resource to the equivalent v1 resource type.
	v3key, ok := kvp.Key.(model.ResourceKey)
	if !ok {
		return nil, errors.New("Key is not a valid V2 resource key")
	}

	if v3key.Name == "" {
		return nil, errors.New("Missing Name field to create a v1 Profile Key")
	}

	pk := model.ProfileKey{
		Name: v3key.Name,
	}

	v1labelsKey := model.ProfileLabelsKey{pk}
	v1rulesKey := model.ProfileRulesKey{pk}
	v3kvp := *kvp

	var v1profile *model.Profile
	var err error
	// Deletion events will have a value of nil. Do not convert anything for a deletion event.
	if kvp.Value != nil {
		v1profile, err = convertProfileV2ToV1Value(kvp.Value)
		if err != nil {
			// Currently treat any errors as a deletion event.
			log.WithField("Resource", kvp.Key).Warn("Unable to process resource data - treating as deleted")
			v3kvp.Value = nil
		}
	}

	labelskvp := &model.KVPair{
		Key: v1labelsKey,
	}
	ruleskvp := &model.KVPair{
		Key: v1rulesKey,
	}

	if v1profile != nil {
		if len(v1profile.Labels) > 0 {
			labelskvp.Value = v1profile.Labels
			labelskvp.Revision = kvp.Revision
		}
		ruleskvp.Value = &v1profile.Rules
		ruleskvp.Revision = kvp.Revision
	}

	// Stream the whole v3 Profile resource, as well as the v1 pieces that legacy Felix code
	// expects.
	return []*model.KVPair{labelskvp, ruleskvp, &v3kvp}, nil
}

func (pup *profileUpdateProcessor) OnSyncerStarting() {
	// Do nothing
}

func convertProfileV2ToV1Value(val interface{}) (*model.Profile, error) {
	v3res, ok := val.(*apiv3.Profile)
	if !ok {
		return nil, errors.New("Value is not a valid Profile resource value")
	}

	var irules []model.Rule
	for _, irule := range v3res.Spec.Ingress {
		irules = append(irules, RuleAPIV2ToBackend(irule, ""))
	}

	var erules []model.Rule
	for _, erule := range v3res.Spec.Egress {
		erules = append(erules, RuleAPIV2ToBackend(erule, ""))
	}

	rules := model.ProfileRules{
		InboundRules:  irules,
		OutboundRules: erules,
	}

	v1value := &model.Profile{
		Rules:  rules,
		Labels: v3res.Spec.LabelsToApply,
	}

	return v1value, nil
}
