// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package converter

import (
	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// ProfileConverter implements a set of functions used for converting between
// API and backend representations of the Profile resource.
type ProfileConverter struct{}

// ConvertMetadataToKey converts a ProfileMetadata to a ProfileKey
func (p ProfileConverter) ConvertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	hm := m.(api.ProfileMetadata)
	k := model.ProfileKey{
		Name: hm.Name,
	}
	return k, nil
}

// ConvertAPIToKVPair converts an API Profile structure to a KVPair containing a
// backend Profile and ProfileKey.
func (c ProfileConverter) ConvertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	ap := a.(api.Profile)
	k, err := c.ConvertMetadataToKey(ap.Metadata)
	if err != nil {
		return nil, err
	}

	// Fix up tags and labels so to be empty values rather than nil.  Felix does not
	// expect a null value in the JSON, so we fix up to make Labels an empty map
	// and tags an empty slice.
	tags := ap.Metadata.Tags
	if tags == nil {
		log.Debug("Tags is nil - convert to empty map for backend")
		tags = []string{}
	}
	labels := ap.Metadata.Labels
	if labels == nil {
		log.Debug("Labels is nil - convert to empty map for backend")
		labels = map[string]string{}
	}

	d := model.KVPair{
		Key: k,
		Value: &model.Profile{
			Rules: model.ProfileRules{
				InboundRules:  RulesAPIToBackend(ap.Spec.IngressRules),
				OutboundRules: RulesAPIToBackend(ap.Spec.EgressRules),
			},
			Tags:   tags,
			Labels: labels,
		},
	}

	return &d, nil
}

// ConvertKVPairToAPI converts a KVPair containing a backend Profile and ProfileKey
// to an API Profile structure.
func (c ProfileConverter) ConvertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	bp := d.Value.(*model.Profile)
	bk := d.Key.(model.ProfileKey)

	ap := api.NewProfile()
	ap.Metadata.Name = bk.Name
	ap.Metadata.Labels = bp.Labels
	if len(bp.Tags) == 0 {
		ap.Metadata.Tags = nil
	} else {
		ap.Metadata.Tags = bp.Tags
	}
	ap.Spec.IngressRules = RulesBackendToAPI(bp.Rules.InboundRules)
	ap.Spec.EgressRules = RulesBackendToAPI(bp.Rules.OutboundRules)

	return ap, nil
}
