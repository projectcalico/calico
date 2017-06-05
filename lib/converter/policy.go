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
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

// PolicyConverter implements a set of functions used for converting between
// API and backend representations of the Policy resource.
type PolicyConverter struct{}

// ConvertMetadataToKey converts a PolicyMetadata to a PolicyKey
func (p PolicyConverter) ConvertMetadataToKey(m unversioned.ResourceMetadata) model.Key {
	pm := m.(api.PolicyMetadata)
	k := model.PolicyKey{
		Name: pm.Name,
	}
	return k
}

// ConvertAPIToKVPair converts an API Policy structure to a KVPair containing a
// backend Policy and PolicyKey.
func (p PolicyConverter) ConvertAPIToKVPair(a unversioned.Resource) *model.KVPair {
	ap := a.(api.Policy)
	k := p.ConvertMetadataToKey(ap.Metadata)

	d := model.KVPair{
		Key: k,
		Value: &model.Policy{
			Order:         ap.Spec.Order,
			InboundRules:  RulesAPIToBackend(ap.Spec.IngressRules),
			OutboundRules: RulesAPIToBackend(ap.Spec.EgressRules),
			Selector:      ap.Spec.Selector,
			DoNotTrack:    ap.Spec.DoNotTrack,
		},
	}

	return &d
}

// ConvertKVPairToAPI converts a KVPair containing a backend Policy and PolicyKey
// to an API Policy structure.
func (p PolicyConverter) ConvertKVPairToAPI(d *model.KVPair) unversioned.Resource {
	bp := d.Value.(*model.Policy)
	bk := d.Key.(model.PolicyKey)

	ap := api.NewPolicy()
	ap.Metadata.Name = bk.Name
	ap.Spec.Order = bp.Order
	ap.Spec.IngressRules = RulesBackendToAPI(bp.InboundRules)
	ap.Spec.EgressRules = RulesBackendToAPI(bp.OutboundRules)
	ap.Spec.Selector = bp.Selector
	ap.Spec.DoNotTrack = bp.DoNotTrack

	return ap
}
