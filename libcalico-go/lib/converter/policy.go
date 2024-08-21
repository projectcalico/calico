// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.

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
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// PolicyConverter implements a set of functions used for converting between
// API and backend representations of the Policy resource.
type PolicyConverter struct{}

// ConvertMetadataToKey converts a PolicyMetadata to a PolicyKey
func (p PolicyConverter) ConvertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	pm := m.(api.PolicyMetadata)
	k := model.PolicyKey{
		Name: pm.Name,
		Tier: names.TierOrDefault(pm.Tier),
	}
	return k, nil
}

// ConvertAPIToKVPair converts an API Policy structure to a KVPair containing a
// backend Policy and PolicyKey.
func (p PolicyConverter) ConvertAPIToKVPair(a unversioned.Resource) (*model.KVPair, error) {
	ap := a.(api.Policy)
	k, err := p.ConvertMetadataToKey(ap.Metadata)
	if err != nil {
		return nil, err
	}

	d := model.KVPair{
		Key: k,
		Value: &model.Policy{
			Order:         ap.Spec.Order,
			InboundRules:  RulesAPIToBackend(ap.Spec.IngressRules),
			OutboundRules: RulesAPIToBackend(ap.Spec.EgressRules),
			Selector:      ap.Spec.Selector,
			DoNotTrack:    ap.Spec.DoNotTrack,
			Annotations:   ap.Metadata.Annotations,
			PreDNAT:       ap.Spec.PreDNAT,
			Types:         nil, // filled in below
		},
	}

	if ap.Spec.DoNotTrack || ap.Spec.PreDNAT {
		// This case happens when there is a preexisting policy in the datastore, from before
		// the ApplyOnForward feature was available. DoNotTrack or PreDNAT policy applies to
		// forward traffic by nature. So in this case we return ApplyOnForward flag as true.
		d.Value.(*model.Policy).ApplyOnForward = true
	}

	if len(ap.Spec.Types) == 0 {
		// Default the Types field according to what inbound and outbound rules are present
		// in the policy.
		if len(ap.Spec.EgressRules) == 0 {
			// Policy has no egress rules, so apply this policy to ingress only.  (Note:
			// intentionally including the case where the policy also has no ingress
			// rules.)
			d.Value.(*model.Policy).Types = []string{string(api.PolicyTypeIngress)}
		} else if len(ap.Spec.IngressRules) == 0 {
			// Policy has egress rules but no ingress rules, so apply this policy to
			// egress only.
			d.Value.(*model.Policy).Types = []string{string(api.PolicyTypeEgress)}
		} else {
			// Policy has both ingress and egress rules, so apply this policy to both
			// ingress and egress.
			d.Value.(*model.Policy).Types = []string{string(api.PolicyTypeIngress), string(api.PolicyTypeEgress)}
		}
	} else {
		// Convert from the API-specified Types.
		d.Value.(*model.Policy).Types = make([]string, len(ap.Spec.Types))
		for i, t := range ap.Spec.Types {
			d.Value.(*model.Policy).Types[i] = string(t)
		}
	}

	return &d, nil
}

// ConvertKVPairToAPI converts a KVPair containing a backend Policy and PolicyKey
// to an API Policy structure.
func (p PolicyConverter) ConvertKVPairToAPI(d *model.KVPair) (unversioned.Resource, error) {
	bp := d.Value.(*model.Policy)
	bk := d.Key.(model.PolicyKey)

	ap := api.NewPolicy()
	ap.Metadata.Name = bk.Name
	ap.Metadata.Tier = bk.Tier
	ap.Metadata.Annotations = bp.Annotations
	ap.Spec.Order = bp.Order
	ap.Spec.IngressRules = RulesBackendToAPI(bp.InboundRules)
	ap.Spec.EgressRules = RulesBackendToAPI(bp.OutboundRules)
	ap.Spec.Selector = bp.Selector
	ap.Spec.DoNotTrack = bp.DoNotTrack
	ap.Spec.PreDNAT = bp.PreDNAT
	ap.Spec.Types = nil

	if len(bp.Types) == 0 {
		// This case happens when there is a preexisting policy in an etcd datastore, from
		// before the explicit Types feature was available.  Calico's previous behaviour was
		// always to apply policy to both ingress and egress traffic, so in this case we
		// return Types as [ ingress, egress ].
		if bp.PreDNAT {
			ap.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		} else {
			ap.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		}
	} else {
		// Convert from the backend-specified Types.
		ap.Spec.Types = make([]api.PolicyType, len(bp.Types))
		for i, t := range bp.Types {
			ap.Spec.Types[i] = api.PolicyType(t)
		}
	}

	return ap, nil
}
