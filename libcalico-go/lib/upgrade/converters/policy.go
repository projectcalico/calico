// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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

package converters

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Policy implements the Converter interface.
type Policy struct{}

// APIV1ToBackendV1 converts v1 Policy API to v1 Policy KVPair.
func (_ Policy) APIV1ToBackendV1(a unversioned.Resource) (*model.KVPair, error) {
	ap := a.(*apiv1.Policy)

	d := model.KVPair{
		Key: model.PolicyKey{
			Name: ap.Metadata.Name,
		},
		Value: &model.Policy{
			Order:         ap.Spec.Order,
			InboundRules:  rulesAPIV1ToBackend(ap.Spec.IngressRules),
			OutboundRules: rulesAPIV1ToBackend(ap.Spec.EgressRules),
			Selector:      ap.Spec.Selector,
			DoNotTrack:    ap.Spec.DoNotTrack,
			Annotations:   ap.Metadata.Annotations,
			PreDNAT:       ap.Spec.PreDNAT,
			Types:         nil, // filled in below
		},
	}

	if ap.Spec.DoNotTrack || ap.Spec.PreDNAT {
		// This case happens when there is a pre-existing policy in the datastore, from before
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
			d.Value.(*model.Policy).Types = []string{string(apiv1.PolicyTypeIngress)}
		} else if len(ap.Spec.IngressRules) == 0 {
			// Policy has egress rules but no ingress rules, so apply this policy to
			// egress only.
			d.Value.(*model.Policy).Types = []string{string(apiv1.PolicyTypeEgress)}
		} else {
			// Policy has both ingress and egress rules, so apply this policy to both
			// ingress and egress.
			d.Value.(*model.Policy).Types = []string{string(apiv1.PolicyTypeIngress), string(apiv1.PolicyTypeEgress)}
		}
	} else {
		// Convert from the API-specified Types.
		d.Value.(*model.Policy).Types = make([]string, len(ap.Spec.Types))
		for i, t := range ap.Spec.Types {
			d.Value.(*model.Policy).Types[i] = string(t)
		}
	}

	log.WithFields(log.Fields{
		"APIv1":  ap,
		"KVPair": d,
	}).Debugf("Converted Policy '%s' V1 API to V1 backend", ap.Metadata.Name)

	return &d, nil
}

// BackendV1ToAPIV3 converts v1 Policy KVPair to v3 API.
func (_ Policy) BackendV1ToAPIV3(kvp *model.KVPair) (Resource, error) {
	bp, ok := kvp.Value.(*model.Policy)
	if !ok {
		return nil, fmt.Errorf("value is not a valid Policy resource")
	}
	bk, ok := kvp.Key.(model.PolicyKey)
	if !ok {
		return nil, fmt.Errorf("value is not a valid Policy resource key")
	}

	ap := apiv3.NewGlobalNetworkPolicy()
	ap.Name = convertNameNoDots(bk.Name)
	ap.Annotations = bp.Annotations
	ap.Spec.Order = bp.Order
	ap.Spec.Ingress = rulesV1BackendToV3API(bp.InboundRules)
	ap.Spec.Egress = rulesV1BackendToV3API(bp.OutboundRules)
	ap.Spec.Selector = convertSelector(bp.Selector)
	ap.Spec.DoNotTrack = bp.DoNotTrack
	ap.Spec.PreDNAT = bp.PreDNAT
	ap.Spec.ApplyOnForward = bp.ApplyOnForward
	ap.Spec.Types = nil // Set later.

	if !bp.ApplyOnForward && (bp.DoNotTrack || bp.PreDNAT) {
		// This case happens when there is a pre-existing policy in the datastore, from before
		// the ApplyOnForward feature was available. DoNotTrack or PreDNAT policy applies to
		// forward traffic by nature. So in this case we return ApplyOnForward flag as true.
		ap.Spec.ApplyOnForward = true
	}

	if len(bp.Types) == 0 {
		// This case happens when there is a pre-existing policy in an etcd datastore, from
		// before the explicit Types feature was available.  Calico's previous behaviour was
		// always to apply policy to both ingress and egress traffic, so in this case we
		// return Types as [ ingress, egress ].
		if bp.PreDNAT {
			ap.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeIngress}
		} else {
			ap.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress}
		}
	} else {
		// Convert from the backend-specified Types.
		ap.Spec.Types = make([]apiv3.PolicyType, len(bp.Types))
		for i, t := range bp.Types {
			if strings.ToLower(t) == "ingress" {
				ap.Spec.Types[i] = apiv3.PolicyTypeIngress
			} else if strings.ToLower(t) == "egress" {
				ap.Spec.Types[i] = apiv3.PolicyTypeEgress
			} else {
				return nil, fmt.Errorf("invalid policy type: '%s'", t)
			}
		}
	}

	log.WithFields(log.Fields{
		"KVPairV1": bp,
		"APIv3":    ap,
	}).Debugf("Converted Policy '%s' V1 backend to GlobalNetworkPolicy '%s' V3 API", bk.Name, ap.Name)

	return ap, nil
}
