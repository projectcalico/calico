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

// Profile implements the Converter interface.
type Profile struct{}

// APIV1ToBackendV1 converts v1 Profile API to v1 Profile KVPair.
func (_ Profile) APIV1ToBackendV1(a unversioned.Resource) (*model.KVPair, error) {
	ap := a.(*apiv1.Profile)

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
		Key: model.ProfileKey{
			Name: ap.Metadata.Name,
		},
		Value: &model.Profile{
			Rules: model.ProfileRules{
				InboundRules:  rulesAPIV1ToBackend(ap.Spec.IngressRules),
				OutboundRules: rulesAPIV1ToBackend(ap.Spec.EgressRules),
			},
			Tags:   tags,
			Labels: labels,
		},
	}

	log.WithFields(log.Fields{
		"APIv1":  ap,
		"KVPair": d,
	}).Debugf("Converted Profile: '%s' V1 API to V1 backend", ap.Metadata.Name)

	return &d, nil
}

// BackendV1ToAPIV3 converts v1 Profile KVPair to v3 API.
func (_ Profile) BackendV1ToAPIV3(kvp *model.KVPair) (Resource, error) {
	bp, ok := kvp.Value.(*model.Profile)
	if !ok {
		return nil, fmt.Errorf("value is not a valid Profile resource")
	}
	bk, ok := kvp.Key.(model.ProfileKey)
	if !ok {
		return nil, fmt.Errorf("value is not a valid Profile resource key")
	}

	ap := apiv3.NewProfile()
	ap.Name = convertProfileName(bk.Name)

	// Merge Tags and Labels into LabelsToApply.
	combinedLabelsToApply := bp.Labels
	if combinedLabelsToApply == nil && len(bp.Tags) != 0 {
		combinedLabelsToApply = map[string]string{}
	}
	for _, t := range bp.Tags {
		// Check to make sure the key doesn't already exist before merging it.
		if val, ok := combinedLabelsToApply[t]; ok {
			return nil, fmt.Errorf("Tag: '%s' and Label '%s == %s' have the same value for Profile: %s. Change the Label key before proceeding", t, t, val, ap.Name)
		}
		combinedLabelsToApply[t] = ""
	}

	ap.Spec.LabelsToApply = combinedLabelsToApply

	ap.Spec.Ingress = rulesV1BackendToV3API(bp.Rules.InboundRules)
	ap.Spec.Egress = rulesV1BackendToV3API(bp.Rules.OutboundRules)

	log.WithFields(log.Fields{
		"KVPairV1": bp,
		"APIv3":    ap,
	}).Debugf("Converted Profile: '%s' V1 backend to V3 API", ap.Name)

	return ap, nil
}

// convertProfileName updates the Kubernetes namespace portion from "k8s_ns" to "kns".
func convertProfileName(in string) string {
	if strings.HasPrefix(in, "k8s_ns.") {
		prof := "kns." + strings.TrimPrefix(in, "k8s_ns.")
		return convertName(prof)
	}
	return convertName(in)
}
