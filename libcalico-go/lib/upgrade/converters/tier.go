// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Tier implements the Converter interface.
type Tier struct{}

// APIV1ToBackendV1 converts v1 Tier API to v1 Tier KVPair.
func (_ Tier) APIV1ToBackendV1(a unversioned.Resource) (*model.KVPair, error) {
	ap := a.(*apiv1.Tier)

	d := model.KVPair{
		Key: model.TierKey{
			Name: ap.Metadata.Name,
		},
		Value: &model.Tier{
			Order: ap.Spec.Order,
		},
	}

	log.WithFields(log.Fields{
		"APIv1":  ap,
		"KVPair": d,
	}).Debugf("Converted Tier: '%s' V1 API to V1 backend", ap.Metadata.Name)

	return &d, nil
}

// BackendV1ToAPIV3 converts v1 Tier KVPair to v3 API.
func (_ Tier) BackendV1ToAPIV3(kvp *model.KVPair) (Resource, error) {
	bp, ok := kvp.Value.(*model.Tier)
	if !ok {
		return nil, fmt.Errorf("value is not a valid Tier resource")
	}
	bk, ok := kvp.Key.(model.TierKey)
	if !ok {
		return nil, fmt.Errorf("value is not a valid Tier resource key")
	}

	ap := apiv3.NewTier()
	ap.Name = convertName(bk.Name)
	ap.Spec.Order = bp.Order

	log.WithFields(log.Fields{
		"KVPairV1": bp,
		"APIv3":    ap,
	}).Debugf("Converted Tier: '%s' V1 backend to V3 API", ap.Name)

	return ap, nil
}
