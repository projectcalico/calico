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
	"testing"

	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var order17 = 17.0
var tierTable = []struct {
	description string
	v1API       unversioned.Resource
	v1KVP       *model.KVPair
	v3API       apiv3.Tier
}{
	{
		description: "fully populated Tier",
		v1API: &apiv1.Tier{
			Metadata: apiv1.TierMetadata{
				Name: "nameyMcTierName",
			},
			Spec: apiv1.TierSpec{
				Order: &order17,
			},
		},
		v1KVP: &model.KVPair{
			Key: model.TierKey{
				Name: "nameyMcTierName",
			},
			Value: &model.Tier{
				Order: &order17,
			},
		},
		v3API: apiv3.Tier{
			ObjectMeta: v1.ObjectMeta{
				Name: "nameymctiername-b645ff6a",
			},
			Spec: apiv3.TierSpec{
				Order: &order17,
			},
		},
	},
}

func TestCanConvertV1ToV3Tier(t *testing.T) {

	for _, entry := range tierTable {
		t.Run(entry.description, func(t *testing.T) {
			RegisterTestingT(t)

			p := Tier{}

			// Test and assert v1 API to v1 backend logic.
			v1KVPResult, err := p.APIV1ToBackendV1(entry.v1API)
			Expect(err).NotTo(HaveOccurred(), entry.description)
			Expect(v1KVPResult.Key.(model.TierKey).Name).To(Equal(entry.v1KVP.Key.(model.TierKey).Name))
			Expect(v1KVPResult.Value.(*model.Tier)).To(Equal(entry.v1KVP.Value))

			// Test and assert v1 backend to v3 API logic.
			v3APIResult, err := p.BackendV1ToAPIV3(entry.v1KVP)
			Expect(err).NotTo(HaveOccurred(), entry.description)
			Expect(v3APIResult.(*apiv3.Tier).Name).To(Equal(entry.v3API.Name), entry.description)
			Expect(v3APIResult.(*apiv3.Tier).Spec).To(Equal(entry.v3API.Spec), entry.description)
		})
	}
}
