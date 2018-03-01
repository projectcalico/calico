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
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/projectcalico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/libcalico-go/lib/apis/v1/unversioned"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

var profileTable = []struct {
	description string
	v1API       unversioned.Resource
	v1KVP       *model.KVPair
	v3API       apiv3.Profile
}{
	{
		description: "fully populated Profile",
		v1API: &apiv1.Profile{
			Metadata: apiv1.ProfileMetadata{
				Name:   "nameyMcProfileName",
				Tags:   []string{"meep", "mop"},
				Labels: map[string]string{"pncs.thingy": "val"},
			},
			Spec: apiv1.ProfileSpec{
				IngressRules: []apiv1.Rule{V1InRule1, V1InRule2},
				EgressRules:  []apiv1.Rule{V1EgressRule1, V1EgressRule2},
			},
		},
		v1KVP: &model.KVPair{
			Key: model.ProfileKey{
				Name: "nameyMcProfileName",
			},
			Value: &model.Profile{
				Rules: model.ProfileRules{
					InboundRules:  []model.Rule{V1ModelInRule1, V1ModelInRule2},
					OutboundRules: []model.Rule{V1ModelEgressRule1, V1ModelEgressRule2},
				},
				Tags:   []string{"meep", "mop"},
				Labels: map[string]string{"pncs.thingy": "val"},
			},
		},
		v3API: apiv3.Profile{
			ObjectMeta: v1.ObjectMeta{
				Name: "nameymcprofilename-9740ed19",
			},
			Spec: apiv3.ProfileSpec{
				Ingress:       []apiv3.Rule{V3InRule1, V3InRule2},
				Egress:        []apiv3.Rule{V3EgressRule1, V3EgressRule2},
				LabelsToApply: map[string]string{"pncs.thingy": "val", "meep": "", "mop": ""},
			},
		},
	},
	{
		description: "Profile name conversion",
		v1API: &apiv1.Profile{
			Metadata: apiv1.ProfileMetadata{
				Name: "k8s_ns.FlUx-.-CaPaCiToR$$",
				Tags: []string{"lalala"},
			},
			Spec: apiv1.ProfileSpec{
				IngressRules: []apiv1.Rule{V1InRule1, V1InRule2},
				EgressRules:  []apiv1.Rule{},
			},
		},
		v1KVP: &model.KVPair{
			Key: model.ProfileKey{
				Name: "k8s_ns.FlUx-.-CaPaCiToR$$",
			},
			Value: &model.Profile{
				Rules: model.ProfileRules{
					InboundRules:  []model.Rule{V1ModelInRule1, V1ModelInRule2},
					OutboundRules: []model.Rule{},
				},
				Tags:   []string{"lalala"},
				Labels: map[string]string{},
			},
		},
		v3API: apiv3.Profile{
			ObjectMeta: v1.ObjectMeta{
				Name: "kns.flux.capacitor-a9ad9f16",
			},
			Spec: apiv3.ProfileSpec{
				Ingress:       []apiv3.Rule{V3InRule1, V3InRule2},
				Egress:        []apiv3.Rule{},
				LabelsToApply: map[string]string{"lalala": ""},
			},
		},
	},
}

func TestCanConvertV1ToV3Profile(t *testing.T) {

	for _, entry := range profileTable {
		t.Run(entry.description, func(t *testing.T) {
			RegisterTestingT(t)

			p := Profile{}

			// Test and assert v1 API to v1 backend logic.
			v1KVPResult, err := p.APIV1ToBackendV1(entry.v1API)
			Expect(err).NotTo(HaveOccurred(), entry.description)
			Expect(v1KVPResult.Key.(model.ProfileKey).Name).To(Equal(entry.v1KVP.Key.(model.ProfileKey).Name))
			Expect(v1KVPResult.Value.(*model.Profile)).To(Equal(entry.v1KVP.Value))

			// Test and assert v1 backend to v3 API logic.
			v3APIResult, err := p.BackendV1ToAPIV3(entry.v1KVP)
			Expect(err).NotTo(HaveOccurred(), entry.description)
			Expect(v3APIResult.(*apiv3.Profile).Name).To(Equal(entry.v3API.Name), entry.description)
			Expect(v3APIResult.(*apiv3.Profile).Spec).To(Equal(entry.v3API.Spec), entry.description)
		})
	}
}

func TestExitOnTagLabelCollision(t *testing.T) {
	t.Run("Profile conversion should exit with an error when a Tag has the same value as a Label key", func(t *testing.T) {
		RegisterTestingT(t)

		p := Profile{}

		v1KVP := &model.KVPair{
			Key: model.ProfileKey{
				Name: "makemake",
			},
			Value: &model.Profile{
				Rules: model.ProfileRules{
					InboundRules:  []model.Rule{V1ModelInRule1, V1ModelInRule2},
					OutboundRules: []model.Rule{},
				},
				Tags:   []string{"lalala", "covfefe", "meep"},
				Labels: map[string]string{"thing1": "val1", "covfefe": "hot", "thing2": "val2"},
			},
		}

		// Assert that converting v1 backend to v3 API returns an error.
		_, err := p.BackendV1ToAPIV3(v1KVP)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal(fmt.Sprintf("Tag: '%s' and Label '%s == %s' have the same value for Profile: %s. Change the Label key before proceeding", "covfefe", "covfefe", "hot", "makemake")))
	})
}

func TestNoLabelsOnBackend(t *testing.T) {
	t.Run("Profile conversion should succeed when there are no labels but there are tags", func(t *testing.T) {
		RegisterTestingT(t)

		p := Profile{}

		v1KVP := &model.KVPair{
			Key: model.ProfileKey{
				Name: "makemake",
			},
			Value: &model.Profile{
				Rules: model.ProfileRules{
					InboundRules:  []model.Rule{V1ModelInRule1, V1ModelInRule2},
					OutboundRules: []model.Rule{},
				},
				Tags:   []string{"lalala", "covfefe", "meep"},
				Labels: nil,
			},
		}

		// Assert that converting v1 backend to v3 API returns an error.
		_, err := p.BackendV1ToAPIV3(v1KVP)
		Expect(err).NotTo(HaveOccurred())
	})
}
func TestNoLabelsOrTagsOnBackend(t *testing.T) {
	t.Run("Profile conversion should succeed when there are no tags or labels", func(t *testing.T) {
		RegisterTestingT(t)

		p := Profile{}

		v1KVP := &model.KVPair{
			Key: model.ProfileKey{
				Name: "makemake",
			},
			Value: &model.Profile{
				Rules: model.ProfileRules{
					InboundRules:  []model.Rule{V1ModelInRule1, V1ModelInRule2},
					OutboundRules: []model.Rule{},
				},
				Tags:   nil,
				Labels: nil,
			},
		}

		// Assert that converting v1 backend to v3 API returns an error.
		_, err := p.BackendV1ToAPIV3(v1KVP)
		Expect(err).NotTo(HaveOccurred())
	})
}
