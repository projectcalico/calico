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

package updateprocessors_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the Tier update processor", func() {
	name1 := "tier1"
	name2 := "tier2"

	v3TierKey1 := model.ResourceKey{
		Kind: apiv3.KindTier,
		Name: name1,
	}
	v3TierKey2 := model.ResourceKey{
		Kind: apiv3.KindTier,
		Name: name2,
	}
	v1TierKey1 := model.TierKey{
		Name: name1,
	}
	v1TierKey2 := model.TierKey{
		Name: name2,
	}

	It("should handle conversion of valid Tiers", func() {
		up := updateprocessors.NewTierUpdateProcessor()

		By("converting a Tier with minimum configuration")
		res := apiv3.NewTier()

		kvps, err := up.Process(&model.KVPair{
			Key:      v3TierKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key:      v1TierKey1,
			Value:    &model.Tier{DefaultAction: apiv3.Deny},
			Revision: "abcde",
		}))

		By("adding another Tier with a full configuration")
		res = apiv3.NewTier()

		order := float64(101)
		aciontPass := apiv3.Pass

		res.Spec.Order = &order
		res.Spec.DefaultAction = &aciontPass
		kvps, err = up.Process(&model.KVPair{
			Key:      v3TierKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1TierKey2,
				Value: &model.Tier{
					Order:         &order,
					DefaultAction: apiv3.Pass,
				},
				Revision: "1234",
			},
		}))

		By("deleting the first tier")
		kvps, err = up.Process(&model.KVPair{
			Key:   v3TierKey1,
			Value: nil,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1TierKey1,
				Value: nil,
			},
		}))
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewTierUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv3.NewTier()

		_, err := up.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: cnet.MustParseIP("1.2.3.4"),
			},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		wres := apiv3.NewHostEndpoint()

		kvps, err := up.Process(&model.KVPair{
			Key:      v3TierKey1,
			Value:    wres,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1TierKey1,
				Value: nil,
			},
		}))

		By("trying to convert without enough information to create a v1 key")
		eres := apiv3.NewTier()
		v3TierKeyEmpty := model.ResourceKey{
			Kind: apiv3.KindTier,
		}

		_, err = up.Process(&model.KVPair{
			Key:      v3TierKeyEmpty,
			Value:    eres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
