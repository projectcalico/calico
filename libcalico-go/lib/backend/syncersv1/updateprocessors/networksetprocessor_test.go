// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the NetworkSet update processor", func() {
	ns1 := "namespace-1"
	name1 := "networkset-1"

	v3NetworkSetKey1 := model.ResourceKey{
		Kind:      apiv3.KindNetworkSet,
		Name:      name1,
		Namespace: ns1,
	}

	cidr1str := "1.2.3.0/24"
	_, cidr1IPNet, _ := net.ParseCIDROrIP(cidr1str)

	v1NetworkSetKey1 := model.NetworkSetKey{
		Name: ns1 + "/" + name1,
	}

	It("should handle conversion of valid NetworkSets", func() {
		up := updateprocessors.NewNetworkSetUpdateProcessor()

		By("converting a NetworkSet with minimum configuration")
		res := apiv3.NewNetworkSet()
		res.Name = v3NetworkSetKey1.Name
		res.Namespace = ns1
		res.Spec.Nets = []string{cidr1str}

		kvps, err := up.Process(&model.KVPair{
			Key:      v3NetworkSetKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1NetworkSetKey1,
			Value: &model.NetworkSet{
				Nets: []net.IPNet{*cidr1IPNet},
				Labels: map[string]string{
					apiv3.LabelNamespace: ns1,
				},
				ProfileIDs: []string{
					"kns." + ns1,
				},
			},
			Revision: "abcde",
		}))

		By("adding another CIDR to the existing NetworkSet")
		cidr2str := "1.2.3.123/32"
		_, cidr2IPNet, _ := net.ParseCIDROrIP(cidr2str)
		res.Spec.Nets = []string{cidr1str, cidr2str}

		kvps, err = up.Process(&model.KVPair{
			Key:      v3NetworkSetKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1NetworkSetKey1,
			Value: &model.NetworkSet{
				Nets: []net.IPNet{*cidr1IPNet, *cidr2IPNet},
				Labels: map[string]string{
					apiv3.LabelNamespace: ns1,
				},
				ProfileIDs: []string{
					"kns." + ns1,
				},
			},
			Revision: "abcde",
		}))

		By("deleting the NetworkSet")
		kvps, err = up.Process(&model.KVPair{
			Key: v3NetworkSetKey1,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1NetworkSetKey1,
			},
		}))
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewNetworkSetUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv3.NewNetworkSet()
		res.Name = v3NetworkSetKey1.Name
		res.Namespace = ns1
		res.Spec.Nets = []string{cidr1str}

		kvps, err := up.Process(&model.KVPair{
			Key:      v3NetworkSetKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1NetworkSetKey1,
			Value: &model.NetworkSet{
				Nets: []net.IPNet{*cidr1IPNet},
				Labels: map[string]string{
					apiv3.LabelNamespace: ns1,
				},
				ProfileIDs: []string{
					"kns." + ns1,
				},
			},
			Revision: "abcde",
		}))
		_, err = up.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		_, err = up.Process(&model.KVPair{
			Key:      v3NetworkSetKey1,
			Value:    apiv3.NewBGPPeer,
			Revision: "abcde",
		})
		// simpleUpdateProcessor returns a nil error if invalid value
		Expect(err).NotTo(HaveOccurred())
	})
})
