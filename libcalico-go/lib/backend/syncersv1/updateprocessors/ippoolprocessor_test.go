// Copyright (c) 2019,2021 Tigera, Inc. All rights reserved.

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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the IPPool update processor", func() {
	v3PoolKey1 := model.ResourceKey{
		Kind: apiv3.KindIPPool,
		Name: "name1",
	}
	v3PoolKey2 := model.ResourceKey{
		Kind: apiv3.KindIPPool,
		Name: "name2",
	}
	cidr1str := "1.2.3.0/24"
	cidr2str := "aa:bb:cc::/120"
	v1PoolKeyCidr1 := model.IPPoolKey{
		CIDR: net.MustParseCIDR(cidr1str),
	}
	v1PoolKeyCidr2 := model.IPPoolKey{
		CIDR: net.MustParseCIDR(cidr2str),
	}

	It("should handle conversion of valid IPPools", func() {
		up := updateprocessors.NewIPPoolUpdateProcessor()

		By("converting an IP Pool with minimum configuration")
		res := apiv3.NewIPPool()
		res.Name = v3PoolKey1.Name
		res.Spec.CIDR = cidr1str

		kvps, err := up.Process(&model.KVPair{
			Key:      v3PoolKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1PoolKeyCidr1,
			Value: &model.IPPool{
				CIDR:             v1PoolKeyCidr1.CIDR,
				IPIPMode:         encap.Undefined,
				Masquerade:       false,
				IPAM:             true,
				Disabled:         false,
				DisableBGPExport: false,
			},
			Revision: "abcde",
		}))

		By("adding another IP IPPool with the same CIDR (but higher alphanumeric name - no update expected")
		res = apiv3.NewIPPool()
		res.Name = v3PoolKey2.Name
		res.Spec.CIDR = cidr1str
		res.Spec.IPIPMode = apiv3.IPIPModeAlways
		res.Spec.NATOutgoing = true
		res.Spec.Disabled = true
		kvps, err = up.Process(&model.KVPair{
			Key:      v3PoolKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(0))

		By("updating the first IPPool to have a different CIDR - expect updates for both pools")
		res = apiv3.NewIPPool()
		res.Name = v3PoolKey1.Name
		res.Spec.CIDR = cidr2str
		kvps, err = up.Process(&model.KVPair{
			Key:      v3PoolKey1,
			Value:    res,
			Revision: "abcdef",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1PoolKeyCidr1,
				Value: &model.IPPool{
					CIDR:             v1PoolKeyCidr1.CIDR,
					IPIPInterface:    "tunl0",
					IPIPMode:         encap.Always,
					Masquerade:       true,
					IPAM:             false,
					Disabled:         true,
					DisableBGPExport: false,
				},
				Revision: "1234",
			},
			{
				Key: v1PoolKeyCidr2,
				Value: &model.IPPool{
					CIDR:             v1PoolKeyCidr2.CIDR,
					IPIPInterface:    "",
					IPIPMode:         encap.Undefined,
					Masquerade:       false,
					IPAM:             true,
					Disabled:         false,
					DisableBGPExport: false,
				},
				Revision: "abcdef",
			},
		}))

		By("updating the first IPPool to have disableBGPExport = true - expect an update")
		res = apiv3.NewIPPool()
		res.Name = v3PoolKey1.Name
		res.Spec.CIDR = cidr2str
		res.Spec.DisableBGPExport = true
		kvps, err = up.Process(&model.KVPair{
			Key:      v3PoolKey1,
			Value:    res,
			Revision: "abcdefg",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1PoolKeyCidr2,
				Value: &model.IPPool{
					CIDR:             v1PoolKeyCidr2.CIDR,
					IPIPInterface:    "",
					IPIPMode:         encap.Undefined,
					Masquerade:       false,
					IPAM:             true,
					Disabled:         false,
					DisableBGPExport: true,
				},
				Revision: "abcdefg",
			},
		}))

		By("deleting the first pool")
		kvps, err = up.Process(&model.KVPair{
			Key: v3PoolKey1,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1PoolKeyCidr2,
			},
		}))

		By("clearing the cache (by starting sync) and failing to delete the second pool")
		up.OnSyncerStarting()
		kvps, err = up.Process(&model.KVPair{
			Key: v3PoolKey2,
		})
		Expect(err).To(HaveOccurred())
	})

	It("should accept VXLANMode CrossSubnet", func() {
		up := updateprocessors.NewIPPoolUpdateProcessor()

		By("converting an IP Pool with VXLANMode CrossSubnet")
		res := &apiv3.IPPool{
			TypeMeta: metav1.TypeMeta{
				Kind:       apiv3.KindIPPool,
				APIVersion: apiv3.GroupVersionCurrent,
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:      cidr1str,
				IPIPMode:  apiv3.IPIPModeNever,
				VXLANMode: apiv3.VXLANModeCrossSubnet,
			},
		}

		kvps, err := up.Process(&model.KVPair{
			Key:      v3PoolKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1PoolKeyCidr1,
			Value: &model.IPPool{
				CIDR:             v1PoolKeyCidr1.CIDR,
				IPIPMode:         encap.Undefined,
				Masquerade:       false,
				IPAM:             true,
				Disabled:         false,
				DisableBGPExport: false,
				VXLANMode:        encap.CrossSubnet,
			},
			Revision: "abcde",
		}))
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewIPPoolUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv3.NewIPPool()
		res.Spec.CIDR = cidr1str

		_, err := up.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		wres := apiv3.NewBGPPeer()

		_, err = up.Process(&model.KVPair{
			Key:      v3PoolKey1,
			Value:    wres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
