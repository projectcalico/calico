// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/net"
)

var _ = Describe("Test the BGPPeer update processor", func() {
	v3PeerKey1 := model.ResourceKey{
		Kind: apiv3.KindBGPPeer,
		Name: "name1",
	}
	v3PeerKey2 := model.ResourceKey{
		Kind: apiv3.KindBGPPeer,
		Name: "name2",
	}
	ip1str := "1.2.3.0"
	ip2str := "aa:bb:cc::"
	node1 := "node1"
	v1GlobalPeerKeyIP1 := model.GlobalBGPPeerKey{
		PeerIP: net.MustParseIP(ip1str),
	}
	v1GlobalPeerKeyIP2 := model.GlobalBGPPeerKey{
		PeerIP: net.MustParseIP(ip2str),
	}
	v1Node1PeerKeyIP2 := model.NodeBGPPeerKey{
		Nodename: node1,
		PeerIP:   net.MustParseIP(ip2str),
	}

	It("should handle conversion of valid BGPPeers", func() {
		up := updateprocessors.NewBGPPeerUpdateProcessor()

		By("converting a global BGPPeer with minimum configuration")
		res := apiv3.NewBGPPeer()
		res.Name = v3PeerKey1.Name
		res.Spec.PeerIP = ip1str
		res.Spec.ASNumber = 11111

		kvps, err := up.Process(&model.KVPair{
			Key:      v3PeerKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1GlobalPeerKeyIP1,
			Value: &model.BGPPeer{
				PeerIP: v1GlobalPeerKeyIP1.PeerIP,
				ASNum:  11111,
			},
			Revision: "abcde",
		}))

		By("adding/updating/deleting/adding another global BGPPeer with the same PeerIP (but higher alphanumeric name - no update expected")
		res = apiv3.NewBGPPeer()
		res.Name = v3PeerKey2.Name
		res.Spec.PeerIP = ip1str
		res.Spec.ASNumber = 1234
		kvps, err = up.Process(&model.KVPair{
			Key:      v3PeerKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(0))

		kvps, err = up.Process(&model.KVPair{
			Key:      v3PeerKey2,
			Value:    res,
			Revision: "1235",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(0))

		kvps, err = up.Process(&model.KVPair{
			Key:      v3PeerKey2,
			Revision: "1235",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(0))

		kvps, err = up.Process(&model.KVPair{
			Key:      v3PeerKey2,
			Value:    res,
			Revision: "1239",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(0))

		By("updating the first BGPPeer to be node specific and with a different IP - expect updates for both BGPPeers")
		res = apiv3.NewBGPPeer()
		res.Name = v3PeerKey1.Name
		res.Spec.PeerIP = ip2str
		res.Spec.ASNumber = 11111
		res.Spec.Node = node1
		kvps, err = up.Process(&model.KVPair{
			Key:      v3PeerKey1,
			Value:    res,
			Revision: "abcdef",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1GlobalPeerKeyIP1,
				Value: &model.BGPPeer{
					PeerIP: v1GlobalPeerKeyIP1.PeerIP,
					ASNum:  1234,
				},
				Revision: "1239",
			},
			{
				Key: v1Node1PeerKeyIP2,
				Value: &model.BGPPeer{
					PeerIP: v1GlobalPeerKeyIP2.PeerIP,
					ASNum:  11111,
				},
				Revision: "abcdef",
			},
		}))

		By("deleting the first BGPPeer")
		kvps, err = up.Process(&model.KVPair{
			Key: v3PeerKey1,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1Node1PeerKeyIP2,
			},
		}))

		By("deleting the second BGPPeer")
		kvps, err = up.Process(&model.KVPair{
			Key: v3PeerKey2,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1GlobalPeerKeyIP1,
			},
		}))

		By("checking global and node peers are treated separately even if they have the same IP")
		res = apiv3.NewBGPPeer()
		res.Name = v3PeerKey1.Name
		res.Spec.PeerIP = ip2str
		res.Spec.ASNumber = 11111
		kvps, err = up.Process(&model.KVPair{
			Key:      v3PeerKey1,
			Value:    res,
			Revision: "00000",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1GlobalPeerKeyIP2,
			Value: &model.BGPPeer{
				PeerIP: v1GlobalPeerKeyIP2.PeerIP,
				ASNum:  11111,
			},
			Revision: "00000",
		}))

		res = apiv3.NewBGPPeer()
		res.Name = v3PeerKey2.Name
		res.Spec.PeerIP = ip2str
		res.Spec.Node = node1
		res.Spec.ASNumber = 22222

		kvps, err = up.Process(&model.KVPair{
			Key:      v3PeerKey2,
			Value:    res,
			Revision: "00001",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1Node1PeerKeyIP2,
			Value: &model.BGPPeer{
				PeerIP: v1GlobalPeerKeyIP2.PeerIP,
				ASNum:  22222,
			},
			Revision: "00001",
		}))

		By("clearing the cache (by starting sync) and failing to delete the second BGPPeer")
		up.OnSyncerStarting()
		kvps, err = up.Process(&model.KVPair{
			Key: v3PeerKey2,
		})
		Expect(err).To(HaveOccurred())
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewBGPPeerUpdateProcessor()

		By("trying to convert with the wrong key type")
		_, err := up.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
			Value:    apiv3.NewIPPool(),
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		res := apiv3.NewBGPPeer()
		res.Name = "name1"
		res.Spec.PeerIP = "1.2.3.4"
		_, err = up.Process(&model.KVPair{
			Key:      model.IPPoolKey{CIDR: net.MustParseCIDR("1.2.3.0/24")},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert a peer with an invalid IP")
		res = apiv3.NewBGPPeer()
		res.Name = "name1"
		res.Spec.PeerIP = "1.2.3.x"
		_, err = up.Process(&model.KVPair{
			Key:      v3PeerKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})

	It("should handle failures to convert a BGPPeer", func() {
		up := updateprocessors.NewBGPPeerUpdateProcessor()

		By("converting a global BGPPeer with minimum configuration")
		res := apiv3.NewBGPPeer()
		res.Name = v3PeerKey1.Name
		res.Spec.PeerIP = ip1str
		res.Spec.ASNumber = 11111

		kvps, err := up.Process(&model.KVPair{
			Key:      v3PeerKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1GlobalPeerKeyIP1,
			Value: &model.BGPPeer{
				PeerIP: v1GlobalPeerKeyIP1.PeerIP,
				ASNum:  11111,
			},
			Revision: "abcde",
		}))

		By("setting an invalid PeerIP address and checking for error with delete")
		res = apiv3.NewBGPPeer()
		res.Name = v3PeerKey1.Name
		res.Spec.PeerIP = "not a valid IP"
		res.Spec.ASNumber = 11111

		kvps, err = up.Process(&model.KVPair{
			Key:      v3PeerKey1,
			Value:    res,
			Revision: "abcdeg",
		})
		Expect(err).To(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1GlobalPeerKeyIP1,
		}))

		By("setting another invalid PeerIP address and checking for error with no update")
		res = apiv3.NewBGPPeer()
		res.Name = v3PeerKey1.Name
		res.Spec.PeerIP = "not a valid IP 2"
		res.Spec.ASNumber = 11111

		kvps, err = up.Process(&model.KVPair{
			Key:      v3PeerKey1,
			Value:    res,
			Revision: "abcdef",
		})
		Expect(err).To(HaveOccurred())
		Expect(kvps).To(HaveLen(0))
	})
})
