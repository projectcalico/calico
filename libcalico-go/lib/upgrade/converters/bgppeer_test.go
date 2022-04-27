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

package converters

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"


	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/scope"
)

var _ = DescribeTable("v1->v3 bgp peer conversion tests table (success)",
	func(v1API *apiv1.BGPPeer, v1KVP *model.KVPair, v3API apiv3.BGPPeer) {
		p := BGPPeer{}

		// Test and assert v1 API to v1 backend logic.
		v1KVPResult, err := p.APIV1ToBackendV1(v1API)
		Expect(err).NotTo(HaveOccurred())
		md := v1API.Metadata
		if md.Scope == "global" {
			Expect(v1KVPResult.Key.(model.GlobalBGPPeerKey).PeerIP).To(Equal(v1KVP.Key.(model.GlobalBGPPeerKey).PeerIP))
		} else {
			Expect(v1KVPResult.Key.(model.NodeBGPPeerKey).PeerIP).To(Equal(v1KVP.Key.(model.NodeBGPPeerKey).PeerIP))
		}
		Expect(v1KVPResult.Value.(*model.BGPPeer)).To(Equal(v1KVP.Value))

		// Test and assert v1 backend to v3 API logic.
		v3APIResult, err := p.BackendV1ToAPIV3(v1KVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(v3APIResult.(*apiv3.BGPPeer).Name).To(Equal(v3API.Name))
		Expect(v3APIResult.(*apiv3.BGPPeer).Spec).To(Equal(v3API.Spec))
	},

	Entry("global scoped BGPPeer",
		&apiv1.BGPPeer{
			Metadata: apiv1.BGPPeerMetadata{
				Scope:  scope.Global,
				PeerIP: *net.ParseIP("10.0.0.1"),
			},
			Spec: apiv1.BGPPeerSpec{
				ASNumber: 255,
			},
		},
		&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: *net.ParseIP("10.0.0.1"),
			},
			Value: &model.BGPPeer{
				PeerIP: *net.ParseIP("10.0.0.1"),
				ASNum:  255,
			},
		},
		apiv3.BGPPeer{
			ObjectMeta: v1.ObjectMeta{
				Name: "10-0-0-1",
			},
			Spec: apiv3.BGPPeerSpec{
				PeerIP:   "10.0.0.1",
				ASNumber: 255,
			},
		},
	),
	Entry("global scoped ipv6 BGPPeer",
		&apiv1.BGPPeer{
			Metadata: apiv1.BGPPeerMetadata{
				Scope:  scope.Global,
				PeerIP: *net.ParseIP("Aa:bb::"),
			},
			Spec: apiv1.BGPPeerSpec{
				ASNumber: 255,
			},
		},
		&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: *net.ParseIP("Aa:bb::"),
			},
			Value: &model.BGPPeer{
				PeerIP: *net.ParseIP("Aa:bb::"),
				ASNum:  255,
			},
		},
		apiv3.BGPPeer{
			ObjectMeta: v1.ObjectMeta{
				Name: "00aa-00bb-0000-0000-0000-0000-0000-0000",
			},
			Spec: apiv3.BGPPeerSpec{
				PeerIP:   "aa:bb::",
				ASNumber: 255,
			},
		},
	),
	Entry("node scoped BGPPeer",
		&apiv1.BGPPeer{
			Metadata: apiv1.BGPPeerMetadata{
				Scope:  scope.Node,
				Node:   "namedNode",
				PeerIP: *net.ParseIP("10.0.0.1"),
			},
			Spec: apiv1.BGPPeerSpec{
				ASNumber: 255,
			},
		},
		&model.KVPair{
			Key: model.NodeBGPPeerKey{
				Nodename: "namedNode",
				PeerIP:   *net.ParseIP("10.0.0.1"),
			},
			Value: &model.BGPPeer{
				PeerIP: *net.ParseIP("10.0.0.1"),
				ASNum:  255,
			},
		},
		apiv3.BGPPeer{
			ObjectMeta: v1.ObjectMeta{
				Name: "namednode.10-0-0-1",
			},
			Spec: apiv3.BGPPeerSpec{
				PeerIP:   "10.0.0.1",
				Node:     "namednode",
				ASNumber: 255,
			},
		},
	),
	Entry("node scoped BGPPeer with ipv6",
		&apiv1.BGPPeer{
			Metadata: apiv1.BGPPeerMetadata{
				Scope:  scope.Node,
				Node:   "namedNode",
				PeerIP: *net.ParseIP("Aa:bb::"),
			},
			Spec: apiv1.BGPPeerSpec{
				ASNumber: 255,
			},
		},
		&model.KVPair{
			Key: model.NodeBGPPeerKey{
				Nodename: "namedNode",
				PeerIP:   *net.ParseIP("Aa:bb::"),
			},
			Value: &model.BGPPeer{
				PeerIP: *net.ParseIP("Aa:bb::"),
				ASNum:  255,
			},
		},
		apiv3.BGPPeer{
			ObjectMeta: v1.ObjectMeta{
				Name: "namednode.00aa-00bb-0000-0000-0000-0000-0000-0000",
			},
			Spec: apiv3.BGPPeerSpec{
				PeerIP:   "aa:bb::",
				Node:     "namednode",
				ASNumber: 255,
			},
		},
	),
)

var _ = DescribeTable("v1->v3 bgp peer conversion tests table (fail)",
	func(v1API *apiv1.BGPPeer) {
		// Failure cases.
		p := BGPPeer{}

		// Test and assert v1 API to v1 backend logic.
		_, err := p.APIV1ToBackendV1(v1API)
		Expect(err).To(HaveOccurred())
	},

	Entry("missing PeerIP",
		&apiv1.BGPPeer{
			Metadata: apiv1.BGPPeerMetadata{
				Scope: scope.Global,
			},
			Spec: apiv1.BGPPeerSpec{
				ASNumber: 255,
			},
		},
	),
	Entry("scope set global with node specified",
		&apiv1.BGPPeer{
			Metadata: apiv1.BGPPeerMetadata{
				Scope:  scope.Global,
				Node:   "namedNode",
				PeerIP: *net.ParseIP("10.0.0.1"),
			},
			Spec: apiv1.BGPPeerSpec{
				ASNumber: 255,
			},
		},
	),
	Entry("scope set node with NO node specified",
		&apiv1.BGPPeer{
			Metadata: apiv1.BGPPeerMetadata{
				Scope:  scope.Node,
				PeerIP: *net.ParseIP("10.0.0.1"),
			},
			Spec: apiv1.BGPPeerSpec{
				ASNumber: 255,
			},
		},
	),
)

var _ = Describe("v1->v3 BGP Peer conversion tests", func() {
	It("APIV1ToBackendV1 with the wrong resource produces an error", func() {
		resource := &apiv1.IPPool{
			Metadata: apiv1.IPPoolMetadata{},
			Spec:     apiv1.IPPoolSpec{},
		}

		p := BGPPeer{}
		_, err := p.APIV1ToBackendV1(resource)

		Expect(err).To(HaveOccurred())
	})

	It("BackendV1ToAPIV3 with wrong resource produces an error", func() {
		resource := &model.KVPair{
			Key:   model.IPPoolKey{},
			Value: &model.IPPool{},
		}

		p := BGPPeer{}
		_, err := p.BackendV1ToAPIV3(resource)

		Expect(err).To(HaveOccurred())
	})
})
