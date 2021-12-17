// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var asn, _ = numorstring.ASNumberFromString("1")
var ipv4String = "192.168.1.1/24"
var ipv4IPNet = cnet.MustParseCIDR(ipv4String)
var ipv4IPNetMask = ipv4IPNet.Network()
var ipv4IP = cnet.MustParseIP("192.168.1.1")
var ipv6String = "fed::5/64"
var ipv6IPNet = cnet.MustParseCIDR(ipv6String)
var ipv6IPNetMask = ipv6IPNet.Network()
var ipv6IP = cnet.MustParseIP("fed::5")

var nodeTable = []TableEntry{
	Entry("Valid basic v1 node has data moved to right place",
		&apiv1.Node{
			Metadata: apiv1.NodeMetadata{
				Name: "my-node",
			},
			Spec: apiv1.NodeSpec{
				BGP: &apiv1.NodeBGPSpec{
					ASNumber:    &asn,
					IPv4Address: &ipv4IPNet,
					IPv6Address: &ipv6IPNet,
				},
			},
		},
		&model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPASNumber: &asn,
				BGPIPv4Addr: &ipv4IP,
				BGPIPv4Net:  ipv4IPNetMask,
				BGPIPv6Addr: &ipv6IP,
				BGPIPv6Net:  ipv6IPNetMask,
			},
		},
		libapiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: libapiv3.NodeSpec{
				BGP: &libapiv3.NodeBGPSpec{
					ASNumber:    &asn,
					IPv4Address: ipv4String,
					IPv6Address: ipv6String,
				},
			},
		},
	),
	Entry("Check name conversion",
		&apiv1.Node{
			Metadata: apiv1.NodeMetadata{
				Name: "myNode.here",
			},
			Spec: apiv1.NodeSpec{
				BGP: &apiv1.NodeBGPSpec{
					ASNumber:    &asn,
					IPv4Address: &ipv4IPNet,
					IPv6Address: &ipv6IPNet,
				},
			},
		},
		&model.KVPair{
			Key: model.NodeKey{
				Hostname: "myNode.here",
			},
			Value: &model.Node{
				BGPASNumber: &asn,
				BGPIPv4Addr: &ipv4IP,
				BGPIPv4Net:  ipv4IPNetMask,
				BGPIPv6Addr: &ipv6IP,
				BGPIPv6Net:  ipv6IPNetMask,
			},
		},
		libapiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "mynode.here",
			},
			Spec: libapiv3.NodeSpec{
				BGP: &libapiv3.NodeBGPSpec{
					ASNumber:    &asn,
					IPv4Address: ipv4String,
					IPv6Address: ipv6String,
				},
			},
		},
	),
	Entry("Conversion with only IPv6",
		&apiv1.Node{
			Metadata: apiv1.NodeMetadata{
				Name: "my-node",
			},
			Spec: apiv1.NodeSpec{
				BGP: &apiv1.NodeBGPSpec{
					IPv6Address: &ipv6IPNet,
				},
			},
		},
		&model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPIPv6Addr: &ipv6IP,
				BGPIPv6Net:  ipv6IPNetMask,
			},
		},
		libapiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: libapiv3.NodeSpec{
				BGP: &libapiv3.NodeBGPSpec{
					IPv6Address: ipv6String,
				},
			},
		},
	),
	Entry("Conversion with only IPv4",
		&apiv1.Node{
			Metadata: apiv1.NodeMetadata{
				Name: "my-node",
			},
			Spec: apiv1.NodeSpec{
				BGP: &apiv1.NodeBGPSpec{
					IPv4Address: &ipv4IPNet,
				},
			},
		},
		&model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPIPv4Addr: &ipv4IP,
				BGPIPv4Net:  ipv4IPNetMask,
			},
		},
		libapiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: libapiv3.NodeSpec{
				BGP: &libapiv3.NodeBGPSpec{
					IPv4Address: ipv4String,
				},
			},
		},
	),
	Entry("Conversion with OrchRefs",
		&apiv1.Node{
			Metadata: apiv1.NodeMetadata{
				Name: "my-node",
			},
			Spec: apiv1.NodeSpec{
				BGP: &apiv1.NodeBGPSpec{
					IPv4Address: &ipv4IPNet,
				},
				OrchRefs: []apiv1.OrchRef{
					{Orchestrator: "orch1"},
					{Orchestrator: "orch2", NodeName: "orch2NodeName"},
				},
			},
		},
		&model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPIPv4Addr: &ipv4IP,
				BGPIPv4Net:  ipv4IPNetMask,
				OrchRefs: []model.OrchRef{
					{Orchestrator: "orch1"},
					{Orchestrator: "orch2", NodeName: "orch2NodeName"},
				},
			},
		},
		libapiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: libapiv3.NodeSpec{
				BGP: &libapiv3.NodeBGPSpec{
					IPv4Address: ipv4String,
				},
				OrchRefs: []libapiv3.OrchRef{
					{Orchestrator: "orch1"},
					{Orchestrator: "orch2", NodeName: "orch2NodeName"},
				},
			},
		},
	),
}

var _ = DescribeTable("v1->v3 Node conversion tests",
	func(v1API *apiv1.Node, v1KVP *model.KVPair, v3API libapiv3.Node) {
		p := Node{}
		// Check v1API->v1KVP.
		convertedKvp, err := p.APIV1ToBackendV1(v1API)
		Expect(err).NotTo(HaveOccurred())

		Expect(convertedKvp.Key.(model.NodeKey)).To(Equal(v1KVP.Key.(model.NodeKey)))
		Expect(convertedKvp.Value.(*model.Node)).To(Equal(v1KVP.Value))

		// Check v1KVP->v3API.
		convertedv3, err := p.BackendV1ToAPIV3(v1KVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(convertedv3.(*libapiv3.Node).ObjectMeta).To(Equal(v3API.ObjectMeta))
		Expect(convertedv3.(*libapiv3.Node).Spec).To(Equal(v3API.Spec))
	},

	nodeTable...,
)

var nodeV1FailTable = []TableEntry{
	Entry("No IPv4 or IPv6 Address",
		&apiv1.Node{
			Metadata: apiv1.NodeMetadata{
				Name: "my-node",
			},
			Spec: apiv1.NodeSpec{
				BGP: &apiv1.NodeBGPSpec{
					ASNumber: &asn,
				},
			},
		},
	),
	Entry("Incorrect Resource",
		apiv1.IPPool{
			Metadata: apiv1.IPPoolMetadata{},
			Spec:     apiv1.IPPoolSpec{},
		},
	),
}

var _ = DescribeTable("v1->v3 Node conversion tests (failure)",
	func(v1API unversioned.Resource) {
		p := Node{}
		// Check v1API->v1KVP.
		_, err := p.APIV1ToBackendV1(v1API)
		Expect(err).To(HaveOccurred())
	},

	nodeV1FailTable...,
)

var _ = Describe("v1->v3 Node conversion tests (failure)", func() {
	It("BackendV1ToAPIV3 with wrong Key produces an error", func() {
		resource := &model.KVPair{
			Key: model.IPPoolKey{},
			Value: &model.Node{
				BGPIPv4Addr: &ipv4IP,
				BGPIPv4Net:  ipv4IPNetMask,
			},
		}
		p := Node{}
		_, err := p.BackendV1ToAPIV3(resource)
		Expect(err).To(HaveOccurred())
	})

	It("BackendV1ToAPIV3 with wrong Value produces an error", func() {
		resource := &model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.IPPool{},
		}
		p := Node{}
		_, err := p.BackendV1ToAPIV3(resource)
		Expect(err).To(HaveOccurred())
	})
})

var nodeKVtoV3Table = []TableEntry{
	Entry("Conversion without the Net fields",
		&model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPASNumber: &asn,
				BGPIPv4Addr: &ipv4IP,
				BGPIPv6Addr: &ipv6IP,
			},
		},
		libapiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: libapiv3.NodeSpec{
				BGP: &libapiv3.NodeBGPSpec{
					ASNumber:    &asn,
					IPv4Address: "192.168.1.1/32",
					// Note this is /128 instead of /64
					IPv6Address: "fed::5/128",
				},
			},
		},
	),
	Entry("Conversion without any Address fields",
		&model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPASNumber: &asn,
			},
		},
		libapiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: libapiv3.NodeSpec{},
		},
	),
}

var _ = DescribeTable("KVP v1->v3 Node conversion tests",
	func(v1KVP *model.KVPair, v3API libapiv3.Node) {
		p := Node{}
		// Check v1KVP->v3API.
		convertedv3, err := p.BackendV1ToAPIV3(v1KVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(convertedv3.(*libapiv3.Node).ObjectMeta).To(Equal(v3API.ObjectMeta))
		Expect(convertedv3.(*libapiv3.Node).Spec).To(Equal(v3API.Spec))
	},

	nodeKVtoV3Table...,
)
