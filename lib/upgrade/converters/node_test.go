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
	"testing"

	. "github.com/onsi/gomega"

	apiv1 "github.com/projectcalico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/libcalico-go/lib/apis/v1/unversioned"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
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

var nodeTable = []struct {
	description string
	v1API       unversioned.Resource
	v1KVP       *model.KVPair
	v3API       apiv3.Node
}{
	{
		description: "Valid basic v1 node has data moved to right place",
		v1API: &apiv1.Node{
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
		v1KVP: &model.KVPair{
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
		v3API: apiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: apiv3.NodeSpec{
				BGP: &apiv3.NodeBGPSpec{
					ASNumber:    &asn,
					IPv4Address: ipv4String,
					IPv6Address: ipv6String,
				},
			},
		},
	},
	{
		description: "Check name conversion",
		v1API: &apiv1.Node{
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
		v1KVP: &model.KVPair{
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
		v3API: apiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "mynode.here",
			},
			Spec: apiv3.NodeSpec{
				BGP: &apiv3.NodeBGPSpec{
					ASNumber:    &asn,
					IPv4Address: ipv4String,
					IPv6Address: ipv6String,
				},
			},
		},
	},
	{
		description: "Conversion with only IPv6",
		v1API: &apiv1.Node{
			Metadata: apiv1.NodeMetadata{
				Name: "my-node",
			},
			Spec: apiv1.NodeSpec{
				BGP: &apiv1.NodeBGPSpec{
					IPv6Address: &ipv6IPNet,
				},
			},
		},
		v1KVP: &model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPIPv6Addr: &ipv6IP,
				BGPIPv6Net:  ipv6IPNetMask,
			},
		},
		v3API: apiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: apiv3.NodeSpec{
				BGP: &apiv3.NodeBGPSpec{
					IPv6Address: ipv6String,
				},
			},
		},
	},
	{
		description: "Conversion with only IPv4",
		v1API: &apiv1.Node{
			Metadata: apiv1.NodeMetadata{
				Name: "my-node",
			},
			Spec: apiv1.NodeSpec{
				BGP: &apiv1.NodeBGPSpec{
					IPv4Address: &ipv4IPNet,
				},
			},
		},
		v1KVP: &model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPIPv4Addr: &ipv4IP,
				BGPIPv4Net:  ipv4IPNetMask,
			},
		},
		v3API: apiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: apiv3.NodeSpec{
				BGP: &apiv3.NodeBGPSpec{
					IPv4Address: ipv4String,
				},
			},
		},
	},
	{
		description: "Conversion with OrchRefs",
		v1API: &apiv1.Node{
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
		v1KVP: &model.KVPair{
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
		v3API: apiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: apiv3.NodeSpec{
				BGP: &apiv3.NodeBGPSpec{
					IPv4Address: ipv4String,
				},
				OrchRefs: []apiv3.OrchRef{
					{Orchestrator: "orch1"},
					{Orchestrator: "orch2", NodeName: "orch2NodeName"},
				},
			},
		},
	},
}

func TestCanConvertV1ToV3Node(t *testing.T) {
	for _, tdata := range nodeTable {
		t.Run(tdata.description, func(t *testing.T) {
			RegisterTestingT(t)

			p := Node{}
			// Check v1API->v1KVP.
			convertedKvp, err := p.APIV1ToBackendV1(tdata.v1API)
			Expect(err).NotTo(HaveOccurred(), tdata.description)

			Expect(convertedKvp.Key.(model.NodeKey)).To(Equal(tdata.v1KVP.Key.(model.NodeKey)))
			Expect(convertedKvp.Value.(*model.Node)).To(Equal(tdata.v1KVP.Value))

			// Check v1KVP->v3API.
			convertedv3, err := p.BackendV1ToAPIV3(tdata.v1KVP)
			Expect(err).NotTo(HaveOccurred(), tdata.description)
			Expect(convertedv3.(*apiv3.Node).ObjectMeta).To(Equal(tdata.v3API.ObjectMeta), tdata.description)
			Expect(convertedv3.(*apiv3.Node).Spec).To(Equal(tdata.v3API.Spec), tdata.description)
		})
	}
}

var nodeV1FailTable = []struct {
	description string
	v1API       unversioned.Resource
}{
	{
		description: "No IPv4 or IPv6 Address",
		v1API: &apiv1.Node{
			Metadata: apiv1.NodeMetadata{
				Name: "my-node",
			},
			Spec: apiv1.NodeSpec{
				BGP: &apiv1.NodeBGPSpec{
					ASNumber: &asn,
				},
			},
		},
	},
	{
		description: "Incorrect Resource",
		v1API: apiv1.IPPool{
			Metadata: apiv1.IPPoolMetadata{},
			Spec:     apiv1.IPPoolSpec{},
		},
	},
}

func TestFailToConvertV1ToKVNode(t *testing.T) {
	for _, tdata := range nodeV1FailTable {
		t.Run(tdata.description, func(t *testing.T) {
			RegisterTestingT(t)

			p := Node{}
			// Check v1API->v1KVP.
			_, err := p.APIV1ToBackendV1(tdata.v1API)
			Expect(err).To(HaveOccurred(), tdata.description)
		})
	}
}

func TestFailToConvertInvalidKVToAPIV3Node(t *testing.T) {
	t.Run("BackendV1ToAPIV3 with wrong Key produces an error", func(t *testing.T) {
		RegisterTestingT(t)

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
	t.Run("BackendV1ToAPIV3 with wrong Value produces an error", func(t *testing.T) {
		RegisterTestingT(t)

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
}

var nodeKVtoV3Table = []struct {
	description string
	v1KVP       *model.KVPair
	v3API       apiv3.Node
}{
	{
		description: "Conversion without the Net fields",
		v1KVP: &model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPASNumber: &asn,
				BGPIPv4Addr: &ipv4IP,
				BGPIPv6Addr: &ipv6IP,
			},
		},
		v3API: apiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: apiv3.NodeSpec{
				BGP: &apiv3.NodeBGPSpec{
					ASNumber:    &asn,
					IPv4Address: "192.168.1.1/32",
					// Note this is /128 instead of /64
					IPv6Address: "fed::5/128",
				},
			},
		},
	},
	{
		description: "Conversion without any Address fields",
		v1KVP: &model.KVPair{
			Key: model.NodeKey{
				Hostname: "my-node",
			},
			Value: &model.Node{
				BGPASNumber: &asn,
			},
		},
		v3API: apiv3.Node{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node",
			},
			Spec: apiv3.NodeSpec{},
		},
	},
}

func TestCanConvertKVToV3Node(t *testing.T) {
	for _, tdata := range nodeKVtoV3Table {
		t.Run(tdata.description, func(t *testing.T) {
			RegisterTestingT(t)

			p := Node{}
			// Check v1KVP->v3API.
			convertedv3, err := p.BackendV1ToAPIV3(tdata.v1KVP)
			Expect(err).NotTo(HaveOccurred(), tdata.description)
			Expect(convertedv3.(*apiv3.Node).ObjectMeta).To(Equal(tdata.v3API.ObjectMeta), tdata.description)
			Expect(convertedv3.(*apiv3.Node).Spec).To(Equal(tdata.v3API.Spec), tdata.description)
		})
	}
}
