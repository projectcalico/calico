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

package resources_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator/clients/v1/k8s/resources"
)

var _ = Describe("Node BGP conversion methods", func() {

	converter := resources.NodeBGPPeerConverter{}

	It("should convert an empty ListInterface", func() {
		node, name, err := converter.ListInterfaceToNodeAndName(
			model.NodeBGPPeerListOptions{},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal(""))
		Expect(name).To(Equal(""))
	})

	It("should convert a List interface with a Node name only", func() {
		node, name, err := converter.ListInterfaceToNodeAndName(
			model.NodeBGPPeerListOptions{
				Nodename: "node",
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal("node"))
		Expect(name).To(Equal(""))
	})

	It("should convert a List interface with a PeerIP only", func() {
		node, name, err := converter.ListInterfaceToNodeAndName(
			model.NodeBGPPeerListOptions{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal(""))
		Expect(name).To(Equal("1-2-3-4"))
	})

	It("should convert a List interface with node and PeerIP (IPv4)", func() {
		node, name, err := converter.ListInterfaceToNodeAndName(
			model.NodeBGPPeerListOptions{
				Nodename: "nodeX",
				PeerIP:   net.MustParseIP("1.2.3.40"),
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal("nodeX"))
		Expect(name).To(Equal("1-2-3-40"))
	})

	It("should convert a List interface with node and PeerIP (IPv6)", func() {
		node, name, err := converter.ListInterfaceToNodeAndName(
			model.NodeBGPPeerListOptions{
				Nodename: "nodeX",
				PeerIP:   net.MustParseIP("1::2:3:4"),
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal("nodeX"))
		Expect(name).To(Equal("0001-0000-0000-0000-0000-0002-0003-0004"))
	})

	It("should convert a Key with node and PeerIP (IPv4)", func() {
		node, name, err := converter.KeyToNodeAndName(
			model.NodeBGPPeerKey{
				Nodename: "nodeY",
				PeerIP:   net.MustParseIP("1.2.3.50"),
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal("nodeY"))
		Expect(name).To(Equal("1-2-3-50"))
	})

	It("should convert a Key with node and PeerIP (IPv6)", func() {
		node, name, err := converter.KeyToNodeAndName(
			model.NodeBGPPeerKey{
				Nodename: "nodeY",
				PeerIP:   net.MustParseIP("aa:ff::12"),
			},
		)
		Expect(err).To(BeNil())
		Expect(node).To(Equal("nodeY"))
		Expect(name).To(Equal("00aa-00ff-0000-0000-0000-0000-0000-0012"))
	})

	It("should convert a valid node name and resource name to a Key (IPv4)", func() {
		key, err := converter.NodeAndNameToKey("nodeA", "1-2-3-4")
		Expect(err).To(BeNil())
		Expect(key).To(Equal(model.NodeBGPPeerKey{
			Nodename: "nodeA",
			PeerIP:   net.MustParseIP("1.2.3.4"),
		}))
	})

	It("should convert a valid node name and resource name to a Key (IPv6)", func() {
		key, err := converter.NodeAndNameToKey("nodeB", "abcd-2000--30-40")
		Expect(err).To(BeNil())
		Expect(key).To(Equal(model.NodeBGPPeerKey{
			Nodename: "nodeB",
			PeerIP:   net.MustParseIP("abcd:2000::30:40"),
		}))
	})

	It("should fail to convert a valid node name and invalid resource name to a Key", func() {
		_, err := converter.NodeAndNameToKey("nodeB", "foobarbaz")
		Expect(err).ToNot(BeNil())
	})
})
