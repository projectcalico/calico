// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package model_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = DescribeTable(
	"BGP Peer key parsing",
	func(strKey string, expected Key, isGlobalPeer bool) {
		var key Key
		if isGlobalPeer {
			key = (GlobalBGPPeerListOptions{}).KeyFromDefaultPath(strKey)
		} else {
			key = (NodeBGPPeerListOptions{}).KeyFromDefaultPath(strKey)
		}

		Expect(key).To(Equal(expected))
		serialized, err := KeyToDefaultPath(expected)
		Expect(err).ToNot(HaveOccurred())
		Expect(serialized).To(Equal(strKey))
	},
	Entry(
		"global BGP peer without port",
		"/calico/bgp/v1/global/peer_v4/10.0.0.5",
		GlobalBGPPeerKey{PeerIP: cnet.IP{IP: net.ParseIP("10.0.0.5")}, Port: 179},
		true,
	),
	Entry(
		"global BGP peer with port",
		"/calico/bgp/v1/global/peer_v4/10.0.0.5-500",
		GlobalBGPPeerKey{PeerIP: cnet.IP{IP: net.ParseIP("10.0.0.5")}, Port: 500},
		true,
	),
	Entry(
		"node BGP peer without port",
		"/calico/bgp/v1/host/random-node-1/peer_v4/10.0.0.5",
		NodeBGPPeerKey{Nodename: "random-node-1", PeerIP: cnet.IP{IP: net.ParseIP("10.0.0.5")}, Port: 179},
		false,
	),
	Entry(
		"node BGP peer with port",
		"/calico/bgp/v1/host/random-node-2/peer_v4/10.0.0.5-500",
		NodeBGPPeerKey{Nodename: "random-node-2", PeerIP: cnet.IP{IP: net.ParseIP("10.0.0.5")}, Port: 500},
		false,
	),
	Entry(
		"node BGP IPv6 peer with port",
		"/calico/bgp/v1/host/random-node-2/peer_v6/aabb:aabb::ffff-123",
		NodeBGPPeerKey{Nodename: "random-node-2", PeerIP: cnet.IP{IP: net.ParseIP("aabb:aabb::ffff")}, Port: 123},
		false,
	),
)
