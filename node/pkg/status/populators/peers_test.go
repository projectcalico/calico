// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package populator

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("Test BIRD BGP peer Scanner", func() {

	It("should be able to scan a table with multiple valid and invalid lines", func() {

		table := `0001 BIRD 1.5.0 ready.
2002-name     proto    table    state  since       info
1002-kernel1  Kernel   master   up     2016-11-21
 device1  Device   master   up     2016-11-21
 direct1  Direct   master   up     2016-11-21
 Mesh_172_17_8_102 BGP      master   up     2016-11-21  Established
 Global_172_17_8_103 BGP      master   up     2016-11-21  Established
 Node_172_17_8_104 BGP      master   down     2016-11-21  Failed  Socket: error
0000
We never get here
`
		mesh_172_17_8_102 := `0001 BIRD 1.5.0 ready.
name     proto    table    state  since       info
mesh_172_17_8_102 BGP      master   up     2016-11-21    Established
Preference:     100
Input filter:   ACCEPT
Output filter:  packet_bgp
Routes:         0 imported, 1 exported, 0 preferred
Route change stats:     received   rejected   filtered    ignored   accepted
  Import updates:              0          0          0          0          0
  Import withdraws:            0          0        ---          0          0
  Export updates:              1          0          0        ---          1
  Export withdraws:            0        ---        ---        ---          0
BGP state:          Established
  Neighbor address: 172.17.8.102
  Neighbor AS:      65530
  Neighbor ID:      147.75.36.73
  Neighbor caps:    refresh restart-aware AS4
  Session:          external AS4
  Source address:   10.99.182.129
  Hold timer:       66/90
  Keepalive timer:  18/30
0000
`
		mesh_172_17_8_103 := `0001 BIRD 1.5.0 ready.
name     proto    table    state  since       info
mesh_172_17_8_103 BGP      master   up     2016-11-21    Established
Preference:     100
Input filter:   ACCEPT
Output filter:  packet_bgp
Routes:         0 imported, 1 exported, 0 preferred
Route change stats:     received   rejected   filtered    ignored   accepted
  Import updates:              0          0          0          0          0
  Import withdraws:            0          0        ---          0          0
  Export updates:              1          0          0        ---          1
  Export withdraws:            0        ---        ---        ---          0
BGP state:          Established
  Neighbor address: 172.17.8.103
  Neighbor AS:      65530
  Neighbor ID:      147.75.36.73
  Neighbor caps:    refresh restart-aware AS4
  Session:          external AS4
  Source address:   10.99.182.129
  Hold timer:       66/90
  Keepalive timer:  18/30
0000
`
		mesh_172_17_8_104 := `0001 BIRD 1.5.0 ready.
name     proto    table    state  since       info
mesh_172_17_8_104 BGP      master   up     2016-11-21    Established
Preference:     100
Input filter:   ACCEPT
Output filter:  packet_bgp
Routes:         0 imported, 1 exported, 0 preferred
Route change stats:     received   rejected   filtered    ignored   accepted
  Import updates:              0          0          0          0          0
  Import withdraws:            0          0        ---          0          0
  Export updates:              1          0          0        ---          1
  Export withdraws:            0        ---        ---        ---          0
BGP state:          OpenSent
  Neighbor address: 172.17.8.104
  Neighbor AS:      65530
  Neighbor ID:      147.75.36.73
  Neighbor caps:    refresh restart-aware AS4
  Session:          external AS4
  Source address:   10.99.182.129
  Hold timer:       66/90
  Keepalive timer:  18/30
0000
`
		expectedPeers := []*bgpPeer{
			{
				session:  "Mesh_172_17_8_102",
				peerIP:   "172.17.8.102",
				peerType: "Mesh",
				state:    "up",
				since:    "2016-11-21",
				bgpState: "Established",
				info:     "",
			},
			{
				session:  "Global_172_17_8_103",
				peerIP:   "172.17.8.103",
				peerType: "Global",
				state:    "up",
				since:    "2016-11-21",
				bgpState: "Established",
				info:     "",
			},
			{
				session:  "Node_172_17_8_104",
				peerIP:   "172.17.8.104",
				peerType: "Node",
				state:    "down",
				since:    "2016-11-21",
				bgpState: "OpenSent",
				info:     "Socket: error",
			},
		}
		bgpPeers, err := readBIRDPeers(getMockBirdConn(IPFamilyV4, table))
		Expect(bgpPeers).To(HaveLen(3))
		Expect(err).NotTo(HaveOccurred())

		err = bgpPeers[0].complete(getMockBirdConn(IPFamilyV4, mesh_172_17_8_102))
		Expect(err).NotTo(HaveOccurred())
		err = bgpPeers[1].complete(getMockBirdConn(IPFamilyV4, mesh_172_17_8_103))
		Expect(err).NotTo(HaveOccurred())
		err = bgpPeers[2].complete(getMockBirdConn(IPFamilyV4, mesh_172_17_8_104))
		Expect(err).NotTo(HaveOccurred())

		Expect(bgpPeers).To(Equal(expectedPeers))
		Expect(err).NotTo(HaveOccurred())

		// Check we can print peers.
		printPeers(bgpPeers, GinkgoWriter)
	})

	It("should not allow a table with invalid headings", func() {
		table := `0001 BIRD 1.5.0 ready.
2002-name     proto    table    state  foo       info
1002-kernel1  Kernel   master   up     2016-11-21
 device1  Device   master   up     2016-11-21
0000
`
		_, err := readBIRDPeers(getMockBirdConn(IPFamilyV4, table))
		Expect(err).To(HaveOccurred())
	})

	It("should not allow a table with a rogue entry", func() {
		table := `0001 BIRD 1.5.0 ready.
2002-name     proto    table    state  since       info
1002-kernel1  Kernel   master   up     2016-11-21
 device1  Device   master   up     2016-11-21
9000
`
		_, err := readBIRDPeers(getMockBirdConn(IPFamilyV4, table))
		Expect(err).To(HaveOccurred())
	})

	It("should be able to scan an ipv6 table", func() {

		table := `0001 BIRD 1.5.0 ready.
2002-name     proto    table    state  since       info
1002-kernel1  Kernel   master   up     2016-11-21
 device1  Device   master   up     2016-11-21
 direct1  Direct   master   up     2016-11-21
 Mesh_2001_20__8 BGP      master   up     2016-11-21  Established
0000
We never get here
`
		mesh_2001_20__8 := `0001 BIRD 1.5.0 ready.
name     proto    table    state  since       info
mesh_2001_20__8 BGP      master   up     2016-11-21    Established
Preference:     100
Input filter:   ACCEPT
Output filter:  packet_bgp
Routes:         0 imported, 1 exported, 0 preferred
Route change stats:     received   rejected   filtered    ignored   accepted
  Import updates:              0          0          0          0          0
  Import withdraws:            0          0        ---          0          0
  Export updates:              1          0          0        ---          1
  Export withdraws:            0        ---        ---        ---          0
BGP state:          Established
  Neighbor address: 2001:20::8
  Neighbor AS:      65530
  Neighbor ID:      147.75.36.73
  Neighbor caps:    refresh restart-aware AS4
  Session:          external AS4
  Source address:   2001:20::1
  Hold timer:       66/90
  Keepalive timer:  18/30
0000
`
		expectedPeers := []*bgpPeer{
			{
				session:  "Mesh_2001_20__8",
				peerIP:   "2001:20::8",
				peerType: "Mesh",
				state:    "up",
				since:    "2016-11-21",
				bgpState: "Established",
				info:     "",
			},
		}
		bgpPeers, err := readBIRDPeers(getMockBirdConn(IPFamilyV6, table))
		Expect(bgpPeers).To(HaveLen(1))
		Expect(err).NotTo(HaveOccurred())

		err = bgpPeers[0].complete(getMockBirdConn(IPFamilyV6, mesh_2001_20__8))
		Expect(err).NotTo(HaveOccurred())

		Expect(bgpPeers).To(Equal(expectedPeers))
		Expect(err).NotTo(HaveOccurred())

		// Check we can print peers.
		printPeers(bgpPeers, GinkgoWriter)
	})

	DescribeTable("Convert to v3 object",
		func(b *bgpPeer, v3Peer v3.CalicoNodePeer) {
			apiPeer := b.toNodeStatusAPI()
			Expect(apiPeer).To(Equal(v3Peer))
		},
		Entry(
			"status ready",
			&bgpPeer{

				session:  "Mesh_2001_20__8",
				peerIP:   "2001:20::8",
				peerType: "Mesh",
				state:    "up",
				since:    "2016-11-21",
				bgpState: "Established",
				info:     "",
			},
			v3.CalicoNodePeer{
				PeerIP: "2001:20::8",
				Type:   v3.RouteSourceTypeNodeMesh,
				State:  v3.BGPSessionStateEstablished,
				Since:  "2016-11-21",
			},
		),
	)
})
