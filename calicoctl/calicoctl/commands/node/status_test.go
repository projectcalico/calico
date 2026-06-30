// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package node

import (
	"bytes"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {

	// Check parsing of BIRD peer lines
	DescribeTable("Parse BIRD peer lines",
		func(line string, parsed bool, peer bgpPeer) {

			outPeer := bgpPeer{}
			outParsed := outPeer.unmarshalBIRD(line, ".")
			Expect(outParsed).To(Equal(parsed))
			Expect(outPeer).To(Equal(peer))
		},
		Entry("reject kernel", "kernel1  Kernel   master   up     2016-11-21", false, bgpPeer{}),
		Entry("reject device", "device1  Device   master   up     2016-11-21", false, bgpPeer{}),
		Entry("reject Meshd", "Meshd_172_17_8_102 BGP      master   up     2016-11-21  Established", false, bgpPeer{}),
		Entry("accept Mesh", "Mesh_172_17_8_102 BGP      master   up     2016-11-21  Established",
			true,
			bgpPeer{
				PeerIP:   "172.17.8.102",
				PeerType: "node-to-node mesh",
				State:    "up",
				Since:    "2016-11-21",
				BGPState: "Established",
				Info:     "",
			}),
		Entry("accept Node", "Node_172_17_80_102 BGP      master   up     2016-11-21  Active    Socket: error",
			true,
			bgpPeer{
				PeerIP:   "172.17.80.102",
				PeerType: "node specific",
				State:    "up",
				Since:    "2016-11-21",
				BGPState: "Active",
				Info:     "Socket: error",
			}),
		Entry("accept Global", "Global_172_17_8_133 BGP master down 2016-11-2 Failed",
			true,
			bgpPeer{
				PeerIP:   "172.17.8.133",
				PeerType: "global",
				State:    "down",
				Since:    "2016-11-2",
				BGPState: "Failed",
				Info:     "",
			}),
	)

	Describe("Test BIRD Scanner", func() {

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
			expectedPeers := []bgpPeer{{
				PeerIP:   "172.17.8.102",
				PeerType: "node-to-node mesh",
				State:    "up",
				Since:    "2016-11-21",
				BGPState: "Established",
				Info:     "",
			}, {
				PeerIP:   "172.17.8.103",
				PeerType: "global",
				State:    "up",
				Since:    "2016-11-21",
				BGPState: "Established",
				Info:     "",
			}, {
				PeerIP:   "172.17.8.104",
				PeerType: "node specific",
				State:    "down",
				Since:    "2016-11-21",
				BGPState: "Failed",
				Info:     "Socket: error",
			}}
			bgpPeers, err := scanBIRDPeers(table, conn{bytes.NewBufferString(table)})

			Expect(bgpPeers).To(Equal(expectedPeers))
			Expect(err).NotTo(HaveOccurred())

			// Check we can print peers.
			printPeers(bgpPeers)
		})

		It("should not allow a table with invalid headings", func() {
			table := `0001 BIRD 1.5.0 ready.
2002-name     proto    table    state  foo       info
1002-kernel1  Kernel   master   up     2016-11-21
 device1  Device   master   up     2016-11-21
0000
`
			_, err := scanBIRDPeers(table, conn{bytes.NewBufferString(table)})
			Expect(err).To(HaveOccurred())
		})

		It("should not allow a table with a rogue entry", func() {
			table := `0001 BIRD 1.5.0 ready.
2002-name     proto    table    state  since       info
1002-kernel1  Kernel   master   up     2016-11-21
 device1  Device   master   up     2016-11-21
9000
`
			_, err := scanBIRDPeers(table, conn{bytes.NewBufferString(table)})
			Expect(err).To(HaveOccurred())
		})

		It("should filter a single BIRD3 socket's mixed-family peers per requested family", func() {
			// BIRD3 is a single daemon: one "show protocols" response contains
			// both IPv4 and IPv6 peers.
			table := `0001 BIRD 3.3.0 ready.
2002-name     proto    table    state  since       info
1002-kernel1  Kernel   master   up     2016-11-21
 Mesh_172_17_8_102 BGP      master   up     2016-11-21  Established
 Mesh_fd80_24e2_f998_72d7__2 BGP      master   up     2016-11-21  Established
0000
`
			v4, err := scanBIRDPeers("4", conn{bytes.NewBufferString(table)})
			Expect(err).NotTo(HaveOccurred())
			Expect(v4).To(HaveLen(1))
			Expect(v4[0].PeerIP).To(Equal("172.17.8.102"))

			v6, err := scanBIRDPeers("6", conn{bytes.NewBufferString(table)})
			Expect(err).NotTo(HaveOccurred())
			Expect(v6).To(HaveLen(1))
			Expect(v6[0].PeerIP).To(Equal("fd80:24e2:f998:72d7::2"))
		})

		It("should parse real BIRD 3.3.0 'show protocols' wire output (capitalised headers)", func() {
			// Captured verbatim from a live BIRD 3.3.0 control socket. Note the
			// capitalised column headers ("Name Proto Table State ...") and the
			// "---" table column, both of which differ from BIRD 1.x.
			table := "0001 BIRD 3.3.0 ready.\n" +
				"2002-Name       Proto      Table      State  Since         Info\n" +
				"1002-device1    Device     ---        up     16:24:18.359  \n" +
				" Mesh_10_0_0_2 BGP        ---        start  16:24:18.359  Passive       \n" +
				" Node_10_0_0_3 BGP        ---        start  16:24:18.359  Passive       \n" +
				" Global_10_0_0_4 BGP        ---        start  16:24:18.359  Passive       \n" +
				" Mesh_2001_db8__2 BGP        ---        start  16:24:18.359  Passive       \n" +
				" Node_2001_db8__3 BGP        ---        start  16:24:18.359  Passive       \n" +
				"0000 \n"

			v4, err := scanBIRDPeers("4", conn{bytes.NewBufferString(table)})
			Expect(err).NotTo(HaveOccurred())
			Expect(v4).To(HaveLen(3))
			Expect(v4[0].PeerIP).To(Equal("10.0.0.2"))
			Expect(v4[0].PeerType).To(Equal("node-to-node mesh"))
			Expect(v4[0].BGPState).To(Equal("Passive"))

			v6, err := scanBIRDPeers("6", conn{bytes.NewBufferString(table)})
			Expect(err).NotTo(HaveOccurred())
			Expect(v6).To(HaveLen(2))
			Expect(v6[0].PeerIP).To(Equal("2001:db8::2"))
			Expect(v6[1].PeerIP).To(Equal("2001:db8::3"))
		})
	})
}

// Implement a Mock net.Conn interface, used to emulate reading data from a
// socket.
type conn struct {
	*bytes.Buffer
}

func (c conn) Close() error {
	panic("Should not be called")
}
func (c conn) LocalAddr() net.Addr {
	panic("Should not be called")
}
func (c conn) RemoteAddr() net.Addr {
	panic("Should not be called")
}
func (c conn) SetDeadline(t time.Time) error {
	panic("Should not be called")
}
func (c conn) SetReadDeadline(t time.Time) error {
	return nil
}
func (c conn) SetWriteDeadline(t time.Time) error {
	panic("Should not be called")
}
