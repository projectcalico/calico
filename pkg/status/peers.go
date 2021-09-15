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

package status

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"reflect"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/olekukonko/tablewriter"

	log "github.com/sirupsen/logrus"
)

// Check for Word_<IP> where every octate is seperated by "_", regardless of IP protocols
// Example match: "Mesh_192_168_56_101" or "Mesh_fd80_24e2_f998_72d7__2"
var bgpPeerRegex = regexp.MustCompile(`^(Global|Node|Mesh)_(.+)$`)

// Mapping the BIRD/GoBGP type extracted from the peer name to the display type.
var bgpTypeMap = map[string]apiv3.BGPPeerType{
	"Global": apiv3.BGPPeerTypeGlobalPeer,
	"Mesh":   apiv3.BGPPeerTypeNodeMesh,
	"Node":   apiv3.BGPPeerTypeNodePeer,
}

// Expected BIRD protocol table columns
var birdExpectedHeadings = []string{"name", "proto", "table", "state", "since", "info"}

// bgpPeer is a structure containing details about a BGP peer.
type bgpPeer struct {
	peerIP   string
	peerType string
	state    string
	since    string
	bgpState string
	info     string
}

func (b *bgpPeer) toNodeStatusAPI() apiv3.CalicoNodePeer {
	info := b.bgpState
	if b.info != "" {
		info += " " + b.info
	}

	return apiv3.CalicoNodePeer{
		PeerIP: b.peerIP,
		Type:   bgpTypeMap[b.peerType],
		State:  b.state,
		Since:  b.since,
		Reason: info,
	}
}

// Unmarshal a peer from a line in the BIRD protocol output.  Returns true if
// successful, false otherwise.
func (b *bgpPeer) unmarshalBIRD(line, ipSep string) bool {
	// Split into fields.  We expect at least 6 columns:
	// 	name, proto, table, state, since and info.
	// The info column contains the BGP state plus possibly some additional
	// info (which will be columns > 6).
	//
	// Peer names will be of the format described by bgpPeerRegex.
	log.Debugf("Parsing line: %s", line)
	columns := strings.Fields(line)
	if len(columns) < 6 {
		log.Debugf("Not a valid line: fewer than 6 columns")
		return false
	}
	if columns[1] != "BGP" {
		log.Debugf("Not a valid line: protocol is not BGP")
		return false
	}

	// Check the name of the peer is of the correct format.  This regex
	// returns two components:
	// -  A type (Global|Node|Mesh) which we can map to a display type
	// -  An IP address (with _ separating the octets)
	sm := bgpPeerRegex.FindStringSubmatch(columns[0])
	if len(sm) != 3 {
		log.Debugf("Not a valid line: peer name '%s' is not correct format", columns[0])
		return false
	}
	var ok bool
	b.peerIP = strings.Replace(sm[2], "_", ipSep, -1)
	if _, ok = bgpTypeMap[sm[1]]; !ok {
		log.Debugf("Not a valid line: peer type '%s' is not recognized", sm[1])
		return false
	}
	b.peerType = sm[1]

	// Store remaining columns (piecing back together the info string)
	b.state = columns[3]
	b.since = columns[4]
	b.bgpState = columns[5]
	if len(columns) > 6 {
		b.info = strings.Join(columns[6:], " ")
	}

	return true
}

// readBIRDPeers queries BIRD and return BGP peer info.
func readBIRDPeers(bc *birdConn) ([]bgpPeer, error) {
	c := bc.conn
	ipv := bc.ipv
	log.Debugf("Getting BGP peers for IPv%s", ipv)

	// To query the current state of the BGP peers, we connect to the BIRD
	// socket and send a "show protocols" message.  BIRD responds with
	// peer data in a table format.
	//
	// Send the request.
	_, err := c.Write([]byte("show protocols\n"))
	if err != nil {
		return nil, fmt.Errorf("Error executing command: unable to write to BIRD socket: %s", err)
	}

	// Scan the output and collect parsed BGP peers
	log.Debugln("Reading output from BIRD")
	peers, err := scanBIRDPeers(ipv, c)
	if err != nil {
		return nil, fmt.Errorf("Error executing command: %v", err)
	}

	// If no peers were returned then just print a message.
	if len(peers) == 0 {
		fmt.Printf("No IPv%s peers found.\n", ipv)
		return peers, nil
	}

	return peers, nil
}

// scanBIRDPeers scans through BIRD output to return a slice of bgpPeer
// structs.
//
// We split this out from the main printBIRDPeers() function to allow us to
// test this processing in isolation.
func scanBIRDPeers(ipv BirdConnType, conn net.Conn) ([]bgpPeer, error) {
	// Determine the separator to use for an IP address, based on the
	// IP version.
	ipSep := ipv.Separator()

	// The following is sample output from BIRD
	//
	// 	0001 BIRD 1.5.0 ready.
	// 	2002-name     proto    table    state  since       info
	// 	1002-kernel1  Kernel   master   up     2016-11-21
	//  	 device1  Device   master   up     2016-11-21
	//  	 direct1  Direct   master   up     2016-11-21
	//  	 Mesh_172_17_8_102 BGP      master   up     2016-11-21  Established
	// 	0000
	scanner := bufio.NewScanner(conn)
	peers := []bgpPeer{}

	// Set a time-out for reading from the socket connection.
	err := conn.SetReadDeadline(time.Now().Add(birdTimeOut))
	if err != nil {
		return nil, errors.New("failed to set time-out")
	}

	for scanner.Scan() {
		// Process the next line that has been read by the scanner.
		str := scanner.Text()
		log.Debugf("Read: %s\n", str)

		if strings.HasPrefix(str, "0000") {
			// "0000" means end of data
			break
		} else if strings.HasPrefix(str, "0001") {
			// "0001" code means BIRD is ready.
		} else if strings.HasPrefix(str, "2002") {
			// "2002" code means start of headings
			f := strings.Fields(str[5:])
			if !reflect.DeepEqual(f, birdExpectedHeadings) {
				return nil, errors.New("unknown BIRD table output format")
			}
		} else if strings.HasPrefix(str, "1002") {
			// "1002" code means first row of data.
			peer := bgpPeer{}
			if peer.unmarshalBIRD(str[5:], ipSep) {
				peers = append(peers, peer)
			}
		} else if strings.HasPrefix(str, " ") {
			// Row starting with a " " is another row of data.
			peer := bgpPeer{}
			if peer.unmarshalBIRD(str[1:], ipSep) {
				peers = append(peers, peer)
			}
		} else {
			// Format of row is unexpected.
			return nil, errors.New("unexpected output line from BIRD")
		}

		// Before reading the next line, adjust the time-out for
		// reading from the socket connection.
		err = conn.SetReadDeadline(time.Now().Add(birdTimeOut))
		if err != nil {
			return nil, errors.New("failed to adjust time-out")
		}
	}

	return peers, scanner.Err()
}

func getBGPPeers(ipv BirdConnType) ([]bgpPeer, error) {
	bc, err := getBirdConn(ipv)
	if err != nil {
		return nil, err
	}
	defer bc.Close()

	peers, err := readBIRDPeers(bc)
	if err != nil {
		return nil, err
	}

	return peers, nil
}

// BirdBGPPeers implement statusPopulator interface.
type BirdBGPPeers struct {
	ipv BirdConnType
}

func (b BirdBGPPeers) Populate(status *apiv3.CalicoNodeStatus) error {
	peers, err := getBGPPeers(b.ipv)
	if err != nil {
		return err
	}
	numEstablished := 0
	numNonEstablished := 0

	convert := func(peers []bgpPeer) []apiv3.CalicoNodePeer {
		result := []apiv3.CalicoNodePeer{}
		for _, p := range peers {
			if p.state == "up" {
				numEstablished++
			} else {
				numNonEstablished++
			}
			result = append(result, p.toNodeStatusAPI())
		}
		return result
	}

	if b.ipv == BirdConnTypeV4 {
		status.Status.BGP.V4Peers = convert(peers)
	} else {
		status.Status.BGP.V6Peers = convert(peers)
	}
	status.Status.BGP.NumEstablished = numEstablished
	status.Status.BGP.NumNotEstablished = numNonEstablished

	return nil
}

// Show displays bgp peers.
func (b BirdBGPPeers) Show() {
	peers, err := getBGPPeers(b.ipv)
	if err != nil {
		fmt.Println("Error getting bird BGP peers: %v", err)
		return
	}

	fmt.Printf("\nbird v%s BGP peers\n", b.ipv.String())
	printPeers(peers)
}

// printPeers prints out the slice of peers in table format.
func printPeers(peers []bgpPeer) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Peer address", "Peer type", "State", "Since", "Info"})

	for _, peer := range peers {
		info := peer.bgpState
		if peer.info != "" {
			info += " " + peer.info
		}
		row := []string{
			peer.peerIP,
			peer.peerType,
			peer.state,
			peer.since,
			info,
		}
		table.Append(row)
	}

	table.Render()
}
