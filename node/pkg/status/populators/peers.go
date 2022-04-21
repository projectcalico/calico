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

package populator

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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

// Check for Word_<IP> where every octate is separated by "_", regardless of IP protocols
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
	session  string
	peerIP   string
	peerType string
	state    string
	since    string
	bgpState string
	info     string
}

var birdStateToBGPState map[string]apiv3.BGPSessionState = map[string]apiv3.BGPSessionState{
	"Idle":        apiv3.BGPSessionStateIdle,
	"Connect":     apiv3.BGPSessionStateConnect,
	"Active":      apiv3.BGPSessionStateActive,
	"OpenSent":    apiv3.BGPSessionStateOpenSent,
	"OpenConfirm": apiv3.BGPSessionStateOpenConfirm,
	"Established": apiv3.BGPSessionStateEstablished,
	"Close":       apiv3.BGPSessionStateClose,
}

func (b *bgpPeer) toNodeStatusAPI() apiv3.CalicoNodePeer {
	return apiv3.CalicoNodePeer{
		PeerIP: b.peerIP,
		Type:   bgpTypeMap[b.peerType],
		State:  birdStateToBGPState[b.bgpState],
		Since:  b.since,
	}
}

// Get BGP peer type and peer IP from session name.
func sessionNameToTypeAndPeerIP(ipSep, name string) (string, string, error) {
	// Check the name of the peer is of the correct format.  This regex
	// returns two components:
	// -  A type (Global|Node|Mesh) which we can map to a display type
	// -  An IP address (with _ separating the octets)
	sm := bgpPeerRegex.FindStringSubmatch(name)
	if len(sm) != 3 {
		log.Debugf("Not a valid line: peer name '%s' is not correct format", name)
		return "", "", fmt.Errorf("not a valid line: session name '%s' is not a correct format", name)
	}

	if _, ok := bgpTypeMap[sm[1]]; !ok {
		return "", "", fmt.Errorf("peer type '%s' is not recognized", sm[1])
	}

	ip := strings.Replace(sm[2], "_", ipSep, -1)
	return sm[1], ip, nil
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
		log.Debug("Not a valid line: fewer than 6 columns.")
		return false
	}
	if columns[1] != "BGP" {
		log.Debugf("Not a valid line(%s): protocol is not BGP", line)
		return false
	}

	peerType, _, err := sessionNameToTypeAndPeerIP(ipSep, columns[0])
	if err != nil {
		log.WithError(err).Warnf("Not a valid line(%s)", line)
		return false
	}

	// All good, set the session name
	b.session = columns[0]
	b.peerType = peerType

	// Store remaining columns (piecing back together the info string)
	b.state = columns[3]
	b.since = columns[4]
	if len(columns) > 6 {
		b.info = strings.Join(columns[6:], " ")
	}

	return true
}

// Complete reads detailed information for a BGP session and fill in bgpPeer structure.
// Currently we only set BGP state and PeerIP but could extend to other fields later.
func (b *bgpPeer) complete(bc *birdConn) error {
	// Send the request.
	cmd := fmt.Sprintf("show protocols all %s\n", b.session)

	// bird&gt; show protocols all neighbor_v4_1
	//name     proto    table    state  since       info
	//neighbor_v4_1 BGP      master   up     15:20:31    Established
	//  Preference:     100
	//  Input filter:   ACCEPT
	//  Output filter:  packet_bgp
	//  Routes:         0 imported, 1 exported, 0 preferred
	//  Route change stats:     received   rejected   filtered    ignored   accepted
	//    Import updates:              0          0          0          0          0
	//    Import withdraws:            0          0        ---          0          0
	//    Export updates:              1          0          0        ---          1
	//    Export withdraws:            0        ---        ---        ---          0
	//  BGP state:          Established
	//    Neighbor address: 10.99.182.128
	//    Neighbor AS:      65530
	//    Neighbor ID:      147.75.36.73
	//    Neighbor caps:    refresh restart-aware AS4
	//    Session:          external AS4
	//    Source address:   10.99.182.129
	//    Hold timer:       66/90
	//    Keepalive timer:  18/30

	// getValue parses a string with the format of "  key: value " and returns value.
	// It also returns if the format is valid or not.
	getValue := func(str, key string) (string, bool) {
		if strings.Contains(str, key) {
			return strings.TrimSpace(strings.ReplaceAll(str, key, " ")), true
		}
		return "", false
	}

	conn := bc.conn
	_, err := conn.Write([]byte(cmd))
	if err != nil {
		return fmt.Errorf("Error executing command: unable to write to BIRD socket: %s", err)
	}

	scanner := bufio.NewScanner(conn)

	// Set a time-out for reading from the socket connection.
	err = conn.SetReadDeadline(time.Now().Add(birdTimeOut))
	if err != nil {
		return errors.New("failed to set time-out")
	}

	for scanner.Scan() {
		// Process the next line that has been read by the scanner.
		str := scanner.Text()
		log.Debugf("Read: %s\n", str)

		if strings.HasPrefix(str, "0000") {
			// "0000" means end of data
			break
		} else if state, ok := getValue(str, "BGP state:"); ok {
			b.bgpState = state
		} else if ip, ok := getValue(str, "Neighbor address:"); ok {
			b.peerIP = ip
		}

		// Before reading the next line, adjust the time-out for
		// reading from the socket connection.
		err = conn.SetReadDeadline(time.Now().Add(birdTimeOut))
		if err != nil {
			return errors.New("failed to adjust time-out")
		}
	}

	return scanner.Err()
}

// readBIRDPeers queries BIRD and return BGP peer info.
func readBIRDPeers(bc *birdConn) ([]*bgpPeer, error) {
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
	log.Debugln("Reading output from BIRD for BGP peers summary")
	peers, err := scanBIRDPeers(ipv, c)
	if err != nil {
		return nil, fmt.Errorf("Error executing command: %v", err)
	}

	// If no peers were returned then just print a message.
	if len(peers) == 0 {
		log.Debugf("No IPv%s peers found.\n", ipv)
		return peers, nil
	}

	log.Debugln("Reading output for BGP peer details")
	for _, peer := range peers {
		err = peer.complete(bc)
		if err != nil {
			return nil, err
		}
	}

	return peers, nil
}

// scanBIRDPeers scans through BIRD output to return a slice of bgpPeer
// structs.
//
// We split this out from the main printBIRDPeers() function to allow us to
// test this processing in isolation.
func scanBIRDPeers(ipv IPFamily, conn net.Conn) ([]*bgpPeer, error) {
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
	peers := []*bgpPeer{}

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
				peers = append(peers, &peer)
			}
		} else if strings.HasPrefix(str, " ") {
			// Row starting with a " " is another row of data.
			peer := bgpPeer{}
			if peer.unmarshalBIRD(str[1:], ipSep) {
				peers = append(peers, &peer)
			}
		} else {
			// Format of row is unexpected.
			return nil, fmt.Errorf("unexpected output line from BIRD: %s", str)
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

func getBGPPeers(ipv IPFamily) ([]*bgpPeer, error) {
	bc, err := getBirdConn(ipv)
	if err != nil {
		return nil, err
	}
	defer bc.Close()

	peers, err := readBIRDPeers(bc)
	if err != nil {
		log.WithError(err).Errorf("failed to get bird BGP peers")
		return nil, err
	}

	return peers, nil
}

// BirdBGPPeers implement populator interface.
type BirdBGPPeers struct {
	ipv IPFamily
}

func NewBirdBGPPeers(ipv IPFamily) BirdBGPPeers {
	return BirdBGPPeers{ipv: ipv}
}

func (b BirdBGPPeers) Populate(status *apiv3.CalicoNodeStatus) error {
	peers, err := getBGPPeers(b.ipv)
	if err != nil {
		// If it is a connection error, e.g. BGP is not enabled,
		// set empty status.
		if _, ok := err.(ErrorSocketConnection); ok {
			if b.ipv == IPFamilyV4 {
				status.Status.BGP = apiv3.CalicoNodeBGPStatus{}
			} else {
				status.Status.BGP = apiv3.CalicoNodeBGPStatus{}
			}
			return nil
		}
		log.WithError(err).Errorf("failed to get bird BGP peers")
		return err
	}

	convert := func(peers []*bgpPeer) ([]apiv3.CalicoNodePeer, int, int) {
		numEstablished := 0
		numNonEstablished := 0

		result := []apiv3.CalicoNodePeer{}
		for _, p := range peers {
			if p.state == "up" {
				numEstablished++
			} else {
				numNonEstablished++
			}
			result = append(result, p.toNodeStatusAPI())
		}
		return result, numEstablished, numNonEstablished
	}

	bgp := &status.Status.BGP
	if b.ipv == IPFamilyV4 {
		bgp.PeersV4, bgp.NumberEstablishedV4, bgp.NumberNotEstablishedV4 = convert(peers)
	} else {
		bgp.PeersV6, bgp.NumberEstablishedV6, bgp.NumberNotEstablishedV6 = convert(peers)
	}

	return nil
}

// Show displays bgp peers.
func (b BirdBGPPeers) Show() {
	peers, err := getBGPPeers(b.ipv)
	if err != nil {
		fmt.Printf("Error getting bird BGP peers: %v\n", err)
		return
	}

	fmt.Printf("\nbird v%s BGP peers\n", b.ipv.String())
	printPeers(peers, os.Stdout)
}

// printPeers prints out the slice of peers in table format.
func printPeers(peers []*bgpPeer, out io.Writer) {
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Peer address", "Peer type", "State", "Since", "BGPState"})

	for _, peer := range peers {
		row := []string{
			peer.peerIP,
			peer.peerType,
			peer.state,
			peer.since,
			peer.bgpState,
		}
		table.Append(row)
	}

	table.Render()
}
