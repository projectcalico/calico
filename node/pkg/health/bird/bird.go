package bird

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Check for Word_<IP> where every octate is separated by "_", regardless of IP protocols
// Example match: "Mesh_192_168_56_101" or "Mesh_fd80_24e2_f998_72d7__2"
var bgpPeerRegex = regexp.MustCompile(`^(Global|Node|Mesh)_(.+)$`)

// Mapping the BIRD type extracted from the peer name to the display type.
var bgpTypeMap = map[string]string{
	"Global": "global",
	"Mesh":   "node-to-node mesh",
	"Node":   "node specific",
}

// Timeout for querying BIRD
var birdTimeOut = 2 * time.Second

// Expected BIRD protocol table columns
var birdExpectedHeadings = []string{"name", "proto", "table", "state", "since", "info"}

func GRInProgress(ipv string) (bool, error) {
	birdSuffix := ""
	if ipv == "6" {
		birdSuffix = "6"
	}

	// Try connecting to the BIRD socket in `/var/run/calico/` first to get the data
	birdSocket := fmt.Sprintf("/var/run/calico/bird%s.ctl", birdSuffix)
	if !socketFileExists(birdSocket) {
		// If that fails, try connecting to BIRD socket in `/var/run/bird` (which is the
		// default socket location for BIRD install) for non-containerized installs
		log.Debugln("Failed to connect to BIRD socket in /var/run/calico file not exists, trying /var/run/bird")
		birdSocket = fmt.Sprintf("/var/run/bird/bird%s.ctl", birdSuffix)
	}
	c, err := net.Dial("unix", birdSocket)
	if err != nil {
		return false, fmt.Errorf("Error querying BIRD: unable to connect to BIRDv%s socket: %v", ipv, err)
	}
	defer c.Close() // nolint: errcheck

	// To query the current state of the BGP peers, we connect to the BIRD
	// socket and send a "show protocols" message.  BIRD responds with
	// peer data in a table format.
	//
	// Send the request.
	_, err = c.Write([]byte("show status\n"))
	if err != nil {
		return false, fmt.Errorf("Error executing command: unable to write to BIRD socket: %s", err)
	}

	// The following is sample output from BIRD
	//
	// 0001 BIRD v0.3.2+birdv1.6.3 ready.
	// 1000-BIRD v0.3.2+birdv1.6.3
	// 1011-Router ID is 172.18.0.4
	// 	 Current server time is 2018-04-03 22:59:51
	// 	 Last reboot on 2018-04-03 22:59:26
	// 	 Last reconfiguration on 2018-04-03 22:59:26
	// 0024-Graceful restart recovery in progress
	// 	   Waiting for 1 protocols to recover
	// 	   Wait timer is 215/240
	// 0013 Daemon is up and running
	scanner := bufio.NewScanner(c)

	// Set a time-out for reading from the socket connection.
	if e := c.SetReadDeadline(time.Now().Add(birdTimeOut)); e != nil {
		return false, e
	}

	for scanner.Scan() {
		// Process the next line that has been read by the scanner.
		str := scanner.Text()
		log.Debugf("Read: %s\n", str)
		if strings.HasPrefix(str, "0013") {
			// "0013" code is the final line and indicates that BIRD is ready,
			break
		} else if strings.HasPrefix(str, "0001") {
			// "0001" code means BIRD is ready.
		} else if strings.HasPrefix(str, "1000") {
			// "1000" code shows the BIRD version
		} else if strings.HasPrefix(str, "1011") {
			// "1011" shows uptime
		} else if strings.HasPrefix(str, "0024") {
			// "0024" code indicates the start of a graceful restart status report.
			// This means a GR is in progress.
			return true, nil
		} else if strings.HasPrefix(str, " ") {
			// Row starting with a " " is another row of data.
		} else {
			// Format of row is unexpected.
			return false, fmt.Errorf("unexpected output line from BIRD: '%s'", str)
		}

		// Before reading the next line, adjust the time-out for
		// reading from the socket connection.
		if e := c.SetReadDeadline(time.Now().Add(birdTimeOut)); e != nil {
			return false, e
		}
	}

	return false, scanner.Err()
}

func socketFileExists(file string) bool {
	stat, err := os.Stat(file)
	if os.IsNotExist(err) {
		return false
	}
	return !stat.IsDir()
}

// bgpPeer is a structure containing details about a BGP peer.
type bgpPeer struct {
	PeerIP   string
	PeerType string
	State    string
	Since    string
	BGPState string
	Info     string
}

func GetPeers(ipv string) ([]bgpPeer, error) {
	log.Debugf("Print BIRD peers for IPv%s", ipv)
	birdSuffix := ""
	if ipv == "6" {
		birdSuffix = "6"
	}

	// Try connecting to the BIRD socket in `/var/run/calico/` first to get the data
	birdSocket := fmt.Sprintf("/var/run/calico/bird%s.ctl", birdSuffix)
	if !socketFileExists(birdSocket) {
		// If that fails, try connecting to BIRD socket in `/var/run/bird` (which is the
		// default socket location for BIRD install) for non-containerized installs
		log.Debugln("Failed to connect to BIRD socket in /var/run/calico file not exists, trying /var/run/bird")
		birdSocket = fmt.Sprintf("/var/run/bird/bird%s.ctl", birdSuffix)
	}
	c, err := net.Dial("unix", birdSocket)
	if err != nil {
		return nil, fmt.Errorf("Error querying BIRD: unable to connect to BIRDv%s socket: %v", ipv, err)
	}
	defer c.Close() // nolint: errcheck

	// To query the current state of the BGP peers, we connect to the BIRD
	// socket and send a "show protocols" message.  BIRD responds with
	// peer data in a table format.
	//
	// Send the request.
	_, err = c.Write([]byte("show protocols\n"))
	if err != nil {
		return nil, fmt.Errorf("Error executing command: unable to write to BIRD socket: %s\n", err)
	}

	// Scan the output and collect parsed BGP peers
	log.Debugln("Reading output from BIRD")
	peers, err := scanBIRDPeers(ipv, c)
	if err != nil {
		return nil, fmt.Errorf("Error executing command: %v", err)
	}

	return peers, nil
}

// scanBIRDPeers scans through BIRD output to return a slice of bgpPeer
// structs.
//
// We split this out from the main printBIRDPeers() function to allow us to
// test this processing in isolation.
func scanBIRDPeers(ipv string, conn net.Conn) ([]bgpPeer, error) {
	// Determine the separator to use for an IP address, based on the
	// IP version.
	ipSep := "."
	if ipv == "6" {
		ipSep = ":"
	}

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
	if e := conn.SetReadDeadline(time.Now().Add(birdTimeOut)); e != nil {
		return nil, e
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
			return nil, fmt.Errorf("unexpected output line from BIRD: '%s'", str)
		}

		// Before reading the next line, adjust the time-out for
		// reading from the socket connection.
		if e := conn.SetReadDeadline(time.Now().Add(birdTimeOut)); e != nil {
			return nil, e
		}
	}

	return peers, scanner.Err()
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
	b.PeerIP = strings.Replace(sm[2], "_", ipSep, -1)
	if b.PeerType, ok = bgpTypeMap[sm[1]]; !ok {
		log.Debugf("Not a valid line: peer type '%s' is not recognized", sm[1])
		return false
	}

	// Store remaining columns (piecing back together the info string)
	b.State = columns[3]
	b.Since = columns[4]
	b.BGPState = columns[5]
	if len(columns) > 6 {
		b.Info = strings.Join(columns[6:], " ")
	}

	return true
}
