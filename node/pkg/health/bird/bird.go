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
	// In BIRD3, a single daemon handles both IPv4 and IPv6.
	// Always connect to the same socket regardless of IP family.

	// Try connecting to the BIRD socket in `/var/run/calico/` first to get the data
	birdSocket := "/var/run/calico/bird.ctl"
	if !socketFileExists(birdSocket) {
		// If that fails, try connecting to BIRD socket in `/var/run/bird` (which is the
		// default socket location for BIRD install) for non-containerized installs
		log.Debugln("Failed to connect to BIRD socket in /var/run/calico file not exists, trying /var/run/bird")
		birdSocket = "/var/run/bird/bird.ctl"
	}
	c, err := net.Dial("unix", birdSocket)
	if err != nil {
		return false, fmt.Errorf("error querying BIRD: unable to connect to BIRDv%s socket: %v", ipv, err)
	}
	defer c.Close() // nolint: errcheck

	// To query the current state of the BGP peers, we connect to the BIRD
	// socket and send a "show protocols" message.  BIRD responds with
	// peer data in a table format.
	//
	// Send the request.
	_, err = c.Write([]byte("show status\n"))
	if err != nil {
		return false, fmt.Errorf("error executing command: unable to write to BIRD socket: %s", err)
	}

	// The following is sample output from BIRD
	//
	// 0001 BIRD 3.3.0 ready.
	// 1000-BIRD 3.3.0
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
	// In BIRD3, a single daemon handles both IPv4 and IPv6.
	// Always connect to the same socket regardless of IP family.

	// Try connecting to the BIRD socket in `/var/run/calico/` first to get the data
	birdSocket := "/var/run/calico/bird.ctl"
	if !socketFileExists(birdSocket) {
		// If that fails, try connecting to BIRD socket in `/var/run/bird` (which is the
		// default socket location for BIRD install) for non-containerized installs
		log.Debugln("Failed to connect to BIRD socket in /var/run/calico file not exists, trying /var/run/bird")
		birdSocket = "/var/run/bird/bird.ctl"
	}
	c, err := net.Dial("unix", birdSocket)
	if err != nil {
		return nil, fmt.Errorf("error querying BIRD: unable to connect to BIRDv%s socket: %v", ipv, err)
	}
	defer c.Close() // nolint: errcheck

	// To query the current state of the BGP peers, we connect to the BIRD
	// socket and send a "show protocols" message.  BIRD responds with
	// peer data in a table format.
	//
	// Send the request.
	_, err = c.Write([]byte("show protocols\n"))
	if err != nil {
		return nil, fmt.Errorf("error executing command: unable to write to BIRD socket: %s", err)
	}

	// Scan the output and collect parsed BGP peers
	log.Debugln("Reading output from BIRD")
	peers, err := scanBIRDPeers(ipv, c)
	if err != nil {
		return nil, fmt.Errorf("error executing command: %v", err)
	}

	return peers, nil
}

// scanBIRDPeers scans through BIRD output to return a slice of bgpPeer
// structs.
//
// We split this out from the main printBIRDPeers() function to allow us to
// test this processing in isolation.
func scanBIRDPeers(ipv string, conn net.Conn) ([]bgpPeer, error) {
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
			// "2002" code means start of headings.
			// BIRD 1.x emitted lowercase column names; BIRD 3.x capitalises
			// them ("Name Proto Table State Since Info"). Compare
			// case-insensitively so both are accepted.
			f := strings.Fields(strings.ToLower(str[5:]))
			if !reflect.DeepEqual(f, birdExpectedHeadings) {
				return nil, errors.New("unknown BIRD table output format")
			}
		} else if strings.HasPrefix(str, "1002") {
			// "1002" code means first row of data.
			peer := bgpPeer{}
			if peer.unmarshalBIRD(str[5:]) {
				peers = append(peers, peer)
			}
		} else if strings.HasPrefix(str, " ") {
			// Row starting with a " " is another row of data.
			peer := bgpPeer{}
			if peer.unmarshalBIRD(str[1:]) {
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

	// In BIRD3 the single control socket returns peers for both address
	// families. Filter to the requested family so callers retain per-AF
	// semantics (GetPeers("4") -> only IPv4 peers, GetPeers("6") -> only IPv6).
	wantV6 := ipv == "6"
	filtered := peers[:0]
	for _, p := range peers {
		if strings.Contains(p.PeerIP, ":") == wantV6 {
			filtered = append(filtered, p)
		}
	}

	return filtered, scanner.Err()
}

// Unmarshal a peer from a line in the BIRD protocol output.  Returns true if
// successful, false otherwise.
func (b *bgpPeer) unmarshalBIRD(line string) bool {
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
	// In BIRD3 a single daemon serves both address families, so a single
	// "show protocols" response contains both IPv4 and IPv6 peers. Detect the
	// family per-peer from the encoded name rather than relying on a single
	// separator: IPv4 reconstructs to a valid dotted address, otherwise treat
	// it as IPv6 (':' separated, with '__' representing '::').
	if v4 := strings.ReplaceAll(sm[2], "_", "."); net.ParseIP(v4) != nil && net.ParseIP(v4).To4() != nil {
		b.PeerIP = v4
	} else {
		// IPv6: '_' separates hextets and '__' encodes '::'.
		b.PeerIP = strings.ReplaceAll(sm[2], "_", ":")
	}
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
