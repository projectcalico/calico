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
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/olekukonko/tablewriter"

	log "github.com/sirupsen/logrus"
)

var (
	viaRegex         = regexp.MustCompile(`(?P<dest>\S*)\s*via\s(?P<gateway>\S*)\s*on\s(?P<iface>.*)\s\[(?P<from>\S*)\s.*\].*`)
	devRegex         = regexp.MustCompile(`(?P<dest>\S*)\s*dev\s(?P<iface>.*)\s\[(?P<from>\S*)\s.*\].*`)
	blackholeRegex   = regexp.MustCompile(`(?P<dest>\S*)\s*blackhole\s\[(?P<from>\S*)\s.*\].*`)
	unreachableRegex = regexp.MustCompile(`(?P<dest>\S*)\s*unreachable\s\[(?P<from>\S*)\s.*\].*`)
)

// route is a structure containing details about a route.
type route struct {
	dest        string
	gateway     string
	iface       string
	learnedFrom string
	primary     bool
}

func (r *route) IPFamily() IPFamily {
	if len(r.dest) == 0 {
		log.Fatal("Unknown destination for route")
	}
	if strings.Contains(r.dest, ":") {
		return IPFamilyV6
	}
	return IPFamilyV4
}

func (r *route) toNodeStatusAPI() (*apiv3.CalicoNodeRoute, error) {
	learnedFrom := apiv3.CalicoNodeRouteLearnedFrom{}

	var routeType apiv3.CalicoNodeRouteType
	if r.primary {
		routeType = apiv3.RouteTypeFIB
	} else {
		routeType = apiv3.RouteTypeRIB
	}

	if strings.HasPrefix(r.learnedFrom, "kernel") {
		learnedFrom.SourceType = apiv3.RouteSourceTypeKernel
	} else if strings.HasPrefix(r.learnedFrom, "static") {
		learnedFrom.SourceType = apiv3.RouteSourceTypeStatic
	} else if strings.HasPrefix(r.learnedFrom, "direct") {
		learnedFrom.SourceType = apiv3.RouteSourceTypeDirect
	} else {
		// TODO get information from Confd
		// Currently we just parse BGP session name and set type and peer IP.
		peerType, ip, err := sessionNameToTypeAndPeerIP(r.IPFamily().Separator(), r.learnedFrom)
		if err != nil {
			return nil, err
		}

		if bgpTypeMap[peerType] == apiv3.BGPPeerTypeNodeMesh {
			learnedFrom.SourceType = apiv3.RouteSourceTypeNodeMesh
		} else {
			learnedFrom.SourceType = apiv3.RouteSourceTypeBGPPeer
		}

		learnedFrom.PeerIP = ip
	}

	return &apiv3.CalicoNodeRoute{
		Type:        routeType,
		Destination: r.dest,
		Gateway:     r.gateway,
		Interface:   r.iface,
		LearnedFrom: learnedFrom,
	}, nil
}

// Unmarshal a peer from a line in the BIRD protocol output.
// In case there is no destination specified in the line,
// it will use the destination passed in.
func (r *route) unmarshalBIRD(line, ipSep, previousDest string) (string, bool) {
	log.Debugf("Parsing line: %s", line)

	if strings.Contains(line, " via ") {
		m := getGroupValues(viaRegex, line)
		if len(m) == 0 {
			log.Errorf("Failed to parse (%s)", line)
			return "", false
		}

		r.dest = m["dest"]
		r.gateway = m["gateway"]
		r.iface = m["iface"]
		r.learnedFrom = m["from"]
	} else if strings.Contains(line, " dev ") {
		m := getGroupValues(devRegex, line)
		if len(m) == 0 {
			log.Errorf("Failed to parse (%s)", line)
			return "", false
		}
		r.dest = m["dest"]
		r.gateway = "N/A"
		r.iface = m["iface"]
		r.learnedFrom = m["from"]
	} else if strings.Contains(line, " blackhole ") {
		m := getGroupValues(blackholeRegex, line)
		if len(m) == 0 {
			log.Errorf("Failed to parse (%s)", line)
			return "", false
		}
		r.dest = m["dest"]
		r.gateway = "N/A"
		r.iface = "blackhole"
		r.learnedFrom = m["from"]
	} else if strings.Contains(line, " unreachable ") {
		m := getGroupValues(unreachableRegex, line)
		if len(m) == 0 {
			log.Errorf("Failed to parse (%s)", line)
			return "", false
		}
		r.dest = m["dest"]
		r.gateway = "N/A"
		r.iface = "unreachable"
		r.learnedFrom = m["from"]
	}

	if len(r.dest) == 0 {
		if len(previousDest) == 0 {
			log.Errorf("No destination available, failed to parse (%s)", line)
			return "", false
		}
		// No destination at the start. Use previous destination.
		r.dest = previousDest
	}

	// All good, check if we see "] *" for the primary route.
	// https://github.com/projectcalico/bird/blob/feature-ipinip/nest/rt-table.c#L2517
	if strings.Contains(line, "] *") {
		r.primary = true
	}

	return r.dest, true
}

// Parses string with the given regular expression and convert
// group values to a map.
func getGroupValues(regEx *regexp.Regexp, s string) map[string]string {
	match := regEx.FindStringSubmatch(s)

	vMap := make(map[string]string)
	for i, name := range regEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			vMap[name] = match[i]
		}
	}
	return vMap
}

// readBIRDRoutes queries BIRD and return route info.
func readBIRDRoutes(bc *birdConn) ([]route, error) {
	c := bc.conn
	ipv := bc.ipv
	log.Debugf("Getting BGP routes for IPv%s", ipv)

	// Send the request.
	_, err := c.Write([]byte("show route\n"))
	if err != nil {
		return nil, fmt.Errorf("Error executing command: unable to write to BIRD socket: %s", err)
	}

	// Scan the output and collect parsed BGP routes
	log.Debugln("Reading output from BIRD")
	routes, err := scanBIRDRoutes(ipv, c)
	if err != nil {
		return nil, fmt.Errorf("Error executing command: %v", err)
	}

	// If no routes were returned then just print a message.
	if len(routes) == 0 {
		log.Debugf("No IPv%s routes found.\n", ipv)
		return routes, nil
	}

	return routes, nil
}

// scanBIRDRoutes scans through BIRD output to return a slice of route
// structs.
//
// We split this out from the main printBIRDPeers() function to allow us to
// test this processing in isolation.
func scanBIRDRoutes(ipv IPFamily, conn net.Conn) ([]route, error) {
	// Determine the separator to use for an IP address, based on the
	// IP version.
	ipSep := ipv.Separator()

	// 0001 BIRD v0.3.3+birdv1.6.8 ready.
	//
	// 1007-0.0.0.0/0          via 172.17.0.1 on eth0 [kernel1 20:10:57] * (10)
	//
	//  192.168.110.128/26 via 172.17.0.5 on eth0 [Mesh_172_17_0_5 20:10:57] * (100/0) [i]
	//
	//  192.168.82.0/26    via 172.17.0.4 on eth0 [Mesh_172_17_0_4 20:11:00] * (100/0) [i]
	//
	//  192.168.195.192/26 via 172.17.0.2 on eth0 [Mesh_172_17_0_2 20:10:58] * (100/0) [i]
	//
	//  192.168.162.128/26 blackhole [static1 20:10:56] * (200)
	//
	//  192.168.162.128/32 dev tunl0 [direct1 20:10:56] * (240)
	//
	//  192.168.162.129/32 dev calie58e37f9a7f [kernel1 20:11:10] * (10)
	//
	//  192.168.162.130/32 dev calid598e15828a [kernel1 20:11:12] * (10)
	//
	//  172.17.0.0/16      dev eth0 [direct1 20:10:56] * (240)
	//
	// 0000

	scanner := bufio.NewScanner(conn)
	routes := []route{}

	// Set a time-out for reading from the socket connection.
	err := conn.SetReadDeadline(time.Now().Add(birdTimeOut))
	if err != nil {
		return nil, errors.New("failed to set time-out")
	}

	var previousDest string
	var ok bool
	for scanner.Scan() {
		// Process the next line that has been read by the scanner.
		str := scanner.Text()
		log.Debugf("Read: %s\n", str)

		if strings.HasPrefix(str, "0000") {
			// "0000" means end of data
			break
		} else if strings.HasPrefix(str, "0001") {
			// "0001" code means BIRD is ready.
		} else if strings.HasPrefix(str, "1007") {
			// "1007" code means first row of data.
			route := route{}
			if previousDest, ok = route.unmarshalBIRD(str[5:], ipSep, previousDest); ok {
				routes = append(routes, route)
			}
		} else if strings.HasPrefix(str, " ") {
			// Row starting with a " " is another row of data.
			route := route{}
			if previousDest, ok = route.unmarshalBIRD(str[1:], ipSep, previousDest); ok {
				routes = append(routes, route)
			}
		} else {
			// Format of row is unexpected.
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

	return routes, scanner.Err()
}

func getRoutes(ipv IPFamily) ([]route, error) {
	bc, err := getBirdConn(ipv)
	if err != nil {
		return nil, err
	}
	defer bc.Close()

	routes, err := readBIRDRoutes(bc)
	if err != nil {
		return nil, err
	}

	return routes, nil
}

// BirdRoutes implement populator interface.
type BirdRoutes struct {
	ipv IPFamily
}

func NewBirdRoutes(ipv IPFamily) BirdRoutes {
	return BirdRoutes{ipv: ipv}
}

func (b BirdRoutes) Populate(status *apiv3.CalicoNodeStatus) error {
	routes, err := getRoutes(b.ipv)
	if err != nil {
		// If it is a connection error, e.g. BGP is not enabled,
		// set empty status.
		if _, ok := err.(ErrorSocketConnection); ok {
			if b.ipv == IPFamilyV4 {
				status.Status.Routes = apiv3.CalicoNodeBGPRouteStatus{}
			} else {
				status.Status.Routes = apiv3.CalicoNodeBGPRouteStatus{}
			}
			return nil
		}
		log.WithError(err).Errorf("failed to get bird BGP routes")
		return err
	}

	convert := func(routes []route) ([]apiv3.CalicoNodeRoute, error) {
		result := []apiv3.CalicoNodeRoute{}
		for _, r := range routes {
			apiRoute, err := r.toNodeStatusAPI()
			if err != nil {
				return nil, err
			}
			result = append(result, *apiRoute)
		}
		return result, nil
	}

	apiRoutes, err := convert(routes)
	if err != nil {
		return err
	}

	if b.ipv == IPFamilyV4 {
		status.Status.Routes.RoutesV4 = apiRoutes
	} else {
		status.Status.Routes.RoutesV6 = apiRoutes
	}

	return nil
}

// Show displays routes read from birdcl.
func (b BirdRoutes) Show() {
	routes, err := getRoutes(b.ipv)
	if err != nil {
		fmt.Printf("Error getting birdRoutes: %v\n", err)
		return
	}

	fmt.Printf("\nbird v%s routes\n", b.ipv.String())
	printRoutes(routes, os.Stdout)
}

// printRoutes prints out the slice of route in table format.
func printRoutes(routes []route, out io.Writer) {
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Destination", "Gateway", "Iface", "LearnedFrom", "primary"})

	for _, r := range routes {
		var primary string
		if r.primary {
			primary = "*"
		}
		row := []string{
			r.dest,
			r.gateway,
			r.iface,
			r.learnedFrom,
			primary,
		}
		table.Append(row)
	}

	table.Render()
}
