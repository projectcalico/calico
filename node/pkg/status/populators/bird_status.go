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
	"strings"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/olekukonko/tablewriter"

	log "github.com/sirupsen/logrus"
)

// birdStatus is a structure containing details about bird.
type birdStatus struct {
	ready            bool
	version          string
	routerID         string
	serverTime       string
	lastBootTime     string
	lastReconfigTime string
}

func (b *birdStatus) toNodeStatusAPI() apiv3.BGPDaemonStatus {
	var state apiv3.BGPDaemonState
	if b.ready {
		state = apiv3.BGPDaemonStateReady
	} else {
		state = apiv3.BGPDaemonStateNotReady
	}

	return apiv3.BGPDaemonStatus{
		State:                   state,
		Version:                 b.version,
		RouterID:                b.routerID,
		LastBootTime:            b.lastBootTime,
		LastReconfigurationTime: b.lastReconfigTime,
	}
}

// Unmarshal from a line in the BIRD protocol output.
// Returns true if successful, false otherwise.
func (b *birdStatus) unmarshalBIRD(line string) bool {
	// Peer names will be of the format described by bgpPeerRegex.
	log.Debugf("Parsing line: %s", line)

	if strings.Contains(line, "BIRD") && strings.Contains(line, "ready") {
		b.ready = true
	} else if strings.HasPrefix(line, "BIRD v") {
		b.version = strings.TrimPrefix(line, "BIRD ")
	} else if strings.HasPrefix(line, "Router ID is ") {
		b.routerID = strings.TrimPrefix(line, "Router ID is ")
	} else if strings.HasPrefix(line, "Current server time is ") {
		b.serverTime = strings.TrimPrefix(line, "Current server time is ")
	} else if strings.HasPrefix(line, "Last reboot on ") {
		b.lastBootTime = strings.TrimPrefix(line, "Last reboot on ")
	} else if strings.HasPrefix(line, "Last reconfiguration on ") {
		b.lastReconfigTime = strings.TrimPrefix(line, "Last reconfiguration on ")
	} else {
		return false
	}

	return true
}

// readBIRDStatus queries BIRD and return bird status info.
func readBIRDStatus(bc *birdConn) (*birdStatus, error) {
	c := bc.conn
	ipv := bc.ipv
	log.Debugf("Getting BIRD status for IPv%s", ipv)

	// Send the request.
	_, err := c.Write([]byte("show status\n"))
	if err != nil {
		return nil, fmt.Errorf("Error executing command: unable to write to BIRD socket: %s", err)
	}

	// Scan the output and collect parsed BGP peers
	log.Debugln("Reading output from BIRD")
	status, err := scanBIRDStatus(c)
	if err != nil {
		return nil, fmt.Errorf("Error executing command: %v", err)
	}

	return status, nil
}

// scanBIRDStatus scans through BIRD output to return birdStatus.
func scanBIRDStatus(conn net.Conn) (*birdStatus, error) {
	// The following is sample output from BIRD
	//
	// 0001 BIRD v0.3.3+birdv1.6.8 ready.
	//
	// 1000-BIRD v0.3.3+birdv1.6.8
	//
	// 1011-Router ID is 172.17.0.3
	//
	//  Current server time is 2021-09-19 20:48:43
	//
	//  Last reboot on 2021-09-19 20:10:56
	//
	//  Last reconfiguration on 2021-09-19 20:10:56
	//
	// 013 Daemon is up and running

	scanner := bufio.NewScanner(conn)
	status := &birdStatus{}

	// Set a time-out for reading from the socket connection.
	err := conn.SetReadDeadline(time.Now().Add(birdTimeOut))
	if err != nil {
		return nil, errors.New("failed to set time-out")
	}

	for scanner.Scan() {
		// Process the next line that has been read by the scanner.
		str := scanner.Text()
		log.Debugf("Read: %s\n", str)

		if strings.HasPrefix(str, "0013") {
			// "0013" means end of data
			break
		} else if strings.HasPrefix(str, "0001") ||
			strings.HasPrefix(str, "1000") ||
			strings.HasPrefix(str, "1011") {
			status.unmarshalBIRD(str[5:])
		} else if strings.HasPrefix(str, " ") {
			status.unmarshalBIRD(str[1:])
		} else {
			// Format of row is unexpected.
			// For example "0024-Graceful restart recovery in progress"
			log.Warnf("unexpected output line from BIRD: %s", str)
			break
		}

		// Before reading the next line, adjust the time-out for
		// reading from the socket connection.
		err = conn.SetReadDeadline(time.Now().Add(birdTimeOut))
		if err != nil {
			return nil, errors.New("failed to adjust time-out")
		}
	}

	return status, scanner.Err()
}

func getBirdStatus(ipv IPFamily) (*birdStatus, error) {
	bc, err := getBirdConn(ipv)
	if err != nil {
		return nil, err
	}
	defer bc.Close()

	status, err := readBIRDStatus(bc)
	if err != nil {
		return nil, err
	}

	return status, nil
}

// BirdInfo implement populator interface.
type BirdInfo struct {
	ipv IPFamily
}

func NewBirdInfo(ipv IPFamily) BirdInfo {
	return BirdInfo{ipv: ipv}
}

func (b BirdInfo) Populate(status *apiv3.CalicoNodeStatus) error {
	birdStatus, err := getBirdStatus(b.ipv)
	if err != nil {
		// If it is a connection error, e.g. BGP is not enabled,
		// set NotReady state.
		if _, ok := err.(ErrorSocketConnection); ok {
			if b.ipv == IPFamilyV4 {
				status.Status.Agent.BIRDV4 = apiv3.BGPDaemonStatus{State: apiv3.BGPDaemonStateNotReady}
			} else {
				status.Status.Agent.BIRDV6 = apiv3.BGPDaemonStatus{State: apiv3.BGPDaemonStateNotReady}
			}
			return nil
		}
		log.WithError(err).Errorf("failed to get bird status")
		return err
	}

	if b.ipv == IPFamilyV4 {
		status.Status.Agent.BIRDV4 = birdStatus.toNodeStatusAPI()
	} else {
		status.Status.Agent.BIRDV6 = birdStatus.toNodeStatusAPI()
	}

	return nil
}

func (b BirdInfo) Show() {
	birdStatus, err := getBirdStatus(b.ipv)
	if err != nil {
		fmt.Printf("Error getting birdStatus: %v\n", err)
		return
	}

	fmt.Printf("\nbird v%s status\n", b.ipv.String())
	printStatus(birdStatus, os.Stdout)
}

// printStatus prints out bird status.
func printStatus(status *birdStatus, out io.Writer) {
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Ready", "Version", "RouteID", "ServerTime", "LastBoot", "LastReconfig"})

	row := []string{
		fmt.Sprintf("%t", status.ready),
		status.version,
		status.routerID,
		status.serverTime,
		status.lastBootTime,
		status.lastReconfigTime,
	}
	table.Append(row)

	table.Render()
}
