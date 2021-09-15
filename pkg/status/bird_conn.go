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

package status

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

type BirdConnType string

const (
	BirdConnTypeV4 BirdConnType = "4"
	BirdConnTypeV6              = "6"
)

func (c BirdConnType) String() string {
	return string(c)
}

func (c BirdConnType) Suffix() string {
	if c == BirdConnTypeV4 {
		return ""
	} else if c == BirdConnTypeV6 {
		return "6"
	} else {
		log.Fatal("Unknown BirdConnType")
	}
	return ""
}

func (c BirdConnType) Separator() string {
	if c == BirdConnTypeV4 {
		return "."
	} else if c == BirdConnTypeV6 {
		return ":"
	} else {
		log.Fatal("Unknown BirdConnType")
	}
	return "."
}

// Timeout for querying BIRD
var birdTimeOut = 2 * time.Second

type birdConn struct {
	conn net.Conn
	ipv  BirdConnType
}

func (bc *birdConn) Close() {
	if bc.conn == nil {
		log.Fatal("Cannot close a nil bird connection")
	}
	bc.conn.Close()
}

// getBirdConn return a connection to bird socket.
func getBirdConn(ipv BirdConnType) (*birdConn, error) {
	birdSuffix := ipv.Suffix()

	// Try connecting to the bird socket in `/var/run/calico/` first to get the data
	c, err := net.Dial("unix", fmt.Sprintf("/var/run/calico/bird%s.ctl", birdSuffix))
	if err != nil {
		// If that fails, try connecting to bird socket in `/var/run/bird` (which is the
		// default socket location for bird install) for non-containerized installs
		log.Debugln("Failed to connect to BIRD socket in /var/run/calic, trying /var/run/bird")
		c, err = net.Dial("unix", fmt.Sprintf("/var/run/bird/bird%s.ctl", birdSuffix))
		if err != nil {
			return nil, fmt.Errorf("Error querying BIRD: unable to connect to BIRDv%s socket: %v", ipv, err)
		}
	}

	return &birdConn{conn: c, ipv: ipv}, nil
}
