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
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// Timeout for querying BIRD
var birdTimeOut = 2 * time.Second

type birdConn struct {
	conn net.Conn
	ipv  IPFamily
}

func (bc *birdConn) Close() {
	if bc.conn == nil {
		log.Fatal("Cannot close a nil bird connection")
	}
	bc.conn.Close()
}

// getBirdConn return a connection to bird socket.
func getBirdConn(ipv IPFamily) (*birdConn, error) {
	birdSuffix := ipv.BirdSuffix()

	// Try connecting to the bird socket in `/var/run/calico/` first to get the data
	c, err := net.Dial("unix", fmt.Sprintf("/var/run/calico/bird%s.ctl", birdSuffix))
	if err != nil {
		// If that fails, try connecting to bird socket in `/var/run/bird` (which is the
		// default socket location for bird install) for non-containerized installs
		log.Debugln("Failed to connect to BIRD socket in /var/run/calico, trying /var/run/bird")
		c, err = net.Dial("unix", fmt.Sprintf("/var/run/bird/bird%s.ctl", birdSuffix))
		if err != nil {
			return nil, ErrorSocketConnection{Err: err, ipv: ipv}
		}
	}

	return &birdConn{conn: c, ipv: ipv}, nil
}

// Error indicating connection to bird socket failed.
type ErrorSocketConnection struct {
	Err error
	ipv IPFamily
}

func (e ErrorSocketConnection) Error() string {
	return fmt.Sprintf("Error querying BIRD: unable to connect to BIRDv%s socket: %v", e.ipv, e.Err)
}
