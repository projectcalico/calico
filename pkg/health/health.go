// Copyright (c) 2018 Tigera, Inc. All rights reserved.
//
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
package health

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/node/pkg/health/bird"
)

var felixReadinessEp string
var felixLivenessEp string

func init() {
	felixPort := os.Getenv("FELIX_HEALTHPORT")
	if felixPort == "" {
		felixReadinessEp = "http://localhost:9099/readiness"
		felixLivenessEp = "http://localhost:9099/liveness"
		return
	}

	if _, err := strconv.Atoi(felixPort); err != nil {
		log.Panicf("Failed to parse value for port %q", felixPort)
	}

	felixReadinessEp = "http://localhost:" + felixPort + "/readiness"
	felixLivenessEp = "http://localhost:" + felixPort + "/liveness"
}

func Run(bird, bird6, felixReady, felixLive bool, thresholdTime time.Duration) {
	if felixLive {
		if err := checkFelixHealth(felixLivenessEp, "liveness"); err != nil {
			fmt.Printf("calico/node is not ready: Felix is not live: %+v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if !bird && !felixReady && !bird6 {
		fmt.Printf("calico/node readiness check error: must specify at least one of -bird, -bird6, or -felix")
		os.Exit(1)
	}

	if felixReady {
		if err := checkFelixHealth(felixReadinessEp, "readiness"); err != nil {
			fmt.Printf("calico/node is not ready: felix is not ready: %+v", err)
			os.Exit(1)
		}
	}

	if bird {
		if err := checkBIRDReady("4", thresholdTime); err != nil {
			fmt.Printf("calico/node is not ready: BIRD is not ready: %+v", err)
			os.Exit(1)
		}
	}

	if bird6 {
		if err := checkBIRDReady("6", thresholdTime); err != nil {
			fmt.Printf("calico/node is not ready: BIRD6 is not ready: %+v", err)
			os.Exit(1)
		}
	}
}

// checkBIRDReady checks if BIRD is ready by connecting to the BIRD
// socket to gather all BGP peer connection status, and overall graceful
// restart status.
func checkBIRDReady(ipv string, thresholdTime time.Duration) error {
	// Stat nodename file to get the modified time of the file.
	nodenameFileStat, err := os.Stat("/var/lib/calico/nodename")
	if err != nil {
		return fmt.Errorf("Failed to stat() nodename file: %v", err)
	}

	// Check for unestablished peers
	peers, err := bird.GetPeers(ipv)
	log.Debugf("peers: %v", peers)
	if err != nil {
		return err
	}

	s := []string{}

	// numEstablishedPeer keeps count of number of peers with bgp state established.
	numEstablishedPeer := 0

	for _, peer := range peers {
		if peer.BGPState == "Established" {
			numEstablishedPeer += 1
		} else {
			s = append(s, peer.PeerIP)
		}
	}
	log.Infof("Number of node(s) with BGP peering established = %v", numEstablishedPeer)

	if len(peers) == 0 {
		// In case of no BGP peers return bird to be ready.
		log.Debugf("There are no bgp peers, returning ready.")
	} else if time.Since(nodenameFileStat.ModTime()) < thresholdTime {
		if len(s) > 0 {
			// When we first start up, only report ready if all our peerings are established.
			// This prevents rolling update from proceeding until BGP is back up.
			return fmt.Errorf("BGP not established with %+v", strings.Join(s, ","))
		}
		// Check for GR
		gr, err := bird.GRInProgress(ipv)
		if err != nil {
			return err
		} else if gr {
			return errors.New("graceful restart in progress")
		}
	} else if numEstablishedPeer > 0 {
		// After a while, only require a single peering to be up.  This prevents the whole mesh
		// from reporting not-ready if some nodes go down.
		log.Debugf("There exist(s) %v calico node(s) with BGP peering established.", numEstablishedPeer)
	} else {
		return fmt.Errorf("BGP not established with %+v", strings.Join(s, ","))
	}

	return nil
}

// checkFelixHealth checks if felix is ready or live by making an http request to
// Felix's readiness or liveness endpoint.
func checkFelixHealth(endpoint, probeType string) (err error) {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(endpoint)
	if err != nil {
		return err
	}
	defer func() {
		if e := resp.Body.Close(); e != nil {
			err = e
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("%s probe reporting %d", probeType, resp.StatusCode)
	}
	return nil
}
