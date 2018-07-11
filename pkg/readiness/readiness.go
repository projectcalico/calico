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
package readiness

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/node/pkg/readiness/bird"
)

const felixReadinessEp = "http://localhost:9099/readiness"

func Run(bird, bird6, felix bool) {

	if !bird && !felix && !bird6 {
		fmt.Printf("calico/node readiness check error: must specify at least one of -bird, -bird6, or -felix")
		os.Exit(1)
	}

	if felix {
		if err := checkFelixReady(); err != nil {
			fmt.Printf("calico/node is not ready: felix is not ready: %+v", err)
			os.Exit(1)
		}
	}

	if bird {
		if err := checkBIRDReady("4"); err != nil {
			fmt.Printf("calico/node is not ready: BIRD is not ready: %+v", err)
			os.Exit(1)
		}
	}

	if bird6 {
		if err := checkBIRDReady("6"); err != nil {
			fmt.Printf("calico/node is not ready: BIRD6 is not ready: %+v", err)
			os.Exit(1)
		}
	}
}

// checkBIRDReady checks if BIRD is ready by connecting to the BIRD
// socket to gather all BGP peer connection status, and overall graceful
// restart status.
func checkBIRDReady(ipv string) error {
	// Check for unestablished peers
	peers, err := bird.GetPeers(ipv)
	log.Debugf("peers: %v", peers)
	if err != nil {
		return err
	}

	s := []string{}
	for _, peer := range peers {
		if peer.BGPState != "Established" {
			s = append(s, peer.PeerIP)
		}
	}
	if len(s) > 0 {
		return fmt.Errorf("BGP not established with %+v", strings.Join(s, ","))
	}

	// Check for GR
	gr, err := bird.GRInProgress(ipv)
	if err != nil {
		return err
	} else if gr {
		return errors.New("graceful restart in progress")
	}

	return nil
}

// checkFelixReady checks if felix is ready by making an http request to
// Felix's readiness endpoint.
func checkFelixReady() error {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(felixReadinessEp)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("readiness probe reporting %d", resp.StatusCode)
	}
	return nil
}
