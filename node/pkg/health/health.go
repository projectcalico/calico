// Copyright (c) 2018 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package health

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/projectcalico/calico/node/pkg/health/bird"
)

var felixReadinessEp string
var felixLivenessEp string

func init() {
	felixPort := os.Getenv("FELIX_HEALTHPORT")
	if felixPort == "" {
		felixPort = "9099"
	}

	if _, err := strconv.Atoi(felixPort); err != nil {
		log.Panicf("Failed to parse value for port %q", felixPort)
	}

	felixHost := os.Getenv("FELIX_HEALTHHOST")
	if felixHost == "" {
		felixHost = "localhost"
	}

	felixReadinessEp = "http://" + felixHost + ":" + felixPort + "/readiness"
	felixLivenessEp = "http://" + felixHost + ":" + felixPort + "/liveness"
}

func Run(bird, bird6, felixReady, felixLive, birdLive, bird6Live bool, thresholdTime time.Duration) {
	livenessChecks := felixLive || birdLive || bird6Live
	readinessChecks := bird || felixReady || bird6

	if !livenessChecks && !readinessChecks {
		fmt.Printf("calico/node check error: must specify at least one of -bird-live, -bird6-live, -felix-live, -bird, -bird6, or -felix\n")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), thresholdTime)
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)

	if felixLive {
		g.Go(func() error {
			if err := checkFelixHealth(ctx, felixLivenessEp, "liveness"); err != nil {
				return fmt.Errorf("calico/node is not ready: Felix is not live: %+v", err)
			}
			return nil
		})
	}

	if birdLive {
		g.Go(func() error {
			if err := checkServiceIsLive([]string{"confd", "bird"}); err != nil {
				return fmt.Errorf("calico/node is not ready: bird/confd is not live: %+v", err)
			}
			return nil
		})
	}

	if bird6Live {
		g.Go(func() error {
			if err := checkServiceIsLive([]string{"confd", "bird6"}); err != nil {
				return fmt.Errorf("calico/node is not ready: bird6/confd is not live: %+v", err)
			}
			return nil
		})
	}

	if felixReady {
		g.Go(func() error {
			if err := checkFelixHealth(ctx, felixReadinessEp, "readiness"); err != nil {
				return fmt.Errorf("calico/node is not ready: felix is not ready: %+v", err)
			}
			return nil
		})
	}

	if bird {
		g.Go(func() error {
			if err := checkBIRDReady("4", thresholdTime); err != nil {
				return fmt.Errorf("calico/node is not ready: BIRD is not ready: %+v", err)
			}
			return nil
		})
	}

	if bird6 {
		g.Go(func() error {
			if err := checkBIRDReady("6", thresholdTime); err != nil {
				return fmt.Errorf("calico/node is not ready: BIRD6 is not ready: %+v", err)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
}

func checkServiceIsLive(services []string) error {
	for _, service := range services {
		err := checkService(service)
		if err != nil {
			return err
		}
	}

	return nil
}

func checkService(serviceName string) error {
	out, err := exec.Command("sv", "status", fmt.Sprintf("/etc/service/enabled/%s", serviceName)).Output()
	if err != nil {
		return err
	}

	var cmdOutput = string(out)
	if !strings.HasPrefix(cmdOutput, "run") {
		return fmt.Errorf(fmt.Sprintf("Service %s is not running. Output << %s >>", serviceName, strings.Trim(cmdOutput, "\n")))
	}

	return nil
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
func checkFelixHealth(ctx context.Context, endpoint, probeType string) error {
	c := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	req = req.WithContext(ctx)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("%s probe reporting %d", probeType, resp.StatusCode)
	}
	return nil
}
