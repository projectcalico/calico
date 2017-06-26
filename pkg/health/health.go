// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/typha/pkg/set"
)

// Any kind of value that can be used as a map key and is unique across multiple packages.  For
// example, "type myHealthSource string".
type HealthSource interface{}

type HealthIndicator struct {
	// The source of this health indicator.
	Source HealthSource

	// How long the indicator is valid for.  In other words, if it continues operating normally,
	// the source expects to refresh this indicator before this timeout.
	Timeout time.Duration
}

// For a component that provides health indications, return the sources that it provides to indicate
// readiness, and those that it provides to indicate liveness.
type HealthProvider interface {
	ReadySources() []HealthSource
	LiveSources() []HealthSource
}

func MonitorHealth(
	ready *bool,
	live *bool,
	mutex *sync.Mutex,
	neededForReady set.Set,
	neededForLive set.Set,
	c <-chan HealthIndicator,
) {
	currentHealth := set.New()
	timer := map[HealthSource]*time.Timer{}
	timeoutC := make(chan HealthSource)

	for {
		select {
		case indicator, ok := <-c:
			if !ok {
				log.Warningf("Health channel closed")
				mutex.Lock()
				*ready = false
				*live = false
				mutex.Unlock()
				return
			}
			log.WithField("source", indicator.Source).Debug("Health indicator current")
			if timer[indicator.Source] != nil {
				timer[indicator.Source].Stop()
			}
			if indicator.Timeout > 0 {
				currentHealth.Add(indicator.Source)
				timer[indicator.Source] = time.AfterFunc(indicator.Timeout, func() {
					timeoutC <- indicator.Source
				})
			} else {
				// Shortcut immediate timeout.  A health source can use an
				// indication with zero timeout to cancel a previous indication that
				// might otherwise take a long time to expire.
				log.WithField("source", indicator.Source).Debug("Health indicator cancelled")
				currentHealth.Discard(indicator.Source)
			}
		case source := <-timeoutC:
			log.WithField("source", source).Debug("Health indicator expired")
			currentHealth.Discard(source)
		}
		mutex.Lock()
		*ready = currentHealth.ContainsAll(neededForReady)
		*live = currentHealth.ContainsAll(neededForLive)
		log.WithFields(log.Fields{
			"ready": *ready,
			"live":  *live,
		}).Debug("Health now")
		mutex.Unlock()
	}
}

func ServeHealth(port int, neededForReady set.Set, neededForLive set.Set, c <-chan HealthIndicator) {
	ready := false
	live := false
	mutex := &sync.Mutex{}

	go MonitorHealth(&ready, &live, mutex, neededForReady, neededForLive, c)

	log.WithField("port", port).Info("Starting health endpoints")
	http.HandleFunc("/readiness", func(rsp http.ResponseWriter, req *http.Request) {
		log.Debug("GET /readiness")
		status := 500
		mutex.Lock()
		if ready {
			log.Debug("Typha is ready")
			status = 200
		}
		mutex.Unlock()
		rsp.WriteHeader(status)
	})
	http.HandleFunc("/liveness", func(rsp http.ResponseWriter, req *http.Request) {
		log.Debug("GET /liveness")
		status := 500
		mutex.Lock()
		if live {
			log.Debug("Typha is live")
			status = 200
		}
		mutex.Unlock()
		rsp.WriteHeader(status)
	})
	for {
		err := http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
		log.WithError(err).Error(
			"Readiness endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}
