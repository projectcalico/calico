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
	"github.com/projectcalico/libcalico-go/lib/set"
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

type HealthState struct {
	// Whether we are overall 'ready'.
	ready bool

	// Whether we are overall 'live'.
	live bool

	// Mutex used to protect against concurrently reading and writing those attributes.
	mutex *sync.Mutex
}

func (state *HealthState) Ready() bool {
	state.mutex.Lock()
	defer state.mutex.Unlock()
	return state.ready
}

func (state *HealthState) Live() bool {
	state.mutex.Lock()
	defer state.mutex.Unlock()
	return state.live
}

func NewHealthState() *HealthState {
	// Start as 'live' but not 'ready'.
	return &HealthState{ready: false, live: true, mutex: &sync.Mutex{}}
}

func MonitorHealth(
	state *HealthState,
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
				state.mutex.Lock()
				state.ready = false
				state.live = false
				state.mutex.Unlock()
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
		state.mutex.Lock()
		state.ready = currentHealth.ContainsAll(neededForReady)
		state.live = currentHealth.ContainsAll(neededForLive)
		log.WithFields(log.Fields{
			"ready": state.ready,
			"live":  state.live,
		}).Debug("Health now")
		state.mutex.Unlock()
	}
}

const (
	// The HTTP status that we use for 'ready' or 'live'.  204 means "No Content: The server
	// successfully processed the request and is not returning any content."  (Kubernetes
	// interpets any 200<=status<400 as 'good'.)
	STATUS_GOOD = 204

	// The HTTP status that we use for 'not ready' or 'not live'.  503 means "Service
	// Unavailable: The server is currently unavailable (because it is overloaded or down for
	// maintenance). Generally, this is a temporary state."  (Kubernetes interpets any
	// status>=400 as 'bad'.)
	STATUS_BAD = 503
)

func ServeHealth(port int, neededForReady set.Set, neededForLive set.Set, c <-chan HealthIndicator) {

	state := NewHealthState()

	go MonitorHealth(state, neededForReady, neededForLive, c)

	log.WithField("port", port).Info("Starting health endpoints")
	http.HandleFunc("/readiness", func(rsp http.ResponseWriter, req *http.Request) {
		log.Debug("GET /readiness")
		status := STATUS_BAD
		if state.Ready() {
			log.Debug("Felix is ready")
			status = STATUS_GOOD
		}
		rsp.WriteHeader(status)
	})
	http.HandleFunc("/liveness", func(rsp http.ResponseWriter, req *http.Request) {
		log.Debug("GET /liveness")
		status := STATUS_BAD
		if state.Live() {
			log.Debug("Felix is live")
			status = STATUS_GOOD
		}
		rsp.WriteHeader(status)
	})
	for {
		err := http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
		log.WithError(err).Error(
			"Readiness endpoint failed, trying to restart it...")
		time.Sleep(1 * time.Second)
	}
}
