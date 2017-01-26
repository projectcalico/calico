// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package calc

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

type StatsCollector struct {
	keyCountByHost       map[string]int
	numWorkloadEndpoints int
	numHostEndpoints     int

	lastUpdate StatsUpdate
	inSync     bool

	Callback func(StatsUpdate) error
}

type StatsUpdate struct {
	NumHosts             int
	NumWorkloadEndpoints int
	NumHostEndpoints     int
}

func (s StatsUpdate) String() string {
	return fmt.Sprintf("%#v", s)
}

func NewStatsCollector(callback func(StatsUpdate) error) *StatsCollector {
	return &StatsCollector{
		keyCountByHost: make(map[string]int),
		lastUpdate:     StatsUpdate{NumHosts: -1},
		Callback:       callback,
	}
}

func (s *StatsCollector) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.HostIPKey{}, s.OnUpdate)
	allUpdDispatcher.Register(model.WorkloadEndpointKey{}, s.OnUpdate)
	allUpdDispatcher.Register(model.HostEndpointKey{}, s.OnUpdate)
	allUpdDispatcher.Register(model.HostConfigKey{}, s.OnUpdate)
	allUpdDispatcher.RegisterStatusHandler(s.OnStatusUpdate)
}

func (s *StatsCollector) OnStatusUpdate(status api.SyncStatus) {
	log.WithField("status", status).Debug("Datastore status updated")
	if status == api.InSync {
		s.inSync = true
		s.sendUpdate()
	}
}

func (s *StatsCollector) OnUpdate(update api.Update) (filterOut bool) {
	hostname := ""
	var counter *int
	switch key := update.Key.(type) {
	case model.HostIPKey:
		hostname = key.Hostname
	case model.WorkloadEndpointKey:
		hostname = key.Hostname
		counter = &s.numWorkloadEndpoints
	case model.HostEndpointKey:
		hostname = key.Hostname
		counter = &s.numHostEndpoints
	case model.HostConfigKey:
		hostname = key.Hostname
	}
	if hostname == "" {
		log.WithField("key", update.Key).Warn("Failed to get hostname")
		return
	}
	if update.UpdateType == api.UpdateTypeKVNew {
		s.keyCountByHost[hostname] += 1
		log.WithFields(log.Fields{
			"key":      update.Key,
			"host":     hostname,
			"newCount": s.keyCountByHost[hostname],
		}).Debug("Host-specific key added")
		if counter != nil {
			*counter += 1
		}
	} else if update.UpdateType == api.UpdateTypeKVDeleted {
		s.keyCountByHost[hostname] -= 1
		log.WithFields(log.Fields{
			"key":      update.Key,
			"host":     hostname,
			"newCount": s.keyCountByHost[hostname],
		}).Debug("Host-specific key deleted")
		if s.keyCountByHost[hostname] <= 0 {
			log.WithField("host", hostname).Debug("Host no longer has any keys")
			delete(s.keyCountByHost, hostname)
		}
		if counter != nil {
			*counter -= 1
		}
	}
	s.sendUpdate()
	return
}

func (s *StatsCollector) sendUpdate() {
	log.Debug("Checking whether we should send an update")
	update := StatsUpdate{
		NumHosts:             len(s.keyCountByHost),
		NumHostEndpoints:     s.numHostEndpoints,
		NumWorkloadEndpoints: s.numWorkloadEndpoints,
	}
	if s.inSync && s.lastUpdate != update {
		if err := s.Callback(update); err != nil {
			log.WithError(err).Warn("Failed to report stats")
		} else {
			log.WithField("stats", update).Debug("Sent stats update")
			s.lastUpdate = update
		}
	}
}
