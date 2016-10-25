// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/dispatcher"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

type StatsCollector struct {
	keyCountByHost map[string]int
	lastNumHosts   int
	NumHostsChan   chan int
	inSync         bool
}

func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		keyCountByHost: make(map[string]int),
		NumHostsChan:   make(chan int, 1),
		lastNumHosts:   -1,
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

func (s *StatsCollector) OnUpdate(update model.Update) (filterOut bool) {
	hostname := ""
	switch key := update.Key.(type) {
	case model.HostIPKey:
		hostname = key.Hostname
	case model.WorkloadEndpointKey:
		hostname = key.Hostname
	case model.HostEndpointKey:
		hostname = key.Hostname
	case model.HostConfigKey:
		hostname = key.Hostname
	}
	if hostname == "" {
		log.WithField("key", update.Key).Warn("Failed to get hostname")
		return
	}
	if update.UpdateType == model.UpdateTypeKVNew {
		s.keyCountByHost[hostname] += 1
		log.WithFields(log.Fields{
			"key":      update.Key,
			"host":     hostname,
			"newCount": s.keyCountByHost[hostname],
		}).Debug("Host-specific key added")
	} else if update.UpdateType == model.UpdateTypeKVDeleted {
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
	}
	s.sendUpdate()
	return
}

func (s *StatsCollector) sendUpdate() {
	log.Debug("Checking whether we should send an update")
	numHosts := len(s.keyCountByHost)
	if s.inSync && s.lastNumHosts != numHosts {
		log.WithField("numHosts", numHosts).Debug("Number of hosts in cluster changed")
		select {
		case s.NumHostsChan <- numHosts:
			log.WithField("numHosts", numHosts).Debug("Sent host number update")
			s.lastNumHosts = numHosts
		default:
			// Stats are best-effort.  If no-one is listening, just
			// ignore.
			log.Debug("Failed to send number of hosts, ignoring")
		}
	}
}
