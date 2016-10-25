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
	"github.com/projectcalico/felix/go/felix/set"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

type StatsCollector struct {
	hosts        set.Set
	lastNumHosts int
	NumHostsChan chan int
	inSync       bool
}

func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		hosts:        set.New(),
		NumHostsChan: make(chan int, 1),
		lastNumHosts: -1,
	}
}

func (s *StatsCollector) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.HostIPKey{}, s.OnUpdate)
	allUpdDispatcher.RegisterStatusHandler(s.OnStatusUpdate)
}

func (s *StatsCollector) OnStatusUpdate(status api.SyncStatus) {
	log.WithField("status", status).Debug("Datastore status updated")
	if status == api.InSync {
		s.inSync = true
		s.sendUpdate()
	}
}

func (s *StatsCollector) OnUpdate(update model.KVPair) (filterOut bool) {
	switch key := update.Key.(type) {
	case model.HostIPKey:
		if update.Value == nil {
			log.WithField("hostname", key.Hostname).Debug("Host deleted")
			s.hosts.Discard(key.Hostname)
		} else {
			log.WithField("hostname", key.Hostname).Debug("Host updated")
			s.hosts.Add(key.Hostname)
		}
	}
	s.sendUpdate()
	return
}

func (s *StatsCollector) sendUpdate() {
	log.Debug("Sending update")
	numHosts := s.hosts.Len()
	if s.inSync && s.lastNumHosts != numHosts {
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
