// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"time"

	"github.com/projectcalico/felix/bpf/conntrack"
	"github.com/projectcalico/felix/jitter"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
)

type conntrackManager struct {
	ctMap   bpf.Map
	started bool
}

func newBPFConntrackManager() *conntrackManager {
	return &conntrackManager{
		ctMap: conntrack.Map(),
	}
}

func (m *conntrackManager) OnUpdate(msg interface{}) {
}

func (m *conntrackManager) CompleteDeferredWork() error {
	err := m.ctMap.EnsureExists()
	if err != nil {
		log.WithError(err).Panic("Failed to create Conntrack map")
	}

	if !m.started {
		m.CleanUpConntrack()
		log.Info("Starting conntrack cleanup goroutine.")
		go m.PeriodicallyCleanUp()
		m.started = true
	}

	return nil
}

func (m *conntrackManager) PeriodicallyCleanUp() {
	log.Info("Conntrack cleanup goroutine running...")
	ticker := jitter.NewTicker(10*time.Second, 100*time.Millisecond)
	for range ticker.C {
		log.Debug("Conntrack cleanup timer popped")
		m.CleanUpConntrack()
	}
}

func (m *conntrackManager) CleanUpConntrack() {
	log.Debug("Starting conntrack cleanup.")
	err := m.ctMap.Iter(func(rawK, rawV []byte) {
		var k conntrack.Key
		var v conntrack.Entry
		copy(k[:], rawK)
		copy(v[:], rawV)

		log.WithFields(log.Fields{
			"key":   k,
			"value": v,
		}).Debug("Examining conntrack entry.")
	})
	if err != nil {
		log.WithError(err).Error("Conntrack cleanup failed.")
	} else {
		log.Debug("Conntrack cleanup complete.")
	}
}
