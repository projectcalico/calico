// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package calc

import (
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/config"
	"github.com/projectcalico/felix/go/felix/dispatcher"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

const (
	tickInterval    = 10 * time.Millisecond
	leakyBucketSize = 10
)

var (
	dataplaneStatusGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_resync_state",
		Help: "Current datastore state.",
	})
	resyncsStarted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_resyncs_started",
		Help: "Current datastore state.",
	})
	statusToGaugeValue = map[api.SyncStatus]float64{
		api.WaitForDatastore: 1,
		api.ResyncInProgress: 2,
		api.InSync:           3,
	}
)

func init() {
	prometheus.MustRegister(dataplaneStatusGauge)
	prometheus.MustRegister(resyncsStarted)
}

type AsyncCalcGraph struct {
	Dispatcher       *dispatcher.Dispatcher
	inputEvents      chan interface{}
	outputEvents     chan<- interface{}
	eventBuffer      *EventBuffer
	beenInSync       bool
	needToSendInSync bool

	flushTicks       <-chan time.Time
	flushLeakyBucket int
	dirty            bool
}

func NewAsyncCalcGraph(conf *config.Config, outputEvents chan<- interface{}) *AsyncCalcGraph {
	eventBuffer := NewEventBuffer(conf)
	dispatcher := NewCalculationGraph(eventBuffer, conf.FelixHostname)
	g := &AsyncCalcGraph{
		inputEvents:  make(chan interface{}, 10),
		outputEvents: outputEvents,
		Dispatcher:   dispatcher,
		eventBuffer:  eventBuffer,
	}
	eventBuffer.Callback = g.onEvent
	return g
}

func (acg *AsyncCalcGraph) OnUpdates(updates []api.Update) {
	log.Debugf("Got %v updates; queueing", len(updates))
	acg.inputEvents <- updates
}

func (acg *AsyncCalcGraph) OnStatusUpdated(status api.SyncStatus) {
	log.Debugf("Status updated: %v; queueing", status)
	acg.inputEvents <- status
	dataplaneStatusGauge.Set(statusToGaugeValue[status])
	if status == api.ResyncInProgress {
		resyncsStarted.Inc()
	}
}

func (acg *AsyncCalcGraph) loop() {
	log.Info("AsyncCalcGraph running")
	for {
		select {
		case update := <-acg.inputEvents:
			switch update := update.(type) {
			case []api.Update:
				// Update; send it to the dispatcher.
				log.Debug("Pulled []KVPair off channel")
				acg.Dispatcher.OnUpdates(update)
			case api.SyncStatus:
				// Sync status changed, check if we're now in-sync.
				log.WithField("status", update).Debug(
					"Pulled status update off channel")
				acg.Dispatcher.OnStatusUpdated(update)
				if update == api.InSync && !acg.beenInSync {
					log.Info("First time we've been in sync")
					acg.beenInSync = true
					acg.needToSendInSync = true
					acg.dirty = true
					if acg.flushLeakyBucket == 0 {
						// Force a flush.
						acg.flushLeakyBucket++
					}
				}
			default:
				log.Fatalf("Unexpected update: %#v", update)
			}
			acg.dirty = true
		case <-acg.flushTicks:
			// Timer tick: fill up the leaky bucket.
			if acg.flushLeakyBucket < leakyBucketSize {
				acg.flushLeakyBucket++
			}
		}
		acg.maybeFlush()
	}
}

// maybeFlush flushes the event buffer if: we know it's dirty and we're not throttled.
func (acg *AsyncCalcGraph) maybeFlush() {
	if !acg.dirty {
		return
	}
	if acg.flushLeakyBucket > 0 {
		log.Debug("Not throttled: flushing event buffer")
		acg.flushLeakyBucket--
		acg.eventBuffer.Flush()
		if acg.needToSendInSync {
			log.Info("First flush after becoming in sync, sending InSync message.")
			acg.onEvent(&proto.InSync{})
			acg.needToSendInSync = false
		}
		acg.dirty = false
	} else {
		log.Debug("Throttled: not flushing event buffer")
	}
}

func (acg *AsyncCalcGraph) onEvent(event interface{}) {
	log.Debug("Sending output event on channel")
	acg.outputEvents <- event
	log.Debug("Sent output event on channel")
}

func (acg *AsyncCalcGraph) Start() {
	log.Info("Starting AsyncCalcGraph")
	acg.flushTicks = time.Tick(tickInterval)
	go acg.loop()
}
