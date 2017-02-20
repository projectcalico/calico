// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	"reflect"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
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
	countUpdatesProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_calc_graph_updates_processed",
		Help: "Number of datastore updates processed by the calculation graph.",
	}, []string{"type"})
	countOutputEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_calc_graph_output_events",
		Help: "Number of events emitted by the calculation graph.",
	})
	histUpdateTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "felix_calc_graph_update_time_seconds",
		Help: "Seconds to update calculation graph for each datastore OnUpdate call.",
		Buckets: []float64{
			0.001, 0.010, 0.100, 1.0,
		},
	})
)

func init() {
	prometheus.MustRegister(dataplaneStatusGauge)
	prometheus.MustRegister(resyncsStarted)
	prometheus.MustRegister(countUpdatesProcessed)
	prometheus.MustRegister(countOutputEvents)
	prometheus.MustRegister(histUpdateTime)
}

type AsyncCalcGraph struct {
	Dispatcher       *dispatcher.Dispatcher
	inputEvents      chan interface{}
	outputEvents     chan<- interface{}
	eventBuffer      *EventSequencer
	beenInSync       bool
	needToSendInSync bool

	flushTicks       <-chan time.Time
	flushLeakyBucket int
	dirty            bool
}

func NewAsyncCalcGraph(conf *config.Config, outputEvents chan<- interface{}) *AsyncCalcGraph {
	eventBuffer := NewEventBuffer(conf)
	disp := NewCalculationGraph(eventBuffer, conf.FelixHostname)
	g := &AsyncCalcGraph{
		inputEvents:  make(chan interface{}, 10),
		outputEvents: outputEvents,
		Dispatcher:   disp,
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
				updStartTime := time.Now()
				acg.Dispatcher.OnUpdates(update)
				updEndTime := time.Now()
				if updEndTime.After(updStartTime) {
					// Avoid recording a negative delta in case the clock jumps.
					histUpdateTime.Observe(updEndTime.Sub(updStartTime).Seconds())
				}
				// Record stats for the number of messages processed.
				for _, upd := range update {
					typeName := reflect.TypeOf(upd.Key).Name()
					count := countUpdatesProcessed.WithLabelValues(typeName)
					count.Inc()
				}
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
	countOutputEvents.Inc()
	log.Debug("Sent output event on channel")
}

func (acg *AsyncCalcGraph) Start() {
	log.Info("Starting AsyncCalcGraph")
	acg.flushTicks = time.Tick(tickInterval)
	go acg.loop()
}
