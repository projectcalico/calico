// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.
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

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
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
	summaryUpdateTime = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_calc_graph_update_time_seconds",
		Help: "Seconds to update calculation graph for each datastore OnUpdate call.",
	})
)

func init() {
	prometheus.MustRegister(dataplaneStatusGauge)
	prometheus.MustRegister(resyncsStarted)
	prometheus.MustRegister(countUpdatesProcessed)
	prometheus.MustRegister(countOutputEvents)
	prometheus.MustRegister(summaryUpdateTime)
}

type AsyncCalcGraph struct {
	*CalcGraph
	inputEvents      chan interface{}
	outputChannels   []chan<- interface{}
	eventSequencer   *EventSequencer
	beenInSync       bool
	needToSendInSync bool
	syncStatusNow    api.SyncStatus
	healthAggregator *health.HealthAggregator

	flushTicks       <-chan time.Time
	healthTicks      <-chan time.Time
	flushLeakyBucket int
	dirty            bool

	debugHangC <-chan time.Time
}

const (
	healthName     = "async_calc_graph"
	healthInterval = 10 * time.Second
)

func NewAsyncCalcGraph(
	conf *config.Config,
	outputChannels []chan<- interface{},
	healthAggregator *health.HealthAggregator,
	configChangedRestartCallback func(),
) *AsyncCalcGraph {
	eventSequencer := NewEventSequencer(conf)
	calcGraph := NewCalculationGraph(eventSequencer, conf, configChangedRestartCallback)
	g := &AsyncCalcGraph{
		CalcGraph:        calcGraph,
		inputEvents:      make(chan interface{}, 10),
		outputChannels:   outputChannels,
		eventSequencer:   eventSequencer,
		healthAggregator: healthAggregator,
	}
	if conf.DebugSimulateCalcGraphHangAfter != 0 {
		log.WithField("delay", conf.DebugSimulateCalcGraphHangAfter).Warn(
			"Simulating a calculation graph hang.")
		g.debugHangC = time.After(conf.DebugSimulateCalcGraphHangAfter)
	}
	eventSequencer.Callback = g.onEvent
	if healthAggregator != nil {
		healthAggregator.RegisterReporter(healthName, &health.HealthReport{Live: true, Ready: true}, healthInterval*2)
	}
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
	acg.reportHealth()
	for {
		select {
		case update := <-acg.inputEvents:
			switch update := update.(type) {
			case []api.Update:
				// Update; send it to the dispatcher.
				log.Debug("Pulled []KVPair off channel")
				for i, upd := range update {
					// Send the updates individually so that we can report live in between
					// each update.  (The dispatcher sends individual updates anyway so this makes
					// no difference.)
					updStartTime := time.Now()
					acg.AllUpdDispatcher.OnUpdates(update[i : i+1])
					summaryUpdateTime.Observe(time.Since(updStartTime).Seconds())
					// Record stats for the number of messages processed.
					typeName := reflect.TypeOf(upd.Key).Name()
					count := countUpdatesProcessed.WithLabelValues(typeName)
					count.Inc()
					acg.reportHealth()
				}
			case api.SyncStatus:
				// Sync status changed, check if we're now in-sync.
				log.WithField("status", update).Debug(
					"Pulled status update off channel")
				acg.syncStatusNow = update
				acg.AllUpdDispatcher.OnStatusUpdated(update)
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
				acg.reportHealth()
			default:
				log.Panicf("Unexpected update: %#v", update)
			}
			acg.dirty = true
		case <-acg.flushTicks:
			// Timer tick: fill up the leaky bucket.
			if acg.flushLeakyBucket < leakyBucketSize {
				acg.flushLeakyBucket++
			}
		case <-acg.healthTicks:
			acg.reportHealth()
		case <-acg.debugHangC:
			log.Warning("Debug hang simulation timer popped, hanging the calculation graph!!")
			time.Sleep(1 * time.Hour)
			log.Panic("Woke up after 1 hour, something's probably wrong with the test.")
		}
		acg.maybeFlush()
	}
}

func (acg *AsyncCalcGraph) reportHealth() {
	if acg.healthAggregator != nil {
		acg.healthAggregator.Report(healthName, &health.HealthReport{
			Live:  true,
			Ready: acg.syncStatusNow == api.InSync,
		})
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
		flushStart := time.Now()
		acg.eventSequencer.Flush()
		flushDuration := time.Since(flushStart)
		if flushDuration > time.Second {
			log.WithField("time", flushDuration).Info("Flush took over 1s.")
		}
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
	log.Debug("Sending output event on channel(s)")
	healthTickCount := 0
	startTime := time.Now()
channelLoop:
	for _, c := range acg.outputChannels {
		for {
			select {
			case c <- event:
				continue channelLoop
			case <-acg.healthTicks:
				acg.reportHealth()
				healthTickCount++
				if healthTickCount > 1 {
					log.WithField("time", startTime).Info(
						"Flushing updates to the dataplane is taking a long time")
				}
			}
		}
	}
	countOutputEvents.Inc()
	log.Debug("Sent output event on channel(s)")
}

func (acg *AsyncCalcGraph) Start() {
	log.Info("Starting AsyncCalcGraph")
	acg.flushTicks = time.NewTicker(tickInterval).C
	acg.healthTicks = time.NewTicker(healthInterval).C
	go acg.loop()
}
