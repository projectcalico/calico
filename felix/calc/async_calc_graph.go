// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
)

const (
	tickInterval    = 10 * time.Millisecond
	leakyBucketSize = 10

	eventAgeThreshold       = 60 * time.Second
	perResourceAgeThreshold = 120 * time.Second
)


type DataFreshnessState int

const (
	DataFresh        DataFreshnessState = 0
	DataReconnecting DataFreshnessState = 1
	DataStale        DataFreshnessState = 2
	DataUnknown      DataFreshnessState = 3
)

var (
	dataplaneStatusGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_resync_state",
		Help: "Current datastore state.",
	})
	dataFreshnessGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_datastore_freshness_state",
		Help: "Freshness of datastore view: 0=Fresh, 1=Reconnecting, 2=Stale, 3=Unknown",
	})
	watchLastEventAge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "felix_watch_last_event_age_seconds",
		Help: "Seconds since last watch event received from datastore",
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
	prometheus.MustRegister(dataFreshnessGauge)
	prometheus.MustRegister(watchLastEventAge)
	prometheus.MustRegister(resyncsStarted)
	prometheus.MustRegister(countUpdatesProcessed)
	prometheus.MustRegister(countOutputEvents)
	prometheus.MustRegister(summaryUpdateTime)
}

type AsyncCalcGraph struct {
	CalcGraph        *CalcGraph
	inputEvents      chan interface{}
	outputChannels   []chan<- interface{}
	eventSequencer   *EventSequencer
	beenInSync       bool
	needToSendInSync bool
	syncStatusNow    api.SyncStatus

	dataFreshnessState DataFreshnessState
	lastEventTime      time.Time
	lastFreshnessCheck time.Time

	healthAggregator *health.HealthAggregator

	flushTicks       <-chan time.Time
	healthTicks      <-chan time.Time
	flushLeakyBucket int
	dirty            bool

	debugHangC <-chan time.Time
}

const (
	healthName     = "CalculationGraph"
	healthInterval = 10 * time.Second
	healthTimeout  = 30 * time.Second
)

func NewAsyncCalcGraph(
	conf *config.Config,
	outputChannels []chan<- interface{},
	healthAggregator *health.HealthAggregator,
	lookupCache *LookupsCache,
) *AsyncCalcGraph {
	eventSequencer := NewEventSequencer(conf)
	g := &AsyncCalcGraph{
		inputEvents:        make(chan interface{}, 10),
		outputChannels:     outputChannels,
		eventSequencer:     eventSequencer,
		healthAggregator:   healthAggregator,
		dataFreshnessState: DataUnknown,
		lastEventTime:      time.Now(),
	}
	g.CalcGraph = NewCalculationGraph(eventSequencer, lookupCache, conf, g.reportHealth)
	if conf.DebugSimulateCalcGraphHangAfter != 0 {
		log.WithField("delay", conf.DebugSimulateCalcGraphHangAfter).Warn(
			"Simulating a calculation graph hang.")
		g.debugHangC = time.After(conf.DebugSimulateCalcGraphHangAfter)
	}
	eventSequencer.Callback = g.onEvent
	if healthAggregator != nil {
		healthAggregator.RegisterReporter(healthName, &health.HealthReport{Live: true, Ready: true}, healthTimeout)
	}

	dataFreshnessGauge.Set(float64(DataUnknown))
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
				log.Debug("Pulled []KVPair off channel")
				acg.lastEventTime = time.Now()
				acg.updateFreshnessState(DataFresh)

				for i, upd := range update {
					// Send the updates individually so that we can report live in between
					// each update.  (The dispatcher sends individual updates anyway so this makes
					// no difference.)
					updStartTime := time.Now()
					acg.CalcGraph.OnUpdates(update[i : i+1])
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
				acg.CalcGraph.OnStatusUpdated(update)

				if update == api.InSync {
					if !acg.beenInSync {
						log.Info("First time we've been in sync")
						acg.beenInSync = true
					} else {
						log.Info("Returned to InSync state after reconnection")
					}
					acg.needToSendInSync = true
					acg.dirty = true
					if acg.flushLeakyBucket == 0 {
						// Force a flush.
						acg.flushLeakyBucket++
					}
					acg.updateFreshnessState(DataFresh)
				} else if update == api.ResyncInProgress {
					// Explicitly track reconnection state
					log.Info("Datastore resync in progress")
					acg.updateFreshnessState(DataReconnecting)
				} else if update == api.WaitForDatastore {
					log.Info("Waiting for datastore connection")
					acg.updateFreshnessState(DataUnknown)
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
	acg.checkDataFreshness()

	eventAge := time.Since(acg.lastEventTime).Seconds()
	watchLastEventAge.Set(eventAge)
	dataFreshnessGauge.Set(float64(acg.dataFreshnessState))

	if acg.healthAggregator != nil {
		isReady := acg.syncStatusNow == api.InSync && acg.dataFreshnessState == DataFresh
		acg.healthAggregator.Report(healthName, &health.HealthReport{
			Live:  true,
			Ready: isReady,
		})
	}
}

func (acg *AsyncCalcGraph) updateFreshnessState(newState DataFreshnessState) {
	if acg.dataFreshnessState != newState {
		log.WithFields(log.Fields{
			"oldState": acg.dataFreshnessState,
			"newState": newState,
		}).Info("Datastore freshness state changed")
		acg.dataFreshnessState = newState
		dataFreshnessGauge.Set(float64(newState))
	}
}

func (acg *AsyncCalcGraph) checkDataFreshness() {
	now := time.Now()

	if now.Sub(acg.lastFreshnessCheck) < 10*time.Second {
		return
	}
	acg.lastFreshnessCheck = now

	if acg.syncStatusNow == api.InSync && acg.dataFreshnessState == DataFresh {
		eventAge := now.Sub(acg.lastEventTime)
		if eventAge > eventAgeThreshold {
			log.WithFields(log.Fields{
				"eventAge": eventAge,
				"threshold": eventAgeThreshold,
			}).Warn("No watch events received recently, data may be stale")
			acg.updateFreshnessState(DataStale)
		}
	}
}

func (acg *AsyncCalcGraph) SyncFailed(err error) {
	log.WithError(err).Warn("Datastore sync failure reported")
	acg.updateFreshnessState(DataReconnecting)

	if acg.beenInSync {
		log.Info("Previously in sync, will resync when connection restored")
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
		acg.CalcGraph.Flush()
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
