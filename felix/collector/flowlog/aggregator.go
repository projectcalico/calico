// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package flowlog

import (
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/types/metric"
	logutil "github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/rules"
)

// AggregationKind determines the flow log key
type AggregationKind int

const (
	// FlowDefault is based on purely duration.
	FlowDefault AggregationKind = iota
	// FlowSourcePort accumulates tuples with everything same but the source port
	FlowSourcePort
	// FlowPrefixName accumulates tuples with everything same but the prefix name
	FlowPrefixName
	// FlowNoDestPorts accumulates tuples with everything same but the prefix name, source ports and destination ports
	FlowNoDestPorts
)

const (
	MaxAggregationLevel = FlowNoDestPorts
	MinAggregationLevel = FlowDefault
)

var gaugeFlowStoreCacheSizeLength = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "felix_collector_allowed_flowlog_aggregator_store",
	Help: "Total number of FlowEntries with a given action currently residing in the FlowStore cache used by the aggregator.",
},
	[]string{"action"})

func init() {
	prometheus.MustRegister(gaugeFlowStoreCacheSizeLength)
}

// Aggregator is responsible for creating, aggregating, and storing
// aggregated flow logs until the flow logs are exported.
type Aggregator struct {
	current               AggregationKind
	flowStore             map[FlowMeta]*flowEntry
	flMutex               sync.RWMutex
	includeLabels         bool
	includePolicies       bool
	includeService        bool
	aggregationStartTime  time.Time
	handledAction         rules.RuleAction
	displayDebugTraceLogs bool
}

type flowEntry struct {
	spec         *FlowSpec
	aggregation  AggregationKind
	shouldExport bool
}

// NewAggregator constructs an Aggregator
func NewAggregator() *Aggregator {
	return &Aggregator{
		current:              FlowPrefixName,
		flowStore:            make(map[FlowMeta]*flowEntry),
		flMutex:              sync.RWMutex{},
		aggregationStartTime: time.Now(),
	}
}

func (a *Aggregator) DisplayDebugTraceLogs(b bool) *Aggregator {
	a.displayDebugTraceLogs = b
	return a
}

func (a *Aggregator) IncludeLabels(b bool) *Aggregator {
	a.includeLabels = b
	return a
}

func (a *Aggregator) IncludePolicies(b bool) *Aggregator {
	a.includePolicies = b
	return a
}

func (a *Aggregator) IncludeService(b bool) *Aggregator {
	a.includeService = b
	return a
}

func (a *Aggregator) ForAction(ra rules.RuleAction) *Aggregator {
	a.handledAction = ra
	return a
}

// FeedUpdate constructs and aggregates flow logs from metric Updates.
func (a *Aggregator) FeedUpdate(mu *metric.Update) error {
	// Filter out any action that we aren't configured to handle. Use the hasDenyRule flag rather than the actual
	// verdict rule to determine if we treat this as a deny or an allow from an aggregation perspective. This allows
	// staged denies to be aggregated at the aggregation-level-for-denied even when the final verdict is still allow.
	switch {
	case a.handledAction == rules.RuleActionDeny && !mu.HasDenyRule:
		logutil.Tracef(a.displayDebugTraceLogs, "Update %v not handled for deny-aggregator - no deny rules found", *mu)
		return nil
	case a.handledAction == rules.RuleActionAllow && mu.HasDenyRule:
		logutil.Tracef(a.displayDebugTraceLogs, "Update %v not handled for allow-aggregator - deny rules found", *mu)
		return nil
	}

	flowMeta, err := NewFlowMeta(*mu, a.current, a.includeService)
	if err != nil {
		return err
	}

	a.flMutex.Lock()
	defer a.flMutex.Unlock()
	defer a.reportFlowLogStoreMetrics()

	logutil.Tracef(a.displayDebugTraceLogs, "Flow Log Aggregator got Metric Update: %+v", *mu)

	fl, ok := a.flowStore[flowMeta]
	if !ok {
		logutil.Tracef(a.displayDebugTraceLogs, "flowMeta %+v not found, creating new flowspec for metric update %+v", flowMeta, *mu)
		spec := NewFlowSpec(mu, a.displayDebugTraceLogs)

		newEntry := &flowEntry{
			spec:         spec,
			aggregation:  a.current,
			shouldExport: true,
		}

		a.flowStore[flowMeta] = newEntry
	} else {
		logutil.Tracef(a.displayDebugTraceLogs, "flowMeta %+v found, aggregating flowspec with metric update %+v", flowMeta, *mu)
		fl.spec.AggregateMetricUpdate(mu)
		fl.shouldExport = true
		a.flowStore[flowMeta] = fl
	}

	return nil
}

// GetAndCalibrate returns all aggregated flow logs, as a list of pointers, since the last time a GetAndCalibrate
// was called. Calling GetAndCalibrate will also clear the stored flow logs once the flow logs are returned.
// Clearing the stored flow logs may imply resetting the statistics for a flow log identified using
// its FlowMeta or flushing out the entry of FlowMeta altogether. If no active flow count are recorded
// a flush operation will be applied instead of a reset. In addition to this, a new level of aggregation will
// be set. By changing aggregation levels, all previous entries with a different level will be marked accordingly as not
// be exported at the next call for GetAndCalibrate().They will be kept in the store flow in order to provide an
// accurate number for numFlowCounts.
func (a *Aggregator) GetAndCalibrate() []*FlowLog {
	log.Debug("Get from flow log aggregator")
	aggregationEndTime := time.Now()

	a.flMutex.Lock()
	defer a.flMutex.Unlock()

	resp := make([]*FlowLog, 0, len(a.flowStore))

	for flowMeta, flowEntry := range a.flowStore {
		if flowEntry.shouldExport {
			log.Debug("Converting to flowlogs")
			flowLogs := flowEntry.spec.ToFlowLogs(flowMeta, a.aggregationStartTime, aggregationEndTime, a.includeLabels, a.includePolicies)
			resp = append(resp, flowLogs...)
		}
		a.calibrateFlowStore(flowMeta, a.current)
	}

	a.aggregationStartTime = aggregationEndTime
	return resp
}

func (a *Aggregator) calibrateFlowStore(flowMeta FlowMeta, newLevel AggregationKind) {
	defer a.reportFlowLogStoreMetrics()
	entry, ok := a.flowStore[flowMeta]
	if !ok {
		// This should never happen as calibrateFlowStore is called right after we
		// generate flow logs using the entry.
		log.Warnf("Missing entry for flowMeta %+v", flowMeta)
		return
	}

	// Some specs might contain process names with no active flows. We garbage collect
	// them here so that if there are no other processes tracked, the flow meta can
	// be removed.
	remainingActiveFlowsCount := entry.spec.GarbageCollect()

	// discontinue tracking the stats associated with the
	// flow meta if no more associated 5-tuples exist.
	if remainingActiveFlowsCount == 0 {
		logutil.Tracef(a.displayDebugTraceLogs, "Deleting %v", flowMeta)
		delete(a.flowStore, flowMeta)

		return
	}

	if !entry.shouldExport {
		return
	}

	if entry.aggregation != newLevel {
		log.Debugf("Marking entry as not exportable")
		entry.shouldExport = false
	}

	logutil.Tracef(a.displayDebugTraceLogs, "Resetting %v", flowMeta)
	// reset flow stats for the next interval
	entry.spec.Reset()
	a.flowStore[flowMeta] = &flowEntry{
		spec:         entry.spec,
		aggregation:  entry.aggregation,
		shouldExport: entry.shouldExport,
	}
}

// reportFlowLogStoreMetrics reporting of current FlowStore cache metrics to Prometheus
func (a *Aggregator) reportFlowLogStoreMetrics() {
	gaugeFlowStoreCacheSizeLength.WithLabelValues(strings.ToLower(a.handledAction.String())).Set(float64(len(a.flowStore)))
}
