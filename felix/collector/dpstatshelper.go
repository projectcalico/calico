// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	bpfconntrack "github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/goldmane"
	"github.com/projectcalico/calico/felix/collector/local"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/lib/std/log"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	// Log dispatcher names
	FlowLogsGoldmaneReporterName = "goldmane"
	FlowLogsLocalReporterName    = "socket"
)

// New creates the required dataplane stats collector, reporters and aggregators.
// Returns a collector that statistics should be reported to.
func New(
	configParams *config.Config,
	lookupsCache *calc.LookupsCache,
	healthAggregator *health.HealthAggregator,
) Collector {
	statsCollector := newCollector(
		lookupsCache,
		&Config{
			AgeTimeout:            config.DefaultAgeTimeout,
			InitialReportingDelay: config.DefaultInitialReportingDelay,
			ExportingInterval:     config.DefaultExportingInterval,
			EnableServices:        true,
			EnableNetworkSets:     true,
			PolicyEvaluationMode:  configParams.FlowLogsPolicyEvaluationMode,
			FlowLogsFlushInterval: configParams.FlowLogsFlushInterval,
			IsBPFDataplane:        configParams.BPFEnabled,
			DisplayDebugTraceLogs: configParams.FlowLogsCollectorDebugTrace,
			BPFConntrackTimeouts:  bpfconntrack.GetTimeouts(configParams.BPFConntrackTimeouts),
		},
	)

	dispatchers := map[string]types.Reporter{}
	goldmaneAddr := configParams.FlowLogsGoldmaneServer
	if goldmaneAddr != "" {
		log.Infof("Creating Flow Logs GoldmaneReporter with address %v", goldmaneAddr)
		// Note: The configParams fields are named TyphaXXX, but this is only because the original use
		// for client certificates was for Typha. These certificates generally authenticate Felix as
		// a client, so are used for Goldmane as well.
		gd, err := goldmane.NewReporter(
			goldmaneAddr,
			configParams.TyphaCertFile,
			configParams.TyphaKeyFile,
			configParams.TyphaCAFile,
		)
		if err != nil {
			log.WithError(err).Fatalf("Failed to create Flow Logs GoldmaneReporter.")
		} else {
			dispatchers[FlowLogsGoldmaneReporterName] = gd
		}
	}
	if configParams.FlowLogsLocalReporterEnabled() {
		log.Infof("Creating local Flow Logs Reporter with address %v", local.SocketAddress)
		nd := local.NewReporter()
		dispatchers[FlowLogsLocalReporterName] = nd
	}

	if len(dispatchers) > 0 {
		log.Info("Creating Flow Logs Reporter")
		cw := flowlog.NewReporter(dispatchers, configParams.FlowLogsFlushInterval, healthAggregator)
		configureFlowAggregation(configParams, cw)
		statsCollector.RegisterMetricsReporter(cw)
	}

	return statsCollector
}

// configureFlowAggregation adds appropriate aggregators to the FlowLogReporter, depending on configuration.
func configureFlowAggregation(configParams *config.Config, fr *flowlog.FlowLogReporter) {
	// Set up aggregator for goldmane reporter.
	if configParams.FlowLogsGoldmaneServer != "" {
		log.Info("Creating goldmane Aggregator for allowed")
		gaa := defaultFlowAggregator(rules.RuleActionAllow, configParams.FlowLogsCollectorDebugTrace)
		log.Info("Adding Flow Logs Aggregator (allowed) for goldmane")
		fr.AddAggregator(gaa, []string{FlowLogsGoldmaneReporterName})
		log.Info("Creating goldmane Aggregator for denied")
		gad := defaultFlowAggregator(rules.RuleActionDeny, configParams.FlowLogsCollectorDebugTrace)
		log.Info("Adding Flow Logs Aggregator (denied) for goldmane")
		fr.AddAggregator(gad, []string{FlowLogsGoldmaneReporterName})
	}
	// Set up aggregator for local socket reporter.
	if configParams.FlowLogsLocalReporterEnabled() {
		log.Info("Creating local socket Aggregator for allowed")
		gaa := defaultFlowAggregator(rules.RuleActionAllow, configParams.FlowLogsCollectorDebugTrace)
		log.Info("Adding Flow Logs Aggregator (allowed) for local socket")
		fr.AddAggregator(gaa, []string{FlowLogsLocalReporterName})
		log.Info("Creating local socket Aggregator for denied")
		gad := defaultFlowAggregator(rules.RuleActionDeny, configParams.FlowLogsCollectorDebugTrace)
		log.Info("Adding Flow Logs Aggregator (denied) for local socket")
		fr.AddAggregator(gad, []string{FlowLogsLocalReporterName})
	}
}

func defaultFlowAggregator(forAction rules.RuleAction, traceEnabled bool) *flowlog.Aggregator {
	return flowlog.NewAggregator().
		DisplayDebugTraceLogs(traceEnabled).
		IncludeLabels(true).
		IncludePolicies(true).
		IncludeService(true).
		ForAction(forAction)
}
