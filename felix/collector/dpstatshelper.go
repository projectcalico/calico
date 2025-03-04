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
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/goldmane"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	// Log dispatcher names
	FlowLogsGoldmaneReporterName = "goldmane"
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
		},
	)

	dispatchers := map[string]types.Reporter{}
	goldmaneAddr := configParams.FlowLogsGoldmaneServer
	if goldmaneAddr != "" {
		log.Infof("Creating Flow Logs GoldmaneReporter with address %v", goldmaneAddr)
		gd := goldmane.NewReporter(goldmaneAddr)
		dispatchers[FlowLogsGoldmaneReporterName] = gd
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
	if configParams.FlowLogsGoldmaneServer != "" {
		log.Info("Creating golemane Aggregator for allowed")
		gaa := flowlog.NewAggregator().
			DisplayDebugTraceLogs(configParams.FlowLogsCollectorDebugTrace).
			IncludeLabels(true).
			IncludePolicies(true).
			IncludeService(true).
			ForAction(rules.RuleActionAllow)
		log.Info("Adding Flow Logs Aggregator (allowed) for goldmane")
		fr.AddAggregator(gaa, []string{FlowLogsGoldmaneReporterName})
		log.Info("Creating goldmane Aggregator for denied")
		gad := flowlog.NewAggregator().
			DisplayDebugTraceLogs(configParams.FlowLogsCollectorDebugTrace).
			IncludeLabels(true).
			IncludePolicies(true).
			IncludeService(true).
			ForAction(rules.RuleActionDeny)
		log.Info("Adding Flow Logs Aggregator (denied) for goldmane")
		fr.AddAggregator(gad, []string{FlowLogsGoldmaneReporterName})
	}
}
