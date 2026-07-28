// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Package metrics holds the collectors shared by the Calico webhooks.
package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "calico_webhooks"

var DecisionsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "tier_decisions_total",
		Help:      "Tier authorization decisions, by outcome.",
	},
	[]string{"decision", "resource", "verb"},
)

var DecisionDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "tier_decision_duration_seconds",
		Help:      "Time taken to reach a tier authorization decision.",
		Buckets:   prometheus.DefBuckets,
	},
	[]string{"resource", "verb"},
)

var CacheFallbackGetsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "policy_cache_fallback_gets_total",
		Help:      "Live GETs issued because the policy tier cache could not answer. A high miss rate means the cache is not keeping up; a nonzero unlabeled rate means policies predate the tier-label policy.",
	},
	[]string{"resource", "reason"},
)

var CacheInitialSyncSeconds = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "policy_cache_initial_sync_timestamp_seconds",
		Help:      "Unix timestamp of the policy cache's initial sync at startup. Does not update on resync.",
	},
)

// RegisterAll registers every collector. Already-registered collectors are not an error, so
// that registering twice cannot take the process down.
func RegisterAll(registry prometheus.Registerer) error {
	collectors := []prometheus.Collector{
		DecisionsTotal,
		DecisionDuration,
		CacheFallbackGetsTotal,
		CacheInitialSyncSeconds,
	}

	for _, c := range collectors {
		if err := registry.Register(c); err != nil {
			var already prometheus.AlreadyRegisteredError
			if errors.As(err, &already) {
				continue
			}
			return err
		}
	}
	return nil
}
