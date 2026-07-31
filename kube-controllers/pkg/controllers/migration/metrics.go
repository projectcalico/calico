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

package migration

import "github.com/prometheus/client_golang/prometheus"

var (
	migrationResourcesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "calico",
		Subsystem: "migration",
		Name:      "resources_total",
		Help:      "Total number of resources processed during v1-to-v3 migration, by kind and outcome.",
	}, []string{"kind", "outcome"})

	migrationResourceErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "calico",
		Subsystem: "migration",
		Name:      "resource_errors_total",
		Help:      "Total number of errors encountered during v1-to-v3 migration, by kind.",
	}, []string{"kind"})

	migrationRetries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "calico",
		Subsystem: "migration",
		Name:      "retries_total",
		Help:      "Total number of retried API calls during migration, by kind and operation.",
	}, []string{"kind", "operation"})

	migrationPhase = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "calico",
		Subsystem: "migration",
		Name:      "phase",
		Help:      "Current migration phase (1=active, 0=inactive). Labels: pending, migrating, converged, complete, failed.",
	}, []string{"phase"})

	migrationDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "calico",
		Subsystem: "migration",
		Name:      "duration_seconds",
		Help:      "Total wall-clock duration of the migration.",
		Buckets:   prometheus.ExponentialBuckets(1, 2, 15), // 1s to ~4.5h
	})

	migrationTypeDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "calico",
		Subsystem: "migration",
		Name:      "type_duration_seconds",
		Help:      "Wall-clock duration of migrating a single resource type.",
		Buckets:   prometheus.ExponentialBuckets(0.1, 2, 12), // 100ms to ~3.4min
	}, []string{"kind"})
)

func init() {
	prometheus.MustRegister(
		migrationResourcesTotal,
		migrationResourceErrors,
		migrationRetries,
		migrationPhase,
		migrationDuration,
		migrationTypeDuration,
	)
}

// setPhaseMetric sets the migration phase gauge, clearing all other phases.
func setPhaseMetric(phase DatastoreMigrationPhase) {
	for _, p := range []string{"pending", "migrating", "waiting_for_conflict_resolution", "converged", "complete", "failed"} {
		migrationPhase.WithLabelValues(p).Set(0)
	}
	var label string
	switch phase {
	case DatastoreMigrationPhasePending, "":
		label = "pending"
	case DatastoreMigrationPhaseMigrating:
		label = "migrating"
	case DatastoreMigrationPhaseWaitingForConflictResolution:
		label = "waiting_for_conflict_resolution"
	case DatastoreMigrationPhaseConverged:
		label = "converged"
	case DatastoreMigrationPhaseComplete:
		label = "complete"
	case DatastoreMigrationPhaseFailed:
		label = "failed"
	default:
		return
	}
	migrationPhase.WithLabelValues(label).Set(1)
}
