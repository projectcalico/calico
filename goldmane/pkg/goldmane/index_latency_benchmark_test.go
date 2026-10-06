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

package goldmane_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
)

// BenchmarkIndexLatencyObserve compares the per-flow cost of the old millisecond Summary,
// which saw almost only zeros, with the seconds Histogram that replaced it.
func BenchmarkIndexLatencyObserve(b *testing.B) {
	b.Run("summary_ms", func(b *testing.B) {
		s := cprometheus.NewSummary(prometheus.SummaryOpts{Name: "bench_summary_ms", Help: "bench"})
		b.ReportAllocs()
		for b.Loop() {
			s.Observe(0)
		}
	})
	b.Run("histogram_seconds", func(b *testing.B) {
		h := prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "bench_histogram_seconds",
			Help:    "bench",
			Buckets: prometheus.ExponentialBuckets(1e-6, 4, 11),
		})
		b.ReportAllocs()
		for b.Loop() {
			h.Observe(5e-6)
		}
	})
}
