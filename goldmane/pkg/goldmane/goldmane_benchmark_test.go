// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package goldmane_test

import (
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/lib/std/time"
)

// Performance thresholds for the benchmarks.
// These constants define the upper limits for each key metric.
const (
	maxNsPerOp             = 13000.0 // Max allowed nanoseconds per operation (13 microseconds) - for reference only, check benchmark output
	maxNsPerOpParallel     = 35000.0 // Max allowed nanoseconds per operation (35 microseconds) - for reference only, check benchmark output
	maxHeapAllocMB         = 5.0     // Max allowed total heap allocation in MB
	maxHeapAllocMBParallel = 8.0     // Max allowed total heap allocation in MB
	maxBytesPerOp          = 10000.0 // Max allowed bytes allocated per op
)

var flows []*types.Flow

func init() {
	now := time.Now()
	for i := 0; i < 1000; i++ {
		randomNumber := rand.IntN(1000)
		flowStartTime := now.Add(time.Duration(randomNumber) * time.Millisecond)
		flows = append(flows,
			types.ProtoToFlow(
				testutils.NewRandomFlow(flowStartTime.Unix()),
			),
		)
	}
}

func setupBenchmark(b *testing.B) func() {
	// Set up logrus to use b.Logf via custom writer
	writer := &logrusWriter{b}
	logrus.SetOutput(writer)
	logrus.SetLevel(logrus.WarnLevel)

	return func() {
		logrus.SetOutput(os.Stderr)
	}
}

type logrusWriter struct {
	b *testing.B
}

func (w *logrusWriter) Write(p []byte) (int, error) {
	w.b.Logf("%s", strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

// BenchmarkGoldmaneReceive benchmarks the basic Receive function performance with a single flow.
func BenchmarkGoldmaneReceive(b *testing.B) {
	cleanup := setupBenchmark(b)
	defer cleanup()

	// Setup Goldmane
	gm := goldmane.NewGoldmane()
	now := time.Now().Unix()
	<-gm.Run(now)
	defer gm.Stop()

	flowCount := len(flows)
	idx := rand.IntN(flowCount)

	b.ResetTimer()
	b.ReportAllocs()

	// Clean up memory before measurement begins
	runtime.GC()

	for b.Loop() {
		gm.Receive(flows[idx])

		idx++
		if idx == flowCount {
			idx = 0
		}
	}

	// Cleanup and give GC a moment to settle before measuring memory
	runtime.GC()

	// Collect memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	heapAllocMB := float64(m.HeapAlloc) / (1024 * 1024)
	b.ReportMetric(heapAllocMB, "HeapAllocMB")

	// Log benchmark expectations
	b.Logf("\t=== Benchmark Thresholds (Max allowed values) ===")
	b.Logf("\t\tMax allowed ns/op :\t\t%.1f", maxNsPerOp)
	b.Logf("\t\tMax allowed HeapAllocMB :\t%.3f", maxHeapAllocMB)
	b.Logf("\t\tMax allowed B/op (Bytes/op):\t%.1f", maxBytesPerOp)
	b.Logf("\t\tNote: ns/op is measured by Go's benchmark framework (shown in output above)")

	// Fail the test if memory thresholds are exceeded
	if heapAllocMB > maxHeapAllocMB {
		b.Fatalf("HeapAllocMB too high: got %.2f MB, max %.2f MB", heapAllocMB, maxHeapAllocMB)
	}
}

// BenchmarkGoldmaneReceiveParallel benchmarks parallel Receive calls to test concurrency performance.
func BenchmarkGoldmaneReceiveParallel(b *testing.B) {
	cleanup := setupBenchmark(b)
	defer cleanup()

	// Setup Goldmane
	gm := goldmane.NewGoldmane()
	now := time.Now().Unix()
	<-gm.Run(now)
	defer gm.Stop()

	flowCount := len(flows)

	b.ResetTimer()
	b.ReportAllocs()

	// Clean up memory before measurement begins
	runtime.GC()

	b.RunParallel(func(pb *testing.PB) {
		idx := rand.IntN(flowCount)

		for pb.Next() {
			gm.Receive(flows[idx])

			idx++
			if idx == flowCount {
				idx = 0
			}
		}
	})

	// Cleanup and give GC a moment to settle before measuring memory
	runtime.GC()

	// Collect memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	heapAllocMB := float64(m.HeapAlloc) / (1024 * 1024)
	b.ReportMetric(heapAllocMB, "HeapAllocMB")

	// Log benchmark expectations
	b.Logf("\t=== Benchmark Thresholds (Max allowed values) ===")
	b.Logf("\t\tMax allowed ns/op (Parallel Exec.) :\t\t%.1f", maxNsPerOpParallel)
	b.Logf("\t\tMax allowed HeapAllocMB :\t%.3f", maxHeapAllocMBParallel)
	b.Logf("\t\tMax allowed B/op (Bytes/op):\t%.1f", maxBytesPerOp)
	b.Logf("\t\tNote: ns/op is measured by Go's benchmark framework (shown in output above)")

	// Fail the test if memory thresholds are exceeded
	if heapAllocMB > maxHeapAllocMBParallel {
		b.Fatalf("HeapAllocMB too high: got %.2f MB, max %.2f MB", heapAllocMB, maxHeapAllocMBParallel)
	}
}
