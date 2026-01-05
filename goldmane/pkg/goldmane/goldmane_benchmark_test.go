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
	"fmt"
	"github.com/projectcalico/calico/goldmane/proto"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
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
				newRandomFlow(flowStartTime.Unix()),
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

func newRandomFlow(start int64) *proto.Flow {
	labelCount := 10
	srcNames := map[int]string{
		0: "client-aggr-1",
		1: "client-aggr-2",
		2: "client-aggr-3",
		3: "client-aggr-4",
	}
	dstNames := map[int]string{
		0: "server-aggr-1",
		1: "server-aggr-2",
		2: "server-aggr-3",
		3: "server-aggr-4",
	}
	actions := map[int]proto.Action{
		0: proto.Action_Allow,
		1: proto.Action_Deny,
	}
	reporters := map[int]proto.Reporter{
		0: proto.Reporter_Src,
		1: proto.Reporter_Dst,
	}
	services := map[int]string{
		0: "frontend-service",
		1: "backend-service",
		2: "db-service",
	}
	namespaces := map[int]string{
		0: "test-ns",
		1: "test-ns-2",
		2: "test-ns-3",
		3: "test-ns-4",
		4: "test-ns-5",
	}
	tiers := map[int]string{
		0: "tier-1",
		1: "tier-2",
		2: "tier-3",
		3: "default",
	}
	policies := map[int]string{
		0: "policy-1",
		1: "policy-2",
		2: "policy-3",
		3: "policy-4",
		4: "policy-5",
	}
	indices := map[int]int64{
		0: 0,
		1: 1,
		2: 2,
		3: 3,
	}

	dstNs := randomFromMap(namespaces)
	srcNs := randomFromMap(namespaces)
	action := randomFromMap(actions)
	reporter := randomFromMap(reporters)
	polNs := dstNs
	if reporter == proto.Reporter_Src {
		polNs = srcNs
	}
	f := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:           randomFromMap(srcNames),
			SourceNamespace:      srcNs,
			DestName:             randomFromMap(dstNames),
			DestNamespace:        dstNs,
			Proto:                "tcp",
			Action:               action,
			Reporter:             reporter,
			DestServiceName:      randomFromMap(services),
			DestServicePort:      80,
			DestServiceNamespace: dstNs,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_CalicoNetworkPolicy,
						Tier:        randomFromMap(tiers),
						Name:        randomFromMap(policies),
						Namespace:   polNs,
						Action:      action,
						PolicyIndex: randomFromMap(indices),
						RuleIndex:   0,
					},
					{
						Kind:        proto.PolicyKind_CalicoNetworkPolicy,
						Tier:        "default",
						Name:        "default-allow",
						Namespace:   "default",
						Action:      proto.Action_Allow,
						PolicyIndex: 1,
						RuleIndex:   1,
					},
				},
			},
		},
		StartTime:               start,
		EndTime:                 start + 1,
		BytesIn:                 100,
		BytesOut:                200,
		PacketsIn:               10,
		PacketsOut:              20,
		NumConnectionsStarted:   1,
		NumConnectionsLive:      2,
		NumConnectionsCompleted: 3,
	}

	f.SourceLabels = make([]string, labelCount)
	f.DestLabels = make([]string, labelCount)
	for i := 0; i < labelCount; i++ {
		f.SourceLabels[i] = fmt.Sprintf("srcLabel%d=value", i)
		f.DestLabels[i] = fmt.Sprintf("dstLabel%d=value", i)
	}

	// For now, just copy the enforced policies to the pending policies. This is
	// equivalent to there being no staged policies in the trace.
	f.Key.Policies.PendingPolicies = f.Key.Policies.EnforcedPolicies
	return f
}

func randomFromMap[E comparable](m map[int]E) E {
	// Generate a random number within the size of the map.
	return m[rand.IntN(len(m))]
}
