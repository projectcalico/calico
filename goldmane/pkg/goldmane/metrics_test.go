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
	dto "github.com/prometheus/client_model/go"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/lib/std/time"
)

func TestFlowIndexLatencyHistogram(t *testing.T) {
	const flows = 10

	gm := goldmane.NewGoldmane()
	now := time.Now().Unix()
	<-gm.Run(now)
	defer gm.Stop()

	before := indexLatency(t)
	base := receivedFlows(t)
	for _, f := range testutils.IngestFlows(flows, now) {
		gm.Receive(types.ProtoToFlow(f), "node")
	}
	waitForReceived(t, base+flows)
	after := indexLatency(t)

	if got := after.GetSampleCount() - before.GetSampleCount(); got != flows {
		t.Errorf("expected %d new samples, got %d", flows, got)
	}

	// Whole-millisecond samples of a sub-millisecond operation sum to 0.
	if after.GetSampleSum() <= before.GetSampleSum() {
		t.Errorf("expected sample sum to grow past %v, got %v", before.GetSampleSum(), after.GetSampleSum())
	}

	if gatherMetric(t, "goldmane_aggr_flow_index_latency_ms") != nil {
		t.Error("the replaced millisecond summary is still registered")
	}
}

func indexLatency(t *testing.T) *dto.Histogram {
	t.Helper()
	const name = "goldmane_aggr_flow_index_latency_seconds"
	mf := gatherMetric(t, name)
	if mf == nil {
		t.Fatalf("%s not registered", name)
	}
	if mf.GetType() != dto.MetricType_HISTOGRAM {
		t.Fatalf("expected %s to be a histogram, got %v", name, mf.GetType())
	}
	return mf.GetMetric()[0].GetHistogram()
}

// gatherMetric returns the default registry's family with the given name, or nil if
// nothing by that name is registered.
func gatherMetric(tb testing.TB, name string) *dto.MetricFamily {
	tb.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		tb.Fatalf("gathering metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf
		}
	}
	return nil
}

func receivedFlows(tb testing.TB) float64 {
	tb.Helper()
	mf := gatherMetric(tb, "goldmane_aggr_received_flows_total")
	if mf == nil {
		tb.Fatal("goldmane_aggr_received_flows_total not registered")
	}
	return mf.GetMetric()[0].GetCounter().GetValue()
}

// waitForReceived gives up after a deadline, since a dropped flow never reaches the counter.
func waitForReceived(tb testing.TB, target float64) {
	tb.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for receivedFlows(tb) < target {
		if time.Now().After(deadline) {
			tb.Fatalf("timed out waiting for the aggregator to index flows: %v of %v", receivedFlows(tb), target)
		}
		time.Sleep(time.Millisecond)
	}
}
