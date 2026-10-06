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
	"fmt"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/lib/std/time"
)

// BenchmarkAggregatorThroughput saturates the main loop from several producers and reports
// how fast the aggregator goroutine drains it. Each op is one flow.
func BenchmarkAggregatorThroughput(b *testing.B) {
	defer setupBenchmark(b)()
	const keys = 20000
	const producers = 8

	gm := goldmane.NewGoldmane()
	now := time.Now().Unix()
	<-gm.Run(now)
	defer gm.Stop()

	pf := testutils.IngestFlows(keys, now)
	fl := make([]*types.Flow, keys)
	for i := range pf {
		fl[i] = types.ProtoToFlow(pf[i])
	}

	// Warm every key so the benchmark measures updates to existing flows.
	base := receivedFlows(b)
	for _, f := range fl {
		gm.Receive(f, "warm")
	}
	waitForReceived(b, base+keys)
	base = receivedFlows(b)

	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	var wg sync.WaitGroup
	per := b.N / producers
	for p := range producers {
		n := per
		if p == producers-1 {
			n = b.N - per*(producers-1)
		}
		wg.Go(func() {
			node := ""
			for i := range n {
				// Change node on each pass over the keys, or the aggregator skips them as duplicates.
				if i%keys == 0 {
					node = fmt.Sprintf("10.%d.%d", p, i/keys)
				}
				gm.Receive(fl[(p*per+i)%keys], node)
			}
		})
	}
	wg.Wait()
	waitForReceived(b, base+float64(b.N))
	b.StopTimer()
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "flows/s")
}

func receivedFlows(b *testing.B) float64 {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		b.Fatalf("gathering metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "goldmane_aggr_received_flows_total" {
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	b.Fatal("goldmane_aggr_received_flows_total not registered")
	return 0
}

func waitForReceived(b *testing.B, n float64) {
	for receivedFlows(b) < n {
		time.Sleep(time.Millisecond)
	}
}
