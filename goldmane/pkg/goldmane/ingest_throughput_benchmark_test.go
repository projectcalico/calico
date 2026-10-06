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

	keyedFlows := make([]*types.Flow, keys)
	for i, f := range testutils.IngestFlows(keys, now) {
		keyedFlows[i] = types.ProtoToFlow(f)
	}

	// Warm every key so the benchmark measures updates to existing flows.
	base := receivedFlows(b)
	for _, f := range keyedFlows {
		gm.Receive(f, "warm")
	}
	waitForReceived(b, base+keys)
	base = receivedFlows(b)

	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	var wg sync.WaitGroup
	perProducer := b.N / producers
	for p := range producers {
		n := perProducer
		if p == producers-1 {
			n = b.N - perProducer*(producers-1)
		}
		wg.Go(func() {
			node := ""
			for i := range n {
				// Change node on each pass over the keys, or the aggregator skips them as duplicates.
				if i%keys == 0 {
					node = fmt.Sprintf("10.%d.%d", p, i/keys)
				}
				gm.Receive(keyedFlows[(p*perProducer+i)%keys], node)
			}
		})
	}
	wg.Wait()
	waitForReceived(b, base+float64(b.N))
	b.StopTimer()
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "flows/s")
}
