// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package storage_test

import (
	"fmt"
	"testing"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/lib/std/time"
)

const ingestNow = int64(1000000)

// BenchmarkIngestAddFlowSteady adds flows for keys that already exist, from three nodes, with
// a fresh emission each pass so dedup never skips one.
func BenchmarkIngestAddFlowSteady(b *testing.B) {
	for _, k := range []int{1000, 20000} {
		b.Run(fmt.Sprintf("keys=%d", k), func(b *testing.B) {
			defer setupBenchmark(b)()
			pf := testutils.IngestFlows(k, ingestNow)
			fl := make([]*types.Flow, k)
			for i := range pf {
				fl[i] = types.ProtoToFlow(pf[i])
			}
			nowFunc := func() time.Time { return time.Unix(ingestNow, 0) }
			ring := storage.NewBucketRing(242, 15, ingestNow, storage.WithNowFunc(nowFunc))
			for _, f := range fl {
				ring.AddFlow(storage.FlowFromNode{Flow: f, Node: "seed"})
			}
			nodes := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}

			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				idx := i % k
				pass := i / k
				if idx == 0 {
					b.StopTimer()
					for _, f := range fl {
						f.EndTime = ingestNow + 15 + int64(pass)
					}
					b.StartTimer()
				}
				if ring.AddFlow(storage.FlowFromNode{Flow: fl[idx], Node: nodes[pass%len(nodes)]}) {
					b.Fatal("flow was unexpectedly treated as a duplicate")
				}
			}
		})
	}
}
