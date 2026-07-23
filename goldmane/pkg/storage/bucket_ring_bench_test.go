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
	"unique"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

// BenchmarkBucketRing_AddFlow benchmarks the full ingestion path through
// BucketRing.AddFlow, including bucket lookup, DiachronicFlow management,
// index updates, and bucket tracking.
func BenchmarkBucketRing_AddFlow(b *testing.B) {
	setupBenchmark(b)

	// 242 buckets at 15s intervals, matching production configuration.
	numBuckets := 242
	interval := 15
	now := int64(1000000)

	nowFunc := func() time.Time { return time.Unix(now, 0) }
	ring := storage.NewBucketRing(numBuckets, interval, now, storage.WithNowFunc(nowFunc))

	// Pre-generate flows with distinct keys to exercise both the "new DiachronicFlow"
	// and "existing DiachronicFlow" paths. Use 100 unique flow keys so after the first
	// 100 iterations, most flows hit the existing-key fast path.
	numKeys := 100
	testFlows := make([]*types.Flow, numKeys)
	for i := range numKeys {
		testFlows[i] = &types.Flow{
			Key: types.NewFlowKey(
				&types.FlowKeySource{
					SourceName:      fmt.Sprintf("src-%d", i),
					SourceNamespace: "default",
					SourceType:      proto.EndpointType_WorkloadEndpoint,
				},
				&types.FlowKeyDestination{
					DestName:      fmt.Sprintf("dst-%d", i),
					DestNamespace: "default",
					DestType:      proto.EndpointType_WorkloadEndpoint,
					DestPort:      8080,
				},
				&types.FlowKeyMeta{
					Proto:    "TCP",
					Reporter: proto.Reporter_Src,
					Action:   proto.Action_Allow,
				},
				&proto.PolicyTrace{},
			),
			// Place flows in the current time window so findBucket succeeds.
			StartTime:             now,
			EndTime:               now + int64(interval),
			PacketsIn:             100,
			PacketsOut:            200,
			BytesIn:               10000,
			BytesOut:              20000,
			NumConnectionsStarted: 1,
			SourceLabels:          unique.Make("app=frontend,env=prod,team=platform"),
			DestLabels:            unique.Make("app=backend,env=prod,team=platform"),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		ring.AddFlow(testFlows[i%numKeys])
	}
}
