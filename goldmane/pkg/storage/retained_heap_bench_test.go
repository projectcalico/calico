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
	"runtime"
	"testing"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	retainedFlows        = 200000
	retainedTraces       = 2000
	retainedHitsPerTrace = 4
)

// BenchmarkRetainedHeap reports the heap a BucketRing retains for 200k distinct flow keys, each
// with four enforced policy hits drawn from 2000 distinct traces. The flows and the decoded trace
// cache are built before measuring, so only what the ring holds is counted. Run it with
// -benchtime=1x; retained-B/flow is the signal, not ns/op.
func BenchmarkRetainedHeap(b *testing.B) {
	defer setupBenchmark(b)()
	flows := retainedHeapFlows()
	for _, f := range flows {
		types.CachedPolicyTrace(f.Key.Policies())
	}
	nowFunc := func() time.Time { return time.Unix(ingestNow, 0) }

	var total int64
	iterations := 0
	for b.Loop() {
		before := liveHeap()
		ring := storage.NewBucketRing(242, 15, ingestNow, storage.WithNowFunc(nowFunc))
		for _, f := range flows {
			ring.AddFlow(storage.FlowFromNode{Flow: f})
		}
		total += liveHeap() - before
		runtime.KeepAlive(ring)
		iterations++
	}
	runtime.KeepAlive(flows)

	perRing := float64(total) / float64(iterations)
	b.ReportMetric(perRing/(1<<20), "retained-MB")
	b.ReportMetric(perRing/retainedFlows, "retained-B/flow")
}

// liveHeap returns the bytes of live heap objects after a full collection.
func liveHeap() int64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int64(ms.HeapAlloc)
}

// retainedHeapFlows builds retainedFlows flows with distinct keys, cycling through retainedTraces
// policy traces of retainedHitsPerTrace enforced hits each.
func retainedHeapFlows() []*types.Flow {
	traces := make([]*proto.PolicyTrace, retainedTraces)
	for t := range traces {
		hits := make([]*proto.PolicyHit, retainedHitsPerTrace)
		for j := range hits {
			action := proto.Action_Pass
			if j == len(hits)-1 {
				action = proto.Action_Allow
			}
			hits[j] = &proto.PolicyHit{
				Kind:        proto.PolicyKind_CalicoNetworkPolicy,
				Tier:        fmt.Sprintf("tier-%d", j),
				Name:        fmt.Sprintf("policy-%d-%d", t, j),
				Namespace:   fmt.Sprintf("ns-%d", t%50),
				Action:      action,
				PolicyIndex: int64(j),
				RuleIndex:   int64(t % 3),
			}
		}
		traces[t] = &proto.PolicyTrace{EnforcedPolicies: hits}
	}

	flows := make([]*types.Flow, retainedFlows)
	for i := range flows {
		flows[i] = types.ProtoToFlow(&proto.Flow{
			Key: &proto.FlowKey{
				SourceName:      fmt.Sprintf("client-%d-*", i/100),
				SourceNamespace: fmt.Sprintf("ns-%d", i%50),
				SourceType:      proto.EndpointType_WorkloadEndpoint,
				DestName:        fmt.Sprintf("server-%d-*", i%100),
				DestNamespace:   fmt.Sprintf("ns-%d", (i/7)%50),
				DestType:        proto.EndpointType_WorkloadEndpoint,
				DestPort:        8080,
				Proto:           "tcp",
				Reporter:        proto.Reporter(i % 2),
				Action:          proto.Action_Allow,
				Policies:        traces[i%retainedTraces],
			},
			StartTime:  ingestNow,
			EndTime:    ingestNow + 15,
			PacketsIn:  100,
			PacketsOut: 200,
			BytesIn:    10000,
			BytesOut:   20000,
		})
	}
	return flows
}
