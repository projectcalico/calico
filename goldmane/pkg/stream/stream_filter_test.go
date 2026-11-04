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

package stream_test

import (
	"testing"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

// filterCase is a stream filter, how many flows from each bucket a stream using it receives, and
// the only source namespace it may receive, if any.
type filterCase struct {
	name      string
	filter    *proto.Filter
	perBucket int
	namespace string
}

// The stream applies its filter, and the consumer builds without one as FlowsServer.Stream does,
// so a filtered stream must receive only matching flows from both backfilled and live buckets.
func TestStreamFiltersBackfillAndLiveBuckets(t *testing.T) {
	streams := stream.NewStreamManager()

	clk := func() time.Time { return time.Unix(benchNow, 0) }
	ring := storage.NewBucketRing(20, 1, benchNow, storage.WithStreamReceiver(streams), storage.WithNowFunc(clk))

	// benchFlow spreads flows over ten namespaces, so ns-3 holds two of every twenty.
	const flowsPerBucket = 20
	backfillStart := int64(benchNow - 3)
	liveStart := int64(benchNow - 1)
	for i := range flowsPerBucket {
		ring.AddFlow(storage.FlowFromNode{Flow: benchFlow(i, backfillStart)})
		ring.AddFlow(storage.FlowFromNode{Flow: benchFlow(flowsPerBucket+i, liveStart)})
	}

	cases := []filterCase{
		{"ns-3", &proto.Filter{SourceNamespaces: []*proto.StringMatch{{Value: "ns-3", Type: proto.MatchType_Exact}}}, 2, "ns-3"},
		{"empty", &proto.Filter{}, flowsPerBucket, ""},
		{"nil", nil, flowsPerBucket, ""},
	}

	var registered []stream.Stream
	for _, c := range cases {
		s := streams.Register(&proto.FlowStreamRequest{StartTimeGte: benchNow - 5, Filter: c.filter}, streamBufferSize)
		defer s.Close()
		ring.Backfill(streams, s.ID(), s.StartTimeGte())
		registered = append(registered, s)
	}

	// Backfill stops before the streaming bucket, which rollover then sends to every stream.
	ring.Rollover(nil)

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			numByStart := map[int64]int{}
			for _, f := range collectFlows(t, registered[i], 2*c.perBucket) {
				numByStart[f.StartTime]++
				if c.namespace != "" && f.Key.SourceNamespace != c.namespace {
					t.Errorf("stream sent a flow from namespace %q", f.Key.SourceNamespace)
				}
			}
			if numByStart[backfillStart] != c.perBucket || numByStart[liveStart] != c.perBucket {
				t.Errorf("expected %d backfilled and %d live flows, got %v", c.perBucket, c.perBucket, numByStart)
			}
		})
	}
}

// collectFlows builds the first n flows from s the way FlowsServer.Stream does, then fails if
// another flow arrives shortly after.
func collectFlows(t *testing.T, s stream.Stream, n int) []*proto.Flow {
	t.Helper()
	var flows []*proto.Flow
	deadline := time.After(10 * time.Second)
	for len(flows) < n {
		select {
		case b := <-s.Flows():
			res := &proto.FlowResult{Flow: &proto.Flow{}}
			if b.BuildInto(nil, res) {
				flows = append(flows, res.Flow)
			}
		case <-deadline:
			t.Fatalf("expected %d flows, got %d", n, len(flows))
		}
	}

	select {
	case b := <-s.Flows():
		res := &proto.FlowResult{Flow: &proto.Flow{}}
		if b.BuildInto(nil, res) {
			t.Errorf("expected only %d flows, got another from namespace %q", n, res.Flow.Key.SourceNamespace)
		}
	case <-time.After(100 * time.Millisecond):
	}
	return flows
}
