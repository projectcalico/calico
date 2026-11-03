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
	"context"
	"testing"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

// A stream whose consumer never reads must not block the aggregator from adding flows to the
// bucket that stream is part-way through sending.
func TestStalledStreamDoesNotBlockAddFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streams := stream.NewStreamManager()
	go streams.Run(ctx)

	clk := func() time.Time { return time.Unix(benchNow, 0) }
	ring := storage.NewBucketRing(20, 1, benchNow, storage.WithStreamReceiver(streams), storage.WithNowFunc(clk))
	bucketStart := int64(benchNow - 3)
	for i := range 10 {
		ring.AddFlow(storage.FlowFromNode{Flow: benchFlow(i, bucketStart)})
	}

	stalled := <-streams.Register(&proto.FlowStreamRequest{}, 1)
	defer stalled.Close()
	<-streams.Backfills()
	ring.Backfill(streams, stalled.ID(), bucketStart)

	// Once the one-slot output channel is full, the stream goroutine is parked mid-bucket.
	deadline := time.Now().Add(10 * time.Second)
	for len(stalled.Flows()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("stream never sent a flow")
		}
		time.Sleep(time.Millisecond)
	}

	added := make(chan struct{})
	go func() {
		ring.AddFlow(storage.FlowFromNode{Flow: benchFlow(100, bucketStart), Node: "node-1"})
		close(added)
	}()

	select {
	case <-added:
	case <-time.After(10 * time.Second):
		t.Fatal("AddFlow blocked behind a stalled stream")
	}
}
