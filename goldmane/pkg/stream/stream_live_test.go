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

package stream_test

import (
	"context"
	"testing"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const now = 1000

// newRing builds a ring wired to sm, with one flow (same key) in each bucket from now-5 to
// now-1. The now-1 bucket is the next one a rollover sends live.
func newRing(sm stream.StreamManager) *storage.BucketRing {
	clk := func() time.Time { return time.Unix(now, 0) }
	ring := storage.NewBucketRing(20, 1, now, storage.WithStreamReceiver(sm), storage.WithNowFunc(clk))

	base := testutils.NewRandomFlow(now)
	for i := int64(1); i <= 5; i++ {
		fl := googleproto.Clone(base).(*proto.Flow)
		fl.StartTime = now - i
		fl.EndTime = now - i + 1
		ring.AddFlow(storage.FlowFromNode{Flow: types.ProtoToFlow(fl)})
	}
	return ring
}

func register(t *testing.T, sm stream.StreamManager, start int64) stream.Stream {
	t.Helper()
	s := <-sm.Register(&proto.FlowStreamRequest{StartTimeGte: start}, 100)
	if s == nil {
		t.Fatal("nil stream")
	}
	t.Cleanup(s.Close)
	return s
}

// backfill does what the aggregator loop does for a new stream.
func backfill(ring *storage.BucketRing, sm stream.StreamManager) {
	s := <-sm.Backfills()
	liveFrom := ring.BackfillEndTime()
	ring.Backfill(sm, s.ID(), s.StartTimeGte())
	sm.GoLive(s.ID(), liveFrom)
}

// drain collects the start time of every flow on the stream until it goes quiet.
func drain(s stream.Stream) []int64 {
	var got []int64
	for {
		select {
		case b := <-s.Flows():
			res := &proto.FlowResult{Flow: &proto.Flow{}}
			if b.BuildInto(&proto.Filter{}, res) {
				got = append(got, res.Flow.StartTime)
			}
		case <-time.After(300 * time.Millisecond):
			return got
		}
	}
}

func expectBuckets(t *testing.T, got []int64, want ...int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got start times %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got start times %v, want %v", got, want)
		}
	}
}

// The aggregator selects between rollover and backfill at random when both are ready. If
// rollover wins, the now-1 bucket goes live before the backfill runs, and the backfill then
// covers it too.
func TestRolloverBeforeBackfill(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sm := stream.NewStreamManager()
	go sm.Run(ctx)
	ring := newRing(sm)

	s := register(t, sm, now-5)
	ring.Rollover(nil)
	backfill(ring, sm)

	expectBuckets(t, drain(s), now-5, now-4, now-3, now-2, now-1)
}

// Buckets flushed before a stream exists can still be sitting in the stream manager's queue
// when the stream registers. They must not reach it, because backfill already covers them.
func TestStaleFlushesSkipped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sm := stream.NewStreamManager()

	// Build the ring before the stream manager runs, so its startup flushes are still queued.
	ring := newRing(sm)
	go sm.Run(ctx)

	s := register(t, sm, now-5)
	backfill(ring, sm)

	expectBuckets(t, drain(s), now-5, now-4, now-3, now-2)

	// The next rollover is the first live bucket.
	ring.Rollover(nil)
	expectBuckets(t, drain(s), now-1)
}
