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
	"slices"
	"testing"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const liveNow = 1000

// newLiveRing builds a ring wired to sm with one flow in each bucket from now-5 to now-1.
func newLiveRing(sm stream.StreamManager) *storage.BucketRing {
	clk := func() time.Time { return time.Unix(liveNow, 0) }
	ring := storage.NewBucketRing(20, 1, liveNow, storage.WithStreamReceiver(sm), storage.WithNowFunc(clk))

	base := testutils.NewRandomFlow(liveNow)
	for i := int64(1); i <= 5; i++ {
		fl := &proto.Flow{}
		googleproto.Merge(fl, base)
		fl.StartTime = liveNow - i
		fl.EndTime = liveNow - i + 1
		ring.AddFlow(storage.FlowFromNode{Flow: types.ProtoToFlow(fl)})
	}
	return ring
}

// collect reads n flow start times from s.
func collect(t *testing.T, s stream.Stream, n int) []int64 {
	t.Helper()
	var got []int64
	for len(got) < n {
		select {
		case b := <-s.Flows():
			res := &proto.FlowResult{Flow: &proto.Flow{}}
			if b.BuildInto(&proto.Filter{}, res) {
				got = append(got, res.Flow.StartTime)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("got start times %v, want %d of them", got, n)
		}
	}
	select {
	case b := <-s.Flows():
		t.Fatalf("unexpected extra flow %v after %v", b, got)
	case <-time.After(100 * time.Millisecond):
	}
	return got
}

// Buckets flushed before the stream registered never reach it, and the first rollover after
// backfill sends the next bucket exactly once.
func TestBackfillThenLive(t *testing.T) {
	sm := stream.NewStreamManager()
	ring := newLiveRing(sm)

	s := sm.Register(&proto.FlowStreamRequest{StartTimeGte: liveNow - 5}, 100)
	t.Cleanup(s.Close)
	ring.Backfill(sm, s.ID(), s.StartTimeGte())

	if got, want := collect(t, s, 4), []int64{liveNow - 5, liveNow - 4, liveNow - 3, liveNow - 2}; !slices.Equal(got, want) {
		t.Fatalf("backfill: got %v, want %v", got, want)
	}

	ring.Rollover(nil)
	if got, want := collect(t, s, 1), []int64{liveNow - 1}; !slices.Equal(got, want) {
		t.Fatalf("live: got %v, want %v", got, want)
	}
}

// A stream that stops reading is closed instead of blocking the main loop.
func TestFullQueueClosesStream(t *testing.T) {
	sm := stream.NewStreamManager()
	s := sm.Register(&proto.FlowStreamRequest{}, 1)
	t.Cleanup(s.Close)

	start := time.Now()
	for range 1000 {
		sm.Receive(twoFlows{}, "")
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("Receive blocked for %v", d)
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-s.Flows():
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("stream was not closed")
		}
	}
}

// twoFlows yields two builders, so a reader that never drains blocks on the second one.
type twoFlows struct{}

func (twoFlows) Iter(f func(storage.FlowBuilder) bool) {
	for range 2 {
		if f(nopBuilder{}) {
			return
		}
	}
}

type nopBuilder struct{}

func (nopBuilder) BuildInto(*proto.Filter, *proto.FlowResult) bool { return false }
