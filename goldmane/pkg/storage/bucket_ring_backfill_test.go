// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage_test

import (
	"testing"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
)

const backfillRingSize = 20

// addFlowAt adds one flow to the bucket that begins at start.
func addFlowAt(ring *storage.BucketRing, start int64) {
	f := testutils.NewRandomFlow(start)
	f.StartTime, f.EndTime = start, start+1
	ring.AddFlow(storage.FlowFromNode{Flow: types.ProtoToFlow(f)})
}

// countBuilders returns how many flows p yields.
func countBuilders(p storage.FlowProvider) int {
	var n int
	p.Iter(func(storage.FlowBuilder) bool {
		n++
		return false
	})
	return n
}

// A provider queued for a slow stream must not yield a later interval's flows once the ring
// has reused its bucket, even though that bucket is marked ready again.
func TestQueuedBucketSkipsAfterReuse(t *testing.T) {
	ring := storage.NewBucketRing(
		backfillRingSize,
		1,
		seedNow,
		storage.WithStreamReceiver(&recordingReceiver{}),
		storage.WithNowFunc(seedClock),
	)
	addFlowAt(ring, seedNow-3)

	recv := &recordingReceiver{}
	ring.Backfill(recv, "id", seedNow-3)
	if len(recv.providers) == 0 {
		t.Fatal("backfill sent nothing")
	}
	queued := recv.providers[0]
	if got := countBuilders(queued); got != 1 {
		t.Fatalf("before reuse: queued bucket yields %d flows, want 1", got)
	}

	// Fill the filling bucket before each rollover, so the reused slot holds a flow when it is
	// streamed again.
	for range backfillRingSize {
		addFlowAt(ring, ring.EndOfHistory()-2)
		ring.Rollover(nil)
	}
	if got := countBuilders(queued); got != 0 {
		t.Fatalf("after reuse: queued bucket yields %d flows, want 0", got)
	}
}

// backfillCase is a stream start time and the number of buckets Backfill should send for it.
type backfillCase struct {
	name  string
	start int64
	want  int
}

// With 1s buckets at seedNow, the next bucket to stream starts at seedNow-1, so backfill covers
// [start, seedNow-1). Starts in the filling or head bucket used to wrap the whole ring.
func TestBackfillStopsAtStreamingBucket(t *testing.T) {
	cases := []backfillCase{
		{name: "history", start: seedNow - 3, want: 2},
		{name: "streaming bucket", start: seedNow - 1, want: 0},
		{name: "filling bucket", start: seedNow, want: 0},
		{name: "head bucket", start: seedNow + 1, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ring := storage.NewBucketRing(backfillRingSize, 1, seedNow, storage.WithNowFunc(seedClock))
			recv := &recordingReceiver{}
			ring.Backfill(recv, "id", tc.start)
			if len(recv.providers) != tc.want {
				t.Fatalf("start %d: backfilled %d buckets, want %d", tc.start, len(recv.providers), tc.want)
			}
		})
	}
}
