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
	"github.com/projectcalico/calico/lib/std/time"
)

const seedNow = 1000

func seedClock() time.Time { return time.Unix(seedNow, 0) }

type recordingReceiver struct {
	providers []storage.FlowProvider
}

func (r *recordingReceiver) Receive(p storage.FlowProvider, _ string) {
	r.providers = append(r.providers, p)
}

func TestNewBucketRingDoesNotStreamSeedBuckets(t *testing.T) {
	recv := &recordingReceiver{}
	ring := storage.NewBucketRing(20, 1, seedNow, storage.WithStreamReceiver(recv), storage.WithNowFunc(seedClock))

	if len(recv.providers) != 0 {
		t.Fatalf("expected no buckets streamed while seeding the ring, got %d", len(recv.providers))
	}

	ring.Rollover(nil)
	if len(recv.providers) != 1 {
		t.Fatalf("expected one bucket streamed per rollover, got %d", len(recv.providers))
	}
}

// Backfill only sends buckets marked ready, so seeding has to mark them even though it doesn't stream them.
func TestBackfillAfterSeedingSendsFlows(t *testing.T) {
	ring := storage.NewBucketRing(20, 1, seedNow, storage.WithNowFunc(seedClock))
	for start := int64(seedNow - 5); start < seedNow; start++ {
		f := testutils.NewRandomFlow(start)
		f.StartTime, f.EndTime = start, start+1
		ring.AddFlow(storage.FlowFromNode{Flow: types.ProtoToFlow(f)})
	}

	recv := &recordingReceiver{}
	ring.Backfill(recv, "id", seedNow-5)

	var built int
	for _, p := range recv.providers {
		p.Iter(func(storage.FlowBuilder) bool {
			built++
			return false
		})
	}
	if built == 0 {
		t.Fatalf("expected backfill to send flows from %d buckets, got none", len(recv.providers))
	}
}
