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

	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

// The stream goroutine reads DiachronicFlow windows while the aggregator goroutine keeps
// adding to the same flow. Run with -race.
func TestStreamReadRacesAddFlow(t *testing.T) {
	const now = 1000

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sm := stream.NewStreamManager()
	go sm.Run(ctx)

	clk := func() time.Time { return time.Unix(now, 0) }
	ring := storage.NewBucketRing(20, 1, now, storage.WithStreamReceiver(sm), storage.WithNowFunc(clk))

	base := testutils.NewRandomFlow(now)
	addFlow := func(start int64) {
		fl := googleproto.Clone(base).(*proto.Flow)
		fl.StartTime = start
		fl.EndTime = start + 1
		ring.AddFlow(types.ProtoToFlow(fl))
	}
	for i := int64(1); i <= 5; i++ {
		addFlow(now - i)
	}

	s := <-sm.Register(&proto.FlowStreamRequest{StartTimeGte: now - 5}, 100)
	if s == nil {
		t.Fatal("nil stream")
	}
	defer s.Close()

	bf := <-sm.Backfills()
	ring.Backfill(sm, bf.ID(), bf.StartTimeGte())

	for range 50 {
		addFlow(now)
	}

	var got int
	for {
		select {
		case b := <-s.Flows():
			if b.BuildInto(&proto.Filter{}, &proto.FlowResult{Flow: &proto.Flow{}}) {
				got++
			}
		case <-time.After(300 * time.Millisecond):
			if got != 4 {
				t.Errorf("expected 4 backfilled flows, got %d", got)
			}
			return
		}
	}
}
