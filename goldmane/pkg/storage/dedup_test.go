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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	dedupInterval  = 15
	dedupRingStart = int64(1000005)
	dedupBytesIn   = int64(1000)
)

// TestRingDedup covers the cases the per-bucket claim has to tell apart. Only the first is
// a replay; the rest have to keep accumulating.
func TestRingDedup(t *testing.T) {
	for _, tc := range []struct {
		name       string
		firstNode  string
		secondNode string
		bumpEnd    bool
		wantFactor int64
	}{
		{name: "same node replays the same emission", firstNode: "node-a", secondNode: "node-a", wantFactor: 1},
		{name: "a second node reports the same flow", firstNode: "node-a", secondNode: "node-b", wantFactor: 2},
		{name: "the same node reports a later emission", firstNode: "node-a", secondNode: "node-a", bumpEnd: true, wantFactor: 2},
		{name: "no reporting node is named", wantFactor: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ring := newDedupRing()

			flow := dedupFlow(dedupRingStart)
			ring.AddFlow(storage.FlowFromNode{Flow: flow, Node: tc.firstNode})

			second := *flow
			if tc.bumpEnd {
				second.EndTime++
			}
			ring.AddFlow(storage.FlowFromNode{Flow: &second, Node: tc.secondNode})

			require.Equal(t, tc.wantFactor*dedupBytesIn, ringBytesIn(t, ring))
		})
	}
}

// TestRingDedupWindowExpires documents the memory tradeoff: claims only survive the window
// a client can replay, so a much later replay is counted again.
func TestRingDedupWindowExpires(t *testing.T) {
	ring := newDedupRing()
	flow := dedupFlow(dedupRingStart)

	ring.AddFlow(storage.FlowFromNode{Flow: flow, Node: "node-a"})
	require.Equal(t, dedupBytesIn, ringBytesIn(t, ring))

	// Still inside the window, so the claim holds.
	ring.Rollover(nil)
	ring.AddFlow(storage.FlowFromNode{Flow: flow, Node: "node-a"})
	require.Equal(t, dedupBytesIn, ringBytesIn(t, ring))

	// Past it, and the bucket has dropped its claims.
	for range 25 {
		ring.Rollover(nil)
	}
	ring.AddFlow(storage.FlowFromNode{Flow: flow, Node: "node-a"})
	require.Equal(t, 2*dedupBytesIn, ringBytesIn(t, ring))
}

func newDedupRing() *storage.BucketRing {
	nowFunc := func() time.Time { return time.Unix(dedupRingStart, 0) }
	return storage.NewBucketRing(242, dedupInterval, dedupRingStart, storage.WithNowFunc(nowFunc))
}

func dedupFlow(start int64) *types.Flow {
	return &types.Flow{
		Key: types.NewFlowKey(
			&types.FlowKeySource{
				SourceName:      "client",
				SourceNamespace: "dedup-ns",
				SourceType:      proto.EndpointType_WorkloadEndpoint,
			},
			&types.FlowKeyDestination{
				DestName:      "server",
				DestNamespace: "dedup-ns",
				DestType:      proto.EndpointType_WorkloadEndpoint,
				DestPort:      8080,
			},
			&types.FlowKeyMeta{
				Proto:    "tcp",
				Reporter: proto.Reporter_Src,
				Action:   proto.Action_Allow,
			},
			&proto.PolicyTrace{},
		),
		StartTime: start,
		EndTime:   start + dedupInterval,
		BytesIn:   dedupBytesIn,
		BytesOut:  dedupBytesIn,
	}
}

func ringBytesIn(t *testing.T, ring *storage.BucketRing) int64 {
	t.Helper()
	flows, _, err := ring.List(&proto.FlowListRequest{
		StartTimeGte: dedupRingStart - 600,
		StartTimeLt:  dedupRingStart + 600,
	})
	require.NoError(t, err)
	var total int64
	for _, f := range flows {
		total += f.BytesIn
	}
	return total
}
