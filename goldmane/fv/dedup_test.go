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

package fv

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/server"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	// dedupBucketSeconds matches Goldmane's default rollover, which the Redis backend
	// needs in order to compute the same bucket boundaries.
	dedupBucketSeconds = 15

	dedupBytesInPerFlow = 1000

	// dedupNodeIP is the peer address both connections come from, because a node keeps
	// its IP across a reconnect.
	dedupNodeIP = "192.168.1.5"
)

// TestDedupAcrossReconnect covers a node reconnecting to the same replica. The peer's
// ephemeral port changes, but the flows it replays are the ones already counted.
func TestDedupAcrossReconnect(t *testing.T) {
	start := alignedBucketStart()
	flows := dedupTestFlows(10, start)
	wantBytesIn := int64(len(flows) * dedupBytesInPerFlow)

	gm := goldmane.NewGoldmane()
	<-gm.Run(start)
	defer gm.Stop()
	collector := server.NewFlowCollector(gm)

	before := aggrReceivedFlows(t)
	require.NoError(t, collector.Connect(newReplayStream(dedupNodeIP, 45026, flows)))
	require.NoError(t, collector.Connect(newReplayStream(dedupNodeIP, 54148, flows)))
	waitForDedupIngest(t, before+float64(2*len(flows)))

	require.Equal(t, wantBytesIn, totalBytesIn(t, gm, start), "a replayed flow should not be counted twice")
}

// TestDedupIsPerNode fails if the reporting node is dropped from the claim, which would
// discard one node's copy of a flow that two nodes both report.
func TestDedupIsPerNode(t *testing.T) {
	start := alignedBucketStart()
	flows := dedupTestFlows(10, start)
	wantBytesIn := int64(2 * len(flows) * dedupBytesInPerFlow)

	gm := goldmane.NewGoldmane()
	<-gm.Run(start)
	defer gm.Stop()
	collector := server.NewFlowCollector(gm)

	before := aggrReceivedFlows(t)
	require.NoError(t, collector.Connect(newReplayStream("192.168.1.5", 45026, flows)))
	require.NoError(t, collector.Connect(newReplayStream("192.168.1.6", 45026, flows)))
	waitForDedupIngest(t, before+float64(2*len(flows)))

	require.Equal(t, wantBytesIn, totalBytesIn(t, gm, start), "a second node's flows should still be counted")
}

// totalBytesIn sums BytesIn across every flow the replica returns, so the assertion is on
// exact stats rather than on the flows being present.
func totalBytesIn(t *testing.T, gm *goldmane.Goldmane, start int64) int64 {
	t.Helper()
	res, err := gm.List(&proto.FlowListRequest{StartTimeGte: start - 60, StartTimeLt: start + 60})
	require.NoError(t, err)
	var total int64
	for _, f := range res.Flows {
		total += f.Flow.BytesIn
	}
	return total
}

// alignedBucketStart mirrors what storage.GetStartTime does in the daemon. Bucket
// boundaries derive from the ring's start time, so an unaligned start would write keys the
// Redis backend never reads back.
func alignedBucketStart() int64 {
	now := time.Now().Unix()
	return now - now%dedupBucketSeconds
}

// dedupTestFlows builds one flow per key with fixed stats, all landing in the same bucket.
func dedupTestFlows(n int, bucketStart int64) []*proto.Flow {
	flows := make([]*proto.Flow, 0, n)
	for i := range n {
		flows = append(flows, &proto.Flow{
			Key: &proto.FlowKey{
				SourceName:      fmt.Sprintf("client-%d", i),
				SourceNamespace: "dedup-ns",
				SourceType:      proto.EndpointType_WorkloadEndpoint,
				DestName:        fmt.Sprintf("server-%d", i),
				DestNamespace:   "dedup-ns",
				DestType:        proto.EndpointType_WorkloadEndpoint,
				DestPort:        8080,
				Proto:           "tcp",
				Reporter:        proto.Reporter_Src,
				Action:          proto.Action_Allow,
				Policies:        &proto.PolicyTrace{},
			},
			StartTime:               bucketStart,
			EndTime:                 bucketStart + dedupBucketSeconds,
			SourceLabels:            []string{"app=dedup"},
			DestLabels:              []string{"app=dedup"},
			PacketsIn:               10,
			PacketsOut:              10,
			BytesIn:                 dedupBytesInPerFlow,
			BytesOut:                1000,
			NumConnectionsStarted:   1,
			NumConnectionsCompleted: 1,
		})
	}
	return flows
}

// replayStream replays a fixed set of updates as though they arrived over one connection
// from the given node address.
type replayStream struct {
	grpc.ServerStream

	ctx     context.Context
	updates []*proto.FlowUpdate
	idx     int
}

func newReplayStream(ip string, port int, flows []*proto.Flow) *replayStream {
	updates := make([]*proto.FlowUpdate, 0, len(flows))
	for _, f := range flows {
		updates = append(updates, &proto.FlowUpdate{Flow: f})
	}
	addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
	return &replayStream{
		ctx:     peer.NewContext(context.Background(), &peer.Peer{Addr: addr}),
		updates: updates,
	}
}

func (s *replayStream) Context() context.Context {
	return s.ctx
}

func (s *replayStream) Send(*proto.FlowReceipt) error {
	return nil
}

func (s *replayStream) Recv() (*proto.FlowUpdate, error) {
	if s.idx >= len(s.updates) {
		return nil, io.EOF
	}
	upd := s.updates[s.idx]
	s.idx++
	return upd, nil
}

// waitForDedupIngest blocks until the aggregators have indexed up to target flows. Receive
// only queues, so a List issued before the main loop drains would read a half-written bucket.
func waitForDedupIngest(t *testing.T, target float64) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for aggrReceivedFlows(t) < target {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for ingest to drain: %v of %v", aggrReceivedFlows(t), target)
		}
		time.Sleep(time.Millisecond)
	}
}

// aggrReceivedFlows reads the aggregator's received counter off the default gatherer. The
// counter is unexported, and it is the only signal for when a flow is actually indexed.
func aggrReceivedFlows(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != "goldmane_aggr_received_flows_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			return m.GetCounter().GetValue()
		}
	}
	return 0
}
