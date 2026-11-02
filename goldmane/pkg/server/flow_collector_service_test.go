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

package server

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// recordingSink keeps every flow it is handed, so a test can count duplicates rather
// than just check for presence.
type recordingSink struct {
	flows []*types.Flow
}

func (s *recordingSink) Receive(f *types.Flow) {
	s.flows = append(s.flows, f)
}

// clientStream replays a fixed set of updates as though they arrived over one connection
// from the given address.
type clientStream struct {
	grpc.ServerStream

	ctx     context.Context
	updates []*proto.FlowUpdate
	idx     int
}

func newClientStream(ip string, port int, flows []*proto.Flow) *clientStream {
	updates := make([]*proto.FlowUpdate, 0, len(flows))
	for _, f := range flows {
		updates = append(updates, &proto.FlowUpdate{Flow: f})
	}
	addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
	return &clientStream{
		ctx:     peer.NewContext(context.Background(), &peer.Peer{Addr: addr}),
		updates: updates,
	}
}

func (s *clientStream) Context() context.Context {
	return s.ctx
}

func (s *clientStream) Send(*proto.FlowReceipt) error {
	return nil
}

func (s *clientStream) Recv() (*proto.FlowUpdate, error) {
	if s.idx >= len(s.updates) {
		return nil, io.EOF
	}
	upd := s.updates[s.idx]
	s.idx++
	return upd, nil
}

func testFlows(n int) []*proto.Flow {
	flows := make([]*proto.Flow, 0, n)
	for i := range n {
		flows = append(flows, testutils.NewRandomFlow(int64(i*15)))
	}
	return flows
}

// TestDedupAcrossReconnect covers a Felix reconnect: the node keeps its IP but gets a new
// ephemeral port, and replays the flows it already sent.
func TestDedupAcrossReconnect(t *testing.T) {
	sink := &recordingSink{}
	collector := NewFlowCollector(sink)
	flows := testFlows(10)

	require.NoError(t, collector.Connect(newClientStream("192.168.1.5", 45026, flows)))
	require.Len(t, sink.flows, 10, "first connection should deliver every flow")

	require.NoError(t, collector.Connect(newClientStream("192.168.1.5", 54148, flows)))
	require.Len(t, sink.flows, 10, "replay after reconnect should be deduplicated")
}

func TestDedupWithinConnection(t *testing.T) {
	sink := &recordingSink{}
	collector := NewFlowCollector(sink)
	flows := testFlows(10)
	doubled := append(append([]*proto.Flow{}, flows...), flows...)

	require.NoError(t, collector.Connect(newClientStream("192.168.1.5", 45026, doubled)))
	require.Len(t, sink.flows, 10, "duplicates on one connection should be deduplicated")
}

// TestDedupIsPerNode fails if the scope is dropped from the cache key altogether, which
// would satisfy the two tests above while discarding one node's copy of a flow that two
// nodes legitimately both report.
func TestDedupIsPerNode(t *testing.T) {
	sink := &recordingSink{}
	collector := NewFlowCollector(sink)
	flows := testFlows(10)

	require.NoError(t, collector.Connect(newClientStream("192.168.1.5", 45026, flows)))
	require.NoError(t, collector.Connect(newClientStream("192.168.1.6", 45026, flows)))
	require.Len(t, sink.flows, 20, "flows from a second node should not be deduplicated")
}
