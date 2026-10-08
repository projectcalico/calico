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
	"fmt"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const benchNow = 1000

func benchLabels(prefix string, i int) []string {
	out := make([]string, 0, 10)
	for j := range 10 {
		out = append(out, fmt.Sprintf("%s.example.com/key-%d=value-%d-%d", prefix, j, i%7, j))
	}
	return out
}

// benchFlow returns a distinct flow for each i, spread across ten namespaces.
func benchFlow(i int, start int64) *types.Flow {
	ns := fmt.Sprintf("ns-%d", i%10)
	hit := func(kind proto.PolicyKind, name, tier string, idx int64, a proto.Action) *proto.PolicyHit {
		return &proto.PolicyHit{Kind: kind, Name: name, Namespace: ns, Tier: tier, Action: a, PolicyIndex: idx, RuleIndex: 1}
	}
	return types.ProtoToFlow(&proto.Flow{
		Key: &proto.FlowKey{
			SourceName:           fmt.Sprintf("client-%d-*", i),
			SourceNamespace:      ns,
			SourceType:           proto.EndpointType_WorkloadEndpoint,
			DestName:             fmt.Sprintf("server-%d-*", i),
			DestNamespace:        ns,
			DestType:             proto.EndpointType_WorkloadEndpoint,
			DestPort:             8080,
			DestServiceName:      "svc",
			DestServiceNamespace: ns,
			DestServicePortName:  "http",
			DestServicePort:      80,
			Proto:                "tcp",
			Reporter:             proto.Reporter_Dst,
			Action:               proto.Action_Allow,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					hit(proto.PolicyKind_CalicoNetworkPolicy, "allow-frontend", "security", 0, proto.Action_Pass),
					hit(proto.PolicyKind_NetworkPolicy, "default-deny", "default", 1, proto.Action_Allow),
				},
				PendingPolicies: []*proto.PolicyHit{
					hit(proto.PolicyKind_CalicoNetworkPolicy, "staged-allow", "default", 0, proto.Action_Allow),
				},
			},
		},
		StartTime:             start,
		EndTime:               start + 1,
		SourceLabels:          benchLabels("src", i),
		DestLabels:            benchLabels("dst", i),
		PacketsIn:             10,
		PacketsOut:            20,
		BytesIn:               1000,
		BytesOut:              2000,
		NumConnectionsStarted: 1,
	})
}

// sentinel marks the end of a bucket, so consumers know when a backfill is done whether or
// not the producer filters.
type sentinel struct{}

var _ storage.FlowBuilder = sentinel{}

func (sentinel) BuildInto(*proto.Filter, *proto.FlowResult) bool {
	return false
}

type sentinelProvider struct{}

var _ storage.FlowProvider = sentinelProvider{}

func (sentinelProvider) Iter(_ *proto.Filter, fn func(storage.FlowBuilder) bool) {
	fn(sentinel{})
}

type benchFilter struct {
	name   string
	filter *proto.Filter
}

type benchConsumer struct {
	stream stream.Stream
	filter *proto.Filter
	done   chan struct{}
}

func (c *benchConsumer) run(ctx context.Context) {
	res := &proto.FlowResult{Flow: &proto.Flow{}}
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-c.stream.Flows():
			if f == nil {
				return
			}
			if _, ok := f.(sentinel); ok {
				c.done <- struct{}{}
				continue
			}
			if f.BuildInto(c.filter, res) {
				if _, err := googleproto.Marshal(res); err != nil {
					panic(err)
				}
			}
		}
	}
}

// BenchmarkStreamEndToEnd sends one bucket of flows to each stream through the real stream
// manager, and each consumer builds and marshals every flow it receives. One op is one bucket.
func BenchmarkStreamEndToEnd(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	const numFlows = 5000
	bucketStart := int64(benchNow - 3)

	filters := []benchFilter{
		{"nil", nil},
		{"empty", &proto.Filter{}},
		{"ns10pct", &proto.Filter{SourceNamespaces: []*proto.StringMatch{{Value: "ns-3", Type: proto.MatchType_Exact}}}},
	}

	for _, f := range filters {
		for _, numStreams := range []int{1, 4, 16} {
			b.Run(fmt.Sprintf("filter=%s/streams=%d", f.name, numStreams), func(b *testing.B) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				streams := stream.NewStreamManager()
				go streams.Run(ctx)

				clk := func() time.Time { return time.Unix(benchNow, 0) }
				ring := storage.NewBucketRing(20, 1, benchNow, storage.WithStreamReceiver(streams), storage.WithNowFunc(clk))
				for i := range numFlows {
					ring.AddFlow(storage.FlowFromNode{Flow: benchFlow(i, bucketStart)})
				}

				var consumers []*benchConsumer
				for range numStreams {
					s := <-streams.Register(&proto.FlowStreamRequest{Filter: f.filter}, 484)
					<-streams.Backfills()
					c := &benchConsumer{stream: s, filter: f.filter, done: make(chan struct{}, 1)}
					consumers = append(consumers, c)
					go c.run(ctx)
				}
				defer func() {
					for _, c := range consumers {
						c.stream.Close()
					}
				}()

				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					var wg sync.WaitGroup
					for _, c := range consumers {
						ring.Backfill(streams, c.stream.ID(), bucketStart)
						streams.Receive(sentinelProvider{}, c.stream.ID())
						wg.Go(func() { <-c.done })
					}
					wg.Wait()
				}
			})
		}
	}
}
