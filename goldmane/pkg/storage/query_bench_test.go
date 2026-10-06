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
	"fmt"
	"strconv"
	"sync"
	"testing"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	queryBenchBuckets  = 242
	queryBenchInterval = 15

	// queryBenchFlows is roughly how many distinct flows the ring holds at steady state.
	queryBenchFlows = 100_000

	// queryBenchLife is how many consecutive buckets each flow reports into.
	queryBenchLife = 20
)

type noopReceiver struct{}

func (noopReceiver) Receive(storage.FlowProvider, string) {}

// queryBenchRing is a ring at steady state, where each bucket brings in a batch of new flow keys
// and every key keeps reporting for queryBenchLife buckets.
type queryBenchRing struct {
	ring *storage.BucketRing
	now  int64
}

// sharedQueryBenchRing builds the ring once per process, so -count reuses it.
var sharedQueryBenchRing = sync.OnceValue(newQueryBenchRing)

func newQueryBenchRing() *queryBenchRing {
	q := &queryBenchRing{now: 1_000_005 - 1_000_005%queryBenchInterval}
	q.ring = storage.NewBucketRing(
		queryBenchBuckets,
		queryBenchInterval,
		q.now,
		storage.WithNowFunc(func() time.Time { return time.Unix(q.now, 0) }),
		storage.WithStreamReceiver(noopReceiver{}),
	)

	var policies []*proto.PolicyTrace
	for p := range 40 {
		policies = append(policies, &proto.PolicyTrace{
			EnforcedPolicies: []*proto.PolicyHit{
				{Kind: proto.PolicyKind_CalicoNetworkPolicy, Namespace: fmt.Sprintf("ns-%d", p%20), Name: fmt.Sprintf("pol-%d", p), Tier: "default", Action: proto.Action_Allow, RuleIndex: int64(p % 3)},
				{Kind: proto.PolicyKind_GlobalNetworkPolicy, Name: fmt.Sprintf("gnp-%d", p%7), Tier: "security", Action: proto.Action_Pass, PolicyIndex: 1},
			},
		})
	}

	labels := unique.Make("app=a,env=prod")
	rate := queryBenchFlows / (queryBenchBuckets + queryBenchLife - 1)
	var live [][]*types.FlowKey
	for step := range queryBenchBuckets + queryBenchLife + 1 {
		batch := make([]*types.FlowKey, rate)
		for i := range batch {
			id := step*rate + i
			batch[i] = types.NewFlowKey(
				&types.FlowKeySource{SourceName: "src-" + strconv.Itoa(id%5000), SourceNamespace: "ns-" + strconv.Itoa(id%50), SourceType: proto.EndpointType_WorkloadEndpoint},
				&types.FlowKeyDestination{DestName: "dst-" + strconv.Itoa(id), DestNamespace: "ns-" + strconv.Itoa(id%37), DestType: proto.EndpointType_WorkloadEndpoint, DestPort: int64(id % 1000)},
				&types.FlowKeyMeta{Proto: "TCP", Reporter: proto.Reporter_Src, Action: proto.Action_Allow},
				policies[id%len(policies)],
			)
		}
		live = append(live, batch)
		if len(live) > queryBenchLife {
			live = live[1:]
		}
		for _, keys := range live {
			for _, k := range keys {
				q.ring.AddFlow(storage.FlowFromNode{Node: "node-1", Flow: &types.Flow{
					Key: k, StartTime: q.now, EndTime: q.now + queryBenchInterval,
					PacketsIn: 10, PacketsOut: 10, BytesIn: 100, BytesOut: 100,
					SourceLabels: labels, DestLabels: labels,
				}})
			}
		}
		q.ring.Rollover(nil)
		q.now += queryBenchInterval
	}
	return q
}

type queryBenchCase struct {
	name string
	run  func() int
}

// BenchmarkRingQuery measures time-sorted list and policy hint queries against a full ring,
// at the Info log level that Goldmane runs at by default.
func BenchmarkRingQuery(b *testing.B) {
	logrus.SetLevel(logrus.InfoLevel)
	q := sharedQueryBenchRing()
	r := q.ring
	gteAll, lt := r.BeginningOfHistory(), q.now
	gte5m := q.now - 300
	nsFilter := &proto.Filter{DestNamespaces: []*proto.StringMatch{{Value: "ns-3", Type: proto.MatchType_Exact}}}

	list := func(req *proto.FlowListRequest) int {
		flows, _, err := r.List(req)
		if err != nil {
			b.Fatal(err)
		}
		return len(flows)
	}
	for _, c := range []queryBenchCase{
		{"List_time_all_p20", func() int {
			return list(&proto.FlowListRequest{StartTimeGte: gteAll, StartTimeLt: lt, PageSize: 20})
		}},
		{"List_time_5m_p20", func() int {
			return list(&proto.FlowListRequest{StartTimeGte: gte5m, StartTimeLt: lt, PageSize: 20})
		}},
		{"List_time_all_p20_nsfilter", func() int {
			return list(&proto.FlowListRequest{StartTimeGte: gteAll, StartTimeLt: lt, PageSize: 20, Filter: nsFilter})
		}},
		{"Hints_policyName_all", func() int {
			values, _, err := r.FilterHints(&proto.FilterHintsRequest{Type: proto.FilterType_FilterTypePolicyName, StartTimeGte: gteAll, StartTimeLt: lt})
			if err != nil {
				b.Fatal(err)
			}
			return len(values)
		}},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			var n int
			for b.Loop() {
				n = c.run()
			}
			b.ReportMetric(float64(n), "results")
		})
	}
}
