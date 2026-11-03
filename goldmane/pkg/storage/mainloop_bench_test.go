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

package storage

import (
	"fmt"
	"strconv"
	"testing"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	simBuckets  = 242
	simInterval = 15
)

type simShape struct {
	flows int
	life  int
}

func (s simShape) String() string {
	return fmt.Sprintf("flows=%dk_life=%d", s.flows/1000, s.life)
}

var simShapes = []simShape{{flows: 50_000, life: 20}, {flows: 200_000, life: 20}}

type noopReceiver struct{}

func (noopReceiver) Receive(FlowProvider, string) {}

// ringSim drives a BucketRing at steady state: each bucket introduces rate new flow keys, and each key reports for life buckets.
type ringSim struct {
	ring *BucketRing
	now  int64
	rate int
	life int
	step int
	live [][]*types.FlowKey
}

func newRingSim(shape simShape) *ringSim {
	s := &ringSim{
		now:  1_000_005 - 1_000_005%simInterval,
		rate: shape.flows / (simBuckets + shape.life - 1),
		life: shape.life,
	}
	s.ring = NewBucketRing(
		simBuckets,
		simInterval,
		s.now,
		WithNowFunc(func() time.Time { return time.Unix(s.now, 0) }),
		WithStreamReceiver(noopReceiver{}),
		WithBucketsToAggregate(20),
		WithPushAfter(30),
	)
	return s
}

func (s *ringSim) newKey(id int) *types.FlowKey {
	return types.NewFlowKey(
		&types.FlowKeySource{SourceName: "src-" + strconv.Itoa(id%5000), SourceNamespace: "ns-" + strconv.Itoa(id%50), SourceType: proto.EndpointType_WorkloadEndpoint},
		&types.FlowKeyDestination{
			DestName:      "dst-" + strconv.Itoa(id),
			DestNamespace: "ns-" + strconv.Itoa(id%37),
			DestType:      proto.EndpointType_WorkloadEndpoint,
			DestPort:      int64(id % 1000),
		},
		&types.FlowKeyMeta{Proto: "TCP", Reporter: proto.Reporter_Src, Action: proto.Action_Allow},
		&proto.PolicyTrace{},
	)
}

// fill ingests one bucket's worth of flows at s.now.
func (s *ringSim) fill() {
	keys := make([]*types.FlowKey, s.rate)
	for i := range keys {
		keys[i] = s.newKey(s.step*s.rate + i)
	}
	s.live = append(s.live, keys)
	if len(s.live) > s.life {
		s.live = s.live[1:]
	}
	labels := unique.Make("app=a,env=prod")
	for _, keys := range s.live {
		for _, k := range keys {
			s.ring.AddFlow(FlowFromNode{Node: "node-1", Flow: &types.Flow{
				Key: k, StartTime: s.now, EndTime: s.now + simInterval,
				PacketsIn: 10, PacketsOut: 10, BytesIn: 100, BytesOut: 100,
				SourceLabels: labels, DestLabels: labels,
			}})
		}
	}
	s.step++
}

func (s *ringSim) advance() {
	s.ring.Rollover(nil)
	s.now += simInterval
}

var warmSims = map[simShape]*ringSim{}

// warmSim returns a ring that has run long enough for flows to expire every rollover, built once per shape.
func warmSim(shape simShape) *ringSim {
	if s, ok := warmSims[shape]; ok {
		return s
	}
	s := newRingSim(shape)
	for range simBuckets + s.life + 1 {
		s.fill()
		s.advance()
	}
	warmSims[shape] = s
	return s
}

// BenchmarkMainLoopRollover measures one rollover of a steady-state ring, which expires rate flows from every index.
func BenchmarkMainLoopRollover(b *testing.B) {
	logrus.SetLevel(logrus.ErrorLevel)
	for _, shape := range simShapes {
		s := warmSim(shape)
		b.Run(shape.String(), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				b.StopTimer()
				s.fill()
				b.StartTimer()
				s.advance()
			}
			b.ReportMetric(float64(len(s.ring.diachronics)), "flows")
		})
	}
}

// mainLoopQuery is a named query whose run returns how many results it got.
type mainLoopQuery struct {
	name string
	run  func() (int, error)
}

// BenchmarkMainLoopQuery measures the index-backed queries against a steady-state ring.
func BenchmarkMainLoopQuery(b *testing.B) {
	logrus.SetLevel(logrus.ErrorLevel)
	sortByDest := []*proto.SortOption{{SortBy: proto.SortBy_DestName}}
	for _, shape := range simShapes {
		s := warmSim(shape)
		gteAll, lt := s.ring.BeginningOfHistory(), s.now
		gte5m := s.now - 300
		queries := []mainLoopQuery{
			{"List_dest_all_p20", func() (int, error) {
				f, _, err := s.ring.List(&proto.FlowListRequest{StartTimeGte: gteAll, StartTimeLt: lt, PageSize: 20, SortBy: sortByDest})
				return len(f), err
			}},
			{"List_dest_5m_p20", func() (int, error) {
				f, _, err := s.ring.List(&proto.FlowListRequest{StartTimeGte: gte5m, StartTimeLt: lt, PageSize: 20, SortBy: sortByDest})
				return len(f), err
			}},
			{"Hints_destNS_all", func() (int, error) {
				v, _, err := s.ring.FilterHints(&proto.FilterHintsRequest{Type: proto.FilterType_FilterTypeDestNamespace, StartTimeGte: gteAll, StartTimeLt: lt})
				return len(v), err
			}},
		}
		for _, q := range queries {
			b.Run(shape.String()+"/"+q.name, func(b *testing.B) {
				b.ReportAllocs()
				var n int
				for b.Loop() {
					var err error
					if n, err = q.run(); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(n), "results")
			})
		}
	}
}
