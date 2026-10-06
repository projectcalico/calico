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
	"math/rand/v2"
	"testing"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

var indexBenchSizes = []int{1_000, 10_000, 100_000}

// buildDiachronicFlows builds n flows with random names, so inserts land throughout the index rather than at the end.
func buildDiachronicFlows(n int, idOffset int64, rng *rand.Rand) []*DiachronicFlow {
	out := make([]*DiachronicFlow, n)
	for i := range n {
		k := types.NewFlowKey(
			&types.FlowKeySource{SourceName: fmt.Sprintf("src-%08d", rng.IntN(1<<30)), SourceNamespace: fmt.Sprintf("ns-%d", rng.IntN(50))},
			&types.FlowKeyDestination{DestName: fmt.Sprintf("dst-%08d", rng.IntN(1<<30)), DestNamespace: fmt.Sprintf("ns-%d", rng.IntN(50))},
			&types.FlowKeyMeta{Proto: "TCP", Reporter: proto.Reporter_Src, Action: proto.Action_Allow},
			&proto.PolicyTrace{},
		)
		d := NewDiachronicFlow(k, idOffset+int64(i))
		d.AddFlow(&types.Flow{Key: k, PacketsIn: 1, SourceLabels: unique.Make(""), DestLabels: unique.Make("")}, 0, 15)
		out[i] = d
	}
	return out
}

func buildIndex(n int, rng *rand.Rand) Index[string] {
	idx := NewIndex(func(k *types.FlowKey) string { return k.DestName() })
	for _, d := range buildDiachronicFlows(n, 0, rng) {
		idx.Add(d)
	}
	return idx
}

// BenchmarkIndexChurn measures one new flow key being added then expired, against an index already holding n keys.
func BenchmarkIndexChurn(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	for _, n := range indexBenchSizes {
		b.Run(fmt.Sprintf("%d_flows", n), func(b *testing.B) {
			rng := rand.New(rand.NewPCG(1, 2))
			idx := buildIndex(n, rng)
			extra := buildDiachronicFlows(1_000, int64(n), rng)
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				d := extra[i%len(extra)]
				idx.Add(d)
				idx.Remove(d)
				i++
			}
		})
	}
}

// BenchmarkIndexList measures listing the first page of 20 flows.
func BenchmarkIndexList(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	for _, n := range indexBenchSizes {
		b.Run(fmt.Sprintf("%d_flows", n), func(b *testing.B) {
			idx := buildIndex(n, rand.New(rand.NewPCG(1, 2)))
			b.ReportAllocs()
			for b.Loop() {
				idx.List(IndexFindOpts{startTimeGt: 0, startTimeLt: 15, pageSize: 20})
			}
		})
	}
}

// BenchmarkIndexSortValueSet measures reading the first page of 20 distinct sort values, as a filter hints call does.
func BenchmarkIndexSortValueSet(b *testing.B) {
	logrus.SetLevel(logrus.WarnLevel)
	for _, n := range indexBenchSizes {
		b.Run(fmt.Sprintf("%d_flows", n), func(b *testing.B) {
			idx := buildIndex(n, rand.New(rand.NewPCG(1, 2)))
			b.ReportAllocs()
			for b.Loop() {
				idx.SortValueSet(IndexFindOpts{startTimeGt: 0, startTimeLt: 15, pageSize: 20})
			}
		})
	}
}
