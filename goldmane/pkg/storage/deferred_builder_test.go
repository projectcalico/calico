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
	"unique"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

const builderInterval = 15

func builderTestFlow(windows int) (*storage.DiachronicFlow, *types.Flow) {
	k := types.NewFlowKey(
		&types.FlowKeySource{SourceName: "src", SourceNamespace: "default"},
		&types.FlowKeyDestination{DestName: "dst", DestNamespace: "default"},
		&types.FlowKeyMeta{Proto: "TCP", Reporter: proto.Reporter_Src, Action: proto.Action_Allow},
		&proto.PolicyTrace{},
	)
	f := &types.Flow{
		Key:          k,
		PacketsIn:    1,
		SourceLabels: unique.Make("app=src"),
		DestLabels:   unique.Make("app=dst"),
	}
	df := storage.NewDiachronicFlow(k, 1)
	for i := range windows {
		df.AddFlow(f, int64(i*builderInterval), int64((i+1)*builderInterval))
	}
	return df, f
}

func buildPackets(t *testing.T, fb storage.FlowBuilder) int64 {
	t.Helper()
	res := &proto.FlowResult{Flow: &proto.Flow{}}
	require.True(t, fb.BuildInto(nil, res), "expected the builder to produce a flow")
	return res.Flow.PacketsIn
}

func TestDeferredFlowBuilderSnapshotsWindow(t *testing.T) {
	df, f := builderTestFlow(3)
	start, end := int64(2*builderInterval), int64(3*builderInterval)

	before := storage.NewDeferredFlowBuilder(df, start, end)
	df.AddFlow(f, start, end)
	after := storage.NewDeferredFlowBuilder(df, start, end)

	require.Equal(t, int64(1), buildPackets(t, before), "builder should not see flows added after it was created")
	require.Equal(t, int64(2), buildPackets(t, after), "builder created after AddFlow should see the new flow")
}

func TestDeferredFlowBuilderNoWindowForBucket(t *testing.T) {
	df, _ := builderTestFlow(3)
	fb := storage.NewDeferredFlowBuilder(df, 10*builderInterval, 11*builderInterval)
	require.False(t, fb.BuildInto(nil, &proto.FlowResult{Flow: &proto.Flow{}}))
}

// Creating a builder must cost the same whether the flow has one window of history or a full ring.
func TestDeferredFlowBuilderAllocsIndependentOfHistory(t *testing.T) {
	allocs := map[int]float64{}
	for _, windows := range []int{1, 242} {
		df, _ := builderTestFlow(windows)
		start, end := int64((windows-1)*builderInterval), int64(windows*builderInterval)
		allocs[windows] = testing.AllocsPerRun(100, func() {
			_ = storage.NewDeferredFlowBuilder(df, start, end)
		})
	}
	require.Equal(t, allocs[1], allocs[242], "builder allocations should not grow with history")
	require.LessOrEqual(t, allocs[242], float64(1))
}
