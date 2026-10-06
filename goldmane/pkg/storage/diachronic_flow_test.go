// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/logrusr"
)

func setupTest(t *testing.T) func() {
	// Hook logrus into testing.T
	utils.ConfigureLogging("DEBUG")
	logCancel := logrusr.RedirectLogrusToTestingT(t)
	return func() {
		logCancel()
	}
}

func TestDiachronicFlow(t *testing.T) {
	defer setupTest(t)()

	// Create a DF. The specifics of the key don't matter for this test.
	k := types.NewFlowKey(
		&types.FlowKeySource{},
		&types.FlowKeyDestination{},
		&types.FlowKeyMeta{},
		&proto.PolicyTrace{},
	)
	df := storage.NewDiachronicFlow(k, 0)

	// Add flow data over a bunch of windows.
	f := types.Flow{
		Key:                     k,
		PacketsIn:               1,
		PacketsOut:              2,
		BytesIn:                 3,
		BytesOut:                4,
		NumConnectionsLive:      5,
		NumConnectionsStarted:   6,
		NumConnectionsCompleted: 7,
		SourceLabels:            unique.Make("source"),
		DestLabels:              unique.Make("dest"),
	}
	for i := range 400 {
		df.AddFlow(&f, int64(i), int64(i+1))
	}

	// Check aggregation across full range.
	af := df.Aggregate(0, 400)
	require.Equal(t, f.PacketsIn*400, af.PacketsIn)
	require.Equal(t, f.PacketsOut*400, af.PacketsOut)
	require.Equal(t, f.BytesIn*400, af.BytesIn)
	require.Equal(t, f.BytesOut*400, af.BytesOut)
	require.Equal(t, f.NumConnectionsLive*400, af.NumConnectionsLive)
	require.Equal(t, f.NumConnectionsStarted*400, af.NumConnectionsStarted)
	require.Equal(t, f.NumConnectionsCompleted*400, af.NumConnectionsCompleted)

	// Aggregate across a subset of the range.
	af = df.Aggregate(100, 200)
	require.Equal(t, f.PacketsIn*100, af.PacketsIn)
	require.Equal(t, f.PacketsOut*100, af.PacketsOut)
	require.Equal(t, f.BytesIn*100, af.BytesIn)
	require.Equal(t, f.BytesOut*100, af.BytesOut)
	require.Equal(t, f.NumConnectionsLive*100, af.NumConnectionsLive)
	require.Equal(t, f.NumConnectionsStarted*100, af.NumConnectionsStarted)
	require.Equal(t, f.NumConnectionsCompleted*100, af.NumConnectionsCompleted)

	// Aggregate across a superset of the range.
	af = df.Aggregate(-100, 500)
	require.Equal(t, f.PacketsIn*400, af.PacketsIn)

	// Rollover a few times.
	for i := range 200 {
		require.False(t, df.Rollover(int64(i+1)), "windows remain after rolling over to %d", i+1)
	}

	// Check aggregation across full range. We just rolled windows 0-200
	// out, so we should only have 200 left.
	af = df.Aggregate(0, 400)
	require.Equal(t, f.PacketsIn*200, af.PacketsIn)

	// Roll over the rest. Nothing should remain.
	require.True(t, df.Rollover(401), "no windows remain after the last rollover")
	af = df.Aggregate(0, 400)
	require.Nil(t, af)
}

// TestDiachronicFlowRangeMatchesLinearScan checks the searched range lookups against a scan of
// the windows the flow was given, across gapped histories and open, empty or partial ranges.
func TestDiachronicFlowRangeMatchesLinearScan(t *testing.T) {
	k := types.NewFlowKey(&types.FlowKeySource{}, &types.FlowKeyDestination{}, &types.FlowKeyMeta{}, &proto.PolicyTrace{})
	labels := unique.Make("")
	var withinCases, outsideCases int
	for seed := range 2000 {
		df := storage.NewDiachronicFlow(k, 1)
		var added []scanWindow
		for b := range 30 {
			if (seed*7+b*13)%3 == 0 {
				continue
			}
			w := scanWindow{start: int64(1000 + b*15), end: int64(1015 + b*15), packets: int64(b + 1)}
			df.AddFlow(&types.Flow{Key: k, PacketsIn: w.packets, SourceLabels: labels, DestLabels: labels}, w.start, w.end)
			added = append(added, w)
		}
		var gte, lt int64
		if seed%5 != 0 {
			gte = int64(990 + (seed*31)%480)
		}
		if seed%7 != 0 {
			lt = gte + int64((seed*17)%500)
		}

		want := scanRange(added, gte, lt)
		if want.within {
			withinCases++
		} else {
			outsideCases++
		}

		start, within := df.SortStartTime(gte, lt)
		require.Equal(t, want.within, within, "seed %d [%d, %d): SortStartTime", seed, gte, lt)
		require.Equal(t, want.within, df.Within(gte, lt), "seed %d [%d, %d): Within", seed, gte, lt)
		require.Equal(t, want.start, start, "seed %d [%d, %d): start", seed, gte, lt)

		f := df.Aggregate(gte, lt)
		if !want.within {
			require.Nil(t, f, "seed %d [%d, %d)", seed, gte, lt)
			continue
		}
		require.NotNil(t, f, "seed %d [%d, %d)", seed, gte, lt)
		require.Equal(t, want.start, f.StartTime, "seed %d [%d, %d): aggregated start", seed, gte, lt)
		require.Equal(t, want.packets, f.PacketsIn, "seed %d [%d, %d): packets", seed, gte, lt)
	}
	require.NotZero(t, withinCases)
	require.NotZero(t, outsideCases)
}

type scanWindow struct {
	start, end, packets int64
}

type scanResult struct {
	within         bool
	start, packets int64
}

// scanRange applies Within's rule (a window starts in the range) and Aggregate's rule (a window
// lies wholly in it) to every window, a zero bound being open.
func scanRange(windows []scanWindow, gte, lt int64) scanResult {
	var r scanResult
	for _, w := range windows {
		if (gte == 0 || w.start >= gte) && (lt == 0 || w.start < lt) {
			r.within = true
		}
		if (gte == 0 || w.start >= gte) && (lt == 0 || w.end <= lt) {
			if r.start == 0 {
				r.start = w.start
			}
			r.packets += w.packets
		}
	}
	return r
}
