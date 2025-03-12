// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package types_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func setupTest(t *testing.T, opts ...aggregator.Option) func() {
	// Hook logrus into testing.T
	utils.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)
	return func() {
		logCancel()
	}
}

func TestDiachronicFlow(t *testing.T) {
	defer setupTest(t)()

	// Create a DF.
	k := types.FlowKey{}
	df := types.NewDiachronicFlow(&k)

	// Add flow data over a bunch of windows.
	f := types.Flow{
		PacketsIn:               1,
		PacketsOut:              2,
		BytesIn:                 3,
		BytesOut:                4,
		NumConnectionsLive:      5,
		NumConnectionsStarted:   6,
		NumConnectionsCompleted: 7,
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
		df.Rollover(int64(i + 1))
	}

	// Check aggregation across full range. We just rolled windows 0-200
	// out, so we should only have 200 left.
	af = df.Aggregate(0, 400)
	require.Equal(t, f.PacketsIn*200, af.PacketsIn)

	// Roll over the rest. Nothing should remain.
	df.Rollover(401)
	af = df.Aggregate(0, 400)
	require.Nil(t, af)
}
