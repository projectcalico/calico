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

package storage_test

import (
	"net"
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

// TestDiachronicFlow_IPSets verifies that source / destination IP sets are unioned and
// deduplicated as flows are added to a window and aggregated across windows.
func TestDiachronicFlow_IPSets(t *testing.T) {
	defer setupTest(t)()

	k := types.NewFlowKey(
		&types.FlowKeySource{},
		&types.FlowKeyDestination{},
		&types.FlowKeyMeta{},
		&proto.PolicyTrace{},
	)
	df := storage.NewDiachronicFlow(k, 0)

	// Two flows in the same window, with overlapping source IPs and distinct dest IPs.
	df.AddFlow(&types.Flow{
		Key:          k,
		SourceLabels: unique.Make(""),
		DestLabels:   unique.Make(""),
		SourceIps:    []string{"10.0.0.1", "10.0.0.2"},
		DestIps:      []string{"192.168.0.1"},
	}, 0, 1)
	df.AddFlow(&types.Flow{
		Key:          k,
		SourceLabels: unique.Make(""),
		DestLabels:   unique.Make(""),
		SourceIps:    []string{"10.0.0.2", "10.0.0.3"},
		DestIps:      []string{"192.168.0.2"},
	}, 0, 1)

	af := df.Aggregate(0, 1)
	require.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, af.SourceIps, "source IPs should be unioned and deduplicated")
	require.Equal(t, []string{"192.168.0.1", "192.168.0.2"}, af.DestIps, "dest IPs should be unioned")

	// A flow in a different window contributes additional IPs that must merge on aggregation.
	df.AddFlow(&types.Flow{
		Key:          k,
		SourceLabels: unique.Make(""),
		DestLabels:   unique.Make(""),
		SourceIps:    []string{"10.0.0.4"},
		DestIps:      []string{"192.168.0.1"},
	}, 1, 2)

	af = df.Aggregate(0, 2)
	require.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, af.SourceIps)
	require.Equal(t, []string{"192.168.0.1", "192.168.0.2"}, af.DestIps)
}

// TestDiachronicFlow_IPSetCap verifies the per-flow IP set is capped at MaxIPsPerFlow.
func TestDiachronicFlow_IPSetCap(t *testing.T) {
	defer setupTest(t)()

	k := types.NewFlowKey(
		&types.FlowKeySource{},
		&types.FlowKeyDestination{},
		&types.FlowKeyMeta{},
		&proto.PolicyTrace{},
	)
	df := storage.NewDiachronicFlow(k, 0)

	// Add far more distinct source IPs than the cap allows.
	manyIPs := make([]string, storage.MaxIPsPerFlow*2)
	for i := range manyIPs {
		manyIPs[i] = net.IP{10, byte(i >> 16), byte(i >> 8), byte(i)}.String()
	}
	df.AddFlow(&types.Flow{
		Key:          k,
		SourceLabels: unique.Make(""),
		DestLabels:   unique.Make(""),
		SourceIps:    manyIPs,
	}, 0, 1)

	af := df.Aggregate(0, 1)
	require.Len(t, af.SourceIps, storage.MaxIPsPerFlow, "source IP set should be truncated to the cap")
}

const ipTestInterval = 15

func ipTestFlowKey() *types.FlowKey {
	return types.NewFlowKey(
		&types.FlowKeySource{},
		&types.FlowKeyDestination{},
		&types.FlowKeyMeta{},
		&proto.PolicyTrace{},
	)
}

// addIPs adds a flow carrying the given source IPs to window i of df.
func addIPs(df *storage.DiachronicFlow, k *types.FlowKey, i int, srcIPs ...string) {
	start := int64(i * ipTestInterval)
	df.AddFlow(&types.Flow{
		Key:          k,
		SourceLabels: unique.Make(""),
		DestLabels:   unique.Make(""),
		SourceIps:    srcIPs,
	}, start, start+ipTestInterval)
}

// distinctIPs returns n distinct IPv4 addresses, offset so different calls can avoid overlap.
func distinctIPs(offset, n int) []string {
	ips := make([]string, n)
	for i := range ips {
		v := offset + i
		ips[i] = net.IP{10, byte(v >> 16), byte(v >> 8), byte(v)}.String()
	}
	return ips
}

// TestDiachronicFlow_IPSetCapIsPerKey verifies the cap bounds the IPs retained across all of a
// flow's windows, not per window, and that the most recently seen addresses win.
func TestDiachronicFlow_IPSetCapIsPerKey(t *testing.T) {
	defer setupTest(t)()

	k := ipTestFlowKey()
	df := storage.NewDiachronicFlow(k, 0)

	// A full cap's worth of distinct IPs in each of 5 windows.
	for i := range 5 {
		addIPs(df, k, i, distinctIPs(i*storage.MaxIPsPerFlow, storage.MaxIPsPerFlow)...)
	}

	af := df.Aggregate(0, 5*ipTestInterval)
	require.Len(t, af.SourceIps, storage.MaxIPsPerFlow, "cap should apply across all windows of the key")

	newest := distinctIPs(4*storage.MaxIPsPerFlow, storage.MaxIPsPerFlow)
	require.ElementsMatch(t, newest, af.SourceIps, "the newest window's IPs should have evicted older ones")

	// Older windows no longer report any IPs, since all their addresses were evicted.
	require.Empty(t, df.Aggregate(0, ipTestInterval).SourceIps)
}

// TestDiachronicFlow_IPSetTimeRange verifies a range query returns only the IPs seen in that range.
func TestDiachronicFlow_IPSetTimeRange(t *testing.T) {
	defer setupTest(t)()

	k := ipTestFlowKey()
	df := storage.NewDiachronicFlow(k, 0)

	addIPs(df, k, 0, "10.0.0.1")
	addIPs(df, k, 1, "10.0.0.2")
	addIPs(df, k, 2, "10.0.0.1", "10.0.0.3")

	require.Equal(t, []string{"10.0.0.1"}, df.Aggregate(0, ipTestInterval).SourceIps)
	require.Equal(t, []string{"10.0.0.2"}, df.Aggregate(ipTestInterval, 2*ipTestInterval).SourceIps)
	require.Equal(t, []string{"10.0.0.1", "10.0.0.3"}, df.Aggregate(2*ipTestInterval, 3*ipTestInterval).SourceIps)
	require.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, df.Aggregate(0, 3*ipTestInterval).SourceIps)
}

// TestDiachronicFlow_IPSetRollover verifies IPs are dropped once every window they were seen in has
// expired, and retained while any such window is still live.
func TestDiachronicFlow_IPSetRollover(t *testing.T) {
	defer setupTest(t)()

	k := ipTestFlowKey()
	df := storage.NewDiachronicFlow(k, 0)

	addIPs(df, k, 0, "10.0.0.1", "10.0.0.2")
	addIPs(df, k, 1, "10.0.0.2")

	// Expire window 0. 10.0.0.1 was only seen there; 10.0.0.2 is still live in window 1.
	df.Rollover(ipTestInterval)
	require.Equal(t, []string{"10.0.0.2"}, df.Aggregate(0, 2*ipTestInterval).SourceIps)

	// Re-adding 10.0.0.1 to a new window must not resurrect its expired window.
	addIPs(df, k, 2, "10.0.0.1")
	require.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, df.Aggregate(0, 3*ipTestInterval).SourceIps)
	require.Equal(t, []string{"10.0.0.2"}, df.Aggregate(ipTestInterval, 2*ipTestInterval).SourceIps)

	// Expire everything.
	df.Rollover(3 * ipTestInterval)
	require.True(t, df.Empty())
	addIPs(df, k, 3)
	require.Empty(t, df.Aggregate(0, 4*ipTestInterval).SourceIps)
}

// TestDiachronicFlow_IPSetLateArrival verifies that, once the set is full, an IP arriving for a
// window older than everything retained is dropped rather than evicting newer data.
func TestDiachronicFlow_IPSetLateArrival(t *testing.T) {
	defer setupTest(t)()

	k := ipTestFlowKey()
	df := storage.NewDiachronicFlow(k, 0)

	addIPs(df, k, 5, distinctIPs(0, storage.MaxIPsPerFlow)...)
	addIPs(df, k, 1, "192.168.0.1")

	af := df.Aggregate(0, 6*ipTestInterval)
	require.Len(t, af.SourceIps, storage.MaxIPsPerFlow)
	require.NotContains(t, af.SourceIps, "192.168.0.1")
}

// TestDiachronicFlow_DestIPSetTimeRange verifies destination IPs follow the same per-window
// tracking and rollover as source IPs.
func TestDiachronicFlow_DestIPSetTimeRange(t *testing.T) {
	defer setupTest(t)()

	k := ipTestFlowKey()
	df := storage.NewDiachronicFlow(k, 0)

	for i, ip := range []string{"192.168.0.1", "192.168.0.2"} {
		start := int64(i * ipTestInterval)
		df.AddFlow(&types.Flow{
			Key:          k,
			SourceLabels: unique.Make(""),
			DestLabels:   unique.Make(""),
			DestIps:      []string{ip},
		}, start, start+ipTestInterval)
	}

	require.Equal(t, []string{"192.168.0.1"}, df.Aggregate(0, ipTestInterval).DestIps)
	require.Equal(t, []string{"192.168.0.1", "192.168.0.2"}, df.Aggregate(0, 2*ipTestInterval).DestIps)

	df.Rollover(ipTestInterval)
	require.Equal(t, []string{"192.168.0.2"}, df.Aggregate(0, 2*ipTestInterval).DestIps)
}

// TestDeferredFlowBuilder_IPSnapshot verifies the builder captures the IPs at construction, so later
// changes to the DiachronicFlow (made by the main loop) don't leak into a flow being streamed.
func TestDeferredFlowBuilder_IPSnapshot(t *testing.T) {
	defer setupTest(t)()

	k := ipTestFlowKey()
	df := storage.NewDiachronicFlow(k, 0)
	addIPs(df, k, 0, "10.0.0.1")

	b := storage.NewDeferredFlowBuilder(df, 0, ipTestInterval)

	// Mutate the flow after the builder was created.
	addIPs(df, k, 0, "10.0.0.2")

	res := &proto.FlowResult{Flow: &proto.Flow{}}
	require.True(t, b.BuildInto(nil, res))
	require.Equal(t, []string{"10.0.0.1"}, res.Flow.SourceIps)
}

// TestDiachronicFlow_IPSetEvictionKeepsRefreshedHistory verifies that, when the set is full, an IP
// present in the incoming flow is refreshed before any eviction, so a new IP earlier in the same
// flow cannot evict it and wipe its history from earlier windows.
func TestDiachronicFlow_IPSetEvictionKeepsRefreshedHistory(t *testing.T) {
	defer setupTest(t)()

	k := ipTestFlowKey()
	df := storage.NewDiachronicFlow(k, 0)

	// Window 0: "10.0.0.0" becomes the oldest entry. Window 1 fills the rest of the set.
	addIPs(df, k, 0, "10.0.0.0")
	addIPs(df, k, 1, distinctIPs(1, storage.MaxIPsPerFlow-1)...)

	// Window 2: a new IP listed before the oldest existing one.
	addIPs(df, k, 2, "192.168.0.1", "10.0.0.0")

	require.Contains(t, df.Aggregate(0, ipTestInterval).SourceIps, "10.0.0.0",
		"re-seen IP must keep its window 0 history")
	require.Contains(t, df.Aggregate(2*ipTestInterval, 3*ipTestInterval).SourceIps, "192.168.0.1")
}

func TestDiachronicFlow_IPSetEvictionSameWindowTie(t *testing.T) {
	defer setupTest(t)()

	for _, tc := range []struct {
		name string
		ips  []string
	}{
		{name: "new IP first", ips: []string{"10.0.0.0", "10.0.0.1"}},
		{name: "retained IP first", ips: []string{"10.0.0.1", "10.0.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := ipTestFlowKey()
			df := storage.NewDiachronicFlow(k, 0)
			add := func(window int, ips ...string) {
				start := int64(window * ipTestInterval)
				df.AddFlow(&types.Flow{
					Key:          k,
					SourceLabels: unique.Make(""),
					DestLabels:   unique.Make(""),
					SourceIps:    ips,
					DestIps:      ips,
				}, start, start+ipTestInterval)
			}

			add(0, "10.0.0.1")
			add(1, distinctIPs(2, storage.MaxIPsPerFlow-1)...)
			// Refreshing the retained IP makes every entry equally recent. The new,
			// lower address should be dropped without erasing the retained IP's history.
			add(1, tc.ips...)
			historical := df.Aggregate(0, ipTestInterval)
			require.Equal(t, []string{"10.0.0.1"}, historical.SourceIps)
			require.Equal(t, historical.SourceIps, historical.DestIps)
			current := df.Aggregate(ipTestInterval, 2*ipTestInterval)
			require.Len(t, current.SourceIps, storage.MaxIPsPerFlow)
			require.Contains(t, current.SourceIps, "10.0.0.1")
			require.NotContains(t, current.SourceIps, "10.0.0.0")
			require.Equal(t, current.SourceIps, current.DestIps)

			// A higher address at the same timestamp should still replace the lowest one.
			add(1, "192.0.2.1")
			current = df.Aggregate(ipTestInterval, 2*ipTestInterval)
			require.Len(t, current.SourceIps, storage.MaxIPsPerFlow)
			require.Contains(t, current.SourceIps, "192.0.2.1")
			require.NotContains(t, current.SourceIps, "10.0.0.1")
			require.Equal(t, current.SourceIps, current.DestIps)
			historical = df.Aggregate(0, ipTestInterval)
			require.Empty(t, historical.SourceIps)
			require.Empty(t, historical.DestIps)
		})
	}
}

// BenchmarkDiachronicFlow_AddFlowDuplicateIPs checks that a flow with many duplicate addresses doesn't
// size the IP set by its input length rather than by MaxIPsPerFlow.
func BenchmarkDiachronicFlow_AddFlowDuplicateIPs(b *testing.B) {
	k := ipTestFlowKey()
	ips := make([]string, 100_000)
	for i := range ips {
		ips[i] = "10.0.0.1"
	}
	f := &types.Flow{Key: k, SourceLabels: unique.Make(""), DestLabels: unique.Make(""), SourceIps: ips}
	b.ReportAllocs()
	for b.Loop() {
		storage.NewDiachronicFlow(k, 0).AddFlow(f, 0, ipTestInterval)
	}
}
