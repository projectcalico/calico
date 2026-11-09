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
	"math"
	"slices"
	"strings"
	"testing"
	"unique"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	pagingInterval  = 15
	pagingRingStart = int64(1000005)
)

// TestRingListPagesTiedStartTimes pages through flows that mostly share one start time, which
// is the normal case since starts are bucket-aligned. Every flow must appear once, in the same
// order on every pass through the pages.
func TestRingListPagesTiedStartTimes(t *testing.T) {
	ring := newPagingRing()
	newer := ring.EndOfHistory() - 2*pagingInterval
	older := newer - pagingInterval

	const numNewer, numOlder = 60, 10
	for i := range numOlder {
		ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("older-%d", i), older)})
	}
	for i := range numNewer {
		ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("newer-%d", i), newer)})
	}

	req := &proto.FlowListRequest{StartTimeGte: older, StartTimeLt: newer + pagingInterval, PageSize: 7}
	first := allPages(t, ring, req)
	require.Len(t, first, numNewer+numOlder)

	seen := map[string]bool{}
	for _, f := range first {
		require.False(t, seen[f.Key.DestName()], "flow %s returned on more than one page", f.Key.DestName())
		seen[f.Key.DestName()] = true
	}

	// Newer flows come first, and ties are ordered by flow ID, newest first.
	for i := 1; i < len(first); i++ {
		prev, cur := first[i-1], first[i]
		require.GreaterOrEqual(t, prev.StartTime, cur.StartTime, "flows out of time order at %d", i)
		if prev.StartTime == cur.StartTime {
			require.Greater(t, ring.ID(*prev.Key), ring.ID(*cur.Key), "tied flows out of ID order at %d", i)
		}
	}
	require.Equal(t, newer, first[0].StartTime)
	require.Equal(t, older, first[len(first)-1].StartTime)

	for range 5 {
		require.Equal(t, keyNames(first), keyNames(allPages(t, ring, req)))
	}
}

// TestRingListPartialBucket pins how a flow whose only window ends past StartTimeLt is listed:
// it matches, but aggregates nothing, so it sorts last with a zero start time.
func TestRingListPartialBucket(t *testing.T) {
	ring := newPagingRing()
	start := ring.EndOfHistory() - 2*pagingInterval
	ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow("complete", start-pagingInterval)})
	ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow("partial", start)})

	flows, meta, err := ring.List(&proto.FlowListRequest{StartTimeGte: start - pagingInterval, StartTimeLt: start + 1})
	require.NoError(t, err)
	require.Equal(t, 2, meta.TotalResults)
	require.Equal(t, []string{"complete", "partial"}, keyNames(flows))
	require.Equal(t, start-pagingInterval, flows[0].StartTime)
	require.Equal(t, int64(1), flows[0].PacketsIn)
	require.Zero(t, flows[1].StartTime)
	require.Zero(t, flows[1].PacketsIn)

	// Once the range covers the whole bucket, the flow aggregates normally.
	flows, _, err = ring.List(&proto.FlowListRequest{StartTimeGte: start - pagingInterval, StartTimeLt: start + pagingInterval})
	require.NoError(t, err)
	require.Equal(t, []string{"partial", "complete"}, keyNames(flows))
	require.Equal(t, int64(1), flows[0].PacketsIn)
}

type outOfRangePageCase struct {
	name string
	page int64
}

// TestPagesOutOfRange checks that every list and hint path answers a page holding no results
// with an empty page and the real totals, rather than panicking or wrapping around.
func TestPagesOutOfRange(t *testing.T) {
	ring := newPagingRing()
	start := ring.EndOfHistory() - 2*pagingInterval
	for i := range 50 {
		ring.AddFlow(storage.FlowFromNode{Flow: policyFlow(fmt.Sprintf("dest-%d", i), "ns", fmt.Sprintf("policy-%d", i), start)})
	}
	rangeEnd := start + pagingInterval

	for _, tc := range []outOfRangePageCase{
		{name: "negative page", page: -1},
		{name: "page past the end", page: 3},
		{name: "page offset overflows", page: math.MaxInt64 / 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, sortBy := range []proto.SortBy{proto.SortBy_Time, proto.SortBy_DestName} {
				flows, meta, err := ring.List(&proto.FlowListRequest{
					StartTimeGte: start, StartTimeLt: rangeEnd, PageSize: 20, Page: tc.page,
					SortBy: []*proto.SortOption{{SortBy: sortBy}},
				})
				require.NoError(t, err)
				require.Empty(t, flows, "sorted by %s", sortBy)
				require.Equal(t, types.ListMeta{TotalResults: 50, TotalPages: 3}, *meta, "sorted by %s", sortBy)
			}
			for _, hintType := range []proto.FilterType{proto.FilterType_FilterTypePolicyName, proto.FilterType_FilterTypeDestName} {
				values, meta, err := ring.FilterHints(&proto.FilterHintsRequest{
					Type: hintType, StartTimeGte: start, StartTimeLt: rangeEnd, PageSize: 20, Page: tc.page,
				})
				require.NoError(t, err)
				require.Empty(t, values, "hints for %s", hintType)
				require.Equal(t, types.ListMeta{TotalResults: 50, TotalPages: 3}, *meta, "hints for %s", hintType)
			}
		})
	}

	// The last page holds the remainder.
	flows, meta, err := ring.List(&proto.FlowListRequest{StartTimeGte: start, StartTimeLt: rangeEnd, PageSize: 20, Page: 2})
	require.NoError(t, err)
	require.Len(t, flows, 10)
	require.Equal(t, types.ListMeta{TotalResults: 50, TotalPages: 3}, *meta)
}

// TestRingListPagesMatchFullSort checks that each page, which only ranks flows up to the end of
// the page, holds exactly that slice of the fully sorted list.
func TestRingListPagesMatchFullSort(t *testing.T) {
	ring := newPagingRing()
	newest := ring.EndOfHistory() - 2*pagingInterval

	// Flows share start times within a bucket, and some flows span several buckets.
	for i := range 600 {
		b := int64(i % 7)
		ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("flow-%d", i), newest-b*pagingInterval)})
		if i%5 == 0 {
			ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("flow-%d", i), newest-(b+3)*pagingInterval)})
		}
	}
	req := &proto.FlowListRequest{StartTimeGte: newest - 12*pagingInterval, StartTimeLt: newest + pagingInterval}

	want, meta, err := ring.List(req)
	require.NoError(t, err)
	require.Len(t, want, 600)
	require.Equal(t, 1, meta.TotalPages)

	for _, pageSize := range []int64{1, 7, 20, 64, 599, 600, 1000} {
		req.PageSize = pageSize
		for page := int64(0); page*pageSize < int64(len(want)); page++ {
			req.Page = page
			got, meta, err := ring.List(req)
			require.NoError(t, err)
			require.Equal(t, 600, meta.TotalResults)
			end := min((page+1)*pageSize, int64(len(want)))
			require.Equal(t, keyNames(want[page*pageSize:end]), keyNames(got), "page size %d, page %d", pageSize, page)
		}
	}
}

// TestRingFlowsYieldsEachFlowOnce checks that reading a range's buckets yields a flow in several
// of them once, that a read left early ends, and that a nested read panics rather than letting
// the outer read yield flows twice.
func TestRingFlowsYieldsEachFlowOnce(t *testing.T) {
	ring := newPagingRing()
	start := ring.EndOfHistory() - 2*pagingInterval
	old := start - 10*pagingInterval
	for i := range 10 {
		ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("both-%d", i), start-pagingInterval)})
		ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("both-%d", i), start)})
	}
	for i := range 5 {
		ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("early-%d", i), old)})
		ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("early-%d", i), start)})
	}

	// Flows outside the range keep the ring reading its buckets rather than every flow.
	for i := range 20 {
		ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("other-%d", i), old)})
	}
	flowNames := func() []string {
		flows, _ := ring.Flows(start-pagingInterval, start+1)
		var names []string
		for d := range flows {
			names = append(names, d.Key.DestName())
		}
		slices.Sort(names)
		return names
	}

	var want []string
	for i := range 10 {
		want = append(want, fmt.Sprintf("both-%d", i))
	}
	for i := range 5 {
		want = append(want, fmt.Sprintf("early-%d", i))
	}
	slices.Sort(want)
	require.Equal(t, want, flowNames())

	flows, _ := ring.Flows(start-pagingInterval, start+1)
	for range flows {
		break
	}
	require.Equal(t, want, flowNames(), "a read left early must not block the next one")

	require.Panics(t, func() {
		for range flows {
			flowNames()
		}
	})
	require.Equal(t, want, flowNames(), "a panicking read must not block the next one")
}

type candidateRangeCase struct {
	name       string
	gte        int64
	wantOld    int
	wantRecent int
}

// TestRingListCandidateRanges covers both ways the ring gathers flows: reading the
// buckets in a narrow range, and scanning every flow when the range's buckets hold most of them.
func TestRingListCandidateRanges(t *testing.T) {
	ring := newPagingRing()
	newest := ring.EndOfHistory() - 2*pagingInterval

	// Old flows sit in one early bucket. Recent flows sit in each of the newest six.
	old := newest - 20*pagingInterval
	for i := range 10 {
		ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("old-%d", i), old)})
	}
	for b := range 6 {
		for i := range 10 {
			ring.AddFlow(storage.FlowFromNode{Flow: pagingFlow(fmt.Sprintf("recent-%d", i), newest-int64(b)*pagingInterval)})
		}
	}

	for _, tc := range []candidateRangeCase{
		{name: "two buckets, read from the buckets", gte: newest - pagingInterval, wantRecent: 10},
		{name: "six buckets, scanned and filtered by time", gte: newest - 5*pagingInterval, wantRecent: 10},
		{name: "the whole ring", gte: old, wantOld: 10, wantRecent: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flows, meta, err := ring.List(&proto.FlowListRequest{StartTimeGte: tc.gte, StartTimeLt: newest + pagingInterval})
			require.NoError(t, err)
			require.Equal(t, tc.wantOld+tc.wantRecent, meta.TotalResults)

			counts := map[string]int{}
			for _, name := range keyNames(flows) {
				counts[name]++
			}
			require.Len(t, counts, tc.wantOld+tc.wantRecent, "a flow was returned twice")
			var olds int
			for name := range counts {
				if strings.HasPrefix(name, "old-") {
					olds++
				}
			}
			require.Equal(t, tc.wantOld, olds)
		})
	}
}

// TestRingPolicyHintsSharedTrace checks that hints skip flows sharing an already-counted policy
// trace, but not flows sharing a trace with a flow that failed the filter.
func TestRingPolicyHintsSharedTrace(t *testing.T) {
	ring := newPagingRing()
	start := ring.EndOfHistory() - 2*pagingInterval

	// Many filtered-out flows share the matching flow's trace, so it is almost never seen first.
	for i := range 20 {
		ring.AddFlow(storage.FlowFromNode{Flow: policyFlow(fmt.Sprintf("other-%d", i), "ns-other", "shared", start)})
	}
	ring.AddFlow(storage.FlowFromNode{Flow: policyFlow("match", "ns-match", "shared", start)})
	ring.AddFlow(storage.FlowFromNode{Flow: policyFlow("match-2", "ns-match", "shared", start)})
	ring.AddFlow(storage.FlowFromNode{Flow: policyFlow("unmatched", "ns-other", "excluded", start)})
	ring.AddFlow(storage.FlowFromNode{Flow: policyFlow("own", "ns-match", "own", start)})

	values, meta, err := ring.FilterHints(&proto.FilterHintsRequest{
		Type:         proto.FilterType_FilterTypePolicyName,
		StartTimeGte: start,
		StartTimeLt:  start + pagingInterval,
		Filter:       &proto.Filter{DestNamespaces: []*proto.StringMatch{{Value: "ns-match", Type: proto.MatchType_Exact}}},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"own", "shared"}, values)
	require.Equal(t, 2, meta.TotalResults)

	// A range that holds none of the flows yields no hints.
	values, _, err = ring.FilterHints(&proto.FilterHintsRequest{
		Type:         proto.FilterType_FilterTypePolicyName,
		StartTimeGte: start - 10*pagingInterval,
		StartTimeLt:  start - 5*pagingInterval,
	})
	require.NoError(t, err)
	require.Empty(t, values)
}

func policyFlow(dest, namespace, policy string, start int64) *types.Flow {
	f := pagingFlow(dest, start)
	f.Key = types.NewFlowKey(
		&types.FlowKeySource{SourceName: "client", SourceNamespace: "ns", SourceType: proto.EndpointType_WorkloadEndpoint},
		&types.FlowKeyDestination{DestName: dest, DestNamespace: namespace, DestType: proto.EndpointType_WorkloadEndpoint, DestPort: 80},
		&types.FlowKeyMeta{Proto: "tcp", Reporter: proto.Reporter_Src, Action: proto.Action_Allow},
		&proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{{
			Kind:      proto.PolicyKind_CalicoNetworkPolicy,
			Namespace: "policy-ns",
			Name:      policy,
			Tier:      "default",
			Action:    proto.Action_Allow,
		}}},
	)
	return f
}

func newPagingRing() *storage.BucketRing {
	nowFunc := func() time.Time { return time.Unix(pagingRingStart, 0) }
	return storage.NewBucketRing(242, pagingInterval, pagingRingStart, storage.WithNowFunc(nowFunc))
}

func pagingFlow(dest string, start int64) *types.Flow {
	return &types.Flow{
		Key: types.NewFlowKey(
			&types.FlowKeySource{SourceName: "client", SourceNamespace: "ns", SourceType: proto.EndpointType_WorkloadEndpoint},
			&types.FlowKeyDestination{DestName: dest, DestNamespace: "ns", DestType: proto.EndpointType_WorkloadEndpoint, DestPort: 80},
			&types.FlowKeyMeta{Proto: "tcp", Reporter: proto.Reporter_Src, Action: proto.Action_Allow},
			&proto.PolicyTrace{},
		),
		StartTime:    start,
		EndTime:      start + pagingInterval,
		PacketsIn:    1,
		SourceLabels: unique.Make("app=client"),
		DestLabels:   unique.Make("app=server"),
	}
}

func allPages(t *testing.T, ring *storage.BucketRing, req *proto.FlowListRequest) []*types.Flow {
	t.Helper()
	var all []*types.Flow
	for page := int64(0); ; page++ {
		req.Page = page
		flows, _, err := ring.List(req)
		require.NoError(t, err)
		if len(flows) == 0 {
			return all
		}
		all = append(all, flows...)
	}
}

func keyNames(flows []*types.Flow) []string {
	var names []string
	for _, f := range flows {
		names = append(names, f.Key.DestName())
	}
	return names
}
