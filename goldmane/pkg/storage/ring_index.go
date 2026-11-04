// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"cmp"
	"iter"
	"math"
	"sort"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/topk"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// logAggregator is an interface for retrieving flows from an aggregator implementation. This internal interface makes
// swapping out the implementation possible, which is particularly useful for unit testing (but in general is a useful
// property).
type logAggregator interface {
	// Flows yields every flow with data in the range exactly once, plus a size hint. It may also
	// yield flows with no data in the range.
	Flows(startGt, startLt int64) (iter.Seq[*DiachronicFlow], int)
}

func NewRingIndex(a logAggregator) *RingIndex {
	return &RingIndex{
		agg: a,
	}
}

// RingIndex implements the Index interface using a ring of aggregation buckets.
type RingIndex struct {
	agg logAggregator
}

// rankedFlow pairs a DiachronicFlow with the start time its aggregated flow sorts on.
type rankedFlow struct {
	start int64
	flow  *DiachronicFlow
}

// compareRanked orders newer flows first. Start times are bucket-aligned, so ties are common, and
// breaking them on ID keeps the order, and so the pages, stable across requests.
func compareRanked(x, y rankedFlow) int {
	if c := cmp.Compare(y.start, x.start); c != 0 {
		return c
	}
	return cmp.Compare(y.flow.ID, x.flow.ID)
}

// policyValueFunc returns the filter hint values for a flow key's policy trace. Taking only the
// trace lets FilterValueSet compute the values once per distinct trace.
type policyValueFunc func(policies unique.Handle[string]) []string

// List returns one page of the flows in the time range, newest first, and how many match. It runs
// on the main loop, which also ingests flows, so its time is time ingest waits. Sorting every match
// to cut one page out would mostly order flows nobody asked for, so a topk.Keeper holds only those
// up to the page's end. With 200,000 flows, all history and 20 per page, that is 65ms instead of
// 103ms, and 8.4KiB instead of 3.0MiB.
func (a *RingIndex) List(opts IndexFindOpts) ([]*types.Flow, types.ListMeta) {
	logrus.WithFields(logrus.Fields{
		"opts": opts,
	}).Debug("Listing flows from time sorted index")

	candidates, sizeHint := a.agg.Flows(opts.startTimeGt, opts.startTimeLt)
	if opts.filter != nil {
		// The hint counts flows before filtering, which a selective filter makes far too large.
		sizeHint = 0
	}

	pageStart, pageEnd, pageOK := pageWindow(opts.page, opts.pageSize)
	limit := 0
	if pageOK {
		limit = int(min(pageEnd, int64(math.MaxInt)))
	}
	top := topk.New(limit, compareRanked, sizeHint)
	totalFlows := 0
	for d := range candidates {
		if opts.filter != nil && !types.Matches(opts.filter, &d.Key) {
			continue
		}
		if start, ok := d.Within(opts.startTimeGt, opts.startTimeLt); ok {
			totalFlows++
			top.Offer(rankedFlow{start: start, flow: d})
		}
	}

	ranked := top.Sorted()
	meta := calculateListMeta(totalFlows, int(opts.pageSize))
	if pageStart >= int64(len(ranked)) {
		return nil, meta
	}
	ranked = ranked[pageStart:]

	flows := make([]*types.Flow, 0, len(ranked))
	for _, r := range ranked {
		if f := r.flow.Aggregate(opts.startTimeGt, opts.startTimeLt); f != nil {
			flows = append(flows, f)
		}
	}
	return flows, meta
}

func (r *RingIndex) Add(d *DiachronicFlow) {
}

func (r *RingIndex) Remove(d *DiachronicFlow) {
}

func (a *RingIndex) SortValueSet(opts IndexFindOpts) ([]int64, types.ListMeta) {
	panic("SortValueSet is not supported by the ring index")
}

// FilterValueSet returns the distinct policy values (names, namespaces or tiers, per valueFunc)
// of flows in the time range that match the filter.
func (a *RingIndex) FilterValueSet(valueFunc policyValueFunc, opts IndexFindOpts) ([]string, types.ListMeta) {
	logrus.WithFields(logrus.Fields{
		"opts": opts,
	}).Debug("Listing flows from time sorted index")

	candidates, _ := a.agg.Flows(opts.startTimeGt, opts.startTimeLt)

	// Flows that share a policy trace share their values, so once one of them has matched the
	// rest can be skipped without checking.
	var values []string
	seen := set.New[string]()
	seenPolicies := set.New[unique.Handle[string]]()
	for d := range candidates {
		policies := d.Key.Policies()
		if seenPolicies.Contains(policies) || !d.Matches(opts.filter, opts.startTimeGt, opts.startTimeLt) {
			continue
		}
		seenPolicies.Add(policies)
		for _, val := range valueFunc(policies) {
			if !seen.Contains(val) {
				seen.Add(val)
				values = append(values, val)
			}
		}
	}

	// Sort the values alphanumerically.
	sort.Strings(values)

	meta := calculateListMeta(len(values), int(opts.pageSize))
	start, end, ok := pageWindow(opts.page, opts.pageSize)
	if !ok || start >= int64(len(values)) {
		return nil, meta
	}
	return values[start:min(end, int64(len(values)))], meta
}
