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
	"slices"
	"sort"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// logAggregator is an interface for retrieving flows from an aggregator implementation. This internal interface makes
// swapping out the implementation possible, which is particularly useful for unit testing (but in general is a useful
// property).
type logAggregator interface {
	// FlowCandidates yields each flow with data in the range exactly once, possibly alongside
	// flows without any that callers must filter out, plus a size hint.
	FlowCandidates(startGt, startLt int64) (iter.Seq[*DiachronicFlow], int)
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

func (a *RingIndex) List(opts IndexFindOpts) ([]*types.Flow, types.ListMeta) {
	logrus.WithFields(logrus.Fields{
		"opts": opts,
	}).Debug("Listing flows from time sorted index")

	candidates, sizeHint := a.agg.FlowCandidates(opts.startTimeGt, opts.startTimeLt)
	if opts.filter != nil {
		// The hint counts flows before filtering, which a selective filter makes far too large.
		sizeHint = 0
	}

	// Rank every matching flow, but keep and aggregate only those up to the end of the page.
	pageStart, pageEnd, pageOK := pageWindow(opts.page, opts.pageSize)
	top := newTopRanked(pageEnd, pageOK, sizeHint)
	totalFlows := 0
	for d := range candidates {
		if opts.filter != nil && !types.Matches(opts.filter, &d.Key) {
			continue
		}
		if start, ok := d.SortStartTime(opts.startTimeGt, opts.startTimeLt); ok {
			totalFlows++
			top.offer(rankedFlow{start: start, flow: d})
		}
	}

	ranked := top.sorted()
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

	candidates, _ := a.agg.FlowCandidates(opts.startTimeGt, opts.startTimeLt)

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

// topRanked keeps the first limit flows offered, in compareRanked order. Until it is full it only
// appends; after that it is a heap whose root is the last flow kept, so each later offer costs
// O(log limit) and the flows past the requested page are never sorted.
type topRanked struct {
	limit int
	flows []rankedFlow
}

// newTopRanked returns a topRanked that keeps flows up to the end offset of a page, or none if
// the page is invalid.
func newTopRanked(end int64, ok bool, sizeHint int) *topRanked {
	limit := 0
	if ok {
		limit = int(min(end, int64(math.MaxInt)))
	}
	return &topRanked{limit: limit, flows: make([]rankedFlow, 0, min(limit, sizeHint))}
}

// offer keeps r if it is among the first limit flows offered so far.
func (t *topRanked) offer(r rankedFlow) {
	switch {
	case len(t.flows) < t.limit:
		t.flows = append(t.flows, r)
		if len(t.flows) == t.limit {
			for i := len(t.flows)/2 - 1; i >= 0; i-- {
				t.siftDown(i)
			}
		}
	case t.limit > 0 && compareRanked(r, t.flows[0]) < 0:
		t.flows[0] = r
		t.siftDown(0)
	}
}

// siftDown restores the heap order below index i, where each flow sorts after its children.
func (t *topRanked) siftDown(i int) {
	n := len(t.flows)
	for {
		latest := i
		for _, child := range [2]int{2*i + 1, 2*i + 2} {
			if child < n && compareRanked(t.flows[child], t.flows[latest]) > 0 {
				latest = child
			}
		}
		if latest == i {
			return
		}
		t.flows[i], t.flows[latest] = t.flows[latest], t.flows[i]
		i = latest
	}
}

// sorted returns the kept flows in compareRanked order.
func (t *topRanked) sorted() []rankedFlow {
	slices.SortFunc(t.flows, compareRanked)
	return t.flows
}
