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

// policyValueFunc returns the filter hint values for a flow key's policy trace. Taking only the
// trace lets FilterValueSet compute the values once per distinct trace.
type policyValueFunc func(policies unique.Handle[string]) []string

func (a *RingIndex) List(opts IndexFindOpts) ([]*types.Flow, types.ListMeta) {
	logrus.WithFields(logrus.Fields{
		"opts": opts,
	}).Debug("Listing flows from time sorted index")

	candidates, sizeHint := a.agg.FlowCandidates(opts.startTimeGt, opts.startTimeLt)

	// Rank every matching flow, but aggregate only the ones on the requested page.
	ranked := make([]rankedFlow, 0, sizeHint)
	for d := range candidates {
		if opts.filter != nil && !types.Matches(opts.filter, &d.Key) {
			continue
		}
		if start, ok := d.SortStartTime(opts.startTimeGt, opts.startTimeLt); ok {
			ranked = append(ranked, rankedFlow{start: start, flow: d})
		}
	}

	// Sort newer flows first. Start times are bucket-aligned, so ties are common, and breaking
	// them on ID keeps the order, and so the pages, stable across requests.
	slices.SortFunc(ranked, func(x, y rankedFlow) int {
		if c := cmp.Compare(y.start, x.start); c != 0 {
			return c
		}
		return cmp.Compare(y.flow.ID, x.flow.ID)
	})

	// Assign the total before the result is trimmed to match the page size and start page.
	totalFlows := len(ranked)
	if opts.pageSize > 0 {
		startIdx := opts.page * opts.pageSize
		if startIdx >= int64(len(ranked)) {
			return nil, types.ListMeta{}
		}
		ranked = ranked[startIdx:min(startIdx+opts.pageSize, int64(len(ranked)))]
	}

	flows := make([]*types.Flow, 0, len(ranked))
	for _, r := range ranked {
		if f := r.flow.Aggregate(opts.startTimeGt, opts.startTimeLt); f != nil {
			flows = append(flows, f)
		}
	}
	return flows, calculateListMeta(totalFlows, int(opts.pageSize))
}

func (r *RingIndex) Add(d *DiachronicFlow) {
}

func (r *RingIndex) Remove(d *DiachronicFlow) {
}

func (a *RingIndex) SortValueSet(opts IndexFindOpts) ([]int64, types.ListMeta) {
	panic("SortValueSet is not supported by the ring index")
}

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

	// Assign the total before the result is trimmed to match the page size and start page.
	totalFlows := len(values)

	// If pagination was requested, apply it now after sorting.
	// This is a bit inneficient - we collect more data than we need to return -
	// but it's a simple way to implement basic pagination.
	if opts.pageSize > 0 {
		startIdx := (opts.page) * opts.pageSize
		endIdx := startIdx + opts.pageSize
		if startIdx >= int64(len(values)) {
			return nil, types.ListMeta{}
		}
		if endIdx > int64(len(values)) {
			endIdx = int64(len(values))
		}
		logrus.WithFields(logrus.Fields{
			"pageSize":   opts.pageSize,
			"pageNumber": opts.page,
			"startIdx":   startIdx,
			"endIdx":     endIdx,
			"total":      len(values),
		}).Debug("Returning paginated flows")

		values = values[startIdx:endIdx]
	}

	return values, calculateListMeta(totalFlows, int(opts.pageSize))
}
