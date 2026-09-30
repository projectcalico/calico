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
	"math"

	"github.com/google/btree"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

type Ordered interface {
	~int | ~float64 | ~string | ~int64 // Include commonly used types
}

// Index provides efficient querying of Flow objects based on a given sorting function.
type Index[E Ordered] interface {
	List(opts IndexFindOpts) ([]*types.Flow, types.ListMeta)
	SortValueSet(opts IndexFindOpts) ([]E, types.ListMeta)
	Add(c *DiachronicFlow)
	Remove(c *DiachronicFlow)
}

func NewIndex[E Ordered](sortValueFunc func(*types.FlowKey) E) Index[E] {
	return &index[E]{
		sortValueFunc: sortValueFunc,
		diachronics: btree.NewG(32, func(a, b *DiachronicFlow) bool {
			// Flows with the same sort value are ordered by ID, so every flow has one place in the tree.
			va, vb := sortValueFunc(&a.Key), sortValueFunc(&b.Key)
			if va != vb {
				return va < vb
			}
			return a.ID < b.ID
		}),
	}
}

// index is an implementation of Index that uses a configurable key function with which to sort Flows.
type index[E Ordered] struct {
	sortValueFunc func(*types.FlowKey) E
	diachronics   *btree.BTreeG[*DiachronicFlow]
}

type IndexFindOpts struct {
	startTimeGt int64
	startTimeLt int64

	// pageSize is the maximum number of results to return for this query.
	pageSize int64

	// page is the page from which to start the search.
	page int64

	// filter is an optional Filter for the query.
	filter *proto.Filter
}

// List returns a list of flows and metadata about the list that's returned.
func (idx *index[E]) List(opts IndexFindOpts) ([]*types.Flow, types.ListMeta) {
	var matchedFlows []*types.Flow
	var totalMatchedCount int
	pageStart := int(opts.page * opts.pageSize)

	idx.diachronics.Ascend(func(diachronic *DiachronicFlow) bool {
		if !idx.matches(diachronic, opts) {
			return true
		}

		// Every match counts toward the total, but only the page's flows are worth aggregating.
		totalMatchedCount++
		if totalMatchedCount > pageStart && (opts.pageSize == 0 || int64(len(matchedFlows)) < opts.pageSize) {
			matchedFlows = append(matchedFlows, diachronic.Aggregate(opts.startTimeGt, opts.startTimeLt))
		}
		return true
	})

	return matchedFlows, calculateListMeta(totalMatchedCount, int(opts.pageSize))
}

// SortValueSet retrieves the unique values that this index is sorted by, in their sorted order.
func (idx *index[E]) SortValueSet(opts IndexFindOpts) ([]E, types.ListMeta) {
	var matchedValues []E
	var totalMatchedCount int
	pageStart := int(opts.page * opts.pageSize)
	var previousSortValue *E

	idx.diachronics.Ascend(func(diachronic *DiachronicFlow) bool {
		if !idx.matches(diachronic, opts) {
			return true
		}
		// Equal sort values are adjacent, so a value matching the previous one has already been counted.
		sortValue := idx.sortValueFunc(&diachronic.Key)
		if previousSortValue != nil && sortValue == *previousSortValue {
			return true
		}
		previousSortValue = &sortValue
		totalMatchedCount++
		if totalMatchedCount > pageStart && (opts.pageSize == 0 || int64(len(matchedValues)) < opts.pageSize) {
			matchedValues = append(matchedValues, sortValue)
		}
		return true
	})

	return matchedValues, calculateListMeta(totalMatchedCount, int(opts.pageSize))
}

func calculateListMeta(total, pageSize int) types.ListMeta {
	if total == 0 {
		return types.ListMeta{
			TotalPages:   0,
			TotalResults: 0,
		}
	}
	if pageSize == 0 {
		return types.ListMeta{
			TotalPages:   1,
			TotalResults: total,
		}
	}
	return types.ListMeta{
		TotalPages:   int(math.Ceil(float64(total) / float64(pageSize))),
		TotalResults: total,
	}
}

func (idx *index[E]) Add(d *DiachronicFlow) {
	idx.diachronics.ReplaceOrInsert(d)
}

func (idx *index[E]) Remove(d *DiachronicFlow) {
	if _, ok := idx.diachronics.Delete(d); !ok {
		logrus.WithFields(d.Key.Fields()).Warn("Unable to remove flow - not found in index")
	}
}

// matches is whether the flow has data in the time range and passes the filter. Aggregate never returns nil for such a flow.
func (idx *index[E]) matches(c *DiachronicFlow, opts IndexFindOpts) bool {
	return c.Matches(opts.filter, opts.startTimeGt, opts.startTimeLt)
}
