// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package bucketing

import (
	"math"
	"slices"
	"sort"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
)

type Ordered interface {
	~int | ~float64 | ~string | ~int64 // Include commonly used types
}

type indexInf[K Key[T], T comparable, V Ordered] interface {
	add(key K)
	list(opts FindOpts[K]) ([]K, types.ListMeta)
	uniqueIndexKeys(opts FindOpts[K]) ([]V, types.ListMeta)
	remove(K)
}

func NewStringIndex[K Key[T], T comparable](sortValueFunc func(K) string) indexInf[K, T, string] {
	return &index[K, string, T]{sortValueFunc: sortValueFunc}
}

// index is an implementation of Index that uses a configurable key function with which to sort Flows.
// It maintains a list of DiachronicFlows sorted based on the key function allowing for efficient querying.
type index[K Key[T], E Ordered, T comparable] struct {
	sortValueFunc func(K) E
	keys          []K
}

type FindOpts[K any] struct {
	StartTimeGt int64
	StartTimeLt int64

	// pageSize is the maximum number of results to return for this query.
	PageSize int64

	// page is the page from which to start the search.
	Page int64

	// filter is an optional Filter for the query.
	Filter func(K) bool
	SortBy string
}

// List returns a list of flows and metadata about the list that's returned.
func (idx *index[K, E, T]) list(opts FindOpts[K]) ([]K, types.ListMeta) {
	logrus.WithFields(logrus.Fields{
		"opts": opts,
	}).Debug("Listing flows from index")

	var matchedKeys []K
	var totalMatchedCount int

	pageStart := int(opts.Page * opts.PageSize)

	// Iterate through the DiachronicFlows and evaluate each one until we reach the limit or the end of the list.
	for _, key := range idx.keys {
		if opts.Filter != nil && !opts.Filter(key) {
			// increment the count regardless of whether we're including the key, as we need a total matching count.
			totalMatchedCount++

			// Include the value if:
			// - We're not performing a paginated search.
			// - We are performing a paginated search, and it falls within the page bounds.
			if totalMatchedCount > pageStart && (opts.PageSize == 0 || int64(len(matchedKeys)) < opts.PageSize) {
				matchedKeys = append(matchedKeys, key)
			}
		}
	}

	return matchedKeys, calculateListMeta(totalMatchedCount, int(opts.PageSize))
}

// SortValueSet retrieves the unique values that this index is sorted by, in their sorted order.
func (idx *index[K, E, T]) uniqueIndexKeys(opts FindOpts[K]) ([]E, types.ListMeta) {
	logrus.WithFields(logrus.Fields{
		"opts": opts,
	}).Debug("Listing keys from index")

	var matchedValues []E
	var totalMatchedCount int

	pageStart := int(opts.Page * opts.PageSize)
	var previousSortValue *E

	// Iterate through the DiachronicFlows and evaluate each one until we reach the limit or the end of the list.
	for _, key := range idx.keys {
		if opts.Filter != nil && !opts.Filter(key) {
			sortValue := idx.sortValueFunc(key)
			// If the previous sortValue does not equal the current sortValue we know that we haven't seen this sortValue
			// yet, as this is sorted list and all sortValues with the same value are together.
			if previousSortValue != nil && sortValue == *previousSortValue {
				// If we've seen this key match before then no need to add it to the set.
				continue
			}
			previousSortValue = &sortValue

			// increment the count regardless of whether we're including the key, as we need a total matching count.
			totalMatchedCount++

			// Include the value if:
			// - We're not performing a paginated search.
			// - We are performing a paginated search, and it falls within the page bounds.
			if totalMatchedCount > pageStart && (opts.PageSize == 0 || int64(len(matchedValues)) < opts.PageSize) {
				matchedValues = append(matchedValues, sortValue)
			}
		}
	}

	return matchedValues, calculateListMeta(totalMatchedCount, int(opts.PageSize))
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

func (idx *index[K, E, T]) add(key K) {
	if len(idx.keys) == 0 {
		// This is the first flow in the index. No need to insert it carefully.
		logrus.WithFields(key.Fields()).Debug("Adding first DiachronicFlow to index")
		idx.keys = append(idx.keys, key)
		return
	}

	// Find the index within the Index where the flow should be inserted.
	index := idx.lookup(key)

	if index == len(idx.keys) {
		// The key is the largest in the index. Append it.
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(key.Fields()).Debug("Appending new DiachronicFlow to index")
		}
		idx.keys = append(idx.keys, key)
		return
	}

	if idx.keys[index] != key {
		// The flow key is different from the DiachronicFlow key at this index. Insert a new DiachronicFlow.
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(key.Fields()).WithFields(logrus.Fields{"i": index}).Debug("Inserting new DiachronicFlow into index")
		}
		idx.keys = append(idx.keys[:index], append([]K{key}, idx.keys[index:]...)...)
	}
	// The DiachronicFlow already exists in the index, so do nothing.
}

func (idx *index[K, E, T]) remove(key K) {
	// Find the index of the DiachronicFlow to be removed.
	index := idx.lookup(key)

	if index == len(idx.keys) {
		// The DiachronicFlow doesn't exist in the index (and would have sorted to the end of the index).
		// We can't remove a flow that doesn't exist, so log a warning and return.
		logrus.WithFields(logrus.Fields{"key": key}).Warn("Unable to remove flow - not found in index")
		return
	}

	if idx.keys[index] == key {
		// The DiachronicFlow at the returned index is the same as the DiachronicFlow to be removed.
		// Remove it from the index.
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(key.Fields()).Debug("Removing flow from index")
		}
		idx.keys = slices.Delete(idx.keys, index, index+1)
		return
	} else {
		// The DiachronicFlow at the returned index is not the same as the DiachronicFlow to be removed.
		// This means the DiachronicFlow to be removed doesn't exist in the index.
		logrus.WithFields(key.Fields()).
			WithFields(logrus.Fields{"i": idx.keys[index]}).
			Warn("Unable to remove flow - not found in index")
	}
}

// lookup returns the index within the list of DiachronicFlows where the given DiachronicFlow either already exists or should be inserted.
// - If the DiachronicFlow already exists, the index of the existing DiachronicFlow is returned.
// - If the DiachronicFlow does not exist, the index where it should be inserted is returned.
func (idx *index[K, E, T]) lookup(key K) int {
	return sort.Search(len(idx.keys), func(i int) bool {
		// Compare the new DiachronicFlow with the DiachronicFlow at index i.
		// - If the new DiachronicFlow sorts before the current DiachronicFlow, return true.
		// - If the new DiachronicFlow sorts after the current DiachronicFlow, return false.
		// - If this flow sorts the same as the current DiachronicFlow based on the parameters of this Index,
		//   we need to sort based on the entire flow key to find a deterministic order.
		// on the entire flow key.
		v1 := idx.sortValueFunc(idx.keys[i])
		v2 := idx.sortValueFunc(key)
		if v1 > v2 {
			// The key of the DiachronicFlow at index i greater than the key of the flow.
			return true
		}
		if v1 == v2 {
			// The field(s) this Index is optimized for considers these keys the same.
			// Sort based on the key's ID to ensure a deterministic order.
			// TODO: This will result in different ordering on restart. Should we sort by FlowKey fields instead
			// to be truly deterministic?
			return idx.keys[i].Compare(key)
		}
		return false
	})
}
