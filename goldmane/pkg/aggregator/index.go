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

package aggregator

import (
	"sort"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

type Ordered interface {
	~int | ~float64 | ~string | ~int64 // Include commonly used types
}

// Index provides efficient querying of Flow objects based on a given sorting function.
type Index[E Ordered] interface {
	// TODO: Clients need a way to know how many pages of results exist for a given query.
	List(opts IndexFindOpts) []*types.Flow
	Add(c *types.DiachronicFlow)
	Remove(c *types.DiachronicFlow)
}

func NewIndex[E Ordered](cmpFunc func(*types.FlowKey) E) Index[E] {
	return &index[E]{keyFunc: cmpFunc}
}

// index is an implementation of Index that uses a configurable key function with which to sort Flows.
// It maintains a list of DiachronicFlows sorted based on the key function allowing for efficient querying.
type index[E Ordered] struct {
	keyFunc     func(*types.FlowKey) E
	diachronics []*types.DiachronicFlow
}

type IndexFindOpts struct {
	startTimeGt int64
	startTimeLt int64

	// limit is the maximum number of results to return for this query.
	limit int64

	// page is the page from which to start the search.
	page int64

	// filter is an optional Filter for the query.
	filter *proto.Filter
}

func (idx *index[E]) List(opts IndexFindOpts) []*types.Flow {
	logrus.WithFields(logrus.Fields{
		"opts": opts,
	}).Debug("Listing flows from index")

	var matchedFlows []*types.Flow

	// Find the index into the DiachronicFlow array from which to start the search based on the provided page number and limit.
	// We need to iterate through the DiachronicFlows to find the starting point, since not every DiachronicFlow is necessarily a match
	// for the given options.
	var i int
	if opts.page > 0 {
		target := opts.page * opts.limit
		for j := 0; j < len(idx.diachronics); j++ {
			if idx.evaluate(idx.diachronics[j], opts) != nil {
				i++
			}
			if int64(i) == target {
				break
			}
		}
	}

	// Iterate through the DiachronicFlows and evaluate each one until we reach the limit or the end of the list.
	for ; i < len(idx.diachronics); i++ {
		flow := idx.evaluate(idx.diachronics[i], opts)
		if flow != nil {
			matchedFlows = append(matchedFlows, flow)
		}

		if opts.limit > 0 && int64(len(matchedFlows)) == opts.limit {
			return matchedFlows
		}
	}

	return matchedFlows
}

func (idx *index[E]) Add(d *types.DiachronicFlow) {
	if len(idx.diachronics) == 0 {
		// This is the first flow in the index. No need to insert it carefully.
		logrus.WithFields(logrus.Fields{
			"flow": d,
		}).Debug("Adding first DiachronicFlow to index")
		idx.diachronics = append(idx.diachronics, d)
		return
	}

	// Find the index within the Index where the flow should be inserted.
	index := idx.lookup(d)

	if index == len(idx.diachronics) {
		// The flow is the largest in the index. Append it.
		logrus.WithFields(logrus.Fields{
			"flow": d,
		}).Debug("Appending new DiachronicFlow to index")
		idx.diachronics = append(idx.diachronics, d)
		return
	}

	if idx.diachronics[index].Key != d.Key {
		// The flow key is different from the DiachronicFlow key at this index. Insert a new DiachronicFlow.
		logrus.WithFields(logrus.Fields{
			"flow": d,
			"i":    index,
		}).Debug("Inserting new DiachronicFlow into index")
		idx.diachronics = append(idx.diachronics[:index], append([]*types.DiachronicFlow{d}, idx.diachronics[index:]...)...)
	}
	// The DiachronicFlow already exists in the index, so do nothing.
}

func (idx *index[E]) Remove(d *types.DiachronicFlow) {
	// Find the index of the DiachronicFlow to be removed.
	index := idx.lookup(d)

	if index == len(idx.diachronics) {
		// The DiachronicFlow doesn't exist in the index (and would have sorted to the end of the index).
		// We can't remove a flow that doesn't exist, so log a warning and return.
		logrus.WithFields(logrus.Fields{"flow": d}).Warn("Unable to remove flow - not found in index")
		return
	}

	if idx.diachronics[index].Key == d.Key {
		// The DiachronicFlow at the returned index is the same as the DiachronicFlow to be removed.
		// Remove it from the index.
		logrus.WithFields(logrus.Fields{
			"flow": d,
		}).Debug("Removing flow from index")
		idx.diachronics = append(idx.diachronics[:index], idx.diachronics[index+1:]...)
		return
	} else {
		// The DiachronicFlow at the returned index is not the same as the DiachronicFlow to be removed.
		// This means the DiachronicFlow to be removed doesn't exist in the index.
		logrus.WithFields(logrus.Fields{"flow": d, "i": idx.diachronics[index]}).Warn("Unable to remove flow - not found in index")
	}
}

// lookup returns the index within the list of DiachronicFlows where the given DiachronicFlow either already exists or should be inserted.
// - If the DiachronicFlow already exists, the index of the existing DiachronicFlow is returned.
// - If the DiachronicFlow does not exist, the index where it should be inserted is returned.
func (idx *index[E]) lookup(d *types.DiachronicFlow) int {
	return sort.Search(len(idx.diachronics), func(i int) bool {
		// Compare the new DiachronicFlow with the DiachronicFlow at index i.
		// - If the new DiachronicFlow sorts before the current DiachronicFlow, return true.
		// - If the new DiachronicFlow sorts after the current DiachronicFlow, return false.
		// - If this flow sorts the same as the current DiachronicFlow based on the parameters of this Index,
		//   we need to sort based on the entire flow key to find a deterministic order.
		// on the entire flow key.
		k1 := idx.keyFunc(&idx.diachronics[i].Key)
		k2 := idx.keyFunc(&d.Key)
		if k1 > k2 {
			// The key of the DiachronicFlow at index i greater than the key of the flow.
			return true
		}
		if k1 == k2 {
			// The field(s) this Index is optimized for considers these keys the same.
			// Sort based on the key's ID to ensure a deterministic order.
			// TODO: This will result in different ordering on restart. Should we sort by FlowKey fields instead
			// to be truly deterministic?
			return idx.diachronics[i].ID >= d.ID
		}
		return false
	})
}

// evaluate evaluates the given DiachronicFlow and returns the Flow that matches the given options, or nil if no match is found.
func (idx *index[E]) evaluate(c *types.DiachronicFlow, opts IndexFindOpts) *types.Flow {
	if c.Matches(opts.filter, opts.startTimeLt, opts.startTimeGt) {
		return c.Aggregate(opts.startTimeGt, opts.startTimeLt)
	}
	return nil
}
