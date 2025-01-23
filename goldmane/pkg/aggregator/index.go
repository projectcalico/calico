package aggregator

import (
	"sort"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
)

type Ordered interface {
	~int | ~float64 | ~string | ~int64 // Include commonly used types
}

type Index[E Ordered] interface {
	// TODO: Clients need a way to know how many pages of results exist for a given query.
	List(opts IndexFindOpts[E]) []*types.Flow
	Add(c *types.DiachronicFlow)
}

func NewIndex[E Ordered](cmpFunc func(*types.FlowKey) E) Index[E] {
	return &index[E]{keyFunc: cmpFunc}
}

type index[E Ordered] struct {
	keyFunc     func(*types.FlowKey) E
	diachronics []*types.DiachronicFlow
}

type IndexFindOpts[E comparable] struct {
	startTimeGt int64
	startTimeLt int64

	// cursor is an int64 used to match the ID of the DiachronicFlow from which to start the search.
	cursor int64

	// limit is the maximum number of results to return for this query.
	limit int64
}

func (idx *index[E]) List(opts IndexFindOpts[E]) []*types.Flow {
	var matchedFlows []*types.Flow

	// Find the index of the DiachronicFlow from which to start the search. If the cursor is 0, we start from the beginning.
	// Otherwise, we start from the DiachronicFlow with the ID equal to the cursor.
	var i int
	if opts.cursor > 0 {
		i = sort.Search(len(idx.diachronics), func(i int) bool {
			return idx.diachronics[i].ID > opts.cursor
		})

		// If i is the length of the slice then we didn't find our result.
		if i == len(idx.diachronics) {
			i = 0
		} else {
			i++
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

func (idx *index[E]) Add(c *types.DiachronicFlow) {
	if len(idx.diachronics) == 0 {
		// This is the first flow in the index. No need to insert it carefully.
		idx.diachronics = append(idx.diachronics, c)
		return
	}

	// Find the index within the Index where the flow should be inserted.
	index := sort.Search(len(idx.diachronics), func(i int) bool {
		// Compare the new DiachronicFlow with the DiachronicFlow at index i.
		// - If the new DiachronicFlow sorts before the current DiachronicFlow, return true.
		// - If the new DiachronicFlow sorts after the current DiachronicFlow, return false.
		// - If this flow sorts the same as the current DiachronicFlow based on the parameters of this Index,
		//   we need to sort based on the entire flow key to find a deterministic order.
		// on the entire flow key.
		k1 := idx.keyFunc(&idx.diachronics[i].Key)
		k2 := idx.keyFunc(&c.Key)
		if k1 > k2 {
			// The key of the current DiachronicFlow is greater than the key of the flow, OR
			// this flow is the same
			return true
		}
		if k1 == k2 {
			// The field(s) this Index is optimized for considers these keys the same.
			// Sort based on the key's ID to ensure a deterministic order.
			// TODO: This will result in different ordering on restart. Should we sort by FlowKey fields instead
			// to be truly deterministic?
			return idx.diachronics[i].ID > c.ID
		}
		return false
	})

	if index == len(idx.diachronics) {
		// No existing DiachronicFlow entry for this FlowKey. Append it.
		idx.diachronics = append(idx.diachronics, c)
		return
	}

	if idx.diachronics[index].Key != c.Key {
		// The flow key is different from the DiachronicFlow key at this index. Insert a new DiachronicFlow.
		idx.diachronics = append(idx.diachronics[:index], append([]*types.DiachronicFlow{c}, idx.diachronics[index:]...)...)
	}
}

func (idx *index[E]) evaluate(c *types.DiachronicFlow, opts IndexFindOpts[E]) *types.Flow {
	return c.Aggregate(opts.startTimeGt, opts.startTimeLt)
}
