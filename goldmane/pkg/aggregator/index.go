package aggregator

import (
	"sort"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
)

type Ordered interface {
	~int | ~float64 | ~string | ~int64 // Include commonly used types
}

type Index[E Ordered] interface {
	List(opts IndexFindOpts[E]) []*types.Flow
	Add(c *types.Cascade)
}

func NewIndex[E Ordered](cmpFunc func(*types.FlowKey) E) Index[E] {
	return &index[E]{keyFunc: cmpFunc}
}

type index[E Ordered] struct {
	keyFunc  func(*types.FlowKey) E
	cascades []*types.Cascade
}

type IndexFindOpts[E comparable] struct {
	startTimeGt int64
	startTimeLt int64

	// cursor is an int64 used to match the ID of the cascade from which to start the search.
	cursor int64

	limit int64
}

func (idx *index[E]) List(opts IndexFindOpts[E]) []*types.Flow {
	var matchedFlows []*types.Flow

	// Find the index of the cascade from which to start the search. If the cursor is 0, we start from the beginning.
	// Otherwise, we start from the cascade with the ID equal to the cursor.
	var i int
	if opts.cursor > 0 {
		i = sort.Search(len(idx.cascades), func(i int) bool {
			return idx.cascades[i].ID > opts.cursor
		})

		// If i is the length of the slice then we didn't find our result.
		if i == len(idx.cascades) {
			i = 0
		} else {
			i++
		}
	}

	// Iterate through the cascades and evaluate each one until we reach the limit or the end of the list.
	for ; i < len(idx.cascades); i++ {
		flow := idx.evaluate(idx.cascades[i], opts)
		if flow != nil {
			matchedFlows = append(matchedFlows, flow)
		}

		if opts.limit > 0 && int64(len(matchedFlows)) == opts.limit {
			return matchedFlows
		}
	}

	return matchedFlows
}

func (idx *index[E]) Add(c *types.Cascade) {
	if len(idx.cascades) == 0 {
		// This is the first flow in the index. No need to insert it carefully.
		idx.cascades = append(idx.cascades, c)
		return
	}

	// Find the index within the Index where the flow should be inserted.
	index := sort.Search(len(idx.cascades), func(i int) bool {
		// Compare the new cascade with the cascade at index i.
		// - If the new cascade sorts before the current cascade, return true.
		// - If the new cascade sorts after the current cascade, return false.
		// - If this flow sorts the same as the current cascade based on the parameters of this Index,
		//   we need to sort based on the entire flow key to find a deterministic order.
		// on the entire flow key.
		k1 := idx.keyFunc(&idx.cascades[i].Key)
		k2 := idx.keyFunc(&c.Key)
		if k1 > k2 {
			// The key of the current cascade is greater than the key of the flow, OR
			// this flow is the same
			return true
		}
		if k1 == k2 {
			// The field(s) this Index is optimized for considers these key the same. Sort within the
			// matching keys based on the entire flow key.
		}
		return false
	})

	if index == len(idx.cascades) {
		// No existing cascade entry for this FlowKey. Append it.
		idx.cascades = append(idx.cascades, c)
		return
	}

	if idx.cascades[index].Key != c.Key {
		// The flow key is different from the cascade key at this index. Insert a new cascade.
		idx.cascades = append(idx.cascades[:index], append([]*types.Cascade{c}, idx.cascades[index:]...)...)
	}
}

func (idx *index[E]) evaluate(c *types.Cascade, opts IndexFindOpts[E]) *types.Flow {
	return c.ToFlow(opts.startTimeGt, opts.startTimeLt)
}
