package aggregator

import (
	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"sort"
)

type Ordered interface {
	~int | ~float64 | ~string // Include commonly used types
}

type Index[E Ordered] interface {
	List(opts IndexFindOpts[E]) []*types.Flow
	Add(flow *types.Flow)
}

func NewIndex[E Ordered](cmpFunc func(*types.Flow) E) Index[E] {
	return &index[E]{keyFunc: cmpFunc}
}

type index[E Ordered] struct {
	keyFunc func(*types.Flow) E
	flows   []*types.Flow
}

type IndexFindOpts[E comparable] struct {
	startTimeGt int64
	startTimeLt int64

	cursor *types.Flow
	limit  int64
}

func (idx *index[E]) List(opts IndexFindOpts[E]) []*types.Flow {
	var matchedFlows []*types.Flow
	var i int
	if opts.cursor != nil {
		i = sort.Search(len(idx.flows), func(i int) bool {
			return idx.flows[i].ID > opts.cursor.ID
		})

		// if i is the length of the slice then we didn't find our result.
		if i == len(idx.flows) {
			i = 0
		} else {
			i++
		}
	}

	for ; i < len(idx.flows); i++ {
		flow := idx.evalFlow(idx.flows[i], opts)
		if flow != nil {
			matchedFlows = append(matchedFlows, flow)
		}

		if opts.limit > 0 && int64(len(matchedFlows)) == opts.limit {
			return matchedFlows
		}
	}

	return matchedFlows
}

func (idx *index[E]) Add(flow *types.Flow) {
	if len(idx.flows) == 0 {
		idx.flows = append(idx.flows, flow)
		return
	}

	index := sort.Search(len(idx.flows), func(i int) bool {
		k1 := idx.keyFunc(idx.flows[i])
		k2 := idx.keyFunc(flow)
		if k1 > k2 {
			return true
		}
		if k1 == k2 {
			return idx.flows[i].ID > flow.ID
		}
		return false
	})

	if index == len(idx.flows) {
		idx.flows = append(idx.flows, flow)

		return
	}

	if idx.flows[index].Key != flow.Key {
		idx.flows = append(idx.flows[:index], append([]*types.Flow{flow}, idx.flows[index:]...)...)
	}
}

func (idx *index[E]) evalFlow(flow *types.Flow, opts IndexFindOpts[E]) *types.Flow {
	var matchedFlow *types.Flow
	for _, stat := range flow.DiscreteStatistics {
		if stat.StartTime > opts.startTimeGt && stat.StartTime < opts.startTimeLt {
			if matchedFlow == nil {
				matchedFlow = flow
			}
		}
	}

	return matchedFlow
}
