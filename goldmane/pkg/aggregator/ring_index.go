package aggregator

import (
	"fmt"
	"sort"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
)

func NewRingIndex(a *LogAggregator) *RingIndex {
	return &RingIndex{
		agg: a,
	}
}

// RingIndex implements the Index interface using a ring of aggregation buckets.
type RingIndex struct {
	agg *LogAggregator
}

func (a *RingIndex) List(opts IndexFindOpts[int64]) []*types.Flow {
	// Default to time-sorted flow data.
	// Collect all of the flow keys across all buckets that match the request. We will then
	// use DiachronicFlow data to combine statistics together for each key across the time range.
	keys := a.agg.buckets.FlowSet(opts.startTimeGt, opts.startTimeLt)

	// Aggregate the relevant DiachronicFlows across the time range.
	flowsByKey := map[types.FlowKey]*types.Flow{}
	keys.Iter(func(key types.FlowKey) error {
		c, ok := a.agg.diachronics[key]
		if !ok {
			// This should never happen, as we should have a DiachronicFlow for every key.
			// If we don't, it's a bug. Return an error, which will trigger a panic.
			return fmt.Errorf("no DiachronicFlow for key %v", key)
		}
		flow := c.Aggregate(opts.startTimeGt, opts.startTimeLt)
		if flow != nil {
			flowsByKey[*flow.Key] = flow
		}
		return nil
	})

	// Convert the map to a slice.
	flows := []*types.Flow{}
	for _, flow := range flowsByKey {
		flows = append(flows, flow)
	}

	// Sort the flows by start time, sorting newer flows first.
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].StartTime > flows[j].StartTime
	})

	return flows
}

func (r *RingIndex) Add(d *types.DiachronicFlow) {
}

func (r *RingIndex) Remove(d *types.DiachronicFlow) {
}
