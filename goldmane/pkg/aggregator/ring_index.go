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
	"fmt"
	"sort"

	"github.com/sirupsen/logrus"

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

func (a *RingIndex) List(opts IndexFindOpts) []*types.Flow {
	logrus.WithFields(logrus.Fields{
		"opts": opts,
	}).Debug("Listing flows from time sorted index")

	// Default to time-sorted flow data.
	// Collect all of the flow keys across all buckets that match the request. We will then
	// use DiachronicFlow data to combine statistics together for each key across the time range.
	keys := a.agg.buckets.FlowSet(opts.startTimeGt, opts.startTimeLt)

	// Aggregate the relevant DiachronicFlows across the time range.
	flowsByKey := map[types.FlowKey]*types.Flow{}
	keys.Iter(func(key types.FlowKey) error {
		d, ok := a.agg.diachronics[key]
		if !ok {
			// This should never happen, as we should have a DiachronicFlow for every key.
			// If we don't, it's a bug. Return an error, which will trigger a panic.
			return fmt.Errorf("no DiachronicFlow for key %v", key)
		}
		logrus.WithFields(logrus.Fields{
			"key":    key,
			"filter": opts.filter,
		}).Debug("Checking if flow matches filter")
		if d.Matches(opts.filter, opts.startTimeGt, opts.startTimeLt) {
			logrus.WithFields(logrus.Fields{
				"key": key,
			}).Debug("Flow matches filter")
			flow := d.Aggregate(opts.startTimeGt, opts.startTimeLt)
			if flow != nil {
				logrus.WithFields(logrus.Fields{
					"flow": flow,
				}).Debug("Aggregated flow")
				flowsByKey[*flow.Key] = flow
			}
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

	// If pagination was requested, apply it now after sorting.
	// This is a bit inneficient - we collect more data than we need to return -
	// but it's a simple way to implement basic pagination.
	if opts.limit > 0 {
		startIdx := (opts.page) * opts.limit
		endIdx := startIdx + opts.limit
		if startIdx >= int64(len(flows)) {
			return nil
		}
		if endIdx > int64(len(flows)) {
			endIdx = int64(len(flows))
		}
		logrus.WithFields(logrus.Fields{
			"pageSize":   opts.limit,
			"pageNumber": opts.page,
			"startIdx":   startIdx,
			"endIdx":     endIdx,
			"total":      len(flows),
		}).Debug("Returning paginated flows")

		flows = flows[startIdx:endIdx]
	}

	return flows
}

func (r *RingIndex) Add(d *types.DiachronicFlow) {
}

func (r *RingIndex) Remove(d *types.DiachronicFlow) {
}
