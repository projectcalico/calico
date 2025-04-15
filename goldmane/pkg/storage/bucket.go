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

package storage

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// An aggregation bucket represents a bucket of aggregated flows across a time range.
type AggregationBucket struct {
	// index is the index of the bucket in the ring.
	index int

	// The start and end time of the bucket.
	StartTime int64
	EndTime   int64

	// Pushed indicates whether this bucket has been pushed to the emitter.
	Pushed bool

	// LookupFlow is a function that can be used to look up a DiachronicFlow by its key.
	lookupFlow lookupFn

	// Flows contains an indication of the flows that are part of this bucket.
	Flows set.Set[*DiachronicFlow]

	// Tracker for statistics within this bucket.
	stats *statisticsIndex
}

func (b *AggregationBucket) AddFlow(flow *types.Flow) {
	if b.Pushed {
		logrus.WithField("flow", flow).Warn("Adding flow to already published bucket")
	}

	if flow == nil {
		logrus.Fatal("BUG: Attempted to add nil flow to bucket")
	}
	if flow.Key == nil {
		logrus.WithField("flow", flow).Fatal("BUG: Attempted to add flow with nil key to bucket")
	}
	if b.lookupFlow == nil {
		logrus.WithField("flow", flow).Fatal("BUG: Attempted to add flow to bucket with no lookup function")
	}
	d := b.lookupFlow(*flow.Key)
	if d == nil {
		logrus.WithField("flow", flow).Fatal("BUG: Attempted to add flow with no corresponding DiachronicFlow")
	}

	// Mark this Flow as part of this bucket.
	b.Flows.Add(d)

	// Track policy stats.
	b.stats.AddFlow(flow)
}

func NewAggregationBucket(start, end time.Time) *AggregationBucket {
	return &AggregationBucket{
		StartTime: start.Unix(),
		EndTime:   end.Unix(),
		Flows:     set.New[*DiachronicFlow](),
		stats:     newStatisticsIndex(),
	}
}

func (b *AggregationBucket) Fields() logrus.Fields {
	return logrus.Fields{
		"start_time": b.StartTime,
		"end_time":   b.EndTime,
		"flows":      b.Flows.Len(),
		"index":      b.index,
	}
}

func (b *AggregationBucket) Reset(start, end int64) {
	b.StartTime = start
	b.EndTime = end
	b.Pushed = false
	b.stats = newStatisticsIndex()

	if b.Flows == nil {
		// When resetting a nil bucket, we need to initialize the Flows set.
		b.Flows = set.New[*DiachronicFlow]()
	} else {
		// Otherwise, use the existing set but clear it.
		b.Flows.Iter(func(item *DiachronicFlow) error {
			b.Flows.Discard(item)
			return nil
		})
	}
}

func (b *AggregationBucket) QueryStatistics(q *proto.StatisticsRequest) map[StatisticsKey]*counts {
	return b.stats.QueryStatistics(q)
}
