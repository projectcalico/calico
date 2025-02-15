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
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
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

	// FlowKeys contains an indication of the flows that are part of this bucket.
	FlowKeys set.Set[types.FlowKey]

	// Tracker for statistics within this bucket.
	stats *statisticsIndex
}

func (b *AggregationBucket) AddFlow(flow *types.Flow) {
	if b.Pushed {
		logrus.WithField("flow", flow).Warn("Adding flow to already published bucket")
	}

	// Mark this Flow as part of this bucket.
	b.FlowKeys.Add(*flow.Key)

	// Track policy stats.
	b.stats.AddFlow(flow)
}

func NewAggregationBucket(start, end time.Time) *AggregationBucket {
	return &AggregationBucket{
		StartTime: start.Unix(),
		EndTime:   end.Unix(),
		FlowKeys:  set.New[types.FlowKey](),
		stats:     newStatisticsIndex(),
	}
}

func (b *AggregationBucket) Fields() logrus.Fields {
	return logrus.Fields{
		"start_time": b.StartTime,
		"end_time":   b.EndTime,
		"flows":      b.FlowKeys.Len(),
		"index":      b.index,
	}
}

func (b *AggregationBucket) Reset(start, end int64) {
	b.StartTime = start
	b.EndTime = end
	b.Pushed = false
	b.stats = newStatisticsIndex()

	if b.FlowKeys == nil {
		// When resetting a nil bucket, we need to initialize the FlowKeys set.
		b.FlowKeys = set.New[types.FlowKey]()
	} else {
		// Otherwise, use the existing set but clear it.
		b.FlowKeys.Iter(func(item types.FlowKey) error {
			b.FlowKeys.Discard(item)
			return nil
		})
	}
}

func (b *AggregationBucket) QueryStatistics(q *proto.StatisticsRequest) map[StatisticsKey]*counts {
	return b.stats.QueryStatistics(q)
}
