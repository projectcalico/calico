// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aggregator

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// An aggregation bucket represents a bucket of aggregated flows across a time range.
type AggregationBucket struct {
	// The start and end time of the bucket.
	StartTime int64
	EndTime   int64

	// Pushed indicates whether this bucket has been pushed to the emitter.
	Pushed bool

	// FlowKeys contains an indication of the flows that are part of this bucket.
	FlowKeys set.Set[types.FlowKey]
}

func (b *AggregationBucket) AddFlow(flow *types.Flow) {
	if b.Pushed {
		logrus.WithField("flow", flow).Warn("Adding flow to already published bucket")
	}

	// Mark this Flow as part of this bucket.
	b.FlowKeys.Add(*flow.Key)
}

func NewAggregationBucket(start, end time.Time) *AggregationBucket {
	return &AggregationBucket{
		StartTime: start.Unix(),
		EndTime:   end.Unix(),
		FlowKeys:  set.New[types.FlowKey](),
	}
}

func (b *AggregationBucket) Fields() logrus.Fields {
	return logrus.Fields{
		"start_time": b.StartTime,
		"end_time":   b.EndTime,
		"flows":      b.FlowKeys.Len(),
	}
}

func GetStartTime(interval int) int64 {
	// Start time should always align to interval boundaries so that on restart
	// we can deterministically create a consistent set of buckets. e.g., if the interval is 30s,
	// then the start time should be a multiple of 30s.
	var startTime int64
	for {
		startTime = time.Now().Unix() + int64(interval)
		if startTime%int64(interval) == 0 {
			// We found a multiple - break out of the loop.
			break
		}
		logrus.WithField("start_time", startTime).Debug("Waiting for start time to align to interval")
		time.Sleep(1 * time.Second)
	}
	return startTime
}

func InitialBuckets(n int, interval int, startTime int64) []AggregationBucket {
	logrus.WithFields(logrus.Fields{
		"num":        n,
		"bucketSize": time.Duration(interval) * time.Second,
	}).Debug("Initializing aggregation buckets")

	// Generate an array of N buckets of interval seconds each.
	buckets := make([]AggregationBucket, n)

	// First bucket start time / end time. To account for some amount of clock drift,
	// we'll start the first bucket one interval into the future and work backwards in
	// time from that. This helps ensure that we don't miss any flows that come from nodes
	// with a clock that's slightly ahead of ours.
	startTime = startTime + int64(interval)
	endTime := startTime + int64(interval)

	for i := 0; i < n; i++ {
		// Each bucket is i*interval seconds further back in time.
		buckets[i] = *NewAggregationBucket(
			time.Unix(startTime-int64(i*interval), 0),
			time.Unix(endTime-int64(i*interval), 0),
		)
	}
	return buckets
}
