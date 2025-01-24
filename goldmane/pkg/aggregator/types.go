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
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
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
		"index":      b.index,
	}
}

func (b *AggregationBucket) Reset(start, end int64) {
	b.StartTime = start
	b.EndTime = end
	b.Pushed = false

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

// BucketRing is a ring buffer of aggregation buckets for efficient rollover.
type BucketRing struct {
	buckets   []AggregationBucket
	headIndex int
	interval  int

	// pushAfter is the number of buckets from the head to wait before including
	// a bucket in an aggregated flow for emission. We only push
	// buckets after several rollovers have occurred, to ensure that we have
	// a complete view of the flows in the bucket before emitting them.
	//
	// Increasing this value will increase the latency of the emitted flows. Decreasing it too much
	// will cause the emitter to emit incomplete flows.
	//
	// Latency-to-emit is roughly (pushAfter * rolloverTime).
	pushAfter int

	// bucketsToAggregate is the number of internal buckets to aggregate when pushing flows to the sink.
	// This can be used to reduce the number of distinct flows that are sent to the sink, at the expense of
	// delaying the emission of flows.
	// 20 buckets of 15s provides a 5 minute aggregation.
	bucketsToAggregate int
}

func NewBucketRing(n, interval, pushAfter, bucketsToAggregate int, now int64) *BucketRing {
	ring := &BucketRing{
		buckets:            make([]AggregationBucket, n),
		headIndex:          0,
		interval:           interval,
		pushAfter:          pushAfter,
		bucketsToAggregate: bucketsToAggregate,
	}

	logrus.WithFields(logrus.Fields{
		"num":        n,
		"bucketSize": time.Duration(interval) * time.Second,
	}).Debug("Initializing aggregation buckets")

	// Determine the latest bucket start time. To account for some amount of clock drift,
	// we'll extend the ring one interval into the future. This helps ensure that we don't miss any
	// flows that come from nodes with a clock that's slightly ahead of ours.
	newestBucketStart := now + int64(interval)

	// We need to seed the buckets with the correct state. To do this, we'll initialize the first bucket
	// to be the oldest bucket and then roll over the buckets until we have populated the entire ring. This
	// is an easy way to ensure that the buckets are in the correct state.
	oldestBucketStart := time.Unix(newestBucketStart-int64(interval*n), 0)
	oldestBucketEnd := time.Unix(oldestBucketStart.Unix()+int64(interval), 0)
	ring.buckets[0] = *NewAggregationBucket(oldestBucketStart, oldestBucketEnd)
	for i := 0; i < n; i++ {
		ring.Rollover()
	}

	// Tell each bucket its absolute index.
	for i := range ring.buckets {
		ring.buckets[i].index = i
	}

	logrus.WithFields(logrus.Fields{
		"headIndex":    ring.headIndex,
		"curBucket":    ring.buckets[ring.headIndex],
		"oldestBucket": ring.buckets[(ring.headIndex+1)%n],
	}).Debug("Initialized bucket ring")
	return ring
}

// Rollover moves the head index to the next bucket, resetting to 0 if we've reached the end.
// It also clears data from the bucket that is now the head. The start time of the newest bucket
// is returned, as well as a set of FlowKeys that were in the now obsolete bucket.
func (r *BucketRing) Rollover() (int64, set.Set[types.FlowKey]) {
	// Capture the new bucket's start time - this is the end time of the previous bucket.
	startTime := r.buckets[r.headIndex].EndTime
	endTime := startTime + int64(r.interval)

	// Move the head index to the next bucket.
	r.headIndex = r.nextBucketIndex(r.headIndex)

	// Capture the FlowKeys from the bucket before we clear it.
	flowKeys := r.buckets[r.headIndex].FlowKeys

	// Clear data from the bucket that is now the head. The start time of the new bucket
	// is the end time of the previous bucket.
	r.buckets[r.headIndex].Reset(startTime, endTime)
	return startTime, flowKeys
}

func (r *BucketRing) AddFlow(flow *types.Flow) {
	// Sort this update into a bucket.
	_, bucket := r.findBucket(flow.StartTime)
	if bucket == nil {
		logrus.WithFields(logrus.Fields{
			"time":   flow.StartTime,
			"oldest": r.buckets[r.headIndex-1].StartTime,
			"newest": r.buckets[r.headIndex].EndTime,
		}).Warn("Failed to find bucket, unable to ingest flow")
		return
	}

	fields := bucket.Fields()
	fields["flowStart"] = flow.StartTime
	logrus.WithFields(fields).Debug("Adding flow to bucket")
	bucket.AddFlow(flow)
}

// FlowSet returns the set of FlowKeys that exist across buckets within the given time range.
func (r *BucketRing) FlowSet(startGt, startLt int64) set.Set[types.FlowKey] {
	// TODO: Right now, this iterates all the buckets. We can make a minor optimization here
	// by (1) calculating the buckets to iterate based on the time range, and (2) using pointers to
	// the DiachronicFlow objects instead of using FlowKeys as an intermediary. This is likely a small improvement.
	flowKeys := set.New[types.FlowKey]()
	for _, b := range r.buckets {
		if (startGt == 0 || b.StartTime >= startGt) &&
			(startLt == 0 || b.StartTime <= startLt) {
			flowKeys.AddAll(b.FlowKeys.Slice())
		}
	}
	return flowKeys
}

// BeginningOfHistory returns the start time of the oldest bucket in the ring.
func (r *BucketRing) BeginningOfHistory() int64 {
	// Since the head index points to the newest bucket, and we increment
	// the headIndex on rollover, the oldest bucket is the one right after it (i.e.,
	// the next bucket to be rolled over).
	return r.buckets[r.nextBucketIndex(r.headIndex)].StartTime
}

func (r *BucketRing) Window(flow *types.Flow) (int64, int64, error) {
	// Find the bucket that contains the given time.
	_, bucket := r.findBucket(flow.StartTime)
	if bucket == nil {
		return 0, 0, fmt.Errorf("failed to find bucket for flow")
	}

	// Return the start and end time of the bucket.
	return bucket.StartTime, bucket.EndTime, nil
}

// nextBucketIndex returns the next bucket index, wrapping around if necessary.
func (r *BucketRing) nextBucketIndex(idx int) int {
	return (idx + 1) % len(r.buckets)
}

// indexSubtract subtracts n from idx, wrapping around if necessary.
func (r *BucketRing) indexSubtract(idx, n int) int {
	return (idx - n + len(r.buckets)) % len(r.buckets)
}

func (r *BucketRing) findBucket(time int64) (int, *AggregationBucket) {
	// Find the bucket that contains the given time.
	// TODO: We can do this without iterating over all the buckets by simply calculating
	// the index based on the time. It's a very small win though - there aren't that many buckets to iterate.
	//
	// We always start at the head index and iterate until we find the bucket that contains the time, since
	// most of the time we'll be looking for a recent bucket.
	i := r.headIndex
	for {
		b := &r.buckets[i]
		if time >= b.StartTime && time < b.EndTime {
			return i, b
		}

		// Check the next bucket. If we've wrapped around, we didn't find the bucket.
		i = r.nextBucketIndex(i)
		if i == r.headIndex {
			break
		}
	}
	logrus.WithField("time", time).Warn("Failed to find bucket")
	return 0, nil
}

// FlowCollection returns a collection of flows to emit, or nil if we are still waiting for more data.
// The BucketRing builds a FlowCollection by aggregating flow data from across a window of buckets. The window
// is a fixed size (i.e., a fixed number of buckets), and starts a fixed period of time in the past in order to allow
// for statistics to settle down before publishing.
func (r *BucketRing) FlowCollection(diachronics map[types.FlowKey]*types.DiachronicFlow) *FlowCollection {
	// Determine the newest bucket in the aggregation - this is always N buckets back from the head.
	endIndex := r.indexSubtract(r.headIndex, r.pushAfter)
	startIndex := r.indexSubtract(endIndex, r.bucketsToAggregate)

	logrus.WithFields(logrus.Fields{
		"startIndex": startIndex,
		"endIndex":   endIndex,
	}).Debug("Checking if bucket range should be emitted")

	// Check if we're ready to emit. Wait until the oldest bucket in the window has not yet
	// been pushed, as any newer buckets will not have been pushed either.
	if r.buckets[startIndex].Pushed {
		logrus.WithFields(r.buckets[startIndex].Fields()).Debug("Bucket has already been published, waiting for next bucket")
		return nil
	}
	logrus.WithFields(r.buckets[startIndex].Fields()).Debug("Bucket is ready to emit")
	startTime := r.buckets[startIndex].StartTime
	endTime := r.buckets[endIndex].StartTime

	// Go through each bucket in the window and build the set of flows to emit.
	keys := set.New[types.FlowKey]()
	r.IterBuckets(startIndex, endIndex, func(i int) {
		logrus.WithFields(r.buckets[i].Fields()).Debug("Gathering FlowKeys from bucket")
		keys.AddAll(r.buckets[i].FlowKeys.Slice())

		// Mark the bucket as pushed.
		r.buckets[i].Pushed = true
	})

	// Use the DiachronicFlow data to build the aggregated flows.
	flows := NewFlowCollection(startTime, endTime)
	keys.Iter(func(key types.FlowKey) error {
		logrus.WithFields(logrus.Fields{
			"key":   key,
			"start": startTime,
			"end":   endTime,
		}).Debug("Building aggregated flow for emission")
		c := diachronics[key]
		if f := c.Aggregate(startTime, endTime); f != nil {
			flows.Flows = append(flows.Flows, *f)
		}
		return nil
	})

	// The next bucket that will trigger an emission is the one after the end of the current window.
	// Log this for debugging purposes.
	nextBucket := r.buckets[r.nextBucketIndex(endIndex)]
	logrus.WithFields(nextBucket.Fields()).Debug("Next bucket to emit")

	if len(flows.Flows) == 0 {
		logrus.WithFields(logrus.Fields{
			"start": startTime,
			"end":   endTime,
		}).Debug("No flows to emit in window")
	}
	return flows
}

// IterBuckets iterates over the buckets in the ring, from the starting index until the ending index.
// i.e., i := start; i < end; i++ (but handles wraparound)
func (r *BucketRing) IterBuckets(start, end int, f func(i int)) {
	idx := start
	for idx != end {
		f(idx)
		idx = r.nextBucketIndex(idx)
	}
}
