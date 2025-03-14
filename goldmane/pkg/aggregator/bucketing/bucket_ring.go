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

package bucketing

import (
	"fmt"
	"sort"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// StreamReceiver represents an object that can receive streams of flows.
type StreamReceiver interface {
	Receive(FlowBuilder)
}

// FlowBuilder provides an interface for building Flows. It allows us to conserve memory by
// only rendering Flow objects when they match the filter.
type FlowBuilder interface {
	// Build returns a Flow and its ID.
	Build(*proto.Filter) (*types.Flow, int64)
}

func NewCachedFlowBuilder(d *types.DiachronicFlow, s, e int64) FlowBuilder {
	return &cachedFlowBuilder{
		d: d,
		s: s,
		e: e,
	}
}

type cachedFlowBuilder struct {
	d *types.DiachronicFlow
	s int64
	e int64

	// cache the result in case we get called multiple times so we can
	// avoid re-aggregating the flow.
	cachedFlow *types.Flow
}

func (f *cachedFlowBuilder) Build(filter *proto.Filter) (*types.Flow, int64) {
	if f.d.Matches(filter, f.s, f.e) {
		if f.cachedFlow == nil {
			logrus.WithFields(logrus.Fields{
				"start":  f.s,
				"end":    f.e,
				"flowID": f.d.ID,
			}).Debug("Building flow")
			f.cachedFlow = f.d.Aggregate(f.s, f.e)
		}
		return f.cachedFlow, f.d.ID
	}
	return nil, 0
}

type lookupFn func(key types.FlowKey) *types.DiachronicFlow

// BucketRing is a ring buffer of aggregation buckets for efficient rollover.
type BucketRing struct {
	buckets   []AggregationBucket
	headIndex int
	interval  int

	// lookupFlow is a function that can be used to look up a DiachronicFlow by its key.
	lookupFlow lookupFn

	// streams receives flows from the bucket ring on rollover in order to
	// satisfy stream requests.
	streams StreamReceiver

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

func NewBucketRing(n, interval int, now int64, opts ...BucketRingOption) *BucketRing {
	ring := &BucketRing{
		buckets:   make([]AggregationBucket, n),
		headIndex: 0,
		interval:  interval,
	}
	for _, opt := range opts {
		opt(ring)
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

	// Send flows to the stream manager.
	r.flushToStreams()

	// Move the head index to the next bucket.
	r.headIndex = r.nextBucketIndex(r.headIndex)

	// Capture the FlowKeys from the bucket before we clear it.
	flowKeys := set.New[types.FlowKey]()
	if r.buckets[r.headIndex].FlowKeys != nil {
		flowKeys.AddAll(r.buckets[r.headIndex].FlowKeys.Slice())
	}

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
	fields["head"] = r.headIndex
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
	return r.indexAdd(idx, 1)
}

// indexSubtract subtracts n from idx, wrapping around if necessary.
func (r *BucketRing) indexSubtract(idx, n int) int {
	return (idx - n + len(r.buckets)) % len(r.buckets)
}

// indexAdd adds n to idx, wrapping around if necessary.
func (r *BucketRing) indexAdd(idx, n int) int {
	return (idx + n) % len(r.buckets)
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
		//
		// Note: we want to loop through the ring starting with the most recent bucket (headIndex) going
		// backwards in time, so we need to decrement the index.
		i = r.indexSubtract(i, 1)
		if i == r.headIndex {
			break
		}
	}
	logrus.WithField("time", time).Warn("Failed to find bucket")
	return -1, nil
}

// FlowCollection returns a collection of flows to emit, or nil if we are still waiting for more data.
// The BucketRing builds a FlowCollection by aggregating flow data from across a window of buckets. The window
// is a fixed size (i.e., a fixed number of buckets), and starts a fixed period of time in the past in order to allow
// for statistics to settle down before publishing.
func (r *BucketRing) FlowCollection() *FlowCollection {
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
		d := r.lookupFlow(key)
		if f := d.Aggregate(startTime, endTime); f != nil {
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

func (r *BucketRing) Statistics(req *proto.StatisticsRequest) ([]*proto.StatisticsResult, error) {
	results := map[StatisticsKey]*proto.StatisticsResult{}

	err := r.IterBucketsTime(req.StartTimeGte, req.StartTimeLt, func(b *AggregationBucket) {
		stats := b.QueryStatistics(req)
		if len(stats) > 0 {
			logrus.WithFields(b.Fields()).WithField("num", len(stats)).Debug("Bucket provided statistics")
		}

		for k, v := range stats {
			if _, ok := results[k]; !ok {
				// Initialize a new result object for this hit.
				results[k] = &proto.StatisticsResult{
					Policy:    types.PolicyHitToProto(k.ToHit()),
					Direction: k.RuleDirection(),
					GroupBy:   req.GroupBy,
					Type:      req.Type,
				}
			}

			if req.TimeSeries {
				// Add the statistics to the result object as a new entry.
				results[k].AllowedIn = append(results[k].AllowedIn, v.AllowedIn)
				results[k].DeniedIn = append(results[k].DeniedIn, v.DeniedIn)
				results[k].AllowedOut = append(results[k].AllowedOut, v.AllowedOut)
				results[k].DeniedOut = append(results[k].DeniedOut, v.DeniedOut)
				results[k].PassedIn = append(results[k].PassedIn, v.PassedIn)
				results[k].PassedOut = append(results[k].PassedOut, v.PassedOut)

				// X axis is the start time of the bucket that the statistics are for.
				results[k].X = append(results[k].X, b.StartTime)
			} else {
				if len(results[k].AllowedIn) == 0 {
					// Initialize the result object for this hit.
					results[k].AllowedIn = append(results[k].AllowedIn, 0)
					results[k].DeniedIn = append(results[k].DeniedIn, 0)
					results[k].AllowedOut = append(results[k].AllowedOut, 0)
					results[k].DeniedOut = append(results[k].DeniedOut, 0)
					results[k].PassedIn = append(results[k].PassedIn, 0)
					results[k].PassedOut = append(results[k].PassedOut, 0)
				}

				// Aggregate across the time range.
				results[k].AllowedIn[0] += v.AllowedIn
				results[k].DeniedIn[0] += v.DeniedIn
				results[k].AllowedOut[0] += v.AllowedOut
				results[k].DeniedOut[0] += v.DeniedOut
				results[k].PassedIn[0] += v.PassedIn
				results[k].PassedOut[0] += v.PassedOut
			}
		}
	})
	if err != nil {
		return nil, err
	}

	// Convert the map to a list, and sort it for determinism.
	var resultsList []*proto.StatisticsResult
	for _, v := range results {
		resultsList = append(resultsList, v)
	}
	sort.Slice(resultsList, func(i, j int) bool {
		// Sort policy hits by its key fields (via the string representation), and then by direction (which is
		// a key field only on the Statistics API for rule grouping).
		p1Str := resultsList[i].Policy.String()
		p2Str := resultsList[j].Policy.String()
		if p1Str == p2Str {
			return resultsList[i].Direction < resultsList[j].Direction
		}
		s1, err := resultsList[i].Policy.ToString()
		if err != nil {
			logrus.WithError(err).Error("Invalid policy hit, statistics sorting may be off")
			return false
		}
		s2, err := resultsList[j].Policy.ToString()
		if err != nil {
			logrus.WithError(err).Error("Invalid policy hit, statistics sorting may be off")
			return false
		}
		return s1 < s2
	})
	return resultsList, nil
}

// flushToStreams sends the flows in the current streaming bucket to the stream receiver.
func (r *BucketRing) flushToStreams() {
	if r.streams == nil {
		logrus.Warn("No stream receiver configured, not sending flows to streams")
		return
	}

	// Collect the set of flows to emit to the stream manager. Each rollover, we emit
	// a single bucket of flows to the stream manager.
	bucket := r.streamingBucket()
	r.streamBucket(bucket, r.streams)
}

func (r *BucketRing) streamBucket(b *AggregationBucket, s StreamReceiver) {
	if b.FlowKeys != nil {
		b.FlowKeys.Iter(func(key types.FlowKey) error {
			s.Receive(NewCachedFlowBuilder(r.lookupFlow(key), b.StartTime, b.EndTime))
			return nil
		})
	}
}

// streamingBucket returns the bucket currently slated to be sent to the stream manager.
func (r *BucketRing) streamingBucket() *AggregationBucket {
	// The head index is always one bucket into the future, and the bucket before
	// is the currently filling one. So start two back from the head.
	idx := r.indexSubtract(r.headIndex, 2)
	return &r.buckets[idx]
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

// IterBucketsTime iterates over the buckets in the ring, from the starting time until the ending time.
// If either time is not found, an error is returned.
// If the start time is zero, it will start from the beginning of the ring.
// If the end time is zero, it will iterate until the current time.
func (r *BucketRing) IterBucketsTime(start, end int64, f func(b *AggregationBucket)) error {
	// Find the buckets that contains the given times, if given.
	startIdx := r.indexAdd(r.headIndex, 1)
	if start != 0 {
		startIdx, _ = r.findBucket(start)
	}
	endIdx := r.headIndex
	if end != 0 {
		endIdx, _ = r.findBucket(end)
	}
	if endIdx == -1 || startIdx == -1 {
		return fmt.Errorf("failed to find bucket for time range %d:%d", start, end)
	}
	r.IterBuckets(startIdx, endIdx, func(i int) {
		f(&r.buckets[i])
	})
	return nil
}
