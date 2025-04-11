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
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var StopBucketIteration = errors.New("stop bucket iteration")

// StreamReceiver represents an object that can receive streams of flows.
type StreamReceiver interface {
	Receive(FlowBuilder)
}

// FlowBuilder provides an interface for building Flows. It allows us to conserve memory by
// only rendering Flow objects when they match the filter.
type FlowBuilder interface {
	BuildInto(*proto.Filter, *proto.FlowResult) bool
}

func NewDeferredFlowBuilder(d *types.DiachronicFlow, s, e int64) FlowBuilder {
	return &DeferredFlowBuilder{
		d: d,
		w: d.GetWindows(s, e),
		s: s,
		e: e,
	}
}

// DeferredFlowBuilder is a FlowBuilder that defers the construction of the Flow object until it's needed.
type DeferredFlowBuilder struct {
	d *types.DiachronicFlow
	s int64
	e int64

	// w is the set of windows that this flow is in at the time this builder is instantiated.
	// We hold references to the underlying Window objects so that we can aggregate across them on another
	// goroutine without worrying about the original DiachronicFlow windows being modified.
	//
	// Note: This is a bit of a hack, but it works for now. We can clean this up a lot by reconciling
	// the Window and AggregationBucket objects, which fill similar roles.
	w []*types.Window
}

func (f *DeferredFlowBuilder) BuildInto(filter *proto.Filter, res *proto.FlowResult) bool {
	if f.d.Matches(filter, f.s, f.e) {
		if tf := f.d.AggregateWindows(f.w); tf != nil {
			types.FlowIntoProto(tf, res.Flow)
			res.Id = f.d.ID
			return true
		}
	}
	return false
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
	for range n {
		ring.Rollover()
	}

	// Tell each bucket its absolute index and initialize the lookup function.
	for i := range ring.buckets {
		ring.buckets[i].index = i
		ring.buckets[i].lookupFlow = ring.lookupFlow
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
// is returned, as well as a set of DiachronicFlow objects that were in the now obsolete bucket.
func (r *BucketRing) Rollover() (int64, set.Set[*types.DiachronicFlow]) {
	// Capture the new bucket's start time - this is the end time of the previous bucket.
	startTime := r.buckets[r.headIndex].EndTime
	endTime := startTime + int64(r.interval)

	// Send flows to the stream manager.
	r.flushToStreams()

	// Move the head index to the next bucket.
	r.headIndex = r.nextBucketIndex(r.headIndex)

	// Capture the flows from the bucket before we clear it.
	flows := set.New[*types.DiachronicFlow]()
	if r.buckets[r.headIndex].Flows != nil {
		r.buckets[r.headIndex].Flows.Iter(func(d *types.DiachronicFlow) error {
			flows.Add(d)
			return nil
		})
	}

	// Clear data from the bucket that is now the head. The start time of the new bucket
	// is the end time of the previous bucket.
	r.buckets[r.headIndex].Reset(startTime, endTime)
	return startTime, flows
}

func (r *BucketRing) AddFlow(flow *types.Flow) {
	// Sort this update into a bucket.
	_, bucket := r.findBucket(flow.StartTime)
	if bucket == nil {
		logrus.WithFields(logrus.Fields{
			"time":   flow.StartTime,
			"oldest": r.BeginningOfHistory(),
			"newest": r.EndOfHistory(),
		}).Warn("Failed to find bucket, unable to ingest flow")
		return
	}

	fields := bucket.Fields()
	fields["flowStart"] = flow.StartTime
	fields["head"] = r.headIndex
	logrus.WithFields(fields).Debug("Adding flow to bucket")
	bucket.AddFlow(flow)
}

// FlowSet returns the set of flows that exist across buckets within the given time range.
func (r *BucketRing) FlowSet(startGt, startLt int64) set.Set[*types.DiachronicFlow] {
	// TODO: Right now, this iterates all the buckets. We can make a minor optimization here
	// by calculating the buckets to iterate based on the time range.
	flows := set.New[*types.DiachronicFlow]()
	for _, b := range r.buckets {
		if (startGt == 0 || b.StartTime >= startGt) &&
			(startLt == 0 || b.StartTime <= startLt) {

			b.Flows.Iter(func(d *types.DiachronicFlow) error {
				flows.Add(d)
				return nil
			})
		}
	}
	return flows
}

// BeginningOfHistory returns the start time of the oldest bucket in the ring.
func (r *BucketRing) BeginningOfHistory() int64 {
	// Since the head index points to the newest bucket, and we increment
	// the headIndex on rollover, the oldest bucket is the one right after it (i.e.,
	// the next bucket to be rolled over).
	return r.buckets[r.nextBucketIndex(r.headIndex)].StartTime
}

func (r *BucketRing) EndOfHistory() int64 {
	return r.buckets[r.headIndex].EndTime
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
	logrus.WithFields(logrus.Fields{
		"time":   time,
		"oldest": r.BeginningOfHistory(),
		"newest": r.EndOfHistory(),
	}).Warn("Failed to find bucket")
	return -1, nil
}

// nowIndex returns the index of the bucket that represents the current time.
// This is different from the head index, which is actually one bucket into the future.
func (r *BucketRing) nowIndex() int {
	return r.indexSubtract(r.headIndex, 1)
}

func (r *BucketRing) indexBetween(start, end, target int) bool {
	if start == end {
		// No range to check.
		return false
	}

	if start < end {
		// The range is non-wrapping.
		return target > start && target < end
	}
	// The range wraps around.
	return target > start || target < end
}

func (r *BucketRing) EmitFlowCollections(sink Sink) {
	if sink == nil {
		logrus.Debug("No sink configured, skip flow emission")
		return
	}

	// Determine the newest bucket in the aggregation - this is always pushAfter buckets back from "now".
	endIndex := r.indexSubtract(r.nowIndex(), r.pushAfter)
	startIndex := r.indexSubtract(endIndex, r.bucketsToAggregate)

	// We need to go back through time until we find a flow collection that has already been published.
	collections := []*FlowCollection{}
	for {
		c := r.maybeBuildFlowCollection(startIndex, endIndex)
		if c == nil {
			logrus.WithFields(logrus.Fields{
				"startIndex": startIndex,
				"endIndex":   endIndex,
				"startTime":  r.buckets[startIndex].StartTime,
				"endTime":    r.buckets[endIndex].StartTime,
			}).Debug("Reached an already emitted bucket")
			break
		}
		collections = append(collections, c)

		// Update the start and end index for the next collection.
		// Since we're going backwards in time, the end time of the next collection is the start time
		// of the current collection and the start time is another bucketsToAggregate earlier.
		endIndex = startIndex
		startIndex = r.indexSubtract(startIndex, r.bucketsToAggregate)

		// Terminate the loop if we've gone through all the buckets.
		if r.indexBetween(startIndex, endIndex, r.headIndex) {
			break
		}
	}

	// Emit the collections to the sink.
	for i := len(collections) - 1; i >= 0; i-- {
		c := collections[i]
		if len(c.Flows) > 0 {
			logrus.WithFields(logrus.Fields{
				"start": c.StartTime,
				"end":   c.EndTime,
				"num":   len(c.Flows),
			}).Debug("Emitting flow collection")
			sink.Receive(c)
			c.Complete()
		}
	}
}

// maybeBuildFlowCollection returns a collection of flows to emit, or nil if the flow collection has already been emitted.
func (r *BucketRing) maybeBuildFlowCollection(startIndex, endIndex int) *FlowCollection {
	logrus.WithFields(logrus.Fields{
		"startIndex": startIndex,
		"endIndex":   endIndex,
		"startTime":  r.buckets[startIndex].StartTime,
		"endTime":    r.buckets[endIndex].StartTime,
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

	flows := NewFlowCollection(startTime, endTime)

	// Go through each bucket in the window and build the set of flows to emit.
	keys := set.New[*types.DiachronicFlow]()
	r.IterBuckets(startIndex, endIndex, func(i int) error {
		logrus.WithFields(r.buckets[i].Fields()).Debug("Gathering flows from bucket")
		keys.AddAll(r.buckets[i].Flows.Slice())

		// Add a pointer to the bucket to the FlowCollection. This allows us to mark the bucket as pushed
		// once emitted.
		flows.buckets = append(flows.buckets, &r.buckets[i])
		return nil
	})

	// Use the DiachronicFlow data to build the aggregated flows.
	keys.Iter(func(d *types.DiachronicFlow) error {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
				"start": startTime,
				"end":   endTime,
			}).Debug("Building aggregated flow for emission")
		}
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

	err := r.IterBucketsTime(req.StartTimeGte, req.StartTimeLt, func(b *AggregationBucket) error {
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
		return nil
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
	start := time.Now()

	if r.streams == nil {
		logrus.Warn("No stream receiver configured, not sending flows to streams")
		return
	}

	// Collect the set of flows to emit to the stream manager. Each rollover, we emit
	// a single bucket of flows to the stream manager.
	bucket := r.streamingBucket()
	r.streamBucket(bucket, r.streams)

	if time.Since(start) > 1*time.Second {
		logrus.WithFields(logrus.Fields{
			"duration":    time.Since(start),
			"numInBucket": bucket.Flows.Len(),
		}).Info("Flushing streams > 1s")
	}
}

func (r *BucketRing) streamBucket(b *AggregationBucket, s StreamReceiver) {
	// We need to construct a FlowBuilder for each DiachronicFlow in the bucket serially.
	builders := []FlowBuilder{}
	if b.Flows != nil {
		b.Flows.Iter(func(d *types.DiachronicFlow) error {
			builders = append(builders, NewDeferredFlowBuilder(d, b.StartTime, b.EndTime))
			return nil
		})
	}

	// We can send the builders to the stream manager asynchronously to unblock the main loop.
	go func() {
		for _, b := range builders {
			s.Receive(b)
		}
	}()
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
func (r *BucketRing) IterBuckets(start, end int, f func(i int) error) {
	idx := start
	for idx != end {
		if err := f(idx); err != nil {
			if errors.Is(err, StopBucketIteration) {
				return
			}
		}
		idx = r.nextBucketIndex(idx)
	}
}

// IterBucketsTime iterates over the buckets in the ring, from the starting time until the ending time.
// If either time is not found, an error is returned.
// If the start time is zero, it will start from the beginning of the ring.
// If the end time is zero, it will iterate until the current time.
func (r *BucketRing) IterBucketsTime(start, end int64, f func(b *AggregationBucket) error) error {
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
	r.IterBuckets(startIdx, endIdx, func(i int) error {
		return f(&r.buckets[i])
	})
	return nil
}
