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

package storage

import (
	"errors"
	"fmt"
	"sort"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var ErrStopBucketIteration = errors.New("stop bucket iteration")

type lookupFn func(key types.FlowKey) *DiachronicFlow

type BucketRing struct {
	// buckets is a ring buffer of aggregation buckets for efficient rollover.
	buckets   []*AggregationBucket
	headIndex int
	interval  int

	// nowFunc allows overriding the current time, used in tests.
	nowFunc func() time.Time

	// indices allow for quick handling of flow queries sorted by various methods.
	indices map[proto.SortBy]Index[string]

	// defaultIndex is the default index to use when no sort order is specified.
	defaultIndex *RingIndex

	// diachronics stores a quick lookup of flow identifer to the DiachronicFlow object which
	// contains the bucketed statistics for that flow. This is the primary data structure
	// for storing per-Flow statistics over time.
	diachronics map[types.FlowKey]*DiachronicFlow

	// streams receives flows from the bucket ring on rollover in order to
	// satisfy stream requests.
	streams Receiver

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

	// nextID is used to assign unique IDs to DiachronicFlows as they are created.
	nextID int64
}

func NewBucketRing(n, interval int, now int64, opts ...BucketRingOption) *BucketRing {
	ring := &BucketRing{
		buckets:     make([]*AggregationBucket, n),
		headIndex:   0,
		interval:    interval,
		diachronics: make(map[types.FlowKey]*DiachronicFlow),
		indices: map[proto.SortBy]Index[string]{
			proto.SortBy_DestName:        NewIndex(func(k *types.FlowKey) string { return k.DestName() }),
			proto.SortBy_DestNamespace:   NewIndex(func(k *types.FlowKey) string { return k.DestNamespace() }),
			proto.SortBy_SourceName:      NewIndex(func(k *types.FlowKey) string { return k.SourceName() }),
			proto.SortBy_SourceNamespace: NewIndex(func(k *types.FlowKey) string { return k.SourceNamespace() }),
		},
	}
	// Use a time-based Ring index by default.
	ring.defaultIndex = NewRingIndex(ring)

	for _, opt := range opts {
		opt(ring)
	}

	logrus.WithFields(logrus.Fields{
		"num":        n,
		"bucketSize": time.Duration(interval) * time.Second,
	}).Debug("Initializing aggregation buckets")

	// Determine the latest bucket start time. To account for some amount of time drift,
	// we'll extend the ring one interval into the future. This helps ensure that we don't miss any
	// flows that come from nodes with a time that's slightly ahead of ours.
	newestBucketStart := now + int64(interval)

	// Initialize an empty bucket into each slot in the ring.
	for i := range n {
		ring.buckets[i] = NewAggregationBucket(time.Unix(0, 0), time.Unix(0, 0))
	}

	// Seed the buckets with the correct state. To do this, we'll initialize the first bucket
	// to be the oldest bucket and then roll over the buckets until we have populated the entire ring. This
	// is an easy way to ensure that the buckets are in the correct state.
	oldestBucketStart := time.Unix(newestBucketStart-int64(interval*n), 0)
	oldestBucketEnd := time.Unix(oldestBucketStart.Unix()+int64(interval), 0)
	ring.buckets[0] = NewAggregationBucket(oldestBucketStart, oldestBucketEnd)
	for range n {
		ring.Rollover(nil)
	}

	// Tell each bucket its absolute index and initialize the lookup function.
	for i := range ring.buckets {
		ring.buckets[i].index = i
		ring.buckets[i].lookupFlow = func(key types.FlowKey) *DiachronicFlow {
			return ring.diachronics[key]
		}
	}

	logrus.WithFields(logrus.Fields{
		"headIndex": ring.headIndex,
		"start":     ring.BeginningOfHistory(),
		"end":       ring.EndOfHistory(),
		"now":       now,
	}).Debug("Initialized bucket ring")
	return ring
}

func (r *BucketRing) ID(key types.FlowKey) int64 {
	if d, ok := r.diachronics[key]; ok {
		return d.ID
	}
	return -1
}

func (r *BucketRing) Size() int64 {
	return int64(len(r.diachronics))
}

// TODO: Should we not be using proto types here?
func (r *BucketRing) List(req *proto.FlowListRequest) ([]*types.Flow, *types.ListMeta, error) {
	// If a sort order was requested, use the corresponding index to find the matching flows.
	if len(req.SortBy) > 0 && req.SortBy[0].SortBy != proto.SortBy_Time {
		if idx, ok := r.indices[req.SortBy[0].SortBy]; ok {
			// If a sort order was requested, use the corresponding index to find the matching flows.
			// We need to convert the FlowKey to a string for the index lookup.
			flows, meta := idx.List(IndexFindOpts{
				startTimeGt: req.StartTimeGte,
				startTimeLt: req.StartTimeLt,
				pageSize:    req.PageSize,
				page:        req.Page,
				filter:      req.Filter,
			})
			return flows, &meta, nil
		} else {
			return nil, nil, fmt.Errorf("unsupported sort order: %s", req.SortBy[0].SortBy)
		}
	}

	// Default to time-sorted flow data.
	var flows []*types.Flow
	flows, meta := r.defaultIndex.List(IndexFindOpts{
		startTimeGt: req.StartTimeGte,
		startTimeLt: req.StartTimeLt,
		pageSize:    req.PageSize,
		page:        req.Page,
		filter:      req.Filter,
	})
	return flows, &meta, nil
}

// extractPolicyFieldsFromFlowKey is a convenience function to extract policy fields from a flow key. The given function
// is run over all policy hits (enforced and pending) to get all of the values.
func extractPolicyFieldsFromFlowKey(getField func(*proto.PolicyHit) string) func(key *types.FlowKey) []string {
	return func(key *types.FlowKey) []string {
		var values []string

		policyTrace := types.FlowLogPolicyToProto(key.Policies())
		for _, policyList := range [][]*proto.PolicyHit{policyTrace.EnforcedPolicies, policyTrace.PendingPolicies} {
			for _, p := range policyList {
				val := getField(p)
				if p.Trigger != nil {
					// EndOfTier policies store the tier in the trigger.
					val = getField(p.Trigger)
				}

				values = append(values, val)
			}
		}

		return values
	}
}

func (r *BucketRing) FilterHints(req *proto.FilterHintsRequest) ([]string, *types.ListMeta, error) {
	var sortBy proto.SortBy
	var valueFunc func(*types.FlowKey) []string
	switch req.Type {
	case proto.FilterType_FilterTypeDestName:
		sortBy = proto.SortBy_DestName
	case proto.FilterType_FilterTypeDestNamespace:
		sortBy = proto.SortBy_DestNamespace
	case proto.FilterType_FilterTypeSourceName:
		sortBy = proto.SortBy_SourceName
	case proto.FilterType_FilterTypeSourceNamespace:
		sortBy = proto.SortBy_SourceNamespace
	case proto.FilterType_FilterTypePolicyTier:
		valueFunc = extractPolicyFieldsFromFlowKey(
			func(p *proto.PolicyHit) string {
				return p.Tier
			},
		)
	case proto.FilterType_FilterTypePolicyName:
		valueFunc = extractPolicyFieldsFromFlowKey(
			func(p *proto.PolicyHit) string {
				return p.Name
			},
		)
	default:
		return nil, nil, fmt.Errorf("unsupported filter type '%s'", req.Type.String())
	}

	var values []string
	var meta types.ListMeta
	// If a sort order was requested, use the corresponding index to find the matching flows.
	if idx, ok := r.indices[sortBy]; ok {
		values, meta = idx.SortValueSet(IndexFindOpts{
			startTimeGt: req.StartTimeGte,
			startTimeLt: req.StartTimeLt,
			pageSize:    req.PageSize,
			page:        req.Page,
			filter:      req.Filter,
		})
	} else if valueFunc != nil {
		values, meta = r.defaultIndex.FilterValueSet(valueFunc, IndexFindOpts{
			startTimeGt: req.StartTimeGte,
			startTimeLt: req.StartTimeLt,
			pageSize:    req.PageSize,
			page:        req.Page,
			filter:      req.Filter,
		})
	} else {
		return nil, nil, fmt.Errorf("unsupported sort order")
	}
	return values, &meta, nil
}

// Rollover moves the head index to the next bucket, resetting to 0 if we've reached the end.
// It also clears data from the bucket that is now the head. The start time of the newest bucket
// is returned, as well as a set of DiachronicFlow objects that were in the now obsolete bucket.
func (r *BucketRing) Rollover(sink Sink) int64 {
	start := r.nowFunc()
	defer func() {
		if r.nowFunc().Sub(start) > 1*time.Second {
			logrus.WithField("duration", r.nowFunc().Sub(start)).Warn("Rollover took >1s")
		}
	}()

	// Capture the new bucket's start time - this is the end time of the previous bucket.
	startTime := r.buckets[r.headIndex].EndTime
	endTime := startTime + int64(r.interval)

	// Send flows to the stream manager.
	r.flushToStreams()

	// Move the head index to the next bucket.
	r.headIndex = r.nextBucketIndex(r.headIndex)

	// Capture the flows from the bucket before we clear it.
	flows := set.New[*DiachronicFlow]()
	if r.buckets[r.headIndex].Flows != nil {
		for d := range r.buckets[r.headIndex].Flows.All() {
			flows.Add(d)
		}
	}

	// Clear data from the bucket that is now the head. The start time of the new bucket
	// is the end time of the previous bucket.
	r.buckets[r.headIndex].Reset(startTime, endTime)

	// Update DiachronicFlows. We need to remove any windows from the DiachronicFlows that have expired.
	// Find the oldest bucket's start time and remove any data from the DiachronicFlows that is older than that.
	for d := range flows.All() {
		// Rollover the DiachronicFlow. This will remove any expired data from it.
		d.Rollover(r.BeginningOfHistory())

		if d.Empty() {
			// If the DiachronicFlow is empty, we can remove it. This means it hasn't received any
			// flow updates in a long time.
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.WithFields(d.Key.Fields()).Debug("Removing empty DiachronicFlow")
			}
			for _, idx := range r.indices {
				idx.Remove(d)
			}
			delete(r.diachronics, d.Key)
		}
	}

	// Emit flows to the sink.
	if sink != nil {
		r.EmitFlowCollections(sink)
	}

	return startTime
}

func (r *BucketRing) AddFlow(flow *types.Flow) {
	// Find the window for this Flow based on the global bucket ring. We use the ring to ensure
	// that time windows are consistent across all DiachronicFlows.
	start, end, err := r.Window(flow)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"start": flow.StartTime,
			// "now":   a.nowFunc().Unix(),
		}).WithFields(flow.Key.Fields()).
			WithError(err).
			Warn("Unable to sort flow into a bucket")
		return
	}

	// Check if we are tracking a DiachronicFlow for this FlowKey, and create one if not.
	// Then, add this Flow to the DiachronicFlow.
	if _, ok := r.diachronics[*flow.Key]; !ok {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			// Unpacking the key is a bit expensive, so only do it in debug mode.
			logrus.WithFields(flow.Key.Fields()).Debug("Creating new DiachronicFlow for flow")
		}
		r.nextID++
		d := NewDiachronicFlow(flow.Key, r.nextID)
		r.diachronics[*flow.Key] = d

		// Add the DiachronicFlow to all indices.
		for _, idx := range r.indices {
			idx.Add(d)
		}
	}
	r.diachronics[*flow.Key].AddFlow(flow, start, end)

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

	// TODO: Adding the flow to the bucket can currently block if the bucket is being accessed
	// by another thread. This should be relatively rare and short, but ideally we'd make adding a Flow
	// to a bucket non-blocking.
	fields := bucket.Fields()
	fields["flowStart"] = flow.StartTime
	fields["head"] = r.headIndex
	logrus.WithFields(fields).Debug("Adding flow to bucket")
	bucket.AddFlow(flow)
}

// FlowSet returns the set of flows that exist across buckets within the given time range.
func (r *BucketRing) FlowSet(startGt, startLt int64) set.Set[*DiachronicFlow] {
	// TODO: Right now, this iterates all the buckets. We can make a minor optimization here
	// by calculating the buckets to iterate based on the time range.
	flows := set.New[*DiachronicFlow]()
	for _, b := range r.buckets {
		if (startGt == 0 || b.StartTime >= startGt) &&
			(startLt == 0 || b.StartTime <= startLt) {

			for d := range b.Flows.All() {
				flows.Add(d)
			}
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
		b := r.buckets[i]
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
	if r.buckets[startIndex].pushed {
		logrus.WithFields(r.buckets[startIndex].Fields()).Debug("Bucket has already been published, waiting for next bucket")
		return nil
	}
	logrus.WithFields(r.buckets[startIndex].Fields()).Debug("Bucket is ready to emit")
	startTime := r.buckets[startIndex].StartTime
	endTime := r.buckets[endIndex].StartTime

	flows := NewFlowCollection(startTime, endTime)

	// Go through each bucket in the window and build the set of flows to emit.
	keys := set.New[*DiachronicFlow]()
	r.iterBuckets(startIndex, endIndex, func(i int) error {
		logrus.WithFields(r.buckets[i].Fields()).Debug("Gathering flows from bucket")
		keys.AddAll(r.buckets[i].Flows.Slice())

		// Add a pointer to the bucket to the FlowCollection. This allows us to mark the bucket as pushed
		// once emitted.
		flows.buckets = append(flows.buckets, r.buckets[i])
		return nil
	})

	// Use the DiachronicFlow data to build the aggregated flows.
	for d := range keys.All() {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(d.Key.Fields()).WithFields(logrus.Fields{
				"start": startTime,
				"end":   endTime,
			}).Debug("Building aggregated flow for emission")
		}
		if f := d.Aggregate(startTime, endTime); f != nil {
			flows.Flows = append(flows.Flows, *f)
		}
	}

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

	err := r.iterBucketsTime(req.StartTimeGte, req.StartTimeLt, func(b *AggregationBucket) error {
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
	logrus.WithFields(bucket.Fields()).Debug("Flushing bucket to stream manager")
	r.streamBucket(bucket, r.streams)

	if time.Since(start) > 1*time.Second {
		logrus.WithFields(logrus.Fields{
			"duration":    time.Since(start),
			"numInBucket": bucket.Flows.Len(),
		}).Info("Flushing streams > 1s")
	}
}

func (r *BucketRing) streamBucket(b *AggregationBucket, s Receiver) {
	b.markReady()
	s.Receive(b, "")
}

// streamingBucket returns the bucket currently slated to be sent to the stream manager.
func (r *BucketRing) streamingBucket() *AggregationBucket {
	// The head index is always one bucket into the future, and the bucket before
	// is the currently filling one. So start two back from the head.
	idx := r.indexSubtract(r.headIndex, 2)
	return r.buckets[idx]
}

// BackfillEndTime returns the time that backfill should complete at. This ensures that backfill doesn't
// go past the end of the next bucket to be emitted on rollover, which would otherwise result in
// duplicate and incomplete flows being streamed.
func (r *BucketRing) BackfillEndTime() int64 {
	return r.streamingBucket().StartTime
}

// iterBuckets iterates over the buckets in the ring, from the starting index until the ending index.
// i.e., i := start; i < end; i++ (but handles wraparound)
func (r *BucketRing) iterBuckets(start, end int, f func(i int) error) {
	idx := start
	for idx != end {
		if err := f(idx); err != nil {
			if errors.Is(err, ErrStopBucketIteration) {
				return
			}
		}
		idx = r.nextBucketIndex(idx)
	}
}

// iterBucketsTime iterates over the buckets in the ring, from the starting time until the ending time.
// If either time is not found, an error is returned.
// If the start time is zero, it will start from the beginning of the ring.
// If the end time is zero, it will iterate until the current time.
func (r *BucketRing) iterBucketsTime(start, end int64, f func(b *AggregationBucket) error) error {
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
	r.iterBuckets(startIdx, endIdx, func(i int) error {
		return f(r.buckets[i])
	})
	return nil
}

func (r *BucketRing) NumFlows(start, end int64) int {
	var count int
	_ = r.iterBucketsTime(start, end, func(b *AggregationBucket) error {
		count += b.Flows.Len()
		return nil
	})
	return count
}

func (r *BucketRing) Backfill(recv Receiver, id string, start int64) {
	// Backfill the stream with any buckets that match its time range.
	_ = r.iterBucketsTime(start, r.BackfillEndTime(), func(b *AggregationBucket) error {
		recv.Receive(b, id)
		return nil
	})
}

// IterFlows iterates through all of the Flows in the given time range.
func (r *BucketRing) IterFlows(start, end int64, f func(d *DiachronicFlow, s, e int64) error) error {
	// Iterate all of the buckets in the given range.
	_ = r.iterBucketsTime(start, end, func(b *AggregationBucket) error {
		stopBucketIteration := false

		// Iterate through all of the flows in the bucket.
		for d := range b.Flows.All() {
			if err := f(d, b.StartTime, b.EndTime); errors.Is(err, ErrStopBucketIteration) {
				stopBucketIteration = true
				break
			}
		}

		if stopBucketIteration {
			// If the inner function indicates to stop iterating, return a StopBucketIteration error
			// to skip any remaining buckets.
			return ErrStopBucketIteration
		}
		return nil
	})
	return nil
}
