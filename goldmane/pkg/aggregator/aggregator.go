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
	"sort"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

const (
	// numBuckets is the number of buckets to keep in memory.
	// We keep 240 buckets. Assuming a default window of 15s each, this
	// gives us a total of 1hr of history.
	numBuckets = 240

	// channelDepth is the depth of the channel to use for flow updates.
	channelDepth = 5000
)

// Sink is an interface that can receive aggregated flows.
type Sink interface {
	Receive(*AggregationBucket)
}

// flowRequest is an internal helper used to synchronously request matching flows from the aggregator.
type flowRequest struct {
	respCh chan []*proto.Flow
	req    *proto.FlowRequest
}

type LogAggregator struct {
	buckets []AggregationBucket

	// aggregationWindow is the size of each aggregation bucket.
	aggregationWindow time.Duration

	// Used to trigger goroutine shutdown.
	done chan struct{}

	// Used to make requests for flows synchronously.
	flowRequests chan flowRequest

	// sink is a sink to send aggregated flows to.
	sink Sink

	// recvChan is the channel to receive flow updates on.
	recvChan chan *proto.FlowUpdate

	// rolloverFunc allows manual control over the rollover timer, used in tests.
	// In production, this will be time.After.
	rolloverFunc func(time.Duration) <-chan time.Time

	// bucketsToAggregate is the number of internal buckets to aggregate when pushing flows to the sink.
	// This can be used to reduce the number of distinct flows that are sent to the sink, at the expense of
	// delaying the emission of flows.
	// 20 buckets of 15s provides a 5 minute aggregation.
	bucketsToAggregate int

	// pushIndex is the index of the bucket to push to the emitter. We only push
	// the bucket after it has been rolled over several times, to ensure that we have
	// a complete view of the flows in the bucket.
	//
	// Increasing this value will increase the latency of the emitted flows. Decreasing it too much
	// will cause the emitter to emit incomplete flows.
	//
	// Latency-to-emit is roughly (pushIndex * rolloverTime).
	pushIndex int

	// nowFunc allows overriding the current time, used in tests.
	nowFunc func() time.Time
}

func NewLogAggregator(opts ...Option) *LogAggregator {
	// Establish default aggregator configuration. Options can be used to override these.
	a := &LogAggregator{
		aggregationWindow:  15 * time.Second,
		done:               make(chan struct{}),
		flowRequests:       make(chan flowRequest),
		recvChan:           make(chan *proto.FlowUpdate, channelDepth),
		rolloverFunc:       time.After,
		bucketsToAggregate: 20,
		pushIndex:          30,
		nowFunc:            time.Now,
	}

	// Apply options.
	for _, opt := range opts {
		opt(a)
	}

	// Log out some key information.
	if a.sink != nil {
		logrus.WithFields(logrus.Fields{
			// This is the soonest we will possible emit a flow as part of an aggregation.
			"emissionWindowLeftBound": time.Duration(a.pushIndex-a.bucketsToAggregate) * a.aggregationWindow,

			// This is the latest we will emit a flow as part of an aggregation.
			"emissionWindowRightBound": time.Duration(a.pushIndex) * a.aggregationWindow,

			// This is the total time window that we will aggregate over when generating emitted flows.
			"emissionWindow": time.Duration(a.bucketsToAggregate) * a.aggregationWindow,
		}).Info("Emission of aggregated flows configured")
	}

	logrus.WithFields(logrus.Fields{
		// This is the size of each aggregation bucket.
		"bucketSize": a.aggregationWindow,

		// This is the total amount of history that we will keep in memory.
		"totalHistory": time.Duration(numBuckets) * a.aggregationWindow,
	}).Info("Keeping bucketed flow history in memory")

	return a
}

func (a *LogAggregator) Run(startTime int64) {
	// Initialize the buckets.
	a.buckets = InitialBuckets(numBuckets, int(a.aggregationWindow.Seconds()), startTime)

	// Schedule the first rollover one aggregation period from now.
	rolloverCh := a.rolloverFunc(a.aggregationWindow)

	for {
		select {
		case upd := <-a.recvChan:
			a.handleFlowUpdate(upd)
		case <-rolloverCh:
			rolloverCh = a.rolloverFunc(a.rollover())
			a.maybeEmitBucket()
		case req := <-a.flowRequests:
			logrus.Debug("Received flow request")
			req.respCh <- a.queryFlows(req.req)
		case <-a.done:
			logrus.Warn("Aggregator shutting down")
			return
		}
	}
}

// Receive is used to send a flow update to the aggregator.
func (a *LogAggregator) Receive(f *proto.FlowUpdate) {
	timeout := time.After(5 * time.Second)

	select {
	case a.recvChan <- f:
	case <-timeout:
		logrus.Warn("Output channel full, dropping flow")
	}
}

func (a *LogAggregator) maybeEmitBucket() {
	if a.sink == nil {
		logrus.Debug("No sink configured, skip flow emission")
		return
	}

	if a.buckets[a.pushIndex].Pushed {
		// We've already pushed this bucket, so we can skip it. We'll emit the next flow once
		// bucketsToAggregate buckets have been rolled over.
		logrus.WithFields(a.buckets[a.pushIndex].Fields()).Debug("Skipping already pushed bucket")
		return
	}

	// We should emit an aggregated flow of bucketsToAggregate buckets, starting from the pushIndex.
	b := NewAggregationBucket(
		time.Unix(a.buckets[a.pushIndex].StartTime, 0),
		time.Unix(a.buckets[a.pushIndex-a.bucketsToAggregate+1].EndTime, 0),
	)
	for i := a.pushIndex; i > a.pushIndex-a.bucketsToAggregate; i-- {
		logrus.WithField("idx", i).WithFields(a.buckets[i].Fields()).Debug("Merging bucket")

		// Merge the bucket into the aggregation bucket, and mark it's contents as pushed.
		b.merge(&a.buckets[i])
		a.buckets[i].Pushed = true
	}
	if len(b.Flows) > 0 {
		logrus.WithFields(b.Fields()).Debug("Emitting aggregated bucket to receiver")
		a.sink.Receive(b)
	}
}

// GetFlows returns a list of flows that match the given request. It uses a channel to
// synchronously request the flows from the aggregator.
func (a *LogAggregator) GetFlows(req *proto.FlowRequest) []*proto.Flow {
	respCh := make(chan []*proto.Flow)
	defer close(respCh)
	a.flowRequests <- flowRequest{respCh, req}
	return <-respCh
}

func (a *LogAggregator) queryFlows(req *proto.FlowRequest) []*proto.Flow {
	// Collect all of the flows across all buckets that match the request. We will then
	// combine matching flows together, returning an aggregated view across the time range.
	flowsByKey := map[types.FlowKey]*types.Flow{}

	for i, bucket := range a.buckets {
		// Ignore buckets that fall outside the time range. Once we hit a bucket
		// whose end time comes before the start time of the request, we can stop.
		if bucket.EndTime <= req.StartTimeGt {
			// We've reached a bucket that doesn't fall within the request time range.
			// We can stop checking the remaining buckets, and can mark the start time
			// of the aggregated flows as the end time of this bucket.
			logrus.WithField("index", i).Debug("No need to check remaining buckets")
			break
		}

		// If this bucket's start time is after the end time of the request, then we can
		// skip this bucket and move on to the next one.
		if req.StartTimeLt > 0 && bucket.StartTime >= req.StartTimeLt {
			logrus.WithField("index", i).Debug("Skipping bucket because it starts after the requested time window")
			continue
		}

		// Check each flow in the bucket to see if it matches the request.
		for key, flow := range bucket.Flows {
			if !flowMatches(flow, req) {
				logrus.Debug("Skipping flow because it doesn't match the request")
				continue
			}

			if _, ok := flowsByKey[key]; !ok {
				// Initialize the flow if it doesn't exist by making a copy.
				cp := *flow
				logrus.WithField("idx", i).WithFields(bucket.Fields()).Debug("Adding new flow to results")

				// Set the start and end times of this flow to match the bucket.
				// Aggregated flows always align with bucket intervals for consistent rate calculation.
				cp.StartTime = bucket.StartTime
				cp.EndTime = bucket.EndTime
				flowsByKey[key] = &cp
			} else {
				logrus.WithField("idx", i).WithFields(bucket.Fields()).Debug("Adding flow contribution from bucket to results")

				// Add this bucket's contribution to the flow.
				mergeFlowInto(flowsByKey[key], flow)

				// Since this flow was present in a later (chronologically) bucket, we need to update the start time
				// of the flow to the start time of this (earlier chronologically) bucket.
				flowsByKey[key].StartTime = bucket.StartTime
			}
		}
	}

	// Convert the map to a slice.
	flows := []*proto.Flow{}
	for _, flow := range flowsByKey {
		flows = append(flows, types.FlowToProto(flow))
	}
	// Sort the flows by start time, sorting newer flows first.
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].StartTime > flows[j].StartTime
	})

	// If pagination was requested, apply it now after sorting.
	// This is a bit inneficient - we collect more data than we need to return -
	// but it's a simple way to implement basic pagination.
	if req.PageSize > 0 {
		startIdx := (req.PageNumber) * req.PageSize
		endIdx := startIdx + req.PageSize
		if startIdx >= int64(len(flows)) {
			return []*proto.Flow{}
		}
		if endIdx > int64(len(flows)) {
			endIdx = int64(len(flows))
		}
		flows = flows[startIdx:endIdx]
		logrus.WithFields(logrus.Fields{
			"pageSize":   req.PageSize,
			"pageNumber": req.PageNumber,
			"startIdx":   startIdx,
			"endIdx":     endIdx,
			"total":      len(flows),
		}).Debug("Returning paginated flows")
	}
	return flows
}

func (a *LogAggregator) Stop() {
	close(a.done)
}

func (a *LogAggregator) rollover() time.Duration {
	currentBucketEnd := a.buckets[0].EndTime

	// Add a new bucket at the start and remove the last bucket.
	start := time.Unix(a.buckets[0].EndTime, 0)
	end := start.Add(a.aggregationWindow)
	a.buckets = append([]AggregationBucket{*NewAggregationBucket(start, end)}, a.buckets[:len(a.buckets)-1]...)
	logrus.WithFields(a.buckets[0].Fields()).Debug("Rolled over. New bucket")

	// Determine when we should next rollover. We don't just blindly use the rolloverTime, as this leave us
	// susceptible to slowly drifting over time. Instead, we calculate when the next bucket should start and
	// calculate the difference between then and now.
	//
	// The next bucket should start at the end time of the current bucket.
	nextBucketStart := time.Unix(currentBucketEnd, 0)
	now := a.nowFunc()

	// If the next bucket start time is in the past, we've fallen behind and need to catch up.
	// Schedule a rollover immediately.
	if nextBucketStart.Before(now) {
		logrus.WithFields(logrus.Fields{
			"now":             now.Unix(),
			"nextBucketStart": nextBucketStart.Unix(),
		}).Warn("Falling behind, scheduling immediate rollover")
		// We don't actually use 0 time, as it could starve the main routine. Use a small amount of delay.
		return 10 * time.Millisecond
	}

	// The time until the next rollover is the difference between the next bucket start time and now.
	rolloverIn := nextBucketStart.Sub(now)
	logrus.WithFields(logrus.Fields{
		"nextBucketStart": nextBucketStart.Unix(),
		"now":             now.Unix(),
		"rolloverIn":      rolloverIn,
	}).Debug("Scheduling next rollover")
	return rolloverIn
}

func (a *LogAggregator) handleFlowUpdate(upd *proto.FlowUpdate) {
	logrus.WithField("update", upd).Debug("Received FlowUpdate")

	// Check if there is a FlowKey entry for this Flow.
	i, bucket := a.findBucket(upd.Flow.StartTime)
	if bucket == nil {
		logrus.WithFields(logrus.Fields{
			"time":   upd.Flow.StartTime,
			"oldest": a.buckets[len(a.buckets)-1].StartTime,
			"newest": a.buckets[0].EndTime,
		}).Warn("Failed to find bucket, unable to ingest flow")
		return
	}

	logrus.WithField("idx", i).WithFields(bucket.Fields()).Debug("Adding flow to bucket")
	bucket.AddFlow(types.ProtoToFlow(upd.Flow))
}

func (a *LogAggregator) findBucket(time int64) (int, *AggregationBucket) {
	// Find the bucket that contains the given time.
	for i, b := range a.buckets {
		if time >= b.StartTime && time <= b.EndTime {
			return i, &b
		}
	}
	logrus.WithField("time", time).Warn("Failed to find bucket")
	return 0, nil
}
