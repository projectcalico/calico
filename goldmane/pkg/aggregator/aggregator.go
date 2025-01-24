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

// flowRequest is an internal helper used to synchronously request matching flows from the aggregator.
type flowRequest struct {
	respCh chan *flowResponse
	req    *proto.FlowRequest
}

type flowResponse struct {
	flows []*proto.Flow
	err   error
}

type LogAggregator struct {
	// indices allow for quick handling of flow queries sorted by various methods.
	indicies map[proto.SortBy]Index[string]

	// diachronics stores a quick lookup of flow identifer to the types.DiachronicFlow object which
	// contains the bucketed statistics for that flow. This is the primary data structure
	// for storing per-Flow statistics over time.
	diachronics map[types.FlowKey]*types.DiachronicFlow

	// buckets is the ring of discrete time interval buckets for sorting Flows. The ring serves
	// these main purposes:
	// - It defines the global aggregation windows consistently for all DiachronicFlows.
	// - It allows us to quickly serve time-sorted queries.
	// - It allows us to quickly generate FlowCollections for emission.
	buckets *BucketRing

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
	destIndex := NewIndex(func(k *types.FlowKey) string { return k.DestName })
	a := &LogAggregator{
		aggregationWindow:  15 * time.Second,
		done:               make(chan struct{}),
		flowRequests:       make(chan flowRequest),
		recvChan:           make(chan *proto.FlowUpdate, channelDepth),
		rolloverFunc:       time.After,
		bucketsToAggregate: 20,
		pushIndex:          30,
		nowFunc:            time.Now,
		diachronics:        map[types.FlowKey]*types.DiachronicFlow{},
		indicies: map[proto.SortBy]Index[string]{
			proto.SortBy_DestName: destIndex,
		},
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
	a.buckets = NewBucketRing(
		numBuckets,
		int(a.aggregationWindow.Seconds()),
		a.pushIndex,
		a.bucketsToAggregate,
		startTime,
	)

	// Schedule the first rollover one aggregation period from now.
	rolloverCh := a.rolloverFunc(a.aggregationWindow)

	for {
		select {
		case upd := <-a.recvChan:
			a.handleFlowUpdate(upd)
		case <-rolloverCh:
			rolloverCh = a.rolloverFunc(a.rollover())
			a.maybeEmitFlows()
		case req := <-a.flowRequests:
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

func (a *LogAggregator) maybeEmitFlows() {
	if a.sink == nil {
		logrus.Debug("No sink configured, skip flow emission")
		return
	}

	flows := a.buckets.FlowCollection(a.diachronics)
	if flows == nil {
		// We've already pushed this bucket, so we can skip it. We'll emit the next flow once
		// bucketsToAggregate buckets have been rolled over.
		logrus.Debug("Delaying flow emission, no new flows to emit")
		return
	}

	if len(flows.Flows) > 0 {
		a.sink.Receive(flows)
	}
}

// GetFlows returns a list of flows that match the given request. It uses a channel to
// synchronously request the flows from the aggregator.
func (a *LogAggregator) GetFlows(req *proto.FlowRequest) ([]*proto.Flow, error) {
	respCh := make(chan *flowResponse)
	defer close(respCh)
	a.flowRequests <- flowRequest{respCh, req}
	resp := <-respCh
	return resp.flows, resp.err
}

func (a *LogAggregator) queryFlows(req *proto.FlowRequest) *flowResponse {
	logrus.WithFields(logrus.Fields{"req": req}).Debug("Received flow request")

	// If a sort order was requested, use the corersponding index to find the matching flows.
	if req.SortBy != proto.SortBy_Time {
		if idx, ok := a.indicies[req.SortBy]; ok {
			// If a sort order was requested, use the corresponding index to find the matching flows.
			// We need to convert the FlowKey to a string for the index lookup.
			flows := idx.List(IndexFindOpts[string]{
				startTimeGt: req.StartTimeGt,
				startTimeLt: req.StartTimeLt,
				limit:       req.PageSize,
				cursor:      req.Cursor,
			})

			// Convert the flows to proto format.
			var flowsToReturn []*proto.Flow
			for _, flow := range flows {
				flowsToReturn = append(flowsToReturn, types.FlowToProto(flow))
			}
			return &flowResponse{flowsToReturn, nil}
		} else if !ok {
			return &flowResponse{nil, fmt.Errorf("unsupported sort order")}
		}
	}

	// Default to time-sorted flow data.
	// Collect all of the flow keys across all buckets that match the request. We will then
	// use DiachronicFlow data to combine statistics together for each key across the time range.
	keys := a.buckets.FlowSet(req.StartTimeGt, req.StartTimeLt)

	// Aggregate the relevant DiachronicFlows across the time range.
	flowsByKey := map[types.FlowKey]*types.Flow{}
	keys.Iter(func(key types.FlowKey) error {
		c, ok := a.diachronics[key]
		if !ok {
			// This should never happen, as we should have a DiachronicFlow for every key.
			// If we don't, it's a bug. Return an error, which will trigger a panic.
			return fmt.Errorf("no DiachronicFlow for key %v", key)
		}
		flow := c.Aggregate(req.StartTimeGt, req.StartTimeLt)
		if flow != nil {
			flowsByKey[*flow.Key] = flow
		}
		return nil
	})

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
			return &flowResponse{nil, nil}
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
	return &flowResponse{flows, nil}
}

func (a *LogAggregator) Stop() {
	close(a.done)
}

func (a *LogAggregator) rollover() time.Duration {
	// Tell the bucket ring to rollover and capture the start time of the newest bucket.
	// We'll use this below to determine when the next rollover should occur. The next bucket
	// should always be one interval ahead of Now().
	newBucketStart, keys := a.buckets.Rollover()

	// Update DiachronicFlows. We need to remove any windows from the DiachronicFlows that have expired.
	// Find the oldest bucket's start time and remove any data from the DiachronicFlows that is older than that.
	keys.Iter(func(k types.FlowKey) error {
		d := a.diachronics[k]

		// Rollover the DiachronicFlow. This will remove any expired data from it.
		d.Rollover(a.buckets.BeginningOfHistory())

		if d.Empty() {
			// If the DiachronicFlow is empty, we can remove it. This means it hasn't received any
			// flow updates in a long time.
			logrus.WithField("key", d.Key).Debug("Removing empty DiachronicFlow")
			for _, idx := range a.indicies {
				idx.Remove(d)
			}
			delete(a.diachronics, d.Key)
		}
		return nil
	})

	// Determine when we should next rollover. We don't just blindly use the rolloverTime, as this leave us
	// susceptible to slowly drifting over time. Instead, we determine when the next bucket should start and
	// calculate the difference between then and now.
	//
	// The next bucket should start at the end time of the current bucket, and be one interval ahead of Now().
	nextBucketStart := time.Unix(newBucketStart, 0)
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

	// Find the window for this Flow based on the global bucket ring. We use the ring to ensure
	// that time windows are consistent across all DiachronicFlows.
	flow := types.ProtoToFlow(upd.Flow)
	start, end, err := a.buckets.Window(flow)
	if err != nil {
		logrus.WithField("flow", flow).WithError(err).Warn("Unable to sort flow into a bucket")
		return
	}

	// Check if we are tracking a DiachronicFlow for this FlowKey, and create one if not.
	// Then, add this Flow to the DiachronicFlow.
	k := types.ProtoToFlowKey(upd.Flow.Key)
	if _, ok := a.diachronics[*k]; !ok {
		logrus.WithField("flow", upd.Flow).Debug("Creating new DiachronicFlow for flow")
		d := types.NewDiachronicFlow(k)
		a.diachronics[*k] = d

		// Add the DiachronicFlow to all indices.
		for _, idx := range a.indicies {
			idx.Add(d)
		}
	}
	a.diachronics[*k].AddFlow(types.ProtoToFlow(upd.Flow), start, end)

	// Add the Flow to our bucket ring.
	a.buckets.AddFlow(flow)
}
