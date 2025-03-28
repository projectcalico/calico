// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
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

	"github.com/projectcalico/calico/goldmane/pkg/aggregator/bucketing"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// numBuckets is the number of buckets to keep in memory.
	// We keep 240 buckets. Assuming a default window of 15s each, this
	// gives us a total of 1hr of history.
	numBuckets = 240

	// channelDepth is the depth of the channel to use for flow updates.
	channelDepth = 5000

	// healthName is the name of this component in the health aggregator.
	healthName = "aggregator"
)

// listRequest is an internal helper used to synchronously request matching flows from the aggregator.
type listRequest struct {
	respCh chan *listResponse
	req    *proto.FlowListRequest
}

type filterHintsRequest struct {
	respCh chan *filterHintsResponse
	req    *proto.FilterHintsRequest
}

type listResponse struct {
	results *proto.FlowListResult
	err     error
}

type filterHintsResponse struct {
	results *proto.FilterHintsResult
	err     error
}

type streamRequest struct {
	respCh chan *Stream
	req    *proto.FlowStreamRequest
}

type sinkRequest struct {
	sink bucketing.Sink
	done chan struct{}
}

type LogAggregator struct {
	// indices allow for quick handling of flow queries sorted by various methods.
	indices map[proto.SortBy]Index[string]

	// defaultIndex is the default index to use when no sort order is specified.
	defaultIndex *RingIndex

	// streams is responsible for managing active streams being served by the aggregator.
	streams *streamManager

	// diachronics stores a quick lookup of flow identifer to the types.DiachronicFlow object which
	// contains the bucketed statistics for that flow. This is the primary data structure
	// for storing per-Flow statistics over time.
	diachronics map[types.FlowKey]*types.DiachronicFlow

	// buckets is the ring of discrete time interval buckets for sorting Flows. The ring serves
	// these main purposes:
	// - It defines the global aggregation windows consistently for all DiachronicFlows.
	// - It allows us to quickly serve time-sorted queries.
	// - It allows us to quickly generate FlowCollections for emission.
	buckets *bucketing.BucketRing

	// aggregationWindow is the size of each aggregation bucket.
	aggregationWindow time.Duration

	// Used to trigger goroutine shutdown.
	done chan struct{}

	// Used to make requests for flows synchronously.
	listRequests chan listRequest

	filterHintsRequests chan filterHintsRequest

	// streamRequests is the channel to receive stream requests on.
	streamRequests chan streamRequest

	// sink is a sink to send aggregated flows to.
	sink bucketing.Sink

	// sinkChan allows setting the sink asynchronously.
	sinkChan chan *sinkRequest

	// recvChan is the channel to receive flow updates on.
	recvChan chan *types.Flow

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

	// health is the health aggregator to use for health checks.
	health *health.HealthAggregator
}

func NewLogAggregator(opts ...Option) *LogAggregator {
	// Establish default aggregator configuration. Options can be used to override these.
	a := &LogAggregator{
		aggregationWindow:   15 * time.Second,
		done:                make(chan struct{}),
		listRequests:        make(chan listRequest),
		filterHintsRequests: make(chan filterHintsRequest),
		streamRequests:      make(chan streamRequest),
		sinkChan:            make(chan *sinkRequest, 10),
		recvChan:            make(chan *types.Flow, channelDepth),
		rolloverFunc:        time.After,
		bucketsToAggregate:  20,
		pushIndex:           30,
		nowFunc:             time.Now,
		diachronics:         map[types.FlowKey]*types.DiachronicFlow{},
		indices: map[proto.SortBy]Index[string]{
			proto.SortBy_DestName:        NewIndex(func(k *types.FlowKey) string { return k.DestName() }),
			proto.SortBy_DestNamespace:   NewIndex(func(k *types.FlowKey) string { return k.DestNamespace() }),
			proto.SortBy_SourceName:      NewIndex(func(k *types.FlowKey) string { return k.SourceName() }),
			proto.SortBy_SourceNamespace: NewIndex(func(k *types.FlowKey) string { return k.SourceNamespace() }),
		},
		streams: NewStreamManager(),
	}

	// Use a time-based Ring index by default.
	a.defaultIndex = NewRingIndex(a)

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

func (a *LogAggregator) flowSet(startGt, startLt int64) set.Set[*types.DiachronicFlow] {
	return a.buckets.FlowSet(startGt, startLt)
}

func (a *LogAggregator) diachronicFlow(key types.FlowKey) *types.DiachronicFlow {
	return a.diachronics[key]
}

func (a *LogAggregator) Run(startTime int64) {
	// Initialize the buckets.
	opts := []bucketing.BucketRingOption{
		bucketing.WithBucketsToAggregate(a.bucketsToAggregate),
		bucketing.WithPushAfter(a.pushIndex),
		bucketing.WithLookup(a.diachronicFlow),
		bucketing.WithStreamReceiver(a.streams),
	}
	a.buckets = bucketing.NewBucketRing(
		numBuckets,
		int(a.aggregationWindow.Seconds()),
		startTime,
		opts...,
	)

	if a.health != nil {
		// Register with the health aggregator.
		// We will send reports on each rollover, so we set the timeout to 4x the rollover window to ensure that
		// we don't get marked as unhealthy if we're slow to respond.
		a.health.RegisterReporter(healthName, &health.HealthReport{Live: true, Ready: true}, 4*a.aggregationWindow)

		// Mark as live and ready to start. We'll go unready if we fail to check in during the main loop.
		a.health.Report(healthName, &health.HealthReport{Live: true, Ready: true})
	}

	// Schedule the first rollover one aggregation period from now.
	rolloverCh := a.rolloverFunc(a.aggregationWindow)

	for {
		select {
		case f := <-a.recvChan:
			a.handleFlowUpdate(f)
		case <-rolloverCh:
			rolloverCh = a.rolloverFunc(a.rollover())

			a.buckets.EmitFlowCollections(a.sink)
			if a.health != nil {
				a.health.Report(healthName, &health.HealthReport{Live: true, Ready: true})
			}
		case req := <-a.listRequests:
			req.respCh <- a.queryFlows(req.req)
		case req := <-a.filterHintsRequests:
			req.respCh <- a.queryFilterHints(req.req)
		case req := <-a.streamRequests:
			stream := a.streams.register(req)
			req.respCh <- stream
			a.backfill(stream, req.req)
		case id := <-a.streams.closedStreams():
			a.streams.close(id)
		case req := <-a.sinkChan:
			logrus.WithField("sink", req.sink).Info("Setting aggregator sink")
			a.sink = req.sink
			a.buckets.EmitFlowCollections(a.sink)
			close(req.done)
		case <-a.done:
			logrus.Warn("Aggregator shutting down")
			return
		}
	}
}

// SetSink sets the sink for the aggregator and returns a channel that can be used to wait for the sink to be set,
// if desired by the caller.
func (a *LogAggregator) SetSink(s bucketing.Sink) chan struct{} {
	done := make(chan struct{})
	a.sinkChan <- &sinkRequest{sink: s, done: done}
	return done
}

// Receive is used to send a flow update to the aggregator.
func (a *LogAggregator) Receive(f *types.Flow) {
	timeout := time.After(5 * time.Second)

	select {
	case a.recvChan <- f:
	case <-timeout:
		logrus.Warn("Output channel full, dropping flow")
	}
}

// Stream returns a new Stream from the aggregator. It uses a channel to synchronously request the stream
// from the aggregator.
func (a *LogAggregator) Stream(req *proto.FlowStreamRequest) (*Stream, error) {
	logrus.WithField("req", req).Debug("Received stream request")

	if req.StartTimeGte != 0 {
		// Sanitize the time range, resolving any relative time values.
		// Note that for stream requests, 0 means "now" instead of "beginning of history". As such,
		// we only resolve relative times for StartTimeGt.
		req.StartTimeGte, _ = a.normalizeTimeRange(req.StartTimeGte, 0)
	}

	respCh := make(chan *Stream)
	defer close(respCh)
	a.streamRequests <- streamRequest{respCh, req}
	s := <-respCh
	if s == nil {
		return nil, fmt.Errorf("failed to establish new stream")
	}
	return s, nil
}

// List returns a list of flows that match the given request. It uses a channel to
// synchronously request the flows from the aggregator.
func (a *LogAggregator) List(req *proto.FlowListRequest) (*proto.FlowListResult, error) {
	respCh := make(chan *listResponse)
	defer close(respCh)
	a.listRequests <- listRequest{respCh, req}
	resp := <-respCh
	return resp.results, resp.err
}

func (a *LogAggregator) Hints(req *proto.FilterHintsRequest) (*proto.FilterHintsResult, error) {
	logrus.WithField("req", req).Debug("Received hints request")

	respCh := make(chan *filterHintsResponse)
	defer close(respCh)
	a.filterHintsRequests <- filterHintsRequest{respCh, req}
	resp := <-respCh

	return resp.results, resp.err
}

func (a *LogAggregator) validateListRequest(req *proto.FlowListRequest) error {
	if err := a.validateTimeRange(req.StartTimeGte, req.StartTimeLt); err != nil {
		return err
	}
	if len(req.SortBy) > 1 {
		return fmt.Errorf("at most one sort order is supported")
	}
	return nil
}

func (a *LogAggregator) validateTimeRange(startTimeGt, startTimeLt int64) error {
	if startTimeGt >= startTimeLt {
		return fmt.Errorf("startTimeGt (%d) must be less than startTimeLt (%d)", startTimeGt, startTimeLt)
	}
	return nil
}

func (a *LogAggregator) Statistics(req *proto.StatisticsRequest) ([]*proto.StatisticsResult, error) {
	// Sanitize the time range, resolving any relative time values.
	req.StartTimeGte, req.StartTimeLt = a.normalizeTimeRange(req.StartTimeGte, req.StartTimeLt)

	if err := a.validateTimeRange(req.StartTimeGte, req.StartTimeLt); err != nil {
		logrus.WithField("req", req).WithError(err).Debug("Invalid time range")
		return nil, err
	}
	return a.buckets.Statistics(req)
}

// backfill fills a new Stream instance with historical Flow data based on the request.
func (a *LogAggregator) backfill(stream *Stream, request *proto.FlowStreamRequest) {
	if request.StartTimeGte == 0 {
		// If no start time is provided, we don't need to backfill any data
		// to this stream.
		logrus.WithField("id", stream.id).Debug("No start time provided, skipping backfill")
		return
	}

	// Go through the bucket ring, generating stream events for each flow that matches the request.
	// Right now, the stream endpoint only supports aggregation windows of a single bucket interval.
	err := a.buckets.IterBucketsTime(request.StartTimeGte, a.nowFunc().Unix(), func(bucket *bucketing.AggregationBucket) {
		// Iterate all of the keys in this bucket.
		bucket.Flows.Iter(func(d *types.DiachronicFlow) error {
			builder := bucketing.NewCachedFlowBuilder(d, bucket.StartTime, bucket.EndTime)
			if f, id := builder.Build(request.Filter); f != nil {
				// The flow matches the filter and time range.
				if logrus.IsLevelEnabled(logrus.DebugLevel) {
					logrus.WithFields(f.Key.Fields()).Debug("Sending backfilled flow to stream")
				}
				stream.Receive(&proto.FlowResult{
					Id:   id,
					Flow: types.FlowToProto(f),
				})
			}
			return nil
		})
	})
	if err != nil {
		logrus.WithError(err).Error("Error backfilling stream")
	}
}

// normalizeTimeRange normalizes the time range for a query, converting absent and relative time indicators
// into absolute time values based on the current time. The API suports passing negative numbers to indicate
// a time relative to the current time, and 0 to indicate the beginning or end of the server history. This function
// santisizes the input values into absolute time values for use within the aggregator.
func (a *LogAggregator) normalizeTimeRange(gt, lt int64) (int64, int64) {
	now := a.nowFunc().Unix()
	if gt < 0 {
		gt = now + gt
		logrus.WithField("gte", gt).Debug("Negative start time translated to absolute time")
	} else if gt == 0 {
		gt = a.buckets.BeginningOfHistory()
		logrus.WithField("gte", gt).Debug("No start time provided, defaulting to beginning of server history")
	}

	if lt < 0 {
		lt = now + lt
		logrus.WithField("lt", lt).Debug("Negative end time translated to absolute time")
	} else if lt == 0 {
		lt = now
		logrus.WithField("lt", lt).Debug("No end time provided, defaulting to current time")
	}
	return gt, lt
}

func (a *LogAggregator) queryFlows(req *proto.FlowListRequest) *listResponse {
	logrus.WithFields(logrus.Fields{"req": req}).Debug("Received flow request")

	// Sanitize the time range, resolving any relative time values.
	req.StartTimeGte, req.StartTimeLt = a.normalizeTimeRange(req.StartTimeGte, req.StartTimeLt)

	// Validate the request.
	if err := a.validateListRequest(req); err != nil {
		return &listResponse{nil, err}
	}

	var meta types.ListMeta
	var flowsToReturn []*proto.FlowResult

	// If a sort order was requested, use the corresponding index to find the matching flows.
	if len(req.SortBy) > 0 && req.SortBy[0].SortBy != proto.SortBy_Time {
		if idx, ok := a.indices[req.SortBy[0].SortBy]; ok {
			// If a sort order was requested, use the corresponding index to find the matching flows.
			// We need to convert the FlowKey to a string for the index lookup.
			var flows []*types.Flow
			flows, meta = idx.List(IndexFindOpts{
				startTimeGt: req.StartTimeGte,
				startTimeLt: req.StartTimeLt,
				pageSize:    req.PageSize,
				page:        req.Page,
				filter:      req.Filter,
			})

			// Convert the flows to proto format.
			flowsToReturn = a.flowsToResult(flows)
		} else {
			return &listResponse{nil, fmt.Errorf("unsupported sort order")}
		}
	} else {
		// Default to time-sorted flow data.
		var flows []*types.Flow
		flows, meta = a.defaultIndex.List(IndexFindOpts{
			startTimeGt: req.StartTimeGte,
			startTimeLt: req.StartTimeLt,
			pageSize:    req.PageSize,
			page:        req.Page,
			filter:      req.Filter,
		})

		// Convert the flows to proto format.
		flowsToReturn = a.flowsToResult(flows)
	}

	return &listResponse{&proto.FlowListResult{
		Meta: &proto.ListMetadata{
			TotalPages:   int64(meta.TotalPages),
			TotalResults: int64(meta.TotalResults),
		},
		Flows: flowsToReturn,
	}, nil}
}

func (a *LogAggregator) queryFilterHints(req *proto.FilterHintsRequest) *filterHintsResponse {
	logrus.WithFields(logrus.Fields{"req": req}).Debug("Received filter hints request.")

	// Sanitize the time range, resolving any relative time values.
	req.StartTimeGte, req.StartTimeLt = a.normalizeTimeRange(req.StartTimeGte, req.StartTimeLt)

	// Validate the request.
	if err := a.validateTimeRange(req.StartTimeGte, req.StartTimeLt); err != nil {
		return &filterHintsResponse{nil, err}
	}

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
		return &filterHintsResponse{nil, fmt.Errorf("unsupported filter type '%s'", req.Type.String())}
	}

	var values []string
	var meta types.ListMeta
	// If a sort order was requested, use the corresponding index to find the matching flows.
	if idx, ok := a.indices[sortBy]; ok {
		values, meta = idx.SortValueSet(IndexFindOpts{
			startTimeGt: req.StartTimeGte,
			startTimeLt: req.StartTimeLt,
			pageSize:    req.PageSize,
			page:        req.Page,
			filter:      req.Filter,
		})
	} else if valueFunc != nil {
		values, meta = a.defaultIndex.FilterValueSet(valueFunc, IndexFindOpts{
			startTimeGt: req.StartTimeGte,
			startTimeLt: req.StartTimeLt,
			pageSize:    req.PageSize,
			page:        req.Page,
			filter:      req.Filter,
		})
	} else {
		return &filterHintsResponse{nil, fmt.Errorf("unsupported sort order")}
	}

	var hints []*proto.FilterHint
	for _, value := range values {
		hints = append(hints, &proto.FilterHint{Value: value})
	}

	return &filterHintsResponse{&proto.FilterHintsResult{
		Meta: &proto.ListMetadata{
			TotalPages:   int64(meta.TotalPages),
			TotalResults: int64(meta.TotalResults),
		},
		Hints: hints,
	}, nil}
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

// flowsToResult converts a list of internal Flow objects to a list of proto.FlowResult objects.
func (a *LogAggregator) flowsToResult(flows []*types.Flow) []*proto.FlowResult {
	var flowsToReturn []*proto.FlowResult
	for _, flow := range flows {
		flowsToReturn = append(flowsToReturn, &proto.FlowResult{
			Flow: types.FlowToProto(flow),
			Id:   a.diachronics[*flow.Key].ID,
		})
	}
	return flowsToReturn
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
	keys.Iter(func(d *types.DiachronicFlow) error {
		// Rollover the DiachronicFlow. This will remove any expired data from it.
		d.Rollover(a.buckets.BeginningOfHistory())

		if d.Empty() {
			// If the DiachronicFlow is empty, we can remove it. This means it hasn't received any
			// flow updates in a long time.
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				logrus.WithFields(d.Key.Fields()).Debug("Removing empty DiachronicFlow")
			}
			for _, idx := range a.indices {
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

func (a *LogAggregator) handleFlowUpdate(flow *types.Flow) {
	logrus.WithField("flow", flow).Debug("Received Flow")

	// Find the window for this Flow based on the global bucket ring. We use the ring to ensure
	// that time windows are consistent across all DiachronicFlows.
	start, end, err := a.buckets.Window(flow)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"start": flow.StartTime,
			"now":   a.nowFunc().Unix(),
		}).WithFields(flow.Key.Fields()).
			WithError(err).
			Warn("Unable to sort flow into a bucket")
		return
	}

	// Check if we are tracking a DiachronicFlow for this FlowKey, and create one if not.
	// Then, add this Flow to the DiachronicFlow.
	if _, ok := a.diachronics[*flow.Key]; !ok {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			// Unpacking the key is a bit expensive, so only do it in debug mode.
			logrus.WithFields(flow.Key.Fields()).Debug("Creating new DiachronicFlow for flow")
		}
		d := types.NewDiachronicFlow(flow.Key)
		a.diachronics[*flow.Key] = d

		// Add the DiachronicFlow to all indices.
		for _, idx := range a.indices {
			idx.Add(d)
		}
	}
	a.diachronics[*flow.Key].AddFlow(flow, start, end)

	// Add the Flow to our bucket ring.
	a.buckets.AddFlow(flow)
}
