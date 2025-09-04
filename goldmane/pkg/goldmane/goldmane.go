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

package goldmane

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/lib/std/time"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
)

const (
	// numBuckets is the number of buckets to keep in memory.
	// - 1 bucket that covers [now(), now()+15s], currently filling.
	// - 1 bucket that is 15s into the future, to account for time skew.
	// - 240 buckets of historical data. This gives us 1hr of history with default settings.
	numBuckets = 242

	// channelDepth is the depth of the channel to use for flow updates.
	channelDepth = 5000

	// batchSize is the max number of flows to process per batch.
	batchSize = 1000

	// healthName is the name of this component in the health aggregator.
	healthName = "aggregator"
)

var (
	receivedFlowCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "goldmane_aggr_received_flows_total",
		Help: "Total number of flows received by Goldmane aggregator.",
	})

	flowIndexLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "goldmane_aggr_flow_index_latency_ms",
		Help: "Summary measuring the time taken to index a flow.",
	})

	flowIndexBatchSize = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "goldmane_aggr_flow_index_batch_size",
		Help: "Measure the number of flows processed in a batch.",
	})

	flowChannelSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "goldmane_aggr_flow_index_buffer_size",
		Help: "Current size of the flow index buffer.",
	})

	rolloverLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "goldmane_aggr_rollover_latency_ms",
		Help: "Summary of the time until the next rollover.",
	})

	rolloverDuration = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "goldmane_aggr_rollover_duration_ms",
		Help: "Duration of the rollover process.",
	})

	backfillLatency = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "goldmane_aggr_backfill_latency_ms",
		Help: "Summary measuring the time taken to backfill a stream.",
	})

	numUniqueFlows = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "goldmane_aggr_num_unique_flows",
		Help: "Number of unique flows in the aggregator.",
	})

	numDroppedFlows = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "goldmane_aggr_dropped_flows_total",
		Help: "Total number of flows dropped by the aggregator.",
	})
)

func init() {
	prometheus.MustRegister(receivedFlowCounter)
	prometheus.MustRegister(flowIndexLatency)
	prometheus.MustRegister(flowIndexBatchSize)
	prometheus.MustRegister(flowChannelSize)
	prometheus.MustRegister(rolloverLatency)
	prometheus.MustRegister(rolloverDuration)
	prometheus.MustRegister(backfillLatency)
	prometheus.MustRegister(numUniqueFlows)
	prometheus.MustRegister(numDroppedFlows)
}

// listRequest is an internal helper used to synchronously request matching flows from the aggregator.
type listRequest struct {
	respCh chan *listResponse
	req    *proto.FlowListRequest
}

type listResponse struct {
	results *proto.FlowListResult
	err     error
}

// filterHintsRequest is an internal helper used to synchronously request filter hints from the aggregator.
type filterHintsRequest struct {
	respCh chan *filterHintsResponse
	req    *proto.FilterHintsRequest
}

type filterHintsResponse struct {
	results *proto.FilterHintsResult
	err     error
}

// sinkRequest is an internal helper used to set the sink for the aggregator, which can by modified at runtime.
type sinkRequest struct {
	sink storage.Sink
	done chan struct{}
}

// The Goldmane structure is the main entry point for Goldmane. It is the central unit responsible for
// connecting various internal components together with flow storage. It runs a single main loop that
// serializes inbound requests and manages the flow of data through the system, fanning out to the
// appropriate components as needed.
type Goldmane struct {
	// streams is responsible for managing active streams being served by the aggregator.
	streams stream.StreamManager

	// flowStore is the main data structure used to store flows.
	flowStore *storage.BucketRing

	// bucketDuration is the time duration of each aggregation bucket.
	bucketDuration time.Duration

	// Used to trigger goroutine shutdown.
	done chan struct{}

	// sink is a sink to send aggregated flows to.
	sink storage.Sink

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

	// ratelimiter is used to rate limit log messages that may happen frequently.
	rl *logutils.RateLimitedLogger

	// The following channels are input channels to make resuests of the main loop.
	listRequests        chan listRequest
	filterHintsRequests chan filterHintsRequest
	sinkChan            chan *sinkRequest
	recvChan            chan *types.Flow
}

func NewGoldmane(opts ...Option) *Goldmane {
	// Establish default aggregator configuration. Options can be used to override these.
	a := &Goldmane{
		bucketDuration:      15 * time.Second,
		done:                make(chan struct{}),
		listRequests:        make(chan listRequest),
		filterHintsRequests: make(chan filterHintsRequest),
		sinkChan:            make(chan *sinkRequest, 10),
		recvChan:            make(chan *types.Flow, channelDepth),
		rolloverFunc:        time.After,
		bucketsToAggregate:  20,
		pushIndex:           30,
		nowFunc:             time.Now,
		streams:             stream.NewStreamManager(),
		rl: logutils.NewRateLimitedLogger(
			logutils.OptBurst(1),
			logutils.OptInterval(15*time.Second),
		),
	}

	// Apply options.
	for _, opt := range opts {
		opt(a)
	}

	// Log out some key information.
	if a.sink != nil {
		logrus.WithFields(logrus.Fields{
			// This is the soonest we will possible emit a flow as part of an aggregation.
			"emissionWindowLeftBound": time.Duration(a.pushIndex-a.bucketsToAggregate) * a.bucketDuration,

			// This is the latest we will emit a flow as part of an aggregation.
			"emissionWindowRightBound": time.Duration(a.pushIndex) * a.bucketDuration,

			// This is the total time window that we will aggregate over when generating emitted flows.
			"emissionWindow": time.Duration(a.bucketsToAggregate) * a.bucketDuration,
		}).Info("Emission of aggregated flows configured")
	}

	logrus.WithFields(logrus.Fields{
		// This is the size of each aggregation bucket.
		"bucketSize": a.bucketDuration,

		// This is the total amount of history that we will keep in memory.
		"totalHistory": time.Duration(numBuckets) * a.bucketDuration,
	}).Info("Keeping bucketed flow history in memory")

	return a
}

// Run starts Goldmane - it returns a channel that can be used by the caller to wait
// for Goldmane to be ready to process requests. The channel will be closed when Goldmane is ready.
func (a *Goldmane) Run(startTime int64) <-chan struct{} {
	ready := make(chan struct{})
	go a.run(startTime, ready)
	return ready
}

func (a *Goldmane) run(startTime int64, ready chan<- struct{}) {
	// Initialize the buckets.
	opts := []storage.BucketRingOption{
		storage.WithBucketsToAggregate(a.bucketsToAggregate),
		storage.WithPushAfter(a.pushIndex),
		storage.WithStreamReceiver(a.streams),
		storage.WithNowFunc(a.nowFunc),
	}
	a.flowStore = storage.NewBucketRing(
		numBuckets,
		int(a.bucketDuration.Seconds()),
		startTime,
		opts...,
	)

	if a.health != nil {
		// Register with the health aggregator.
		// We will send reports on each rollover, so we set the timeout to 4x the rollover window to ensure that
		// we don't get marked as unhealthy if we're slow to respond.
		a.health.RegisterReporter(healthName, &health.HealthReport{Live: true, Ready: true}, 4*a.bucketDuration)

		// Mark as live and ready to start. We'll go unready if we fail to check in during the main loop.
		a.health.Report(healthName, &health.HealthReport{Live: true, Ready: true})
	}

	// Start the stream manager on its own goroutine so we can process stream creation and closure
	// requests asynchronously from the main loop.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.streams.Run(ctx)

	// Schedule the first rollover one aggregation period from now.
	rolloverCh := a.rolloverFunc(a.bucketDuration)

	// Indicate that we're ready to process requests.
	close(ready)

	for {
		select {
		case f := <-a.recvChan:
			a.handleFlowBatch(f)
		case <-rolloverCh:
			rolloverCh = a.rolloverFunc(a.rollover())
		case req := <-a.listRequests:
			req.respCh <- a.queryFlows(req.req)
		case req := <-a.filterHintsRequests:
			req.respCh <- a.queryFilterHints(req.req)
		case stream := <-a.streams.Backfills():
			a.backfill(stream)
		case req := <-a.sinkChan:
			logrus.WithField("sink", req.sink).Info("Setting aggregator sink")
			a.sink = req.sink
			a.flowStore.EmitFlowCollections(a.sink)
			close(req.done)
		case <-a.done:
			logrus.Warn("Aggregator shutting down")
			return
		}
	}
}

// SetSink sets the sink for the aggregator and returns a channel that can be used to wait for the sink to be set,
// if desired by the caller.
func (a *Goldmane) SetSink(s storage.Sink) chan struct{} {
	done := make(chan struct{})
	a.sinkChan <- &sinkRequest{sink: s, done: done}
	return done
}

// Receive is used to send a flow update to the aggregator.
func (a *Goldmane) Receive(f *types.Flow) {
	if err := chanutil.WriteWithDeadline(context.Background(), a.recvChan, f, 5*time.Second); err != nil {
		numDroppedFlows.Inc()
		a.rl.Warn("Aggregator receive channel full, dropping flow(s)")
	}
}

// Stream returns a new Stream from the stream manager.
func (a *Goldmane) Stream(req *proto.FlowStreamRequest) (stream.Stream, error) {
	logrus.WithField("req", req).Debug("Received stream request")

	if req.StartTimeGte != 0 {
		// Sanitize the time range, resolving any relative time values.
		// Note that for stream requests, 0 means "now" instead of "beginning of history". As such,
		// we only resolve relative times for StartTimeGt.
		req.StartTimeGte, _ = a.normalizeTimeRange(req.StartTimeGte, 0)
	}

	// Register the stream with the stream manager. This will return a new Stream object.
	respCh := a.streams.Register(req, 2*numBuckets)
	defer close(respCh)

	// Wait for a response.
	s := <-respCh
	if s == nil {
		return nil, fmt.Errorf("failed to establish new stream")
	}
	return s, nil
}

// List returns a list of flows that match the given request. It uses a channel to
// synchronously request the flows from the aggregator.
func (a *Goldmane) List(req *proto.FlowListRequest) (*proto.FlowListResult, error) {
	respCh := make(chan *listResponse)
	defer close(respCh)
	a.listRequests <- listRequest{respCh, req}
	resp := <-respCh
	return resp.results, resp.err
}

func (a *Goldmane) Hints(req *proto.FilterHintsRequest) (*proto.FilterHintsResult, error) {
	logrus.WithField("req", req).Debug("Received hints request")

	respCh := make(chan *filterHintsResponse)
	defer close(respCh)
	a.filterHintsRequests <- filterHintsRequest{respCh, req}
	resp := <-respCh

	return resp.results, resp.err
}

func (a *Goldmane) validateListRequest(req *proto.FlowListRequest) error {
	if err := a.validateTimeRange(req.StartTimeGte, req.StartTimeLt); err != nil {
		return err
	}
	if len(req.SortBy) > 1 {
		return fmt.Errorf("at most one sort order is supported")
	}
	return nil
}

func (a *Goldmane) validateTimeRange(startTimeGt, startTimeLt int64) error {
	if startTimeGt >= startTimeLt {
		return fmt.Errorf("startTimeGt (%d) must be less than startTimeLt (%d)", startTimeGt, startTimeLt)
	}
	return nil
}

func (a *Goldmane) Statistics(req *proto.StatisticsRequest) ([]*proto.StatisticsResult, error) {
	// Sanitize the time range, resolving any relative time values.
	req.StartTimeGte, req.StartTimeLt = a.normalizeTimeRange(req.StartTimeGte, req.StartTimeLt)

	if err := a.validateTimeRange(req.StartTimeGte, req.StartTimeLt); err != nil {
		logrus.WithField("req", req).WithError(err).Debug("Invalid time range")
		return nil, err
	}
	return a.flowStore.Statistics(req)
}

// backfill fills a new Stream instance with historical Flow data based on the request.
func (a *Goldmane) backfill(stream stream.Stream) {
	if stream.StartTimeGte() == 0 {
		// If no start time is provided, we don't need to backfill any data
		// to this stream.
		logrus.WithField("id", stream.ID()).Debug("No start time provided, skipping backfill")
		return
	}

	// Measure the time it takes to backfill the stream.
	start := time.Now()
	defer func() {
		logrus.WithField("id", stream.ID()).WithField("duration", time.Since(start)).Debug("Backfill complete")
		backfillLatency.Observe(float64(time.Since(start).Milliseconds()))
	}()
	a.flowStore.Backfill(a.streams, stream.ID(), stream.StartTimeGte())
}

// normalizeTimeRange normalizes the time range for a query, converting absent and relative time indicators
// into absolute time values based on the current time. The API suports passing negative numbers to indicate
// a time relative to the current time, and 0 to indicate the beginning or end of the server history. This function
// santisizes the input values into absolute time values for use within the aggregator.
func (a *Goldmane) normalizeTimeRange(gt, lt int64) (int64, int64) {
	now := a.nowFunc().Unix()
	if gt < 0 {
		gt = now + gt
		logrus.WithField("gte", gt).Debug("Negative start time translated to absolute time")
	} else if gt == 0 {
		gt = a.flowStore.BeginningOfHistory()
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

func (a *Goldmane) queryFlows(req *proto.FlowListRequest) *listResponse {
	logrus.WithFields(logrus.Fields{"req": req}).Debug("Received flow request")

	// Sanitize the time range, resolving any relative time values.
	req.StartTimeGte, req.StartTimeLt = a.normalizeTimeRange(req.StartTimeGte, req.StartTimeLt)

	// Validate the request.
	if err := a.validateListRequest(req); err != nil {
		return &listResponse{nil, err}
	}

	flowsToReturn, meta, err := a.flowStore.List(req)
	if err != nil {
		logrus.WithError(err).Warn("Error listing flows")
		return &listResponse{nil, err}
	}

	return &listResponse{&proto.FlowListResult{
		Meta: &proto.ListMetadata{
			TotalPages:   int64(meta.TotalPages),
			TotalResults: int64(meta.TotalResults),
		},
		Flows: a.flowsToResult(flowsToReturn),
	}, nil}
}

func (a *Goldmane) queryFilterHints(req *proto.FilterHintsRequest) *filterHintsResponse {
	logrus.WithFields(logrus.Fields{"req": req}).Debug("Received filter hints request.")

	// Sanitize the time range, resolving any relative time values.
	req.StartTimeGte, req.StartTimeLt = a.normalizeTimeRange(req.StartTimeGte, req.StartTimeLt)

	// Validate the request.
	if err := a.validateTimeRange(req.StartTimeGte, req.StartTimeLt); err != nil {
		return &filterHintsResponse{nil, err}
	}

	values, meta, err := a.flowStore.FilterHints(req)
	if err != nil {
		logrus.WithError(err).Warn("Error listing filter hints")
		return &filterHintsResponse{nil, err}
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

// flowsToResult converts a list of internal Flow objects to a list of proto.FlowResult objects.
func (a *Goldmane) flowsToResult(flows []*types.Flow) []*proto.FlowResult {
	var flowsToReturn []*proto.FlowResult
	for _, flow := range flows {
		flowsToReturn = append(flowsToReturn, &proto.FlowResult{
			Flow: types.FlowToProto(flow),
			Id:   a.flowStore.ID(*flow.Key),
		})
	}
	return flowsToReturn
}

func (a *Goldmane) Stop() {
	close(a.done)
}

func (a *Goldmane) rollover() time.Duration {
	start := time.Now()
	defer func() {
		rolloverDuration.Observe(float64(time.Since(start).Milliseconds()))
	}()

	// Report readiness.
	if a.health != nil {
		a.health.Report(healthName, &health.HealthReport{Live: true, Ready: true})
	}

	// Tell the bucket ring to rollover and capture the start time of the newest bucket.
	// We'll use this below to determine when the next rollover should occur. The next bucket
	// should always be one interval ahead of Now().
	newBucketStart := a.flowStore.Rollover(a.sink)

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
		rolloverLatency.Observe(float64(10))
		return 10 * time.Millisecond
	}

	// The time until the next rollover is the difference between the next bucket start time and now.
	rolloverIn := nextBucketStart.Sub(now)
	logrus.WithFields(logrus.Fields{
		"nextBucketStart": nextBucketStart.Unix(),
		"now":             now.Unix(),
		"rolloverIn":      rolloverIn,
	}).Debug("Scheduling next rollover")
	rolloverLatency.Observe(float64(rolloverIn.Milliseconds()))
	return rolloverIn
}

func (a *Goldmane) handleFlowBatch(first *types.Flow) {
	// Index the flow that triggered the batch.
	a.indexFlow(first)

	// While we're here, check to see if there are any other flows to process.
	numHandled := 1
batchLoop:
	for range batchSize {
		select {
		case f := <-a.recvChan:
			a.indexFlow(f)
			numHandled++
		default:
			// No more flows to process.
			break batchLoop
		}
	}
	logrus.WithField("num", numHandled).Debug("Processed flow batch")

	// Set the number of unique flows in the aggregator based on the number of DiachronicFlows.
	numUniqueFlows.Set(float64(a.flowStore.Size()))
	flowChannelSize.Set(float64(len(a.recvChan)))
	flowIndexBatchSize.Observe(float64(numHandled))
}

func (a *Goldmane) indexFlow(flow *types.Flow) {
	flowStart := time.Now()
	logrus.WithField("flow", flow).Debug("Received Flow")

	// Increment the received flow counter.
	receivedFlowCounter.Inc()

	// Add the Flow to our bucket ring.
	a.flowStore.AddFlow(flow)

	// Record time taken to process the flow.
	flowIndexLatency.Observe(float64(time.Since(flowStart).Milliseconds()))
}
