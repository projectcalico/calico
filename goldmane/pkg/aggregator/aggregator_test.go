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

package aggregator_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var agg *aggregator.LogAggregator

func setupTest(t *testing.T, opts ...aggregator.Option) func() {
	// Hook logrus into testing.T
	utils.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)
	if len(opts) == 0 {
		opts = append(opts, aggregator.WithRolloverTime(1*time.Second))
	}
	agg = aggregator.NewLogAggregator(opts...)
	return func() {
		agg.Stop()
		agg = nil
		logCancel()
	}
}

func TestIngestFlowLogs(t *testing.T) {
	defer setupTest(t)()

	// Start the aggregator.
	now := int64(100)
	go agg.Run(now)

	// Ingest a flow log.
	fl := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             now - 15,
		EndTime:               now,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	agg.Receive(&proto.FlowUpdate{Flow: fl})

	// Expect the aggregator to have received it.
	var flows []proto.Flow
	require.Eventually(t, func() bool {
		flows = agg.GetFlows(&proto.FlowRequest{})
		return len(flows) == 1
	}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive flow")

	// Expect aggregation to have happened.
	exp := proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             flows[0].StartTime,
		EndTime:               flows[0].EndTime,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	require.Equal(t, exp, flows[0])

	// Send another copy of the flow log.
	agg.Receive(&proto.FlowUpdate{Flow: fl})

	// Expect the aggregator to have received it.
	flows = agg.GetFlows(&proto.FlowRequest{})
	require.Len(t, flows, 1)

	// Expect aggregation to have happened.
	exp.NumConnectionsStarted = 2
	exp.BytesIn = 200
	exp.BytesOut = 400
	exp.PacketsIn = 20
	exp.PacketsOut = 40
	require.Equal(t, exp, flows[0])

	// Wait for the aggregator to rollover.
	time.Sleep(1001 * time.Millisecond)

	// Send another flow log.
	agg.Receive(&proto.FlowUpdate{Flow: fl})

	// Expect the aggregator to have received it. This should be added to a new bucket,
	// but aggregated into the same flow on read.
	flows = agg.GetFlows(&proto.FlowRequest{})
	require.Len(t, flows, 1)

	exp2 := proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             flows[0].StartTime,
		EndTime:               flows[0].EndTime,
		BytesIn:               300,
		BytesOut:              600,
		PacketsIn:             30,
		PacketsOut:            60,
		NumConnectionsStarted: 3,
	}
	require.Equal(t, exp2, flows[0])
}

func TestManyFlows(t *testing.T) {
	defer setupTest(t)()

	now := int64(100)
	go agg.Run(now)

	// Create 20k flows and send them as fast as we can. See how the aggregator handles it.
	fl := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             now - 15,
		EndTime:               now,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	for i := 0; i < 20000; i++ {
		agg.Receive(&proto.FlowUpdate{Flow: fl})
	}

	// Query for the flow.
	var flows []proto.Flow
	require.Eventually(t, func() bool {
		flows = agg.GetFlows(&proto.FlowRequest{})
		if len(flows) != 1 {
			return false
		}
		return flows[0].NumConnectionsStarted == 20000
	}, 1*time.Second, 20*time.Millisecond, "Didn't reach 20k flows: %d", len(flows))
}

func TestPagination(t *testing.T) {
	defer setupTest(t)()

	now := int64(100)
	go agg.Run(now)

	// Create 30 different flows.
	for i := 0; i < 30; i++ {
		fl := &proto.Flow{
			Key: &proto.FlowKey{
				SourceName:      "test-src",
				SourceNamespace: "test-ns",

				// Each flow is to a unique destination, thus making the flow unique.
				DestName:      fmt.Sprintf("test-dst-%d", i),
				DestNamespace: "test-dst-ns",
				Proto:         "tcp",
			},

			// Give each flow a unique time stamp, for deterministic ordering.
			StartTime:             now - int64(i),
			EndTime:               now - int64(i) + 1,
			BytesIn:               100,
			BytesOut:              200,
			PacketsIn:             10,
			PacketsOut:            20,
			NumConnectionsStarted: 1,
		}
		agg.Receive(&proto.FlowUpdate{Flow: fl})
	}

	// Query without pagination.
	var flows []proto.Flow
	require.Eventually(t, func() bool {
		flows = agg.GetFlows(&proto.FlowRequest{})
		return len(flows) == 30
	}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive all flows")

	// Query with a page size of 5.
	page1 := agg.GetFlows(&proto.FlowRequest{PageSize: 5})
	require.Len(t, page1, 5)
	require.Equal(t, page1[0].StartTime, int64(100))
	require.Equal(t, page1[4].StartTime, int64(96))

	// Query the third page - should be a different 5 flows (skipping page 2).
	page3 := agg.GetFlows(&proto.FlowRequest{PageSize: 5, PageNumber: 2})
	require.Len(t, page3, 5)
	require.Equal(t, page3[0].StartTime, int64(90))
	require.Equal(t, page3[4].StartTime, int64(86))

	// Pages should not be equal.
	require.NotEqual(t, page1, page3)

	// Query the third page again. It should be consistent (since no new data).
	page2Again := agg.GetFlows(&proto.FlowRequest{PageSize: 5, PageNumber: 2})
	require.Equal(t, page3, page2Again)
}

func TestTimeRanges(t *testing.T) {
	now := int64(100)
	prepareFlows := func() {
		// Create a flow spread across the full range of buckets within the aggregator.
		// 60 buckes of 1s each means we want one flow per second for 60s.
		for i := 0; i < 60; i++ {
			flow := &proto.Flow{
				// Start one rollover period into the future, since that is how the aggregator works.
				Key: &proto.FlowKey{
					SourceName:      "test-src",
					SourceNamespace: "test-ns",
					DestName:        "test-dst",
					DestNamespace:   "test-dst-ns",
					Proto:           "tcp",
				},
				StartTime:             now + 1 - int64(i),
				EndTime:               now + 1 - int64(i-1),
				BytesIn:               100,
				BytesOut:              200,
				PacketsIn:             10,
				PacketsOut:            20,
				NumConnectionsStarted: 1,
			}
			agg.Receive(&proto.FlowUpdate{Flow: flow})
		}
	}

	type testCase struct {
		name                          string
		query                         *proto.FlowRequest
		expectedNumConnectionsStarted int
		expectNoMatch                 bool
	}

	tests := []testCase{
		{
			name:                          "All flows",
			query:                         &proto.FlowRequest{},
			expectedNumConnectionsStarted: 60,
		},
		{
			name:                          "10s of flows",
			query:                         &proto.FlowRequest{StartTimeGt: now - 10, StartTimeLt: now},
			expectedNumConnectionsStarted: 10,
		},
		{
			name:  "10s of flows, starting in the future",
			query: &proto.FlowRequest{StartTimeGt: now + 10, StartTimeLt: now + 20},
			// Should return no flows, since the query is in the future.
			expectNoMatch: true,
		},
		{
			name:                          "5s of flows",
			query:                         &proto.FlowRequest{StartTimeGt: now - 12, StartTimeLt: now - 7},
			expectedNumConnectionsStarted: 5,
		},
		{
			name:  "end time before start time",
			query: &proto.FlowRequest{StartTimeGt: now - 7, StartTimeLt: now - 12},
			// Should return no flows, since the query covers 0s.
			expectNoMatch: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupTest(t)()
			go agg.Run(now)

			// Create flows.
			prepareFlows()

			// Run the query, and check how many flows we get back.
			var flows []proto.Flow

			if !test.expectNoMatch {
				// Should return one aggregated flow that sums the component flows.
				require.Eventually(t, func() bool {
					flows = agg.GetFlows(test.query)
					return len(flows) == 1
				}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive flow")
				require.Eventually(t, func() bool {
					flows = agg.GetFlows(test.query)
					return flows[0].NumConnectionsStarted == int64(test.expectedNumConnectionsStarted)
				}, 100*time.Millisecond, 10*time.Millisecond, "Expected %d to equal %d", flows[0].NumConnectionsStarted, test.expectedNumConnectionsStarted)

				// Verify other fields are aggregated correctly.
				exp := proto.Flow{
					Key: &proto.FlowKey{
						SourceName:      "test-src",
						SourceNamespace: "test-ns",
						DestName:        "test-dst",
						DestNamespace:   "test-dst-ns",
						Proto:           "tcp",
					},
					StartTime:             flows[0].StartTime,
					EndTime:               flows[0].EndTime,
					BytesIn:               100 * int64(test.expectedNumConnectionsStarted),
					BytesOut:              200 * int64(test.expectedNumConnectionsStarted),
					PacketsIn:             10 * int64(test.expectedNumConnectionsStarted),
					PacketsOut:            20 * int64(test.expectedNumConnectionsStarted),
					NumConnectionsStarted: int64(test.expectedNumConnectionsStarted),
				}
				require.Equal(t, exp, flows[0])
			} else {
				// Should consistently return no flows.
				for i := 0; i < 10; i++ {
					flows := agg.GetFlows(test.query)
					require.Len(t, flows, 0)
					time.Sleep(10 * time.Millisecond)
				}
			}
		})
	}
}

func TestSink(t *testing.T) {
	now := int64(100)

	// Configure the aggregator with a test sink.
	sink := &testSink{buckets: []*aggregator.AggregationBucket{}}
	roller := &rolloverController{
		ch:           make(chan time.Time),
		intervalSecs: 1,
		t:            now,
	}
	opts := []aggregator.Option{
		aggregator.WithRolloverTime(1 * time.Second),
		aggregator.WithSink(sink),
		aggregator.WithRolloverFunc(roller.After),
	}
	defer setupTest(t, opts...)()

	// Start the aggregator, and trigger enough rollovers to trigger an emission.
	// We shouldn't see any buckets pushed to the sink, as we haven't sent any flows.
	go agg.Run(now)
	roller.rollover(35)
	require.Len(t, sink.buckets, 0)

	// Place 5 new flow logs in the first 5 buckets of the aggregator.
	for i := 0; i < 5; i++ {
		fl := &proto.Flow{
			Key: &proto.FlowKey{
				SourceName:      "test-src",
				SourceNamespace: "test-ns",
				DestName:        "test-dst",
				DestNamespace:   "test-dst-ns",
				Proto:           "tcp",
			},
			StartTime:             roller.now() + 1 - int64(i),
			EndTime:               roller.now() + 2 - int64(i),
			BytesIn:               100,
			BytesOut:              200,
			PacketsIn:             10,
			PacketsOut:            20,
			NumConnectionsStarted: 1,
		}
		agg.Receive(&proto.FlowUpdate{Flow: fl})
	}

	// Wait for all flows to be received.
	time.Sleep(10 * time.Millisecond)

	// Rollover until index 4 is in the rollover location (idx 30). This will trigger
	// a rollover of this batch of 5 buckets.
	roller.rollover(25)
	require.Len(t, sink.buckets, 0)
	roller.rollover(1)
	require.Len(t, sink.buckets, 1, "Expected 1 bucket to be pushed to the sink")

	// Bucket should be aggregated across 20 intervals, for a total of 20 seconds.
	require.Equal(t, int64(20), sink.buckets[0].EndTime-sink.buckets[0].StartTime)

	// Expect the bucket to have aggregated to a single flow.
	require.Len(t, sink.buckets[0].Flows, 1)

	// Statistics should be aggregated correctly. The flow time range should
	// be updated to match the bucket time range, since the flow was present in
	// each of the 5 intervals.
	exp := proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             sink.buckets[0].StartTime,
		EndTime:               sink.buckets[0].StartTime + 5, // 5 seconds of flow.
		BytesIn:               500,
		BytesOut:              1000,
		PacketsIn:             50,
		PacketsOut:            100,
		NumConnectionsStarted: 5,
	}
	flow := sink.buckets[0].Flows[*types.ProtoToFlowKey(exp.Key)]
	require.NotNil(t, flow)
	require.Equal(t, *types.ProtoToFlow(&exp), *flow)
}
