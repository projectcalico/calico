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

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var (
	agg *aggregator.LogAggregator
	c   *clock
)

func setupTest(t *testing.T, opts ...aggregator.Option) func() {
	// Register gomega with test.
	RegisterTestingT(t)

	// Hook logrus into testing.T
	utils.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)
	agg = aggregator.NewLogAggregator(opts...)
	return func() {
		agg.Stop()
		agg = nil
		c = nil
		logCancel()
	}
}

func ExpectFlowsEqual(t *testing.T, expected, actual *proto.Flow) {
	if !googleproto.Equal(expected, actual) {
		msg := fmt.Sprintf("\nExpected:\n\t%v\nActual:\n\t%v", expected, actual)
		t.Error(msg)
	}
}

func TestIngestFlowLogs(t *testing.T) {
	c := newClock(100)
	now := c.Now().Unix()
	opts := []aggregator.Option{
		aggregator.WithRolloverTime(1 * time.Second),
		aggregator.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()

	// Start the aggregator.
	go agg.Run(now)

	// Ingest a flow log.
	fl := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Policies: &proto.FlowLogPolicy{AllPolicies: []string{
				"0|test-tier|kube-system/test-tier.cluster-dns|allow|1",
			}},
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
	var flows []*proto.Flow
	Eventually(func() bool {
		flows, _ = agg.GetFlows(&proto.FlowRequest{})
		return len(flows) == 1
	}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive flow").Should(BeTrue())

	// Expect aggregation to have happened.
	exp := proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Policies: &proto.FlowLogPolicy{AllPolicies: []string{
				"0|test-tier|kube-system/test-tier.cluster-dns|allow|1",
			}},
		},
		StartTime:             flows[0].StartTime,
		EndTime:               flows[0].EndTime,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}

	ExpectFlowsEqual(t, &exp, flows[0])

	// Send another copy of the flow log.
	agg.Receive(&proto.FlowUpdate{Flow: fl})

	// Expect the aggregator to have received it.
	var err error
	flows, err = agg.GetFlows(&proto.FlowRequest{})
	require.NoError(t, err)
	require.Len(t, flows, 1)

	// Expect aggregation to have happened.
	exp.NumConnectionsStarted = 2
	exp.BytesIn = 200
	exp.BytesOut = 400
	exp.PacketsIn = 20
	exp.PacketsOut = 40
	ExpectFlowsEqual(t, &exp, flows[0])

	// Wait for the aggregator to rollover.
	time.Sleep(1001 * time.Millisecond)

	// Send another flow log.
	agg.Receive(&proto.FlowUpdate{Flow: fl})

	// Expect the aggregator to have received it. This should be added to a new bucket,
	// but aggregated into the same flow on read.
	flows, err = agg.GetFlows(&proto.FlowRequest{})
	require.NoError(t, err)
	require.Len(t, flows, 1)

	exp2 := proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Policies: &proto.FlowLogPolicy{AllPolicies: []string{
				"0|test-tier|kube-system/test-tier.cluster-dns|allow|1",
			}},
		},
		StartTime:             flows[0].StartTime,
		EndTime:               flows[0].EndTime,
		BytesIn:               300,
		BytesOut:              600,
		PacketsIn:             30,
		PacketsOut:            60,
		NumConnectionsStarted: 3,
	}
	ExpectFlowsEqual(t, &exp2, flows[0])
}

// TestRotation tests that the aggregator correctly rotates out old flows.
func TestRotation(t *testing.T) {
	// Create a clock and rollover controller.
	c := newClock(100)
	now := c.Now().Unix()
	roller := &rolloverController{
		ch:                    make(chan time.Time),
		aggregationWindowSecs: 1,
		clock:                 c,
	}
	opts := []aggregator.Option{
		aggregator.WithRolloverTime(1 * time.Second),
		aggregator.WithRolloverFunc(roller.After),
		aggregator.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()
	go agg.Run(now)

	// Create a Flow in the latest bucket.
	fl := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Policies:        &proto.FlowLogPolicy{AllPolicies: []string{}},
		},
		StartTime:             now,
		EndTime:               now + 1,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	agg.Receive(&proto.FlowUpdate{Flow: fl})

	// We should be able to read it back.
	var flows []*proto.Flow
	Eventually(func() bool {
		flows, _ = agg.GetFlows(&proto.FlowRequest{})
		return len(flows) == 1
	}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive flow").Should(BeTrue())

	// Rollover the aggregator until we push the flow out of the window.
	roller.rolloverAndAdvanceClock(238)

	// The flow should still be here.
	Eventually(func() bool {
		flows, _ = agg.GetFlows(&proto.FlowRequest{})
		return len(flows) == 1
	}, 100*time.Millisecond, 10*time.Millisecond, "Flow rotated out too early").Should(BeTrue())

	// This one should do it.
	roller.rolloverAndAdvanceClock(1)

	// We should no longer be able to read the flow.
	Consistently(func() int {
		flows, _ = agg.GetFlows(&proto.FlowRequest{})
		return len(flows)
	}, 100*time.Millisecond, 10*time.Millisecond).Should(Equal(0), "Flow did not rotate out")
}

func TestManyFlows(t *testing.T) {
	c := newClock(100)
	now := c.Now().Unix()
	opts := []aggregator.Option{
		aggregator.WithRolloverTime(1 * time.Second),
		aggregator.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()
	go agg.Run(now)

	// Create 20k flows and send them as fast as we can. See how the aggregator handles it.
	fl := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Policies:        &proto.FlowLogPolicy{AllPolicies: []string{}},
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
	var flows []*proto.Flow
	Eventually(func() bool {
		flows, _ = agg.GetFlows(&proto.FlowRequest{})
		if len(flows) != 1 {
			return false
		}
		return flows[0].NumConnectionsStarted == 20000
	}, 1*time.Second, 20*time.Millisecond, "Didn't reach 20k flows: %d", len(flows)).Should(BeTrue())
}

func TestPagination(t *testing.T) {
	c := newClock(100)
	now := c.Now().Unix()
	opts := []aggregator.Option{
		aggregator.WithRolloverTime(1 * time.Second),
		aggregator.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()
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
				Policies:      &proto.FlowLogPolicy{AllPolicies: []string{}},
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
	var flows []*proto.Flow
	Eventually(func() bool {
		flows, _ = agg.GetFlows(&proto.FlowRequest{})
		return len(flows) == 30
	}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive all flows").Should(BeTrue())

	// Query with a page size of 5.
	page1, err := agg.GetFlows(&proto.FlowRequest{PageSize: 5})
	require.NoError(t, err)
	require.Len(t, page1, 5)
	require.Equal(t, page1[0].StartTime, int64(100))
	require.Equal(t, page1[4].StartTime, int64(96))

	// Query the third page - should be a different 5 flows (skipping page 2).
	page3, err := agg.GetFlows(&proto.FlowRequest{PageSize: 5, PageNumber: 2})
	require.NoError(t, err)
	require.Len(t, page3, 5)
	require.Equal(t, page3[0].StartTime, int64(90))
	require.Equal(t, page3[4].StartTime, int64(86))

	// Pages should not be equal.
	require.NotEqual(t, page1, page3)

	// Query the third page again. It should be consistent (since no new data).
	page2Again, err := agg.GetFlows(&proto.FlowRequest{PageSize: 5, PageNumber: 2})
	require.NoError(t, err)
	require.Equal(t, page3, page2Again)
}

func TestTimeRanges(t *testing.T) {
	c := newClock(100)
	now := c.Now().Unix()
	opts := []aggregator.Option{
		aggregator.WithRolloverTime(1 * time.Second),
		aggregator.WithNowFunc(c.Now),
	}
	prepareFlows := func() {
		// Create a flow spread across a range of buckets within the aggregator.
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
					Policies:        &proto.FlowLogPolicy{AllPolicies: []string{}},
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
			defer setupTest(t, opts...)()
			go agg.Run(now)

			// Create flows.
			prepareFlows()

			// Run the query, and check how many flows we get back.
			var flows []*proto.Flow

			if !test.expectNoMatch {
				// Should return one aggregated flow that sums the component flows.
				Eventually(func() bool {
					flows, _ = agg.GetFlows(test.query)
					return len(flows) == 1
				}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive flow").Should(BeTrue())
				Eventually(func() bool {
					flows, _ = agg.GetFlows(test.query)
					return flows[0].NumConnectionsStarted == int64(test.expectedNumConnectionsStarted)
				}, 100*time.Millisecond, 10*time.Millisecond, "Expected %d to equal %d", flows[0].NumConnectionsStarted, test.expectedNumConnectionsStarted).Should(BeTrue())

				// Verify other fields are aggregated correctly.
				exp := proto.Flow{
					Key: &proto.FlowKey{
						SourceName:      "test-src",
						SourceNamespace: "test-ns",
						DestName:        "test-dst",
						DestNamespace:   "test-dst-ns",
						Proto:           "tcp",
						Policies:        &proto.FlowLogPolicy{AllPolicies: []string{}},
					},
					StartTime:             flows[0].StartTime,
					EndTime:               flows[0].EndTime,
					BytesIn:               100 * int64(test.expectedNumConnectionsStarted),
					BytesOut:              200 * int64(test.expectedNumConnectionsStarted),
					PacketsIn:             10 * int64(test.expectedNumConnectionsStarted),
					PacketsOut:            20 * int64(test.expectedNumConnectionsStarted),
					NumConnectionsStarted: int64(test.expectedNumConnectionsStarted),
				}
				ExpectFlowsEqual(t, &exp, flows[0])
			} else {
				// Should consistently return no flows.
				for i := 0; i < 10; i++ {
					flows, err := agg.GetFlows(test.query)
					require.NoError(t, err)
					require.Len(t, flows, 0)
					time.Sleep(10 * time.Millisecond)
				}
			}
		})
	}
}

func TestSink(t *testing.T) {
	c := newClock(100)
	now := c.Now().Unix()

	// Configure the aggregator with a test sink.
	sink := &testSink{buckets: []*aggregator.FlowCollection{}}
	roller := &rolloverController{
		ch:                    make(chan time.Time),
		aggregationWindowSecs: 1,
		clock:                 c,
	}
	opts := []aggregator.Option{
		aggregator.WithRolloverTime(1 * time.Second),
		aggregator.WithSink(sink),
		aggregator.WithRolloverFunc(roller.After),
		aggregator.WithNowFunc(c.Now),
		aggregator.WithBucketsToCombine(20),
		aggregator.WithPushIndex(30),
	}
	defer setupTest(t, opts...)()

	// Start the aggregator, and rollover to trigger an emission.
	// We shouldn't see any buckets pushed to the sink, as we haven't sent any flows.
	go agg.Run(now)
	roller.rolloverAndAdvanceClock(1)
	require.Len(t, sink.buckets, 0)

	// We've rolled over once. The next emission should happen after
	// 21 more rollovers, which is the point at which the first bucket
	// not included in the previous emission will become eligible (since we are configured
	// to combine 20 buckets at a time).
	nextEmission := 21

	// Place 5 new flow logs in the first 5 buckets of the ring.
	flowStart := roller.now() + 1 - 4
	flowEnd := roller.now() + 2
	for i := 0; i < 5; i++ {
		fl := &proto.Flow{
			Key: &proto.FlowKey{
				SourceName:      "test-src",
				SourceNamespace: "test-ns",
				DestName:        "test-dst",
				DestNamespace:   "test-dst-ns",
				Proto:           "tcp",
				Policies:        &proto.FlowLogPolicy{AllPolicies: []string{}},
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

	// Rollover until we trigger the next emission. The flows we added above
	// won't appear in this emission, since they are in the first 5 buckets which
	// haven't reached the emission window yet.
	roller.rolloverAndAdvanceClock(nextEmission - 1)
	require.Len(t, sink.buckets, 0)
	roller.rolloverAndAdvanceClock(1)
	require.Len(t, sink.buckets, 0)

	// Now, rollover another 21 times. This will trigger emission of a bucket with the
	// 5 flows we added above.
	roller.rolloverAndAdvanceClock(nextEmission)
	require.Len(t, sink.buckets, 1, "Expected 1 bucket to be pushed to the sink")

	// We expect the collection to have been aggregated across 20 intervals, for a total of 20 seconds.
	// Since we started at 100:
	// - The first window we aggregated covered 52-72 (but had now flows)
	// - The second window we aggregated covered 72-92 (but had no flows)
	// - The third window we aggregated covered 92-112 (and had flows!)
	require.Equal(t, int64(112), sink.buckets[0].EndTime)
	require.Equal(t, int64(92), sink.buckets[0].StartTime)
	require.Equal(t, int64(20), sink.buckets[0].EndTime-sink.buckets[0].StartTime)

	// Expect the bucket to have aggregated to a single flow.
	require.Len(t, sink.buckets[0].Flows, 1)

	// Statistics should be aggregated correctly.
	exp := proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
		},
		StartTime:             flowStart,
		EndTime:               flowEnd,
		BytesIn:               500,
		BytesOut:              1000,
		PacketsIn:             50,
		PacketsOut:            100,
		NumConnectionsStarted: 5,
	}
	flow := sink.buckets[0].Flows[0]
	require.NotNil(t, flow)
	require.Equal(t, *types.ProtoToFlow(&exp), flow)
}

// TestBucketDrift makes sure that the aggregator is able to account for its internal array of
// aggregation buckets slowly drifting with respect to time.Now(). This can happen due to the time taken to process
// other operations on the shared main goroutine, and is accounted for by adjusting the the next rollover time.
func TestBucketDrift(t *testing.T) {
	// Create a clock and rollover controller.
	c := newClock(100)
	aggregationWindowSecs := 10
	roller := &rolloverController{
		ch:                    make(chan time.Time),
		aggregationWindowSecs: int64(aggregationWindowSecs),
		clock:                 c,
	}

	var rolloverScheduledAt time.Duration
	rolloverFunc := func(d time.Duration) <-chan time.Time {
		rolloverScheduledAt = d
		return roller.After(d)
	}
	opts := []aggregator.Option{
		aggregator.WithRolloverTime(time.Duration(aggregationWindowSecs) * time.Second),
		aggregator.WithRolloverFunc(rolloverFunc),
		aggregator.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()

	// This can get a bit confusing, so let's walk through it:
	//
	// - The aggregator maintains an internal array of buckets. The most recent bucket actually starts one aggregation window in the future, to handle clock skew between nodes.
	// - For this test, we want to simulate a rollover that happens slightly late.
	// - Now() is mocked to 100, With an aggregation window of 10s. So buckets[head] will cover 110-120, bucket[head-1] will cover 100-110.
	// - Normally, a rollover would occur at 110, adding a new bucket[head] covering 120-130.
	// - For this test, we'll simulate a rollover at 113, which is 3 seconds late.
	//
	// From there, we can expect the aggregator to notice that it has missed time somehow and accelerate the scheduling of the next rollover
	// in order to compensate.
	go agg.Run(c.Now().Unix())

	// We want to simulate a rollover that happens at 113, which is 3 seconds late for the scheduled 110 rollover.
	c.Set(time.Unix(113, 0))
	roller.rollover()

	// Assert that the rollover function was called with an expedited reschedule time of 7 seconds, compared to the
	// expected rollover interval of 10 seconds.
	require.Equal(t, 7, int(rolloverScheduledAt.Seconds()), "Expedited rollover should have been scheduled at 7s")

	// Advance the clock to 120, the expected time of the next rollover.
	c.Set(time.Unix(120, 0))

	// Trigger another rollover. This time, the aggregator should have caught up, so the rollover should be scheduled
	// at the expected time of one aggregation window in the future (10s).
	roller.rollover()

	require.Equal(t, aggregationWindowSecs, int(rolloverScheduledAt.Seconds()), "Expected rollover to be scheduled at 10s")

	// Now let's try the other dirction - simulate a rollover that happens 4 seconds early.
	// We expect the next rollover to occur at 130, so trigger one at 126.
	c.Set(time.Unix(126, 0))
	roller.rollover()

	// The aggregator should notice that it's ahead of schedule and delay the next rollover by 4 seconds.
	require.Equal(t, 14, int(rolloverScheduledAt.Seconds()), "Delayed rollover should have been scheduled at 14s")

	// And check what happens if we're so far behind that the next bucket is already in the past.
	// The next bucket should start at 140, so trigger a rollover at 155.
	// This should trigger an immediate rollover.
	c.Set(time.Unix(155, 0))
	roller.rollover()
	require.Equal(t, 10*time.Millisecond, rolloverScheduledAt, "Immediate rollover should have been scheduled for 10ms")
}
