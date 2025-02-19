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
	"math/rand/v2"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
	"github.com/projectcalico/calico/goldmane/pkg/aggregator/bucketing"
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

func TestList(t *testing.T) {
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
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns",
						Namespace:   "kube-system",
						Tier:        "test-tier",
						Action:      "allow",
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
			},
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
	var flows []*proto.FlowResult
	Eventually(func() bool {
		flows, _ = agg.List(&proto.FlowListRequest{})
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
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns",
						Namespace:   "kube-system",
						Tier:        "test-tier",
						Action:      "allow",
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
			},
		},
		StartTime:             flows[0].Flow.StartTime,
		EndTime:               flows[0].Flow.EndTime,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}

	ExpectFlowsEqual(t, &exp, flows[0].Flow)

	// IDs are assigned in order, so we can check that the ID is 1.
	Expect(flows[0].Id).To(Equal(int64(1)))

	// Send another copy of the flow log.
	agg.Receive(&proto.FlowUpdate{Flow: fl})

	// Expect the aggregator to have received it. Aggregation of new flows
	// happens asynchonously, so we may need to wait a few ms for it.
	var err error
	Eventually(func() error {
		flows, err = agg.List(&proto.FlowListRequest{})
		if err != nil {
			return err
		}
		if len(flows) != 1 {
			return fmt.Errorf("Expected 1 flow, got %d", len(flows))
		}
		if flows[0].Flow.NumConnectionsStarted != 2 {
			return fmt.Errorf("Expected 2 connections, got %d", flows[0].Flow.NumConnectionsStarted)
		}
		return nil
	}, 100*time.Millisecond, 10*time.Millisecond, "Incorrect flow output").Should(BeNil())

	// Expect aggregation to have happened.
	exp.NumConnectionsStarted = 2
	exp.BytesIn = 200
	exp.BytesOut = 400
	exp.PacketsIn = 20
	exp.PacketsOut = 40
	ExpectFlowsEqual(t, &exp, flows[0].Flow)

	// ID should be unchanged.
	Expect(flows[0].Id).To(Equal(int64(1)))

	// Wait for the aggregator to rollover.
	time.Sleep(1001 * time.Millisecond)

	// Send another flow log.
	agg.Receive(&proto.FlowUpdate{Flow: fl})

	// Expect the aggregator to have received it. This should be added to a new bucket,
	// but aggregated into the same flow on read.
	Eventually(func() error {
		flows, err = agg.List(&proto.FlowListRequest{})
		if err != nil {
			return err
		}
		if len(flows) != 1 {
			return fmt.Errorf("Expected 1 flow, got %d", len(flows))
		}
		if flows[0].Flow.NumConnectionsStarted != 3 {
			return fmt.Errorf("Expected 3 connections, got %d", flows[0].Flow.NumConnectionsStarted)
		}
		return nil
	}, 100*time.Millisecond, 10*time.Millisecond, "Incorrect flow output").Should(BeNil())

	exp2 := proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns",
						Namespace:   "kube-system",
						Tier:        "test-tier",
						Action:      "allow",
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
			},
		},
		StartTime:             flows[0].Flow.StartTime,
		EndTime:               flows[0].Flow.EndTime,
		BytesIn:               300,
		BytesOut:              600,
		PacketsIn:             30,
		PacketsOut:            60,
		NumConnectionsStarted: 3,
	}
	ExpectFlowsEqual(t, &exp2, flows[0].Flow)

	// ID should be unchanged.
	Expect(flows[0].Id).To(Equal(int64(1)))
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
			Policies:        &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
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
	var flows []*proto.FlowResult
	Eventually(func() bool {
		flows, _ = agg.List(&proto.FlowListRequest{})
		return len(flows) == 1
	}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive flow").Should(BeTrue())

	// ID should is non-deterministic, but should be consistent.
	flowID := flows[0].Id
	Expect(flowID).To(BeNumerically(">", 0))

	// Rollover the aggregator until we push the flow out of the window.
	roller.rolloverAndAdvanceClock(238)

	// The flow should still be here.
	Eventually(func() bool {
		flows, _ = agg.List(&proto.FlowListRequest{})
		return len(flows) == 1
	}, 100*time.Millisecond, 10*time.Millisecond, "Flow rotated out too early").Should(BeTrue())

	// ID should be unchanged.
	Expect(flows[0].Id).To(Equal(flowID))

	// This one should do it.
	roller.rolloverAndAdvanceClock(1)

	// We should no longer be able to read the flow.
	Consistently(func() int {
		flows, _ = agg.List(&proto.FlowListRequest{})
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
			Policies:        &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
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
	var flows []*proto.FlowResult
	Eventually(func() bool {
		flows, _ = agg.List(&proto.FlowListRequest{})
		if len(flows) != 1 {
			return false
		}
		return flows[0].Flow.NumConnectionsStarted == 20000
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
				Policies:      &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
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
	var flows []*proto.FlowResult
	Eventually(func() bool {
		flows, _ = agg.List(&proto.FlowListRequest{})
		return len(flows) == 30
	}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive all flows").Should(BeTrue())

	// Query with a page size of 5.
	page0, err := agg.List(&proto.FlowListRequest{PageSize: 5})
	require.NoError(t, err)
	require.Len(t, page0, 5, "Page 0 should have 5 flows")
	require.Equal(t, int64(100), page0[0].Flow.StartTime)
	require.Equal(t, int64(96), page0[4].Flow.StartTime)
	require.NotEqual(t, page0[0].Id, page0[4].Id, "should have unique flow IDs")

	// Query the third page - should be a different 5 flows (skipping page 2).
	page2, err := agg.List(&proto.FlowListRequest{PageSize: 5, PageNumber: 2})
	require.NoError(t, err)
	require.Len(t, page2, 5, "Page 2 should have 5 flows")
	require.Equal(t, int64(90), page2[0].Flow.StartTime)
	require.Equal(t, int64(14), page2[0].Id)
	require.Equal(t, int64(86), page2[4].Flow.StartTime)
	require.Equal(t, int64(18), page2[4].Id)

	// Pages should not be equal.
	require.NotEqual(t, page0, page2, "Page 0 and 2 should not be equal")

	// Query the third page again. It should be consistent (since no new data).
	page2Again, err := agg.List(&proto.FlowListRequest{PageSize: 5, PageNumber: 2})
	require.NoError(t, err)
	require.Equal(t, page2, page2Again, "Page 2 and 2 should be equal on second query")
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
					Policies:        &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
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
		query                         *proto.FlowListRequest
		expectedNumConnectionsStarted int
		expectNoMatch                 bool
		expectErr                     bool
	}

	tests := []testCase{
		{
			name:                          "All flows",
			query:                         &proto.FlowListRequest{},
			expectedNumConnectionsStarted: 60,
		},
		{
			name:                          "10s of flows",
			query:                         &proto.FlowListRequest{StartTimeGt: now - 10, StartTimeLt: now},
			expectedNumConnectionsStarted: 10,
		},
		{
			name:  "10s of flows, starting in the future",
			query: &proto.FlowListRequest{StartTimeGt: now + 10, StartTimeLt: now + 20},
			// Should return no flows, since the query is in the future.
			expectNoMatch: true,
		},
		{
			name:                          "5s of flows",
			query:                         &proto.FlowListRequest{StartTimeGt: now - 12, StartTimeLt: now - 7},
			expectedNumConnectionsStarted: 5,
		},
		{
			name:  "end time before start time",
			query: &proto.FlowListRequest{StartTimeGt: now - 7, StartTimeLt: now - 12},
			// Should return no flows, since the query covers 0s.
			expectNoMatch: true,
			expectErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupTest(t, opts...)()
			go agg.Run(now)

			// Create flows.
			prepareFlows()

			// Run the query, and check how many flows we get back.
			var flows []*proto.FlowResult

			if !test.expectNoMatch {
				// Should return one aggregated flow that sums the component flows.
				Eventually(func() bool {
					flows, _ = agg.List(test.query)
					return len(flows) == 1
				}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive flow").Should(BeTrue())
				Eventually(func() bool {
					flows, _ = agg.List(test.query)
					return flows[0].Flow.NumConnectionsStarted == int64(test.expectedNumConnectionsStarted)
				}, 100*time.Millisecond, 10*time.Millisecond, "Expected %d to equal %d", flows[0].Flow.NumConnectionsStarted, test.expectedNumConnectionsStarted).Should(BeTrue())

				// Verify other fields are aggregated correctly.
				exp := proto.Flow{
					Key: &proto.FlowKey{
						SourceName:      "test-src",
						SourceNamespace: "test-ns",
						DestName:        "test-dst",
						DestNamespace:   "test-dst-ns",
						Proto:           "tcp",
						Policies:        &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
					},
					StartTime:             flows[0].Flow.StartTime,
					EndTime:               flows[0].Flow.EndTime,
					BytesIn:               100 * int64(test.expectedNumConnectionsStarted),
					BytesOut:              200 * int64(test.expectedNumConnectionsStarted),
					PacketsIn:             10 * int64(test.expectedNumConnectionsStarted),
					PacketsOut:            20 * int64(test.expectedNumConnectionsStarted),
					NumConnectionsStarted: int64(test.expectedNumConnectionsStarted),
				}
				ExpectFlowsEqual(t, &exp, flows[0].Flow)
			} else {
				// Should consistently return no flows.
				for i := 0; i < 10; i++ {
					flows, err := agg.List(test.query)
					if test.expectErr {
						require.Error(t, err)
					} else {
						require.NoError(t, err)
					}
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
	sink := &testSink{buckets: []*bucketing.FlowCollection{}}
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
				Policies:        &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
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

func TestStreams(t *testing.T) {
	// Create a clock and rollover controller.
	c := newClock(100)
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

	// Start the aggregator.
	go agg.Run(c.Now().Unix())

	// Insert some random historical flow data from the past over the
	// time range of now-10 to now-5.
	for i := 5; i < 10; i++ {
		fl := newRandomFlow(c.Now().Unix() - int64(i))
		agg.Receive(&proto.FlowUpdate{Flow: fl})
	}

	// Expect the flows to have been received.
	Eventually(func() error {
		flows, err := agg.List(&proto.FlowListRequest{})
		if err != nil {
			return err
		}
		if len(flows) != 5 {
			return fmt.Errorf("Expected 5 flows, got %d", len(flows))
		}
		return nil
	}, 100*time.Millisecond, 10*time.Millisecond).Should(BeNil())

	// Create two streams. The first will be be configured to start streaming from
	// the present, and the second will be configured to start streaming from the past.
	stream, err := agg.Stream(&proto.FlowStreamRequest{})
	require.Nil(t, err)
	require.NotNil(t, stream)
	defer stream.Close()

	// stream2 will start streaming from the past, and should receive some historical flows.
	// we'll start it from now-7, so it should receive the flows from now-7 to now-5.
	stream2, err := agg.Stream(&proto.FlowStreamRequest{StartTimeGt: c.Now().Unix() - 7})
	require.Nil(t, err)
	require.NotNil(t, stream2)
	defer stream2.Close()

	// Expect nothing on the first stream, since it's starting from the present.
	Consistently(stream.Flows(), 100*time.Millisecond, 10*time.Millisecond).ShouldNot(Receive())

	// Expect three historical flows on the second stream: now-5, now-6, now-7.
	// We should receive them in time order, and should NOT receive now-8 or now-9.
	for i := 7; i >= 5; i-- {
		var flow *proto.FlowResult
		Eventually(stream2.Flows(), 1*time.Second, 10*time.Millisecond).Should(Receive(&flow), fmt.Sprintf("Expected flow %d", i))
		Expect(flow.Flow.StartTime).To(Equal(c.Now().Unix() - int64(i)))
	}

	// We shouldn't receive any more flows.
	Consistently(stream2.Flows(), 100*time.Millisecond, 10*time.Millisecond).ShouldNot(Receive(), "Expected no more flows")

	// Ingest some new flow data.
	fl := newRandomFlow(c.Now().Unix() - 1)
	agg.Receive(&proto.FlowUpdate{Flow: fl})

	// Expect the flow to have been received for a total of 6 flows in the aggregator.
	Eventually(func() error {
		flows, err := agg.List(&proto.FlowListRequest{})
		if err != nil {
			return err
		}
		if len(flows) != 6 {
			return fmt.Errorf("Expected 6 flows, got %d", len(flows))
		}
		return nil
	}, 100*time.Millisecond, 10*time.Millisecond).Should(BeNil())

	// Trigger a rollover, which should cause the flow to be emitted to the stream.
	roller.rolloverAndAdvanceClock(1)

	// Expect the flow to have been received on both streams.
	var flow *proto.FlowResult
	var flow2 *proto.FlowResult
	Eventually(stream.Flows(), 1*time.Second, 10*time.Millisecond).Should(Receive(&flow))
	Eventually(stream2.Flows(), 1*time.Second, 10*time.Millisecond).Should(Receive(&flow2))
	ExpectFlowsEqual(t, fl, flow.Flow)
	ExpectFlowsEqual(t, fl, flow2.Flow)

	// Expect no other flows.
	Consistently(stream.Flows(), 100*time.Millisecond, 10*time.Millisecond).ShouldNot(Receive())
	Consistently(stream2.Flows(), 100*time.Millisecond, 10*time.Millisecond).ShouldNot(Receive())
}

// TestSortOrder tests basic functionality of the various sorted indices supported by the aggregator.
func TestSortOrder(t *testing.T) {
	type tc struct {
		name   string
		sortBy proto.SortBy
	}

	// Define test cases.
	tests := []tc{
		{name: "SourceName", sortBy: proto.SortBy_SourceName},
		{name: "SourceNamespace", sortBy: proto.SortBy_SourceNamespace},
		{name: "DestName", sortBy: proto.SortBy_DestName},
		{name: "DestNamespace", sortBy: proto.SortBy_DestNamespace},
		{name: "Time", sortBy: proto.SortBy_Time},
	}

	// Run each test.
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a clock and rollover controller.
			c := newClock(100)
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
			go agg.Run(c.Now().Unix())

			// Create a bunch of random flows.
			for i := 0; i < 100; i++ {
				fl := newRandomFlow(c.Now().Unix() - 1)
				agg.Receive(&proto.FlowUpdate{Flow: fl})
			}

			// Query for Flows, sorted by the Index under test. Since we have created a bunch of random flows,
			// we don't know exactly how many unique keys there will be. But it will be a non-zero number.
			var flows []*proto.FlowResult
			Eventually(func() bool {
				flows, _ = agg.List(&proto.FlowListRequest{SortBy: []*proto.SortOption{{SortBy: tc.sortBy}}})
				return len(flows) > 3
			}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive flows").Should(BeTrue())

			// Compare the resulting sort order.
			for i := 1; i < len(flows); i++ {
				msg := fmt.Sprintf("Expected %+v to be greater than or equal to %+v", flows[i].Flow, flows[i-1].Flow)
				switch tc.sortBy {
				case proto.SortBy_DestNamespace:
					Expect(flows[i].Flow.Key.DestNamespace >= flows[i-1].Flow.Key.DestNamespace).To(BeTrue(), msg)
				case proto.SortBy_DestName:
					Expect(flows[i].Flow.Key.DestName >= flows[i-1].Flow.Key.DestName).To(BeTrue(), msg)
				case proto.SortBy_SourceNamespace:
					Expect(flows[i].Flow.Key.SourceNamespace >= flows[i-1].Flow.Key.SourceNamespace).To(BeTrue(), msg)
				case proto.SortBy_SourceName:
					Expect(flows[i].Flow.Key.SourceName >= flows[i-1].Flow.Key.SourceName).To(BeTrue(), msg)
				}
			}
		})
	}
}

func TestFilter(t *testing.T) {
	type tc struct {
		name     string
		req      *proto.FlowListRequest
		numFlows int
		check    func(*proto.FlowResult) error
	}

	tests := []tc{
		{
			name:     "SourceName, no sort",
			req:      &proto.FlowListRequest{Filter: &proto.Filter{SourceName: "source-1"}},
			numFlows: 1,
			check: func(fl *proto.FlowResult) error {
				if fl.Flow.Key.SourceName != "source-1" {
					return fmt.Errorf("Expected SourceName to be source-1, got %s", fl.Flow.Key.SourceName)
				}
				return nil
			},
		},

		{
			name: "SourceName, sort by SourceName",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{SourceName: "source-1"},
				SortBy: []*proto.SortOption{{SortBy: proto.SortBy_SourceName}},
			},
			numFlows: 1,
			check: func(fl *proto.FlowResult) error {
				if fl.Flow.Key.SourceName != "source-1" {
					return fmt.Errorf("Expected SourceName to be source-1, got %s", fl.Flow.Key.SourceName)
				}
				return nil
			},
		},

		{
			name:     "SourceNamespace, no sort",
			req:      &proto.FlowListRequest{Filter: &proto.Filter{SourceNamespace: "source-ns-1"}},
			numFlows: 1,
			check: func(fl *proto.FlowResult) error {
				if fl.Flow.Key.SourceNamespace != "source-ns-1" {
					return fmt.Errorf("Expected SourceNamespace to be source-ns-1, got %s", fl.Flow.Key.SourceNamespace)
				}
				return nil
			},
		},

		{
			name:     "DestName, no sort",
			req:      &proto.FlowListRequest{Filter: &proto.Filter{DestName: "dest-2"}},
			numFlows: 1,
			check: func(fl *proto.FlowResult) error {
				if fl.Flow.Key.DestName != "dest-2" {
					return fmt.Errorf("Expected DestName to be dest-2, got %s", fl.Flow.Key.DestName)
				}
				return nil
			},
		},

		{
			name:     "DestName, no sort, no match",
			req:      &proto.FlowListRequest{Filter: &proto.Filter{DestName: "dest-100"}},
			numFlows: 0,
		},

		{
			name:     "Port, no sort",
			req:      &proto.FlowListRequest{Filter: &proto.Filter{DestPort: 5}},
			numFlows: 1,
			check: func(fl *proto.FlowResult) error {
				if fl.Flow.Key.DestPort != 5 {
					return fmt.Errorf("Expected DestPort to be 5, got %d", fl.Flow.Key.DestPort)
				}
				return nil
			},
		},

		{
			name: "Tier",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policy: &proto.PolicyMatch{Tier: "tier-5"},
				},
			},
			numFlows: 1,
			check: func(fl *proto.FlowResult) error {
				if fl.Flow.Key.Policies.EnforcedPolicies[0].Tier != "tier-5" {
					return fmt.Errorf("Expected Tier to be tier-5, got %s", fl.Flow.Key.Policies.EnforcedPolicies[0].Tier)
				}
				return nil
			},
		},

		{
			name: "Full policy match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policy: &proto.PolicyMatch{
						Tier:      "tier-5",
						Name:      "name-5",
						Namespace: "ns-5",
						Action:    "allow",
						Kind:      proto.PolicyKind_CalicoNetworkPolicy,
					},
				},
			},
			numFlows: 1,
		},

		{
			name: "match on policy Kind, no match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policy: &proto.PolicyMatch{
						Kind: proto.PolicyKind_CalicoGlobalNetworkPolicy,
					},
				},
			},
			numFlows: 0,
		},

		{
			name: "match on policy Kind, match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policy: &proto.PolicyMatch{
						Kind: proto.PolicyKind_CalicoNetworkPolicy,
					},
				},
			},
			numFlows: 10,
		},

		{
			name: "match on pending policy",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policy: &proto.PolicyMatch{
						Namespace: "pending-ns-5",
					},
				},
			},
			numFlows: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a clock and rollover controller.
			c := newClock(100)
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
			go agg.Run(c.Now().Unix())

			// Create 10 flows, with a mix of fields to filter on.
			for i := 0; i < 10; i++ {
				// Start with a base flow.
				fl := newRandomFlow(c.Now().Unix() - 1)

				// Configure fields to filter on.
				fl.Key.SourceName = fmt.Sprintf("source-%d", i)
				fl.Key.SourceNamespace = fmt.Sprintf("source-ns-%d", i)
				fl.Key.DestName = fmt.Sprintf("dest-%d", i)
				fl.Key.DestNamespace = fmt.Sprintf("dest-ns-%d", i)
				fl.Key.Proto = "tcp"
				fl.Key.DestPort = int64(i)
				fl.Key.Policies = &proto.PolicyTrace{
					EnforcedPolicies: []*proto.PolicyHit{
						{
							Tier:      fmt.Sprintf("tier-%d", i),
							Name:      fmt.Sprintf("name-%d", i),
							Namespace: fmt.Sprintf("ns-%d", i),
							Action:    "allow",
							Kind:      proto.PolicyKind_CalicoNetworkPolicy,
						},
					},
					PendingPolicies: []*proto.PolicyHit{
						{
							Tier:      fmt.Sprintf("pending-tier-%d", i),
							Name:      fmt.Sprintf("pending-name-%d", i),
							Namespace: fmt.Sprintf("pending-ns-%d", i),
							Action:    "allow",
							Kind:      proto.PolicyKind_CalicoNetworkPolicy,
						},
					},
				}

				// Send it to the aggregator.
				agg.Receive(&proto.FlowUpdate{Flow: fl})
			}

			// Query for flows using the query from the testcase.
			var flows []*proto.FlowResult
			if tc.numFlows == 0 {
				Consistently(func() int {
					flows, _ = agg.List(tc.req)
					return len(flows)
				}, 100*time.Millisecond, 10*time.Millisecond).Should(Equal(0))
				return
			} else {
				Eventually(func() bool {
					flows, _ = agg.List(tc.req)
					return len(flows) >= tc.numFlows
				}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive flows").Should(BeTrue())

				Expect(len(flows)).To(Equal(tc.numFlows), "Expected %d flows, got %d", tc.numFlows, len(flows))

				if tc.check != nil {
					for _, fl := range flows {
						Expect(tc.check(fl)).To(BeNil())
					}
				}
			}
		})
	}
}

func TestFilterHints(t *testing.T) {
	type tc struct {
		name    string
		req     *proto.FilterHintsRequest
		numResp int
		check   func([]*proto.FilterHint) error
	}

	tests := []tc{
		{
			name:    "SourceName, no filters",
			req:     &proto.FilterHintsRequest{Type: proto.FilterType_FilterTypeSourceName},
			numResp: 10,
			check: func(hints []*proto.FilterHint) error {
				for i, hint := range hints {
					if hint.Value != fmt.Sprintf("source-%d", i) {
						return fmt.Errorf("Expected SourceName to be source-%d, got %s", i, hint.Value)
					}
				}
				return nil
			},
		},

		{
			name: "SourceName, with SourceName filter",
			req: &proto.FilterHintsRequest{
				Type:   proto.FilterType_FilterTypeSourceName,
				Filter: &proto.Filter{SourceName: "source-1"},
			},
			numResp: 1,
		},

		{
			name: "Tier, no filters",
			req: &proto.FilterHintsRequest{
				Type: proto.FilterType_FilterTypePolicyTier,
			},
			numResp: 10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a clock and rollover controller.
			c := newClock(100)
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
			go agg.Run(c.Now().Unix())

			// Create 10 flows, with a mix of fields to filter on.
			for i := 0; i < 10; i++ {
				// Start with a base flow.
				fl := newRandomFlow(c.Now().Unix() - 1)

				// Configure fields to filter on.
				fl.Key.SourceName = fmt.Sprintf("source-%d", i)
				fl.Key.SourceNamespace = fmt.Sprintf("source-ns-%d", i)
				fl.Key.DestName = fmt.Sprintf("dest-%d", i)
				fl.Key.DestNamespace = fmt.Sprintf("dest-ns-%d", i)
				fl.Key.Proto = "tcp"
				fl.Key.DestPort = int64(i)
				fl.Key.Policies = &proto.PolicyTrace{
					EnforcedPolicies: []*proto.PolicyHit{
						{Tier: fmt.Sprintf("tier-%d", i)},
					},
				}

				// Send it to the aggregator.
				agg.Receive(&proto.FlowUpdate{Flow: fl})
			}

			// Wait for all flows to be received.
			Eventually(func() bool {
				flows, _ := agg.List(&proto.FlowListRequest{})
				return len(flows) == 10
			}, 100*time.Millisecond, 10*time.Millisecond, "Didn't receive all flows").Should(BeTrue())

			// Query for hints using the query from the testcase.
			hints, err := agg.Hints(tc.req)
			require.NoError(t, err)

			// Verify the hints.
			require.Len(t, hints, tc.numResp, "Expected %d hints, got %d: %+v", tc.numResp, len(hints), hints)

			if tc.check != nil {
				require.NoError(t, tc.check(hints), fmt.Sprintf("Hints check failed on hints: %+v", hints))
			}
		})
	}
}

func newRandomFlow(start int64) *proto.Flow {
	srcNames := map[int]string{
		0: "client-aggr-1",
		1: "client-aggr-2",
		2: "client-aggr-3",
		3: "client-aggr-4",
	}
	dstNames := map[int]string{
		0: "server-aggr-1",
		1: "server-aggr-2",
		2: "server-aggr-3",
		3: "server-aggr-4",
	}
	actions := map[int]string{
		0: "allow",
		1: "deny",
	}
	reporters := map[int]string{
		0: "src",
		1: "dst",
	}
	services := map[int]string{
		0: "frontend-service",
		1: "backend-service",
		2: "db-service",
	}
	namespaces := map[int]string{
		0: "test-ns",
		1: "test-ns-2",
		2: "test-ns-3",
	}

	dstNs := randomFromMap(namespaces)
	return &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:           randomFromMap(srcNames),
			SourceNamespace:      randomFromMap(namespaces),
			DestName:             randomFromMap(dstNames),
			DestNamespace:        dstNs,
			Proto:                "tcp",
			Policies:             &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
			Action:               randomFromMap(actions),
			Reporter:             randomFromMap(reporters),
			DestServiceName:      randomFromMap(services),
			DestServicePort:      80,
			DestServiceNamespace: dstNs,
		},
		StartTime:             start,
		EndTime:               start + 1,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
}

func randomFromMap[E comparable](m map[int]E) E {
	// Generate a random number within the size of the map.
	return m[rand.IntN(len(m))]
}
