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

package goldmane_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/internal/utils"
	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/stream"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var (
	waitTimeout = 5 * time.Second
	retryTime   = 25 * time.Millisecond
)

var (
	gm *goldmane.Goldmane
	c  *clock
)

// initialNow is time.Now() at the start of the test. This must be
// large enough that initialNow - numBuckets * aggregationWindowSecs is positive.
const initialNow = 1000

func setupTest(t *testing.T, opts ...goldmane.Option) func() {
	// Register gomega with test.
	RegisterTestingT(t)

	// Hook logrus into testing.T
	utils.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)
	gm = goldmane.NewGoldmane(opts...)
	return func() {
		gm.Stop()
		gm = nil
		c = nil
		logCancel()
	}
}

func ExpectFlowsEqual(t *testing.T, expected, actual *proto.Flow, additionalMsg ...string) {
	if !googleproto.Equal(expected, actual) {
		msg := fmt.Sprintf("\nExpected:\n\t%v\nActual:\n\t%v", expected, actual)
		for _, m := range additionalMsg {
			msg += "\n" + m
		}
		t.Error(msg)
	}
}

func TestList(t *testing.T) {
	c := newClock(initialNow)
	now := c.Now().Unix()
	opts := []goldmane.Option{
		goldmane.WithRolloverTime(1 * time.Second),
		goldmane.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()

	// Start goldmane.
	<-gm.Run(now)

	// Ingest a flow log.
	fl := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Action:          proto.Action_Allow,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns",
						Namespace:   "kube-system",
						Tier:        "test-tier",
						Action:      proto.Action_Allow,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
			},
		},
		StartTime:             now - 15,
		EndTime:               now,
		SourceLabels:          []string{"key=valueSource"},
		DestLabels:            []string{"key=valueDest"},
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	gm.Receive(types.ProtoToFlow(fl))

	// Expect Goldmane to have received it.
	var flows []*proto.FlowResult
	var meta *proto.ListMetadata
	var err error
	Eventually(func() error {
		var results *proto.FlowListResult
		results, err = gm.List(&proto.FlowListRequest{})
		meta, flows = results.Meta, results.Flows
		if len(flows) == 1 {
			return nil
		}
		return fmt.Errorf("expected 1 flow, got %d", len(flows))
	}, waitTimeout, retryTime, "Didn't receive flow").ShouldNot(HaveOccurred())

	Expect(meta.TotalResults).Should(BeEquivalentTo(1))
	Expect(meta.TotalResults).Should(BeEquivalentTo(1))

	// Expect aggregation to have happened.
	exp := proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Action:          proto.Action_Allow,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns",
						Namespace:   "kube-system",
						Tier:        "test-tier",
						Action:      proto.Action_Allow,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
			},
		},
		StartTime:             flows[0].Flow.StartTime,
		EndTime:               flows[0].Flow.EndTime,
		SourceLabels:          []string{"key=valueSource"},
		DestLabels:            []string{"key=valueDest"},
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}

	ExpectFlowsEqual(t, &exp, flows[0].Flow)
	id := flows[0].Id

	// Send another copy of the flow log.
	gm.Receive(types.ProtoToFlow(fl))

	// Expect Goldmane to have received it. Aggregation of new flows
	// happens asynchonously, so we may need to wait a few ms for it.
	Eventually(func() error {
		var results *proto.FlowListResult
		results, err = gm.List(&proto.FlowListRequest{})
		flows = results.Flows
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
	}, waitTimeout, retryTime, "Incorrect flow output").Should(BeNil())

	// Expect aggregation to have happened.
	exp.NumConnectionsStarted = 2
	exp.BytesIn = 200
	exp.BytesOut = 400
	exp.PacketsIn = 20
	exp.PacketsOut = 40
	ExpectFlowsEqual(t, &exp, flows[0].Flow)

	// ID should be unchanged.
	Expect(flows[0].Id).To(Equal(id))

	// Wait for Goldmane to rollover.
	time.Sleep(1001 * time.Millisecond)

	// Send another flow log.
	gm.Receive(types.ProtoToFlow(fl))

	// Expect Goldmane to have received it. This should be added to a new bucket,
	// but aggregated into the same flow on read.
	Eventually(func() error {
		var results *proto.FlowListResult
		results, err = gm.List(&proto.FlowListRequest{})
		flows = results.Flows
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
	}, waitTimeout, retryTime, "Incorrect flow output").Should(BeNil())

	exp2 := proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Action:          proto.Action_Allow,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_NetworkPolicy,
						Name:        "cluster-dns",
						Namespace:   "kube-system",
						Tier:        "test-tier",
						Action:      proto.Action_Allow,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
			},
		},
		StartTime:             flows[0].Flow.StartTime,
		EndTime:               flows[0].Flow.EndTime,
		SourceLabels:          []string{"key=valueSource"},
		DestLabels:            []string{"key=valueDest"},
		BytesIn:               300,
		BytesOut:              600,
		PacketsIn:             30,
		PacketsOut:            60,
		NumConnectionsStarted: 3,
	}
	ExpectFlowsEqual(t, &exp2, flows[0].Flow)

	// ID should be unchanged.
	Expect(flows[0].Id).To(Equal(int64(id)))
}

func TestLabelMerge(t *testing.T) {
	// Create a clock and rollover controller.
	c := newClock(initialNow)
	roller := &rolloverController{
		ch:                    make(chan time.Time),
		aggregationWindowSecs: 1,
		clock:                 c,
	}
	opts := []goldmane.Option{
		goldmane.WithRolloverTime(1 * time.Second),
		goldmane.WithRolloverFunc(roller.After),
		goldmane.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()
	<-gm.Run(c.Now().Unix())

	// Create 10 flows, each with one common label and one unique label.
	// All other fields are the same.
	base := testutils.NewRandomFlow(c.Now().Unix() - 1)
	for i := range 10 {
		fl := googleproto.Clone(base).(*proto.Flow)
		fl.SourceLabels = []string{"common=src", fmt.Sprintf("unique-src=%d", i)}
		fl.DestLabels = []string{"common=dst", fmt.Sprintf("unique-dest=%d", i)}
		gm.Receive(types.ProtoToFlow(fl))
	}

	// Query for the flow, and expect that labels are properly aggregated. We should see
	// the common label, but not the unique labels.
	var flows []*proto.FlowResult
	var err error
	Eventually(func() error {
		var results *proto.FlowListResult
		results, err = gm.List(&proto.FlowListRequest{})
		flows = results.Flows
		if err != nil {
			return err
		}
		if len(flows) != 1 {
			return fmt.Errorf("Expected 1 flow, got %d", len(flows))
		}
		if flows[0].Flow.NumConnectionsCompleted != base.NumConnectionsCompleted*10 {
			return fmt.Errorf("Expected %d connections, got %d", base.NumConnectionsCompleted*10, flows[0].Flow.NumConnectionsCompleted)
		}
		return nil
	}, waitTimeout, retryTime, "Didn't receive flow").ShouldNot(HaveOccurred())

	Expect(flows[0].Flow.SourceLabels).To(ConsistOf("common=src"))
	Expect(flows[0].Flow.DestLabels).To(ConsistOf("common=dst"))
}

// TestRotation tests that Goldmane correctly rotates out old flows.
func TestRotation(t *testing.T) {
	// Create a clock and rollover controller.
	c := newClock(initialNow)
	now := c.Now().Unix()
	roller := &rolloverController{
		ch:                    make(chan time.Time),
		aggregationWindowSecs: 1,
		clock:                 c,
	}
	opts := []goldmane.Option{
		goldmane.WithRolloverTime(1 * time.Second),
		goldmane.WithRolloverFunc(roller.After),
		goldmane.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()
	<-gm.Run(now)

	// Create a Flow. This test relies on an understanding of the underlying bucket ring:
	// - The index contains two extra buckets, one currently filling, and one in the future.
	// - We place this flow one bucket earlier than the currently filling bucket.
	// - As such, the flow should be rotated out after sizeOf(ring) - 2 rollovers.
	fl := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Action:          proto.Action_Allow,
			Policies:        &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
		},
		StartTime:             now - 1,
		EndTime:               now,
		BytesIn:               100,
		BytesOut:              200,
		PacketsIn:             10,
		PacketsOut:            20,
		NumConnectionsStarted: 1,
	}
	gm.Receive(types.ProtoToFlow(fl))

	// We should be able to read it back.
	var flows []*proto.FlowResult
	var err error
	Eventually(func() error {
		var results *proto.FlowListResult
		results, err = gm.List(&proto.FlowListRequest{})
		flows = results.Flows
		if err != nil {
			return err
		}
		if len(flows) != 1 {
			return fmt.Errorf("Expected 1 flow, got %d", len(flows))
		}
		return nil
	}, waitTimeout, retryTime, "Didn't receive flow").ShouldNot(HaveOccurred())

	// ID should is non-deterministic, but should be consistent.
	flowID := flows[0].Id
	Expect(flowID).To(BeNumerically(">", 0))

	// Rollover Goldmane until we push the flow out of the window.
	roller.rolloverAndAdvanceClock(239)

	// The flow should still be here.
	Eventually(func() error {
		var results *proto.FlowListResult
		results, err = gm.List(&proto.FlowListRequest{})
		flows = results.Flows
		if err != nil {
			return err
		}
		if len(flows) != 1 {
			return fmt.Errorf("Expected 1 flow, got %d", len(flows))
		}
		return nil
	}, waitTimeout, retryTime, "Flow rotated out too early").ShouldNot(HaveOccurred())

	// ID should be unchanged.
	Expect(flows[0].Id).To(Equal(flowID))

	// This one should do it.
	roller.rolloverAndAdvanceClock(1)

	// We should no longer be able to read the flow.
	Consistently(func() int {
		var results *proto.FlowListResult
		results, _ = gm.List(&proto.FlowListRequest{})
		flows = results.Flows
		return len(flows)
	}, 1*time.Second, retryTime).Should(Equal(0), "Flow did not rotate out")
}

func TestManyFlows(t *testing.T) {
	c := newClock(initialNow)
	now := c.Now().Unix()
	opts := []goldmane.Option{
		goldmane.WithRolloverTime(1 * time.Second),
		goldmane.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()
	<-gm.Run(now)

	// Create 20k flows and send them as fast as we can. See how Goldmane handles it.
	fl := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "test-src",
			SourceNamespace: "test-ns",
			DestName:        "test-dst",
			DestNamespace:   "test-dst-ns",
			Proto:           "tcp",
			Action:          proto.Action_Allow,
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
	for range 20000 {
		gm.Receive(types.ProtoToFlow(fl))
	}

	// Query for the flow.
	var flows []*proto.FlowResult
	var meta *proto.ListMetadata
	Eventually(func() bool {
		var results *proto.FlowListResult
		results, _ = gm.List(&proto.FlowListRequest{})
		meta = results.Meta
		flows = results.Flows
		if len(flows) != 1 {
			return false
		}
		return flows[0].Flow.NumConnectionsStarted == 20000
	}, waitTimeout, retryTime, "Didn't reach 20k flows: %d", len(flows)).Should(BeTrue())
	Expect(meta.TotalPages).To(BeEquivalentTo(1))
	Expect(meta.TotalResults).To(BeEquivalentTo(1))
}

func TestPagination(t *testing.T) {
	c := newClock(initialNow)
	now := c.Now().Unix()
	opts := []goldmane.Option{
		goldmane.WithRolloverTime(1 * time.Second),
		goldmane.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()
	<-gm.Run(now)

	// Create 30 different flows.
	for i := range 30 {
		fl := &proto.Flow{
			Key: &proto.FlowKey{
				SourceName:      "test-src",
				SourceNamespace: "test-ns",

				// Each flow is to a unique destination, thus making the flow unique.
				DestName:      fmt.Sprintf("test-dst-%d", i),
				DestNamespace: "test-dst-ns",
				Proto:         "tcp",
				Action:        proto.Action_Allow,
				Policies:      &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
			},

			// Give each flow a unique time stamp, for deterministic ordering.
			StartTime:             now - int64(i) - 1,
			EndTime:               now - int64(i),
			BytesIn:               100,
			BytesOut:              200,
			PacketsIn:             10,
			PacketsOut:            20,
			NumConnectionsStarted: 1,
		}
		gm.Receive(types.ProtoToFlow(fl))
	}

	// Query without pagination.
	var flows []*proto.FlowResult
	var err error
	Eventually(func() error {
		var results *proto.FlowListResult
		results, err = gm.List(&proto.FlowListRequest{})
		_, flows = results.Meta, results.Flows
		if err != nil {
			return err
		}
		if len(flows) != 30 {
			return fmt.Errorf("Expected 30 flows, got %d", len(flows))
		}
		return nil
	}, waitTimeout, retryTime, "Didn't receive all flows").ShouldNot(HaveOccurred())

	// Query with a page size of 5, encompassing the entire time range.
	results, err := gm.List(&proto.FlowListRequest{
		PageSize:     5,
		StartTimeGte: now - 30,
		StartTimeLt:  now + 1,
	})
	page0 := results.Flows
	require.NoError(t, err)
	require.Len(t, page0, 5, "Page 0 should have 5 flows")
	require.Equal(t, int64(now-1), page0[0].Flow.StartTime)
	require.Equal(t, int64(now-5), page0[4].Flow.StartTime)
	require.NotEqual(t, page0[0].Id, page0[4].Id, "should have unique flow IDs")

	// Query the third page - should be a different 5 flows (skipping page 2).
	results, err = gm.List(&proto.FlowListRequest{
		PageSize:     5,
		Page:         2,
		StartTimeGte: now - 30,
		StartTimeLt:  now + 1,
	})
	meta := results.Meta
	page2 := results.Flows
	require.NoError(t, err)
	require.Len(t, page2, 5, "Page 2 should have 5 flows")
	require.Equal(t, int64(989), page2[0].Flow.StartTime)
	require.Equal(t, int64(985), page2[4].Flow.StartTime)
	require.Equal(t, int64(6), meta.TotalPages, "Should have 6 pages")
	require.Equal(t, int64(30), meta.TotalResults, "Should have 30 results")

	// We can't assert on the actual values of the ID, but they should be
	// unique and incrementing.
	require.Equal(t, page2[0].Id+4, page2[4].Id)

	// Pages should not be equal.
	require.NotEqual(t, page0, page2, "Page 0 and 2 should not be equal")

	// Query the third page again. It should be consistent (since no new data).
	results, err = gm.List(&proto.FlowListRequest{
		PageSize:     5,
		Page:         2,
		StartTimeGte: now - 30,
		StartTimeLt:  now + 1,
	})
	page2Again := results.Flows
	require.NoError(t, err)
	require.Equal(t, page2, page2Again, "Page 2 and 2 should be equal on second query")
}

func TestTimeRanges(t *testing.T) {
	c := newClock(initialNow)
	now := c.Now().Unix()
	opts := []goldmane.Option{
		goldmane.WithRolloverTime(1 * time.Second),
		goldmane.WithNowFunc(c.Now),
	}
	prepareFlows := func() {
		// Create a flow spread across a range of buckets within goldmane.
		// 60 buckes of 1s each means we want one flow per second for 60s.
		for i := range 60 {
			startTime := now - int64(i) + 1
			endTime := startTime + 1
			fl := &proto.Flow{
				// Start one rollover period into the future, since that is how Goldmane works.
				Key: &proto.FlowKey{
					SourceName:      "test-src",
					SourceNamespace: "test-ns",
					DestName:        "test-dst",
					DestNamespace:   "test-dst-ns",
					Proto:           "tcp",
					Action:          proto.Action_Allow,
					Policies:        &proto.PolicyTrace{EnforcedPolicies: []*proto.PolicyHit{}},
				},
				StartTime:             startTime,
				EndTime:               endTime,
				BytesIn:               100,
				BytesOut:              200,
				PacketsIn:             10,
				PacketsOut:            20,
				NumConnectionsStarted: 1,
			}
			gm.Receive(types.ProtoToFlow(fl))
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
			// This should return up until "now", which doesn't include flows currently being aggregated.
			// i.e., it will exclude flows in the current and future buckets.
			name:                          "All flows",
			query:                         &proto.FlowListRequest{},
			expectedNumConnectionsStarted: 58,
		},
		{
			// This sets the time range explicitly, to include flows currently being aggregated and flows that
			// are seen as from the "future" by goldmane.
			name:                          "All flows, including current + future",
			query:                         &proto.FlowListRequest{StartTimeLt: now + 2},
			expectedNumConnectionsStarted: 60,
		},
		{
			name:                          "10s of flows",
			query:                         &proto.FlowListRequest{StartTimeGte: now - 10, StartTimeLt: now},
			expectedNumConnectionsStarted: 10,
		},
		{
			name:  "10s of flows, starting in the future",
			query: &proto.FlowListRequest{StartTimeGte: now + 10, StartTimeLt: now + 20},
			// Should return no flows, since the query is in the future.
			expectNoMatch: true,
		},
		{
			name:                          "5s of flows",
			query:                         &proto.FlowListRequest{StartTimeGte: now - 12, StartTimeLt: now - 7},
			expectedNumConnectionsStarted: 5,
		},
		{
			name:  "end time before start time",
			query: &proto.FlowListRequest{StartTimeGte: now - 7, StartTimeLt: now - 12},
			// Should return no flows, since the query covers 0s.
			expectNoMatch: true,
			expectErr:     true,
		},
		{
			name:                          "relative time range, last 10s",
			query:                         &proto.FlowListRequest{StartTimeGte: -10},
			expectedNumConnectionsStarted: 10,
		},
		{
			name:                          "relative time range, 15s window",
			query:                         &proto.FlowListRequest{StartTimeGte: -20, StartTimeLt: -5},
			expectedNumConnectionsStarted: 15,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer setupTest(t, opts...)()
			<-gm.Run(now)

			// Create flows.
			prepareFlows()

			// Run the query, and check how many flows we get back.
			var flows []*proto.FlowResult

			if !test.expectNoMatch {
				// Should return one aggregated flow that sums the component flows.
				Eventually(func() bool {
					var results *proto.FlowListResult
					results, _ = gm.List(test.query)
					flows = results.Flows
					return len(flows) == 1
				}, waitTimeout, retryTime, "Didn't receive flow").Should(BeTrue())

				Eventually(func() bool {
					var results *proto.FlowListResult
					results, _ = gm.List(test.query)
					flows = results.Flows
					return flows[0].Flow.NumConnectionsStarted == int64(test.expectedNumConnectionsStarted)
				}, waitTimeout, retryTime).Should(
					BeTrue(),
					fmt.Sprintf("Expected %d to equal %d", flows[0].Flow.NumConnectionsStarted, test.expectedNumConnectionsStarted),
				)

				// Verify other fields are aggregated correctly.
				exp := proto.Flow{
					Key: &proto.FlowKey{
						SourceName:      "test-src",
						SourceNamespace: "test-ns",
						DestName:        "test-dst",
						DestNamespace:   "test-dst-ns",
						Proto:           "tcp",
						Action:          proto.Action_Allow,
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
				for range 10 {
					results, err := gm.List(test.query)
					if test.expectErr {
						require.Error(t, err)
						require.Nil(t, results)
					} else {
						require.NoError(t, err)
						require.Len(t, results.Flows, 0)
					}

					time.Sleep(10 * time.Millisecond)
				}
			}
		})
	}
}

func TestSink(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		c := newClock(initialNow)
		now := c.Now().Unix()

		// Configure Goldmane with a test sink.
		sink := newTestSink()
		roller := &rolloverController{
			ch:                    make(chan time.Time),
			aggregationWindowSecs: 1,
			clock:                 c,
		}
		pushIndex := 10
		bucketsToCombine := 20
		opts := []goldmane.Option{
			goldmane.WithRolloverTime(1 * time.Second),
			goldmane.WithRolloverFunc(roller.After),
			goldmane.WithNowFunc(c.Now),
			goldmane.WithBucketsToCombine(bucketsToCombine),
			goldmane.WithPushIndex(pushIndex),
		}
		defer setupTest(t, opts...)()

		// Start Goldmane, and rollover to trigger an emission.
		// We shouldn't see any buckets pushed to the sink, as we haven't sent any flows.
		<-gm.Run(now)

		// Set the sink. Setting the Sink is asynchronous and triggers a check for flow emission - as such,
		// we need to wait for this to complete before we can start sending flows.
		Eventually(gm.SetSink(sink), waitTimeout, retryTime).Should(BeClosed())

		roller.rolloverAndAdvanceClock(1)
		require.Equal(t, 0, sink.len())

		// Write some data into Goldmane in a way that will trigger an emission on the next rollover.
		// Write a flow that will trigger an emission, since it's within the push index.
		fl := testutils.NewRandomFlow(now - int64(pushIndex))
		gm.Receive(types.ProtoToFlow(fl))

		// Wait for the flow to be received.
		Eventually(func() error {
			results, err := gm.List(&proto.FlowListRequest{})
			if err != nil {
				return nil
			}
			if len(results.Flows) < 1 {
				return fmt.Errorf("Expected a flow, got none")
			}
			return nil
		}, waitTimeout, retryTime).ShouldNot(HaveOccurred(), "Didn't receive flow")

		// Rollover to trigger the emission. This will mark all buckets from -50 to -30 as emitted.
		roller.rolloverAndAdvanceClock(1)
		Eventually(func() int {
			return sink.len()
		}, waitTimeout, retryTime).Should(Equal(1), "Expected 1 bucket to be pushed to the sink")
		require.Len(t, sink.bucket(0).Flows, 1, "Expected 1 flow in the bucket")
		sink.reset()

		// We've rolled over once. The next emission should happen after
		// bucktsToCombine more rollovers, which is the point at which the first bucket
		// not included in the previous emission will become eligible.
		nextEmission := bucketsToCombine

		// Place 5 new flow logs in the first 5 buckets of the ring.
		flowStart := roller.now() + 1 - 4
		flowEnd := roller.now() + 2
		for i := range 5 {
			fl := &proto.Flow{
				Key: &proto.FlowKey{
					SourceName:      "test-src",
					SourceNamespace: "test-ns",
					DestName:        "test-dst",
					DestNamespace:   "test-dst-ns",
					Proto:           "tcp",
					Action:          proto.Action_Allow,
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
			gm.Receive(types.ProtoToFlow(fl))
		}

		// Wait for all flows to be received.
		time.Sleep(10 * time.Millisecond)

		// Rollover until we trigger the next emission. The flows we added above
		// won't appear in this emission, since they are in the first 5 buckets which
		// haven't reached the emission window yet.
		roller.rolloverAndAdvanceClock(nextEmission - 1)
		require.Equal(t, sink.len(), 0)

		// Rollover until we trigger the next emission. This time, the flows we added above will be present.
		roller.rolloverAndAdvanceClock(1)
		Eventually(func() int {
			return sink.len()
		}, waitTimeout, retryTime).Should(Equal(1), "Expected 1 bucket to be pushed to the sink")

		// We expect the collection to have been aggregated across 20 intervals, for a total of 20 seconds.
		require.Equal(t, int64(1012), sink.bucket(0).EndTime)
		require.Equal(t, int64(992), sink.bucket(0).StartTime)
		require.Equal(t, int64(20), sink.bucket(0).EndTime-sink.bucket(0).StartTime)

		// Expect the bucket to have aggregated to a single flow, since all flows are identical.
		require.Len(t, sink.bucket(0).Flows, 1)

		// Statistics should be aggregated correctly.
		exp := proto.Flow{
			Key: &proto.FlowKey{
				SourceName:      "test-src",
				SourceNamespace: "test-ns",
				DestName:        "test-dst",
				DestNamespace:   "test-dst-ns",
				Proto:           "tcp",
				Action:          proto.Action_Allow,
			},
			StartTime:             flowStart,
			EndTime:               flowEnd,
			BytesIn:               500,
			BytesOut:              1000,
			PacketsIn:             50,
			PacketsOut:            100,
			NumConnectionsStarted: 5,
		}
		flow := sink.bucket(0).Flows[0]
		require.NotNil(t, flow)
		require.Equal(t, *types.ProtoToFlow(&exp), flow)
	})

	// This test verifies that Goldmane handles publishing multiple buckets of Flows if there are
	// multiple buckets worth of flows that haven't been published yet.
	t.Run("PushMultiple", func(t *testing.T) {
		c := newClock(initialNow)
		now := c.Now().Unix()

		// Configure Goldmane with a test sink.
		sink := newTestSink()
		roller := &rolloverController{
			ch:                    make(chan time.Time),
			aggregationWindowSecs: 1,
			clock:                 c,
		}
		pushIndex := 10
		bucketsToCombine := 20
		opts := []goldmane.Option{
			goldmane.WithRolloverTime(1 * time.Second),
			goldmane.WithRolloverFunc(roller.After),
			goldmane.WithNowFunc(c.Now),
			goldmane.WithBucketsToCombine(bucketsToCombine),
			goldmane.WithPushIndex(pushIndex),
		}
		defer setupTest(t, opts...)()

		// Start Goldmane, and rollover to trigger an emission.
		// We shouldn't see any buckets pushed to the sink, as we haven't sent any flows.
		<-gm.Run(now)

		// Set the sink. Setting the Sink is asynchronous and triggers a check for flow emission - as such,
		// we need to wait for this to complete before we can start sending flows.
		Eventually(gm.SetSink(sink), waitTimeout, retryTime).Should(BeClosed())

		// Load up Goldmane with Flow data across a widge range of buckets, spanning
		// multiple emission windows.
		for i := range 100 {
			fl := testutils.NewRandomFlow(now - int64(pushIndex) - int64(i))
			gm.Receive(types.ProtoToFlow(fl))
		}

		// Wait for the flows to be received.
		Eventually(func() error {
			results, err := gm.List(&proto.FlowListRequest{})
			if err != nil {
				logrus.Infof("Got %d flows", len(results.Flows))
				return nil
			}
			if len(results.Flows) < 80 {
				logrus.Infof("Got %d flows", len(results.Flows))
				return fmt.Errorf("Expected 80 flows, got %d", len(results.Flows))
			}
			return nil
		}, waitTimeout, retryTime).ShouldNot(HaveOccurred())

		// Rollover, which should trigger an emission. Since we're combining 20 buckets, and we're filling 100,
		// we expect to see 5 emissions.
		roller.rolloverAndAdvanceClock(1)
		Eventually(func() int {
			return sink.len()
		}, waitTimeout, retryTime).Should(Equal(5), "Expected 5 buckets to be pushed to the sink")

		// We shouldn't see any more emissions.
		for range 400 {
			roller.rolloverAndAdvanceClock(1)
			require.Equal(t, 5, sink.len(), "Unexpected bucket pushed to sink")
		}
	})

	// This test verifies that Goldmane handles publishing multiple buckets of Flows if there is no
	// sink configured, but a sink is added later.
	t.Run("AddSink", func(t *testing.T) {
		c := newClock(initialNow)
		now := c.Now().Unix()

		// Configure Goldmane with a test sink.
		sink := newTestSink()
		roller := &rolloverController{
			ch:                    make(chan time.Time),
			aggregationWindowSecs: 1,
			clock:                 c,
		}
		pushIndex := 10
		bucketsToCombine := 20
		opts := []goldmane.Option{
			goldmane.WithRolloverTime(1 * time.Second),
			goldmane.WithRolloverFunc(roller.After),
			goldmane.WithNowFunc(c.Now),
			goldmane.WithBucketsToCombine(bucketsToCombine),
			goldmane.WithPushIndex(pushIndex),
		}
		defer setupTest(t, opts...)()

		// Start Goldmane, and rollover to trigger an emission.
		// We shouldn't see any buckets pushed to the sink, as we haven't sent any flows.
		<-gm.Run(now)

		// Load up Goldmane with Flow data across a widge range of buckets, spanning
		// multiple emission windows.
		for i := range 100 {
			fl := testutils.NewRandomFlow(now - int64(pushIndex) - int64(i))
			gm.Receive(types.ProtoToFlow(fl))
		}

		// Wait for the flows to be received.
		Eventually(func() error {
			results, err := gm.List(&proto.FlowListRequest{})
			if err != nil {
				return nil
			}
			if len(results.Flows) < 80 {
				return fmt.Errorf("Expected 80 flows, got %d", len(results.Flows))
			}
			return nil
		}, waitTimeout, retryTime).ShouldNot(HaveOccurred())

		// Rollover. Since we haven't provided a Sink, we shouldn't see any emissions.
		roller.rolloverAndAdvanceClock(1)
		Consistently(func() int {
			return sink.len()
		}, 1*time.Second, retryTime).Should(Equal(0), "Unexpected bucket pushed to sink")

		// Set the sink. Setting the Sink is asynchronous and triggers a check for flow emission - as such,
		// we need to wait for this to complete before we can start sending flows.
		Eventually(gm.SetSink(sink), waitTimeout, retryTime).Should(BeClosed())

		// We should see the emissions now.
		Eventually(func() int {
			return sink.len()
		}, waitTimeout, retryTime).Should(Equal(5), "Expected 5 buckets to be pushed to the sink")
	})
}

// TestBucketDrift makes sure that Goldmane is able to account for its internal array of
// aggregation buckets slowly drifting with respect to time.Now(). This can happen due to the time taken to process
// other operations on the shared main goroutine, and is accounted for by adjusting the the next rollover time.
func TestBucketDrift(t *testing.T) {
	// Create a clock and rollover controller.
	c := newClock(initialNow)
	aggregationWindowSecs := 10
	roller := &rolloverController{
		ch:                    make(chan time.Time),
		aggregationWindowSecs: int64(aggregationWindowSecs),
		clock:                 c,
	}

	// Track the scheduled rollover time. We need a mutex to prevent data races, as
	// this is being accessed from multiple goroutines.
	mu := sync.Mutex{}
	var rolloverScheduledAt time.Duration
	rolloverFunc := func(d time.Duration) <-chan time.Time {
		mu.Lock()
		defer mu.Unlock()
		rolloverScheduledAt = d
		return roller.After(d)
	}
	getScheduledAt := func() time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return rolloverScheduledAt
	}
	opts := []goldmane.Option{
		goldmane.WithRolloverTime(time.Duration(aggregationWindowSecs) * time.Second),
		goldmane.WithRolloverFunc(rolloverFunc),
		goldmane.WithNowFunc(c.Now),
	}
	defer setupTest(t, opts...)()

	// This can get a bit confusing, so let's walk through it:
	//
	// - Goldmane maintains an internal array of buckets. The most recent bucket actually starts one aggregation window in the future, to handle clock skew between nodes.
	// - For this test, we want to simulate a rollover that happens slightly late.
	// - Now() is mocked to 1000, With an aggregation window of 10s. So buckets[head] will cover 1010-1020, bucket[head-1] will cover 1000-1010.
	// - Normally, a rollover would occur at 1010, adding a new bucket[head] covering 1020-1030.
	// - For this test, we'll simulate a rollover at 1013, which is 3 seconds late.
	//
	// From there, we can expect Goldmane to notice that it has missed time somehow and accelerate the scheduling of the next rollover
	// in order to compensate.
	<-gm.Run(c.Now().Unix())

	// We want to simulate a rollover that happens 3 seconds late for the scheduled rollover.
	rt := int64(initialNow + aggregationWindowSecs + 3)
	c.Set(time.Unix(rt, 0))
	roller.rollover()

	// Assert that the rollover function was called with an expedited reschedule time of 7 seconds, compared to the
	// expected rollover interval of 10 seconds.
	require.Equal(t, 7, int(getScheduledAt().Seconds()), "Expedited rollover should have been scheduled at 7s")

	// Advance the clock to the expected time of the next rollover.
	nextRollover := int64(initialNow + 2*aggregationWindowSecs)
	c.Set(time.Unix(nextRollover, 0))

	// Trigger another rollover. This time, Goldmane should have caught up, so the rollover should be scheduled
	// at the expected time of one aggregation window in the future (10s).
	roller.rollover()

	require.Equal(t, aggregationWindowSecs, int(getScheduledAt().Seconds()), "Expected rollover to be scheduled at 10s")

	// Now let's try the other dirction - simulate a rollover that happens 4 seconds early.
	// We expect the next rollover to occur at 1030, so trigger one at 1026.
	earlyRt := int64(initialNow + 3*aggregationWindowSecs - 4)
	c.Set(time.Unix(earlyRt, 0))
	roller.rollover()

	// Goldmane should notice that it's ahead of schedule and delay the next rollover by 4 seconds.
	require.Equal(t, 14, int(getScheduledAt().Seconds()), "Delayed rollover should have been scheduled at 14s")

	// And check what happens if we're so far behind that the next bucket is already in the past.
	// The next bucket should start at 1040, so trigger a rollover at 1055.
	// This should trigger an immediate rollover.
	lateRt := int64(initialNow + 5*aggregationWindowSecs + 5)
	c.Set(time.Unix(lateRt, 0))
	roller.rollover()
	require.Equal(t, 10*time.Millisecond, getScheduledAt(), "Immediate rollover should have been scheduled for 10ms")
}

func TestStreams(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		// Create a clock and rollover controller.
		c := newClock(initialNow)
		roller := &rolloverController{
			ch:                    make(chan time.Time),
			aggregationWindowSecs: 1,
			clock:                 c,
		}
		opts := []goldmane.Option{
			goldmane.WithRolloverTime(1 * time.Second),
			goldmane.WithRolloverFunc(roller.After),
			goldmane.WithNowFunc(c.Now),
		}
		defer setupTest(t, opts...)()

		// Start goldmane.
		<-gm.Run(c.Now().Unix())

		// Insert some random historical flow data from the past over the
		// time range of now-10 to now-5.
		for i := 5; i < 10; i++ {
			fl := testutils.NewRandomFlow(c.Now().Unix() - int64(i))
			gm.Receive(types.ProtoToFlow(fl))
		}

		// Expect the flows to have been received.
		Eventually(func() error {
			results, err := gm.List(&proto.FlowListRequest{})
			if err != nil {
				return err
			}
			if len(results.Flows) != 5 {
				return fmt.Errorf("Expected 5 flows, got %d", len(results.Flows))
			}
			return nil
		}, waitTimeout, retryTime).Should(BeNil())

		// Create two streams. The first will be be configured to start streaming from
		// the present, and the second will be configured to start streaming from the past.
		stream, err := gm.Stream(&proto.FlowStreamRequest{StartTimeGte: -1})
		require.Nil(t, err)
		require.NotNil(t, stream)
		defer stream.Close()

		// stream2 will start streaming from the past, and should receive some historical flows.
		// we'll start it from now-7, so it should receive the flows from now-7 to now-5.
		stream2, err := gm.Stream(&proto.FlowStreamRequest{StartTimeGte: c.Now().Unix() - 7})
		require.Nil(t, err)
		require.NotNil(t, stream2)
		defer stream2.Close()

		// Expect nothing on the first stream, since it's starting from the present.
		Consistently(stream.Flows(), 1*time.Second, retryTime).ShouldNot(Receive())

		// Expect three historical flows on the second stream: now-5, now-6, now-7.
		// We should receive them in time order, and should NOT receive now-8 or now-9.
		for i := 7; i >= 5; i-- {
			var builder *storage.DeferredFlowBuilder
			flow := &proto.FlowResult{Flow: &proto.Flow{}}
			Eventually(stream2.Flows(), waitTimeout, retryTime).Should(Receive(&builder), fmt.Sprintf("Expected flow %d", i))
			require.True(t, builder.BuildInto(&proto.Filter{}, flow), "Failed to build flow")
			Expect(flow.Flow.StartTime).To(Equal(c.Now().Unix() - int64(i)))
		}

		// We shouldn't receive any more flows.
		Consistently(stream2.Flows(), 1*time.Second, retryTime).ShouldNot(Receive(), "Expected no more flows")

		// Ingest some new flow data.
		fl := testutils.NewRandomFlow(c.Now().Unix() - 1)
		gm.Receive(types.ProtoToFlow(fl))

		// Expect the flow to have been received for a total of 6 flows in goldmane.
		Eventually(func() error {
			results, err := gm.List(&proto.FlowListRequest{})
			if err != nil {
				return err
			}
			if len(results.Flows) != 6 {
				return fmt.Errorf("Expected 6 flows, got %d", len(results.Flows))
			}
			return nil
		}, waitTimeout, retryTime).Should(BeNil())

		// Trigger a rollover, which should cause the flow to be emitted to the stream.
		roller.rolloverAndAdvanceClock(1)

		// Expect the flow to have been received on both streams.
		b1 := &storage.DeferredFlowBuilder{}
		b2 := &storage.DeferredFlowBuilder{}
		flow := &proto.FlowResult{Flow: &proto.Flow{}}
		flow2 := &proto.FlowResult{Flow: &proto.Flow{}}
		Eventually(stream.Flows(), waitTimeout, retryTime).Should(Receive(&b1))
		Eventually(stream2.Flows(), waitTimeout, retryTime).Should(Receive(&b2))

		b1.BuildInto(&proto.Filter{}, flow)
		b2.BuildInto(&proto.Filter{}, flow2)
		ExpectFlowsEqual(t, fl, flow.Flow)
		ExpectFlowsEqual(t, fl, flow2.Flow)

		// Expect no other flows.
		Consistently(stream.Flows(), 1*time.Second, retryTime).ShouldNot(Receive())
		Consistently(stream2.Flows(), 1*time.Second, retryTime).ShouldNot(Receive())
	})

	// This tests that the stream endpoint produces the correct results when a stream is started
	// and the same FlowKey falls across multiple time buckets.
	//
	// We expect the stream to return an update for each bucket.
	t.Run("SameFlowOverTime", func(t *testing.T) {
		// Create a clock and rollover controller.
		c := newClock(initialNow)
		roller := &rolloverController{
			ch:                    make(chan time.Time),
			aggregationWindowSecs: 1,
			clock:                 c,
		}
		opts := []goldmane.Option{
			goldmane.WithRolloverTime(1 * time.Second),
			goldmane.WithRolloverFunc(roller.After),
			goldmane.WithNowFunc(c.Now),
		}
		defer setupTest(t, opts...)()

		// Start goldmane.
		<-gm.Run(c.Now().Unix())

		// Create a flow that will span multiple time buckets.
		newestStart := c.Now().Unix() - 2
		base := testutils.NewRandomFlow(newestStart)
		base.NumConnectionsCompleted = 1

		var startTimes []int64
		for i := 0; i < 20; i += 2 {
			// Create a copy of the base flow and send it back in time.
			fl := googleproto.Clone(base).(*proto.Flow)
			fl.StartTime = base.StartTime - int64(i)
			fl.EndTime = base.EndTime - int64(i)
			startTimes = append(startTimes, fl.StartTime)
			gm.Receive(types.ProtoToFlow(fl))
		}

		// Expect all 10 flows to have been received.
		Eventually(func() error {
			results, err := gm.List(&proto.FlowListRequest{})
			if err != nil {
				return err
			}
			flows := results.Flows
			if len(flows) != 1 {
				return fmt.Errorf("Expected 1 flows, got %d", len(flows))
			}
			if flows[0].Flow.NumConnectionsCompleted != 10 {
				return fmt.Errorf("Expected 10 connections, got %d", flows[0].Flow.NumConnectionsCompleted)
			}
			return nil
		}, waitTimeout, retryTime).Should(BeNil())

		// Create a stream that starts from the past. The flow goes back 22 seconds,
		// so start the stream from 30 seconds ago.
		stream, err := gm.Stream(&proto.FlowStreamRequest{StartTimeGte: c.Now().Unix() - 30})
		require.Nil(t, err)
		require.NotNil(t, stream)
		defer stream.Close()

		// Verify the Flows. The only difference between them should be the StartTime and EndTime.
		exp := googleproto.Clone(base).(*proto.Flow)

		// Expect to receive 10 updates, one for each bucket.
		result := &proto.FlowResult{Flow: &proto.Flow{}}
		for i := range 10 {
			builder := &storage.DeferredFlowBuilder{}
			Eventually(stream.Flows(), waitTimeout, retryTime).Should(Receive(&builder), fmt.Sprintf("Timed out waiting for flow %d", i))
			require.True(t, builder.BuildInto(&proto.Filter{}, result))

			require.NotEqual(t, 0, result.Flow.StartTime, "Expected non-zero StartTime")
			require.NotEqual(t, 0, result.Flow.EndTime, "Expected non-zero EndTime")

			// Assert the start / end times are correct. They should match the start times we used to create the flows, in reverse order.
			exp.StartTime = startTimes[len(startTimes)-1-i]
			exp.EndTime = exp.StartTime + 1
			ExpectFlowsEqual(t, exp, result.Flow, fmt.Sprintf("Flow %d", i))
		}
	})

	// This test verifies the behavior of stream backfill, by ensuring that the correct flows are emitted.
	// It then performs a rollover, and verifies that no duplicates are emitted.
	t.Run("Backfill and rollover", func(t *testing.T) {
		// Create a clock and rollover controller.
		c := newClock(initialNow)
		roller := &rolloverController{
			ch:                    make(chan time.Time),
			aggregationWindowSecs: 1,
			clock:                 c,
		}
		opts := []goldmane.Option{
			goldmane.WithRolloverTime(1 * time.Second),
			goldmane.WithRolloverFunc(roller.After),
			goldmane.WithNowFunc(c.Now),
		}
		defer setupTest(t, opts...)()

		// Start Goldmane.
		<-gm.Run(c.Now().Unix())

		// Create a flow that will span multiple time buckets, with the
		// newest start time falling at Now().
		newestStart := c.Now().Unix()
		base := testutils.NewRandomFlow(newestStart)
		base.NumConnectionsCompleted = 1

		// Fill the last 10 buckets with flows.
		var startTimes []int64
		for i := 0; i < 10; i += 1 {
			// Create a copy of the base flow and send it back in time.
			fl := googleproto.Clone(base).(*proto.Flow)
			fl.StartTime = base.StartTime - int64(i)
			fl.EndTime = base.EndTime - int64(i)
			startTimes = append(startTimes, fl.StartTime)
			gm.Receive(types.ProtoToFlow(fl))
		}

		// Wait for flows to be received.
		Eventually(func() error {
			results, err := gm.List(&proto.FlowListRequest{})
			if err != nil {
				return err
			}
			if len(results.Flows) != 1 {
				return fmt.Errorf("Expected 1 flows, got %d", len(results.Flows))
			}
			return nil
		}, waitTimeout, retryTime).Should(BeNil())

		// Start a stream from the past, using the start time of the oldest flow.
		stream, err := gm.Stream(&proto.FlowStreamRequest{StartTimeGte: startTimes[len(startTimes)-1]})
		require.Nil(t, err)
		require.NotNil(t, stream)
		defer stream.Close()

		streamed := newEnforcedFlowSet()

		// Verify the flows - we should receive updates for each bucket from the start time until now-2, since
		// the now-1 bucket is not yet rolled over.
		for i := range 8 {
			builder := &storage.DeferredFlowBuilder{}
			result := &proto.FlowResult{Flow: &proto.Flow{}}
			Eventually(stream.Flows(), waitTimeout, retryTime).Should(Receive(&builder), fmt.Sprintf("Timed out waiting for flow %d", i))
			require.True(t, builder.BuildInto(&proto.Filter{}, result))

			// Assert the start / end times are correct. They should match the start times we used to create the flows, in reverse order.
			exp := googleproto.Clone(base).(*proto.Flow)
			exp.StartTime = startTimes[len(startTimes)-1-i]
			exp.EndTime = exp.StartTime + 1
			ExpectFlowsEqual(t, exp, result.Flow, fmt.Sprintf("Flow %d", i))

			// Track the flows we've seen, to ensure we don't get duplicates.
			require.Nil(t, streamed.add(result))
		}

		// Trigger a rollover. We should get another flow, and it should not be a duplicate.
		roller.rolloverAndAdvanceClock(1)
		builder := &storage.DeferredFlowBuilder{}
		result := &proto.FlowResult{Flow: &proto.Flow{}}
		Eventually(stream.Flows(), waitTimeout, retryTime).Should(Receive(&builder))
		require.True(t, builder.BuildInto(&proto.Filter{}, result))
		require.Nil(t, streamed.add(result))
	})

	t.Run("Stream cancellation", func(t *testing.T) {
		// Create a clock and rollover controller.
		c := newClock(initialNow)
		roller := &rolloverController{
			ch:                    make(chan time.Time),
			aggregationWindowSecs: 1,
			clock:                 c,
		}
		opts := []goldmane.Option{
			goldmane.WithRolloverTime(1 * time.Second),
			goldmane.WithRolloverFunc(roller.After),
			goldmane.WithNowFunc(c.Now),
		}
		defer setupTest(t, opts...)()

		// Start Goldmane.
		<-gm.Run(c.Now().Unix())

		// Create many flows, tracking how many unique flows we create.
		keys := make(map[types.FlowKey]struct{})
		for range 5000 {
			// Ingest some new flow data.
			fl := testutils.NewRandomFlow(c.Now().Unix() - 5)
			keys[*types.ProtoToFlowKey(fl.Key)] = struct{}{}
			gm.Receive(types.ProtoToFlow(fl))
		}

		// Wait for flows to be received. Depending on test environment speed, this may take a little while.
		// We just want to ensure that the flows are present before we start streaming. If we don't, then
		// we may miss them when we start the stream.
		Eventually(func() error {
			results, err := gm.List(&proto.FlowListRequest{})
			if err != nil {
				return err
			}
			if len(results.Flows) < len(keys) {
				return fmt.Errorf("Expected at least %d flows, got %d", len(keys), len(results.Flows))
			}
			return nil
		}, 3*waitTimeout, retryTime).Should(BeNil(), "Goldmane took too long to receive flows")

		// Start a stream, and cancel it immediately after receiving the first flow in order to
		// "catch it in the act" of iterating flows.
		for range 10 {
			stream, err := gm.Stream(&proto.FlowStreamRequest{StartTimeGte: c.Now().Unix() - 6})
			require.Nil(t, err)
			require.NotNil(t, stream)
			defer stream.Close()

			builder := &storage.DeferredFlowBuilder{}
			Eventually(stream.Flows(), waitTimeout, retryTime).Should(Receive(&builder))

			stream.Close()
		}
	})

	t.Run("Concurrent streams", func(t *testing.T) {
		// Create a clock and rollover controller.
		c := newClock(initialNow)
		roller := &rolloverController{
			ch:                    make(chan time.Time),
			aggregationWindowSecs: 1,
			clock:                 c,
		}
		opts := []goldmane.Option{
			goldmane.WithRolloverTime(1 * time.Second),
			goldmane.WithRolloverFunc(roller.After),
			goldmane.WithNowFunc(c.Now),
		}
		defer setupTest(t, opts...)()

		// Start Goldmane.
		<-gm.Run(c.Now().Unix())

		// Create many flows.
		keys := make(map[types.FlowKey]struct{})
		for range 5000 {
			// Ingest some new flow data.
			fl := testutils.NewRandomFlow(c.Now().Unix() - 5)
			keys[*types.ProtoToFlowKey(fl.Key)] = struct{}{}
			gm.Receive(types.ProtoToFlow(fl))
		}

		// Wait for flows to be received. Depending on test environment speed, this may take a little while.
		// We just want to ensure that the flows are present before we start streaming. If we don't, then
		// we may miss them when we start the stream.
		Eventually(func() error {
			results, err := gm.List(&proto.FlowListRequest{})
			if err != nil {
				return err
			}
			if len(results.Flows) < len(keys) {
				return fmt.Errorf("Expected at least %d flows, got %d", len(keys), len(results.Flows))
			}
			return nil
		}, 3*waitTimeout, retryTime).Should(BeNil(), "Goldmane took too long to receive flows")

		// Start 10 concurrent streams that will act at the same time.
		var streams []stream.Stream
		for range 10 {
			stream, err := gm.Stream(&proto.FlowStreamRequest{StartTimeGte: c.Now().Unix() - 6})
			require.Nil(t, err)
			require.NotNil(t, stream)
			defer stream.Close()
			streams = append(streams, stream)
		}

		// Each stream should receive something.
		for _, stream := range streams {
			builder := &storage.DeferredFlowBuilder{}
			Eventually(stream.Flows(), waitTimeout, retryTime).Should(Receive(&builder))
			stream.Close()
		}
	})
}

// TestSortOrder tests basic functionality of the various sorted indices supported by goldmane.
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
			c := newClock(initialNow)
			roller := &rolloverController{
				ch:                    make(chan time.Time),
				aggregationWindowSecs: 1,
				clock:                 c,
			}
			opts := []goldmane.Option{
				goldmane.WithRolloverTime(1 * time.Second),
				goldmane.WithRolloverFunc(roller.After),
				goldmane.WithNowFunc(c.Now),
			}
			defer setupTest(t, opts...)()
			<-gm.Run(c.Now().Unix())

			// Create a bunch of random flows.
			for range 100 {
				fl := testutils.NewRandomFlow(c.Now().Unix() - 1)
				gm.Receive(types.ProtoToFlow(fl))
			}

			// Query for Flows, sorted by the Index under test. Since we have created a bunch of random flows,
			// we don't know exactly how many unique keys there will be. But it will be a non-zero number.
			var flows []*proto.FlowResult
			Eventually(func() bool {
				var results *proto.FlowListResult
				results, _ = gm.List(&proto.FlowListRequest{SortBy: []*proto.SortOption{{SortBy: tc.sortBy}}})
				flows = results.Flows
				return len(flows) > 3
			}, waitTimeout, retryTime, "Didn't receive flows").Should(BeTrue())

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

func TestStatistics(t *testing.T) {
	var roller *rolloverController

	// Number of flows to create for each test.
	numFlows := 10

	mutateUniquePolicyName := func(fl *proto.Flow, i int) {
		// Modify the first policy hit to have a unique policy name. This ensures that
		// we don't get duplicate policy hits in the statistics.
		fl.Key.Policies.EnforcedPolicies[0].Name = fmt.Sprintf("policy-%d", i)
	}

	// Helper function for the statistics tests to create a bunch of random flows.
	createFlows := func(numFlows int, mutators ...func(*proto.Flow, int)) []*proto.Flow {
		flows := []*proto.Flow{}

		// Create a bunch of flows across different buckets, one per bucket.
		// Each Flow has a random policy hit as well as a well-known one.
		for i := range numFlows {
			fl := testutils.NewRandomFlow(roller.clock.Now().Unix())

			// If a mutator was given, apply it to the flow.
			for _, mutator := range mutators {
				mutator(fl, i)
			}

			// Store off the flows we created so the tests can refer to them.
			flows = append(flows, fl)

			// Send it to goldmane.
			gm.Receive(types.ProtoToFlow(fl))
			roller.rolloverAndAdvanceClock(1)
		}

		// Wait for all flows to be received.
		Eventually(func() bool {
			results, _ := gm.List(&proto.FlowListRequest{})
			return len(results.Flows) == 10
		}, waitTimeout, retryTime).Should(BeTrue(), "Didn't receive all flows")
		return flows
	}

	for statVal, statName := range proto.StatisticType_name {
		statType := proto.StatisticType(statVal)

		t.Run(fmt.Sprintf("GroupBy_Policy %s", statName), func(t *testing.T) {
			// Create a clock and rollover controller.
			c := newClock(initialNow)
			roller = &rolloverController{
				ch:                    make(chan time.Time),
				aggregationWindowSecs: 1,
				clock:                 c,
			}
			opts := []goldmane.Option{
				goldmane.WithRolloverTime(1 * time.Second),
				goldmane.WithRolloverFunc(roller.After),
				goldmane.WithNowFunc(c.Now),
			}
			defer setupTest(t, opts...)()
			<-gm.Run(c.Now().Unix())

			// Create some flows.
			flows := createFlows(numFlows, mutateUniquePolicyName)

			// Query for packet statistics per-policy.
			perPolicyStats, err := gm.Statistics(&proto.StatisticsRequest{
				Type:    statType,
				GroupBy: proto.StatisticsGroupBy_Policy,
			})
			require.NoError(t, err)

			// Verify the statistics. We expect an entry for each of the randomly generated policy
			// hits, as well as an entry for the common "default" policy hit on each Flow.
			require.NotNil(t, perPolicyStats)
			require.Len(t, perPolicyStats, numFlows+1)

			// Query for a specific policy hit - the one that is common across all flows.
			hitToMatch := flows[0].Key.Policies.EnforcedPolicies[1]
			stats, err := gm.Statistics(&proto.StatisticsRequest{
				Type:       statType,
				GroupBy:    proto.StatisticsGroupBy_Policy,
				TimeSeries: true,
				PolicyMatch: &proto.PolicyMatch{
					Tier:      hitToMatch.Tier,
					Name:      hitToMatch.Name,
					Namespace: hitToMatch.Namespace,
					Kind:      hitToMatch.Kind,
				},
			})
			require.NoError(t, err)

			// Expect a single entry for the common policy hit.
			require.NotNil(t, stats)
			require.Len(t, stats, 1)

			// The statistics should span the entire time range of the flows.
			stat := stats[0]
			require.Len(t, stat.AllowedIn, numFlows)
			require.Len(t, stat.AllowedOut, numFlows)
			require.Len(t, stat.DeniedIn, numFlows)
			require.Len(t, stat.DeniedOut, numFlows)
			require.Len(t, stat.X, numFlows)

			for i, fl := range flows {
				// The X axis should be the start time of the buckets the flow went into.
				require.Equal(t, fl.StartTime, stat.X[i])

				// The common policy hit was an allow for each bucket, so we should see stats
				// in and out for each bucket matching the flow for that time range.
				switch statType {
				case proto.StatisticType_PacketCount:
					require.Equal(t, fl.PacketsIn, stat.AllowedIn[i])
					require.Equal(t, fl.PacketsOut, stat.AllowedOut[i])
				case proto.StatisticType_ByteCount:
					require.Equal(t, fl.BytesIn, stat.AllowedIn[i])
					require.Equal(t, fl.BytesOut, stat.AllowedOut[i])
				case proto.StatisticType_LiveConnectionCount:
					switch fl.Key.Reporter {
					case proto.Reporter_Src:
						require.Equal(t, fl.NumConnectionsLive, stat.AllowedOut[i])
					case proto.Reporter_Dst:
						require.Equal(t, fl.NumConnectionsLive, stat.AllowedIn[i])
					}
				}
			}

			// Ingest the same flows again. This should double the statistics.
			for _, fl := range flows {
				gm.Receive(types.ProtoToFlow(fl))
			}

			// Wait for all flows to be received.
			Eventually(func() error {
				results, err := gm.List(&proto.FlowListRequest{})
				if err != nil {
					return err
				}
				if len(flows) != numFlows {
					return fmt.Errorf("Expected %d flows, got %d", numFlows, len(flows))
				}
				for _, f := range results.Flows {
					// Use the NumConnectionsStarted field to verify that we've received a second copy of each flow.
					if f.Flow.NumConnectionsStarted != 2 {
						return fmt.Errorf("Expected flow.NumConnectionsStarted to be 2, got %+v", f.Flow.NumConnectionsStarted)
					}
				}
				return nil
			}, waitTimeout, retryTime).ShouldNot(HaveOccurred(), "Didn't receive all flows")

			// Query for new statistics.
			stats, err = gm.Statistics(&proto.StatisticsRequest{
				Type:    statType,
				GroupBy: proto.StatisticsGroupBy_Policy,
			})
			require.NoError(t, err)

			// Compare them to the originally received statistics.
			require.NotNil(t, stats)
			require.Len(t, stats, numFlows+1)
			for i, stat := range stats {
				orig := perPolicyStats[i]

				// X axis should be the same.
				require.Equal(t, orig.X, stat.X)

				// But the other values should be doubled.
				for j := range orig.X {
					require.Equal(t, orig.AllowedIn[j]*2, stat.AllowedIn[j])
					require.Equal(t, orig.AllowedOut[j]*2, stat.AllowedOut[j])
					require.Equal(t, orig.DeniedIn[j]*2, stat.DeniedIn[j])
					require.Equal(t, orig.DeniedOut[j]*2, stat.DeniedOut[j])
				}
			}
		})

		// This test verifies that time-series data is consistent with aggregated data by
		// querying both and comparing the results.
		t.Run(fmt.Sprintf("Time-series consistency %s", statName), func(t *testing.T) {
			// Create a clock and rollover controller.
			c := newClock(initialNow)
			roller = &rolloverController{
				ch:                    make(chan time.Time),
				aggregationWindowSecs: 1,
				clock:                 c,
			}
			opts := []goldmane.Option{
				goldmane.WithRolloverTime(1 * time.Second),
				goldmane.WithRolloverFunc(roller.After),
				goldmane.WithNowFunc(c.Now),
			}
			defer setupTest(t, opts...)()
			<-gm.Run(c.Now().Unix())

			// Create some flows.
			_ = createFlows(numFlows, mutateUniquePolicyName)

			// Send a query for non-time-series data, which will aggregate
			// all the flows into a single statistic.
			stats, err := gm.Statistics(&proto.StatisticsRequest{
				Type:       statType,
				GroupBy:    proto.StatisticsGroupBy_Policy,
				TimeSeries: false,
			})
			require.NoError(t, err)
			require.Len(t, stats, numFlows+1)

			// Collect the time-series data as well, so we can compre the aggregated data
			// with the time-series data for the same range.
			timeSeriesStats, err := gm.Statistics(&proto.StatisticsRequest{
				Type:       statType,
				GroupBy:    proto.StatisticsGroupBy_Policy,
				TimeSeries: true,
			})
			require.NoError(t, err)

			for i, stat := range stats {
				// The X axis should be nil.
				require.Nil(t, stat.X)

				tsStat := timeSeriesStats[i]

				require.Equal(t, sum(tsStat.AllowedIn), stat.AllowedIn[0])
				require.Equal(t, sum(tsStat.AllowedOut), stat.AllowedOut[0])
				require.Equal(t, sum(tsStat.DeniedIn), stat.DeniedIn[0])
				require.Equal(t, sum(tsStat.DeniedOut), stat.DeniedOut[0])
				require.Equal(t, sum(tsStat.PassedIn), stat.PassedIn[0])
				require.Equal(t, sum(tsStat.PassedOut), stat.PassedOut[0])
			}
		})

		t.Run(fmt.Sprintf("EndOfTier per-policy statistics %s", statName), func(t *testing.T) {
			// Create a clock and rollover controller.
			c := newClock(initialNow)
			roller = &rolloverController{
				ch:                    make(chan time.Time),
				aggregationWindowSecs: 1,
				clock:                 c,
			}
			opts := []goldmane.Option{
				goldmane.WithRolloverTime(1 * time.Second),
				goldmane.WithRolloverFunc(roller.After),
				goldmane.WithNowFunc(c.Now),
			}
			defer setupTest(t, opts...)()
			<-gm.Run(c.Now().Unix())

			// Create some flows, mutating the first policy hit in each to be an EndOfTier hit.
			mutateEndOftier := func(fl *proto.Flow, i int) {
				trigger := googleproto.Clone(fl.Key.Policies.EnforcedPolicies[0]).(*proto.PolicyHit)
				fl.Key.Policies.EnforcedPolicies = []*proto.PolicyHit{
					{
						// Turn this into a typical EndOfTier default-deny policy.
						Kind:      proto.PolicyKind_EndOfTier,
						Tier:      trigger.Tier,
						RuleIndex: -1,
						Trigger:   trigger,
						Action:    proto.Action_Deny,
					},
				}
				fl.Key.Policies.PendingPolicies = []*proto.PolicyHit{}
			}
			_ = createFlows(
				numFlows,
				mutateUniquePolicyName,
				mutateEndOftier,
			)

			// Send a query for non-time-series data, aggregated by Policy.
			// Collect aggreated statistics, by policy rule.
			stats, err := gm.Statistics(&proto.StatisticsRequest{
				Type:       statType,
				GroupBy:    proto.StatisticsGroupBy_Policy,
				TimeSeries: false,
			})
			require.NoError(t, err)
			require.NotNil(t, stats)

			// We should have a unique entry for each EOT policy hit.
			require.Len(t, stats, numFlows)

			for _, stat := range stats {
				require.Equal(t, proto.PolicyKind_CalicoNetworkPolicy, stat.Policy.Kind)

				// Statistics per-policy don't include an action, as they aggregate across all actions.
				require.Equal(t, proto.Action_ActionUnspecified, stat.Policy.Action)
				switch stat.Direction {
				case proto.RuleDirection_Egress:
					require.NotEqual(t, int64(0), stat.DeniedIn[0])
				case proto.RuleDirection_Ingress:
					require.NotEqual(t, int64(0), stat.DeniedOut[0])
				}
				require.Equal(t, int64(0), stat.AllowedIn[0])
				require.Equal(t, int64(0), stat.AllowedOut[0])
				require.Equal(t, int64(0), stat.PassedIn[0])
				require.Equal(t, int64(0), stat.PassedOut[0])
			}
		})

		t.Run(fmt.Sprintf("EndOfTier per-rule statistics %s", statName), func(t *testing.T) {
			// Create a clock and rollover controller.
			c := newClock(initialNow)
			roller = &rolloverController{
				ch:                    make(chan time.Time),
				aggregationWindowSecs: 1,
				clock:                 c,
			}
			opts := []goldmane.Option{
				goldmane.WithRolloverTime(1 * time.Second),
				goldmane.WithRolloverFunc(roller.After),
				goldmane.WithNowFunc(c.Now),
			}
			defer setupTest(t, opts...)()
			<-gm.Run(c.Now().Unix())

			// Create some flows, mutating the first policy hit in each to be an EndOfTier hit.
			mutateEndOftier := func(fl *proto.Flow, i int) {
				trigger := googleproto.Clone(fl.Key.Policies.EnforcedPolicies[0]).(*proto.PolicyHit)
				fl.Key.Policies.EnforcedPolicies = []*proto.PolicyHit{
					{
						// Turn this into a typical EndOfTier default-deny policy.
						Kind:      proto.PolicyKind_EndOfTier,
						Tier:      trigger.Tier,
						RuleIndex: -1,
						Trigger:   trigger,
						Action:    proto.Action_Deny,
					},
				}
				fl.Key.Policies.PendingPolicies = []*proto.PolicyHit{}
			}
			_ = createFlows(
				numFlows,
				mutateUniquePolicyName,
				mutateEndOftier,
			)

			// Send a query for non-time-series data, aggregated by Policy.
			// Collect aggreated statistics, by policy rule.
			stats, err := gm.Statistics(&proto.StatisticsRequest{
				Type:       statType,
				GroupBy:    proto.StatisticsGroupBy_PolicyRule,
				TimeSeries: false,
			})
			require.NoError(t, err)
			require.NotNil(t, stats)

			// We should have a unique entry for each EOT policy hit.
			require.Len(t, stats, numFlows)

			for _, stat := range stats {
				require.Equal(t, proto.PolicyKind_CalicoNetworkPolicy, stat.Policy.Kind)
				require.True(t, strings.HasPrefix(stat.Policy.Name, "policy"), fmt.Sprintf("Unexpected policy name: %s", stat.Policy.Name))
				require.True(t, strings.HasPrefix(stat.Policy.Namespace, "test-ns"), fmt.Sprintf("Unexpected policy namespace: %s", stat.Policy.Namespace))
				require.NotEqual(t, proto.Action_ActionUnspecified, stat.Policy.Action)
			}
		})

		t.Run(fmt.Sprintf("GroupBy_PolicyRule %s", statName), func(t *testing.T) {
			// Create a clock and rollover controller.
			c := newClock(initialNow)
			roller = &rolloverController{
				ch:                    make(chan time.Time),
				aggregationWindowSecs: 1,
				clock:                 c,
			}
			opts := []goldmane.Option{
				goldmane.WithRolloverTime(1 * time.Second),
				goldmane.WithRolloverFunc(roller.After),
				goldmane.WithNowFunc(c.Now),
			}
			defer setupTest(t, opts...)()
			<-gm.Run(c.Now().Unix())

			// Create some flows.
			_ = createFlows(numFlows, mutateUniquePolicyName)

			// Collect aggreated statistics, by policy rule.
			stats, err := gm.Statistics(&proto.StatisticsRequest{
				Type:       statType,
				GroupBy:    proto.StatisticsGroupBy_PolicyRule,
				TimeSeries: false,
			})
			require.NoError(t, err)

			// We now expect one entry per policy rule. Each Flow has a single unique policy rule, as well
			// as a common policy rule. The common policy rule is itself is actually two separate rules depending
			// on whether the flow was ingress or egress.
			require.Len(t, stats, numFlows+2)
		})
	}
}

func sum(nums []int64) int64 {
	var sum int64
	for _, n := range nums {
		sum += n
	}
	return sum
}
