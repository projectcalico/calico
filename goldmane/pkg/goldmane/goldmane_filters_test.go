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
	"testing"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

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
			req:      &proto.FlowListRequest{Filter: &proto.Filter{SourceNames: []*proto.StringMatch{{Value: "source-1"}}}},
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
				Filter: &proto.Filter{SourceNames: []*proto.StringMatch{{Value: "source-1"}}},
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
			name: "SourceNamespace, no sort",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{SourceNamespaces: []*proto.StringMatch{{Value: "source-ns-1"}}},
			},
			numFlows: 1,
			check: func(fl *proto.FlowResult) error {
				if fl.Flow.Key.SourceNamespace != "source-ns-1" {
					return fmt.Errorf("Expected SourceNamespace to be source-ns-1, got %s", fl.Flow.Key.SourceNamespace)
				}
				return nil
			},
		},

		{
			name: "Multiple SourceNamespaces, no sort",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					SourceNamespaces: []*proto.StringMatch{{Value: "source-ns-1"}, {Value: "source-ns-2"}},
				},
			},
			numFlows: 2,
		},

		{
			name:     "DestName, no sort",
			req:      &proto.FlowListRequest{Filter: &proto.Filter{DestNames: []*proto.StringMatch{{Value: "dest-2"}}}},
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
			req:      &proto.FlowListRequest{Filter: &proto.Filter{DestNames: []*proto.StringMatch{{Value: "dest-100"}}}},
			numFlows: 0,
		},

		{
			name:     "Port, no sort",
			req:      &proto.FlowListRequest{Filter: &proto.Filter{DestPorts: []*proto.PortMatch{{Port: 5}}}},
			numFlows: 1,
			check: func(fl *proto.FlowResult) error {
				if fl.Flow.Key.DestPort != 5 {
					return fmt.Errorf("Expected DestPort to be 5, got %d", fl.Flow.Key.DestPort)
				}
				return nil
			},
		},

		{
			name: "Multiple ports, no sort",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					DestPorts: []*proto.PortMatch{{Port: 5}, {Port: 6}},
				},
			},
			numFlows: 2,
		},

		{
			name: "Tier",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{{Tier: "tier-5"}},
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
			name: "Multiple Tiers",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{{Tier: "tier-5"}, {Tier: "tier-6"}},
				},
			},
			numFlows: 2,
		},

		{
			name: "Full policy match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{
							Tier:      "tier-5",
							Name:      "name-5",
							Namespace: "ns-5",
							Action:    proto.Action_Allow,
							Kind:      proto.PolicyKind_CalicoNetworkPolicy,
						},
					},
				},
			},
			numFlows: 1,
		},

		{
			name: "match on policy Kind, no match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{
							Kind: proto.PolicyKind_GlobalNetworkPolicy,
						},
					},
				},
			},
			numFlows: 0,
		},

		{
			name: "match on policy Kind, match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{
							Kind: proto.PolicyKind_CalicoNetworkPolicy,
						},
					},
				},
			},
			numFlows: 10,
		},

		{
			name: "match on pending policy",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{
							Namespace: "pending-ns-5",
						},
					},
				},
			},
			numFlows: 1,
		},

		{
			name: "fuzzy match on destination namespace",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					DestNamespaces: []*proto.StringMatch{
						{
							// This should match all of the flow's destination namespaces.
							Value: "dest",
							Type:  proto.MatchType_Fuzzy,
						},
					},
				},
			},
			numFlows: 10,
		},

		{
			name: "fuzzy match on destination namespace, no match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					DestNamespaces: []*proto.StringMatch{
						{
							Value: "nomatch",
							Type:  proto.MatchType_Fuzzy,
						},
					},
				},
			},
			numFlows: 0,
		},
	}

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

			// Create 10 flows, with a mix of fields to filter on.
			for i := range 10 {
				// Start with a base flow.
				fl := testutils.NewRandomFlow(c.Now().Unix() - 1)

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
							Action:    proto.Action_Allow,
							Kind:      proto.PolicyKind_CalicoNetworkPolicy,
						},
					},
					PendingPolicies: []*proto.PolicyHit{
						{
							Tier:      fmt.Sprintf("pending-tier-%d", i),
							Name:      fmt.Sprintf("pending-name-%d", i),
							Namespace: fmt.Sprintf("pending-ns-%d", i),
							Action:    proto.Action_Allow,
							Kind:      proto.PolicyKind_CalicoNetworkPolicy,
						},
					},
				}

				// Send it to goldmane.
				gm.Receive(types.ProtoToFlow(fl))
			}

			// Query for flows using the query from the testcase.
			var flows []*proto.FlowResult
			if tc.numFlows == 0 {
				Consistently(func() int {
					var results *proto.FlowListResult
					results, _ = gm.List(tc.req)
					flows = results.Flows
					return len(flows)
				}, 1*time.Second, retryTime).Should(Equal(0))
				return
			} else {
				var err error
				Eventually(func() error {
					var results *proto.FlowListResult
					results, err = gm.List(tc.req)
					flows = results.Flows
					if err != nil {
						return err
					}
					if len(flows) >= tc.numFlows {
						return nil
					}
					return fmt.Errorf("Expected %d flows, got %d", tc.numFlows, len(flows))
				}, waitTimeout, retryTime, "Didn't receive flows").ShouldNot(HaveOccurred())

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
				Filter: &proto.Filter{SourceNames: []*proto.StringMatch{{Value: "source-1"}}},
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
		{
			name: "Policy name, no filters",
			req: &proto.FilterHintsRequest{
				Type: proto.FilterType_FilterTypePolicyName,
			},
			numResp: 10,
		},
	}

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

			// Create 10 flows, with a mix of fields to filter on.
			for i := range 10 {
				// Start with a base flow.
				fl := testutils.NewRandomFlow(c.Now().Unix() - 1)

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
							Name: fmt.Sprintf("name-%d", i),
							Tier: fmt.Sprintf("tier-%d", i),
						},
					},
				}

				// Send it to goldmane.
				gm.Receive(types.ProtoToFlow(fl))
			}

			// Wait for all flows to be received.
			Eventually(func() bool {
				results, _ := gm.List(&proto.FlowListRequest{})
				return len(results.Flows) == 10
			}, waitTimeout, retryTime, "Didn't receive all flows").Should(BeTrue())

			// Query for hints using the query from the testcase.
			results, err := gm.Hints(tc.req)
			require.NoError(t, err)

			// Verify the hints.
			require.Len(t, results.Hints, tc.numResp, "Expected %d hints, got %d: %+v", tc.numResp, len(results.Hints), results.Hints)

			if tc.check != nil {
				require.NoError(t, tc.check(results.Hints), fmt.Sprintf("Hints check failed on hints: %+v", results.Hints))
			}
		})
	}

	// Run some tests against EndOfTier flows.
	eotTests := []tc{
		{
			name: "EndOfTier, Tier, no filters",
			req: &proto.FilterHintsRequest{
				Type: proto.FilterType_FilterTypePolicyTier,
			},
			numResp: 10,
		},
	}

	for _, tc := range eotTests {
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

			// Create 10 flows, with a mix of fields to filter on.
			for i := range 10 {
				// Start with a base flow.
				fl := testutils.NewRandomFlow(c.Now().Unix() - 1)

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
							Trigger: &proto.PolicyHit{
								Tier: fmt.Sprintf("tier-%d", i),
							},
						},
					},
				}

				// Send it to goldmane.
				gm.Receive(types.ProtoToFlow(fl))
			}

			// Wait for all flows to be received.
			Eventually(func() bool {
				results, _ := gm.List(&proto.FlowListRequest{})
				return len(results.Flows) == 10
			}, waitTimeout, retryTime, "Didn't receive all flows").Should(BeTrue())

			// Query for hints using the query from the testcase.
			results, err := gm.Hints(tc.req)
			require.NoError(t, err)

			// Verify the hints.
			require.Len(t, results.Hints, tc.numResp, "Expected %d hints, got %d: %+v", tc.numResp, len(results.Hints), results.Hints)

			if tc.check != nil {
				require.NoError(t, tc.check(results.Hints), fmt.Sprintf("Hints check failed on hints: %+v", results.Hints))
			}
		})
	}
}
