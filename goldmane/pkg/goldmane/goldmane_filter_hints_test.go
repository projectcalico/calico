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
			numResp: 12,
		},
		{
			name: "Policy name, no filters",
			req: &proto.FilterHintsRequest{
				Type: proto.FilterType_FilterTypePolicyName,
			},
			numResp: 12,
		},
		{
			name: "Namespace hints with filters kind & tier",
			req: &proto.FilterHintsRequest{
				Type: proto.FilterType_FilterTypeSourceNamespace,
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{
							Kind: proto.PolicyKind_CalicoNetworkPolicy,
							Tier: "tier-5",
						},
					},
				},
			},
			numResp: 1,
			check: func(hints []*proto.FilterHint) error {
				for _, h := range hints {
					if h.Value != "source-ns-5" {
						return fmt.Errorf("expected namespace source-ns-5, got %s", h.Value)
					}
				}
				return nil
			},
		},
		{
			name: "PolicyName hints with filters namespace & kind",
			req: &proto.FilterHintsRequest{
				Type: proto.FilterType_FilterTypePolicyName,
				Filter: &proto.Filter{
					SourceNamespaces: []*proto.StringMatch{{Value: "source-ns-4"}},
					Policies:         []*proto.PolicyMatch{{Kind: proto.PolicyKind_CalicoNetworkPolicy}},
				},
			},
			numResp: 2,
		},
		{
			name: "PolicyTier hints with filter policy name",
			req: &proto.FilterHintsRequest{
				Type: proto.FilterType_FilterTypePolicyTier,
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{Name: "name-4"},
						{Name: "name-5"},
					},
				},
			},
			numResp: 4,
			check: func(hints []*proto.FilterHint) error {
				if hints[0].Value != "tier-4" {
					return fmt.Errorf("expected tier tier-4, got %s", hints[0].Value)
				}
				if hints[1].Value != "tier-5" {
					return fmt.Errorf("expected tier tier-5, got %s", hints[0].Value)
				}
				return nil
			},
		},
		{
			name: "PolicyKind hints with filters namespace & tier",
			req: &proto.FilterHintsRequest{
				Type: proto.FilterType_FilterTypePolicyKind,
				Filter: &proto.Filter{
					SourceNamespaces: []*proto.StringMatch{{Value: "source-ns-2"}},
					Policies: []*proto.PolicyMatch{{
						Tier:      "tier-2",
						Namespace: "policy-namespace-2",
					}},
				},
			},
			numResp: 1,
			check: func(hints []*proto.FilterHint) error {
				// In this test all policies use only CalicoNetworkPolicy kind.
				if hints[0].Value != "CalicoNetworkPolicy" {
					return fmt.Errorf("expected kind CalicoNetworkPolicy, got %s", hints[0].Value)
				}
				return nil
			},
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
				enforcedPolicyKind := proto.PolicyKind_CalicoNetworkPolicy
				pendingPolicyKind := proto.PolicyKind_CalicoNetworkPolicy
				if i > 5 {
					pendingPolicyKind = proto.PolicyKind_Profile
					enforcedPolicyKind = proto.PolicyKind_Profile
				}

				fl.Key.Policies = &proto.PolicyTrace{
					EnforcedPolicies: []*proto.PolicyHit{
						{
							Name:      fmt.Sprintf("name-%d", i),
							Tier:      fmt.Sprintf("tier-%d", i),
							Namespace: fmt.Sprintf("policy-namespace-%d", i),
							Kind:      enforcedPolicyKind,
						},
					},
					PendingPolicies: []*proto.PolicyHit{
						{
							Name:      fmt.Sprintf("name-pending-%d", i),
							Kind:      pendingPolicyKind,
							Tier:      fmt.Sprintf("tier-pending-%d", i),
							Namespace: fmt.Sprintf("ns-pending-%d", i),
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
				enforcedPolicyKind := proto.PolicyKind_CalicoNetworkPolicy
				fl.Key.Policies = &proto.PolicyTrace{
					EnforcedPolicies: []*proto.PolicyHit{
						{
							Trigger: &proto.PolicyHit{
								Name:      fmt.Sprintf("name-%d", i),
								Kind:      enforcedPolicyKind,
								Tier:      fmt.Sprintf("tier-%d", i),
								Namespace: fmt.Sprintf("ns-%d", i),
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
