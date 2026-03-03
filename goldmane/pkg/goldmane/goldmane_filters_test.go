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
		check    func([]*proto.FlowResult) error
	}

	tests := []tc{
		{
			name:     "SourceName, no sort",
			req:      &proto.FlowListRequest{Filter: &proto.Filter{SourceNames: []*proto.StringMatch{{Value: "source-1"}}}},
			numFlows: 1,
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					if fl.Flow.Key.SourceName != "source-1" {
						return fmt.Errorf("Expected SourceName to be source-1, got %s", fl.Flow.Key.SourceName)
					}
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
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					if fl.Flow.Key.SourceName != "source-1" {
						return fmt.Errorf("Expected SourceName to be source-1, got %s", fl.Flow.Key.SourceName)
					}
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
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					if fl.Flow.Key.SourceNamespace != "source-ns-1" {
						return fmt.Errorf("Expected SourceNamespace to be source-ns-1, got %s", fl.Flow.Key.SourceNamespace)
					}
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
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					if fl.Flow.Key.DestName != "dest-2" {
						return fmt.Errorf("Expected DestName to be dest-2, got %s", fl.Flow.Key.DestName)
					}
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
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					if fl.Flow.Key.DestPort != 5 {
						return fmt.Errorf("Expected DestPort to be 5, got %d", fl.Flow.Key.DestPort)
					}
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
			name: "multiple enforced policy Tiers (OR operator), match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{Tier: "tier-5"},
						{Tier: "tier-4"},
						{Tier: "tier-3"},
					},
				},
			},
			numFlows: 3,
			check: func(flows []*proto.FlowResult) error {
				// Tiers we expect across all flows.
				expected := map[string]bool{
					"tier-5": false,
					"tier-4": false,
					"tier-3": false,
				}

				for _, fl := range flows {
					if len(fl.Flow.Key.Policies.EnforcedPolicies) == 0 {
						return fmt.Errorf("flow has no enforced policies")
					}

					tier := fl.Flow.Key.Policies.EnforcedPolicies[0].Tier

					// Flow must belong to one of the expected tiers.
					if _, ok := expected[tier]; !ok {
						return fmt.Errorf("unexpected tier %q in flow", tier)
					}

					// Mark this expected tier as seen.
					expected[tier] = true
				}

				// Ensure all three tiers were present exactly once.
				for tier, found := range expected {
					if !found {
						return fmt.Errorf("expected tier %s to appear in some flow, but it did not", tier)
					}
				}

				return nil
			},
		},

		{
			name: "multiple pending policy Tiers (OR operator), match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{Tier: "pending-tier-5"},
						{Tier: "pending-tier-4"},
						{Tier: "pending-tier-3"},
					},
				},
			},
			numFlows: 3,
			check: func(flows []*proto.FlowResult) error {
				expected := map[string]bool{
					"pending-tier-5": false,
					"pending-tier-4": false,
					"pending-tier-3": false,
				}

				for _, fl := range flows {
					if len(fl.Flow.Key.Policies.PendingPolicies) == 0 {
						return fmt.Errorf("flow has no enforced policies")
					}

					tier := fl.Flow.Key.Policies.PendingPolicies[0].Tier

					if _, ok := expected[tier]; !ok {
						return fmt.Errorf("unexpected tier %q in flow", tier)
					}

					expected[tier] = true
				}

				for tier, found := range expected {
					if !found {
						return fmt.Errorf("expected tier %s to appear in some flow, but it did not", tier)
					}
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
							Tier:      "tier-4",
							Name:      "name-4",
							Namespace: "ns-4",
							Action:    proto.Action_Allow,
							Kind:      proto.PolicyKind_CalicoNetworkPolicy,
						},
					},
				},
			},
			numFlows: 1,
			check: func(results []*proto.FlowResult) error {
				foundPolicy := results[0].Flow.Key.Policies.EnforcedPolicies[0]
				if foundPolicy.Tier != "tier-4" || foundPolicy.Name != "name-4" || foundPolicy.Namespace != "ns-4" ||
					foundPolicy.Action != proto.Action_Allow || foundPolicy.Kind != proto.PolicyKind_CalicoNetworkPolicy {
					return fmt.Errorf("Policy does not match expected values")
				}
				return nil
			},
		},

		{
			name: "Full Profile enforced policy match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{
							Tier:      "pending-tier-5",
							Name:      "pending-name-5",
							Namespace: "pending-ns-5",
							Action:    proto.Action_Deny,
							Kind:      proto.PolicyKind_Profile,
						},
					},
				},
			},
			numFlows: 1,
			check: func(results []*proto.FlowResult) error {
				foundPolicy := results[0].Flow.Key.Policies.PendingPolicies[0]
				if foundPolicy.Tier != "pending-tier-5" || foundPolicy.Name != "pending-name-5" || foundPolicy.Namespace != "pending-ns-5" ||
					foundPolicy.Action != proto.Action_Deny || foundPolicy.Kind != proto.PolicyKind_Profile {
					return fmt.Errorf("Policy does not match expected values")
				}
				return nil
			},
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
			name: "No Policies filter: match on policy Kind=Profile",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{
							Kind: proto.PolicyKind_Profile,
						},
					},
				},
			},
			numFlows: 5,
			check: func(results []*proto.FlowResult) error {
				foundPolicy := results[0].Flow.Key.Policies.PendingPolicies[0]
				if foundPolicy.Kind != proto.PolicyKind_Profile {
					return fmt.Errorf("Policy does not match expected values")
				}
				return nil
			},
		},

		{
			name: "match on multiple enforced policy Kinds (OR Operator), match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{Kind: proto.PolicyKind_CalicoNetworkPolicy},
						{Kind: proto.PolicyKind_NetworkPolicy},
					},
				},
			},
			numFlows: 10,
			check: func(flows []*proto.FlowResult) error {
				expected := map[proto.PolicyKind]bool{
					proto.PolicyKind_CalicoNetworkPolicy: false,
					proto.PolicyKind_NetworkPolicy:       false,
				}

				for _, fl := range flows {
					if len(fl.Flow.Key.Policies.EnforcedPolicies) == 0 {
						return fmt.Errorf("flow has no enforced policies")
					}

					kind := fl.Flow.Key.Policies.EnforcedPolicies[0].Kind

					if _, ok := expected[kind]; !ok {
						return fmt.Errorf("unexpected kind %q in flow", kind)
					}

					expected[kind] = true
				}

				for kind, found := range expected {
					if !found {
						return fmt.Errorf("expected kind %s to appear in some flow, but it did not", kind)
					}
				}

				return nil
			},
		},

		{
			name: "match on multiple pending policy Kinds (OR Operator), match",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Policies: []*proto.PolicyMatch{
						{Kind: proto.PolicyKind_StagedNetworkPolicy},
						{Kind: proto.PolicyKind_Profile},
					},
				},
			},
			numFlows: 10,
			check: func(flows []*proto.FlowResult) error {
				expected := map[proto.PolicyKind]bool{
					proto.PolicyKind_StagedNetworkPolicy: false,
					proto.PolicyKind_Profile:             false,
				}

				for _, fl := range flows {
					pending := fl.Flow.Key.Policies.PendingPolicies
					if len(pending) == 0 {
						return fmt.Errorf("flow has no pending policies")
					}

					for _, p := range pending {
						kind := p.Kind

						// Mark this expected kind as observed.
						expected[kind] = true
					}
				}

				// Ensure all expected kinds appeared in at least one flow.
				for kind, found := range expected {
					if !found {
						return fmt.Errorf("expected kind %s to appear in some flow, but it did not", kind)
					}
				}

				return nil
			},
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

		{
			name: "Reporter filter - Src",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Reporter: proto.Reporter_Src,
				},
			},
			numFlows: 5, // Assuming half of the 10 flows have Reporter_Src
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					if fl.Flow.Key.Reporter != proto.Reporter_Src {
						return fmt.Errorf("Expected Reporter to be Src, got %s", fl.Flow.Key.Reporter)
					}
				}

				return nil
			},
		},

		{
			name: "Reporter filter - Dst",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Reporter: proto.Reporter_Dst,
				},
			},
			numFlows: 5, // Assuming half of the 10 flows have Reporter_Dst
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					if fl.Flow.Key.Reporter != proto.Reporter_Dst {
						return fmt.Errorf("Expected Reporter to be Dst, got %s", fl.Flow.Key.Reporter)
					}
				}

				return nil
			},
		},

		{
			name: "Actions filter - Allow",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Actions: []proto.Action{proto.Action_Allow},
				},
			},
			numFlows: 5,
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					if fl.Flow.Key.Action != proto.Action_Allow {
						return fmt.Errorf("Expected flow with Allow action")
					}
				}

				return nil
			},
		},

		{
			name: "Actions filter - Deny",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					Actions: []proto.Action{proto.Action_Deny},
				},
			},
			numFlows: 5,
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					if fl.Flow.Key.Action != proto.Action_Deny {
						return fmt.Errorf("Expected flow with Deny action")
					}
				}

				return nil
			},
		},

		{
			name: "PendingActions filter - Allow",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					PendingActions: []proto.Action{proto.Action_Allow},
				},
			},
			numFlows: 5,
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					hasPendingAllow := false
					for _, p := range fl.Flow.Key.Policies.PendingPolicies {
						if p.Action == proto.Action_Allow {
							hasPendingAllow = true
							break
						}
					}
					if !hasPendingAllow {
						return fmt.Errorf("Expected at least one pending policy with Allow action")
					}
				}

				return nil
			},
		},

		{
			name: "PendingActions filter - Deny",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					PendingActions: []proto.Action{proto.Action_Deny},
				},
			},
			numFlows: 5, // All flows have pending policy with Action_Allow
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					hasPendingDeny := false
					for _, p := range fl.Flow.Key.Policies.PendingPolicies {
						if p.Action == proto.Action_Deny {
							hasPendingDeny = true
							break
						}
					}
					if !hasPendingDeny {
						return fmt.Errorf("Expected at least one pending policy with Deny action")
					}
				}

				return nil
			},
		},

		{
			name: "PendingActions - Deny AND Actions - Deny",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					PendingActions: []proto.Action{proto.Action_Deny},
					Actions:        []proto.Action{proto.Action_Deny},
				},
			},
			numFlows: 5,
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					hasPendingDeny := false
					for _, p := range fl.Flow.Key.Policies.PendingPolicies {
						if p.Action == proto.Action_Deny {
							hasPendingDeny = true
							break
						}
					}
					if !hasPendingDeny || fl.Flow.Key.Action != proto.Action_Deny {
						return fmt.Errorf("Expected flow with action=Deny and pending_action=Deny")
					}
				}

				return nil
			},
		},

		{
			name: "PendingActions - Allow AND Actions - Allow",
			req: &proto.FlowListRequest{
				Filter: &proto.Filter{
					PendingActions: []proto.Action{proto.Action_Allow},
					Actions:        []proto.Action{proto.Action_Allow},
				},
			},
			numFlows: 5,
			check: func(flows []*proto.FlowResult) error {
				for _, fl := range flows {
					hasPendingAllow := false
					for _, p := range fl.Flow.Key.Policies.PendingPolicies {
						if p.Action == proto.Action_Allow {
							hasPendingAllow = true
							break
						}
					}
					if !hasPendingAllow || fl.Flow.Key.Action != proto.Action_Allow {
						return fmt.Errorf("Expected flow with action=Allow and pending_action=Allow")
					}
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
				fl.Key.Reporter = proto.Reporter_Src
				fl.Key.Action = proto.Action_Allow
				policyAction := proto.Action_Allow
				enforcedPolicyKind := proto.PolicyKind_CalicoNetworkPolicy
				pendingPolicyKind := proto.PolicyKind_StagedNetworkPolicy
				if i >= 5 {
					fl.Key.Reporter = proto.Reporter_Dst
					policyAction = proto.Action_Deny
					fl.Key.Action = proto.Action_Deny
					enforcedPolicyKind = proto.PolicyKind_NetworkPolicy
					pendingPolicyKind = proto.PolicyKind_Profile
				}

				fl.Key.Policies = &proto.PolicyTrace{
					EnforcedPolicies: []*proto.PolicyHit{
						{
							Tier:      fmt.Sprintf("tier-%d", i),
							Name:      fmt.Sprintf("name-%d", i),
							Namespace: fmt.Sprintf("ns-%d", i),
							Action:    policyAction,
							Kind:      enforcedPolicyKind,
						},
					},

					PendingPolicies: []*proto.PolicyHit{
						{
							Tier:      fmt.Sprintf("pending-tier-%d", i),
							Name:      fmt.Sprintf("pending-name-%d", i),
							Namespace: fmt.Sprintf("pending-ns-%d", i),
							Action:    policyAction,
							Kind:      pendingPolicyKind,
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
					Expect(tc.check(flows)).To(BeNil())
				}
			}
		})
	}
}
