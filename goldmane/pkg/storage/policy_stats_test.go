// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package storage_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

const policyStatsPackets = int64(10)

type policyStatsCounts struct {
	allowed int64
	denied  int64
}

// TestPolicyStatisticsCountFlowOncePerAction covers a flow that hits one policy as two rules,
// as when a staged policy shifts the pending trace. The policy counts the flow once per action,
// and each rule still counts it.
func TestPolicyStatisticsCountFlowOncePerAction(t *testing.T) {
	for _, tc := range []struct {
		name          string
		pendingAction proto.Action
		wantPolicy    policyStatsCounts
		wantRules     policyStatsCounts
	}{
		{
			name:          "both rules allow",
			pendingAction: proto.Action_Allow,
			wantPolicy:    policyStatsCounts{allowed: policyStatsPackets},
			wantRules:     policyStatsCounts{allowed: 2 * policyStatsPackets},
		},
		{
			name:          "the rules disagree",
			pendingAction: proto.Action_Deny,
			wantPolicy:    policyStatsCounts{allowed: policyStatsPackets, denied: policyStatsPackets},
			wantRules:     policyStatsCounts{allowed: policyStatsPackets, denied: policyStatsPackets},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			np := func(idx int64, action proto.Action) *proto.PolicyHit {
				return &proto.PolicyHit{
					Kind:        proto.PolicyKind_NetworkPolicy,
					Name:        "np",
					Namespace:   "ns",
					Tier:        "default",
					Action:      action,
					PolicyIndex: idx,
				}
			}
			staged := &proto.PolicyHit{
				Kind:        proto.PolicyKind_StagedNetworkPolicy,
				Name:        "staged",
				Namespace:   "ns",
				Tier:        "default",
				Action:      proto.Action_Allow,
				PolicyIndex: 0,
			}
			flow := types.ProtoToFlow(&proto.Flow{
				Key: &proto.FlowKey{
					SourceName: "client",
					DestName:   "server",
					Reporter:   proto.Reporter_Dst,
					Action:     proto.Action_Allow,
					Policies: &proto.PolicyTrace{
						EnforcedPolicies: []*proto.PolicyHit{np(0, proto.Action_Allow)},
						PendingPolicies:  []*proto.PolicyHit{staged, np(1, tc.pendingAction)},
					},
				},
				StartTime: dedupRingStart,
				EndTime:   dedupRingStart + dedupInterval,
				PacketsIn: policyStatsPackets,
			})
			ring := newDedupRing()
			ring.AddFlow(storage.FlowFromNode{Flow: flow, Node: "node-a"})

			require.Equal(t, tc.wantPolicy, npStatistics(t, ring, proto.StatisticsGroupBy_Policy))
			require.Equal(t, tc.wantRules, npStatistics(t, ring, proto.StatisticsGroupBy_PolicyRule))
		})
	}
}

// npStatistics sums the ingress packet counts of every statistics entry for policy np.
func npStatistics(t *testing.T, ring *storage.BucketRing, groupBy proto.StatisticsGroupBy) policyStatsCounts {
	t.Helper()
	results, err := ring.Statistics(&proto.StatisticsRequest{
		Type:        proto.StatisticType_PacketCount,
		GroupBy:     groupBy,
		PolicyMatch: &proto.PolicyMatch{Name: &proto.StringMatch{Value: "np", Type: proto.MatchType_Exact}},
	})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	var c policyStatsCounts
	for _, r := range results {
		c.allowed += r.AllowedIn[0]
		c.denied += r.DeniedIn[0]
	}
	return c
}
