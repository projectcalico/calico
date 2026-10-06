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

package storage

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// TestStatisticsMatchReference feeds a generated workload through the bucket and through the
// per-flow decoding implementation it replaced, and requires identical statistics.
func TestStatisticsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	_, cache, b, cancel := setup(t)
	defer cancel()
	ref := newStatisticsIndex()

	keys := make([]*proto.FlowKey, 300)
	for i := range keys {
		keys[i] = randomStatsKey(rng)
	}
	for i := range 20000 {
		f := types.ProtoToFlow(&proto.Flow{
			Key:                keys[rng.IntN(len(keys))],
			PacketsIn:          int64(rng.IntN(100)),
			PacketsOut:         int64(rng.IntN(100)),
			BytesIn:            int64(rng.IntN(10000)),
			BytesOut:           int64(rng.IntN(10000)),
			NumConnectionsLive: int64(rng.IntN(5)),
			StartTime:          int64(i),
		})
		cache.add(f)
		b.AddFlow(f)
		referenceAddFlow(ref, f)
	}

	require.NotEmpty(t, ref.policies)
	require.Equal(t, ref.statistics, b.stats.statistics)
	require.Equal(t, ref.policies, b.stats.policies)
}

func randomStatsHit(rng *rand.Rand, idx int) *proto.PolicyHit {
	h := &proto.PolicyHit{
		Kind:        []proto.PolicyKind{proto.PolicyKind_CalicoNetworkPolicy, proto.PolicyKind_NetworkPolicy, proto.PolicyKind_StagedNetworkPolicy}[rng.IntN(3)],
		Name:        fmt.Sprintf("policy-%d", rng.IntN(4)),
		Namespace:   fmt.Sprintf("ns-%d", rng.IntN(2)),
		Tier:        []string{"default", "security"}[rng.IntN(2)],
		Action:      []proto.Action{proto.Action_Allow, proto.Action_Deny, proto.Action_Pass}[rng.IntN(3)],
		PolicyIndex: int64(idx),
		RuleIndex:   int64(rng.IntN(3)),
	}
	if rng.IntN(5) == 0 {
		trigger := h
		h = &proto.PolicyHit{Kind: proto.PolicyKind_EndOfTier, Tier: trigger.Tier, Action: proto.Action_Deny, PolicyIndex: int64(idx), RuleIndex: -1, Trigger: trigger}
	}
	return h
}

// randomStatsKey builds traces that repeat policies across rules and between the enforced and
// pending lists, with and without differing actions, since those are what deduplication handles.
func randomStatsKey(rng *rand.Rand) *proto.FlowKey {
	trace := &proto.PolicyTrace{}
	for i := range rng.IntN(4) {
		trace.EnforcedPolicies = append(trace.EnforcedPolicies, randomStatsHit(rng, i))
	}
	switch rng.IntN(3) {
	case 0:
		trace.PendingPolicies = trace.EnforcedPolicies
	case 1:
		for i := range rng.IntN(4) {
			trace.PendingPolicies = append(trace.PendingPolicies, randomStatsHit(rng, i))
		}
	}
	return &proto.FlowKey{
		SourceName: fmt.Sprintf("src-%d", rng.IntN(10)),
		Reporter:   []proto.Reporter{proto.Reporter_Src, proto.Reporter_Dst}[rng.IntN(2)],
		Action:     []proto.Action{proto.Action_Allow, proto.Action_Deny}[rng.IntN(2)],
		Policies:   trace,
	}
}

// referenceAddFlow is statisticsIndex.AddFlow from before policy rules were cached on the
// DiachronicFlow, kept as an oracle.
func referenceAddFlow(s *statisticsIndex, flow *types.Flow) {
	s.add(flow, flow.Key.Action())

	trace := types.FlowLogPolicyToProto(flow.Key.Policies())
	policyHits := append(trace.EnforcedPolicies, trace.PendingPolicies...)

	polToRules := make(map[StatisticsKey]map[StatisticsKey]proto.Action)
	for _, hit := range policyHits {
		meta := hit
		if meta.Kind == proto.PolicyKind_EndOfTier {
			meta = hit.Trigger
		}
		sk := StatisticsKey{
			Namespace: meta.Namespace,
			Name:      meta.Name,
			Kind:      meta.Kind,
			Tier:      meta.Tier,
			Action:    hit.Action,
			RuleIndex: meta.PolicyIndex,
			Direction: direction(flow),
		}
		pk := sk.policyID()
		if _, ok := polToRules[pk]; !ok {
			polToRules[pk] = make(map[StatisticsKey]proto.Action)
		}
		if _, ok := polToRules[pk][sk]; !ok {
			polToRules[pk][sk] = hit.Action
		}
	}

	for pk, rules := range polToRules {
		ps, ok := s.policies[pk]
		if !ok {
			ps = &policyStatistics{rules: make(map[StatisticsKey]*statistics)}
			s.policies[pk] = ps
		}
		for k, action := range rules {
			ps.add(flow, action)
			rs, ok := ps.rules[k]
			if !ok {
				rs = &statistics{}
				ps.rules[k] = rs
			}
			rs.add(flow, action)
		}
	}
}
