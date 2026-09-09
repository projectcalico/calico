// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package collector

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	clttypes "github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// An evaluation that cannot be completed says so, rather than returning an empty trace. Overwriting
// the flow's pending trace with that would report the flow as having no pending policy at all,
// which is a stronger claim than "we could not work it out" — so the last trace stands.
func TestPendingRuleTraceKeptWhenEvaluationFails(t *testing.T) {
	RegisterTestingT(t)

	c, flowTuple1, _ := setupPolicyEvalCollector(t)
	evaluated := []*calc.RuleID{calc.NewRuleID(
		v3.KindGlobalNetworkPolicy, "default", "policy1", "", 0, rules.RuleDirIngress, rules.RuleActionAllow)}

	// Control: with the endpoint's policy in the store, the trace is worked out and recorded.
	var ruleIDs []*calc.RuleID
	c.policyStoreManager.DoWithLock(func(ps *policystore.PolicyStore) {
		c.evaluatePendingRuleTrace(rules.RuleDirIngress, ps, localEd1, TupleAsFlow(flowTuple1), &ruleIDs)
	})
	Expect(ruleIDs).To(Equal(evaluated))

	c.policyStoreManager.DoWithLock(func(ps *policystore.PolicyStore) {
		// The endpoint's tier still names policy1, but its rules are no longer in the store, so the
		// evaluation fails part way through.
		delete(ps.PolicyByID, types.PolicyID{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy})
		c.evaluatePendingRuleTrace(rules.RuleDirIngress, ps, localEd1, TupleAsFlow(flowTuple1), &ruleIDs)
	})
	Expect(ruleIDs).To(Equal(evaluated), "the trace from the last successful evaluation should stand")
}

// The two helpers below live in collector_test.go on master, where #13316 added them. They are
// carried here so that this test does not depend on backporting that change as well.

// workloadEndpointID converts a model workload endpoint key to its protobuf endpoint ID.
func workloadEndpointID(key model.WorkloadEndpointKey) types.WorkloadEndpointID {
	return types.WorkloadEndpointID{
		OrchestratorId: key.OrchestratorID,
		WorkloadId:     key.WorkloadID,
		EndpointId:     key.EndpointID,
	}
}

// setupPolicyEvalCollector builds a collector holding two flows against a populated policy store:
// flow1 is local-to-local (policy1 allow), flow2 is local-to-remote (policy2 deny). It returns the
// collector and the two flow tuples.
func setupPolicyEvalCollector(t *testing.T) (*collector, tuple.Tuple, tuple.Tuple) {
	t.Helper()

	epMap := map[[16]byte]calc.EndpointData{
		localIp1:  localEd1,
		localIp2:  localEd2,
		remoteIp1: remoteEd1,
	}
	lm := newMockLookupsCache(epMap, nil, nil, nil)
	policyStoreManager := policystore.NewPolicyStoreManager()

	c := newCollector(lm, &Config{
		AgeTimeout:            10 * time.Second,
		InitialReportingDelay: 5 * time.Second,
		ExportingInterval:     time.Second,
		FlowLogsFlushInterval: 100 * time.Second,
		PolicyStoreManager:    policyStoreManager,
	}).(*collector)

	flowTuple1 := tuple.New(localIp1, localIp2, proto_tcp, 1000, 1000)
	flowTuple2 := tuple.New(localIp2, remoteIp1, proto_tcp, 1000, 1000)

	localWlEp1Proto := calc.ModelWorkloadEndpointToProto(localWlEp1, nil, nil, []*proto.TierInfo{{
		Name:            "default",
		IngressPolicies: []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
		EgressPolicies:  []*proto.PolicyID{{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}},
	}})
	localWlEp2Proto := calc.ModelWorkloadEndpointToProto(localWlEp2, nil, nil, []*proto.TierInfo{{
		Name:            "default",
		IngressPolicies: []*proto.PolicyID{{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
		EgressPolicies:  []*proto.PolicyID{{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}},
	}})
	remoteWlEp1Proto := calc.ModelWorkloadEndpointToProto(remoteWlEp1, nil, nil, []*proto.TierInfo{})

	policyStoreManager.DoWithLock(func(ps *policystore.PolicyStore) {
		ps.Endpoints[workloadEndpointID(localWlEPKey1)] = localWlEp1Proto
		ps.Endpoints[workloadEndpointID(localWlEPKey2)] = localWlEp2Proto
		ps.Endpoints[workloadEndpointID(remoteWlEpKey1)] = remoteWlEp1Proto
		ps.PolicyByID[types.PolicyID{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}] = &proto.Policy{
			Tier:          "default",
			InboundRules:  []*proto.Rule{{Action: "allow"}},
			OutboundRules: []*proto.Rule{{Action: "allow"}},
		}
		ps.PolicyByID[types.PolicyID{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}] = &proto.Policy{
			Tier:          "default",
			InboundRules:  []*proto.Rule{{Action: "deny"}},
			OutboundRules: []*proto.Rule{{Action: "deny"}},
		}
	})
	policyStoreManager.OnInSync()

	// Simulate packet processing to create flow data in epStats.
	c.applyPacketInfo(clttypes.PacketInfo{
		Tuple:     *flowTuple1,
		Direction: rules.RuleDirIngress,
		RuleHits:  []clttypes.RuleHit{{RuleID: calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy1", "", 0, rules.RuleDirIngress, rules.RuleActionAllow), Hits: 1, Bytes: 100}},
	})
	c.applyPacketInfo(clttypes.PacketInfo{
		Tuple:     *flowTuple1,
		Direction: rules.RuleDirEgress,
		RuleHits:  []clttypes.RuleHit{{RuleID: calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy1", "", 0, rules.RuleDirEgress, rules.RuleActionAllow), Hits: 1, Bytes: 100}},
	})
	c.applyPacketInfo(clttypes.PacketInfo{
		Tuple:     *flowTuple2,
		Direction: rules.RuleDirEgress,
		RuleHits:  []clttypes.RuleHit{{RuleID: calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy2", "", 0, rules.RuleDirEgress, rules.RuleActionDeny), Hits: 1, Bytes: 100}},
	})

	return c, *flowTuple1, *flowTuple2
}
