//go:build !windows

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

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
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

// With no staged policy in a tier, the pending trace reports the tier's default action against the
// same policy as the enforced trace Felix builds from the dataplane's end-of-tier hit, so the two
// flow-log fields agree when nothing would change.
func TestPendingTierDefaultActionNamesSamePolicyAsEnforced(t *testing.T) {
	RegisterTestingT(t)

	keys := []model.PolicyKey{
		{Name: "allow-dns", Kind: v3.KindGlobalNetworkPolicy},
		{Name: "allow-https", Namespace: "ns1", Kind: v3.KindNetworkPolicy},
		{Name: "allow-monitoring", Kind: v3.KindGlobalNetworkPolicy},
	}

	tier := calc.NewTierInfo("tier1")
	tier.Valid = true
	tier.DefaultAction = v3.Deny
	protoTier := &proto.TierInfo{Name: "tier1", DefaultAction: string(v3.Deny)}
	store := policystore.NewPolicyStore()
	for _, key := range keys {
		md := calc.ExtractPolicyMetadata(&model.Policy{Tier: "tier1"})
		tier.OrderedPolicies = append(tier.OrderedPolicies, calc.PolKV{Key: key, Value: &md})

		id := &proto.PolicyID{Name: key.Name, Namespace: key.Namespace, Kind: key.Kind}
		protoTier.IngressPolicies = append(protoTier.IngressPolicies, id)
		protoTier.EgressPolicies = append(protoTier.EgressPolicies, id)
		// No rules, so every flow ends at the tier's default action.
		store.PolicyByID[types.ProtoToPolicyID(id)] = &proto.Policy{Tier: "tier1", Namespace: key.Namespace}
	}

	enforced := calc.NewEndpointLookupsCache().CreateLocalEndpointData(localWlEPKey1, localWlEp1, []calc.TierInfo{*tier})
	protoEp := calc.ModelWorkloadEndpointToProto(localWlEp1, nil, nil, []*proto.TierInfo{protoTier})
	flow := TupleAsFlow(*tuple.New(localIp1, localIp2, proto_tcp, 1000, 80))

	for dir, md := range map[rules.RuleDir]*calc.MatchData{
		rules.RuleDirIngress: enforced.IngressMatchData(),
		rules.RuleDirEgress:  enforced.EgressMatchData(),
	} {
		pending, err := checker.Evaluate(checker.StagedAsEnforced, dir, store, protoEp, &flow)
		Expect(err).NotTo(HaveOccurred())
		Expect(md.TierData["tier1"].TierDefaultActionRuleID.Name).To(Equal("allow-monitoring"), "direction %v", dir)
		Expect(pending).To(Equal([]*calc.RuleID{md.TierData["tier1"].TierDefaultActionRuleID}), "direction %v", dir)
	}
}
