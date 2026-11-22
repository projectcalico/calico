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
	"github.com/projectcalico/calico/felix/config"
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
// flow-log fields agree when nothing would change. Both sides are built from one tier by Felix's
// own code, with a different last policy in each direction.
func TestPendingTierDefaultActionNamesSamePolicyAsEnforced(t *testing.T) {
	RegisterTestingT(t)

	policies := []struct {
		key   model.PolicyKey
		types []string
	}{
		{model.PolicyKey{Name: "allow-dns", Kind: v3.KindGlobalNetworkPolicy}, nil},
		{model.PolicyKey{Name: "allow-https", Namespace: "ns1", Kind: v3.KindNetworkPolicy}, []string{"egress"}},
		{model.PolicyKey{Name: "allow-monitoring", Kind: v3.KindGlobalNetworkPolicy}, []string{"ingress"}},
	}

	tier := calc.NewTierInfo("tier1")
	tier.Valid = true
	tier.DefaultAction = v3.Deny
	store := policystore.NewPolicyStore()
	for _, p := range policies {
		md := calc.ExtractPolicyMetadata(&model.Policy{Tier: "tier1", Types: p.types})
		tier.OrderedPolicies = append(tier.OrderedPolicies, calc.PolKV{Key: p.key, Value: &md})
		id := &proto.PolicyID{Name: p.key.Name, Namespace: p.key.Namespace, Kind: p.key.Kind}
		// No rules, so every flow ends at the tier's default action.
		store.PolicyByID[types.ProtoToPolicyID(id)] = &proto.Policy{Tier: "tier1", Namespace: p.key.Namespace}
	}
	tiers := []calc.TierInfo{*tier}

	enforced := calc.NewEndpointLookupsCache().CreateLocalEndpointData(localWlEPKey1, localWlEp1, tiers)

	// The policy store holds the endpoint as the event sequencer sends it.
	var protoEp *proto.WorkloadEndpoint
	es := calc.NewEventSequencer(config.New())
	es.Callback = func(msg any) {
		if u, ok := msg.(*proto.WorkloadEndpointUpdate); ok {
			protoEp = u.Endpoint
		}
	}
	es.OnEndpointTierUpdate(localWlEPKey1, localWlEp1, nil, nil, tiers)
	es.Flush()
	Expect(protoEp).NotTo(BeNil())

	flow := TupleAsFlow(*tuple.New(localIp1, localIp2, proto_tcp, 1000, 80))
	for _, tc := range []struct {
		dir  rules.RuleDir
		md   *calc.MatchData
		want string
	}{
		{rules.RuleDirIngress, enforced.IngressMatchData(), "allow-monitoring"},
		{rules.RuleDirEgress, enforced.EgressMatchData(), "allow-https"},
	} {
		eot := tc.md.TierData["tier1"].TierDefaultActionRuleID
		Expect(eot.Name).To(Equal(tc.want), "direction %v", tc.dir)

		pending, err := checker.Evaluate(checker.StagedAsEnforced, tc.dir, store, protoEp, &flow)
		Expect(err).NotTo(HaveOccurred())
		Expect(pending).To(Equal([]*calc.RuleID{eot}), "direction %v", tc.dir)
	}
}
