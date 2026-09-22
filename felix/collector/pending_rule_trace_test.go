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

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
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
