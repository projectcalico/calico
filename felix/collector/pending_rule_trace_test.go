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

	// Control: with the endpoint's policy in the store, the trace is worked out.
	flow := TupleAsFlow(flowTuple1)
	var trace []*calc.RuleID
	var ok bool
	c.policyStoreManager.DoWithLock(func(ps *policystore.PolicyStore) {
		trace, ok = c.computePendingTrace(rules.RuleDirIngress, ps, localEd1, &flow)
	})
	Expect(ok).To(BeTrue())
	Expect(trace).To(Equal(evaluated))

	c.policyStoreManager.DoWithLock(func(ps *policystore.PolicyStore) {
		// The endpoint's tier still names policy1, but its rules are no longer in the store, so the
		// evaluation fails part way through.
		delete(ps.PolicyByID, types.PolicyID{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy})
		trace, ok = c.computePendingTrace(rules.RuleDirIngress, ps, localEd1, &flow)
	})
	Expect(ok).To(BeFalse(), "a failed evaluation says so instead of returning a trace")
	Expect(trace).To(BeNil())

	// And applying that failure to a flow leaves the trace from the last successful evaluation.
	data := NewData(flowTuple1, nil, localEd1)
	data.IngressPendingRuleIDs = evaluated
	c.epStats[flowTuple1] = data
	c.applyPolicyEvalResult(policyEvalResult{
		policyEvalRequest: policyEvalRequest{data: data, tuple: flowTuple1, dstEp: localEd1, seq: data.evalSeq, reason: policyEvalRecalc},
	})
	Expect(data.IngressPendingRuleIDs).To(Equal(evaluated), "the trace from the last successful evaluation should stand")
}
