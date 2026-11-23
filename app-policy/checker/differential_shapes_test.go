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

package checker

import (
	"fmt"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

// The rule-shape preset checks every kind of criterion: each flow aimed at a rule, in both
// directions and families, must get the trace the oracle works out from what the dataplanes
// enforce. Flows that can expose a known difference between the evaluator and the dataplanes are
// left out; see policyscale.KnownDifferences.
func TestEvaluateAgreesWithOracleOnRuleShapes(t *testing.T) {
	restoreLogging := withBenchLogging(logrus.ErrorLevel)
	defer restoreLogging()

	fx := policyscale.Build(policyscale.RuleShapes())
	store, ep := fx.NewStore(), fx.Endpoint()
	excluded := policyscale.DifferencesAt(policyscale.Evaluator)

	corpus := differentialCorpus(fx, 7, 100, 1)
	for _, dir := range []policyscale.Direction{policyscale.Ingress, policyscale.Egress} {
		for _, sf := range fx.ShapeFlows(dir, excluded...) {
			corpus = append(corpus, corpusFlow{name: fmt.Sprintf("%s %s %v", dir, sf.Name, sf.Flow), dir: ruleDir(dir), flow: sf.Flow})
		}
	}
	for _, scope := range []PolicyScope{StagedAsEnforced, EnforcedOnly} {
		assertEquivalent(t, fmt.Sprintf("rule shapes scope %d", scope), scope, Evaluate, oracleEvaluator(fx), store, ep, corpus)
	}
}

// Flows the preset marks with a difference the evaluator has on purpose are what that difference
// says: here, a rule whose negated CIDRs are all of one family still matches the other family in
// the evaluator, where the dataplanes leave it out. If this starts failing, the difference is gone
// and its entry in policyscale.KnownDifferences should go too.
func TestEvaluateOneFamilyNegatedCIDRsStillDiffer(t *testing.T) {
	restoreLogging := withBenchLogging(logrus.ErrorLevel)
	defer restoreLogging()

	fx := policyscale.Build(policyscale.RuleShapes())
	store, ep := fx.NewStore(), fx.Endpoint()
	oracle := oracleEvaluator(fx)
	checked := 0
	for _, dir := range []policyscale.Direction{policyscale.Ingress, policyscale.Egress} {
		for _, sf := range fx.ShapeFlows(dir) {
			if len(sf.Differences) != 1 || sf.Differences[0] != policyscale.OneFamilyNegatedCIDRs {
				continue
			}
			got, err := Evaluate(StagedAsEnforced, ruleDir(dir), store, ep, sf.Flow)
			if err != nil {
				t.Fatalf("%s: %v", sf.Name, err)
			}
			want, _ := oracle(StagedAsEnforced, ruleDir(dir), store, ep, sf.Flow)
			if sameTrace(got, want) {
				t.Errorf("%s %s: the evaluator now agrees with the dataplanes: %v", dir, sf.Name, formatTrace(got))
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("the preset marked no flow with the difference")
	}
}

// Named cases for a tier's default action: it is reported against the tier's last policy, and
// any default action but Pass denies, including none at all.
func TestEvaluateNamedTierDefaultCases(t *testing.T) {
	restoreLogging := withBenchLogging(logrus.ErrorLevel)
	defer restoreLogging()

	const tier = "t1"
	ingress := rules.RuleDirIngress
	flow := policyscale.NewFlow("10.0.0.6", 40000, "10.0.0.5", 80)
	build := func(defaultAction string, names ...string) (*policystore.PolicyStore, *proto.WorkloadEndpoint) {
		store := policystore.NewPolicyStore()
		ti := &proto.TierInfo{Name: tier, DefaultAction: defaultAction}
		for _, name := range names {
			id := &proto.PolicyID{Name: name, Kind: v3.KindGlobalNetworkPolicy}
			// One rule for another port, so the flow matches no policy.
			store.PolicyByID[types.ProtoToPolicyID(id)] = &proto.Policy{Tier: tier, InboundRules: []*proto.Rule{
				{Action: "allow", DstPorts: []*proto.PortRange{{First: 1, Last: 1}}},
			}}
			ti.IngressPolicies = append(ti.IngressPolicies, id)
		}
		return store, &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{ti}}
	}
	tierDefault := func(policy string, action rules.RuleAction) *calc.RuleID {
		return calc.NewRuleID(v3.KindGlobalNetworkPolicy, tier, policy, "", tierDefaultActionIndex, ingress, action)
	}
	profileDeny := calc.NewRuleID(v3.KindProfile, profileStr, profileStr, "", tierDefaultActionIndex, ingress, rules.RuleActionDeny)

	for _, c := range []struct {
		name          string
		defaultAction string
		want          []*calc.RuleID
	}{
		{"deny names the last of several policies", "Deny", []*calc.RuleID{tierDefault("p3", rules.RuleActionDeny)}},
		{"pass names the last of several policies", "Pass", []*calc.RuleID{tierDefault("p3", rules.RuleActionPass), profileDeny}},
		{"no default action denies", "", []*calc.RuleID{tierDefault("p3", rules.RuleActionDeny)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			store, ep := build(c.defaultAction, "p1", "p2", "p3")
			for _, scope := range []PolicyScope{StagedAsEnforced, EnforcedOnly} {
				got, err := Evaluate(scope, ingress, store, ep, flow)
				if err != nil {
					t.Fatalf("scope %d: unexpected error: %v", scope, err)
				}
				if !sameTrace(got, c.want) {
					t.Fatalf("scope %d: got %v, want %v", scope, formatTrace(got), formatTrace(c.want))
				}
			}
		})
	}
}
