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

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

// The rule-shape preset checks every kind of criterion: each flow aimed at a rule, in both
// directions and families, must get the trace the oracle works out from what the dataplanes
// enforce. Flows that can expose a known difference between the evaluator and the dataplanes are
// left out; see policyscale.KnownDifferences.
func TestEvaluateAgreesWithOracleOnRuleShapes(t *testing.T) {
	restoreLogging := withBenchLogging(logrus.ErrorLevel)
	defer restoreLogging()

	// Some policies staged, so that the two scopes give different traces.
	spec := policyscale.RuleShapes()
	spec.Shapes.Staged = true
	fx := policyscale.Build(spec)
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
