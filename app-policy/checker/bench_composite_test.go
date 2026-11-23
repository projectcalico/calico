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

// BenchmarkEvaluateComposite measures policyscale's Composite set: both measured shapes applied
// to one endpoint, the reference set the pending-policy evaluation targets are quoted against
// (10,000 new flows/s on a node leaves at most 100 µs per evaluation). Each case is the
// evaluation the flow-log collector makes for pending policies, so staged policies count as
// enforced. POLICYSCALE_POLICIES, POLICYSCALE_RULES_PER_POLICY and POLICYSCALE_IPSETS scale the
// egress set up without a code change.
//
//	go test ./app-policy/checker/ -run '^$' -bench BenchmarkEvaluateComposite \
//	    -benchmem -benchtime 20x -cpu 1

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/hack/perf/perfdoc"
)

func BenchmarkEvaluateComposite(b *testing.B) {
	fx := policyscale.Build(policyscale.ScaleFromEnv(policyscale.Composite()))
	target := fx.EgressTarget()

	// The rule a case's walk must end on, so that rules/op is the walk actually timed. Matching
	// no rule at all, the walk visits every rule and ends at the tier's default action.
	missAll := walkEnd{index: tierDefaultActionIndex, action: rules.RuleActionDeny}
	for _, c := range []struct {
		name        string
		dir         policyscale.Direction
		flow        *policyscale.Flow
		rulesWalked int
		end         walkEnd
	}{
		// Matches no ingress rule, so the walk covers the whole baseline tier.
		{"IngressMissAll", policyscale.Ingress, fx.DeniedFlow(policyscale.Ingress), fx.Rules(policyscale.Ingress), missAll},
		// Matches no egress rule, on the most popular port, so every rule carrying that port
		// checks the address too.
		{"EgressMissAll", policyscale.Egress, fx.DeniedFlow(policyscale.Egress), fx.Rules(policyscale.Egress), missAll},
		// Matches the allow-list's target rule, two thirds of the way down, on a port few rules
		// carry.
		{"EgressTailPort", policyscale.Egress, egressFlow(target.AddrInCIDR, target.TailPort), target.RulesWalked,
			walkEnd{policy: target.Policy, index: target.RuleIndex, action: rules.RuleActionAllow}},
	} {
		b.Run(c.name, func(b *testing.B) {
			for _, engine := range benchEngines {
				b.Run(engine.name, func(b *testing.B) {
					benchEvaluateFlows(b, fx, engine, c.dir, []*policyscale.Flow{c.flow}, c.rulesWalked, &c.end)
				})
			}
		})
	}
}

// walkEnd is the one entry a trace must hold for the walk to have gone where a case says: a rule
// that decides the flow, or the tier's default action after every rule. An empty policy matches
// any.
type walkEnd struct {
	policy string
	index  int
	action rules.RuleAction
}

func (w walkEnd) String() string {
	return fmt.Sprintf("%s[%d]=%v", w.policy, w.index, w.action)
}

func (w walkEnd) matches(trace []*calc.RuleID) bool {
	return len(trace) == 1 && trace[0].Index == w.index && trace[0].Action == w.action &&
		(w.policy == "" || trace[0].Name == w.policy)
}

// benchEvaluateFlows times the pending evaluation of the given flows, one after the other, as one
// op. Before the timed loop it checks every trace against the fixture's oracle, and against end
// when given, so a change to the fixture can't silently turn the walk being timed into a different
// one.
func benchEvaluateFlows(b *testing.B, fx *policyscale.Fixture, engine benchEngine, dir policyscale.Direction, flows []*policyscale.Flow, rulesPerOp int, end *walkEnd) {
	restoreLogging := withBenchLogging(logrus.WarnLevel)
	defer restoreLogging()

	store, ep := engine.load(fx)
	oracle := oracleEvaluator(fx)
	rd := ruleDir(dir)
	for _, f := range flows {
		got, err := engine.evaluate(StagedAsEnforced, rd, store, ep, f)
		if err != nil {
			b.Fatalf("%v: evaluation failed: %v", f, err)
		}
		if want, _ := oracle(StagedAsEnforced, rd, store, ep, f); !sameTrace(got, want) {
			b.Fatalf("%v: trace %s, the oracle expects %s", f, formatTrace(got), formatTrace(want))
		}
		if end != nil && !end.matches(got) {
			b.Fatalf("%v: trace %s doesn't end where the case's walk does, %s", f, formatTrace(got), end)
		}
	}

	b.ReportAllocs()
	rec := perfdoc.Start(b)
	for i := 0; i < b.N; i++ {
		for _, f := range flows {
			benchTraceSink, _ = engine.evaluate(StagedAsEnforced, rd, store, ep, f)
		}
	}
	b.StopTimer()
	c := engineCase{engine: engine.name, dir: dir, rulesPerOp: rulesPerOp}
	if len(flows) > 1 {
		c.flowsPerOp = len(flows)
	}
	reportEngineCase(b, rec, fx, c)
}
