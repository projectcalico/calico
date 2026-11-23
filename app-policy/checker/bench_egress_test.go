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

package checker

// Benchmark for Evaluate() against a single-tier egress allow-list, the second rule-set shape
// measured in production (the first is in bench_test.go). The policy set is policyscale's
// EgressAllowList preset, built from anonymized measurements of a policy dump.
//
//	go test ./app-policy/checker/ -run '^$' -bench BenchmarkEvaluateEgressAllowList \
//	    -benchmem -benchtime 100x -cpu 1
//
// Shape: one tier, ~301 policies with no selector (so all of them apply to every endpoint),
// ~18,600 egress rules, almost all Pass. The tier is a destination allow-list: match a rule
// and leave the tier, match nothing and the tier default denies. Every rule's source block is
// empty; each matches a destination address plus a handful of destination ports.
//
// The three cases below must be read separately, because criterion ordering helps them by
// different amounts. A flow whose port is shared by few rules is rejected on the port
// comparison almost everywhere and never pays for the address criteria; a flow on a popular
// port pays the address criteria on every rule that shares it; and a denied flow walks the
// whole tier no matter what, so ordering can only reduce its per-rule cost, never its scan
// depth. Averaging the three hides that.

import (
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/hack/perf/perfdoc"
)

func BenchmarkEvaluateEgressAllowList(b *testing.B) {
	fx := policyscale.Build(policyscale.EgressAllowList())
	target := fx.EgressTarget()

	// A flow on a port few rules share: rejected on the port comparison nearly everywhere.
	b.Run("TailPort", func(b *testing.B) {
		benchEvaluateEgressAllowList(b, fx, egressCase{
			flow:        egressFlow(target.AddrInCIDR, target.TailPort),
			rulesWalked: target.RulesWalked,
			matches:     true,
		})
	})
	// A flow on the most popular port: ~18% of rules share it and go on to the address check.
	b.Run("PopularPort", func(b *testing.B) {
		benchEvaluateEgressAllowList(b, fx, egressCase{
			flow:        egressFlow(target.AddrInCIDR, target.PopularPort),
			rulesWalked: target.RulesWalked,
			matches:     true,
		})
	})
	// No rule matches, so the walk covers the whole tier and ends in the tier default deny.
	// Ordering cannot reduce the scan depth here, only the cost of each rejected rule.
	b.Run("Denied", func(b *testing.B) {
		benchEvaluateEgressAllowList(b, fx, egressCase{
			flow:        fx.DeniedFlow(policyscale.Egress),
			rulesWalked: fx.Rules(policyscale.Egress),
		})
	})
}

// egressCase is what one benchmark case measures: the flow, how many rules the walk is
// expected to visit, and whether a rule is expected to match it.
type egressCase struct {
	flow        *policyscale.Flow
	rulesWalked int
	matches     bool
}

// egressFlow is a TCP flow from the allow-list's source to the given destination.
func egressFlow(destIP string, destPort int32) *policyscale.Flow {
	return policyscale.NewFlow(policyscale.SourceIP, policyscale.DefaultSourcePort, destIP, int(destPort))
}

func benchEvaluateEgressAllowList(b *testing.B, fx *policyscale.Fixture, c egressCase) {
	for _, engine := range benchEngines {
		b.Run(engine.name, func(b *testing.B) {
			restoreLogging := withBenchLogging(log.WarnLevel)
			defer restoreLogging()

			store, ep := engine.newStore(fx), fx.Endpoint()
			target := fx.EgressTarget()

			// Pre-flight outside the timed loop: prove the walk is the one the case intends, so
			// that a fixture change cannot silently turn a full walk into an early exit.
			trace, err := Evaluate(EnforcedOnly, rules.RuleDirEgress, store, ep, c.flow)
			if err != nil {
				b.Fatalf("evaluation failed: %v", err)
			}
			if c.matches {
				if len(trace) != 1 || trace[0].Action != rules.RuleActionAllow || trace[0].Index != target.RuleIndex {
					b.Fatalf("expected an allow from the target rule at index %d, got %v", target.RuleIndex, trace)
				}
			} else if len(trace) != 1 || trace[0].Action != rules.RuleActionDeny || trace[0].Index != tierDefaultActionIndex {
				b.Fatalf("expected a full walk ending in the tier default deny, got %v", trace)
			}

			b.ReportAllocs()
			rec := perfdoc.Start(b)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchTraceSink, _ = Evaluate(EnforcedOnly, rules.RuleDirEgress, store, ep, c.flow)
			}
			b.StopTimer()
			reportEngineCase(b, rec, fx, engineCase{engine: engine.name, dir: policyscale.Egress, rulesPerOp: c.rulesWalked})
		})
	}
}
