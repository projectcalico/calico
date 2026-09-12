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

// Benchmarks for Evaluate() at the scale observed in a large production deployment. The policy
// sets come from app-policy/policyscale, which also renders them as Calico resources and drives
// the collector-level benchmark, so the numbers here, there and on a node describe the same sets.
//
// BenchmarkEvaluateBaselinePolicyScale: hundreds of "baseline" policies that apply to every
// endpoint, and thousands of IP sets. Run with:
//
//	go test ./app-policy/checker/ -run '^$' -bench BenchmarkEvaluateBaselinePolicyScale \
//	    -benchmem -benchtime 100x -cpu 1
//
// The MissingSets variant deletes some referenced IP sets from the store, which makes
// each evaluation log "IPSet not found" warnings — the signature seen in production
// logs when the policy store is out of sync. The warnings/op metric ties the two
// together: if production logs show those warnings spaced T apart, the implied
// per-evaluation wall time is T x warnings/op, which can be compared against the
// measured ns/op to judge whether a node is evaluation-bound or pacing on something
// else. Note that the benchmark discards log output, so a real deployment pays the
// log write on top of the formatting cost measured here.
//
// BenchmarkEvaluateComposite applies both measured shapes to one endpoint: the reference set the
// PMREQ-954 target (10k flows/s per node, so at most 100 µs per evaluation) is quoted against.

import (
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/lib/logrusr"
)

// benchTraceSink prevents the compiler from eliminating the Evaluate call.
var benchTraceSink []*calc.RuleID

func BenchmarkEvaluateBaselinePolicyScale(b *testing.B) {
	b.Run("AllSetsPresent", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, policyscale.Baseline(), log.WarnLevel, false)
	})
	b.Run("MissingSets", func(b *testing.B) {
		spec := policyscale.Baseline()
		spec.Baseline.MissingIPSets = 8
		benchEvaluateBaselinePolicyScale(b, spec, log.WarnLevel, false)
	})
	// As MissingSets but with warnings disabled, to isolate the cost of formatting the
	// "IPSet not found" warnings.
	b.Run("MissingSetsLogsOff", func(b *testing.B) {
		spec := policyscale.Baseline()
		spec.Baseline.MissingIPSets = 8
		benchEvaluateBaselinePolicyScale(b, spec, log.ErrorLevel, false)
	})
	// Fixed per-Evaluate overhead: the first rule of the first policy matches, so the
	// walk short-circuits immediately.
	b.Run("MatchEarly", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, policyscale.Baseline(), log.WarnLevel, true)
	})
}

// BenchmarkEvaluateComposite measures the reference set in the three cases that matter for the
// collector: an ingress flow that misses every baseline rule, an egress flow that misses every
// allow-list rule, and an egress flow that matches the target rule on a port few rules share.
func BenchmarkEvaluateComposite(b *testing.B) {
	_, restoreLogging := withBenchLogging(log.WarnLevel)
	defer restoreLogging()

	fx := policyscale.Build(policyscale.Composite())
	store, ep := fx.NewStore(), fx.Endpoint()
	target := fx.EgressTarget()

	cases := []struct {
		name  string
		dir   rules.RuleDir
		flow  *policyscale.Flow
		walk  int
		final rules.RuleAction
		index int
	}{
		{"IngressMissAll", rules.RuleDirIngress, fx.DeniedFlow(policyscale.Ingress), fx.Rules(policyscale.Ingress), rules.RuleActionDeny, tierDefaultActionIndex},
		{"EgressMissAll", rules.RuleDirEgress, fx.DeniedFlow(policyscale.Egress), fx.Rules(policyscale.Egress), rules.RuleActionDeny, tierDefaultActionIndex},
		{"EgressTailPort", rules.RuleDirEgress, policyscale.NewFlow(policyscale.SourceIP, policyscale.DefaultSourcePort, target.AddrInCIDR, int(target.TailPort)), target.RulesWalked, rules.RuleActionAllow, target.RuleIndex},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			trace, err := Evaluate(StagedAsEnforced, c.dir, store, ep, c.flow)
			if err != nil {
				b.Fatalf("evaluation failed: %v", err)
			}
			if len(trace) != 1 || trace[0].Action != c.final || trace[0].Index != c.index {
				b.Fatalf("expected %v at index %d, got %v", c.final, c.index, trace)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchTraceSink, _ = Evaluate(StagedAsEnforced, c.dir, store, ep, c.flow)
			}
			b.StopTimer()
			b.ReportMetric(float64(c.walk), "rules/op")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(c.walk), "ns/rule")
		})
	}
}

// BenchmarkEvaluateVerdictCache measures Evaluate with the verdict cache in front of it, on the
// sampler's flow model: new flows aimed uniformly at the walk, a tenth missing every rule, and a
// fraction repeating an earlier flow on a new source port, which is what the collector sees. The
// sampler's allocation of each flow is inside the timed loop, so allocs/op includes one for it.
func BenchmarkEvaluateVerdictCache(b *testing.B) {
	_, restoreLogging := withBenchLogging(log.WarnLevel)
	defer restoreLogging()

	fx := policyscale.Build(policyscale.Composite())
	ep := fx.Endpoint()
	for _, c := range []struct {
		name   string
		cache  bool
		repeat float64
	}{
		{"Uncached/Repeat50", false, 0.5},
		{"Cached/Repeat0", true, 0},
		{"Cached/Repeat50", true, 0.5},
		{"Cached/Repeat90", true, 0.9},
	} {
		b.Run(c.name, func(b *testing.B) {
			store := fx.NewStore()
			stats := &policystore.VerdictCacheStats{}
			if c.cache {
				store.Verdicts = policystore.NewVerdictCache(1<<16, stats)
			}
			s := fx.NewSampler(1, policyscale.FlowModel{Direction: policyscale.Egress, MissFraction: 0.1, RepeatFraction: c.repeat})
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchTraceSink, _ = Evaluate(StagedAsEnforced, rules.RuleDirEgress, store, ep, s.Next())
			}
			b.StopTimer()
			if c.cache {
				total := stats.Hits.Load() + stats.Misses.Load()
				b.ReportMetric(float64(stats.Hits.Load())/float64(max(total, 1)), "hit-ratio")
			}
		})
	}
}

func benchEvaluateBaselinePolicyScale(b *testing.B, spec policyscale.Spec, level log.Level, matchEarly bool) {
	logger := log.StandardLogger()
	counter, restoreLogging := withBenchLogging(level)
	defer restoreLogging()

	fx := policyscale.Build(spec)
	store, ep := fx.NewStore(), fx.Endpoint()
	expectedWarns := fx.MissingSetReferences()
	if matchEarly {
		addMatchEarlyPolicy(store, ep)
	}
	flow := fx.DeniedFlow(policyscale.Ingress)

	// Pre-flight outside the timed loop: prove the walk is the intended one and that
	// the warning count matches the analytic count, so that warnings/op is exact.
	trace, _ := Evaluate(EnforcedOnly, rules.RuleDirIngress, store, ep, flow)
	if matchEarly {
		if len(trace) != 1 || trace[0].Action != rules.RuleActionAllow || trace[0].Index != 0 {
			b.Fatalf("expected an immediate allow from the match-early policy, got %v", trace)
		}
	} else {
		if len(trace) != 1 || trace[0].Action != rules.RuleActionDeny || trace[0].Index != -1 {
			b.Fatalf("expected a full walk ending in the tier default deny, got %v", trace)
		}
	}
	if logger.IsLevelEnabled(log.WarnLevel) && counter.count.Load() != int64(expectedWarns) {
		b.Fatalf("expected %d 'IPSet not found' warnings per Evaluate, got %d",
			expectedWarns, counter.count.Load())
	}
	counter.count.Store(0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchTraceSink, _ = Evaluate(EnforcedOnly, rules.RuleDirIngress, store, ep, flow)
	}
	b.StopTimer()
	b.ReportMetric(float64(counter.count.Load())/float64(b.N), "warnings/op")
	rulesWalked := fx.Rules(policyscale.Ingress)
	if matchEarly {
		rulesWalked = 1
	}
	b.ReportMetric(float64(rulesWalked), "rules/op")
}

// addMatchEarlyPolicy prepends a policy whose first rule matches any flow.
func addMatchEarlyPolicy(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint) {
	policyID := &proto.PolicyID{Name: "policy-match-early", Kind: v3.KindGlobalNetworkPolicy}
	store.PolicyByID[types.ProtoToPolicyID(policyID)] = &proto.Policy{
		Tier:         ep.Tiers[0].Name,
		InboundRules: []*proto.Rule{{Action: "allow"}},
	}
	ep.Tiers[0].IngressPolicies = append([]*proto.PolicyID{policyID}, ep.Tiers[0].IngressPolicies...)
}

// ipsetMissCounter is a logrus hook that counts "IPSet not found" warnings, so the
// benchmark can report warnings per evaluation.
type ipsetMissCounter struct {
	count atomic.Int64
}

func (c *ipsetMissCounter) Levels() []log.Level { return []log.Level{log.WarnLevel} }

func (c *ipsetMissCounter) Fire(e *log.Entry) error {
	// The message carries the set ID, so match on the prefix.
	if strings.HasPrefix(e.Message, "IPSet not found") {
		c.count.Add(1)
	}
	return nil
}

// withBenchLogging sets the log level, discards output so the terminal is not part of the
// measurement, installs the "IPSet not found" counter, and unthrottles the evaluation path's
// rate-limited loggers. It returns the counter and a function restoring everything.
func withBenchLogging(level log.Level) (*ipsetMissCounter, func()) {
	logger := log.StandardLogger()
	oldLevel, oldOut := logger.GetLevel(), logger.Out
	counter := &ipsetMissCounter{}
	hooks := make(log.LevelHooks)
	hooks.Add(counter)
	oldHooks := logger.ReplaceHooks(hooks)
	restoreLoggers := withUnthrottledEvalPathLogs()

	logger.SetLevel(level)
	// The formatting cost stays in the measurement; a real deployment pays the write too.
	logger.SetOutput(io.Discard)

	return counter, func() {
		logger.SetLevel(oldLevel)
		logger.SetOutput(oldOut)
		logger.ReplaceHooks(oldHooks)
		restoreLoggers()
	}
}

// withUnthrottledEvalPathLogs replaces the evaluation path's rate-limited loggers with ones
// that never suppress, and returns a function restoring them. The warnings/op metric counts
// every occurrence, which is the point of it — production gets the throttled loggers, and the
// emitted line's "logsSkipped" field carries the count this benchmark reports directly.
func withUnthrottledEvalPathLogs() func() {
	saved := []**logrusr.RateLimitedLogger{
		&rlogIPSetMissing, &rlogBadPrincipal, &rlogBadProtocol, &rlogBadProtocolName,
		&rlogBadCIDR, &rlogBadSelector, &rlogBadRulePath,
	}
	originals := make([]*logrusr.RateLimitedLogger, len(saved))
	for i, l := range saved {
		originals[i] = *l
		// A negative interval puts the next-log deadline in the past on every call. The
		// burst keeps the limiter off the WithFields path it takes to report a skip count,
		// which would otherwise allocate on every line the benchmark measures.
		*l = logrusr.NewRateLimitedLogger(
			logrusr.OptInterval(-time.Nanosecond), logrusr.OptBurst(1))
	}
	return func() {
		for i, l := range saved {
			*l = originals[i]
		}
	}
}
