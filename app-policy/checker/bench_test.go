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

// Benchmark for Evaluate() at the scale observed in a large production deployment:
// hundreds of "baseline" policies that apply to every endpoint, and thousands of IP
// sets. The policy set is policyscale's Baseline preset, built from anonymized
// measurements of the deployment's diagnostics; policyscale also renders it as Calico
// resources, so this number and a node-level run describe the same set.
//
// Run with:
//
//	go test ./app-policy/checker/ -run '^$' -bench BenchmarkEvaluateBaselinePolicyScale \
//	    -benchmem -benchtime 100x -cpu 1
//
// The MissingSets variants leave some referenced IP sets out of the store, so every
// evaluation looks up sets that are not there — the condition behind the "IPSet not
// found" logs seen in production when the policy store is out of sync. Those lookups
// are aggregated into one line per interval, so the variants measure what that leaves
// on the hot path: MissingSets pays the aggregator's per-lookup bookkeeping, LogsOff
// has the level gate closed so it pays nothing at all, and Unaggregated writes a line
// per lookup, as this call site did before it was aggregated. The misses/op metric is
// the number of missing-set lookups one evaluation makes, checked against the analytic
// count before the timed loop. Note that the benchmark discards log output, so a real
// deployment pays the log write on top of the formatting cost measured here.

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/hack/perf/perfdoc"
	"github.com/projectcalico/calico/lib/logrusr"
	log "github.com/projectcalico/calico/lib/std/log"
)

// benchTraceSink prevents the compiler from eliminating the Evaluate call.
var benchTraceSink []*calc.RuleID

func BenchmarkEvaluateBaselinePolicyScale(b *testing.B) {
	missingSetsSpec := func() policyscale.Spec {
		spec := policyscale.Baseline()
		spec.Baseline.MissingIPSets = 8
		return spec
	}

	b.Run("AllSetsPresent", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			spec: policyscale.Baseline(), logLevel: logrus.WarnLevel,
		})
	})
	b.Run("MissingSets", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			spec: missingSetsSpec(), logLevel: logrus.WarnLevel,
		})
	})
	// As MissingSets but with warnings disabled, so the aggregator drops each miss at its
	// level gate: what separates this from MissingSets is the aggregator's bookkeeping.
	b.Run("MissingSetsLogsOff", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			spec: missingSetsSpec(), logLevel: logrus.ErrorLevel,
		})
	})
	// As MissingSets but writing a line per miss, which is what this call site did before
	// it was aggregated: what separates this from MissingSets is what aggregation saves.
	b.Run("MissingSetsUnaggregated", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			spec: missingSetsSpec(), logLevel: logrus.WarnLevel, unaggregated: true,
		})
	})
	// Fixed per-Evaluate overhead: the first rule of the first policy matches, so the
	// walk short-circuits immediately.
	b.Run("MatchEarly", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			spec: policyscale.Baseline(), logLevel: logrus.WarnLevel, matchEarly: true,
		})
	})
}

// benchRun is one variant: the policy set to evaluate against, and how the logging that
// the evaluation provokes is set up.
type benchRun struct {
	spec policyscale.Spec

	// Level the log backend is set to. The missing-set line is reported at Warn, so
	// anything above that closes its level gate.
	logLevel logrus.Level

	// unaggregated makes the missing-set logger write one line per occurrence rather than
	// one per interval, reproducing what this call site cost before it was aggregated.
	unaggregated bool

	matchEarly bool
}

func benchEvaluateBaselinePolicyScale(b *testing.B, run benchRun) {
	fx := policyscale.Build(run.spec)
	for _, engine := range benchEngines {
		b.Run(engine.name, func(b *testing.B) {
			benchEvaluateBaselinePolicyScaleWith(b, run, fx, engine)
		})
	}
}

func benchEvaluateBaselinePolicyScaleWith(b *testing.B, run benchRun, fx *policyscale.Fixture, engine benchEngine) {
	logger := logrus.StandardLogger()
	restoreLogging := withBenchLogging(run.logLevel)
	oldMissingIPSets := missingIPSets
	defer func() {
		restoreLogging()
		missingIPSets = oldMissingIPSets
	}()

	store, ep := engine.newStore(fx), fx.Endpoint()
	expectedMisses := fx.MissingSetReferences()
	if run.matchEarly {
		addMatchEarlyPolicy(store, ep)
	}
	flow := fx.DeniedFlow(policyscale.Ingress)

	// Pre-flight outside the timed loop: prove the walk is the intended one and that the
	// number of missing-set lookups matches the analytic count, so misses/op is exact.
	// Counting them means seeing every one, so for this single evaluation the aggregator
	// is given a zero interval, which writes a line per occurrence.
	counter := &ipsetMissCounter{Logger: log.Default()}
	missingIPSets = newMissingIPSetsLogger(counter)

	trace, err := Evaluate(EnforcedOnly, rules.RuleDirIngress, store, ep, flow)
	if err != nil {
		b.Fatalf("pre-flight Evaluate failed: %v", err)
	}
	if run.matchEarly {
		if len(trace) != 1 || trace[0].Action != rules.RuleActionAllow || trace[0].Index != 0 {
			b.Fatalf("expected an immediate allow from the match-early policy, got %v", trace)
		}
	} else {
		if len(trace) != 1 || trace[0].Action != rules.RuleActionDeny || trace[0].Index != -1 {
			b.Fatalf("expected a full walk ending in the tier default deny, got %v", trace)
		}
	}
	if logger.IsLevelEnabled(logrus.WarnLevel) && counter.count.Load() != int64(expectedMisses) {
		b.Fatalf("expected %d missing IP set lookups per Evaluate, got %d",
			expectedMisses, counter.count.Load())
	}

	// The timed loop runs the real logger, at the production interval — unless this is the
	// variant measuring what that interval saves.
	missingIPSets = oldMissingIPSets
	if run.unaggregated {
		missingIPSets = newMissingIPSetsLogger(nil)
	}

	b.ReportAllocs()
	rec := perfdoc.Start(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchTraceSink, _ = Evaluate(EnforcedOnly, rules.RuleDirIngress, store, ep, flow)
	}
	b.StopTimer()
	b.ReportMetric(float64(expectedMisses), "misses/op")
	rulesWalked := fx.Rules(policyscale.Ingress)
	if run.matchEarly {
		rulesWalked = 1
	}
	reportEngineCase(b, rec, fx, engineCase{
		engine:     engine.name,
		dir:        policyscale.Ingress,
		rulesPerOp: rulesWalked,
		fields:     map[string]any{"misses_per_op": expectedMisses},
	})
}

// newMissingIPSetsLogger builds a stand-in for the checker's missing-IP-set logger that
// writes a line per occurrence rather than one per interval, to the given Logger or to
// the registered default when it is nil.
func newMissingIPSetsLogger(target log.Logger) *log.AggregatingLogger {
	opts := []log.AggregatingLoggerOpt{log.OptInterval(0)}
	if target != nil {
		opts = append(opts, log.OptLogger(target))
	}
	return log.NewAggregatingLogger("IPSet not found", "ipsets", opts...)
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

// ipsetMissCounter counts the "IPSet not found" lines written through it and passes
// everything on to the Logger it wraps, so the benchmark can count missing-set lookups
// while they still cost what they cost in production. Embedding the Logger is also what
// keeps the level gate honest: Enabled comes from the wrapped backend.
type ipsetMissCounter struct {
	log.Logger
	count atomic.Int64
}

func (c *ipsetMissCounter) Warn(msg string, args ...any) {
	if msg == "IPSet not found" {
		c.count.Add(1)
	}
	c.Logger.Warn(msg, args...)
}

// withBenchLogging sets the log level, discards output so the terminal is not part of the
// measurement, registers the logrus backend behind the lib/std/log facade, and unthrottles the
// evaluation path's rate-limited loggers. It returns a function restoring all of it.
//
// The facade discards everything until a backend is registered, so without that the benchmark
// would measure a path no deployment runs, and the miss count would come out at zero.
func withBenchLogging(level logrus.Level) func() {
	logger := logrus.StandardLogger()
	oldLevel, oldOut := logger.GetLevel(), logger.Out
	oldDefault := log.Default()
	restoreLoggers := withUnthrottledEvalPathLogs()

	logger.SetLevel(level)
	// The formatting cost stays in the measurement; a real deployment pays the write too.
	logger.SetOutput(io.Discard)
	log.SetDefaultLogger(logrusr.New(logger))

	return func() {
		logger.SetLevel(oldLevel)
		logger.SetOutput(oldOut)
		log.SetDefaultLogger(oldDefault)
		restoreLoggers()
	}
}

// withUnthrottledEvalPathLogs replaces the evaluation path's rate-limited loggers with ones
// that never suppress, and returns a function restoring them. The benchmark counts every
// occurrence, which is the point of it — production gets the throttled loggers, and the
// emitted line's "logsSkipped" field carries the count this benchmark reports directly.
func withUnthrottledEvalPathLogs() func() {
	saved := []**logrusr.RateLimitedLogger{
		&rlogBadProtocol, &rlogBadProtocolName,
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
