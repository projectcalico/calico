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
// sets. All data is synthetic; the scale parameters and the IP set size distribution
// are anonymized measurements taken from the deployment's diagnostics.
//
// Run with:
//
//	go test ./app-policy/checker/ -run '^$' -bench BenchmarkEvaluateBaselinePolicyScale \
//	    -benchmem -benchtime 100x -cpu 1
//
// The MissingSets variants delete some referenced IP sets from the store, so every
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
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

// baselinePolicyScaleParams describes a policy store dominated by "baseline" policies:
// every policy applies to the endpoint, and almost every rule is a Pass. The defaults
// are the anonymized per-node scale measured in a large production deployment.
type baselinePolicyScaleParams struct {
	seed             int64
	numPolicies      int
	rulesPerPolicy   int
	numDenyRules     int     // Rules with a "deny" action, spread at random; the rest are "pass".
	numAllowRules    int     // As numDenyRules, but "allow".
	ipsetRefFraction float64 // Fraction of rules that reference an IP set.
	numMissingIPSets int     // Referenced IP sets to delete from the store ("IPSet not found" storm).
}

func defaultBaselinePolicyScaleParams() baselinePolicyScaleParams {
	return baselinePolicyScaleParams{
		seed:             20200,
		numPolicies:      294,
		rulesPerPolicy:   68,
		numDenyRules:     10,
		numAllowRules:    1,
		ipsetRefFraction: 0.242, // ~4,838 IP set references across 294*68 rules.
	}
}

// ipSetSizeHistogram is the per-node IP set size distribution measured in the same
// deployment: 3,708 sets, ~256k members in total, dominated by tiny sets with a long
// tail of large ones.
var ipSetSizeHistogram = []struct{ numSets, minSize, maxSize int }{
	{4, 0, 0},
	{3035, 1, 9},
	{446, 10, 99},
	{64, 100, 999},
	{158, 1000, 9999},
	{1, 54566, 54566},
}

// The benchmark flow. TEST-NET addresses; generated IP set members and rule CIDRs all
// come from 10.0.0.0/8, so no rule ever matches on address and the walk covers the
// whole policy set.
const (
	benchSourceIP   = "192.0.2.10"
	benchDestIP     = "198.51.100.20"
	benchSourcePort = 45000
	benchDestPort   = 8080

	// benchSentinelIPSetID is a set containing the flow's addresses; see makeScaleRule.
	benchSentinelIPSetID = "s:bench-sentinel"
)

// benchTraceSink prevents the compiler from eliminating the Evaluate call.
var benchTraceSink []*calc.RuleID

func BenchmarkEvaluateBaselinePolicyScale(b *testing.B) {
	missingSetsParams := func() baselinePolicyScaleParams {
		p := defaultBaselinePolicyScaleParams()
		p.numMissingIPSets = 8
		return p
	}

	b.Run("AllSetsPresent", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			params: defaultBaselinePolicyScaleParams(), logLevel: log.WarnLevel,
		})
	})
	b.Run("MissingSets", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			params: missingSetsParams(), logLevel: log.WarnLevel,
		})
	})
	// As MissingSets but with warnings disabled, so the aggregator drops each miss at its
	// level gate: what separates this from MissingSets is the aggregator's bookkeeping.
	b.Run("MissingSetsLogsOff", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			params: missingSetsParams(), logLevel: log.ErrorLevel,
		})
	})
	// As MissingSets but writing a line per miss, which is what this call site did before
	// it was aggregated: what separates this from MissingSets is what aggregation saves.
	b.Run("MissingSetsUnaggregated", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			params: missingSetsParams(), logLevel: log.WarnLevel, unaggregated: true,
		})
	})
	// Fixed per-Evaluate overhead: the first rule of the first policy matches, so the
	// walk short-circuits immediately.
	b.Run("MatchEarly", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, benchRun{
			params: defaultBaselinePolicyScaleParams(), logLevel: log.WarnLevel, matchEarly: true,
		})
	})
}

// benchRun is one variant: the store to evaluate against, and how the logging the
// evaluation provokes is set up.
type benchRun struct {
	params baselinePolicyScaleParams

	// Level the logger is set to. The missing-set line is reported at Warn, so anything
	// above that closes its level gate.
	logLevel log.Level

	// unaggregated makes the missing-set logger write one line per occurrence rather than
	// one per interval, reproducing what this call site cost before it was aggregated.
	unaggregated bool

	matchEarly bool
}

func benchEvaluateBaselinePolicyScale(b *testing.B, run benchRun) {
	p := run.params

	logger := log.StandardLogger()
	restoreLogging := withBenchLogging(run.logLevel)
	// The counter hooks the standard logger, which is where the checker's aggregator writes.
	counter := &ipsetMissCounter{}
	hooks := make(log.LevelHooks)
	hooks.Add(counter)
	oldHooks := logger.ReplaceHooks(hooks)
	oldMissingIPSets := missingIPSets
	defer func() {
		logger.ReplaceHooks(oldHooks)
		restoreLogging()
		missingIPSets = oldMissingIPSets
	}()

	store, ep, expectedMisses := buildBaselinePolicyStore(p)
	if run.matchEarly {
		addMatchEarlyPolicy(store, ep)
	}
	flow := &MockFlow{
		SourceIP:   net.ParseIP(benchSourceIP),
		DestIP:     net.ParseIP(benchDestIP),
		SourcePort: benchSourcePort,
		DestPort:   benchDestPort,
		Protocol:   6, // TCP
	}

	// Pre-flight outside the timed loop: prove the walk is the intended one and that the
	// number of missing-set lookups matches the analytic count, so misses/op is exact.
	// Counting them means seeing every one, so for this single evaluation the aggregator
	// is given a zero interval, which writes a line per occurrence.
	missingIPSets = newMissingIPSetsLogger()

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
	if logger.IsLevelEnabled(log.WarnLevel) && counter.count.Load() != int64(expectedMisses) {
		b.Fatalf("expected %d missing IP set lookups per Evaluate, got %d",
			expectedMisses, counter.count.Load())
	}

	// The timed loop runs the real logger, at the production interval — unless this is the
	// variant measuring what that interval saves.
	missingIPSets = oldMissingIPSets
	if run.unaggregated {
		missingIPSets = newMissingIPSetsLogger()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchTraceSink, _ = Evaluate(EnforcedOnly, rules.RuleDirIngress, store, ep, flow)
	}
	b.StopTimer()
	b.ReportMetric(float64(expectedMisses), "misses/op")
	rulesWalked := p.numPolicies * p.rulesPerPolicy
	if run.matchEarly {
		rulesWalked = 1
	}
	b.ReportMetric(float64(rulesWalked), "rules/op")
}

// newMissingIPSetsLogger builds a stand-in for the checker's missing-IP-set logger that
// writes a line per occurrence rather than one per interval.
func newMissingIPSetsLogger() *logutils.AggregatingLogger {
	return logutils.NewAggregatingLogger("IPSet not found", "ipsets", logutils.OptAggregationInterval(0))
}

// buildBaselinePolicyStore builds a policy store at the given scale, plus an endpoint
// whose single "perimeter" tier applies every policy. It returns the number of rule
// references to deleted (missing) IP sets, which is exactly the number of missing-set
// lookups one Evaluate of a non-matching flow makes.
func buildBaselinePolicyStore(p baselinePolicyScaleParams) (*policystore.PolicyStore, *proto.WorkloadEndpoint, int) {
	rng := rand.New(rand.NewSource(p.seed))
	store := policystore.NewPolicyStore()
	setIDs := makeScaleIPSets(rng, store)

	// Pick the rule slots that get the few non-Pass actions.
	numRules := p.numPolicies * p.rulesPerPolicy
	specialAction := map[int]string{}
	for len(specialAction) < p.numDenyRules {
		specialAction[rng.Intn(numRules)] = "deny"
	}
	for n := 0; n < p.numAllowRules; {
		slot := rng.Intn(numRules)
		if _, ok := specialAction[slot]; !ok {
			specialAction[slot] = "allow"
			n++
		}
	}

	tier := &proto.TierInfo{Name: "perimeter", DefaultAction: "Deny"}
	var referencedIDs []string
	refCount := map[string]int{}
	ruleIdx := 0
	for i := 0; i < p.numPolicies; i++ {
		policyID := &proto.PolicyID{Name: fmt.Sprintf("policy-%03d", i), Kind: v3.KindGlobalNetworkPolicy}
		policy := &proto.Policy{Tier: tier.Name}
		for j := 0; j < p.rulesPerPolicy; j++ {
			action := specialAction[ruleIdx]
			if action == "" {
				action = "pass"
			}
			rule, refID := makeScaleRule(rng, setIDs, action, p.ipsetRefFraction)
			policy.InboundRules = append(policy.InboundRules, rule)
			if refID != "" {
				if refCount[refID] == 0 {
					referencedIDs = append(referencedIDs, refID)
				}
				refCount[refID]++
			}
			ruleIdx++
		}
		store.PolicyByID[types.ProtoToPolicyID(policyID)] = policy
		tier.IngressPolicies = append(tier.IngressPolicies, policyID)
	}

	// Delete some referenced sets to reproduce the "IPSet not found" storm.
	rng.Shuffle(len(referencedIDs), func(a, b int) {
		referencedIDs[a], referencedIDs[b] = referencedIDs[b], referencedIDs[a]
	})
	expectedMisses := 0
	for _, id := range referencedIDs[:p.numMissingIPSets] {
		delete(store.IPSetByID, id)
		expectedMisses += refCount[id]
	}

	ep := &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{tier}}
	return store, ep, expectedMisses
}

// makeScaleIPSets populates the store with NET-type IP sets (the dominant type in the
// measured deployment: selector and networkset derived sets) following the measured
// size histogram. Members are unique /32s from 10.0.0.0/8.
func makeScaleIPSets(rng *rand.Rand, store *policystore.PolicyStore) []string {
	sentinel := policystore.NewIPSet(proto.IPSetUpdate_NET)
	sentinel.AddString(benchSourceIP + "/32")
	sentinel.AddString(benchDestIP + "/32")
	store.IPSetByID[benchSentinelIPSetID] = sentinel

	var ids []string
	member := 0
	for _, bucket := range ipSetSizeHistogram {
		for i := 0; i < bucket.numSets; i++ {
			id := fmt.Sprintf("s:bench-%04d", len(ids))
			s := policystore.NewIPSet(proto.IPSetUpdate_NET)
			size := bucket.minSize + rng.Intn(bucket.maxSize-bucket.minSize+1)
			for j := 0; j < size; j++ {
				s.AddString(fmt.Sprintf("10.%d.%d.%d/32", member>>16&0xff, member>>8&0xff, member&0xff))
				member++
			}
			store.IPSetByID[id] = s
			ids = append(ids, id)
		}
	}
	return ids
}

// makeScaleRule builds a rule that never matches the benchmark flow. It returns the
// referenced IP set ID, or "" for a rule with no reference.
//
// A rule that references an IP set must reach the set lookup whatever order match()
// evaluates criteria in, and must still miss when the referenced set is absent from
// the store (an absent set is skipped rather than treated as a non-match). Both hold
// by pairing the reference with a negated reference to benchSentinelIPSetID, which
// contains the flow's addresses: if the referenced set is present the lookup misses
// and evaluation stops there; if it is absent the sentinel makes the rule miss.
func makeScaleRule(rng *rand.Rand, setIDs []string, action string, refFraction float64) (*proto.Rule, string) {
	rule := &proto.Rule{Action: action}
	if rng.Float64() < refFraction {
		id := setIDs[rng.Intn(len(setIDs))]
		if rng.Intn(2) == 0 {
			rule.SrcIpSetIds = []string{id}
			rule.NotSrcIpSetIds = []string{benchSentinelIPSetID}
		} else {
			rule.DstIpSetIds = []string{id}
			rule.NotDstIpSetIds = []string{benchSentinelIPSetID}
		}
		return rule, id
	}
	// No IP set reference: guard with a non-matching destination port.
	rule.DstPorts = []*proto.PortRange{{First: 65001, Last: 65001}}
	return rule, ""
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

// ipsetMissCounter is a logrus hook that counts the "IPSet not found" lines written, so
// the benchmark can check the missing-set lookups one evaluation makes while they still
// cost what they cost in production.
type ipsetMissCounter struct {
	count atomic.Int64
}

func (c *ipsetMissCounter) Levels() []log.Level { return []log.Level{log.WarnLevel} }

func (c *ipsetMissCounter) Fire(e *log.Entry) error {
	if e.Message == "IPSet not found" {
		c.count.Add(1)
	}
	return nil
}

// withBenchLogging sets the log level, discards output so the terminal is not part of the
// measurement, and unthrottles the evaluation path's rate-limited loggers. It returns a
// function restoring all of it.
func withBenchLogging(level log.Level) func() {
	logger := log.StandardLogger()
	oldLevel, oldOut := logger.GetLevel(), logger.Out
	restoreLoggers := withUnthrottledEvalPathLogs()

	logger.SetLevel(level)
	// The formatting cost stays in the measurement; a real deployment pays the write too.
	logger.SetOutput(io.Discard)

	return func() {
		logger.SetLevel(oldLevel)
		logger.SetOutput(oldOut)
		restoreLoggers()
	}
}

// withUnthrottledEvalPathLogs replaces the evaluation path's rate-limited loggers with ones
// that never suppress, and returns a function restoring them, so that a benchmark measures
// the cost of every line rather than of whichever few the limiter let through. The
// missing-set and bad-principal sites aggregate instead; see benchEvaluateBaselinePolicyScale
// for how those are handled.
func withUnthrottledEvalPathLogs() func() {
	saved := []**logutils.RateLimitedLogger{
		&rlogBadProtocol, &rlogBadProtocolName,
		&rlogBadCIDR, &rlogBadSelector, &rlogBadRulePath,
	}
	originals := make([]*logutils.RateLimitedLogger, len(saved))
	for i, l := range saved {
		originals[i] = *l
		// A negative interval puts the next-log deadline in the past on every call. The
		// burst keeps the limiter off the WithFields path it takes to report a skip count,
		// which would otherwise allocate on every line the benchmark measures.
		*l = logutils.NewRateLimitedLogger(
			logutils.OptInterval(-time.Nanosecond), logutils.OptBurst(1))
	}
	return func() {
		for i, l := range saved {
			*l = originals[i]
		}
	}
}
