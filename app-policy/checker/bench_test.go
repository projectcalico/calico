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
// The MissingSets variant deletes some referenced IP sets from the store, which makes
// each evaluation log "IPSet not found" warnings — the signature seen in production
// logs when the policy store is out of sync. The warnings/op metric ties the two
// together: if production logs show those warnings spaced T apart, the implied
// per-evaluation wall time is T x warnings/op, which can be compared against the
// measured ns/op to judge whether a node is evaluation-bound or pacing on something
// else. Note that the benchmark discards log output, so a real deployment pays the
// log write on top of the formatting cost measured here.

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync/atomic"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
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

// benchTraceSink prevents the compiler from eliminating the Evaluate call.
var benchTraceSink []*calc.RuleID

func BenchmarkEvaluateBaselinePolicyScale(b *testing.B) {
	b.Run("AllSetsPresent", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, defaultBaselinePolicyScaleParams(), log.WarnLevel, false)
	})
	b.Run("MissingSets", func(b *testing.B) {
		p := defaultBaselinePolicyScaleParams()
		p.numMissingIPSets = 8
		benchEvaluateBaselinePolicyScale(b, p, log.WarnLevel, false)
	})
	// As MissingSets but with warnings disabled, to isolate the cost of formatting the
	// "IPSet not found" warnings.
	b.Run("MissingSetsLogsOff", func(b *testing.B) {
		p := defaultBaselinePolicyScaleParams()
		p.numMissingIPSets = 8
		benchEvaluateBaselinePolicyScale(b, p, log.ErrorLevel, false)
	})
	// Fixed per-Evaluate overhead: the first rule of the first policy matches, so the
	// walk short-circuits immediately.
	b.Run("MatchEarly", func(b *testing.B) {
		benchEvaluateBaselinePolicyScale(b, defaultBaselinePolicyScaleParams(), log.WarnLevel, true)
	})
}

func benchEvaluateBaselinePolicyScale(b *testing.B, p baselinePolicyScaleParams, level log.Level, matchEarly bool) {
	logger := log.StandardLogger()
	oldLevel, oldOut := logger.GetLevel(), logger.Out
	counter := &ipsetMissCounter{}
	hooks := make(log.LevelHooks)
	hooks.Add(counter)
	oldHooks := logger.ReplaceHooks(hooks)
	defer func() {
		logger.SetLevel(oldLevel)
		logger.SetOutput(oldOut)
		logger.ReplaceHooks(oldHooks)
	}()
	log.SetLevel(level)
	// Discard output so we don't benchmark the terminal; the formatting cost stays, but
	// a real deployment pays the log write too.
	log.SetOutput(io.Discard)

	store, ep, expectedWarns := buildBaselinePolicyStore(p)
	if matchEarly {
		addMatchEarlyPolicy(store, ep)
	}
	flow := &MockFlow{
		// TEST-NET addresses; generated IP set members all come from 10.0.0.0/8, so no
		// rule ever matches and the walk covers the whole policy set.
		SourceIP:   net.ParseIP("192.0.2.10"),
		DestIP:     net.ParseIP("198.51.100.20"),
		SourcePort: 45000,
		DestPort:   8080,
		Protocol:   6, // TCP
	}

	// Pre-flight outside the timed loop: prove the walk is the intended one and that
	// the warning count matches the analytic count, so that warnings/op is exact.
	trace := Evaluate(rules.RuleDirIngress, store, ep, flow)
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
		benchTraceSink = Evaluate(rules.RuleDirIngress, store, ep, flow)
	}
	b.StopTimer()
	b.ReportMetric(float64(counter.count.Load())/float64(b.N), "warnings/op")
	rulesWalked := p.numPolicies * p.rulesPerPolicy
	if matchEarly {
		rulesWalked = 1
	}
	b.ReportMetric(float64(rulesWalked), "rules/op")
}

// buildBaselinePolicyStore builds a policy store at the given scale, plus an endpoint
// whose single "perimeter" tier applies every policy. It returns the number of rule
// references to deleted (missing) IP sets, which is exactly the number of "IPSet not
// found" warnings one Evaluate of a non-matching flow emits.
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
	expectedWarns := 0
	for _, id := range referencedIDs[:p.numMissingIPSets] {
		delete(store.IPSetByID, id)
		expectedWarns += refCount[id]
	}

	ep := &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{tier}}
	return store, ep, expectedWarns
}

// makeScaleIPSets populates the store with NET-type IP sets (the dominant type in the
// measured deployment: selector and networkset derived sets) following the measured
// size histogram. Members are unique /32s from 10.0.0.0/8.
func makeScaleIPSets(rng *rand.Rand, store *policystore.PolicyStore) []string {
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

// makeScaleRule builds a rule that never matches the benchmark flow but still pays the
// full match cost. Rules that reference an IP set are shaped so the set lookup always
// executes:
//   - src refs guard with a non-matching source port, which match() evaluates after the
//     src IP set lookup; the guard is needed because a missing src set is skipped rather
//     than treated as a non-match.
//   - dst refs guard with a non-matching destination port for the same reason, and
//     leave the source criteria empty so evaluation reaches the destination.
//
// It returns the referenced IP set ID, or "" for a rule with no reference.
func makeScaleRule(rng *rand.Rand, setIDs []string, action string, refFraction float64) (*proto.Rule, string) {
	rule := &proto.Rule{Action: action}
	if rng.Float64() < refFraction {
		id := setIDs[rng.Intn(len(setIDs))]
		if rng.Intn(2) == 0 {
			rule.SrcIpSetIds = []string{id}
			rule.SrcPorts = []*proto.PortRange{{First: 65001, Last: 65001}}
		} else {
			rule.DstIpSetIds = []string{id}
			rule.DstPorts = []*proto.PortRange{{First: 65001, Last: 65001}}
		}
		return rule, id
	}
	// No IP set reference: guard with a non-matching destination port so the match walks
	// the whole chain (including the per-rule dst-IP-port formatting) before failing.
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

// ipsetMissCounter is a logrus hook that counts "IPSet not found" warnings, so the
// benchmark can report warnings per evaluation.
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
