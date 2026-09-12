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

import (
	"fmt"
	"net"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

// TestCachedEvaluateAgreesWithUncached runs the differential corpus, plus a repeat-heavy sample so
// that hits are exercised as well as misses, through a cached store and an uncached one, twice,
// so the second pass is answered from the cache.
func TestCachedEvaluateAgreesWithUncached(t *testing.T) {
	_, restoreLogging := withBenchLogging(log.ErrorLevel)
	defer restoreLogging()

	for _, c := range []struct {
		name string
		spec policyscale.Spec
	}{
		{"egress allow-list", policyscale.EgressAllowList()},
		{"composite", policyscale.Composite()},
	} {
		t.Run(c.name, func(t *testing.T) {
			fx := policyscale.Build(c.spec)
			plain, ep := fx.NewStore(), fx.Endpoint()
			stats := &policystore.VerdictCacheStats{}
			cached := fx.NewStore()
			cached.Verdicts = policystore.NewVerdictCache(1<<16, stats)

			corpus := differentialCorpus(fx, 13, 150, 401)
			for _, dir := range []policyscale.Direction{policyscale.Ingress, policyscale.Egress} {
				if fx.Rules(dir) == 0 {
					continue
				}
				s := fx.NewSampler(17, policyscale.FlowModel{Direction: dir, MissFraction: 0.1, RepeatFraction: 0.8})
				for i := 0; i < 300; i++ {
					corpus = append(corpus, corpusFlow{name: fmt.Sprintf("%s repeat-heavy %d", dir, i), dir: ruleDir(dir), flow: s.Next()})
				}
			}

			viaCache := func(scope PolicyScope, dir rules.RuleDir, _ *policystore.PolicyStore, ep *proto.WorkloadEndpoint, flow Flow) ([]*calc.RuleID, error) {
				return Evaluate(scope, dir, cached, ep, flow)
			}
			for pass := 0; pass < 2; pass++ {
				for _, scope := range []PolicyScope{StagedAsEnforced, EnforcedOnly} {
					assertEquivalent(t, fmt.Sprintf("%s pass %d scope %d", c.name, pass, scope), scope, viaCache, Evaluate, plain, ep, corpus)
				}
			}
			// The second pass repeats every flow of the first, so at least that many hits.
			if hits, misses := stats.Hits.Load(), stats.Misses.Load(); hits < uint64(2*len(corpus)) || misses == 0 {
				t.Errorf("cache traffic: %d hits, %d misses over %d flows x 2 scopes x 2 passes", hits, misses, len(corpus))
			}
			if stats.Resets.Load() != 0 || stats.Evictions.Load() != 0 {
				t.Errorf("unexpected resets %d / evictions %d", stats.Resets.Load(), stats.Evictions.Load())
			}
		})
	}
}

func TestCachedEvaluateNamedCases(t *testing.T) {
	_, restoreLogging := withBenchLogging(log.ErrorLevel)
	defer restoreLogging()
	runNamedCases(t, cachedEvaluator(t))
}

// cachedEvaluator attaches a cache to the case's store, evaluates twice so that the second answer
// is served from the cache, checks the two agree, and returns the second.
func cachedEvaluator(t *testing.T) evaluator {
	return func(scope PolicyScope, dir rules.RuleDir, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, flow Flow) ([]*calc.RuleID, error) {
		if store.Verdicts == nil {
			store.Verdicts = policystore.NewVerdictCache(1024, nil)
		}
		first, err1 := Evaluate(scope, dir, store, ep, flow)
		second, err2 := Evaluate(scope, dir, store, ep, flow)
		if (err1 != nil) != (err2 != nil) || !sameTrace(first, second) {
			t.Errorf("cached evaluation differs from the first: %v (%v) vs %v (%v)", formatTrace(first), err1, formatTrace(second), err2)
		}
		return second, err2
	}
}

// TestVerdictCacheFollowsStoreUpdates feeds a store through ProcessUpdate, as the collector does,
// and checks that a cached verdict is dropped as soon as anything the verdict depends on changes.
func TestVerdictCacheFollowsStoreUpdates(t *testing.T) {
	_, restoreLogging := withBenchLogging(log.ErrorLevel)
	defer restoreLogging()

	stats := &policystore.VerdictCacheStats{}
	store := policystore.NewPolicyStore()
	store.Verdicts = policystore.NewVerdictCache(1024, stats)
	apply := func(u *proto.ToDataplane) { store.ProcessUpdate("per-host-policies", u) }

	pID := &proto.PolicyID{Name: "p", Kind: v3.KindGlobalNetworkPolicy}
	apply(&proto.ToDataplane{Payload: &proto.ToDataplane_IpsetUpdate{IpsetUpdate: &proto.IPSetUpdate{Id: "s", Type: proto.IPSetUpdate_NET}}})
	apply(&proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{ActivePolicyUpdate: &proto.ActivePolicyUpdate{
		Id: pID, Policy: &proto.Policy{Tier: "t", InboundRules: []*proto.Rule{{Action: "allow", DstIpSetIds: []string{"s"}}}},
	}}})
	ep := &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{{Name: "t", DefaultAction: "Deny", IngressPolicies: []*proto.PolicyID{pID}}}}
	flow := policyscale.NewFlow("10.0.0.9", 1234, "10.0.0.5", 80)

	eval := func() []*calc.RuleID {
		t.Helper()
		trace, err := Evaluate(StagedAsEnforced, rules.RuleDirIngress, store, ep, flow)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return trace
	}
	deny := calc.NewRuleID(v3.KindGlobalNetworkPolicy, "t", "p", "", tierDefaultActionIndex, rules.RuleDirIngress, rules.RuleActionDeny)
	allow := calc.NewRuleID(v3.KindGlobalNetworkPolicy, "t", "p", "", 0, rules.RuleDirIngress, rules.RuleActionAllow)

	if got := eval(); !sameTrace(got, []*calc.RuleID{deny}) {
		t.Fatalf("before the set has the address: %v", formatTrace(got))
	}
	eval()
	if stats.Hits.Load() != 1 {
		t.Fatalf("second evaluation was not a hit: %+v", stats)
	}

	// The set gains the destination: the verdict flips and the stale entry is gone.
	apply(&proto.ToDataplane{Payload: &proto.ToDataplane_IpsetDeltaUpdate{IpsetDeltaUpdate: &proto.IPSetDeltaUpdate{Id: "s", AddedMembers: []string{"10.0.0.5/32"}}}})
	if got := eval(); !sameTrace(got, []*calc.RuleID{allow}) {
		t.Fatalf("after the set gained the address: %v", formatTrace(got))
	}
	if stats.Resets.Load() != 1 {
		t.Fatalf("expected one reset, stats %+v", stats)
	}

	// The policy changes its action: same again.
	apply(&proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{ActivePolicyUpdate: &proto.ActivePolicyUpdate{
		Id: pID, Policy: &proto.Policy{Tier: "t", InboundRules: []*proto.Rule{{Action: "deny", DstIpSetIds: []string{"s"}}}},
	}}})
	denyRule := calc.NewRuleID(v3.KindGlobalNetworkPolicy, "t", "p", "", 0, rules.RuleDirIngress, rules.RuleActionDeny)
	if got := eval(); !sameTrace(got, []*calc.RuleID{denyRule}) {
		t.Fatalf("after the policy changed: %v", formatTrace(got))
	}

	// The policy goes away: the evaluation fails, and the failure is not cached.
	apply(&proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyRemove{ActivePolicyRemove: &proto.ActivePolicyRemove{Id: pID}}})
	for i := 0; i < 2; i++ {
		if _, err := Evaluate(StagedAsEnforced, rules.RuleDirIngress, store, ep, flow); err == nil {
			t.Fatal("expected the evaluation to fail with the policy missing")
		}
	}
	if store.Verdicts.Len() != 0 {
		t.Fatalf("a failed evaluation was cached: %d entries", store.Verdicts.Len())
	}
}

// TestVerdictKeyIncludesSourcePortOnlyWhenRulesUseIt: flows that differ only in their source port
// share an entry unless a rule that applies to the endpoint looks at source ports.
func TestVerdictKeyIncludesSourcePortOnlyWhenRulesUseIt(t *testing.T) {
	build := func(rule *proto.Rule) (*policystore.PolicyStore, *proto.WorkloadEndpoint, *policystore.VerdictCacheStats) {
		stats := &policystore.VerdictCacheStats{}
		store := policystore.NewPolicyStore()
		store.Verdicts = policystore.NewVerdictCache(1024, stats)
		pID := &proto.PolicyID{Name: "p", Kind: v3.KindGlobalNetworkPolicy}
		store.PolicyByID[types.ProtoToPolicyID(pID)] = &proto.Policy{Tier: "t", InboundRules: []*proto.Rule{rule}}
		ep := &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{{Name: "t", DefaultAction: "Deny", IngressPolicies: []*proto.PolicyID{pID}}}}
		return store, ep, stats
	}
	allowed := func(trace []*calc.RuleID) bool { return len(trace) == 1 && trace[0].Action == rules.RuleActionAllow }

	// Rules ignore the source port: one entry serves every source port.
	store, ep, stats := build(&proto.Rule{Action: "allow", DstPorts: []*proto.PortRange{{First: 80, Last: 80}}})
	for sp := 1000; sp < 1010; sp++ {
		trace, err := Evaluate(StagedAsEnforced, rules.RuleDirIngress, store, ep, policyscale.NewFlow("10.0.0.9", sp, "10.0.0.5", 80))
		if err != nil || !allowed(trace) {
			t.Fatalf("source port %d: %v %v", sp, formatTrace(trace), err)
		}
	}
	if stats.Misses.Load() != 1 || stats.Hits.Load() != 9 {
		t.Fatalf("source-port-insensitive endpoint: %d misses, %d hits, want 1 and 9", stats.Misses.Load(), stats.Hits.Load())
	}

	// A rule matches on the source port: the key carries it, and verdicts stay per port.
	store, ep, stats = build(&proto.Rule{Action: "allow", SrcPorts: []*proto.PortRange{{First: 1000, Last: 1004}}})
	for pass := 0; pass < 2; pass++ {
		for sp := 1000; sp < 1010; sp++ {
			trace, err := Evaluate(StagedAsEnforced, rules.RuleDirIngress, store, ep, policyscale.NewFlow("10.0.0.9", sp, "10.0.0.5", 80))
			if err != nil || allowed(trace) != (sp <= 1004) {
				t.Fatalf("pass %d source port %d: %v %v", pass, sp, formatTrace(trace), err)
			}
		}
	}
	if stats.Misses.Load() != 10 || stats.Hits.Load() != 10 {
		t.Fatalf("source-port-sensitive endpoint: %d misses, %d hits, want 10 and 10", stats.Misses.Load(), stats.Hits.Load())
	}

	// A negated named source port counts as looking at the source port too.
	store, ep, stats = build(&proto.Rule{Action: "allow", NotSrcNamedPortIpSetIds: []string{"np"}})
	for sp := 1000; sp < 1003; sp++ {
		_, _ = Evaluate(StagedAsEnforced, rules.RuleDirIngress, store, ep, policyscale.NewFlow("10.0.0.9", sp, "10.0.0.5", 80))
	}
	if stats.Misses.Load() != 3 {
		t.Fatalf("named source port endpoint: %d misses, want 3", stats.Misses.Load())
	}
}

func TestVerdictCacheSkipsL7FlowsAndNilAddresses(t *testing.T) {
	stats := &policystore.VerdictCacheStats{}
	store := policystore.NewPolicyStore()
	store.Verdicts = policystore.NewVerdictCache(1024, stats)
	pID := &proto.PolicyID{Name: "p", Kind: v3.KindGlobalNetworkPolicy}
	store.PolicyByID[types.ProtoToPolicyID(pID)] = &proto.Policy{Tier: "t", InboundRules: []*proto.Rule{{Action: "allow"}}}
	ep := &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{{Name: "t", DefaultAction: "Deny", IngressPolicies: []*proto.PolicyID{pID}}}}

	principal := "spiffe://cluster.local/ns/default/sa/client"
	method := "GET"
	flows := map[string]Flow{
		"source principal":   &MockFlow{SourceIP: net.ParseIP("10.0.0.9"), DestIP: net.ParseIP("10.0.0.5"), DestPort: 80, Protocol: 6, SourcePrincipal: &principal},
		"HTTP method":        &MockFlow{SourceIP: net.ParseIP("10.0.0.9"), DestIP: net.ParseIP("10.0.0.5"), DestPort: 80, Protocol: 6, HttpMethod: &method},
		"destination labels": &MockFlow{SourceIP: net.ParseIP("10.0.0.9"), DestIP: net.ParseIP("10.0.0.5"), DestPort: 80, Protocol: 6, DestLabels: map[string]string{"a": "b"}},
		"nil source":         &policyscale.Flow{DstIP: net.ParseIP("10.0.0.5"), DstPort: 80, Protocol: 6},
		"nil destination":    &policyscale.Flow{SrcIP: net.ParseIP("10.0.0.9"), DstPort: 80, Protocol: 6},
	}
	for name, f := range flows {
		for i := 0; i < 2; i++ {
			if _, err := Evaluate(StagedAsEnforced, rules.RuleDirIngress, store, ep, f); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	if stats.Hits.Load()+stats.Misses.Load() != 0 || store.Verdicts.Len() != 0 {
		t.Fatalf("uncacheable flows touched the cache: %+v, %d entries", stats, store.Verdicts.Len())
	}

	// And a plain L4 flow on the same store is cached.
	for i := 0; i < 2; i++ {
		_, _ = Evaluate(StagedAsEnforced, rules.RuleDirIngress, store, ep, policyscale.NewFlow("10.0.0.9", 1, "10.0.0.5", 80))
	}
	if stats.Hits.Load() != 1 || stats.Misses.Load() != 1 {
		t.Fatalf("L4 flow: %+v", stats)
	}
}
