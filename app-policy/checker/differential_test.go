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

// Differential tests for Evaluate.
//
// Two evaluators are run over the same corpus and must agree on every trace. Today the second
// evaluator is the policyscale oracle, which answers from the generator's model of each rule
// rather than from the proto the engine reads. A change that adds a second implementation of the
// walk (compiled policies, a verdict cache, evaluation on another goroutine) runs it through the
// same harness against Evaluate, and through the named cases below, before it is switched on.

import (
	"fmt"
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

// evaluator is the shape of Evaluate, so that another implementation can be run through the
// same harness.
type evaluator func(scope PolicyScope, dir rules.RuleDir, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, flow Flow) ([]*calc.RuleID, error)

// corpusFlow is one evaluation of the differential corpus.
type corpusFlow struct {
	name string
	dir  rules.RuleDir
	flow *policyscale.Flow
}

func TestEvaluateAgreesWithOracle(t *testing.T) {
	_, restoreLogging := withBenchLogging(log.ErrorLevel)
	defer restoreLogging()

	missing := policyscale.Baseline()
	missing.Baseline.MissingIPSets = 8

	for _, c := range []struct {
		name string
		spec policyscale.Spec
	}{
		{"baseline", policyscale.Baseline()},
		{"baseline with missing sets", missing},
		{"egress allow-list", policyscale.EgressAllowList()},
		{"composite", policyscale.Composite()},
	} {
		t.Run(c.name, func(t *testing.T) {
			fx := policyscale.Build(c.spec)
			store, ep := fx.NewStore(), fx.Endpoint()
			corpus := differentialCorpus(fx, 7, 250, 257)
			for _, scope := range []PolicyScope{StagedAsEnforced, EnforcedOnly} {
				assertEquivalent(t, fmt.Sprintf("%s scope %d", c.name, scope), scope, Evaluate, oracleEvaluator(fx), store, ep, corpus)
			}
		})
	}
}

// differentialCorpus draws the flows a fixture is checked with, in every direction it has rules
// for: the denied flow, a flow aimed at every stride-th rule, and sampled flows following a flow
// model. Aimed flows are also replayed as UDP (no generated rule names a protocol, so the verdict
// must not change), and a few with an invalid protocol and with a nil address.
func differentialCorpus(fx *policyscale.Fixture, seed int64, sampled, stride int) []corpusFlow {
	var corpus []corpusFlow
	for _, dir := range []policyscale.Direction{policyscale.Ingress, policyscale.Egress} {
		rulesInDir := fx.Rules(dir)
		if rulesInDir == 0 {
			continue
		}
		rd := ruleDir(dir)
		add := func(name string, f *policyscale.Flow) {
			corpus = append(corpus, corpusFlow{name: fmt.Sprintf("%s %s %v", dir, name, f), dir: rd, flow: f})
		}
		add("denied", fx.DeniedFlow(dir))
		for ordinal := 0; ordinal < rulesInDir; ordinal += stride {
			f := fx.MatchingFlow(dir, ordinal)
			add(fmt.Sprintf("aimed at %d", ordinal), f)
			udp := *f
			udp.Protocol = 17
			add(fmt.Sprintf("aimed at %d as UDP", ordinal), &udp)
			if ordinal%(stride*8) == 0 {
				invalid := *f
				invalid.Protocol = 256
				add(fmt.Sprintf("aimed at %d with protocol 256", ordinal), &invalid)
				noSrc := *f
				noSrc.SrcIP = nil
				add(fmt.Sprintf("aimed at %d with nil source", ordinal), &noSrc)
				noDst := *f
				noDst.DstIP = nil
				add(fmt.Sprintf("aimed at %d with nil destination", ordinal), &noDst)
			}
		}
		s := fx.NewSampler(seed, policyscale.FlowModel{Direction: dir, MissFraction: 0.1, RepeatFraction: 0.3})
		for i := 0; i < sampled; i++ {
			add(fmt.Sprintf("sampled %d", i), s.Next())
		}
	}
	return corpus
}

// assertEquivalent evaluates every corpus flow with both evaluators and reports each
// disagreement, up to a limit. The two must agree on the trace and on whether the evaluation
// failed.
func assertEquivalent(t *testing.T, name string, scope PolicyScope, a, b evaluator, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, corpus []corpusFlow) {
	t.Helper()
	const maxReported = 10
	mismatches := 0
	for _, c := range corpus {
		traceA, errA := a(scope, c.dir, store, ep, c.flow)
		traceB, errB := b(scope, c.dir, store, ep, c.flow)
		if (errA != nil) != (errB != nil) || !sameTrace(traceA, traceB) {
			mismatches++
			if mismatches <= maxReported {
				t.Errorf("%s: %s:\n  a: %v (err %v)\n  b: %v (err %v)", name, c.name, formatTrace(traceA), errA, formatTrace(traceB), errB)
			}
		}
	}
	if mismatches > maxReported {
		t.Errorf("%s: %d mismatches in %d flows (%d shown)", name, mismatches, len(corpus), maxReported)
	}
}

// oracleEvaluator answers from the fixture's model. Only flows the fixture generated are meaningful
// to it, and it ignores the scope: the generated sets hold no staged policies.
func oracleEvaluator(fx *policyscale.Fixture) evaluator {
	return func(_ PolicyScope, dir rules.RuleDir, _ *policystore.PolicyStore, _ *proto.WorkloadEndpoint, flow Flow) ([]*calc.RuleID, error) {
		var trace []*calc.RuleID
		for _, v := range fx.Expect(policyDir(dir), flow.(*policyscale.Flow)) {
			trace = append(trace, calc.NewRuleID(v.Kind, v.Tier, v.Policy, "", v.Index, dir, actionFromOracle(v.Action)))
		}
		return trace, nil
	}
}

func actionFromOracle(action string) rules.RuleAction {
	switch action {
	case "allow":
		return rules.RuleActionAllow
	case "deny":
		return rules.RuleActionDeny
	case "pass":
		return rules.RuleActionPass
	}
	panic("unexpected oracle action " + action)
}

func ruleDir(d policyscale.Direction) rules.RuleDir {
	if d == policyscale.Egress {
		return rules.RuleDirEgress
	}
	return rules.RuleDirIngress
}

func policyDir(d rules.RuleDir) policyscale.Direction {
	if d == rules.RuleDirEgress {
		return policyscale.Egress
	}
	return policyscale.Ingress
}

func sameTrace(a, b []*calc.RuleID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameRuleID(a[i], b[i]) {
			return false
		}
	}
	return true
}

func sameRuleID(a, b *calc.RuleID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Kind == b.Kind && a.Tier == b.Tier && a.Name == b.Name && a.Namespace == b.Namespace &&
		a.Index == b.Index && a.Direction == b.Direction && a.Action == b.Action
}

func formatTrace(trace []*calc.RuleID) string {
	s := "["
	for i, r := range trace {
		if i > 0 {
			s += " "
		}
		if r == nil {
			s += "<nil>"
			continue
		}
		s += fmt.Sprintf("%s/%s/%s[%d]=%v", r.Kind, r.Tier, r.Name, r.Index, r.Action)
	}
	return s + "]"
}

// namedCase is one hand-built evaluation with a known answer: the edge cases the generated corpus
// cannot reach. Every evaluator must reproduce the answer.
type namedCase struct {
	name    string
	scope   PolicyScope
	dir     rules.RuleDir
	store   *policystore.PolicyStore
	ep      *proto.WorkloadEndpoint
	flow    Flow
	want    []*calc.RuleID
	wantErr bool
}

func TestEvaluateNamedCases(t *testing.T) {
	_, restoreLogging := withBenchLogging(log.ErrorLevel)
	defer restoreLogging()
	runNamedCases(t, Evaluate)
}

// runNamedCases checks an evaluator against every named case.
func runNamedCases(t *testing.T, eval evaluator) {
	t.Helper()
	for _, c := range namedCases() {
		t.Run(c.name, func(t *testing.T) {
			got, err := eval(c.scope, c.dir, c.store, c.ep, c.flow)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got trace %v", formatTrace(got))
				}
				if got != nil {
					t.Fatalf("expected no trace with the error, got %v", formatTrace(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !sameTrace(got, c.want) {
				t.Fatalf("got %v, want %v", formatTrace(got), formatTrace(c.want))
			}
		})
	}
}

func namedCases() []namedCase {
	const (
		tier    = "t1"
		setA    = "set-a"
		absent  = "set-absent"
		npSet   = "named-port-set"
		ipPort  = "ip-port-set"
		peerIP  = "10.0.0.5"
		otherIP = "10.0.0.6"
	)
	ingress := rules.RuleDirIngress
	tcp := func(src string, dst string, dport int) *policyscale.Flow {
		return policyscale.NewFlow(src, 40000, dst, dport)
	}
	gnp := func(kind, name, tier string, rs ...*proto.Rule) (*proto.PolicyID, *proto.Policy) {
		return &proto.PolicyID{Name: name, Kind: kind}, &proto.Policy{Tier: tier, InboundRules: rs}
	}
	allow := func(r *proto.Rule) *proto.Rule { r.Action = "allow"; return r }
	deny := func(r *proto.Rule) *proto.Rule { r.Action = "deny"; return r }
	pass := func(r *proto.Rule) *proto.Rule { r.Action = "pass"; return r }
	ruleID := func(kind, name string, index int, action rules.RuleAction) *calc.RuleID {
		return calc.NewRuleID(kind, tier, name, "", index, ingress, action)
	}
	profileDeny := calc.NewRuleID(v3.KindProfile, profileStr, profileStr, "", tierDefaultActionIndex, ingress, rules.RuleActionDeny)

	// build returns a store and endpoint with one tier holding the given policies, in order.
	build := func(defaultAction string, policies ...func() (*proto.PolicyID, *proto.Policy)) (*policystore.PolicyStore, *proto.WorkloadEndpoint) {
		store := policystore.NewPolicyStore()
		a := policystore.NewIPSet(proto.IPSetUpdate_NET)
		a.AddString(peerIP + "/32")
		store.IPSetByID[setA] = a
		np := policystore.NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
		np.AddString(ipProtoPortKey(peerIP, 6, 8080))
		store.IPSetByID[npSet] = np
		ipp := policystore.NewIPSet(proto.IPSetUpdate_IP_AND_PORT)
		ipp.AddString(ipProtoPortKey(peerIP, 6, 8080))
		store.IPSetByID[ipPort] = ipp

		ti := &proto.TierInfo{Name: tier, DefaultAction: defaultAction}
		for _, p := range policies {
			id, policy := p()
			store.PolicyByID[types.ProtoToPolicyID(id)] = policy
			ti.IngressPolicies = append(ti.IngressPolicies, id)
		}
		return store, &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{ti}}
	}
	policy := func(name string, rs ...*proto.Rule) func() (*proto.PolicyID, *proto.Policy) {
		return func() (*proto.PolicyID, *proto.Policy) { return gnp(v3.KindGlobalNetworkPolicy, name, tier, rs...) }
	}
	stagedPolicy := func(name string, rs ...*proto.Rule) func() (*proto.PolicyID, *proto.Policy) {
		return func() (*proto.PolicyID, *proto.Policy) {
			return gnp(v3.KindStagedGlobalNetworkPolicy, name, tier, rs...)
		}
	}

	var cases []namedCase
	add := func(name string, scope PolicyScope, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, flow Flow, want ...*calc.RuleID) {
		cases = append(cases, namedCase{name: name, scope: scope, dir: ingress, store: store, ep: ep, flow: flow, want: want})
	}

	// Nil addresses: a positive set or CIDR reference never matches them, a negated one always does.
	{
		store, ep := build("Deny",
			policy("p", allow(&proto.Rule{SrcIpSetIds: []string{setA}}), allow(&proto.Rule{SrcNet: []string{"10.0.0.0/8"}}), allow(&proto.Rule{NotSrcIpSetIds: []string{setA}, NotSrcNet: []string{"10.0.0.0/8"}})))
		add("nil source address", StagedAsEnforced, store, ep, &policyscale.Flow{DstIP: tcp(peerIP, peerIP, 80).DstIP, SrcPort: 1, DstPort: 80, Protocol: 6},
			ruleID(v3.KindGlobalNetworkPolicy, "p", 2, rules.RuleActionAllow))
	}

	// Named ports resolve through the IP+port set on the destination; a negated named port is
	// the complement.
	{
		store, ep := build("Deny", policy("p", allow(&proto.Rule{DstNamedPortIpSetIds: []string{npSet}})))
		add("named port on the flow's port", StagedAsEnforced, store, ep, tcp(otherIP, peerIP, 8080), ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionAllow))
		add("named port on another port", StagedAsEnforced, store, ep, tcp(otherIP, peerIP, 8081), ruleID(v3.KindGlobalNetworkPolicy, "p", tierDefaultActionIndex, rules.RuleActionDeny))
		store, ep = build("Deny", policy("p", allow(&proto.Rule{NotDstNamedPortIpSetIds: []string{npSet}})))
		add("negated named port on the flow's port", StagedAsEnforced, store, ep, tcp(otherIP, peerIP, 8080), ruleID(v3.KindGlobalNetworkPolicy, "p", tierDefaultActionIndex, rules.RuleActionDeny))
		add("negated named port on another port", StagedAsEnforced, store, ep, tcp(otherIP, peerIP, 8081), ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionAllow))
	}

	// A numeric port range is tried before the named-port sets and matches on its own.
	{
		store, ep := build("Deny", policy("p", allow(&proto.Rule{DstPorts: []*proto.PortRange{{First: 8000, Last: 8100}}, DstNamedPortIpSetIds: []string{npSet}})))
		add("port range or named port", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 8050), ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionAllow))
	}

	// Negated IP sets, and IP+port sets on the destination.
	{
		store, ep := build("Deny", policy("p", allow(&proto.Rule{NotDstIpSetIds: []string{setA}})))
		add("negated set holding the destination", StagedAsEnforced, store, ep, tcp(otherIP, peerIP, 80), ruleID(v3.KindGlobalNetworkPolicy, "p", tierDefaultActionIndex, rules.RuleActionDeny))
		add("negated set not holding the destination", StagedAsEnforced, store, ep, tcp(peerIP, otherIP, 80), ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionAllow))
		store, ep = build("Deny", policy("p", allow(&proto.Rule{DstIpPortSetIds: []string{ipPort}})))
		add("IP+port set on the flow's port", StagedAsEnforced, store, ep, tcp(otherIP, peerIP, 8080), ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionAllow))
		add("IP+port set on another port", StagedAsEnforced, store, ep, tcp(otherIP, peerIP, 8081), ruleID(v3.KindGlobalNetworkPolicy, "p", tierDefaultActionIndex, rules.RuleActionDeny))
	}

	// A reference to a set the store does not hold is skipped, negated or not.
	{
		store, ep := build("Deny", policy("p", allow(&proto.Rule{DstIpSetIds: []string{absent}})))
		add("missing set is skipped", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 80), ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionAllow))
		store, ep = build("Deny", policy("p", allow(&proto.Rule{NotDstIpSetIds: []string{absent}})))
		add("missing negated set is skipped", StagedAsEnforced, store, ep, tcp(otherIP, peerIP, 80), ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionAllow))
	}

	// Protocols: out of range matches nothing, even a rule with no protocol; by name and by number;
	// negated.
	{
		store, ep := build("Deny", policy("p", allow(&proto.Rule{})))
		for _, p := range []int{0, 256, -1} {
			f := tcp(otherIP, otherIP, 80)
			f.Protocol = p
			add(fmt.Sprintf("protocol %d matches nothing", p), StagedAsEnforced, store, ep, f, ruleID(v3.KindGlobalNetworkPolicy, "p", tierDefaultActionIndex, rules.RuleActionDeny))
		}
		store, ep = build("Deny", policy("p",
			allow(&proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "UDP"}}}),
			allow(&proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 132}}}),
			allow(&proto.Rule{NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}}}),
			allow(&proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "TCP"}}})))
		add("protocol by name and number", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 80), ruleID(v3.KindGlobalNetworkPolicy, "p", 3, rules.RuleActionAllow))
		udp := tcp(otherIP, otherIP, 80)
		udp.Protocol = 17
		add("protocol by name matches UDP", StagedAsEnforced, store, ep, udp, ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionAllow))
		sctp := tcp(otherIP, otherIP, 80)
		sctp.Protocol = 132
		add("protocol by number matches SCTP", StagedAsEnforced, store, ep, sctp, ruleID(v3.KindGlobalNetworkPolicy, "p", 1, rules.RuleActionAllow))
	}

	// Staged policies: out of scope for the enforced verdict, in scope for the pending one. A tier
	// whose policies are all staged contributes nothing to the enforced verdict, default included.
	{
		store, ep := build("Deny", stagedPolicy("s", allow(&proto.Rule{})))
		add("staged-only tier, enforced scope", EnforcedOnly, store, ep, tcp(otherIP, otherIP, 80), profileDeny)
		add("staged-only tier, pending scope", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 80), ruleID(v3.KindStagedGlobalNetworkPolicy, "s", 0, rules.RuleActionAllow))
		store, ep = build("Deny", policy("e", allow(&proto.Rule{DstPorts: []*proto.PortRange{{First: 1, Last: 1}}})), stagedPolicy("s", allow(&proto.Rule{})))
		add("enforced then staged, enforced scope", EnforcedOnly, store, ep, tcp(otherIP, otherIP, 80), ruleID(v3.KindGlobalNetworkPolicy, "e", tierDefaultActionIndex, rules.RuleActionDeny))
		add("enforced then staged, pending scope", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 80), ruleID(v3.KindStagedGlobalNetworkPolicy, "s", 0, rules.RuleActionAllow))
	}

	// An L4 flow carries no HTTP attributes, so HTTP criteria match it.
	{
		store, ep := build("Deny", policy("p", allow(&proto.Rule{HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}, Paths: []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Exact{Exact: "/x"}}}}})))
		add("HTTP rule against an L4 flow", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 80), ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionAllow))
	}

	// A Log rule matches and evaluation continues.
	{
		store, ep := build("Deny", policy("p", &proto.Rule{Action: "log"}, deny(&proto.Rule{})))
		add("log rule continues", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 80), ruleID(v3.KindGlobalNetworkPolicy, "p", 1, rules.RuleActionDeny))
	}

	// Pass leaves the tier: the trace carries the pass, then the next tier's verdict; with no next
	// tier and no profiles, the profile deny.
	{
		store, ep := build("Deny", policy("p", pass(&proto.Rule{})))
		add("pass with nothing after it", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 80), ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionPass), profileDeny)
		store, ep = build("Deny", policy("p", pass(&proto.Rule{})))
		t2 := &proto.TierInfo{Name: "t2", DefaultAction: "Deny"}
		id, pol := gnp(v3.KindGlobalNetworkPolicy, "q", "t2", deny(&proto.Rule{}))
		store.PolicyByID[types.ProtoToPolicyID(id)] = pol
		t2.IngressPolicies = []*proto.PolicyID{id}
		ep.Tiers = append(ep.Tiers, t2)
		add("pass then next tier", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 80),
			ruleID(v3.KindGlobalNetworkPolicy, "p", 0, rules.RuleActionPass),
			calc.NewRuleID(v3.KindGlobalNetworkPolicy, "t2", "q", "", 0, ingress, rules.RuleActionDeny))
	}

	// Tier default Pass continues to the profiles; a profile allow ends there.
	{
		store, ep := build("Pass", policy("p", allow(&proto.Rule{DstPorts: []*proto.PortRange{{First: 1, Last: 1}}})))
		store.ProfileByID[types.ProtoToProfileID(&proto.ProfileID{Name: "prof"})] = &proto.Profile{InboundRules: []*proto.Rule{allow(&proto.Rule{})}}
		ep.ProfileIds = []string{"prof"}
		add("tier default pass then profile", StagedAsEnforced, store, ep, tcp(otherIP, otherIP, 80),
			ruleID(v3.KindGlobalNetworkPolicy, "p", tierDefaultActionIndex, rules.RuleActionPass),
			calc.NewRuleID(v3.KindProfile, profileStr, "prof", "", 0, ingress, rules.RuleActionAllow))
	}

	// A policy the endpoint names but the store lacks fails the evaluation rather than skipping it.
	{
		store, ep := build("Deny", policy("p", allow(&proto.Rule{})))
		ep.Tiers[0].IngressPolicies = append([]*proto.PolicyID{{Name: "ghost", Kind: v3.KindGlobalNetworkPolicy}}, ep.Tiers[0].IngressPolicies...)
		cases = append(cases, namedCase{name: "missing policy fails", scope: StagedAsEnforced, dir: ingress, store: store, ep: ep, flow: tcp(otherIP, otherIP, 80), wantErr: true})
	}

	return cases
}
