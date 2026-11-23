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

package policyscale

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/proto"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

// Each flow aimed at a rule of the shape preset is decided by that rule exactly when it is marked
// as a hit, so the flows that differ only in the rule's criterion really do test that criterion.
func TestShapeFlowsHitOnlyTheirRule(t *testing.T) {
	fx := Build(RuleShapes())
	for _, dir := range []Direction{Ingress, Egress} {
		rules := fx.ShapeRules(dir)
		if len(rules) < 30 {
			t.Fatalf("%s: only %d shape rules", dir, len(rules))
		}
		for _, r := range rules {
			var hits, misses int
			for _, f := range r.Flows {
				decided := slices.ContainsFunc(fx.Expect(dir, f.Flow), func(v Verdict) bool {
					return v.Tier == r.Tier && v.Policy == r.Policy && v.Index == r.Index
				})
				if decided != f.Hit {
					t.Errorf("%s %s: %v decided by the rule: %v, want %v (trace %v)", dir, f.Name, f.Flow, decided, f.Hit, fx.Expect(dir, f.Flow))
				}
				if f.Hit {
					hits++
				} else {
					misses++
				}
			}
			if hits == 0 || misses == 0 {
				t.Errorf("%s %s: %d hits and %d misses, want some of each", dir, r.Name, hits, misses)
			}
		}
		for _, f := range fx.ShapeFlows(dir) {
			if f.Hit {
				continue
			}
			// Flows that aren't hits reach no rule except Pass-tier and main-tier defaults, or
			// the rule they were aimed at when that rule is a Pass.
			for _, v := range fx.Expect(dir, f.Flow) {
				if v.Index != TierDefaultIndex && v.Action != "pass" {
					t.Errorf("%s %s: %v decided by %v", dir, f.Name, f.Flow, v)
				}
			}
		}
	}
}

// A flow matching nothing passes through the Pass tier on its default and is denied by the main
// tier's default, both reported against the tier's last policy.
func TestShapeTierDefaultsNameTheLastPolicy(t *testing.T) {
	fx := Build(RuleShapes())
	p := DefaultShapes()
	for _, dir := range []Direction{Ingress, Egress} {
		got := fx.Expect(dir, fx.DeniedFlow(dir))
		rules := fx.ShapeRules(dir)
		lastPolicy := rules[len(rules)-1].Policy
		want := []Verdict{
			{Kind: v3.KindGlobalNetworkPolicy, Tier: p.PassTier, Policy: "shape-pass-" + dirShort(dir) + "-1", Index: TierDefaultIndex, Action: "pass"},
			{Kind: v3.KindGlobalNetworkPolicy, Tier: p.Tier, Policy: lastPolicy, Index: TierDefaultIndex, Action: "deny"},
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", dir, got, want)
		}
		if lastPolicy == rules[2].Policy {
			t.Errorf("%s: the main tier has one policy; it needs several for the default's name to matter", dir)
		}
	}
}

// The preset sets every rule criterion the evaluator checks at least once.
func TestShapesCoverEveryCriterion(t *testing.T) {
	fx := Build(RuleShapes())
	seen := map[string]bool{}
	for _, dir := range []Direction{Ingress, Egress} {
		for _, r := range fx.ShapeRules(dir) {
			_, rule, _ := fx.ruleAt(dir, ordinalOf(fx, dir, r))
			pr := rule.proto()
			mark := func(name string, set bool) {
				if set {
					seen[name] = true
				}
			}
			mark("protocol name", pr.GetProtocol().GetName() != "")
			mark("protocol number", pr.GetProtocol() != nil && pr.GetProtocol().GetName() == "")
			mark("not protocol name", pr.GetNotProtocol().GetName() != "")
			mark("not protocol number", pr.GetNotProtocol() != nil && pr.GetNotProtocol().GetName() == "")
			mark("ip version 4", pr.IpVersion == proto.IPVersion_IPV4)
			mark("ip version 6", pr.IpVersion == proto.IPVersion_IPV6)
			mark("icmp type", pr.GetIcmpType() != 0)
			mark("icmp type and code", pr.GetIcmpTypeCode() != nil)
			mark("not icmp type", pr.GetNotIcmpType() != 0)
			mark("not icmp type and code", pr.GetNotIcmpTypeCode() != nil)
			mark("src ports", len(pr.SrcPorts) > 0)
			mark("not src ports", len(pr.NotSrcPorts) > 0)
			mark("src named port", len(pr.SrcNamedPortIpSetIds) > 0)
			mark("not src named port", len(pr.NotSrcNamedPortIpSetIds) > 0)
			mark("dst ports", len(pr.DstPorts) > 0)
			mark("not dst ports", len(pr.NotDstPorts) > 0)
			mark("src net", len(pr.SrcNet) > 0)
			mark("dst net", len(pr.DstNet) > 0)
			mark("not src net", len(pr.NotSrcNet) > 0)
			mark("not dst net", len(pr.NotDstNet) > 0)
			mark("src ip set", len(pr.SrcIpSetIds) > 0)
			mark("dst ip set", len(pr.DstIpSetIds) > 0)
			mark("not src ip set", len(pr.NotSrcIpSetIds) > 0)
			mark("not dst ip set", len(pr.NotDstIpSetIds) > 0)
			mark("dst named port", len(pr.DstNamedPortIpSetIds) > 0)
			mark("not dst named port", len(pr.NotDstNamedPortIpSetIds) > 0)
			mark("dst service", len(pr.DstIpPortSetIds) > 0)
			mark("allow", rule.action == "allow")
			mark("deny", rule.action == "deny")
			mark("pass", rule.action == "pass")
		}
	}
	for _, name := range []string{
		"protocol name", "protocol number", "not protocol name", "not protocol number", "ip version 4", "ip version 6",
		"icmp type", "icmp type and code", "not icmp type", "not icmp type and code",
		"src ports", "not src ports", "src named port", "not src named port", "dst ports", "not dst ports", "src net", "dst net", "not src net", "not dst net",
		"src ip set", "dst ip set", "not src ip set", "not dst ip set",
		"dst named port", "not dst named port", "dst service", "allow", "deny", "pass",
	} {
		if !seen[name] {
			t.Errorf("no shape rule sets %s", name)
		}
	}
}

func ordinalOf(fx *Fixture, dir Direction, r *ShapeRule) int {
	n := 0
	for _, t := range fx.tiers {
		for _, p := range t.policies[dir] {
			if t.name == r.Tier && p.name == r.Policy {
				return n + r.Index
			}
			n += len(p.rules)
		}
	}
	panic("shape rule not found")
}

// Every rendered resource passes the API validator, enforced and staged, and the named ports and
// services the rules use are listed for a cluster to provide.
func TestShapeResourcesValidate(t *testing.T) {
	fx := Build(RuleShapes())
	for _, staged := range []bool{false, true} {
		for _, obj := range fx.Resources(ResourceOptions{Enforced: !staged}) {
			if err := validator.Validate(obj); err != nil {
				t.Errorf("staged=%v: %T %v: %v", staged, obj, obj, err)
			}
		}
	}
	if len(fx.NamedPorts()) < 3 || len(fx.Services()) != 1 {
		t.Errorf("named ports %v, services %v", fx.NamedPorts(), fx.Services())
	}
	for _, np := range fx.NamedPorts() {
		if len(np.Name) > 15 || len(np.Addrs) != 2 {
			t.Errorf("named port %+v", np)
		}
	}
}

// Every difference a flow is marked with is a known one the preset generates, and excluding a
// place's differences leaves out exactly the flows marked with them.
func TestShapeFlowDifferences(t *testing.T) {
	fx := Build(RuleShapes())
	used := map[Difference]bool{}
	for _, dir := range []Direction{Ingress, Egress} {
		all := fx.ShapeFlows(dir)
		for _, f := range all {
			for _, d := range f.Differences {
				used[d] = true
			}
		}
		for _, where := range [][]Where{{Evaluator}, {Evaluator, Iptables}, {Evaluator, Nftables}, {Evaluator, BPF}} {
			excluded := DifferencesAt(where...)
			kept := fx.ShapeFlows(dir, excluded...)
			want := 0
			for _, f := range all {
				if !slices.ContainsFunc(f.Differences, func(d Difference) bool { return slices.Contains(excluded, d) }) {
					want++
				}
			}
			if len(kept) != want || len(kept) == len(all) {
				t.Errorf("%s at %v: kept %d of %d flows, want %d", dir, where, len(kept), len(all), want)
			}
		}
	}
	for _, kd := range KnownDifferences() {
		if kd.Generated != used[kd.Difference] {
			t.Errorf("%s: generated %v but marked on flows %v", kd.Difference, kd.Generated, used[kd.Difference])
		}
		delete(used, kd.Difference)
	}
	if len(used) > 0 {
		t.Errorf("flows marked with unlisted differences %v", used)
	}
}

// Conntrack starts a flow only on ICMP request types; the dataplanes drop or accept the other
// types before policy and log no flow, so a functional test could send no other aimed flow.
func TestShapeICMPFlowsUseRequestTypes(t *testing.T) {
	fx := Build(RuleShapes())
	requests := map[int][]int{ProtocolICMP: {8, 13, 15, 17}, ProtocolICMPv6: {128, 139}}
	for _, dir := range []Direction{Ingress, Egress} {
		for _, f := range fx.ShapeFlows(dir) {
			if f.Flow.Protocol != ProtocolICMP && f.Flow.Protocol != ProtocolICMPv6 {
				continue
			}
			if typ, _ := ICMPTypeCode(f.Flow); !slices.Contains(requests[f.Flow.Protocol], typ) {
				t.Errorf("%s %s: ICMP type %d starts no flow", dir, f.Name, typ)
			}
		}
	}
}

// BPF parses no SCTP header, so it enforces and reports SCTP flows with ports of zero.
func TestSCTPPortsDifferOnEveryDataplane(t *testing.T) {
	for _, w := range []Where{Iptables, Nftables, BPF} {
		if !slices.Contains(DifferencesAt(w), SCTPPorts) {
			t.Errorf("%s: SCTP ports not listed", w)
		}
	}
}

// A set rendered with the zero options is safe on a live cluster: every policy is staged, and
// applies only to endpoints labelled for it.
func TestDefaultRenderingIsStagedAndTargeted(t *testing.T) {
	for _, obj := range Build(RuleShapes()).Resources(ResourceOptions{}) {
		switch p := obj.(type) {
		case *v3.GlobalNetworkPolicy:
			t.Errorf("%s rendered enforced", p.Name)
		case *v3.StagedGlobalNetworkPolicy:
			if p.Spec.Selector != TargetSelector {
				t.Errorf("%s selects %q", p.Name, p.Spec.Selector)
			}
		}
	}
}

// A cluster reports a policy by the name and kind it was rendered with, so those must be the
// fixture's: the traces Expect gives are then the ones a cluster's flow logs carry.
func TestRenderedPoliciesKeepTheFixturesNamesAndKinds(t *testing.T) {
	p := DefaultShapes()
	p.Staged = true
	fx := Build(Spec{Seed: DefaultSeed, Shapes: &p})
	kinds := map[string]string{}
	for _, tm := range fx.tiers {
		for _, policies := range tm.policies {
			for _, pol := range policies {
				kinds[pol.name] = pol.kind()
			}
		}
	}
	for _, enforced := range []bool{true, false} {
		rendered := 0
		for _, obj := range fx.Resources(ResourceOptions{Enforced: enforced}) {
			var name, kind string
			switch o := obj.(type) {
			case *v3.GlobalNetworkPolicy:
				name, kind = o.Name, o.Kind
			case *v3.StagedGlobalNetworkPolicy:
				name, kind = o.Name, o.Kind
			default:
				continue
			}
			rendered++
			want, ok := kinds[name]
			if !ok {
				t.Errorf("rendered policy %s isn't in the fixture", name)
				continue
			}
			if !enforced {
				want = v3.KindStagedGlobalNetworkPolicy
			}
			if kind != want {
				t.Errorf("enforced=%v: %s rendered as %s, want %s", enforced, name, kind, want)
			}
		}
		if rendered != len(kinds) {
			t.Errorf("enforced=%v: rendered %d policies of %d", enforced, rendered, len(kinds))
		}
	}
	trace := AsStaged([]Verdict{{Kind: v3.KindGlobalNetworkPolicy}, {Kind: v3.KindStagedGlobalNetworkPolicy}, {Kind: v3.KindProfile}})
	if trace[0].Kind != v3.KindStagedGlobalNetworkPolicy || trace[1].Kind != v3.KindStagedGlobalNetworkPolicy || trace[2].Kind != v3.KindProfile {
		t.Errorf("AsStaged: %v", trace)
	}
}

// In the enforced scope staged policies count for nothing, and a tier of them alone is skipped;
// in the pending scope they count as enforced, and a tier's default names its last policy either
// way.
func TestExpectScopes(t *testing.T) {
	p := DefaultShapes()
	p.Staged = true
	fx := Build(Spec{Seed: DefaultSeed, Shapes: &p})
	for _, dir := range []Direction{Ingress, Egress} {
		denied := fx.DeniedFlow(dir)
		pending, enforced := fx.ExpectIn(PendingScope, dir, denied), fx.ExpectIn(EnforcedScope, dir, denied)
		if len(pending) != 3 || pending[0].Tier != shapesStagedTier || pending[0].Kind != v3.KindStagedGlobalNetworkPolicy {
			t.Errorf("%s pending: %v", dir, pending)
		}
		if len(enforced) != 2 || enforced[0].Tier != p.PassTier || enforced[0].Kind != v3.KindGlobalNetworkPolicy ||
			enforced[0].Policy == pending[1].Policy || enforced[1].Policy == pending[2].Policy {
			t.Errorf("%s enforced: %v (pending %v)", dir, enforced, pending)
		}
		stagedDecides := 0
		for _, sf := range fx.ShapeFlows(dir) {
			if slices.ContainsFunc(fx.ExpectIn(EnforcedScope, dir, sf.Flow), func(v Verdict) bool { return v.Kind == v3.KindStagedGlobalNetworkPolicy }) {
				t.Errorf("%s %s: enforced trace names a staged policy", dir, sf.Name)
			}
			if sf.Hit && !slices.Equal(fx.ExpectIn(EnforcedScope, dir, sf.Flow), fx.ExpectIn(PendingScope, dir, sf.Flow)[1:]) {
				stagedDecides++
			}
		}
		if stagedDecides == 0 {
			t.Errorf("%s: no aimed flow is decided differently in the two scopes", dir)
		}
	}
}

// The list is a copy each time, so one test changing it can't change what another excludes.
func TestKnownDifferencesIsACopy(t *testing.T) {
	first := KnownDifferences()
	first[0].Difference, first[0].Where[0] = "changed", BPF
	if again := KnownDifferences(); again[0].Difference == "changed" || again[0].Where[0] == BPF {
		t.Errorf("a caller's change reached the list: %v", again[0])
	}
}

// A peer endpoint carries the label of its rule's set, so that a rule keyed on that set finds the
// named ports the endpoint declares; the local endpoint and the address no rule names are in no set.
func TestEndpointLabels(t *testing.T) {
	p := DefaultShapes()
	fx := Build(Spec{Seed: DefaultSeed, Shapes: &p})
	key := "policyscale.projectcalico.org/set"

	peer4, peer6 := p.PeerIPv4.Addr().Next(), p.PeerIPv6.Addr().Next()
	got := fx.EndpointLabels(ResourceOptions{}, peer4, peer6)
	if got[key] != "shape-peer-0" || len(got) != 1 {
		t.Errorf("first peer: got %v, want %s=shape-peer-0", got, key)
	}
	if got := fx.EndpointLabels(ResourceOptions{}, p.LocalIPv4, p.LocalIPv6); len(got) != 0 {
		t.Errorf("local endpoint: got %v, want no labels", got)
	}
	if got := fx.EndpointLabels(ResourceOptions{SetLabelKey: "k"}, peer4); got["k"] != "shape-peer-0" {
		t.Errorf("custom label key: got %v", got)
	}
}

// A dataplane that can't apply a kind of rule gets a set without it; the rules left keep
// alternating between allow and deny, and no flow is aimed at a rule that isn't there.
func TestShapesLeaveOut(t *testing.T) {
	all := Build(RuleShapes())
	for _, leaveOut := range [][]Difference{LeaveOutAt(Nftables), {ProtocolNamesOnBPF}} {
		p := DefaultShapes()
		p.LeaveOut = leaveOut
		fx := Build(Spec{Seed: DefaultSeed, Shapes: &p})
		for _, dir := range []Direction{Ingress, Egress} {
			if len(fx.ShapeRules(dir)) == len(all.ShapeRules(dir)) {
				t.Errorf("%v: no %v rule was left out", leaveOut, dir)
			}
			n := 0
			for _, r := range fx.ShapeRules(dir) {
				for _, f := range r.Flows {
					if slices.ContainsFunc(f.Differences, func(d Difference) bool { return slices.Contains(leaveOut, d) }) {
						t.Errorf("%v: %v rule %q should have been left out", leaveOut, dir, r.Name)
						break
					}
				}
				if r.Tier != p.Tier {
					continue
				}
				_, rule, _ := fx.ruleAt(dir, ordinalOf(fx, dir, r))
				if want := []string{"allow", "deny"}[n%2]; rule.action != want {
					t.Errorf("%v: %v rule %q is %s, want %s", leaveOut, dir, r.Name, rule.action, want)
				}
				n++
			}
		}
	}

	p := DefaultShapes()
	p.LeaveOut = LeaveOutAt(Nftables)
	fx := Build(Spec{Seed: DefaultSeed, Shapes: &p})
	for _, o := range fx.Resources(ResourceOptions{Enforced: true}) {
		gnp, ok := o.(*v3.GlobalNetworkPolicy)
		if !ok {
			continue
		}
		for _, r := range append(gnp.Spec.Ingress, gnp.Spec.Egress...) {
			if (r.ICMP != nil && r.ICMP.Code != nil) || (r.NotICMP != nil && r.NotICMP.Code != nil) {
				t.Errorf("policy %s still has an ICMP type and code rule", gnp.Name)
			}
		}
	}
	if len(LeaveOutAt(Iptables, BPF)) != 0 {
		t.Errorf("iptables and BPF apply every rule, got %v", LeaveOutAt(Iptables, BPF))
	}
}

// LeaveOut drops whole rules, so it refuses a difference that is marked on single flows rather
// than ignore it; ShapeFlows leaves those flows out.
func TestShapesLeaveOutRefusesFlowDifferences(t *testing.T) {
	for _, d := range []Difference{SCTPPorts, NegatedICMPTypeAndCode, OneFamilyNegatedCIDRs, UnparsedProtocolsOnBPF, HostEndpoints} {
		p := DefaultShapes()
		p.LeaveOut = []Difference{d}
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), string(d)) {
					t.Errorf("LeaveOut %s: got panic %v, want one that names it", d, r)
				}
			}()
			Build(Spec{Seed: DefaultSeed, Shapes: &p})
		}()
	}
}

// Every SCTP and UDP-Lite flow is marked, so that a test against BPF can leave them all out.
func TestUnparsedProtocolsMarked(t *testing.T) {
	fx := Build(RuleShapes())
	for _, dir := range []Direction{Ingress, Egress} {
		seen := 0
		for _, f := range fx.ShapeFlows(dir) {
			unparsed := f.Flow.Protocol == ProtocolSCTP || f.Flow.Protocol == ProtocolUDPLite
			if unparsed {
				seen++
			}
			if unparsed != slices.Contains(f.Differences, UnparsedProtocolsOnBPF) {
				t.Errorf("%v flow %q: protocol %d, differences %v", dir, f.Name, f.Flow.Protocol, f.Differences)
			}
		}
		if seen == 0 {
			t.Errorf("%v: no SCTP or UDP-Lite flows to check", dir)
		}
		for _, f := range fx.ShapeFlows(dir, DifferencesAt(BPF)...) {
			if f.Flow.Protocol == ProtocolSCTP || f.Flow.Protocol == ProtocolUDPLite {
				t.Errorf("%v flow %q should be left out on BPF", dir, f.Name)
			}
		}
	}
}

// A network set big enough to pass the API server's request limit once server-side apply records
// its fields is split into several, which the rules still pick by one label: together they hold
// exactly the set's members.
func TestLargeSetsAreSplit(t *testing.T) {
	fx := baselineFixture()
	byLabel := map[string][]string{}
	largest := 0
	for _, obj := range fx.Resources(ResourceOptions{}) {
		gns, ok := obj.(*v3.GlobalNetworkSet)
		if !ok {
			continue
		}
		largest = max(largest, len(gns.Spec.Nets))
		id := gns.Labels[defaultSetLabelKey]
		byLabel[id] = append(byLabel[id], gns.Spec.Nets...)
	}
	if largest > maxNetsPerNetworkSet {
		t.Errorf("largest network set has %d nets, more than %d", largest, maxNetsPerNetworkSet)
	}
	for _, id := range fx.setOrder {
		if !slices.Equal(byLabel[id], fx.sets[id].members) {
			t.Errorf("set %s: the network sets labelled for it hold %d nets, the set %d", id, len(byLabel[id]), len(fx.sets[id].members))
		}
	}
	if len(fx.sets[fx.setOrder[len(fx.setOrder)-1]].members) <= maxNetsPerNetworkSet {
		t.Fatal("the baseline's largest set no longer needs splitting; the test checks nothing")
	}
}
