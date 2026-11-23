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
	"slices"
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
		"src ports", "dst ports", "not dst ports", "src net", "dst net", "not src net", "not dst net",
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
		for _, obj := range fx.Resources(ResourceOptions{Staged: staged}) {
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
	for _, kd := range KnownDifferences {
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
