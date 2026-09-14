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

package policyscale_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	. "github.com/projectcalico/calico/app-policy/policyscale"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

func TestPresetScale(t *testing.T) {
	cases := []struct {
		name                       string
		spec                       Spec
		ingressRules, egressRules  int
		ingressPolicies, egressPol int
		sets                       int
	}{
		{"baseline", Baseline(), 294 * 68, 0, 294, 0, 3708 + 1},
		{"egress", EgressAllowList(), 0, 301 * 62, 0, 301, 3862},
		{"composite", Composite(), 294 * 68, 301 * 62, 294, 301, 3708 + 1 + 3862},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := Build(c.spec)
			if got := fx.Rules(Ingress); got != c.ingressRules {
				t.Errorf("ingress rules: got %d, want %d", got, c.ingressRules)
			}
			if got := fx.Rules(Egress); got != c.egressRules {
				t.Errorf("egress rules: got %d, want %d", got, c.egressRules)
			}
			if got := fx.Policies(Ingress); got != c.ingressPolicies {
				t.Errorf("ingress policies: got %d, want %d", got, c.ingressPolicies)
			}
			if got := fx.Policies(Egress); got != c.egressPol {
				t.Errorf("egress policies: got %d, want %d", got, c.egressPol)
			}
			if got := fx.IPSets(); got != c.sets {
				t.Errorf("IP sets: got %d, want %d", got, c.sets)
			}
			if got := fx.Tiers(); len(got) != 1 || got[0] != "perimeter" {
				t.Errorf("tiers: got %v, want [perimeter]", got)
			}
			store := fx.NewStore()
			if got := len(store.PolicyByID); got != c.ingressPolicies+c.egressPol {
				t.Errorf("store policies: got %d", got)
			}
			if got := len(store.IPSetByID); got != c.sets {
				t.Errorf("store IP sets: got %d, want %d", got, c.sets)
			}
			if got := len(fx.Updates()); got != c.sets+c.ingressPolicies+c.egressPol {
				t.Errorf("updates: got %d", got)
			}
		})
	}
}

func TestBaselineMembersMatchMeasurement(t *testing.T) {
	fx := Build(Baseline())
	// The histogram sums to 3,708 sets. Sizes are drawn uniformly within each bucket, so the
	// 1,000-9,999 bucket alone contributes ~870k members and the set holds about 1M in all, four
	// times the measured ~256k; the measured distribution was skewed towards the small end of each
	// bucket. Pin the generated total so that a change to it is deliberate.
	if got := fx.IPSetMembers(); got < 950_000 || got > 1_100_000 {
		t.Errorf("baseline members: got %d, want about 1M", got)
	}
}

func TestMissingSets(t *testing.T) {
	spec := Baseline()
	spec.Baseline.MissingIPSets = 8
	fx := Build(spec)
	if got := fx.MissingIPSets(); got != 8 {
		t.Fatalf("missing sets: got %d, want 8", got)
	}
	if fx.MissingSetReferences() < 8 {
		t.Errorf("missing references: got %d, want at least one per missing set", fx.MissingSetReferences())
	}
	if got := len(fx.NewStore().IPSetByID); got != 3709-8 {
		t.Errorf("store sets: got %d, want %d", got, 3709-8)
	}
	// Every resource is still rendered: a cluster never has a missing set.
	if got := countKind(fx.Resources(ResourceOptions{}), v3.KindGlobalNetworkSet); got != 3709 {
		t.Errorf("rendered sets: got %d, want 3709", got)
	}
}

func TestDeterministic(t *testing.T) {
	a, b := render(t, Build(Composite())), render(t, Build(Composite()))
	if !bytes.Equal(a, b) {
		t.Fatal("two builds of the same spec rendered differently")
	}
	other := Composite()
	other.Seed++
	if bytes.Equal(a, render(t, Build(other))) {
		t.Fatal("a different seed rendered the same resources")
	}
}

func TestEgressTargetAndOracle(t *testing.T) {
	fx := Build(EgressAllowList())
	tgt := fx.EgressTarget()
	if tgt == nil {
		t.Fatal("no egress target")
	}
	numRules := 301 * 62
	if tgt.Ordinal != int(0.65*float64(numRules)) || tgt.RulesWalked != tgt.Ordinal+1 {
		t.Errorf("target position: %+v", tgt)
	}
	want := []Verdict{{Kind: v3.KindGlobalNetworkPolicy, Tier: "perimeter", Policy: tgt.Policy, Index: tgt.RuleIndex, Action: "allow"}}
	for name, f := range map[string]*Flow{
		"tail port":    NewFlow(SourceIP, DefaultSourcePort, tgt.AddrInCIDR, int(tgt.TailPort)),
		"popular port": NewFlow(SourceIP, DefaultSourcePort, tgt.AddrInCIDR, int(tgt.PopularPort)),
		"aimed":        fx.MatchingFlow(Egress, tgt.Ordinal),
	} {
		if got := fx.Expect(Egress, f); !equalVerdicts(got, want) {
			t.Errorf("%s flow %v: got %v, want %v", name, f, got, want)
		}
	}

	denied := fx.Expect(Egress, fx.DeniedFlow(Egress))
	wantDenied := []Verdict{{Kind: v3.KindGlobalNetworkPolicy, Tier: "perimeter", Policy: "egress-000", Index: TierDefaultIndex, Action: "deny"}}
	if !equalVerdicts(denied, wantDenied) {
		t.Errorf("denied flow: got %v, want %v", denied, wantDenied)
	}

	// A flow aimed at any rule is matched by that rule or an earlier one, never a later one.
	for _, ordinal := range []int{0, 1, 4000, 18661} {
		f := fx.MatchingFlow(Egress, ordinal)
		got := fx.Expect(Egress, f)
		if len(got) == 0 || got[0].Index == TierDefaultIndex {
			t.Errorf("flow aimed at rule %d was denied: %v", ordinal, got)
			continue
		}
		if pos := egressOrdinal(got[0]); pos > ordinal {
			t.Errorf("flow aimed at rule %d matched later rule %d (%v)", ordinal, pos, got[0])
		}
	}
}

func TestBaselineOracle(t *testing.T) {
	fx := Build(Baseline())
	denied := fx.Expect(Ingress, fx.DeniedFlow(Ingress))
	wantDenied := []Verdict{{Kind: v3.KindGlobalNetworkPolicy, Tier: "perimeter", Policy: "policy-000", Index: TierDefaultIndex, Action: "deny"}}
	if !equalVerdicts(denied, wantDenied) {
		t.Errorf("denied flow: got %v, want %v", denied, wantDenied)
	}

	// The set-guarded rules match a flow drawn from their set; the port-guarded ones never do,
	// so a flow aimed at one of those is matched by the first port-guarded rule instead.
	passes, finals := 0, 0
	for ordinal := 0; ordinal < fx.Rules(Ingress); ordinal += 97 {
		f := fx.MatchingFlow(Ingress, ordinal)
		got := fx.Expect(Ingress, f)
		if len(got) == 0 {
			t.Fatalf("empty trace for %v", f)
		}
		if got[0].Index == TierDefaultIndex {
			t.Errorf("flow aimed at rule %d was denied: %v", ordinal, got)
			continue
		}
		if pos := baselineOrdinal(got[0]); pos > ordinal {
			t.Errorf("flow aimed at rule %d matched later rule %d (%v)", ordinal, pos, got[0])
		}
		switch got[0].Action {
		case "pass":
			passes++
			// A pass with no further tier and no profiles ends in the profile deny.
			if len(got) != 2 || got[1].Kind != v3.KindProfile || got[1].Action != "deny" {
				t.Errorf("pass trace for rule %d: %v", ordinal, got)
			}
		default:
			finals++
			if len(got) != 1 {
				t.Errorf("final trace for rule %d: %v", ordinal, got)
			}
		}
	}
	if passes == 0 {
		t.Error("no aimed flow reached a pass rule")
	}
}

func TestSampler(t *testing.T) {
	fx := Build(Composite())
	s := fx.NewSampler(1, FlowModel{Direction: Egress, MissFraction: 0.2, RepeatFraction: 0.3})
	seen := map[string]int{}
	denied := 0
	for i := 0; i < 2000; i++ {
		f := s.Next()
		if f.Protocol != ProtocolTCP || f.SrcPort < 32768 {
			t.Fatalf("unexpected flow %v", f)
		}
		key := fmt.Sprintf("%s>%s:%d", f.SrcIP, f.DstIP, f.DstPort)
		seen[key]++
		if v := fx.Expect(Egress, f); v[0].Index == TierDefaultIndex {
			denied++
		}
	}
	if denied < 200 || denied > 1000 {
		t.Errorf("denied flows: %d of 2000, want roughly 20%% plus their repeats", denied)
	}
	repeats := 0
	for _, n := range seen {
		repeats += n - 1
	}
	if repeats < 300 {
		t.Errorf("repeated flows: %d of 2000, want roughly 30%%", repeats)
	}
}

func TestResourcesValidateAndRoundTrip(t *testing.T) {
	fx := Build(Composite())
	opts := ResourceOptions{Selector: "policyscale.projectcalico.org/target == 'true'"}
	objs := fx.Resources(opts)
	if got := countKind(objs, v3.KindTier); got != 1 {
		t.Errorf("tiers: %d", got)
	}
	if got := countKind(objs, v3.KindGlobalNetworkPolicy); got != 294+301 {
		t.Errorf("policies: %d", got)
	}
	if got := countKind(objs, v3.KindGlobalNetworkSet); got != 3709+3862 {
		t.Errorf("sets: %d", got)
	}

	// Validate a sample through the API validator: the tier, the first policies of each direction,
	// the target policy, and a few sets including the largest.
	validated := 0
	for _, obj := range objs {
		validate := false
		switch o := obj.(type) {
		case *v3.Tier:
			validate = true
		case *v3.GlobalNetworkPolicy:
			validate = strings.HasSuffix(o.Name, "-000") || strings.HasSuffix(o.Name, "-001") || o.Name == "perimeter."+fx.EgressTarget().Policy
		case *v3.GlobalNetworkSet:
			validate = o.Name == SentinelIPSetID || strings.HasSuffix(o.Name, "-0000") || len(o.Spec.Nets) > 50000
		}
		if !validate {
			continue
		}
		if err := validator.Validate(obj); err != nil {
			t.Errorf("%T %s: %v", obj, obj.(interface{ GetName() string }).GetName(), err)
		}
		validated++
	}
	if validated < 8 {
		t.Errorf("validated only %d objects", validated)
	}

	docs := bytes.Split(render(t, fx, opts), []byte("\n---\n"))
	if len(docs) != len(objs) {
		t.Fatalf("yaml documents: got %d, want %d", len(docs), len(objs))
	}
	var gnp v3.GlobalNetworkPolicy
	if err := yaml.Unmarshal(docs[1], &gnp); err != nil {
		t.Fatal(err)
	}
	if gnp.Name != "perimeter.policy-000" || gnp.Spec.Tier != "perimeter" || gnp.Spec.Selector != opts.Selector {
		t.Errorf("first policy: %+v", gnp.ObjectMeta)
	}
	if len(gnp.Spec.Types) != 1 || gnp.Spec.Types[0] != v3.PolicyTypeIngress || len(gnp.Spec.Ingress) != 68 {
		t.Errorf("first policy rules: types=%v ingress=%d", gnp.Spec.Types, len(gnp.Spec.Ingress))
	}
	for i, r := range gnp.Spec.Ingress {
		if len(r.Destination.Ports) > 0 && (r.Protocol == nil || r.Protocol.String() != "TCP") {
			t.Errorf("rule %d has ports but protocol %v", i, r.Protocol)
		}
	}
}

func render(t *testing.T, fx *Fixture, opts ...ResourceOptions) []byte {
	t.Helper()
	var o ResourceOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	var buf bytes.Buffer
	if err := fx.WriteYAML(&buf, o); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func countKind(objs []runtime.Object, kind string) int {
	n := 0
	for _, o := range objs {
		if o.GetObjectKind().GroupVersionKind().Kind == kind {
			n++
		}
	}
	return n
}

func equalVerdicts(a, b []Verdict) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// egressOrdinal and baselineOrdinal recover a rule's position in the walk from its verdict, using
// the presets' policy naming and rule counts.
func egressOrdinal(v Verdict) int {
	var n int
	fmt.Sscanf(v.Policy, "egress-%d", &n)
	return n*62 + v.Index
}

func baselineOrdinal(v Verdict) int {
	var n int
	fmt.Sscanf(v.Policy, "policy-%d", &n)
	return n*68 + v.Index
}
