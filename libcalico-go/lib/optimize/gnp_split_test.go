// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package optimize

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

func TestSplitPolicyOnSelectors_NoSelectors_NoChange(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "nosplit"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Types:   []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
			Ingress: []apiv3.Rule{{Action: apiv3.Allow}},
			Egress:  []apiv3.Rule{{Action: apiv3.Allow}},
		},
	}

	out := splitPolicyOnSelectors(gnp)
	if len(out) != 1 {
		t.Fatalf("expected 1 object, got %d", len(out))
	}
	if out[0] != gnp {
		t.Fatalf("expected pass-through of original object when no selectors present")
	}
}

func TestSplitPolicyOnSelectors_SplitIngressIntoGroups(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "ingress-split"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Selector: "all()",
			Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress},
			Ingress: []apiv3.Rule{
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "app == 'b'"}},
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "app == 'a'"}},
				{Action: apiv3.Deny, Destination: apiv3.EntityRule{Selector: "app == 'x'"}},
				{Action: apiv3.Deny, Destination: apiv3.EntityRule{Selector: "app == 'x'"}},
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "app == 'c'"}},
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "app == 'c'"}},
			},
		},
	}

	out := splitPolicyOnSelectors(gnp)
	if len(out) != 4 {
		t.Fatalf("expected 4 split policies, got %d", len(out))
	}

	pols := out

	// Expected groups with new stable grouping (no alphabetical sort within action runs):
	// Original order of distinct selectors within each action run preserved, duplicates grouped:
	// [Allow:b], [Allow:a], [Deny:x,x], [Allow:c,c]
	// Verify names have proper suffixes and contents are grouped.
	suffixLen := 1
	for i, pol := range pols {
		expectedNameSuffix := "-i-" + fmt.Sprintf("%0*d", suffixLen, i)
		if !strings.HasSuffix(pol.Name, expectedNameSuffix) {
			t.Fatalf("unexpected policy name for index %d: %s (want suffix %s)", i, pol.Name, expectedNameSuffix)
		}
		if len(pol.Spec.Types) != 1 || pol.Spec.Types[0] != apiv3.PolicyTypeIngress {
			t.Fatalf("expected Types to be [Ingress], got %#v", pol.Spec.Types)
		}
		if pol.Spec.Egress != nil {
			t.Fatalf("expected Egress to be nil in split ingress policy")
		}
	}

	// Group 0: single Allow b
	if pols[0].Spec.Selector != "app == 'b'" {
		t.Fatalf("group 0 top-level selector unexpected: %s", pols[0].Spec.Selector)
	}
	if len(pols[0].Spec.Ingress) != 1 || pols[0].Spec.Ingress[0].Destination.Selector != "" || pols[0].Spec.Ingress[0].Destination.NamespaceSelector != "" {
		t.Fatalf("group 0 rule not cleared or wrong size: %#v", pols[0].Spec.Ingress)
	}

	// Group 1: single Allow a
	if pols[1].Spec.Selector != "app == 'a'" {
		t.Fatalf("group 1 top-level selector unexpected: %s", pols[1].Spec.Selector)
	}
	if len(pols[1].Spec.Ingress) != 1 || pols[1].Spec.Ingress[0].Destination.Selector != "" {
		t.Fatalf("group 1 rule not cleared or wrong size: %#v", pols[1].Spec.Ingress)
	}

	// Group 2: two Deny x,x
	if pols[2].Spec.Selector != "app == 'x'" {
		t.Fatalf("group 2 top-level selector unexpected: %s", pols[2].Spec.Selector)
	}
	if len(pols[2].Spec.Ingress) != 2 || pols[2].Spec.Ingress[0].Destination.Selector != "" || pols[2].Spec.Ingress[1].Destination.Selector != "" {
		t.Fatalf("group 2 rules not cleared or wrong size: %#v", pols[2].Spec.Ingress)
	}

	// Group 3: two Allow c,c
	if pols[3].Spec.Selector != "app == 'c'" {
		t.Fatalf("group 3 top-level selector unexpected: %s", pols[3].Spec.Selector)
	}
	if len(pols[3].Spec.Ingress) != 2 || pols[3].Spec.Ingress[0].Destination.Selector != "" || pols[3].Spec.Ingress[1].Destination.Selector != "" {
		t.Fatalf("group 3 rules not cleared or wrong size: %#v", pols[3].Spec.Ingress)
	}
}

func TestSplitPolicyOnSelectors_SplitEgressIntoGroups(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "egress-split"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Selector: "env == 'prod'",
			Types:    []apiv3.PolicyType{apiv3.PolicyTypeEgress},
			Egress: []apiv3.Rule{
				{Action: apiv3.Deny, Source: apiv3.EntityRule{Selector: "app == 'b'"}},
				{Action: apiv3.Deny, Source: apiv3.EntityRule{Selector: "app == 'a'"}},
				{Action: apiv3.Allow, Source: apiv3.EntityRule{Selector: "app == 'c'"}},
				{Action: apiv3.Allow, Source: apiv3.EntityRule{Selector: "app == 'c'"}},
			},
		},
	}

	out := splitPolicyOnSelectors(gnp)
	if len(out) != 3 {
		t.Fatalf("expected 3 split policies, got %d", len(out))
	}
	pols := out

	// Expected groups with new stable grouping: [Deny:b], [Deny:a], [Allow:c,c]
	suffixLen := 1
	for i, pol := range pols {
		expectedNameSuffix := "-e-" + fmt.Sprintf("%0*d", suffixLen, i)
		if !strings.HasSuffix(pol.Name, expectedNameSuffix) {
			t.Fatalf("unexpected egress policy name for index %d: %s (want suffix %s)", i, pol.Name, expectedNameSuffix)
		}
	}

	if pols[0].Spec.Selector != andSelectors("env == 'prod'", "app == 'b'") {
		t.Fatalf("egress group 0 top-level selector unexpected: %s", pols[0].Spec.Selector)
	}
	if pols[1].Spec.Selector != andSelectors("env == 'prod'", "app == 'a'") {
		t.Fatalf("egress group 1 top-level selector unexpected: %s", pols[1].Spec.Selector)
	}
	if pols[2].Spec.Selector != andSelectors("env == 'prod'", "app == 'c'") {
		t.Fatalf("egress group 2 top-level selector unexpected: %s", pols[2].Spec.Selector)
	}
	if len(pols[2].Spec.Egress) != 2 || pols[2].Spec.Egress[0].Source.Selector != "" || pols[2].Spec.Egress[1].Source.Selector != "" {
		t.Fatalf("egress group 2 rules not cleared or wrong size: %#v", pols[2].Spec.Egress)
	}
	for _, pol := range pols {
		if len(pol.Spec.Types) != 1 || pol.Spec.Types[0] != apiv3.PolicyTypeEgress {
			t.Fatalf("expected Types to be [Egress], got %#v", pol.Spec.Types)
		}
		if pol.Spec.Ingress != nil {
			t.Fatalf("expected Ingress to be nil in split egress policy")
		}
	}
}

func TestSplitPolicyOnSelectors_SkipsForApplyOnForward(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "apply-on-forward-nosplit"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			ApplyOnForward: true,
			Types:          []apiv3.PolicyType{apiv3.PolicyTypeIngress},
			Ingress: []apiv3.Rule{
				{
					Action:      apiv3.Allow,
					Destination: apiv3.EntityRule{Selector: "app == 'a'"},
				},
				{
					Action:      apiv3.Allow,
					Destination: apiv3.EntityRule{Selector: "app == 'b'"},
				},
			},
		},
	}
	out := splitPolicyOnSelectors(gnp)
	if len(out) != 1 || out[0] != gnp {
		t.Fatalf("expected no split for ApplyOnForward policy")
	}
}

func TestSplitPolicyOnSelectors_SkipsForPreDNAT(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "prednat-nosplit"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			PreDNAT: true,
			Types:   []apiv3.PolicyType{apiv3.PolicyTypeIngress},
			Ingress: []apiv3.Rule{
				{
					Action:      apiv3.Allow,
					Destination: apiv3.EntityRule{Selector: "app == 'a'"},
				},
				{
					Action:      apiv3.Allow,
					Destination: apiv3.EntityRule{Selector: "app == 'b'"},
				},
			},
		},
	}
	out := splitPolicyOnSelectors(gnp)
	if len(out) != 1 || out[0] != gnp {
		t.Fatalf("expected no split for PreDNAT policy")
	}
}

func TestSplitPolicyOnSelectors_SkipsForDoNotTrack(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "dnt-nosplit"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			DoNotTrack: true,
			Types:      []apiv3.PolicyType{apiv3.PolicyTypeIngress},
			Ingress: []apiv3.Rule{
				{
					Action:      apiv3.Allow,
					Destination: apiv3.EntityRule{Selector: "app == 'a'"},
				},
				{
					Action:      apiv3.Allow,
					Destination: apiv3.EntityRule{Selector: "app == 'b'"},
				},
			},
		},
	}
	out := splitPolicyOnSelectors(gnp)
	if len(out) != 1 || out[0] != gnp {
		t.Fatalf("expected no split for DoNotTrack policy")
	}
}

func TestSplitPolicyOnSelectors_NameTooLong_ReturnsOriginal(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	longName := strings.Repeat("n", 250) // 250 + "-i-0" => 254 > 253, triggers name-too-long recovery
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: longName},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Selector: "all()",
			Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress},
			Ingress: []apiv3.Rule{
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "app == 'a'"}},
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "app == 'b'"}},
			},
		},
	}

	out := splitPolicyOnSelectors(gnp)
	if len(out) != 1 || out[0] != gnp {
		t.Fatalf("expected original policy returned when name too long for split; got %d results", len(out))
	}
}

func TestAndSelectors(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	cases := []struct{ a, b, exp string }{
		{"", "app == 'x'", "app == 'x'"},
		{"all()", "app == 'x'", "app == 'x'"},
		{"app == 'x'", "", "app == 'x'"},
		{"app == 'x'", "all()", "app == 'x'"},
		{"app == 'x'", "env == 'prod'", selector.Normalise("((app == 'x') && (env == 'prod'))")},
	}
	for i, c := range cases {
		got := andSelectors(c.a, c.b)
		if got != c.exp {
			t.Fatalf("case %d: andSelectors(%q,%q)=%q want %q", i, c.a, c.b, got, c.exp)
		}
	}
}

func TestRulesGroupedOnSelector(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	rules := []apiv3.Rule{
		{Destination: apiv3.EntityRule{Selector: "a"}},
		{Destination: apiv3.EntityRule{Selector: "a"}},
		{Destination: apiv3.EntityRule{Selector: "b"}},
		{Destination: apiv3.EntityRule{Selector: "b", NamespaceSelector: "ns == 'x'"}},
		{Destination: apiv3.EntityRule{Selector: "b", NamespaceSelector: "ns == 'x'"}},
	}
	groups := slices.Collect(rulesGroupedOnSelector(rules, func(r *apiv3.Rule) *apiv3.EntityRule { return &r.Destination }))
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	if len(groups[0]) != 2 || len(groups[1]) != 1 || len(groups[2]) != 2 {
		t.Fatalf("unexpected group sizes: %d, %d, %d", len(groups[0]), len(groups[1]), len(groups[2]))
	}
	if !entityRuleSelectorsEqual(&groups[0][0].Destination, &groups[0][1].Destination) {
		t.Fatalf("group 0 items should have equal selectors")
	}
	if entityRuleSelectorsEqual(&groups[1][0].Destination, &groups[2][0].Destination) {
		t.Fatalf("groups 1 and 2 should differ due to namespace selector")
	}
}

func TestEntityRuleSelectorsEqual(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	a := &apiv3.EntityRule{Selector: "app == 'x'", NamespaceSelector: "ns == 'a'"}
	b := &apiv3.EntityRule{Selector: "app == 'x'", NamespaceSelector: "ns == 'a'"}
	c := &apiv3.EntityRule{Selector: "app == 'y'", NamespaceSelector: "ns == 'a'"}
	d := &apiv3.EntityRule{Selector: "app == 'x'", NamespaceSelector: "ns == 'b'"}
	if !entityRuleSelectorsEqual(a, b) {
		t.Fatalf("expected a==b")
	}
	if entityRuleSelectorsEqual(a, c) {
		t.Fatalf("expected a!=c (selector different)")
	}
	if entityRuleSelectorsEqual(a, d) {
		t.Fatalf("expected a!=d (namespace selector different)")
	}
}

func TestOptimizeGNP_CanonicalisesSelectors(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Selector:               "  ", // may canonicalize to all()
			NamespaceSelector:      "  all( ) ",
			ServiceAccountSelector: "sa == \"x\"\n\t",
			Ingress: []apiv3.Rule{{
				Source:      apiv3.EntityRule{Selector: "foo==\"bar\"", NamespaceSelector: "ns in{\"a\",\"b\"}"},
				Destination: apiv3.EntityRule{NotSelector: "has(label)\t"},
			}},
			Egress: []apiv3.Rule{{
				Source:      apiv3.EntityRule{NotSelector: " not has(x) ", ServiceAccounts: &apiv3.ServiceAccountMatch{Selector: " has(sa) "}},
				Destination: apiv3.EntityRule{Selector: "(all())"},
			}},
		},
	}

	// Compute expected normalized forms using the same Normalise function as the optimizer.
	expectTopSel := selector.Normalise(gnp.Spec.Selector)
	expectTopNS := selector.Normalise(gnp.Spec.NamespaceSelector)
	expectTopSA := selector.Normalise(gnp.Spec.ServiceAccountSelector)
	expectIngressSrcSel := selector.Normalise(gnp.Spec.Ingress[0].Source.Selector)
	expectIngressSrcNS := selector.Normalise(gnp.Spec.Ingress[0].Source.NamespaceSelector)
	expectIngressDstNotSel := selector.Normalise(gnp.Spec.Ingress[0].Destination.NotSelector)
	expectEgressSrcNotSel := selector.Normalise(gnp.Spec.Egress[0].Source.NotSelector)
	expectEgressDstSel := selector.Normalise(gnp.Spec.Egress[0].Destination.Selector)
	expectEgressSASel := selector.Normalise(gnp.Spec.Egress[0].Source.ServiceAccounts.Selector)

	out := Objects([]runtime.Object{gnp})
	if len(out) != 1 {
		t.Fatalf("expected single optimized GNP, got %d", len(out))
	}
	og, ok := out[0].(*apiv3.GlobalNetworkPolicy)
	if !ok {
		t.Fatalf("unexpected type: %#v", out[0])
	}
	// Optimizer strips explicit all() to empty string at top-level.
	expSel := expectTopSel
	if expSel == selector.All.String() {
		expSel = ""
	}
	if og.Spec.Selector != expSel {
		t.Errorf("top-level selector not canonicalized: got %q want %q", og.Spec.Selector, expSel)
	}
	if og.Spec.NamespaceSelector != expectTopNS {
		t.Errorf("ns selector not canonicalized: got %q want %q", og.Spec.NamespaceSelector, expectTopNS)
	}
	if og.Spec.ServiceAccountSelector != expectTopSA {
		t.Errorf("sa selector not canonicalized: got %q want %q", og.Spec.ServiceAccountSelector, expectTopSA)
	}
	// Ingress rule canonicalization
	if og.Spec.Ingress[0].Source.Selector != expectIngressSrcSel {
		t.Errorf("ingress source selector not canonicalized: got %q want %q", og.Spec.Ingress[0].Source.Selector, expectIngressSrcSel)
	}
	if og.Spec.Ingress[0].Source.NamespaceSelector != expectIngressSrcNS {
		t.Errorf("ingress source ns selector not canonicalized: got %q want %q", og.Spec.Ingress[0].Source.NamespaceSelector, expectIngressSrcNS)
	}
	if og.Spec.Ingress[0].Destination.NotSelector != expectIngressDstNotSel {
		t.Errorf("ingress dest notSelector not canonicalized: got %q want %q", og.Spec.Ingress[0].Destination.NotSelector, expectIngressDstNotSel)
	}
	// Egress rule canonicalization
	if og.Spec.Egress[0].Source.NotSelector != expectEgressSrcNotSel {
		t.Errorf("egress source notSelector not canonicalized: got %q want %q", og.Spec.Egress[0].Source.NotSelector, expectEgressSrcNotSel)
	}
	if og.Spec.Egress[0].Source.ServiceAccounts == nil || og.Spec.Egress[0].Source.ServiceAccounts.Selector != expectEgressSASel {
		t.Errorf("egress source sa selector not canonicalized: %#v want %q", og.Spec.Egress[0].Source.ServiceAccounts, expectEgressSASel)
	}
	if og.Spec.Egress[0].Destination.Selector != expectEgressDstSel {
		t.Errorf("egress dest selector not canonicalized: got %q want %q", og.Spec.Egress[0].Destination.Selector, expectEgressDstSel)
	}
}

func TestOptimizeGNP_RemovesRedundantRuleSelectors(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	// Top-level selectors
	topSel := "app == 'api'"
	topNS := "has(kubernetes.io/metadata.name)"
	topSelNorm := selector.Normalise(topSel)
	topNSNorm := selector.Normalise(topNS)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Selector:          topSel,
			NamespaceSelector: topNS,
			Egress: []apiv3.Rule{
				{Source: apiv3.EntityRule{Selector: topSel, NamespaceSelector: topNS}},           // redundant -> cleared
				{Source: apiv3.EntityRule{Selector: "app == 'other'", NamespaceSelector: topNS}}, // not redundant, will be split
			},
			Ingress: []apiv3.Rule{
				{Destination: apiv3.EntityRule{Selector: topSel, NamespaceSelector: topNS}},       // redundant -> cleared
				{Destination: apiv3.EntityRule{Selector: topSel, NamespaceSelector: "ns == 'x'"}}, // not redundant, will be split
			},
		},
	}

	out := Objects([]runtime.Object{gnp})

	// Expect exactly 2 split policies for ingress and 2 for egress.
	var ingressPolicies, egressPolicies []*apiv3.GlobalNetworkPolicy
	for _, obj := range out {
		pol := obj.(*apiv3.GlobalNetworkPolicy)
		if len(pol.Spec.Ingress) > 0 && pol.Spec.Egress == nil {
			ingressPolicies = append(ingressPolicies, pol)
		}
		if len(pol.Spec.Egress) > 0 && pol.Spec.Ingress == nil {
			egressPolicies = append(egressPolicies, pol)
		}
	}
	if len(ingressPolicies) != 2 || len(egressPolicies) != 2 {
		t.Fatalf("expected 2 ingress and 2 egress split policies, got %d ingress, %d egress", len(ingressPolicies), len(egressPolicies))
	}

	// Egress: both policies should have exactly 1 rule and cleared per-rule selectors.
	for _, pol := range egressPolicies {
		if len(pol.Spec.Egress) != 1 {
			t.Fatalf("egress split policy should have 1 rule, got %d", len(pol.Spec.Egress))
		}
		r := pol.Spec.Egress[0]
		if r.Source.Selector != "" || r.Source.NamespaceSelector != "" {
			t.Fatalf("egress rule selectors not cleared: %#v", r.Source)
		}
		if selector.Normalise(pol.Spec.NamespaceSelector) != topNSNorm && !strings.Contains(pol.Spec.NamespaceSelector, "kubernetes.io/metadata.name") {
			t.Fatalf("egress policy should carry namespace selector, got %q", pol.Spec.NamespaceSelector)
		}
	}
	// Ensure one policy retains topSel and the other has a different selector (indicating split).
	var foundTop, foundDifferent bool
	selectorsSet := map[string]struct{}{}
	for _, pol := range egressPolicies {
		selectorsSet[pol.Spec.Selector] = struct{}{}
		if selector.Normalise(pol.Spec.Selector) == topSelNorm {
			foundTop = true
		} else {
			foundDifferent = true
		}
	}
	if !foundTop || !foundDifferent || len(selectorsSet) != 2 {
		t.Fatalf("egress split selectors unexpected: foundTop=%v foundDifferent=%v selectors=%v", foundTop, foundDifferent, selectorsSet)
	}

	// Ingress: both policies should have exactly 1 rule and cleared per-rule destination selectors.
	for _, pol := range ingressPolicies {
		if len(pol.Spec.Ingress) != 1 {
			t.Fatalf("ingress split policy should have 1 rule, got %d", len(pol.Spec.Ingress))
		}
		r := pol.Spec.Ingress[0]
		if r.Destination.Selector != "" || r.Destination.NamespaceSelector != "" {
			t.Fatalf("ingress rule selectors not cleared: %#v", r.Destination)
		}
	}
	// Ensure one ingress policy retains topSel/topNS and the other contains the ns=='x' constraint.
	var foundIngressTop, foundIngressNSX bool
	for _, pol := range ingressPolicies {
		if selector.Normalise(pol.Spec.Selector) == topSelNorm && selector.Normalise(pol.Spec.NamespaceSelector) == topNSNorm {
			foundIngressTop = true
		}
		if strings.Contains(pol.Spec.NamespaceSelector, "ns == 'x'") || strings.Contains(pol.Spec.NamespaceSelector, "ns == \"x\"") {
			foundIngressNSX = true
		}
	}
	if !foundIngressTop || !foundIngressNSX {
		t.Fatalf("ingress split selectors unexpected: top=%v nsX=%v", foundIngressTop, foundIngressNSX)
	}
}

func TestOptimizeGNP_PreservesEmptyRuleSelectors(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp-empty-selectors"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Selector: selector.All.String(),
			Egress: []apiv3.Rule{{
				Source:      apiv3.EntityRule{Selector: "   ", NamespaceSelector: "\n\t"},
				Destination: apiv3.EntityRule{NotSelector: "   "},
			}},
			Ingress: []apiv3.Rule{{
				Destination: apiv3.EntityRule{Selector: "   ", NamespaceSelector: "   ", ServiceAccounts: &apiv3.ServiceAccountMatch{Selector: "   "}},
			}},
		},
	}

	out := Objects([]runtime.Object{gnp})
	og := out[0].(*apiv3.GlobalNetworkPolicy)
	// Egress: rule-level whitespace selectors should remain empty after normalization.
	if og.Spec.Egress[0].Source.Selector != "" || og.Spec.Egress[0].Source.NamespaceSelector != "" {
		t.Errorf("expected empty egress source selectors, got: %#v", og.Spec.Egress[0].Source)
	}
	if og.Spec.Egress[0].Destination.NotSelector != "" {
		t.Errorf("expected empty egress destination notSelector, got: %q", og.Spec.Egress[0].Destination.NotSelector)
	}
	// Ingress: destination selector/ns and SA selector should be empty.
	if og.Spec.Ingress[0].Destination.Selector != "" || og.Spec.Ingress[0].Destination.NamespaceSelector != "" {
		t.Errorf("expected empty ingress destination selectors, got: %#v", og.Spec.Ingress[0].Destination)
	}
	if og.Spec.Ingress[0].Destination.ServiceAccounts == nil || og.Spec.Ingress[0].Destination.ServiceAccounts.Selector != "" {
		t.Errorf("expected empty SA selector, got: %#v", og.Spec.Ingress[0].Destination.ServiceAccounts)
	}
}

func TestOptimizeGNP_SortsIngressByDestSelectorWithinAction(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp-sort-ingress"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Ingress: []apiv3.Rule{
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "z"}},
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "a"}},
				{Action: apiv3.Deny, Destination: apiv3.EntityRule{Selector: "c"}},
				{Action: apiv3.Deny, Destination: apiv3.EntityRule{Selector: "b"}},
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "n"}},
				{Action: apiv3.Allow, Destination: apiv3.EntityRule{Selector: "m"}},
			},
		},
	}

	groupGNPByRuleSelector(gnp)
	// New behavior: stable grouping only, original relative order of unique selectors within each contiguous action run preserved.
	if gnp.Spec.Ingress[0].Destination.Selector != "z" || gnp.Spec.Ingress[1].Destination.Selector != "a" ||
		gnp.Spec.Ingress[2].Destination.Selector != "c" || gnp.Spec.Ingress[3].Destination.Selector != "b" ||
		gnp.Spec.Ingress[4].Destination.Selector != "n" || gnp.Spec.Ingress[5].Destination.Selector != "m" {
		// Update failure message to show full order
		var order []string
		for _, r := range gnp.Spec.Ingress {
			order = append(order, r.Destination.Selector)
		}
		// Use Fatalf for concise failure.
		// nolint:staticcheck
		t.Fatalf("unexpected ingress ordering: %v", order)
	}
}

func TestOptimizeGNP_SortsEgressBySourceSelectorWithinAction(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp-sort-egress"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Egress: []apiv3.Rule{
				{Action: apiv3.Deny, Source: apiv3.EntityRule{Selector: "delta"}},
				{Action: apiv3.Deny, Source: apiv3.EntityRule{Selector: "alpha"}},
				{Action: apiv3.Allow, Source: apiv3.EntityRule{Selector: "zeta"}},
				{Action: apiv3.Allow, Source: apiv3.EntityRule{Selector: "beta"}},
				{Action: apiv3.Deny, Source: apiv3.EntityRule{Selector: "gamma"}},
			},
		},
	}

	groupGNPByRuleSelector(gnp)
	if gnp.Spec.Egress[0].Source.Selector != "delta" || gnp.Spec.Egress[1].Source.Selector != "alpha" ||
		gnp.Spec.Egress[2].Source.Selector != "zeta" || gnp.Spec.Egress[3].Source.Selector != "beta" ||
		gnp.Spec.Egress[4].Source.Selector != "gamma" {
		var order []string
		for _, r := range gnp.Spec.Egress {
			order = append(order, r.Source.Selector)
		}
		t.Fatalf("unexpected egress ordering: %v", order)
	}
}

func TestOptimizeGNP_PreservesEmptyTopLevelServiceAccountSelector(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp-empty-top-sa"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Selector:               "all()",
			ServiceAccountSelector: "   ",                               // should remain empty, not all()
			Ingress:                []apiv3.Rule{{Action: apiv3.Allow}}, // ensure policy retained (not dropped as empty)
		},
	}

	out := Objects([]runtime.Object{gnp})
	if len(out) != 1 {
		t.Fatalf("expected 1 optimized object, got %d", len(out))
	}
	og := out[0].(*apiv3.GlobalNetworkPolicy)
	if og.Spec.ServiceAccountSelector != "" {
		t.Fatalf("top-level ServiceAccountSelector should remain empty, got %q", og.Spec.ServiceAccountSelector)
	}
}

// New test: duplicate rule detection ignores Metadata differences.
func TestOptimizeGNP_DuplicateRulesIgnoreMetadata(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "dup-meta"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Ingress: []apiv3.Rule{
				// Two allow-all rules differing only by metadata; second should be removed.
				{Action: apiv3.Allow, Metadata: &apiv3.RuleMetadata{Annotations: map[string]string{"id": "1"}}},
				{Action: apiv3.Allow, Metadata: &apiv3.RuleMetadata{Annotations: map[string]string{"id": "2"}}},
				{Action: apiv3.Deny}, // unreachable after terminal allow, trimmed
			},
		},
	}
	out := Objects([]runtime.Object{gnp})
	if len(out) != 1 {
		t.Fatalf("expected 1 optimized object, got %d", len(out))
	}
	og := out[0].(*apiv3.GlobalNetworkPolicy)
	if len(og.Spec.Ingress) != 1 {
		t.Fatalf("expected 1 rule, got %d: %#v", len(og.Spec.Ingress), og.Spec.Ingress)
	}
	if og.Spec.Ingress[0].Action != apiv3.Allow {
		t.Fatalf("unexpected rule action: %s", og.Spec.Ingress[0].Action)
	}
	if og.Spec.Ingress[0].Metadata == nil || og.Spec.Ingress[0].Metadata.Annotations["id"] != "1" {
		t.Fatalf("expected rule collapse: %#v", og.Spec.Ingress)
	}
}

func TestOptimizeGNP_RemovesDuplicateNonTerminalRule(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp := &apiv3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkPolicy, APIVersion: apiv3.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "dup-non-terminal"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Ingress: []apiv3.Rule{
				// Non-terminal allow rule (has selector) with metadata.
				{Action: apiv3.Allow, Source: apiv3.EntityRule{Selector: "app == 'x'"}, Metadata: &apiv3.RuleMetadata{Annotations: map[string]string{"id": "1"}}},
				// Duplicate of first rule differing only by metadata; should be removed by duplicate detection (seenRules.Contains).
				{Action: apiv3.Allow, Source: apiv3.EntityRule{Selector: "app == 'x'"}, Metadata: &apiv3.RuleMetadata{Annotations: map[string]string{"id": "2"}}},
				// Another distinct non-terminal rule.
				{Action: apiv3.Deny, Source: apiv3.EntityRule{Selector: "app == 'y'"}},
				// Terminal deny-all rule.
				{Action: apiv3.Deny},
				// Unreachable rule after terminal, should be trimmed.
				{Action: apiv3.Allow, Source: apiv3.EntityRule{Selector: "app == 'z'"}},
			},
		},
	}

	out := Objects([]runtime.Object{gnp})
	if len(out) != 1 {
		t.Fatalf("expected 1 optimized object, got %d", len(out))
	}
	og := out[0].(*apiv3.GlobalNetworkPolicy)
	if len(og.Spec.Ingress) != 3 { // duplicate removed; unreachable trimmed
		// Provide details for debugging.
		var sels []string
		for _, r := range og.Spec.Ingress {
			sels = append(sels, r.Source.Selector)
		}
		t.Fatalf("expected 3 ingress rules, got %d: selectors=%v", len(og.Spec.Ingress), sels)
	}
	if og.Spec.Ingress[0].Action != apiv3.Allow || og.Spec.Ingress[0].Source.Selector != "app == \"x\"" {
		t.Fatalf("unexpected first rule: %#v", og.Spec.Ingress[0])
	}
	if og.Spec.Ingress[1].Action != apiv3.Deny || og.Spec.Ingress[1].Source.Selector != "app == \"y\"" {
		t.Fatalf("unexpected second rule: %#v", og.Spec.Ingress[1])
	}
	if og.Spec.Ingress[2].Action != apiv3.Deny || og.Spec.Ingress[2].Source.Selector != "" {
		t.Fatalf("expected terminal deny-all third rule, got: %#v", og.Spec.Ingress[2])
	}
}
