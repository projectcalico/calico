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
