package optimize

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestSplitPolicyOnSelectors_NoSelectors_NoChange(t *testing.T) {
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
	if out[0] != runtime.Object(gnp) {
		t.Fatalf("expected pass-through of original object when no selectors present")
	}
}

func TestSplitPolicyOnSelectors_SplitIngressIntoGroups(t *testing.T) {
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

	// Cast and verify each split policy
	pols := make([]*apiv3.GlobalNetworkPolicy, 0, len(out))
	for i, obj := range out {
		pol, ok := obj.(*apiv3.GlobalNetworkPolicy)
		if !ok {
			t.Fatalf("out[%d] not a GlobalNetworkPolicy: %#v", i, obj)
		}
		pols = append(pols, pol)
	}

	// Expected groups after sorting within action runs: [Allow:a], [Allow:b], [Deny:x,x], [Allow:c,c]
	// Verify names have proper suffixes and contents are grouped.
	suffixLen := int(math.Floor(math.Log10(float64(len(pols))) + 1))
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

	// Check each group's selector moved to top-level and cleared in rules.
	// Group 0: single Allow a
	if pols[0].Spec.Selector != andSelectors("all()", "app == 'a'") {
		t.Fatalf("group 0 top-level selector unexpected: %s", pols[0].Spec.Selector)
	}
	if len(pols[0].Spec.Ingress) != 1 || pols[0].Spec.Ingress[0].Destination.Selector != "" || pols[0].Spec.Ingress[0].Destination.NamespaceSelector != "" {
		t.Fatalf("group 0 rule not cleared or wrong size: %#v", pols[0].Spec.Ingress)
	}

	// Group 1: single Allow b
	if pols[1].Spec.Selector != andSelectors("all()", "app == 'b'") {
		t.Fatalf("group 1 top-level selector unexpected: %s", pols[1].Spec.Selector)
	}
	if len(pols[1].Spec.Ingress) != 1 || pols[1].Spec.Ingress[0].Destination.Selector != "" {
		t.Fatalf("group 1 rule not cleared or wrong size: %#v", pols[1].Spec.Ingress)
	}

	// Group 2: two Deny x,x
	if pols[2].Spec.Selector != andSelectors("all()", "app == 'x'") {
		t.Fatalf("group 2 top-level selector unexpected: %s", pols[2].Spec.Selector)
	}
	if len(pols[2].Spec.Ingress) != 2 || pols[2].Spec.Ingress[0].Destination.Selector != "" || pols[2].Spec.Ingress[1].Destination.Selector != "" {
		t.Fatalf("group 2 rules not cleared or wrong size: %#v", pols[2].Spec.Ingress)
	}

	// Group 3: two Allow c,c
	if pols[3].Spec.Selector != andSelectors("all()", "app == 'c'") {
		t.Fatalf("group 3 top-level selector unexpected: %s", pols[3].Spec.Selector)
	}
	if len(pols[3].Spec.Ingress) != 2 || pols[3].Spec.Ingress[0].Destination.Selector != "" || pols[3].Spec.Ingress[1].Destination.Selector != "" {
		t.Fatalf("group 3 rules not cleared or wrong size: %#v", pols[3].Spec.Ingress)
	}
}

func TestSplitPolicyOnSelectors_SplitEgressIntoGroups(t *testing.T) {
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
	pols := make([]*apiv3.GlobalNetworkPolicy, 0, len(out))
	for i, obj := range out {
		pol, ok := obj.(*apiv3.GlobalNetworkPolicy)
		if !ok {
			t.Fatalf("out[%d] not a GlobalNetworkPolicy: %#v", i, obj)
		}
		pols = append(pols, pol)
	}
	// Name suffix checks for egress policies
	suffixLen := int(math.Floor(math.Log10(float64(len(pols))) + 1))
	for i, pol := range pols {
		expectedNameSuffix := "-e-" + fmt.Sprintf("%0*d", suffixLen, i)
		if !strings.HasSuffix(pol.Name, expectedNameSuffix) {
			t.Fatalf("unexpected egress policy name for index %d: %s (want suffix %s)", i, pol.Name, expectedNameSuffix)
		}
	}

	// Expected groups after sorting within action runs: [Deny:a], [Deny:b], [Allow:c,c]
	// Validate top-level selectors reflect Source selector and rules cleared.
	if pols[0].Spec.Selector != andSelectors("env == 'prod'", "app == 'a'") {
		t.Fatalf("egress group 0 top-level selector unexpected: %s", pols[0].Spec.Selector)
	}
	if pols[1].Spec.Selector != andSelectors("env == 'prod'", "app == 'b'") {
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

func TestAndSelectors(t *testing.T) {
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
