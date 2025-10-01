package optimize

import (
	"reflect"
	"strings"
	"testing"

	apia "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func newGNP(name string) *apia.GlobalNetworkPolicy {
	return &apia.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       apia.KindGlobalNetworkPolicy,
			APIVersion: apia.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

func TestObjects_PassThrough_UnoptimizedSlice(t *testing.T) {
	// Use an unhandled type (IPPool) to verify pass-through behavior for a slice.
	ipp1 := &apia.IPPool{TypeMeta: metav1.TypeMeta{Kind: apia.KindIPPool, APIVersion: apia.GroupVersionCurrent}, ObjectMeta: metav1.ObjectMeta{Name: "a"}}
	ipp2 := &apia.IPPool{TypeMeta: metav1.TypeMeta{Kind: apia.KindIPPool, APIVersion: apia.GroupVersionCurrent}, ObjectMeta: metav1.ObjectMeta{Name: "b"}}
	in := []runtime.Object{ipp1, ipp2}

	out := Objects(in)

	if len(out) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(out))
	}
	if !reflect.DeepEqual(out[0], ipp1) || !reflect.DeepEqual(out[1], ipp2) {
		t.Fatalf("unexpected output slice: %#v", out)
	}
}

func TestObjects_Preserves_GNPList(t *testing.T) {
	gnp1 := *newGNP("a")
	gnp2 := *newGNP("b")
	lst := &apia.GlobalNetworkPolicyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       apia.KindGlobalNetworkPolicyList,
			APIVersion: apia.GroupVersionCurrent,
		},
		Items: []apia.GlobalNetworkPolicy{gnp1, gnp2},
	}
	in := []runtime.Object{lst}

	out := Objects(in)

	if len(out) != 1 {
		t.Fatalf("expected 1 output list, got %d", len(out))
	}
	ol, ok := out[0].(*apia.GlobalNetworkPolicyList)
	if !ok {
		t.Fatalf("expected GlobalNetworkPolicyList, got %#v", out[0])
	}
	if len(ol.Items) != 2 {
		t.Fatalf("expected 2 items in list, got %d", len(ol.Items))
	}
	if ol.Items[0].Name != "a" || ol.Items[1].Name != "b" {
		t.Fatalf("unexpected list items: %#v", ol.Items)
	}
}

func TestObjects_PassThrough_UnhandledType(t *testing.T) {
	ippool := &apia.IPPool{
		TypeMeta: metav1.TypeMeta{
			Kind:       apia.KindIPPool,
			APIVersion: apia.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{Name: "ippool"},
	}
	out := Objects([]runtime.Object{ippool})
	if len(out) != 1 {
		t.Fatalf("expected 1 output, got %d", len(out))
	}
	if !reflect.DeepEqual(out[0], ippool) {
		t.Fatalf("unexpected output: %#v", out[0])
	}
}

func TestObjects_EmptyInput(t *testing.T) {
	out := Objects(nil)
	if len(out) != 0 {
		t.Fatalf("expected empty output for nil input, got %d", len(out))
	}

	out = Objects([]runtime.Object{})
	if len(out) != 0 {
		t.Fatalf("expected empty output for empty slice input, got %d", len(out))
	}
}

func TestOptimizeGNP_CanonicalisesSelectors(t *testing.T) {
	gnp := &apia.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apia.KindGlobalNetworkPolicy, APIVersion: apia.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp"},
		Spec: apia.GlobalNetworkPolicySpec{
			Selector:               "  ", // may canonicalize to all()
			NamespaceSelector:      "  all( ) ",
			ServiceAccountSelector: "sa == \"x\"\n\t",
			Ingress: []apia.Rule{{
				Source:      apia.EntityRule{Selector: "foo==\"bar\"", NamespaceSelector: "ns in{\"a\",\"b\"}"},
				Destination: apia.EntityRule{NotSelector: "has(label)\t"},
			}},
			Egress: []apia.Rule{{
				Source:      apia.EntityRule{NotSelector: " not has(x) ", ServiceAccounts: &apia.ServiceAccountMatch{Selector: " has(sa) "}},
				Destination: apia.EntityRule{Selector: "(all())"},
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
	og, ok := out[0].(*apia.GlobalNetworkPolicy)
	if !ok {
		t.Fatalf("unexpected type: %#v", out[0])
	}
	if og.Spec.Selector != expectTopSel {
		t.Errorf("top-level selector not canonicalized: got %q want %q", og.Spec.Selector, expectTopSel)
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
	// Top-level selectors
	topSel := "app == 'api'"
	topNS := "has(kubernetes.io/metadata.name)"
	gnp := &apia.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apia.KindGlobalNetworkPolicy, APIVersion: apia.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp"},
		Spec: apia.GlobalNetworkPolicySpec{
			Selector:          topSel,
			NamespaceSelector: topNS,
			Egress: []apia.Rule{
				{Source: apia.EntityRule{Selector: topSel, NamespaceSelector: topNS}},           // redundant -> cleared
				{Source: apia.EntityRule{Selector: "app == 'other'", NamespaceSelector: topNS}}, // not redundant, will be split
			},
			Ingress: []apia.Rule{
				{Destination: apia.EntityRule{Selector: topSel, NamespaceSelector: topNS}},       // redundant -> cleared
				{Destination: apia.EntityRule{Selector: topSel, NamespaceSelector: "ns == 'x'"}}, // not redundant, will be split
			},
		},
	}

	out := Objects([]runtime.Object{gnp})

	// Expect multiple split policies: some for ingress, some for egress.
	var ingressPolicies, egressPolicies []*apia.GlobalNetworkPolicy
	for _, obj := range out {
		pol := obj.(*apia.GlobalNetworkPolicy)
		if len(pol.Spec.Types) == 1 && pol.Spec.Types[0] == apia.PolicyTypeIngress {
			ingressPolicies = append(ingressPolicies, pol)
		}
		if len(pol.Spec.Types) == 1 && pol.Spec.Types[0] == apia.PolicyTypeEgress {
			egressPolicies = append(egressPolicies, pol)
		}
	}
	if len(ingressPolicies) == 0 || len(egressPolicies) == 0 {
		t.Fatalf("expected split policies for both ingress and egress, got %d ingress, %d egress", len(ingressPolicies), len(egressPolicies))
	}

	// Validate egress: one policy should have top-level selector unchanged (redundant cleared group),
	// another should include the specific source selector (app == 'other'). In both, rule-level selectors must be cleared.
	var foundEgressRedundant, foundEgressOther bool
	for _, pol := range egressPolicies {
		if pol.Spec.Selector == topSel && pol.Spec.NamespaceSelector == topNS {
			// Redundant group: rules should be present with cleared selectors.
			if len(pol.Spec.Egress) != 1 || pol.Spec.Egress[0].Source.Selector != "" || pol.Spec.Egress[0].Source.NamespaceSelector != "" {
				t.Fatalf("egress redundant group not cleared correctly: %#v", pol.Spec.Egress)
			}
			foundEgressRedundant = true
		}
		if strings.Contains(pol.Spec.Selector, "app == 'other'") {
			if len(pol.Spec.Egress) != 1 || pol.Spec.Egress[0].Source.Selector != "" || pol.Spec.Egress[0].Source.NamespaceSelector != "" {
				t.Fatalf("egress other group not cleared correctly: %#v", pol.Spec.Egress)
			}
			if pol.Spec.NamespaceSelector != topNS {
				t.Fatalf("egress other group should carry top-level namespace selector, got %q", pol.Spec.NamespaceSelector)
			}
			foundEgressOther = true
		}
	}
	if !foundEgressRedundant || !foundEgressOther {
		t.Fatalf("did not find expected egress groups: redundant=%v other=%v", foundEgressRedundant, foundEgressOther)
	}

	// Validate ingress similarly: one policy should have top-level unchanged (redundant cleared),
	// another should include the specific destination namespace selector change (ns == 'x') plus topSel.
	var foundIngressRedundant, foundIngressNSX bool
	for _, pol := range ingressPolicies {
		if pol.Spec.Selector == topSel && pol.Spec.NamespaceSelector == topNS {
			if len(pol.Spec.Ingress) != 1 || pol.Spec.Ingress[0].Destination.Selector != "" || pol.Spec.Ingress[0].Destination.NamespaceSelector != "" {
				t.Fatalf("ingress redundant group not cleared correctly: %#v", pol.Spec.Ingress)
			}
			foundIngressRedundant = true
		}
		if strings.Contains(pol.Spec.Selector, topSel) && strings.Contains(pol.Spec.NamespaceSelector, "ns == 'x'") {
			if len(pol.Spec.Ingress) != 1 || pol.Spec.Ingress[0].Destination.Selector != "" || pol.Spec.Ingress[0].Destination.NamespaceSelector != "" {
				t.Fatalf("ingress ns=='x' group not cleared correctly: %#v", pol.Spec.Ingress)
			}
			foundIngressNSX = true
		}
	}
	if !foundIngressRedundant || !foundIngressNSX {
		t.Fatalf("did not find expected ingress groups: redundant=%v nsX=%v", foundIngressRedundant, foundIngressNSX)
	}
}

func TestOptimizeGNP_PreservesEmptyRuleSelectors(t *testing.T) {
	gnp := &apia.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apia.KindGlobalNetworkPolicy, APIVersion: apia.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp-empty-selectors"},
		Spec: apia.GlobalNetworkPolicySpec{
			Selector: selector.All.String(),
			Egress: []apia.Rule{{
				Source:      apia.EntityRule{Selector: "   ", NamespaceSelector: "\n\t"},
				Destination: apia.EntityRule{NotSelector: "   "},
			}},
			Ingress: []apia.Rule{{
				Destination: apia.EntityRule{Selector: "   ", NamespaceSelector: "   ", ServiceAccounts: &apia.ServiceAccountMatch{Selector: "   "}},
			}},
		},
	}

	out := Objects([]runtime.Object{gnp})
	og := out[0].(*apia.GlobalNetworkPolicy)
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
	gnp := &apia.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apia.KindGlobalNetworkPolicy, APIVersion: apia.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp-sort-ingress"},
		Spec: apia.GlobalNetworkPolicySpec{
			Ingress: []apia.Rule{
				{Action: apia.Allow, Destination: apia.EntityRule{Selector: "z"}},
				{Action: apia.Allow, Destination: apia.EntityRule{Selector: "a"}},
				{Action: apia.Deny, Destination: apia.EntityRule{Selector: "c"}},
				{Action: apia.Deny, Destination: apia.EntityRule{Selector: "b"}},
				{Action: apia.Allow, Destination: apia.EntityRule{Selector: "n"}},
				{Action: apia.Allow, Destination: apia.EntityRule{Selector: "m"}},
			},
		},
	}

	out := Objects([]runtime.Object{gnp})
	og := out[0].(*apia.GlobalNetworkPolicy)
	// Expect the first Allow run sorted by Destination.Selector: a, z
	if og.Spec.Ingress[0].Action != apia.Allow || og.Spec.Ingress[0].Destination.Selector != "a" {
		t.Fatalf("unexpected ingress[0]: action=%s sel=%s", og.Spec.Ingress[0].Action, og.Spec.Ingress[0].Destination.Selector)
	}
	if og.Spec.Ingress[1].Action != apia.Allow || og.Spec.Ingress[1].Destination.Selector != "z" {
		t.Fatalf("unexpected ingress[1]: action=%s sel=%s", og.Spec.Ingress[1].Action, og.Spec.Ingress[1].Destination.Selector)
	}
	// Deny run should remain in the middle and be sorted: b, c
	if og.Spec.Ingress[2].Action != apia.Deny || og.Spec.Ingress[2].Destination.Selector != "b" {
		t.Fatalf("unexpected ingress[2]: action=%s sel=%s", og.Spec.Ingress[2].Action, og.Spec.Ingress[2].Destination.Selector)
	}
	if og.Spec.Ingress[3].Action != apia.Deny || og.Spec.Ingress[3].Destination.Selector != "c" {
		t.Fatalf("unexpected ingress[3]: action=%s sel=%s", og.Spec.Ingress[3].Action, og.Spec.Ingress[3].Destination.Selector)
	}
	// Second Allow run should remain last and be sorted: m, n (not merged with first Allow run)
	if og.Spec.Ingress[4].Action != apia.Allow || og.Spec.Ingress[4].Destination.Selector != "m" {
		t.Fatalf("unexpected ingress[4]: action=%s sel=%s", og.Spec.Ingress[4].Action, og.Spec.Ingress[4].Destination.Selector)
	}
	if og.Spec.Ingress[5].Action != apia.Allow || og.Spec.Ingress[5].Destination.Selector != "n" {
		t.Fatalf("unexpected ingress[5]: action=%s sel=%s", og.Spec.Ingress[5].Action, og.Spec.Ingress[5].Destination.Selector)
	}
}

func TestOptimizeGNP_SortsEgressBySourceSelectorWithinAction(t *testing.T) {
	gnp := &apia.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apia.KindGlobalNetworkPolicy, APIVersion: apia.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp-sort-egress"},
		Spec: apia.GlobalNetworkPolicySpec{
			Egress: []apia.Rule{
				{Action: apia.Deny, Source: apia.EntityRule{Selector: "delta"}},
				{Action: apia.Deny, Source: apia.EntityRule{Selector: "alpha"}},
				{Action: apia.Allow, Source: apia.EntityRule{Selector: "zeta"}},
				{Action: apia.Allow, Source: apia.EntityRule{Selector: "beta"}},
				{Action: apia.Deny, Source: apia.EntityRule{Selector: "gamma"}},
			},
		},
	}

	out := Objects([]runtime.Object{gnp})
	og := out[0].(*apia.GlobalNetworkPolicy)
	// First Deny run sorted: alpha, delta
	if og.Spec.Egress[0].Action != apia.Deny || og.Spec.Egress[0].Source.Selector != "alpha" {
		t.Fatalf("unexpected egress[0]: action=%s sel=%s", og.Spec.Egress[0].Action, og.Spec.Egress[0].Source.Selector)
	}
	if og.Spec.Egress[1].Action != apia.Deny || og.Spec.Egress[1].Source.Selector != "delta" {
		t.Fatalf("unexpected egress[1]: action=%s sel=%s", og.Spec.Egress[1].Action, og.Spec.Egress[1].Source.Selector)
	}
	// Allow run sorted: beta, zeta
	if og.Spec.Egress[2].Action != apia.Allow || og.Spec.Egress[2].Source.Selector != "beta" {
		t.Fatalf("unexpected egress[2]: action=%s sel=%s", og.Spec.Egress[2].Action, og.Spec.Egress[2].Source.Selector)
	}
	if og.Spec.Egress[3].Action != apia.Allow || og.Spec.Egress[3].Source.Selector != "zeta" {
		t.Fatalf("unexpected egress[3]: action=%s sel=%s", og.Spec.Egress[3].Action, og.Spec.Egress[3].Source.Selector)
	}
	// Final Deny run remains last (not merged with first Deny) and single-item sorted trivially
	if og.Spec.Egress[4].Action != apia.Deny || og.Spec.Egress[4].Source.Selector != "gamma" {
		t.Fatalf("unexpected egress[4]: action=%s sel=%s", og.Spec.Egress[4].Action, og.Spec.Egress[4].Source.Selector)
	}
}
