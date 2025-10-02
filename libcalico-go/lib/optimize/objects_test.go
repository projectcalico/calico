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
	"reflect"
	"strings"
	"testing"

	apia "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/selector"
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
	topSelNorm := selector.Normalise(topSel)
	topNSNorm := selector.Normalise(topNS)
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

	// Expect exactly 2 split policies for ingress and 2 for egress.
	var ingressPolicies, egressPolicies []*apia.GlobalNetworkPolicy
	for _, obj := range out {
		pol := obj.(*apia.GlobalNetworkPolicy)
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

	// Call the sorting pass directly to avoid interaction with splitting logic.
	sortGNPByRuleSelector(gnp)
	if gnp.Spec.Ingress[0].Action != apia.Allow || gnp.Spec.Ingress[0].Destination.Selector != "a" {
		t.Fatalf("unexpected ingress[0]: action=%s sel=%s", gnp.Spec.Ingress[0].Action, gnp.Spec.Ingress[0].Destination.Selector)
	}
	if gnp.Spec.Ingress[1].Action != apia.Allow || gnp.Spec.Ingress[1].Destination.Selector != "z" {
		t.Fatalf("unexpected ingress[1]: action=%s sel=%s", gnp.Spec.Ingress[1].Action, gnp.Spec.Ingress[1].Destination.Selector)
	}
	if gnp.Spec.Ingress[2].Action != apia.Deny || gnp.Spec.Ingress[2].Destination.Selector != "b" {
		t.Fatalf("unexpected ingress[2]: action=%s sel=%s", gnp.Spec.Ingress[2].Action, gnp.Spec.Ingress[2].Destination.Selector)
	}
	if gnp.Spec.Ingress[3].Action != apia.Deny || gnp.Spec.Ingress[3].Destination.Selector != "c" {
		t.Fatalf("unexpected ingress[3]: action=%s sel=%s", gnp.Spec.Ingress[3].Action, gnp.Spec.Ingress[3].Destination.Selector)
	}
	if gnp.Spec.Ingress[4].Action != apia.Allow || gnp.Spec.Ingress[4].Destination.Selector != "m" {
		t.Fatalf("unexpected ingress[4]: action=%s sel=%s", gnp.Spec.Ingress[4].Action, gnp.Spec.Ingress[4].Destination.Selector)
	}
	if gnp.Spec.Ingress[5].Action != apia.Allow || gnp.Spec.Ingress[5].Destination.Selector != "n" {
		t.Fatalf("unexpected ingress[5]: action=%s sel=%s", gnp.Spec.Ingress[5].Action, gnp.Spec.Ingress[5].Destination.Selector)
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

	// Call the sorting pass directly.
	sortGNPByRuleSelector(gnp)
	if gnp.Spec.Egress[0].Action != apia.Deny || gnp.Spec.Egress[0].Source.Selector != "alpha" {
		t.Fatalf("unexpected egress[0]: action=%s sel=%s", gnp.Spec.Egress[0].Action, gnp.Spec.Egress[0].Source.Selector)
	}
	if gnp.Spec.Egress[1].Action != apia.Deny || gnp.Spec.Egress[1].Source.Selector != "delta" {
		t.Fatalf("unexpected egress[1]: action=%s sel=%s", gnp.Spec.Egress[1].Action, gnp.Spec.Egress[1].Source.Selector)
	}
	if gnp.Spec.Egress[2].Action != apia.Allow || gnp.Spec.Egress[2].Source.Selector != "beta" {
		t.Fatalf("unexpected egress[2]: action=%s sel=%s", gnp.Spec.Egress[2].Action, gnp.Spec.Egress[2].Source.Selector)
	}
	if gnp.Spec.Egress[3].Action != apia.Allow || gnp.Spec.Egress[3].Source.Selector != "zeta" {
		t.Fatalf("unexpected egress[3]: action=%s sel=%s", gnp.Spec.Egress[3].Action, gnp.Spec.Egress[3].Source.Selector)
	}
	if gnp.Spec.Egress[4].Action != apia.Deny || gnp.Spec.Egress[4].Source.Selector != "gamma" {
		t.Fatalf("unexpected egress[4]: action=%s sel=%s", gnp.Spec.Egress[4].Action, gnp.Spec.Egress[4].Source.Selector)
	}
}

func TestOptimizeGNP_PreservesEmptyTopLevelServiceAccountSelector(t *testing.T) {
	gnp := &apia.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: apia.KindGlobalNetworkPolicy, APIVersion: apia.GroupVersionCurrent},
		ObjectMeta: metav1.ObjectMeta{Name: "gnp-empty-top-sa"},
		Spec: apia.GlobalNetworkPolicySpec{
			Selector:               "all()",
			ServiceAccountSelector: "   ", // should remain empty, not all()
		},
	}

	out := Objects([]runtime.Object{gnp})
	if len(out) != 1 {
		t.Fatalf("expected 1 optimized object, got %d", len(out))
	}
	og := out[0].(*apia.GlobalNetworkPolicy)
	if og.Spec.ServiceAccountSelector != "" {
		t.Fatalf("top-level ServiceAccountSelector should remain empty, got %q", og.Spec.ServiceAccountSelector)
	}
}
