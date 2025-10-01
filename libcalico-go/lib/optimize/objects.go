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

// Package optimize provides functions to optimize Calico API resources.
package optimize

import (
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"

	apia "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// Objects takes a slice of runtime.Object and returns a new slice containing
// the optimized objects. List objects are preserved (not flattened) and contain
// the optimized versions of their items. Non-list objects may expand into
// multiple objects.
func Objects(in []runtime.Object) []runtime.Object {
	out := make([]runtime.Object, 0, len(in))
	for _, obj := range in {
		out = append(out, optimizeOne(obj)...)
	}
	return out
}

func optimizeOne(obj runtime.Object) []runtime.Object {
	// If this is a List type, optimize each item and return a List object of the
	// same type containing the optimized items. Items are assumed to be non-list
	// resources; each may expand into multiple objects which are all included.
	if items, err := meta.ExtractList(obj); err == nil {
		optimizedItems := make([]runtime.Object, 0, len(items))
		for _, it := range items {
			optimizedItems = append(optimizedItems, optimizeNonList(it)...)
		}

		// Create a copy of the input list object and set the Items field.
		listCopy := obj.DeepCopyObject()
		if err := meta.SetList(listCopy, optimizedItems); err == nil {
			return []runtime.Object{listCopy}
		}
		// If we couldn't set the list (unexpected), return the original object as-is.
		return []runtime.Object{obj}
	}

	return optimizeNonList(obj)
}

// optimizeNonList optimizes a single non-list object and may return multiple objects.
func optimizeNonList(obj runtime.Object) []runtime.Object {
	switch t := obj.(type) {
	case *apia.GlobalNetworkPolicy:
		return optimizeGlobalNetworkPolicy(t)
	default:
		// No-op for unhandled resource types.
		return []runtime.Object{obj}
	}
}

// optimizeGlobalNetworkPolicy returns zero or more GlobalNetworkPolicy resources
// derived from the provided input. Current passes:
//   - Canonicalize selectors (top-level and within ingress/egress rules).
//   - Remove redundant rule selectors that duplicate the top-level subject/namespace
//     for egress source and ingress destination.
func optimizeGlobalNetworkPolicy(gnp *apia.GlobalNetworkPolicy) []runtime.Object {
	// Work on a deep copy to avoid mutating the original object.
	cpy := gnp.DeepCopy()
	canonicaliseGNPSelectors(cpy)
	removeRedundantRuleSelectors(cpy)
	return []runtime.Object{cpy}
}

// canonicaliseGNPSelectors normalizes all selector strings within the policy.
func canonicaliseGNPSelectors(g *apia.GlobalNetworkPolicy) {
	g.Spec.Selector = selector.Normalise(g.Spec.Selector)
	g.Spec.NamespaceSelector = selector.Normalise(g.Spec.NamespaceSelector)
	g.Spec.ServiceAccountSelector = selector.Normalise(g.Spec.ServiceAccountSelector)
	for i := range g.Spec.Ingress {
		canonicaliseRuleSelectors(&g.Spec.Ingress[i])
	}
	for i := range g.Spec.Egress {
		canonicaliseRuleSelectors(&g.Spec.Egress[i])
	}
}

func canonicaliseRuleSelectors(r *apia.Rule) {
	// Source
	r.Source.Selector = normaliseRuleSelector(r.Source.Selector)
	r.Source.NotSelector = normaliseRuleSelector(r.Source.NotSelector)
	r.Source.NamespaceSelector = normaliseRuleSelector(r.Source.NamespaceSelector)
	if r.Source.ServiceAccounts != nil {
		r.Source.ServiceAccounts.Selector = normaliseRuleSelector(r.Source.ServiceAccounts.Selector)
	}
	// Destination
	r.Destination.Selector = normaliseRuleSelector(r.Destination.Selector)
	r.Destination.NotSelector = normaliseRuleSelector(r.Destination.NotSelector)
	r.Destination.NamespaceSelector = normaliseRuleSelector(r.Destination.NamespaceSelector)
	if r.Destination.ServiceAccounts != nil {
		r.Destination.ServiceAccounts.Selector = normaliseRuleSelector(r.Destination.ServiceAccounts.Selector)
	}
}

// normaliseRuleSelector preserves the special meaning of an empty selector at rule level.
// If the input is empty or whitespace-only, returns the empty string. Otherwise, returns
// the canonical normalised selector string.
func normaliseRuleSelector(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return selector.Normalise(s)
}

// removeRedundantRuleSelectors removes per-rule Source/Destination selectors that are
// redundant with the top-level subject selectors:
//   - For egress rules: if rule.Source.Selector and NamespaceSelector equal the top-level
//     Selector and NamespaceSelector then clear them.
//   - For ingress rules: if rule.Destination.Selector and NamespaceSelector equal the top-level
//     Selector and NamespaceSelector then clear them.
//
// Assumes canonicaliseGNPSelectors has already been applied.
func removeRedundantRuleSelectors(g *apia.GlobalNetworkPolicy) {
	topSel := selector.Normalise(g.Spec.Selector)
	topNS := selector.Normalise(g.Spec.NamespaceSelector)
	for i := range g.Spec.Egress {
		r := &g.Spec.Egress[i]
		if r.Source.Selector == topSel && r.Source.NamespaceSelector == topNS {
			// Remove redundant matches; keep other Source fields as-is.
			r.Source.Selector = ""
			r.Source.NamespaceSelector = ""
		}
	}
	for i := range g.Spec.Ingress {
		r := &g.Spec.Ingress[i]
		if r.Destination.Selector == topSel && r.Destination.NamespaceSelector == topNS {
			// Remove redundant matches; keep other Destination fields as-is.
			r.Destination.Selector = ""
			r.Destination.NamespaceSelector = ""
		}
	}
}
