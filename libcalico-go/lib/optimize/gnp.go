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
	"sort"
	"strings"

	apia "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// optimizeGlobalNetworkPolicy returns zero or more GlobalNetworkPolicy resources
// derived from the provided input. Current passes:
//   - Canonicalize selectors (top-level and within ingress/egress rules).
//   - Remove redundant rule selectors that duplicate the top-level subject/namespace
//     for egress source and ingress destination.
//   - Sort rules by selector within groups of the same action (ingress by destination selector,
//     egress by source selector).
func optimizeGlobalNetworkPolicy(gnp *apia.GlobalNetworkPolicy) []runtime.Object {
	// Work on a deep copy to avoid mutating the original object.
	cpy := gnp.DeepCopy()
	canonicaliseGNPSelectors(cpy)
	removeRedundantRuleSelectors(cpy)
	sortGNPByRuleSelector(cpy)
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

// sortGNPByRuleSelector sorts ingress rules by Destination.Selector and egress rules by Source.Selector,
// but only within groups of the same Action. Relative order of different Action groups is preserved.
func sortGNPByRuleSelector(g *apia.GlobalNetworkPolicy) {
	g.Spec.Ingress = sortRulesBySelectorAndAction(g.Spec.Ingress, func(r apia.Rule) string {
		return r.Destination.Selector
	})
	g.Spec.Egress = sortRulesBySelectorAndAction(g.Spec.Egress, func(r apia.Rule) string {
		return r.Source.Selector
	})
}

// sortRulesBySelectorAndAction sorts only contiguous runs of the same Action by the provided
// selector function, preserving the relative order of runs with different Actions.
func sortRulesBySelectorAndAction(rules []apia.Rule, selectorFn func(apia.Rule) string) []apia.Rule {
	if len(rules) <= 1 {
		return rules
	}
	// Work on a copy to avoid mutating the input.
	out := make([]apia.Rule, len(rules))
	copy(out, rules)

	// Walk the slice and identify contiguous segments with the same Action.
	for i := 0; i < len(out); {
		j := i + 1
		act := out[i].Action
		for j < len(out) && out[j].Action == act {
			j++
		}
		// Sort this contiguous segment by selector.
		segment := out[i:j]
		sort.SliceStable(segment, func(a, b int) bool {
			return selectorFn(segment[a]) < selectorFn(segment[b])
		})
		i = j
	}
	return out
}
