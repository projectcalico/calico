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
	"iter"
	"slices"
	"sort"
	"strconv"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
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
func optimizeGlobalNetworkPolicy(gnp *apiv3.GlobalNetworkPolicy) []runtime.Object {
	// Work on a deep copy to avoid mutating the original object.
	cpy := gnp.DeepCopy()
	canonicaliseGNPSelectors(cpy)
	removeRedundantRuleSelectors(cpy)
	pols := splitPolicyOnSelectors(cpy)

	var out []runtime.Object
	for _, pol := range pols {
		if pol.Spec.Selector == "all()" {
			// Remove explicit defaults.
			pol.Spec.Selector = ""
		}
		out = append(out, pol)
	}

	return out
}

// canonicaliseGNPSelectors normalizes all selector strings within the policy.
func canonicaliseGNPSelectors(g *apiv3.GlobalNetworkPolicy) {
	// The top-level subject selector defaults to "all()" so Normalise does the
	// right thing.
	g.Spec.Selector = selector.Normalise(g.Spec.Selector)
	// For the namespace selector, "" and "all()" mean different things so we must
	// preserve empties.
	g.Spec.NamespaceSelector = normaliseSelectorPreserveEmpty(g.Spec.NamespaceSelector)
	// Preserve empty semantics for top-level ServiceAccountSelector like rule-level selectors.
	g.Spec.ServiceAccountSelector = normaliseSelectorPreserveEmpty(g.Spec.ServiceAccountSelector)
	for i := range g.Spec.Ingress {
		canonicaliseRuleSelectors(&g.Spec.Ingress[i])
	}
	for i := range g.Spec.Egress {
		canonicaliseRuleSelectors(&g.Spec.Egress[i])
	}
}

func canonicaliseRuleSelectors(r *apiv3.Rule) {
	// Source
	r.Source.Selector = normaliseSelectorPreserveEmpty(r.Source.Selector)
	r.Source.NotSelector = normaliseSelectorPreserveEmpty(r.Source.NotSelector)
	r.Source.NamespaceSelector = normaliseSelectorPreserveEmpty(r.Source.NamespaceSelector)
	if r.Source.ServiceAccounts != nil {
		r.Source.ServiceAccounts.Selector = normaliseSelectorPreserveEmpty(r.Source.ServiceAccounts.Selector)
	}
	// Destination
	r.Destination.Selector = normaliseSelectorPreserveEmpty(r.Destination.Selector)
	r.Destination.NotSelector = normaliseSelectorPreserveEmpty(r.Destination.NotSelector)
	r.Destination.NamespaceSelector = normaliseSelectorPreserveEmpty(r.Destination.NamespaceSelector)
	if r.Destination.ServiceAccounts != nil {
		r.Destination.ServiceAccounts.Selector = normaliseSelectorPreserveEmpty(r.Destination.ServiceAccounts.Selector)
	}
}

// normaliseSelectorPreserveEmpty preserves the special meaning of an empty selector.
// If the input is empty or whitespace-only, returns the empty string. Otherwise, returns
// the canonical normalised selector string.
func normaliseSelectorPreserveEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return selector.Normalise(s)
}

// splitPolicyOnSelectors scans the ingress rules for destination selectors
// and the egress rules for source selectors.  If found, it breaks the policy
// up into chunks based on those selectors and moves the selector into the
// top-level subject selector.  If therea are no such selectors, it returns the
// policy unmodified.
func splitPolicyOnSelectors(gnp *apiv3.GlobalNetworkPolicy) (out []*apiv3.GlobalNetworkPolicy) {
	if gnp.Spec.ApplyOnForward || gnp.Spec.PreDNAT || gnp.Spec.DoNotTrack {
		// These policies apply to traffic flowing through an endpoint as well
		// as the endpoint itself.  We expect them to have source and dest
		// selectors on their rules, and it's not safe to split them up.
		logrus.Infof("Skipping split of pre-DNAT / apply-on-forward / no-track policy: %q", gnp.Name)
		return []*apiv3.GlobalNetworkPolicy{gnp}
	}

	// Check if there are any of the offending selectors.
	found := false
	for _, rule := range gnp.Spec.Ingress {
		if rule.Destination.Selector != "" || rule.Destination.NamespaceSelector != "" {
			found = true
			break
		}
	}
	for _, rule := range gnp.Spec.Egress {
		if rule.Source.Selector != "" || rule.Source.NamespaceSelector != "" {
			found = true
			break
		}
	}

	if !found {
		// No selectors to split on, return policy unmodified.
		return []*apiv3.GlobalNetworkPolicy{gnp}
	}

	defer func(gnp *apiv3.GlobalNetworkPolicy) {
		if r := recover(); r != nil {
			if r == errNameTooLong {
				logrus.Warn("could not split policy into more efficient parts because its name was too long, returning it unaltered: ", gnp.Name)
				out = []*apiv3.GlobalNetworkPolicy{gnp}
			} else {
				panic(r)
			}
		}
	}(gnp)

	// selector (but avoid reordering rules that have different actions).
	// Otherwise, we split up the policy.  Start by sorting the rules on
	gnp = gnp.DeepCopy()
	sortGNPByRuleSelector(gnp)

	// Split the policy into ingress and egress halves and process separately.
	var pols []*apiv3.GlobalNetworkPolicy
	if len(gnp.Spec.Ingress) > 0 && policyHasType(gnp, apiv3.PolicyTypeIngress) {
		inPol := gnp.DeepCopy()
		inPol.Spec.Egress = nil
		inPol.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeIngress}
		pols = append(pols,
			splitIngressOrEgressPolicy(
				"i",
				inPol,
				inPol.Spec.Ingress,
				func(rule *apiv3.Rule) *apiv3.EntityRule {
					return &rule.Destination
				},
				func(policy *apiv3.GlobalNetworkPolicy, rules []apiv3.Rule) {
					policy.Spec.Ingress = rules
				},
			)...)
	}
	if len(gnp.Spec.Egress) > 0 && policyHasType(gnp, apiv3.PolicyTypeEgress) {
		ePol := gnp.DeepCopy()
		ePol.Spec.Ingress = nil
		ePol.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeEgress}
		pols = append(
			pols,
			splitIngressOrEgressPolicy(
				"e",
				ePol,
				ePol.Spec.Egress,
				func(rule *apiv3.Rule) *apiv3.EntityRule {
					return &rule.Source
				},
				func(policy *apiv3.GlobalNetworkPolicy, rules []apiv3.Rule) {
					policy.Spec.Egress = rules
				},
			)...)
	}

	return pols
}

func policyHasType(gnp *apiv3.GlobalNetworkPolicy, typ apiv3.PolicyType) bool {
	if len(gnp.Spec.Types) == 0 {
		// Autodetect if there's no types field.
		switch typ {
		case apiv3.PolicyTypeIngress:
			return len(gnp.Spec.Ingress) > 0
		case apiv3.PolicyTypeEgress:
			return len(gnp.Spec.Egress) > 0
		}
	}
	return slices.Contains(gnp.Spec.Types, typ)
}

var errNameTooLong = fmt.Errorf("name too long")

func splitIngressOrEgressPolicy(
	direction string,
	pol *apiv3.GlobalNetworkPolicy,
	rules []apiv3.Rule,
	getEntityRule func(rule *apiv3.Rule) *apiv3.EntityRule,
	setRules func(*apiv3.GlobalNetworkPolicy, []apiv3.Rule),
) []*apiv3.GlobalNetworkPolicy {
	// Figure out how long our numeric suffix needs to be. We're relying on
	// lexicographic ordering of policy names to make sure that the generated
	// policies run in the right order if more than one policy applies to the
	// same endpoint.  (In general we can't be sure that the policies will
	// match disjoint endpoints.)
	subsets := slices.Collect(rulesGroupedOnSelector(rules, getEntityRule))

	if len(subsets) == 0 {
		panic("rulesGroupedOnSelector returned 0 groups for policy " + pol.Name + " in direction " + direction)
	}
	if len(subsets) == 1 {
		return []*apiv3.GlobalNetworkPolicy{pol}
	}

	suffixLen := len(strconv.Itoa(len(subsets) - 1))
	suffixFmt := fmt.Sprint("%0", suffixLen, "d")

	var out []*apiv3.GlobalNetworkPolicy
	for i, rulesSubset := range subsets {
		// We have a group of rules, make a new policy copy and name it uniquely.
		cpy := pol.DeepCopy()
		cpy.Name = cpy.Name + "-" + direction + "-" + fmt.Sprintf(suffixFmt, i)
		if len(cpy.Name) > 253 {
			panic(errNameTooLong)
		}

		// Find the selectors for this group. rulesGroupedOnSelector never
		// returns an empty slice.
		firstEntRule := getEntityRule(&rulesSubset[0])
		// Rewrite the top-level selector to include the rule selector.
		cpy.Spec.Selector = andSelectors(cpy.Spec.Selector, firstEntRule.Selector)
		cpy.Spec.NamespaceSelector = andSelectors(cpy.Spec.NamespaceSelector, firstEntRule.NamespaceSelector)

		// Since we've moved the selector to the top-level subject selector,
		// we can zero it out in the rule itself.
		for i := range rulesSubset {
			er := getEntityRule(&rulesSubset[i])
			er.Selector = ""
			er.NamespaceSelector = ""
		}
		setRules(cpy, rulesSubset)

		out = append(out, cpy)
	}
	return out
}

func andSelectors(s string, s2 string) string {
	if s == "" || s == "all()" {
		return s2
	}
	if s2 == "" || s2 == "all()" {
		return s
	}
	return selector.Normalise("((" + s + ") && (" + s2 + "))")
}

func rulesGroupedOnSelector(rules []apiv3.Rule, getEntityRule func(rule *apiv3.Rule) *apiv3.EntityRule) iter.Seq[[]apiv3.Rule] {
	return func(yield func([]apiv3.Rule) bool) {
		var group []apiv3.Rule
		for _, rule := range rules {
			if len(group) > 0 {
				firstGroupRule := getEntityRule(&group[0])
				thisRule := getEntityRule(&rule)
				if !entityRuleSelectorsEqual(firstGroupRule, thisRule) {
					// This rule is the start of a new group, emit the old
					// group.
					if !yield(group) {
						return
					}
					group = nil
				}
			}
			group = append(group, rule)
		}
		if len(group) > 0 {
			yield(group)
		}
	}
}

func entityRuleSelectorsEqual(a, b *apiv3.EntityRule) bool {
	if a.Selector != b.Selector {
		return false
	}
	if a.NamespaceSelector != b.NamespaceSelector {
		return false
	}
	return true
}

// removeRedundantRuleSelectors removes per-rule Source/Destination selectors that are
// redundant with the top-level subject selectors:
//   - For egress rules: if rule.Source.Selector and NamespaceSelector equal the top-level
//     Selector and NamespaceSelector then clear them.
//   - For ingress rules: if rule.Destination.Selector and NamespaceSelector equal the top-level
//     Selector and NamespaceSelector then clear them.
//
// Assumes canonicaliseGNPSelectors has already been applied.
func removeRedundantRuleSelectors(gnp *apiv3.GlobalNetworkPolicy) {
	if gnp.Spec.ApplyOnForward || gnp.Spec.PreDNAT || gnp.Spec.DoNotTrack {
		// These policies apply to traffic flowing through an endpoint as well
		// as the endpoint itself.  We expect them to have source and dest
		// selectors on their rules, and it's not safe to split them up.
		logrus.Infof("Skipping remove redundant on pre-DNAT / apply-on-forward / no-track policy: %q", gnp.Name)
		return
	}

	topSel := gnp.Spec.Selector
	topNS := gnp.Spec.NamespaceSelector
	for i := range gnp.Spec.Egress {
		r := &gnp.Spec.Egress[i]
		if compareTopLevelVsRuleSelectors(topSel, topNS, r.Source.Selector, r.Source.NamespaceSelector) {
			// Remove redundant matches; keep other Source fields as-is.
			r.Source.Selector = ""
			r.Source.NamespaceSelector = ""
		}
	}
	for i := range gnp.Spec.Ingress {
		r := &gnp.Spec.Ingress[i]
		if compareTopLevelVsRuleSelectors(topSel, topNS, r.Destination.Selector, r.Destination.NamespaceSelector) {
			// Remove redundant matches; keep other Destination fields as-is.
			r.Destination.Selector = ""
			r.Destination.NamespaceSelector = ""
		}
	}
}

func compareTopLevelVsRuleSelectors(topSel, topNS, ruleSel, ruleNS string) bool {
	topNS = normaliseSelectorPreserveEmpty(topNS)
	ruleNS = normaliseSelectorPreserveEmpty(ruleNS)
	if topNS != ruleNS {
		return false
	}

	topSel = selector.Normalise(topSel)
	if ruleNS != "" || ruleSel != "" {
		// Subtlety: if only the ns selector is set then the rule selector
		// effectively defaults to "all()".
		ruleSel = selector.Normalise(ruleSel)
	}
	return topSel == ruleSel
}

// sortGNPByRuleSelector sorts ingress rules by Destination.Selector and egress rules by Source.Selector,
// but only within groups of the same Action. Relative order of different Action groups is preserved.
func sortGNPByRuleSelector(g *apiv3.GlobalNetworkPolicy) {
	g.Spec.Ingress = sortRulesBySelectorAndAction(g.Spec.Ingress, func(r apiv3.Rule) string {
		return r.Destination.Selector
	})
	g.Spec.Egress = sortRulesBySelectorAndAction(g.Spec.Egress, func(r apiv3.Rule) string {
		return r.Source.Selector
	})
}

// sortRulesBySelectorAndAction sorts only contiguous runs of the same Action by the provided
// selector function, preserving the relative order of runs with different Actions.
func sortRulesBySelectorAndAction(rules []apiv3.Rule, selectorFn func(apiv3.Rule) string) []apiv3.Rule {
	if len(rules) <= 1 {
		return rules
	}
	// Work on a copy to avoid mutating the input.
	out := make([]apiv3.Rule, len(rules))
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
