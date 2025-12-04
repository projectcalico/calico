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
	"reflect"
	"slices"
	"strconv"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// GlobalNetworkPolicy returns zero or more GlobalNetworkPolicy resources
// derived from the provided input.
//
// After some normalisation passes, it looks for source selectors in egress
// rules and dest selectors in ingress rules.  Since those would match on the
// workload to which the policy is applied, it's much more efficient to
// represent that match at the top level; so it splits the policy on groups of
// such selectors and hoists such selectors to the top-level. As a final pass,
// it removes some values that are set to their default values.
func GlobalNetworkPolicy(gnp *apiv3.GlobalNetworkPolicy) []*apiv3.GlobalNetworkPolicy {
	// Work on a deep copy to avoid mutating the original object.
	logrus.Infof("Optimizing policy %s", gnp.Name)
	logFullYAML(gnp, "Input policy:")
	cpy := gnp.DeepCopy()

	// Normalise selectors so that we have a better chance of spotting equal
	// selectors in later phases.
	canonicaliseGNPSelectors(cpy)

	// Remove redundant selectors from rules that already match the top-level
	// subject selector in the policy.  This avoids generating unneeded splits
	removeRedundantRuleSelectors(cpy)

	// Split policies on inefficient ingress-dest and egress-source selectors
	// and hoist those into the top-level selectors of the generated policies.
	pols := splitPolicyOnSelectors(cpy)

	// Remove explicit defaults again, just to slim down the policies.
	removeExplicitDefaults(pols)

	// Remove repeated and unreachable rules.
	pols = removeRedundantRules(pols)

	return pols
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
			logrus.Infof("Egress rule has redundant source selector: namespaceSelector=%q selector=%q", r.Source.NamespaceSelector, r.Source.Selector)
			r.Source.Selector = ""
			r.Source.NamespaceSelector = ""
		}
	}
	for i := range gnp.Spec.Ingress {
		r := &gnp.Spec.Ingress[i]
		if compareTopLevelVsRuleSelectors(topSel, topNS, r.Destination.Selector, r.Destination.NamespaceSelector) {
			// Remove redundant matches; keep other Destination fields as-is.
			logrus.Infof("Ingress rule has redundant destination selector: namespaceSelector=%q selector=%q", r.Destination.NamespaceSelector, r.Destination.Selector)
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

// splitPolicyOnSelectors scans the ingress rules for destination selectors
// and the egress rules for source selectors.  If found, it breaks the policy
// up into chunks based on those selectors and moves the selector into the
// top-level subject selector.  If there are no such selectors, it returns the
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
	logrus.Info("Policy has destination selectors in ingress rules and/or source selectors in egress rules.  Splitting the policy...")

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

	// Sort on selector (but avoid reordering rules that have different actions).
	// This results in fewer split policies.
	gnp = gnp.DeepCopy()
	gnp.ObjectMeta.CreationTimestamp = metav1.Time{}
	gnp.ObjectMeta.UID = ""
	gnp.ObjectMeta.ResourceVersion = ""
	groupGNPByRuleSelector(gnp)

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
	logrus.Infof("Grouped rules on the redundant selectors in %s direction, found %v groups", direction, len(subsets))

	if len(subsets) == 0 {
		panic("rulesGroupedOnSelector returned 0 groups for policy " + pol.Name + " in direction " + direction)
	}
	if len(subsets) == 1 {
		logrus.Infof("Only found one group in %s direction, short-circuiting.", direction)
		pol.Name += "-" + direction
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
		logrus.Infof("Creating new policy %s from rules with selectors namespace=%q, selector=%q", cpy.Name, firstEntRule.NamespaceSelector, firstEntRule.Selector)

		// Rewrite the top-level selector to include the rule selector.
		cpy.Spec.Selector = andSelectors(cpy.Spec.Selector, firstEntRule.Selector)
		logrus.Infof("  Calculating top-level subject selector from parent top-level and rule selector: ((%s) && (%s)) => %s", pol.Spec.Selector, firstEntRule.Selector, cpy.Spec.Selector)
		cpy.Spec.NamespaceSelector = andSelectors(cpy.Spec.NamespaceSelector, firstEntRule.NamespaceSelector)
		logrus.Infof("  Calculating top-level subject namespace selector from parent top-level and rule selector: ((%s) && (%s)) => %s", pol.Spec.NamespaceSelector, firstEntRule.NamespaceSelector, cpy.Spec.NamespaceSelector)

		// Since we've moved the selector to the top-level subject selector,
		// we can zero it out in the rule itself.
		for i := range rulesSubset {
			er := getEntityRule(&rulesSubset[i])
			er.Selector = ""
			er.NamespaceSelector = ""
		}
		setRules(cpy, rulesSubset)

		logFullYAML(cpy, "New per-selector policy:")

		out = append(out, cpy)
	}
	return out
}

func andSelectors(s string, s2 string) string {
	if s == "" || s == "all()" || s == s2 {
		return s2
	}
	if s2 == "" || s2 == "all()" {
		return s
	}
	return selector.Normalise("(" + s + ") && (" + s2 + ")")
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

// groupGNPByRuleSelector sorts ingress rules by Destination.Selector and egress rules by Source.Selector,
// but only within groups of the same Action. Relative order of different Action groups is preserved.
func groupGNPByRuleSelector(g *apiv3.GlobalNetworkPolicy) {
	g.Spec.Ingress = groupRulesBySelectorAndAction(g.Spec.Ingress, func(r apiv3.Rule) string {
		return "namespaceSelector: " + r.Destination.NamespaceSelector + ", selector: " + r.Destination.Selector
	})
	g.Spec.Egress = groupRulesBySelectorAndAction(g.Spec.Egress, func(r apiv3.Rule) string {
		return "namespaceSelector: " + r.Source.NamespaceSelector + ", selector: " + r.Source.Selector
	})
}

// groupRulesBySelectorAndAction sorts only contiguous runs of the same Action by the provided
// selector function, preserving the relative order of runs with different Actions.
func groupRulesBySelectorAndAction(rules []apiv3.Rule, selectorFn func(apiv3.Rule) string) []apiv3.Rule {
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

		var groupsNames []string
		groups := map[string][]apiv3.Rule{}
		indexes := map[string][]int{}

		for k, rule := range segment {
			groupName := selectorFn(rule)
			if groups[groupName] == nil {
				groupsNames = append(groupsNames, groupName)
			}
			groups[groupName] = append(groups[groupName], rule)
			indexes[groupName] = append(indexes[groupName], i+k)
		}

		k := 0
		for _, groupName := range groupsNames {
			logrus.Infof("  Forming group from rules with same selectors and action: %v", summariseIndexNumbers(indexes[groupName]))
			for _, rule := range groups[groupName] {
				segment[k] = rule
				k++
			}
			logFullYAML(segment[k-len(groups[groupName]):k], "Group:")
		}

		i = j
	}
	return out
}

func removeRedundantRules(pols []*apiv3.GlobalNetworkPolicy) (out []*apiv3.GlobalNetworkPolicy) {
	for _, pol := range pols {
		logrus.Infof("Looking for duplicate/unreachable rules in policy %s", pol.Name)
		pol.Spec.Ingress = removeRedundantRulesInner(pol.Spec.Ingress)
		pol.Spec.Egress = removeRedundantRulesInner(pol.Spec.Egress)
		if len(pol.Spec.Ingress) == 0 && len(pol.Spec.Egress) == 0 {
			continue
		}
		out = append(out, pol)
		logFullYAML(pol, "Policy after trimming duplicate/unreachable rules:")
	}
	return
}

func removeRedundantRulesInner(rules []apiv3.Rule) (out []apiv3.Rule) {
	// Rules aren't comparable, so the best way to find dupes is to serialise
	// to JSON.
	seenRules := set.New[string]()
	for _, rule := range rules {
		ruleForComparison := rule
		ruleForComparison.Metadata = nil

		j, err := json.Marshal(ruleForComparison)
		if err != nil {
			panic(err)
		}
		js := string(j)
		if seenRules.Contains(js) {
			logrus.Infof("  Policy contains duplicate rule, skipping: %s", js)
			continue
		}
		out = append(out, rule)

		if reflect.DeepEqual(ruleForComparison, apiv3.Rule{Action: apiv3.Deny}) ||
			reflect.DeepEqual(ruleForComparison, apiv3.Rule{Action: apiv3.Allow}) ||
			reflect.DeepEqual(ruleForComparison, apiv3.Rule{Action: apiv3.Pass}) {
			logrus.Info("  Reached a terminal allow/deny/pass all rule; skipping remaining rules.")
			break
		}

		seenRules.Add(js)
	}
	return
}

func removeExplicitDefaults(pols []*apiv3.GlobalNetworkPolicy) {
	for _, pol := range pols {
		if pol.Spec.Selector == "all()" {
			// Remove explicit defaults.
			pol.Spec.Selector = ""
		}
	}
}

func logFullYAML(val any, msg string) {
	polYAML, err := yaml.Marshal(val)
	if err != nil {
		panic(err)
	}
	logrus.Info("  " + msg)
	logrus.Info("")
	for _, line := range strings.Split(string(polYAML), "\n") {
		line = strings.TrimRight(line, "\n")
		logrus.Info("    " + line)
	}
}

func summariseIndexNumbers(indexes []int) string {
	slices.Sort(indexes)
	first := indexes[0]
	if len(indexes) == 1 {
		return fmt.Sprint(first)
	}
	last := indexes[len(indexes)-1]
	if last-first == len(indexes)-1 {
		return fmt.Sprint(first) + "-" + fmt.Sprint(last)
	}
	return fmt.Sprintf("rules %v", indexes)
}
