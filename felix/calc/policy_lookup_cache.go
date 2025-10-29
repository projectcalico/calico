// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package calc

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type pcRuleID struct {
	ruleID *RuleID
	id64   uint64
}

var gaugePolicyCacheLength = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "felix_collector_lookups_cache_policies",
	Help: "Total number of entries currently residing in the endpoints lookup cache.",
})

// PolicyLookupsCache provides an API to lookup policy to NFLOG prefix mapping.
// To do this, the PolicyLookupsCache hooks into the calculation graph
// by handling callbacks for policy and profile updates.
type PolicyLookupsCache struct {
	lock sync.RWMutex

	nflogPrefixesPolicy  map[model.PolicyKey]set.Set[string]
	nflogPrefixesProfile map[model.ProfileRulesKey]set.Set[string]
	nflogPrefixHash      map[[64]byte]pcRuleID

	useIDs bool
	ids    *idalloc.IDAllocator

	tierRefs  map[string]int
	keyToTier map[model.PolicyKey]string
}

func NewPolicyLookupsCache() *PolicyLookupsCache {
	pc := &PolicyLookupsCache{
		nflogPrefixesPolicy:  map[model.PolicyKey]set.Set[string]{},
		nflogPrefixesProfile: map[model.ProfileRulesKey]set.Set[string]{},
		nflogPrefixHash:      map[[64]byte]pcRuleID{},
		tierRefs:             map[string]int{},
		keyToTier:            map[model.PolicyKey]string{},
		ids:                  idalloc.New(),
	}
	// Add NFLog mappings for the no-profile match.
	pc.addNFLogPrefixEntry(
		rules.CalculateNoMatchProfileNFLOGPrefixStr(rules.RuleDirIngress),
		NewRuleID("", "", "", "", 0, rules.RuleDirIngress, rules.RuleActionDeny),
	)

	pc.addNFLogPrefixEntry(
		rules.CalculateNoMatchProfileNFLOGPrefixStr(rules.RuleDirEgress),
		NewRuleID("", "", "", "", 0, rules.RuleDirEgress, rules.RuleActionDeny),
	)

	return pc
}

// SetUseIDs enables generating unique uint64 IDs for each inserted prefix after
// the cache is created. This allows a user that is created later to flip the
// behavior. Once it is turned on, it cannot be turned off.
func (pc *PolicyLookupsCache) SetUseIDs() {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	pc.useIDs = true
}

func (pc *PolicyLookupsCache) OnPolicyActive(key model.PolicyKey, policy *model.Policy) {
	pc.updatePolicyRulesNFLOGPrefixes(key, policy)
}

func (pc *PolicyLookupsCache) OnPolicyInactive(key model.PolicyKey) {
	pc.removePolicyRulesNFLOGPrefixes(key)
}

func (pc *PolicyLookupsCache) OnProfileActive(key model.ProfileRulesKey, profile *model.ProfileRules) {
	pc.updateProfileRulesNFLOGPrefixes(key, profile)
}

func (pc *PolicyLookupsCache) OnProfileInactive(key model.ProfileRulesKey) {
	pc.removeProfileRulesNFLOGPrefixes(key)
}

// addNFLogPrefixEntry adds a single NFLOG prefix entry to our internal cache.
func (pc *PolicyLookupsCache) addNFLogPrefixEntry(prefix string, ruleID *RuleID) {
	var bph [64]byte
	copy(bph[:], []byte(prefix[:]))
	pc.lock.Lock()
	defer pc.lock.Unlock()

	id := pcRuleID{
		ruleID: ruleID,
	}

	if pc.useIDs {
		id.id64 = pc.ids.GetOrAlloc(prefix)
	}

	pc.nflogPrefixHash[bph] = id
}

// deleteNFLogPrefixEntry deletes a single NFLOG prefix entry to our internal cache.
func (pc *PolicyLookupsCache) deleteNFLogPrefixEntry(prefix string) {
	var bph [64]byte
	copy(bph[:], []byte(prefix[:]))
	pc.lock.Lock()
	defer pc.lock.Unlock()
	if pc.useIDs {
		id64 := pc.nflogPrefixHash[bph].id64
		if err := pc.ids.ReleaseUintID(id64); err != nil {
			log.WithError(err).WithField("id", id64).Error("failed to release ID")
		}
	}
	delete(pc.nflogPrefixHash, bph)
}

// updatePolicyRulesNFLOGPrefixes stores the required prefix to RuleID maps for a policy, deleting any
// stale entries if the number of rules or action types have changed.
func (pc *PolicyLookupsCache) updatePolicyRulesNFLOGPrefixes(key model.PolicyKey, policy *model.Policy) {
	// Track mapping of key to tier, allowing us to manage tier reference counts. If the tier for a policy
	// changes, we need to treat that as a removal from the old tier and an addition to the new tier.
	oldTier, ok := pc.keyToTier[key]
	if ok && oldTier != policy.Tier {
		pc.removePolicyRulesNFLOGPrefixes(key)
	}
	pc.keyToTier[key] = policy.Tier

	// If this is the first time we have seen this tier, add the default deny entries for the tier, and the default
	// pass (for staged-only tiers).
	count, ok := pc.tierRefs[policy.Tier]
	if !ok {
		pc.addNFLogPrefixEntry(
			rules.CalculateEndOfTierDropNFLOGPrefixStr(rules.RuleDirIngress, policy.Tier),
			NewRuleID("", policy.Tier, "", "", 0, rules.RuleDirIngress, rules.RuleActionDeny),
		)
		pc.addNFLogPrefixEntry(
			rules.CalculateEndOfTierDropNFLOGPrefixStr(rules.RuleDirEgress, policy.Tier),
			NewRuleID("", policy.Tier, "", "", 0, rules.RuleDirEgress, rules.RuleActionDeny),
		)
		pc.addNFLogPrefixEntry(
			rules.CalculateEndOfTierPassNFLOGPrefixStr(rules.RuleDirIngress, policy.Tier),
			NewRuleID("", policy.Tier, "", "", 0, rules.RuleDirIngress, rules.RuleActionPass),
		)
		pc.addNFLogPrefixEntry(
			rules.CalculateEndOfTierPassNFLOGPrefixStr(rules.RuleDirEgress, policy.Tier),
			NewRuleID("", policy.Tier, "", "", 0, rules.RuleDirEgress, rules.RuleActionPass),
		)
	}
	pc.tierRefs[policy.Tier] = count + 1

	oldPrefixes := pc.nflogPrefixesPolicy[key]
	pc.nflogPrefixesPolicy[key] = pc.updateRulesNFLOGPrefixes(
		key.Kind,
		key.Namespace,
		policy.Tier,
		key.Name,
		oldPrefixes,
		policy.InboundRules,
		policy.OutboundRules,
	)

	pc.reportPolicyCacheMetrics(1)
}

// removePolicyRulesNFLOGPrefixes removes the prefix to RuleID maps for a policy.
func (pc *PolicyLookupsCache) removePolicyRulesNFLOGPrefixes(key model.PolicyKey) {
	// Look up the tier for this policy.
	tier, ok := pc.keyToTier[key]
	if !ok {
		// We have never seen this policy. Nothing to do.
		log.Warnf("Attempted to remove unknown policy %v from PolicyLookupsCache", key)
		return
	}
	delete(pc.keyToTier, key)

	// If this is the last entry for the tier, remove the default action entries for the tier.
	// Increment the reference count so that we don't keep adding tiers.
	count := pc.tierRefs[tier]
	if count == 1 {
		delete(pc.tierRefs, tier)
		pc.deleteNFLogPrefixEntry(
			rules.CalculateEndOfTierDropNFLOGPrefixStr(rules.RuleDirIngress, tier),
		)
		pc.deleteNFLogPrefixEntry(
			rules.CalculateEndOfTierDropNFLOGPrefixStr(rules.RuleDirEgress, tier),
		)
	} else {
		pc.tierRefs[tier] = count - 1
	}

	oldPrefixes := pc.nflogPrefixesPolicy[key]
	pc.deleteRulesNFLOGPrefixes(oldPrefixes)
	delete(pc.nflogPrefixesPolicy, key)

	pc.reportPolicyCacheMetrics(1)
}

// updateProfileRulesNFLOGPrefixes stores the required prefix to RuleID maps for a profile, deleting any
// stale entries if the number of rules or action types have changed.
func (pc *PolicyLookupsCache) updateProfileRulesNFLOGPrefixes(key model.ProfileRulesKey, profile *model.ProfileRules) {
	oldPrefixes := pc.nflogPrefixesProfile[key]
	pc.nflogPrefixesProfile[key] = pc.updateRulesNFLOGPrefixes(
		v3.KindProfile,
		"",
		"",
		key.Name,
		oldPrefixes,
		profile.InboundRules,
		profile.OutboundRules,
	)
}

// removeProfileRulesNFLOGPrefixes removes the prefix to RuleID maps for a profile.
func (pc *PolicyLookupsCache) removeProfileRulesNFLOGPrefixes(key model.ProfileRulesKey) {
	oldPrefixes := pc.nflogPrefixesProfile[key]
	pc.deleteRulesNFLOGPrefixes(oldPrefixes)
	delete(pc.nflogPrefixesProfile, key)
}

// updateRulesNFLOGPrefixes updates our NFLOG prefix to RuleID map based on the supplied set of
// ingress and egress rules, and the old set of prefixes associated with the previous resource
// settings. This method adds any new rules and removes any obsolete rules.
// TODO (rlb): Maybe we should do a lazy clean up of rules?
func (pc *PolicyLookupsCache) updateRulesNFLOGPrefixes(
	kind, namespace, tier, name string, oldPrefixes set.Set[string], ingress []model.Rule, egress []model.Rule,
) set.Set[string] {
	newPrefixes := set.New[string]()

	convertAction := func(a string) rules.RuleAction {
		switch a {
		case "allow":
			return rules.RuleActionAllow
		case "deny":
			return rules.RuleActionDeny
		case "pass", "next-tier":
			return rules.RuleActionPass
		}
		return rules.RuleActionDeny
	}
	owner := rules.RuleOwnerTypePolicy
	if tier == "" {
		owner = rules.RuleOwnerTypeProfile
	}
	for ii, rule := range ingress {
		action := convertAction(rule.Action)
		prefix := rules.CalculateNFLOGPrefixStr(action, owner, rules.RuleDirIngress, ii, name)
		pc.addNFLogPrefixEntry(
			prefix,
			NewRuleID(kind, tier, name, namespace, ii, rules.RuleDirIngress, action),
		)
		newPrefixes.Add(prefix)
	}
	for ii, rule := range egress {
		action := convertAction(rule.Action)
		prefix := rules.CalculateNFLOGPrefixStr(action, owner, rules.RuleDirEgress, ii, name)
		pc.addNFLogPrefixEntry(
			prefix,
			NewRuleID(kind, tier, name, namespace, ii, rules.RuleDirEgress, action),
		)
		newPrefixes.Add(prefix)
	}

	// If this is a staged policy then we also add ingress/egress lookups for no-match. These
	// actually map to the end-of-tier defaultActions associated with that policy since that is how
	// they will be reported by the collector. The collector will only report these stats if we hit
	// the end-of-tier pass indicating that the tier contains only staged policies.
	if model.KindIsStaged(kind) {
		prefix := rules.CalculateNoMatchPolicyNFLOGPrefixStr(rules.RuleDirIngress, name)
		pc.addNFLogPrefixEntry(
			prefix,
			NewRuleID(kind, tier, name, namespace, RuleIndexTierDefaultAction, rules.RuleDirIngress, rules.RuleActionDeny),
		)
		newPrefixes.Add(prefix)

		prefix = rules.CalculateNoMatchPolicyNFLOGPrefixStr(rules.RuleDirEgress, name)
		pc.addNFLogPrefixEntry(
			prefix,
			NewRuleID(kind, tier, name, namespace, RuleIndexTierDefaultAction, rules.RuleDirEgress, rules.RuleActionDeny),
		)
		newPrefixes.Add(prefix)
	}

	// Delete the stale prefixes.
	if oldPrefixes != nil {
		oldPrefixes.Iter(func(item string) error {
			if !newPrefixes.Contains(item) {
				pc.deleteNFLogPrefixEntry(item)
			}
			return nil
		})
	}

	return newPrefixes
}

// deleteRulesNFLOGPrefixes deletes the supplied set of prefixes.
func (pc *PolicyLookupsCache) deleteRulesNFLOGPrefixes(prefixes set.Set[string]) {
	if prefixes != nil {
		prefixes.Iter(func(item string) error {
			pc.deleteNFLogPrefixEntry(item)
			return nil
		})
	}
}

// GetRuleIDFromNFLOGPrefix returns the RuleID associated with the supplied NFLOG prefix.
func (pc *PolicyLookupsCache) GetRuleIDFromNFLOGPrefix(prefix [64]byte) *RuleID {
	pc.lock.RLock()
	defer pc.lock.RUnlock()
	return pc.nflogPrefixHash[prefix].ruleID
}

// GetRuleIDFromID64 returns the RuleID associated with the supplied 64bit ID.
// Returns nil if the id does not exist.
func (pc *PolicyLookupsCache) GetRuleIDFromID64(id uint64) *RuleID {
	pc.lock.RLock()
	defer pc.lock.RUnlock()

	pfx, ok := pc.ids.GetReverse(id)
	if !ok {
		return nil
	}

	var pfx64 [64]byte
	copy(pfx64[:], []byte(pfx[:]))

	return pc.nflogPrefixHash[pfx64].ruleID
}

// GetID64FromNFLOGPrefix returns the 64 bit ID associated with the supplied
// NFLOG prefix. Returns 0 (an invalid 64bit ID) if the prefix does not exist or
// the 64bit IDs were not enabled.
func (pc *PolicyLookupsCache) GetID64FromNFLOGPrefix(prefix [64]byte) uint64 {
	pc.lock.RLock()
	defer pc.lock.RUnlock()

	return pc.nflogPrefixHash[prefix].id64
}

const (
	// String values used in the string representation of the RuleID. These are used
	// in some of the external APIs and therefore should not be modified.
	RuleDirIngressStr  = "ingress"
	RuleDirEgressStr   = "egress"
	ActionAllowStr     = "allow"
	ActionDenyStr      = "deny"
	ActionNextTierStr  = "pass"
	GlobalNamespaceStr = "__GLOBAL__"
	ProfileTierStr     = "__PROFILE__"
	NoMatchNameStr     = "__NO_MATCH__"
	UnknownStr         = "__UNKNOWN__"

	// Special rule index that specifies that a policy has selected traffic that has applied the
	//  tier default action on traffic.
	RuleIndexTierDefaultAction int = -1
	RuleIDIndexUnknown         int = -2
)

type PolicyID struct {
	// The policy or profile name. This has the tier removed from the name. If this is blank, this represents
	// a "no match" rule. For k8s policies, this will be the full v3 name (knp.default.<k8s name>) - this avoids
	// name conflicts with Calico policies.
	Name string
	// The namespace. This is only non-blank for a NetworkPolicy type. For Tiers, GlobalNetworkPolicies and the
	// no match rules this will be blank.
	Namespace string
	// The kind of policy.
	Kind string
}

// RuleID contains the complete identifiers for a particular rule. This is a breakdown of the
// Felix v1 representation into the v3 representation used by the API and the collector.
type RuleID struct {
	// The policy.
	PolicyID
	// The rule direction.
	Direction rules.RuleDir
	// The index into the rule slice.
	Index int
	// A stringified version of the above index (stored to avoid frequent conversion)
	IndexStr string
	// The rule action.
	Action rules.RuleAction
	// The tier of the policy. Empty for profiles.
	Tier string

	// Optimization so that the hot path doesn't need to create strings.
	dpName string
	fpName string
}

func NewRuleID(kind, tier, name, namespace string, ruleIndex int, ruleDirection rules.RuleDir, ruleAction rules.RuleAction) *RuleID {
	rid := &RuleID{
		PolicyID: PolicyID{
			Name:      name,
			Namespace: namespace,
			Kind:      kind,
		},
		Tier:      tier,
		Direction: ruleDirection,
		Index:     ruleIndex,
		IndexStr:  strconv.Itoa(ruleIndex),
		Action:    ruleAction,
	}
	rid.setDeniedPacketRuleName()
	rid.setFlowLogPolicyName()
	return rid
}

func (r *RuleID) Equals(r2 *RuleID) bool {
	return r.PolicyID == r2.PolicyID &&
		r.Direction == r2.Direction &&
		r.Index == r2.Index &&
		r.Action == r2.Action
}

func (r *RuleID) String() string {
	return fmt.Sprintf(
		"Rule(Tier=%s,Name=%s,Namespace=%s,Direction=%s,Index=%s,Action=%s)",
		r.TierString(), r.NameString(), r.NamespaceString(), r.DirectionString(), r.IndexStr, r.ActionString(),
	)
}

func (r *RuleID) IsNamespaced() bool {
	return len(r.Namespace) != 0
}

func (r *RuleID) IsProfile() bool {
	return len(r.Tier) == 0
}

func (r *RuleID) IsEndOfTier() bool {
	return len(r.Name) == 0
}

func (r *RuleID) IsEndOfTierPass() bool {
	return len(r.Name) == 0 && r.Action == rules.RuleActionPass
}

func (r *RuleID) IsTierDefaultActionRule() bool {
	return r.Index == RuleIndexTierDefaultAction
}

// TierString returns either the Tier name or the Profile indication string.
func (r *RuleID) TierString() string {
	if len(r.Tier) == 0 {
		return ProfileTierStr
	}
	return r.Tier
}

// NameString returns either the resource name or the No-match indication string.
func (r *RuleID) NameString() string {
	if len(r.Name) == 0 {
		return NoMatchNameStr
	}
	return r.Name
}

// NamespaceString returns either the resource namespace or the Global indication string.
func (r *RuleID) NamespaceString() string {
	if len(r.Namespace) == 0 {
		return GlobalNamespaceStr
	}
	return r.Namespace
}

// ActionString converts the action to a string value.
func (r *RuleID) ActionString() string {
	switch r.Action {
	case rules.RuleActionDeny:
		return ActionDenyStr
	case rules.RuleActionAllow:
		return ActionAllowStr
	case rules.RuleActionPass:
		return ActionNextTierStr
	}
	return ""
}

// DirectionString converts the direction to a string value.
func (r *RuleID) DirectionString() string {
	switch r.Direction {
	case rules.RuleDirIngress:
		return RuleDirIngressStr
	case rules.RuleDirEgress:
		return RuleDirEgressStr
	}
	return ""
}

func (r *RuleID) setDeniedPacketRuleName() {
	if r.Action != rules.RuleActionDeny {
		return
	}
	if !r.IsNamespaced() {
		r.dpName = fmt.Sprintf(
			"%s|%s|%s|%s",
			r.TierString(),
			r.NameString(),
			r.IndexStr,
			r.ActionString(),
		)
		return
	}
	r.dpName = fmt.Sprintf(
		"%s|%s/%s|%s|%s",
		r.TierString(),
		r.Namespace,
		r.NameString(),
		r.IndexStr,
		r.ActionString(),
	)
}

func (r *RuleID) GetDeniedPacketRuleName() string {
	if r == nil {
		return ""
	}
	return r.dpName
}

func (r *RuleID) setFlowLogPolicyName() {
	if !r.IsNamespaced() {
		if model.KindIsStaged(r.Kind) {
			// Staged GlobalNetworkPolicy.
			r.fpName = fmt.Sprintf(
				"%s|%s.staged:%s|%s",
				r.TierString(),
				r.TierString(),
				r.NameString(),
				r.ActionString(),
			)
		} else {
			// GlobalNetworkPolicy, AdminNetworkPolicy, BaselineAdminNetworkPolicy.
			r.fpName = fmt.Sprintf(
				"%s|%s|%s",
				r.TierString(),
				r.NameString(),
				r.ActionString(),
			)
		}
	} else if r.Kind == model.KindKubernetesNetworkPolicy {
		// Kubernetes NetworkPolicy.
		r.fpName = fmt.Sprintf(
			"%s|%s/%s|%s",
			r.TierString(),
			r.Namespace,
			r.NameString(),
			r.ActionString(),
		)
	} else if r.Kind == v3.KindStagedKubernetesNetworkPolicy {
		// StagedKubernetesNetworkPolicy.
		r.fpName = fmt.Sprintf(
			"%s|%s/staged:%s|%s",
			r.TierString(),
			r.Namespace,
			r.NameString(),
			r.ActionString(),
		)
	} else if r.Kind == v3.KindStagedNetworkPolicy {
		// StagedNetworkPolicy.
		r.fpName = fmt.Sprintf(
			"%s|%s/%s.staged:%s|%s",
			r.TierString(),
			r.Namespace,
			r.TierString(),
			r.NameString(),
			r.ActionString(),
		)
	} else {
		// Calico namespaced NetworkPolicy.
		r.fpName = fmt.Sprintf(
			"%s|%s/%s|%s",
			r.TierString(),
			r.Namespace,
			r.NameString(),
			r.ActionString(),
		)
	}
}

func (r *RuleID) GetFlowLogPolicyName() string {
	if r == nil {
		return ""
	}
	return r.fpName
}

// Dump returns the contents of important structures in the LookupManager used for
// logging purposes in the test code. This should not be used in any mainline code.
func (pc *PolicyLookupsCache) Dump() string {
	pc.lock.RLock()
	defer pc.lock.RUnlock()
	lines := []string{}
	for p, r := range pc.nflogPrefixHash {
		lines = append(lines, string(p[:])+": "+r.ruleID.String())
	}
	return strings.Join(lines, "\n")
}

// reportPolicyCacheMetrics reports policy cache performance metrics to prometheus
func (pc *PolicyLookupsCache) reportPolicyCacheMetrics(policyCacheWritesDelta uint32) {
	gaugePolicyCacheLength.Set(float64(len(pc.nflogPrefixesPolicy)))
}
