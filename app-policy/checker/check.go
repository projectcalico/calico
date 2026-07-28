// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

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

package checker

import (
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/types"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	ftypes "github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var (
	OK                = int32(code.Code_OK)
	PERMISSION_DENIED = int32(code.Code_PERMISSION_DENIED)
	UNAVAILABLE       = int32(code.Code_UNAVAILABLE)
	INVALID_ARGUMENT  = int32(code.Code_INVALID_ARGUMENT)
	INTERNAL          = int32(code.Code_INTERNAL)
	UNKNOWN           = int32(code.Code_UNKNOWN)

	rlog1 = logutils.NewRateLimitedLogger()
	rlog2 = logutils.NewRateLimitedLogger()
)

// Action is an enumeration of actions a policy rule can take if it is matched.
type Action int

const (
	ALLOW Action = iota
	DENY
	LOG
	PASS
	NO_MATCH // Indicates policy did not match request. Cannot be assigned to rule.

	profileStr = "__PROFILE__"
	// tierDefaultActionIndex is the index used for the default deny rule at the end of a tier.
	tierDefaultActionIndex = -1
	// unknownIndex is the index used for invalid policy or profile check.
	unknownIndex = -2
)

// Evaluate evaluates the flow against the policy store, appending the trace of
// rules it took to trace and returning the result. Callers that evaluate
// repeatedly should pass a scratch slice (as buf[:0]) so that a trace costs no
// allocation; pass nil for a freshly allocated one.
func Evaluate(dir rules.RuleDir, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, flow Flow, trace []*calc.RuleID) []*calc.RuleID {
	_, trace = checkTiers(store, ep, dir, flow, trace)
	return trace
}

// LookupEndpointKeysFromSrcDst looks up the source and destination endpoint keys for the given
// source and destination addresses.
func LookupEndpointKeysFromSrcDst(store *policystore.PolicyStore, src, dst string) (source, destination []proto.WorkloadEndpointID, err error) {
	if store == nil {
		return source, destination, types.ErrNoStore{}
	}

	// Map the destination
	if destinationIp, err := ip.ParseCIDROrIP(dst); err != nil {
		rlog1.WithError(err).Errorf("cannot process destination addr %s", dst)
	} else {
		log.Debugf("lookup endpoint for destination %s", destinationIp.String())
		destination = ipToEndpointKeys(store, destinationIp.Addr())
	}
	// Map the source
	if sourceIp, err := ip.ParseCIDROrIP(src); err != nil {
		rlog2.WithError(err).Errorf("cannot process source addr %s", src)
	} else {
		log.Debugf("lookup endpoint for source %s", sourceIp.String())
		source = ipToEndpointKeys(store, sourceIp.Addr())
	}

	return
}

// ipToEndpointKeys returns the keys of the endpoints that have the given IP address.
func ipToEndpointKeys(store *policystore.PolicyStore, addr ip.Addr) []proto.WorkloadEndpointID {
	return store.IPToIndexes.Keys(addr)
}

// checkStore applies the tiered policy plus any config based corrections and returns OK if the
// check passes or PERMISSION_DENIED if the check fails.
func checkStore(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, dir rules.RuleDir, req Flow) (s status.Status) {
	// Check using the configured policy. Dikastes wants the verdict, not the
	// trace, so it passes no slice to append it to.
	s, _ = checkTiers(store, ep, dir, req, nil)
	return
}

// checkTiers applies the tiered policy in the given store and returns OK if the check passes, or PERMISSION_DENIED if
// the check fails. Note, if no policy matches, the default is PERMISSION_DENIED. It returns the trace of rules that
// were evaluated.
func checkTiers(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, dir rules.RuleDir, flow Flow, traceBuf []*calc.RuleID) (s status.Status, trace []*calc.RuleID) {
	s = status.Status{Code: PERMISSION_DENIED}
	trace = traceBuf
	if ep == nil {
		return
	}

	// The request cache is scratch space for one evaluation. It cannot live on
	// the stack — the compiled matchers take it through a func value, so escape
	// analysis has to assume it leaks — so it is pooled rather than allocated
	// per flow. A single shared one would race: dikastes evaluates concurrently
	// under the store's read lock.
	request := getRequestCache(store, flow)
	defer putRequestCache(request)
	defer handlePanic(&s)

	// The endpoint's compiled form, if it has one, holds its policies' compiled
	// forms in slices parallel to its tiers, so the walk below indexes a slice
	// instead of hashing each policy ID. A nil compiledEndpoint just means
	// every policy is looked up by ID, as before.
	ce, _ := store.CompiledEndpoints[ep].(*compiledEndpoint)

	// The walk below logs per tier, per policy and per profile, so — as in the
	// match functions — it tests the level once rather than paying the
	// argument boxing on every iteration with debug logging switched off.
	debugEnabled := log.IsLevelEnabled(log.DebugLevel)

	for ti, tier := range ep.Tiers {
		if debugEnabled {
			log.Debugf("Checking tier %s", tier.GetName())
		}
		policies := getPoliciesByDirection(dir, tier)
		if len(policies) == 0 {
			continue
		}
		td := ce.tierDirFor(ti, dir, len(policies))
		slots := td.policySlots()

		var (
			ruleIndex               int
			matched                 *compiledPolicy
			tierDefaultActionRuleID *calc.RuleID
		)

		action := NO_MATCH
	Policy:
		for i, pID := range policies {
			action, ruleIndex, matched = checkTierPolicy(store, slotAt(slots, i), pID, dir, request)
			if debugEnabled {
				log.Debugf("Policy checked (ordinal=%d, Id=%+v, action=%v)", i, pID, action)
			}
			switch action {
			case NO_MATCH:
				if tierDefaultActionRuleID == nil {
					tierDefaultActionRuleID = td.tierDefaultRuleID(pID, tier, dir)
				}
				continue Policy
			// If the Policy matches, end evaluation (skipping profiles, if any)
			case ALLOW:
				s.Code = OK
				trace = append(trace, policyRuleID(matched, dir, ruleIndex, pID, tier, rules.RuleActionAllow))
				return
			case DENY:
				s.Code = PERMISSION_DENIED
				trace = append(trace, policyRuleID(matched, dir, ruleIndex, pID, tier, rules.RuleActionDeny))
				return
			case PASS:
				trace = append(trace, policyRuleID(matched, dir, ruleIndex, pID, tier, rules.RuleActionPass))
				// Pass means end evaluation of policies and proceed to next tier (or profiles), if any.
				break Policy
			case LOG:
				log.Debug("policy should never return LOG action")
				s.Code = INVALID_ARGUMENT
				return
			}
		}
		// Done evaluating policies in the tier. If no policy rules have matched, apply tier's default action.
		if action == NO_MATCH {
			if debugEnabled {
				log.Debugf("No policy matched. Tier default action %v applies.", tier.DefaultAction)
			}
			trace = append(trace, tierDefaultActionRuleID)
			// If the default action is anything beside Pass, then apply tier default deny action.
			// Otherwise, continue to next tier or profiles.
			if tier.DefaultAction != string(v3.Pass) {
				s.Code = PERMISSION_DENIED
				return
			}
		}
	}

	// If we reach here, there were either no tiers, or a policy PASSed the request.
	if len(ep.ProfileIds) > 0 {
		slots := ce.profileSlotsFor(len(ep.ProfileIds))
		for i, name := range ep.ProfileIds {
			pID := proto.ProfileID{Name: name}
			action, ruleIndex, matched := checkEndpointProfile(store, slotAt(slots, i), &pID, dir, request)
			if debugEnabled {
				log.Debugf("Profile checked (ordinal=%d, profileId=%v, action=%v)", i, &pID, action)
			}
			switch action {
			case NO_MATCH:
				continue
			case ALLOW:
				s.Code = OK
				trace = append(trace, profileRuleID(matched, dir, ruleIndex, name, rules.RuleActionAllow))
				return
			case DENY, PASS:
				s.Code = PERMISSION_DENIED
				trace = append(trace, profileRuleID(matched, dir, ruleIndex, name, rules.RuleActionDeny))
				return
			case LOG:
				log.Debug("profile should never return LOG action")
				s.Code = INVALID_ARGUMENT
				return
			}
		}
	} else {
		log.Debug("0 active profiles, deny request.")
		s.Code = PERMISSION_DENIED
		trace = append(trace, noProfilesDenyRuleID(dir))
	}
	return
}

// The RuleID recording that an endpoint with no profiles denied the flow
// depends only on the direction, so both are built once. RuleIDs are read-only
// once constructed (as the calc package's own interning of them relies on).
var (
	noProfilesDenyIngress = calc.NewRuleID(v3.KindProfile, profileStr, profileStr, "", tierDefaultActionIndex, rules.RuleDirIngress, rules.RuleActionDeny)
	noProfilesDenyEgress  = calc.NewRuleID(v3.KindProfile, profileStr, profileStr, "", tierDefaultActionIndex, rules.RuleDirEgress, rules.RuleActionDeny)
)

func noProfilesDenyRuleID(dir rules.RuleDir) *calc.RuleID {
	if dir == rules.RuleDirEgress {
		return noProfilesDenyEgress
	}
	return noProfilesDenyIngress
}

// slotAt returns the precomputed slot at index i, or nil if the caller has no
// precomputed slots (slots is nil unless the endpoint has a compiled form).
func slotAt(slots []*policystore.PolicySlot, i int) *policystore.PolicySlot {
	if slots == nil {
		return nil
	}
	return slots[i]
}

// checkTierPolicy checks one of a tier's policies against the request: its
// compiled form when it has one, otherwise the stored policy interpreted per
// flow (no compiler configured, the policy failed to compile, or it is absent
// from the store). slot is the precomputed slot for this policy, or nil when
// the endpoint has no compiled form and the slot must be looked up by ID.
// It also returns the compiled policy it used, if any, so that the caller can
// take the matched rule's trace entry from it instead of building one.
func checkTierPolicy(
	store *policystore.PolicyStore, slot *policystore.PolicySlot, pID *proto.PolicyID,
	dir rules.RuleDir, req *requestCache,
) (Action, int, *compiledPolicy) {
	if slot == nil {
		slot = store.CompiledPolicyByID[ftypes.ProtoToPolicyID(pID)]
	}
	if cp, ok := slot.Compiled().(*compiledPolicy); ok {
		action, index := cp.check(dir, req)
		return action, index, cp
	}
	action, index := checkPolicy(store.PolicyByID[ftypes.ProtoToPolicyID(pID)], dir, req)
	return action, index, nil
}

// checkEndpointProfile is checkTierPolicy for one of an endpoint's profiles.
func checkEndpointProfile(
	store *policystore.PolicyStore, slot *policystore.PolicySlot, pID *proto.ProfileID,
	dir rules.RuleDir, req *requestCache,
) (Action, int, *compiledPolicy) {
	if slot == nil {
		slot = store.CompiledProfileByID[ftypes.ProtoToProfileID(pID)]
	}
	if cp, ok := slot.Compiled().(*compiledPolicy); ok {
		action, index := cp.check(dir, req)
		return action, index, cp
	}
	action, index := checkProfile(store.ProfileByID[ftypes.ProtoToProfileID(pID)], dir, req)
	return action, index, nil
}

// policyRuleID returns the trace entry for the rule a policy matched, memoized
// on the compiled rule when the policy was compiled.
func policyRuleID(
	cp *compiledPolicy, dir rules.RuleDir, index int,
	pID *proto.PolicyID, tier *proto.TierInfo, action rules.RuleAction,
) *calc.RuleID {
	if cp != nil {
		return cp.ruleID(dir, index, pID.Kind, tier.GetName(), pID.Name, pID.Namespace, action)
	}
	return calc.NewRuleID(pID.Kind, tier.GetName(), pID.Name, pID.Namespace, index, dir, action)
}

// profileRuleID is policyRuleID for a rule a profile matched.
func profileRuleID(cp *compiledPolicy, dir rules.RuleDir, index int, name string, action rules.RuleAction) *calc.RuleID {
	if cp != nil {
		return cp.ruleID(dir, index, v3.KindProfile, profileStr, name, "", action)
	}
	return calc.NewRuleID(v3.KindProfile, profileStr, name, "", index, dir, action)
}

// checkPolicy checks the policy against the request and returns the action to take.
func checkPolicy(policy *proto.Policy, dir rules.RuleDir, req *requestCache) (action Action, index int) {
	if policy == nil {
		return Action(INTERNAL), unknownIndex
	}

	if dir == rules.RuleDirEgress {
		return checkRules(policy.OutboundRules, req, policy.Namespace)
	}
	return checkRules(policy.InboundRules, req, policy.Namespace)
}

// checkProfile checks the profile against the request and returns the action to take.
func checkProfile(profile *proto.Profile, dir rules.RuleDir, req *requestCache) (action Action, index int) {
	// profiles or profile updates might not be available yet. use internal here
	if profile == nil {
		return Action(INTERNAL), unknownIndex
	}

	if dir == rules.RuleDirEgress {
		return checkRules(profile.OutboundRules, req, "")
	}
	return checkRules(profile.InboundRules, req, "")
}

// checkRules checks the rules against the request and returns the action to take.
func checkRules(rules []*proto.Rule, req *requestCache, policyNamespace string) (action Action, index int) {
	for i, r := range rules {
		if match(policyNamespace, r, req) {
			log.Debugf("checkRules: Rule matched %v", r)
			a := actionFromString(r.Action)
			if a != LOG {
				// We don't support actually logging requests, but if we hit a LOG action, we should
				// continue processing rules.
				return a, i
			}
		}
	}
	return NO_MATCH, tierDefaultActionIndex
}

// actionFromString converts a string to an Action. It panics if the string is not a valid action.
// The string is case-insensitive. EqualFold compares without allocating, where lowercasing the
// input would allocate on every call.
func actionFromString(s string) Action {
	// Felix currently passes us the v1 resource types where the "pass" action is called "next-tier".
	// Here we support both the v1 and v3 action names.
	switch {
	case strings.EqualFold(s, "allow"):
		return ALLOW
	case strings.EqualFold(s, "deny"):
		return DENY
	case strings.EqualFold(s, "pass"), strings.EqualFold(s, "next-tier"):
		return PASS
	case strings.EqualFold(s, "log"):
		return LOG
	}
	log.Errorf("Got bad action %v", s)
	panic(&InvalidDataFromDataPlane{"got bad action"})
}

// ruleActionFromStr converts a string to a rules.RuleAction. It panics if the string is not a
// valid action.
func ruleActionFromStr(s string) rules.RuleAction {
	switch {
	case strings.EqualFold(s, "allow"):
		return rules.RuleActionAllow
	case strings.EqualFold(s, "deny"):
		return rules.RuleActionDeny
	case strings.EqualFold(s, "pass"):
		return rules.RuleActionPass
	}
	log.Errorf("Got bad action %v", s)
	panic(&InvalidDataFromDataPlane{"got bad action"})
}

// handlePanic recovers from a panic and sets the status to INVALID_ARGUMENT if the panic was due
// to an invalid action from the data plane.
func handlePanic(s *status.Status) {
	if r := recover(); r != nil {
		if v, ok := r.(*InvalidDataFromDataPlane); ok {
			log.Debug("InvalidFromDataPlane: ", v.string)
			*s = status.Status{Code: INVALID_ARGUMENT}
		} else {
			panic(r)
		}
	}
}

// getPoliciesByDirection returns the list of policy names for the given direction.
func getPoliciesByDirection(dir rules.RuleDir, tier *proto.TierInfo) []*proto.PolicyID {
	if dir == rules.RuleDirEgress {
		return tier.EgressPolicies
	}
	return tier.IngressPolicies
}
