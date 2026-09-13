// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"strings"
	"time"

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
	"github.com/projectcalico/calico/lib/logrusr"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var (
	OK                = int32(code.Code_OK)
	PERMISSION_DENIED = int32(code.Code_PERMISSION_DENIED)
	UNAVAILABLE       = int32(code.Code_UNAVAILABLE)
	INVALID_ARGUMENT  = int32(code.Code_INVALID_ARGUMENT)
	INTERNAL          = int32(code.Code_INTERNAL)
	UNKNOWN           = int32(code.Code_UNKNOWN)

	rlogBadDstAddr = logrusr.NewRateLimitedLogger()
	rlogBadSrcAddr = logrusr.NewRateLimitedLogger()
	// A missing policy is one log line per evaluation, and Felix's collector re-evaluates every
	// flow in both directions on every sweep, so a policy that stays missing would log per flow
	// per sweep.
	rlogMissingPolicy = logrusr.NewRateLimitedLogger()
)

// PolicyScope selects which of an endpoint's policies take part in an evaluation.
type PolicyScope int

const (
	// EnforcedOnly ignores staged policies, giving the verdict that is actually enforced.
	// A tier whose policies are all staged is skipped entirely, end-of-tier action included,
	// exactly as if the tier were not attached to the endpoint at all.
	EnforcedOnly PolicyScope = iota
	// StagedAsEnforced evaluates staged policies as though they had been promoted to enforced,
	// giving the "pending" verdict: what would happen if the staged policies went live now.
	StagedAsEnforced
)

// Every log site on the per-request evaluation path needs its own rate limiter.
//
// A rule set that applies tens of thousands of rules to one endpoint turns any per-rule log
// into a storm: the conditions below are all "shouldn't happen, but does" — a dangling IP set
// reference while the store catches up, a malformed CIDR or selector that got past validation,
// a flow that is not IP at all — and each one repeats for every rule in the set, on every
// request. Rate limiting is per logger instance, so sharing one across sites would let the
// noisiest message starve the rest; sites that report the same condition do share one.
//
// These sites must not use the WithField/WithError builders: those allocate a fields map, a
// logrus.Entry and a wrapper *before* the rate limiter gets to drop the message, which is the
// per-rule allocation this path has been optimised to avoid. Pass the value to Warnf instead.
var (
	rlogIPSetMissing = newEvalPathLogger()
	rlogBadPrincipal = newEvalPathLogger()
	rlogBadProtocol  = newEvalPathLogger()
	// The adapter warns when Envoy names a protocol it cannot map. requestCache memoizes
	// the resolved protocol, so this fires once per request rather than once per rule.
	rlogBadProtocolName = newEvalPathLogger()
	rlogBadCIDR         = newEvalPathLogger()
	rlogBadSelector     = newEvalPathLogger()
	rlogBadRulePath     = newEvalPathLogger()
)

// newEvalPathLogger returns a logger that admits a short burst and then one line per interval,
// so a storm leaves a few concrete examples plus a "logsSkipped" count rather than filling the
// log. Tests that need every line replace these vars; see withUnthrottledEvalPathLogs.
func newEvalPathLogger() *logrusr.RateLimitedLogger {
	return logrusr.NewRateLimitedLogger(
		logrusr.OptInterval(30*time.Second),
		logrusr.OptBurst(10),
	)
}

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

// Evaluate evaluates the flow against the policy store and returns the trace of rules. The scope
// decides whether staged policies take part: pass StagedAsEnforced for the pending trace, or
// EnforcedOnly for the trace the dataplane enforces.
//
// The trace is appended to traceBuf. Callers that evaluate repeatedly should pass a scratch slice
// (as buf[:0]) so that a trace costs no allocation; pass nil for a freshly allocated one.
//
// It returns an error if the evaluation could not be completed, in which case the trace is nil and
// the caller should hold on to whatever trace it already had: an empty trace would say the flow has
// no policy, which is a stronger claim than "we could not work it out".
func Evaluate(scope PolicyScope, dir rules.RuleDir, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, flow Flow, traceBuf []*calc.RuleID) ([]*calc.RuleID, error) {
	s, trace := checkTiers(scope, store, ep, dir, flow, traceBuf)
	if s.Code == INTERNAL || s.Code == INVALID_ARGUMENT {
		// The evaluation stopped part way through, so the trace stops short of a verdict. Drop it
		// and report why it stopped.
		return nil, fmt.Errorf("%s: %s", code.Code(s.Code), s.Message)
	}
	return trace, nil
}

// LookupEndpointKeysFromSrcDst looks up the source and destination endpoint keys for the given
// source and destination addresses.
func LookupEndpointKeysFromSrcDst(store *policystore.PolicyStore, src, dst string) (source, destination []proto.WorkloadEndpointID, err error) {
	if store == nil {
		return source, destination, types.ErrNoStore{}
	}

	// Map the destination
	if destinationIp, err := ip.ParseCIDROrIP(dst); err != nil {
		rlogBadDstAddr.Errorf("cannot process destination addr %s: %v", dst, err)
	} else {
		log.Debugf("lookup endpoint for destination %s", destinationIp.String())
		destination = ipToEndpointKeys(store, destinationIp.Addr())
	}
	// Map the source
	if sourceIp, err := ip.ParseCIDROrIP(src); err != nil {
		rlogBadSrcAddr.Errorf("cannot process source addr %s: %v", src, err)
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
func checkStore(scope PolicyScope, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, dir rules.RuleDir, req Flow) (s status.Status) {
	// Check using the configured policy. Dikastes wants the verdict, not the
	// trace, so it passes no slice to append it to.
	s, _ = checkTiers(scope, store, ep, dir, req, nil)
	return
}

// checkTiers applies the tiered policy in the given store and returns OK if the check passes, or PERMISSION_DENIED if
// the check fails. Note, if no policy matches, the default is PERMISSION_DENIED. It returns the trace of rules that
// were evaluated, appended to traceBuf.
//
// The walk is shared by the compiled and the interpreted engine: each policy is evaluated by its
// compiled form when it has one and interpreted otherwise (see checkTierPolicy), so the scope,
// the end-of-tier action and the fail-closed handling of a policy missing from the store apply
// identically whichever engine evaluates a given policy.
func checkTiers(scope PolicyScope, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, dir rules.RuleDir, flow Flow, traceBuf []*calc.RuleID) (s status.Status, trace []*calc.RuleID) {
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
			tierDefaultActionRuleID *calc.RuleID
			// Policies of this tier that are in scope for this evaluation. A tier with none of
			// them contributes nothing at all, end-of-tier action included.
			policiesInScope int
		)

		action := NO_MATCH
	Policy:
		for i, pID := range policies {
			if scope == EnforcedOnly && model.KindIsStaged(pID.Kind) {
				if debugEnabled {
					log.Debugf("Staged policy, not enforced, skipping (ordinal=%d, Id=%+v)", i, pID)
				}
				continue Policy
			}
			policiesInScope++

			var found bool
			action, ruleIndex, found = checkTierPolicy(store, slotAt(slots, i), pID, dir, request)
			if !found {
				// The endpoint's tier names this policy but the store does not have it, so we cannot
				// know its verdict. We should never get here: a policy is sent before the endpoints
				// that reference it. Fail closed rather than apply the rest of the tier to a request
				// this policy may govern.
				policyID := ftypes.ProtoToPolicyID(pID)
				rlogMissingPolicy.Errorf("Policy named in tier is missing from the store, failing evaluation (ordinal=%d, policy=%s, tier=%s)",
					i, policyID.ID(), tier.GetName())
				s.Code = INTERNAL
				s.Message = fmt.Sprintf("policy %s of tier %s is missing from the policy store",
					policyID.ID(), tier.GetName())
				return
			}
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
				trace = append(trace, policyRuleID(store, slotAt(slots, i), dir, ruleIndex, pID, tier, rules.RuleActionAllow))
				return
			case DENY:
				s.Code = PERMISSION_DENIED
				trace = append(trace, policyRuleID(store, slotAt(slots, i), dir, ruleIndex, pID, tier, rules.RuleActionDeny))
				return
			case PASS:
				trace = append(trace, policyRuleID(store, slotAt(slots, i), dir, ruleIndex, pID, tier, rules.RuleActionPass))
				// Pass means end evaluation of policies and proceed to next tier (or profiles), if any.
				break Policy
			case LOG:
				log.Debug("policy should never return LOG action")
				s.Code = INVALID_ARGUMENT
				s.Message = fmt.Sprintf("policy %s returned a LOG action", ftypes.ProtoToPolicyID(pID).ID())
				return
			}
		}
		// Done evaluating policies in the tier. If no policy rules have matched, apply tier's default action.
		if policiesInScope > 0 && action == NO_MATCH {
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
			action, ruleIndex := checkEndpointProfile(store, slotAt(slots, i), &pID, dir, request)
			if debugEnabled {
				log.Debugf("Profile checked (ordinal=%d, profileId=%v, action=%v)", i, &pID, action)
			}
			switch action {
			case NO_MATCH:
				continue
			case ALLOW:
				s.Code = OK
				trace = append(trace, profileRuleID(store, slotAt(slots, i), dir, ruleIndex, &pID, rules.RuleActionAllow))
				return
			case DENY, PASS:
				s.Code = PERMISSION_DENIED
				trace = append(trace, profileRuleID(store, slotAt(slots, i), dir, ruleIndex, &pID, rules.RuleActionDeny))
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
// flow (no compiler configured, or the policy failed to compile). slot is the
// precomputed slot for this policy, or nil when the endpoint has no compiled
// form and the slot must be looked up by ID.
//
// found is false when the store holds no such policy at all, compiled or not.
// The caller fails the evaluation closed: the policy's verdict is unknowable,
// so neither engine may guess at it.
func checkTierPolicy(
	store *policystore.PolicyStore, slot *policystore.PolicySlot, pID *proto.PolicyID,
	dir rules.RuleDir, req *requestCache,
) (action Action, index int, found bool) {
	if cp := compiledPolicyFor(store, slot, pID); cp != nil {
		action, index = cp.check(dir, req)
		return action, index, true
	}
	policy := store.PolicyByID[ftypes.ProtoToPolicyID(pID)]
	if policy == nil {
		return Action(INTERNAL), unknownIndex, false
	}
	action, index = checkPolicy(policy, dir, req)
	return action, index, true
}

// checkEndpointProfile is checkTierPolicy for one of an endpoint's profiles.
// A profile missing from the store keeps checkProfile's nil semantics.
func checkEndpointProfile(
	store *policystore.PolicyStore, slot *policystore.PolicySlot, pID *proto.ProfileID,
	dir rules.RuleDir, req *requestCache,
) (Action, int) {
	if cp := compiledProfileFor(store, slot, pID); cp != nil {
		return cp.check(dir, req)
	}
	return checkProfile(store.ProfileByID[ftypes.ProtoToProfileID(pID)], dir, req)
}

// compiledPolicyFor resolves a tier policy's compiled form: the endpoint's
// precomputed slot when it has one, otherwise a lookup by ID.
func compiledPolicyFor(store *policystore.PolicyStore, slot *policystore.PolicySlot, pID *proto.PolicyID) *compiledPolicy {
	if slot == nil {
		slot = store.CompiledPolicyByID[ftypes.ProtoToPolicyID(pID)]
	}
	cp, _ := slot.Compiled().(*compiledPolicy)
	return cp
}

func compiledProfileFor(store *policystore.PolicyStore, slot *policystore.PolicySlot, pID *proto.ProfileID) *compiledPolicy {
	if slot == nil {
		slot = store.CompiledProfileByID[ftypes.ProtoToProfileID(pID)]
	}
	cp, _ := slot.Compiled().(*compiledPolicy)
	return cp
}

// policyRuleID returns the trace entry for the rule a policy matched, taken
// from the compiled rule's memo when the policy was compiled. It resolves the
// compiled policy again rather than having the walk carry it along: a walk
// traces at most one rule, so this runs once per evaluation, where the walk
// runs once per policy.
func policyRuleID(
	store *policystore.PolicyStore, slot *policystore.PolicySlot, dir rules.RuleDir, index int,
	pID *proto.PolicyID, tier *proto.TierInfo, action rules.RuleAction,
) *calc.RuleID {
	if cp := compiledPolicyFor(store, slot, pID); cp != nil {
		return cp.ruleID(dir, index, pID.Kind, tier.GetName(), pID.Name, pID.Namespace, action)
	}
	return calc.NewRuleID(pID.Kind, tier.GetName(), pID.Name, pID.Namespace, index, dir, action)
}

// profileRuleID is policyRuleID for a rule a profile matched.
func profileRuleID(
	store *policystore.PolicyStore, slot *policystore.PolicySlot, dir rules.RuleDir, index int,
	pID *proto.ProfileID, action rules.RuleAction,
) *calc.RuleID {
	if cp := compiledProfileFor(store, slot, pID); cp != nil {
		return cp.ruleID(dir, index, v3.KindProfile, profileStr, pID.Name, "", action)
	}
	return calc.NewRuleID(v3.KindProfile, profileStr, pID.Name, "", index, dir, action)
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
			*s = status.Status{Code: INVALID_ARGUMENT, Message: v.string}
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
