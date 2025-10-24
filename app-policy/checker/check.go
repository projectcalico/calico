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

// Evaluate evaluates the flow against the policy store and returns the trace of rules.
func Evaluate(dir rules.RuleDir, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, flow Flow) []*calc.RuleID {
	_, trace := checkTiers(store, ep, dir, flow)
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
	// Check using the configured policy
	s, _ = checkTiers(store, ep, dir, req)
	return
}

// checkTiers applies the tiered policy in the given store and returns OK if the check passes, or PERMISSION_DENIED if
// the check fails. Note, if no policy matches, the default is PERMISSION_DENIED. It returns the trace of rules that
// were evaluated.
func checkTiers(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, dir rules.RuleDir, flow Flow) (s status.Status, trace []*calc.RuleID) {
	s = status.Status{Code: PERMISSION_DENIED}
	if ep == nil {
		return
	}

	request := NewRequestCache(store, flow)
	defer handlePanic(&s)

	for _, tier := range ep.Tiers {
		log.Debugf("Checking tier %s", tier.GetName())
		policies := getPoliciesByDirection(dir, tier)
		if len(policies) == 0 {
			continue
		}

		var (
			ruleIndex               int
			tierDefaultActionRuleID *calc.RuleID
		)

		action := NO_MATCH
	Policy:
		for i, pID := range policies {
			policy := store.PolicyByID[ftypes.ProtoToPolicyID(pID)]
			action, ruleIndex = checkPolicy(policy, dir, request)
			log.Debugf("Policy checked (ordinal=%d, Id=%+v, action=%v)", i, pID, action)
			switch action {
			case NO_MATCH:
				if tierDefaultActionRuleID == nil {
					tierDefaultActionRuleID = calc.NewRuleID(pID.Kind, tier.GetName(), pID.Name, pID.Namespace, tierDefaultActionIndex, dir, ruleActionFromStr(tier.DefaultAction))
				}
				continue Policy
			// If the Policy matches, end evaluation (skipping profiles, if any)
			case ALLOW:
				s.Code = OK
				trace = append(trace, calc.NewRuleID(pID.Kind, tier.GetName(), pID.Name, pID.Namespace, ruleIndex, dir, rules.RuleActionAllow))
				return
			case DENY:
				s.Code = PERMISSION_DENIED
				trace = append(trace, calc.NewRuleID(pID.Kind, tier.GetName(), pID.Name, pID.Namespace, ruleIndex, dir, rules.RuleActionDeny))
				return
			case PASS:
				trace = append(trace, calc.NewRuleID(pID.Kind, tier.GetName(), pID.Name, pID.Namespace, ruleIndex, dir, rules.RuleActionPass))
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
			log.Debugf("No policy matched. Tier default action %v applies.", tier.DefaultAction)
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
		for i, name := range ep.ProfileIds {
			pID := proto.ProfileID{Name: name}
			profile := store.ProfileByID[ftypes.ProtoToProfileID(&pID)]
			action, ruleIndex := checkProfile(profile, dir, request)
			log.Debugf("Profile checked (ordinal=%d, profileId=%v, action=%v)", i, &pID, action)
			switch action {
			case NO_MATCH:
				continue
			case ALLOW:
				s.Code = OK
				trace = append(trace, calc.NewRuleID(v3.KindProfile, profileStr, name, "", ruleIndex, dir, rules.RuleActionAllow))
				return
			case DENY, PASS:
				s.Code = PERMISSION_DENIED
				trace = append(trace, calc.NewRuleID(v3.KindProfile, profileStr, name, "", ruleIndex, dir, rules.RuleActionDeny))
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
		trace = append(trace, calc.NewRuleID(v3.KindProfile, profileStr, profileStr, "", tierDefaultActionIndex, dir, rules.RuleActionDeny))
	}
	return
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
// The string is case-insensitive.
func actionFromString(s string) Action {
	// Felix currently passes us the v1 resource types where the "pass" action is called "next-tier".
	// Here we support both the v1 and v3 action names.
	m := map[string]Action{
		"allow":     ALLOW,
		"deny":      DENY,
		"pass":      PASS,
		"next-tier": PASS,
		"log":       LOG,
	}
	a, found := m[strings.ToLower(s)]
	if !found {
		log.Errorf("Got bad action %v", s)
		panic(&InvalidDataFromDataPlane{"got bad action"})
	}
	return a
}

// ruleActionFromStr converts a string to a rules.RuleAction. It panics if the string is not a
// valid action.
func ruleActionFromStr(s string) rules.RuleAction {
	switch strings.ToLower(s) {
	case "allow":
		return rules.RuleActionAllow
	case "deny":
		return rules.RuleActionDeny
	case "pass":
		return rules.RuleActionPass
	default:
		log.Errorf("Got bad action %v", s)
		panic(&InvalidDataFromDataPlane{"got bad action"})
	}
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
