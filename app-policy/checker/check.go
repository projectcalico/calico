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
	flxrules "github.com/projectcalico/calico/felix/rules"
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
	//rlog3 = logutils.NewRateLimitedLogger()
	//rlog4 = logutils.NewRateLimitedLogger()
	//rlog5 = logutils.NewRateLimitedLogger()
)

// Action is an enumeration of actions a policy rule can take if it is matched.
type Action int

const (
	ALLOW Action = iota
	DENY
	LOG
	PASS
	NO_MATCH // Indicates policy did not match request. Cannot be assigned to rule.

	// defaultTier is the name of the default tier.
	defaultTier = "default"
	// endOfTierDenyIndex is the index used for the default deny rule at the end of a tier.
	endOfTierDenyIndex = -1
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

// checkRequest checks the request against the policy store.
/*func checkRequest(store *policystore.PolicyStore, req Flow) status.Status {
	src, dst, err := lookupEndpointsFromRequest(store, req)
	if err != nil {
		return status.Status{Code: INTERNAL, Message: fmt.Sprintf("endpoint lookup error: %v", err)}
	}
	log.Debugf("Found endpoints from request [src: %v, dst: %v]", src, dst)

	if len(dst) > 0 {
		// checking if the destination is not a sidecar
		if dst[0].ApplicationLayer == nil {
			alpIPset, ok := store.IPSetByID[tproxydefs.ApplicationLayerPolicyIPSet]
			if !ok {
				return status.Status{Code: UNKNOWN, Message: "cannot process ALP yet"}
			}

			if !alpIPset.Contains(req.GetDestIP().String()) {
				return status.Status{Code: UNKNOWN, Message: "ALP not enabled for this request destination"}
			}

		}
		// Destination is local workload, apply its ingress policy.
		// possible there's multiple weps for an ip.
		// let's run through all of them and apply its ingress policy
		for _, ds := range dst {
			if s := checkStore(store, ds, flxrules.RuleDirIngress, req); s.Code != OK {
				// stop looping on first non-OK status
				return status.Status{
					Code:    s.Code,
					Message: s.Message,
					Details: s.Details,
				}
			}
		}
		// all local destinations aren't getting denied by policy
		// let traffic through
		return status.Status{Code: OK}
	}

	if len(src) > 0 {
		// Source is local but destination is not.  We assume that the traffic reached Envoy as
		// a false positive; for example, a workload connecting out to an L7-annotated service.
		// Let it through; it should be handled by the remote Envoy/Dikastes.

		// NB: in the future we can process egress rules here e.g.

		if src != nil { // originating node: so process src traffic
			return checkStore(store, src, req) // TODO need flag to reverse policy logic
		}

		// possible future iteration: apply src egress policy
		// return checkStore(store, src, req, withEgressProcessing{})
		log.Debugf("allowing traffic to continue to its destination hop/next processing leg. (req: %v)", req)

		return status.Status{Code: OK, Message: fmt.Sprintf("request %v passing through", req)}
	}

	// Don't know source or dest.  Why was this packet sent to us?
	// Assume that we're out of sync and reject it.
	log.Debug("encountered invalid ext_authz request case")
	return status.Status{Code: UNKNOWN} // return unknown so that next check provider can continue processing
}*/

// lookupEndpointsFromRequest looks up the source and destination endpoints for the given flow.
/*func lookupEndpointsFromRequest(store *policystore.PolicyStore, flow Flow) (source, destination []*proto.WorkloadEndpoint, err error) {
	if store == nil {
		return source, destination, types.ErrNoStore{}
	}

	// Map the destination
	if destinationIp, err := ip.ParseCIDROrIP(flow.GetDestIP().String()); err != nil {
		rlog3.WithError(err).Errorf("cannot process destination addr %s:%d", flow.GetDestIP().String(), flow.GetDestPort())
	} else {
		log.Debugf("lookup endpoint for destination %v:%d", destinationIp, flow.GetDestPort())
		destination = ipToEndpoints(store, destinationIp.Addr())
	}

	// Map the source
	if sourceIp, err := ip.ParseCIDROrIP(flow.GetSourceIP().String()); err != nil {
		rlog4.WithError(err).Warnf("cannot process source addr %s:%d", flow.GetSourceIP().String(), flow.GetSourcePort())
	} else {
		log.Debugf("lookup endpoint for source %s:%d", sourceIp.String(), flow.GetSourcePort())
		source = ipToEndpoints(store, sourceIp.Addr())
	}

	return
}*/

// ipToEndpoints returns the endpoints that have the given IP address.
/*func ipToEndpoints(store *policystore.PolicyStore, addr ip.Addr) []*proto.WorkloadEndpoint {
	return store.IPToIndexes.Get(addr)
}*/

// ipToEndpointKeys returns the keys of the endpoints that have the given IP address.
func ipToEndpointKeys(store *policystore.PolicyStore, addr ip.Addr) []proto.WorkloadEndpointID {
	return store.IPToIndexes.Keys(addr)
}

// checkStore applies the tiered policy plus any config based corrections and returns OK if the
// check passes or PERMISSION_DENIED if the check fails.
func checkStore(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, dir flxrules.RuleDir, req Flow) (s status.Status) {
	// Check using the configured policy
	s, _ = checkTiers(store, ep, dir, req)
	return
}

// checkTiers applies the tiered policy in the given store and returns OK if the check passes, or PERMISSION_DENIED if
// the check fails. Note, if no policy matches, the default is PERMISSION_DENIED. It returns the trace of rules that
// were evaluated.
func checkTiers(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, dir flxrules.RuleDir, flow Flow) (s status.Status, trace []*calc.RuleID) {
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
			ruleIndex         int
			defaultDenyRuleID *calc.RuleID
		)

		action := NO_MATCH
	Policy:
		for i, name := range policies {
			pID := proto.PolicyID{Tier: tier.GetName(), Name: name}
			policy := store.PolicyByID[ftypes.ProtoToPolicyID(&pID)]
			action, ruleIndex = checkPolicy(policy, dir, request)
			log.Debugf("Policy checked (ordinal=%d, profileId=%v, action=%v)", i, &pID, action)
			policyName := getPolicyName(name)
			switch action {
			case NO_MATCH:
				if defaultDenyRuleID == nil {
					defaultDenyRuleID = calc.NewRuleID(tier.GetName(), policyName, policy.GetNamespace(), endOfTierDenyIndex, dir, flxrules.RuleActionDeny)
				}
				continue Policy
			// If the Policy matches, end evaluation (skipping profiles, if any)
			case ALLOW:
				s.Code = OK
				trace = append(trace, calc.NewRuleID(tier.GetName(), policyName, policy.GetNamespace(), ruleIndex, dir, flxrules.RuleActionAllow))
				return
			case DENY:
				s.Code = PERMISSION_DENIED
				trace = append(trace, calc.NewRuleID(tier.GetName(), policyName, policy.GetNamespace(), ruleIndex, dir, flxrules.RuleActionDeny))
				return
			case PASS:
				trace = append(trace, calc.NewRuleID(tier.GetName(), policyName, policy.GetNamespace(), ruleIndex, dir, flxrules.RuleActionPass))
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
			// If the default action is anything beside Pass, then apply tier default deny action.
			// Otherwise, continue to next tier or profiles.
			if tier.DefaultAction != string(v3.Pass) {
				trace = append(trace, defaultDenyRuleID)
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
			policyName := getPolicyName(name)
			switch action {
			case NO_MATCH:
				continue
			case ALLOW:
				s.Code = OK
				trace = append(trace, calc.NewRuleID(defaultTier, policyName, "", ruleIndex, dir, flxrules.RuleActionAllow))
				return
			case DENY, PASS:
				s.Code = PERMISSION_DENIED
				trace = append(trace, calc.NewRuleID(defaultTier, policyName, "", ruleIndex, dir, flxrules.RuleActionDeny))
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
		trace = append(trace, calc.NewRuleID(defaultTier, "__PROFILE__", "", endOfTierDenyIndex, dir, flxrules.RuleActionDeny))

	}
	return
}

// checkPolicy checks the policy against the request and returns the action to take.
func checkPolicy(policy *proto.Policy, dir flxrules.RuleDir, req *requestCache) (action Action, index int) {
	if policy == nil {
		return Action(INTERNAL), unknownIndex
	}

	if dir == flxrules.RuleDirEgress {
		return checkRules(policy.OutboundRules, req, policy.Namespace)
	}
	return checkRules(policy.InboundRules, req, policy.Namespace)
}

// checkProfile checks the profile against the request and returns the action to take.
func checkProfile(profile *proto.Profile, dir flxrules.RuleDir, req *requestCache) (action Action, index int) {
	// profiles or profile updates might not be available yet. use internal here
	if profile == nil {
		return Action(INTERNAL), unknownIndex
	}

	if dir == flxrules.RuleDirEgress {
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
	return NO_MATCH, endOfTierDenyIndex
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
func getPoliciesByDirection(dir flxrules.RuleDir, tier *proto.TierInfo) []string {
	if dir == flxrules.RuleDirEgress {
		return tier.EgressPolicies
	}
	return tier.IngressPolicies
}

// getPolicyName Removes any namespace and tier prefix to get the name of the policy only; preserves
// the "staged:" infix if present.
func getPolicyName(s string) string {
	parts := strings.Split(s, ".")
	if len(parts) > 1 {
		polName := parts[1]
		if strings.Contains(s, "staged:") {
			polName = "staged:" + polName
		}
		return polName
	}
	// If no period is found and a '/' exists, return only the policy name by removing the namespace prefix.
	parts = strings.Split(s, "/")
	if len(parts) > 1 {
		return parts[1]
	}
	// Return the original string if no period or slash is found
	return s
}
