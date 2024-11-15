// Copyright (c) 2018-2024 Tigera, Inc. All rights reserved.

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

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

var OK = int32(code.Code_OK)
var PERMISSION_DENIED = int32(code.Code_PERMISSION_DENIED)
var UNAVAILABLE = int32(code.Code_UNAVAILABLE)
var INVALID_ARGUMENT = int32(code.Code_INVALID_ARGUMENT)
var INTERNAL = int32(code.Code_INTERNAL)

// Action is an enumeration of actions a policy rule can take if it is matched.
type Action int

const (
	ALLOW Action = iota
	DENY
	LOG
	PASS
	NO_MATCH // Indicates policy did not match request. Cannot be assigned to rule.
)

// checkStore applies the tiered policy plus any config based corrections and returns OK if the check passes or
// PERMISSION_DENIED if the check fails.
func checkStore(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, req *authz.CheckRequest) (s status.Status) {
	// Check using the configured policy
	s = checkTiers(store, ep, req)
	return
}

// checkTiers applies the tiered policy in the given store and returns OK if the check passes, or PERMISSION_DENIED if
// the check fails. Note, if no policy matches, the default is PERMISSION_DENIED.
func checkTiers(store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, req *authz.CheckRequest) (s status.Status) {
	s = status.Status{Code: PERMISSION_DENIED}
	// nothing to check. return early
	if ep == nil {
		return
	}
	reqCache, err := NewRequestCache(store, req)
	if err != nil {
		log.Errorf("Failed to init requestCache: %v", err)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			// Recover from the panic if we know what it is and we know what to do with it.
			if v, ok := r.(*InvalidDataFromDataPlane); ok {
				log.Debug("encountered InvalidFromDataPlane: ", v.string)
				s = status.Status{Code: INVALID_ARGUMENT}
			} else {
				panic(r)
			}
		}
	}()
	for _, tier := range ep.Tiers {
		log.Debug("Checking policy tier", tier.GetName())
		policies := tier.IngressPolicies
		if len(policies) == 0 {
			// No ingress policy in this tier, move on to next one.
			continue
		} else {
			log.Debug("policies: ", policies)
		}

		action := NO_MATCH
	Policy:
		for i, name := range policies {
			pID := types.PolicyID{Tier: tier.GetName(), Name: name}
			policy := store.PolicyByID[pID]
			action = checkPolicy(policy, reqCache)
			log.Debugf("Policy checked (ordinal=%d, profileId=%v, action=%v)", i, pID, action)
			switch action {
			case NO_MATCH:
				continue Policy
			// If the Policy matches, end evaluation (skipping profiles, if any)
			case ALLOW:
				s.Code = OK
				return
			case DENY:
				s.Code = PERMISSION_DENIED
				return
			case PASS:
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
				s.Code = PERMISSION_DENIED
				return
			}
		}
	}
	// If we reach here, there were either no tiers, or a policy PASSed the request.
	if len(ep.ProfileIds) > 0 {
		for i, name := range ep.ProfileIds {
			pID := types.ProfileID{Name: name}
			profile := store.ProfileByID[pID]
			action := checkProfile(profile, reqCache)
			log.Debugf("Profile checked (ordinal=%d, profileId=%v, action=%v)", i, pID, action)
			switch action {
			case NO_MATCH:
				continue
			case ALLOW:
				s.Code = OK
				return
			case DENY, PASS:
				s.Code = PERMISSION_DENIED
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
	}
	return
}

// checkPolicy checks if the policy matches the request data, and returns the action.
func checkPolicy(policy *proto.Policy, req *requestCache) (action Action) {
	if policy == nil {
		return Action(INTERNAL)
	}

	// Note that we support only inbound policy.
	return checkRules(policy.InboundRules, req, policy.Namespace)
}

func checkProfile(profile *proto.Profile, req *requestCache) (action Action) {
	// profiles or profile updates might not be available yet. use internal here
	if profile == nil {
		return Action(INTERNAL)
	}

	return checkRules(profile.InboundRules, req, "")
}

func checkRules(rules []*proto.Rule, req *requestCache, policyNamespace string) (action Action) {
	for _, r := range rules {
		if match(r, req, policyNamespace) {
			log.Debugf("Rule matched.")
			a := actionFromString(r.Action)
			if a != LOG {
				// We don't support actually logging requests, but if we hit a LOG action, we should
				// continue processing rules.
				return a
			}
		}
	}
	return NO_MATCH
}

// actionFromString converts a string action name, like "allow" into an Action.
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
		log.Panic("got bad action")
	}
	return a
}
