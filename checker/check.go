// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/app-policy/policystore"
	"github.com/projectcalico/app-policy/proto"

	authz "github.com/envoyproxy/data-plane-api/api/auth"
	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
)

var OK = code.Code_value["OK"]
var PERMISSION_DENIED = code.Code_value["PERMISSION_DENIED"]

// Action is an enumeration of actions a policy rule can take if it is matched.
type Action int

const (
	ALLOW Action = iota
	DENY
	LOG
	PASS
	NO_MATCH // Indicates policy did not match request. Cannot be assigned to rule.
)

// checkStore applies the policy in the given store and returns OK if the check passes, or PERMISSION_DENIED if the
// check fails. Note, if no policy matches, the default is PERMISSION_DENIED.
func checkStore(store *policystore.PolicyStore, req *authz.CheckRequest) (s status.Status) {
	s = status.Status{Code: PERMISSION_DENIED}
	ep := store.Endpoint
	if ep == nil {
		log.Warning("CheckRequest before we synced Endpoint information.")
		return
	}
	reqCache := NewRequestCache(store, req)
	err := reqCache.InitPeers()
	if err != nil {
		log.WithField("error", err).Error("Failed to Init() requestCache")
		return
	}
	if len(ep.Tiers) > 0 {
		// We only support a single tier.
		log.Debug("Checking policy tier 1.")

		tier := ep.Tiers[0]
		policies := tier.IngressPolicies
	Policy:
		for i, name := range policies {
			pID := proto.PolicyID{Tier: tier.GetName(), Name: name}
			policy := store.PolicyByID[pID]
			action := checkPolicy(policy, reqCache)
			log.WithFields(log.Fields{
				"ordinal":  i,
				"PolicyID": pID,
				"result":   action,
			}).Debug("Policy checked")
			switch action {
			case NO_MATCH:
				continue
			// If the Policy matches, end evaluation (skipping profiles, if any)
			case ALLOW:
				s.Code = OK
				return
			case DENY:
				s.Code = PERMISSION_DENIED
				return
			case PASS:
				// Pass means end evaluation of policies and proceed to profiles, if any.
				break Policy
			case LOG:
				panic("policy should never return LOG action")
			}
		}
	}
	// If we reach here, there were either no policies, or none that matched.
	if len(ep.ProfileIds) > 0 {
		for i, name := range ep.ProfileIds {
			pID := proto.ProfileID{Name: name}
			profile := store.ProfileByID[pID]
			action := checkProfile(profile, reqCache)
			log.WithFields(log.Fields{
				"ordinal":   i,
				"ProfileID": pID,
				"result":    action,
			}).Debug("Profile checked", i, name, action)
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
				panic("profile should never return LOG action")
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
	// Note that we support only inbound policy.
	return checkRules(policy.InboundRules, req)
}

func checkProfile(p *proto.Profile, req *requestCache) (action Action) {
	return checkRules(p.InboundRules, req)
}

func checkRules(rules []*proto.Rule, req *requestCache) (action Action) {
	for _, r := range rules {
		if match(r, req) {
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
	m := map[string]Action{
		"allow": ALLOW,
		"deny":  DENY,
		"pass":  PASS,
		"log":   LOG,
	}
	a, found := m[strings.ToLower(s)]
	if !found {
		log.Errorf("Got bad action %v", s)
		panic("got bad action")
	}
	return a
}
