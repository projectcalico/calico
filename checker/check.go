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
	authz "github.com/envoyproxy/data-plane-api/api/auth"

	"github.com/projectcalico/app-policy/policystore"

	"github.com/projectcalico/app-policy/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
	"strings"
)

var OK = code.Code_value["OK"]
var PERMISSION_DENIED = code.Code_value["PERMISSION_DENIED"]

type Action int

const (
	ALLOW Action = iota
	DENY
	LOG
	PASS
)

// Check a list of policies and return OK if the check passes, or PERMISSION_DENIED if the check fails.
// Note, if no policy matches, the default is PERMISSION_DENIED.
func checkStore(store *policystore.PolicyStore, req *authz.CheckRequest) (s status.Status) {
	s = status.Status{}
	ep := store.Endpoint
	if ep == nil {
		log.Warning("CheckRequest before we synced Endpoint information.")
		s.Code = PERMISSION_DENIED
		return
	}
	if len(ep.Tiers) > 0 {
		log.Debug("Checking policy tier 1.") // We only support a single tier.

		tier := ep.Tiers[0]
		policies := tier.IngressPolicies
		if len(policies) == 0 {
			log.Debug("0 active policies, allow request.")
			s.Code = OK
		} else {
			// If there are active policies, the default is deny if no rules match.
			s.Code = PERMISSION_DENIED
		}
		for i, name := range policies {
			pID := proto.PolicyID{Tier: tier.GetName(), Name: name}
			policy := store.PolicyByID[pID]
			action := checkPolicy(policy, req)
			log.Debugf("Policy %d %v returned action %s", i, pID, action)
			switch action {
			case PASS:
				continue
			case ALLOW:
				s.Code = OK
				break
			case LOG, DENY:
				s.Code = PERMISSION_DENIED
				break
			}
		}
	}
	return
}

// checkPolicy checks if the policy matches the request data, and returns the action.
func checkPolicy(policy *proto.Policy, req *authz.CheckRequest) (action Action) {
	// Note that we support only inbound policy.
	for _, r := range policy.InboundRules {
		if match(r, req) {
			log.Debugf("Rule matched.")
			return ActionFromString(r.Action)
		}
	}
	// Default for unmatched policy is "pass"
	return PASS
}

func ActionFromString(s string) Action {
	m := map[string]Action{
		"allow": ALLOW,
		"deny":  DENY,
		"pass":  PASS,
		"log":   LOG,
	}
	a, found := m[strings.ToLower(s)]
	if !found {
		log.Fatalf("Got bad action %v", s)
	}
	return a
}
