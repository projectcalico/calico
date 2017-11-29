package server

import (
	authz "github.com/projectcalico/app-policy/proto"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"

	log "github.com/sirupsen/logrus"
)

// Check a list of policies and return OK if the check passes, or PERMISSION_DENIED if the check fails.
// Note, if no policy matches, the default is PERMISSION_DENIED.
func checkPolicies(policies []api.GlobalNetworkPolicy, req *authz.Request) (status authz.Response_Status_Code) {
	if len(policies) == 0 {
		log.Debug("0 active policies, allow request.")
		status = authz.Response_Status_OK
		return
	}
	// If there are active policies, the default is deny if no rules match.
	status = authz.Response_Status_PERMISSION_DENIED
	for i, p := range policies {
		action := checkPolicy(p.Spec, req)
		log.Debugf("Policy %d returned action %s", i, action)
		switch action {
		case api.Pass:
			continue
		case api.Allow:
			status = authz.Response_Status_OK
			break
		case api.Log, api.Deny:
			status = authz.Response_Status_PERMISSION_DENIED
			break
		}
	}
	return
}

// checkPolicy checks if the policy matches the request data, and returns the action.
func checkPolicy(policy api.GlobalNetworkPolicySpec, req *authz.Request) (action api.Action) {
	// Note that we support only Ingress policy for this prototype.
	for _, r := range policy.Ingress {
		if match(r, req) {
			log.Debugf("Rule matched.")
			return r.Action
		}
	}
	// Default for unmatched policy is "pass"
	return api.Pass
}
