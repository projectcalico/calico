package server

import (
	authz "tigera.io/dikastes/proto"

	"github.com/projectcalico/libcalico-go/lib/api"

	log "github.com/sirupsen/logrus"
)

const (
	ALLOW = "allow"
	DENY  = "deny"
	LOG   = "log"
	PASS  = "pass"
)

// Check a list of policies and return OK if the check passes, or PERMISSION_DENIED if the check fails.
// Note, if no policy matches, the default is PERMISSION_DENIED.
func checkPolicies(policies []api.Policy, req *authz.Request) (status authz.Response_Status_Code) {
	if len(policies) == 0 {
		log.Debug("0 active policies, allow request.")
		status = authz.OK
		return
	}
	// If there are active policies, the default is deny if no rules match.
	status = authz.PERMISSION_DENIED
	for i, p := range policies {
		action := checkPolicy(p.Spec, req)
		log.Debugf("Policy %d returned action %s", i, action)
		switch action {
		case PASS:
			continue
		case ALLOW:
			status = authz.OK
			break
		case LOG, DENY:
			status = authz.PERMISSION_DENIED
			break
		}
	}
	return
}

// checkPolicy checks if the policy matches the request data, and returns the action.
func checkPolicy(policy api.PolicySpec, req *authz.Request) (action string) {
	// Note that we support only Ingress policy for this prototype.
	for _, r := range policy.IngressRules {
		if match(r, req) {
			log.Debugf("Rule matched.")
			return r.Action
		}
	}
	// Default for unmatched policy is "pass"
	return PASS
}
