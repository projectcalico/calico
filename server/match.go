package server

import (
	"tigera.io/dikastes/proto"

	"github.com/projectcalico/libcalico-go/lib/api"

	log "github.com/sirupsen/logrus"
)

// match checks if the Rule matches the request.  It returns true if the Rule matches, false otherwise.
func match(rule api.Rule, req *authz.Request) bool {
	log.Debugf("Checking rule %v on request %v", rule, req)
	return matchSubject(rule.Source, req.Subject) && matchAction(rule.Destination, req.Action)
}

func matchSubject(er api.EntityRule, subj *authz.Request_Subject) bool {
	return matchServiceAccounts(er, subj.ServiceAccount, subj.Namespace)
}

func matchAction(er api.EntityRule, act *authz.Request_Action) bool {
	return true
}

func matchServiceAccounts(er api.EntityRule, accountName string, namespace string) bool {
	log.WithFields(log.Fields{
		"subject_account":   accountName,
		"subject_namespace": namespace,
		"rule":              er.ServiceAccounts},
	).Debug("Matching service account.")

	if len(er.ServiceAccounts) == 0 {
		log.Debug("No service accounts on rule.")
		return true
	}

	// Service accounts in the rule are in the format <namespace>:<accountName>
	both := namespace + ":" + accountName
	for _, sa2 := range er.ServiceAccounts {
		if sa2 == both {
			return true
		}
	}
	return false
}
