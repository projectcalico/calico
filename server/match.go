package server

import (
	authz "tigera.io/dikastes/proto"

	"github.com/projectcalico/libcalico-go/lib/api"

	log "github.com/sirupsen/logrus"
)

// match checks if the Rule matches the request.  It returns true if the Rule matches, false otherwise.
func match(rule api.Rule, req *authz.Request) bool {
	log.Debugf("Checking rule %v on request %v", rule, req)
	return matchSubject(rule.Source, req.Subject) && matchAction(rule.Destination, req.Action)
}

func matchSubject(er api.EntityRule, subj *authz.Request_Subject) bool {
	return matchServiceAccounts(er.ServiceAccounts, subj.ServiceAccount, subj.Namespace)
}

func matchAction(er api.EntityRule, act *authz.Request_Action) bool {
	return true
}

func matchServiceAccounts(saMatch api.ServiceAccountMatch, accountName, namespace string) bool {
	log.WithFields(log.Fields{
		"account":   accountName,
		"namespace": namespace,
		"rule":      saMatch},
	).Debug("Matching service account.")
	return matchServiceAccountName(saMatch.Names, accountName) &&
		matchServiceAccountNamespace(saMatch.Namespace, namespace) &&
		matchServiceAccountLabels(saMatch.Selector, map[string]string{})
}

func matchServiceAccountName(names []string, name string) bool {
	if len(names) == 0 {
		log.Debug("No service account names on rule.")
		return true
	}
	for _, name2 := range names {
		if name2 == name {
			return true
		}
	}
	return false
}

func matchServiceAccountNamespace(matchNamespace, namespace string) bool {
	if matchNamespace == "" {
		log.Debug("No sercice account namespace in rule.")
		return true
	}
	return matchNamespace == namespace
}

func matchServiceAccountLabels(selector string, labels map[string]string) bool {
	return true
}
