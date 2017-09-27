package server

import (
	authz "tigera.io/dikastes/proto"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/selector"

	log "github.com/sirupsen/logrus"
)

// match checks if the Rule matches the request.  It returns true if the Rule matches, false otherwise.
func match(rule api.Rule, req *authz.Request) bool {
	log.Debugf("Checking rule %v on request %v", rule, req)
	return matchSubject(rule.Source, req.Subject) && matchAction(rule.Destination, req.Action)
}

func matchSubject(er api.EntityRule, subj *authz.Request_Subject) bool {
	return matchServiceAccounts(er.ServiceAccounts, subj)
}

func matchAction(er api.EntityRule, act *authz.Request_Action) bool {
	return true
}

func matchServiceAccounts(saMatch api.ServiceAccountMatch, subj *authz.Request_Subject) bool {
	accountName := subj.ServiceAccount
	namespace := subj.Namespace
	labels := subj.ServiceAccountLabels
	log.WithFields(log.Fields{
		"account":   accountName,
		"namespace": namespace,
		"labels":    labels,
		"rule":      saMatch},
	).Debug("Matching service account.")
	return matchServiceAccountName(saMatch.Names, accountName) &&
		matchServiceAccountNamespace(saMatch.Namespace, namespace) &&
		matchServiceAccountLabels(saMatch.Selector, labels)
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

func matchServiceAccountLabels(selectorStr string, labels map[string]string) bool {
	log.WithFields(log.Fields{
		"selector": selectorStr,
		"labels":   labels,
	}).Debug("Matching service account labels.")
	sel, err := selector.Parse(selectorStr)
	if err != nil {
		log.Warnf("Could not parse policy selector %v, %v", selectorStr, err)
		return false
	}
	log.Debugf("Parsed selector.", sel)
	return sel.Evaluate(labels)

}
