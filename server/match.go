package server

import (
	authz "tigera.io/dikastes/proto"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/selector"

	log "github.com/sirupsen/logrus"
)

// match checks if the Rule matches the request.  It returns true if the Rule matches, false otherwise.
func match(rule api.Rule, req *authz.Request) bool {
	log.Debugf("Checking rule %v on request %v", rule, req)
	return matchSubject(rule.Source, req.GetSubject()) && matchAction(rule, req.GetAction())
}

func matchSubject(er api.EntityRule, subj *authz.Request_Subject) bool {
	return matchServiceAccounts(er.ServiceAccounts, subj)
}

func matchAction(rule api.Rule, act *authz.Request_Action) bool {
	log.WithFields(log.Fields{
		"action": act,
	}).Debug("Matching action.")
	return matchHTTP(rule.HTTP, act.GetHttp())
}

func matchServiceAccounts(saMatch *api.ServiceAccountMatch, subj *authz.Request_Subject) bool {
	accountName := subj.GetServiceAccount()
	namespace := subj.GetNamespace()
	labels := subj.GetServiceAccountLabels()
	log.WithFields(log.Fields{
		"account":   accountName,
		"namespace": namespace,
		"labels":    labels,
		"rule":      saMatch},
	).Debug("Matching service account.")
	return matchServiceAccountName(saMatch.Names, accountName) &&
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

func matchHTTP(rule api.HTTPRule, req *authz.HTTPRequest) bool {
	return matchHTTPMethods(rule.Methods, req.GetMethod())
}

func matchHTTPMethods(methods []string, reqMethod string) bool {
	log.WithFields(log.Fields{
		"methods":   methods,
		"reqMethod": reqMethod,
	}).Debug("Matching HTTP Methods")
	if len(methods) == 0 {
		log.Debug("Rule has 0 HTTP Methods, matched.")
		return true
	}
	for _, method := range methods {
		if method == "*" {
			log.Debug("Rule matches all methods with wildcard *")
			return true
		}
		if method == reqMethod {
			log.Debug("HTTP Method matched.")
			return true
		}
	}
	log.Debug("HTTP Method not matched.")
	return false
}
