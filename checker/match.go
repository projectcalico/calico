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
	"github.com/projectcalico/app-policy/proto"
	"github.com/projectcalico/libcalico-go/lib/selector"

	authz "github.com/envoyproxy/data-plane-api/api/auth"
	log "github.com/sirupsen/logrus"
)

// match checks if the Rule matches the request.  It returns true if the Rule matches, false otherwise.
func match(rule *proto.Rule, req *requestCache) bool {
	log.Debugf("Checking rule %v on request %v", rule, req)
	attr := req.Request.GetAttributes()
	return matchSource(rule, req) && matchRequest(rule, attr.GetRequest())
}

func matchSource(r *proto.Rule, req *requestCache) bool {
	// TODO IPSets
	return matchServiceAccounts(r.GetSrcServiceAccountMatch(), req.Source())
}

func matchRequest(rule *proto.Rule, req *authz.AttributeContext_Request) bool {
	log.WithField("request", req).Debug("Matching request.")
	return matchHTTP(rule.GetHttpMatch(), req.GetHttp())
}

func matchServiceAccounts(saMatch *proto.ServiceAccountMatch, peer Peer) bool {
	log.WithFields(log.Fields{
		"name":      peer.Name,
		"namespace": peer.Namespace,
		"labels":    peer.Labels,
		"rule":      saMatch},
	).Debug("Matching service account.")
	if saMatch == nil {
		log.Debug("nil ServiceAccountMatch.  Return true.")
		return true
	}
	return matchServiceAccountName(saMatch.GetNames(), peer.Name) &&
		matchServiceAccountLabels(saMatch.GetSelector(), peer.Labels)
}

func matchServiceAccountName(names []string, name string) bool {
	log.WithFields(log.Fields{
		"names": names,
		"name":  name,
	}).Debug("Matching service account name")
	if len(names) == 0 {
		log.Debug("No service account names on rule.")
		return true
	}
	for _, n := range names {
		if n == name {
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

func matchHTTP(rule *proto.HTTPMatch, req *authz.AttributeContext_HTTPRequest) bool {
	log.WithFields(log.Fields{
		"rule": rule,
	}).Debug("Matching HTTP.")
	if rule == nil {
		log.Debug("nil HTTPRule.  Return true")
		return true
	}
	return matchHTTPMethods(rule.GetMethods(), req.GetMethod())
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
