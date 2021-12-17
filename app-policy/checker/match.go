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
	"net"
	"strings"

	"github.com/projectcalico/calico/app-policy/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"

	"fmt"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	log "github.com/sirupsen/logrus"
)

var (
	// Envoy supports TCP only. Add a k:v into this map if more protocol is supported in the future.
	protocolMapL4 = map[int32]string{6: "tcp"}
)

type namespaceMatch struct {
	Names    []string
	Selector string
}

// InvalidDataFromDataPlane is an error is used when we get data from
// dataplane (Envoy) which is invalid.
type InvalidDataFromDataPlane struct {
	string
}

func (i *InvalidDataFromDataPlane) Error() string {
	return "Invalid data from dataplane " + i.string
}

// match checks if the Rule matches the request.  It returns true if the Rule matches, false otherwise.
func match(rule *proto.Rule, req *requestCache, policyNamespace string) bool {
	log.WithFields(log.Fields{
		"rule":            rule,
		"Req.Method":      req.Request.GetAttributes().GetRequest().GetHttp().GetMethod(),
		"Req.Path":        req.Request.GetAttributes().GetRequest().GetHttp().GetPath(),
		"Req.Protocol":    req.Request.GetAttributes().GetRequest().GetHttp().GetProtocol(),
		"Req.Source":      req.Request.GetAttributes().GetSource(),
		"Req.Destination": req.Request.GetAttributes().GetDestination(),
	}).Debug("Checking rule on request")
	attr := req.Request.GetAttributes()
	return matchSource(rule, req, policyNamespace) &&
		matchDestination(rule, req, policyNamespace) &&
		matchRequest(rule, attr.GetRequest()) &&
		matchL4Protocol(rule, attr.GetDestination())
}

func matchSource(r *proto.Rule, req *requestCache, policyNamespace string) bool {
	nsMatch := computeNamespaceMatch(
		policyNamespace,
		r.GetOriginalSrcNamespaceSelector(),
		r.GetOriginalSrcSelector(),
		r.GetOriginalNotSrcSelector(),
		r.GetSrcServiceAccountMatch())
	addr := req.Request.GetAttributes().GetSource().GetAddress()
	return matchServiceAccounts(r.GetSrcServiceAccountMatch(), req.SourcePeer()) &&
		matchNamespace(nsMatch, req.SourceNamespace()) &&
		matchSrcIPSets(r, req) &&
		matchPort("src", r.GetSrcPorts(), r.GetSrcNamedPortIpSetIds(), req, addr) &&
		matchNet("src", r.GetSrcNet(), addr)
}

func computeNamespaceMatch(
	policyNamespace, nsSelector, podSelector, notPodSelector string, saMatch *proto.ServiceAccountMatch,
) *namespaceMatch {
	nsMatch := &namespaceMatch{}
	if nsSelector != "" {
		// In all cases, if a namespace label selector is present, it takes precedence.
		nsMatch.Selector = nsSelector
	} else {
		// NetworkPolicies have `policyNamespace` set, GlobalNetworkPolicy and Profiles have it set to empty string.
		// If this is a NetworkPolicy and there is pod label selector (or not selector) or service account match, then
		// we must only accept connections from this namespace.  GlobalNetworkPolicy, Profile, or those without a pod
		// selector/service account match can match any namespace.
		if policyNamespace != "" &&
			(podSelector != "" ||
				notPodSelector != "" ||
				len(saMatch.GetNames()) != 0 ||
				saMatch.GetSelector() != "") {
			nsMatch.Names = []string{policyNamespace}
		}
	}
	return nsMatch
}

func matchDestination(r *proto.Rule, req *requestCache, policyNamespace string) bool {
	nsMatch := computeNamespaceMatch(
		policyNamespace,
		r.GetOriginalDstNamespaceSelector(),
		r.GetOriginalDstSelector(),
		r.GetOriginalNotDstSelector(),
		r.GetDstServiceAccountMatch())
	addr := req.Request.GetAttributes().GetDestination().GetAddress()
	return matchServiceAccounts(r.GetDstServiceAccountMatch(), req.DestinationPeer()) &&
		matchNamespace(nsMatch, req.DestinationNamespace()) &&
		matchDstIPSets(r, req) &&
		matchPort("dst", r.GetDstPorts(), r.GetDstNamedPortIpSetIds(), req, addr) &&
		matchNet("dst", r.GetDstNet(), addr)
}

func matchRequest(rule *proto.Rule, req *authz.AttributeContext_Request) bool {
	log.WithField("request", req).Debug("Matching request.")
	return matchHTTP(rule.GetHttpMatch(), req.GetHttp())
}

func matchServiceAccounts(saMatch *proto.ServiceAccountMatch, p peer) bool {
	log.WithFields(log.Fields{
		"name":      p.Name,
		"namespace": p.Namespace,
		"labels":    p.Labels,
		"rule":      saMatch},
	).Debug("Matching service account.")
	if saMatch == nil {
		log.Debug("nil ServiceAccountMatch.  Return true.")
		return true
	}
	// In case of plain text, Dikastes falls back on IP addresses. In such a case
	// service account is empty as there is no such information in the authorization header.
	// In case of plain text so Dikastes only matches if the IP addresses are part of
	// IP sets of a policy rule. So empty service account is considered a match in such a case.
	return p.Name == "" ||
		(matchName(saMatch.GetNames(), p.Name) &&
			matchLabels(saMatch.GetSelector(), p.Labels))
}

func matchName(names []string, name string) bool {
	log.WithFields(log.Fields{
		"names": names,
		"name":  name,
	}).Debug("Matching name")
	if len(names) == 0 {
		log.Debug("No names on rule.")
		return true
	}
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func matchLabels(selectorStr string, labels map[string]string) bool {
	log.WithFields(log.Fields{
		"selector": selectorStr,
		"labels":   labels,
	}).Debug("Matching labels.")
	sel, err := selector.Parse(selectorStr)
	if err != nil {
		log.Warnf("Could not parse label selector %v, %v", selectorStr, err)
		return false
	}
	log.Debugf("Parsed selector.")
	return sel.Evaluate(labels)
}

func matchNamespace(nsMatch *namespaceMatch, ns namespace) bool {
	log.WithFields(log.Fields{
		"namespace": ns.Name,
		"labels":    ns.Labels,
		"rule":      nsMatch},
	).Debug("Matching namespace.")
	// In case of plain text, Dikastes falls back on IP addresses. In such a case
	// namespace is empty as there is no such information in the authorization header.
	// In case of plain text so Dikastes only matches if the IP addresses are part of
	// IP sets of a policy rule. So empty namespace is considered a match in such a case.
	return ns.Name == "" ||
		(matchName(nsMatch.Names, ns.Name) &&
			matchLabels(nsMatch.Selector, ns.Labels))
}

func matchHTTP(rule *proto.HTTPMatch, req *authz.AttributeContext_HttpRequest) bool {
	log.WithFields(log.Fields{
		"rule": rule,
	}).Debug("Matching HTTP.")
	if rule == nil {
		log.Debug("nil HTTPRule.  Return true")
		return true
	}
	return matchHTTPMethods(rule.GetMethods(), req.GetMethod()) && matchHTTPPaths(rule.GetPaths(), req.GetPath())
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

func matchHTTPPaths(paths []*proto.HTTPMatch_PathMatch, reqPath string) bool {
	log.WithFields(log.Fields{
		"paths":   paths,
		"reqPath": reqPath,
	}).Debug("Matching HTTP Paths")
	if len(paths) == 0 {
		log.Debug("Rule has 0 HTTP Paths, matched.")
		return true
	}
	// Accept only valid paths
	if !strings.HasPrefix(reqPath, "/") {
		s := fmt.Sprintf("Invalid HTTP Path \"%s\"", reqPath)
		log.Error(s)
		// Let the caller recover from the panic.
		panic(&InvalidDataFromDataPlane{s})
	}
	// Strip out the query '?' and fragment '#' identifier
	for _, s := range []string{"?", "#"} {
		reqPath = strings.Split(reqPath, s)[0]
	}
	for _, pathMatch := range paths {
		switch pathMatch.GetPathMatch().(type) {
		case *proto.HTTPMatch_PathMatch_Exact:
			if reqPath == pathMatch.GetExact() {
				log.Debug("HTTP Path exact matched.")
				return true
			}
		case *proto.HTTPMatch_PathMatch_Prefix:
			if strings.HasPrefix(reqPath, pathMatch.GetPrefix()) {
				log.Debugf("HTTP Path prefix %s matched.", pathMatch.GetPrefix())
				return true
			}
		}
	}
	log.Debug("HTTP Path not matched.")
	return false
}

func matchSrcIPSets(r *proto.Rule, req *requestCache) bool {
	log.WithFields(log.Fields{
		"SrcIpSetIds":    r.SrcIpSetIds,
		"NotSrcIpSetIds": r.NotSrcIpSetIds,
	}).Debug("matching source IP sets")
	addr := req.Request.GetAttributes().GetSource().GetAddress()
	return matchIPSetsAll(r.SrcIpSetIds, req, addr) &&
		matchIPSetsNotAny(r.NotSrcIpSetIds, req, addr)
}

func matchDstIPSets(r *proto.Rule, req *requestCache) bool {
	log.WithFields(log.Fields{
		"DstIpSetIds":    r.DstIpSetIds,
		"NotDstIpSetIds": r.NotDstIpSetIds,
	}).Debug("matching destination IP sets")
	addr := req.Request.GetAttributes().GetDestination().GetAddress()
	return matchIPSetsAll(r.DstIpSetIds, req, addr) &&
		matchIPSetsNotAny(r.NotDstIpSetIds, req, addr)
}

// matchIPSetsAll returns true if the address matches all of the IP set ids, false otherwise.
func matchIPSetsAll(ids []string, req *requestCache, addr *core.Address) bool {
	for _, id := range ids {
		s := req.GetIPSet(id)
		if !s.ContainsAddress(addr) {
			return false
		}
	}
	return true
}

// matchIPSetsNotAny returns true if the address does not match any of the ipset ids, false otherwise.
func matchIPSetsNotAny(ids []string, req *requestCache, addr *core.Address) bool {
	for _, id := range ids {
		s := req.GetIPSet(id)
		if s.ContainsAddress(addr) {
			return false
		}
	}
	return true
}

func matchPort(dir string, ranges []*proto.PortRange, namedPortSets []string, req *requestCache, addr *core.Address) bool {
	log.WithFields(log.Fields{
		"ranges":        ranges,
		"namedPortSets": namedPortSets,
		"addr":          addr,
		"dir":           dir,
	}).Debug("matching port")
	if len(ranges) == 0 && len(namedPortSets) == 0 {
		return true
	}
	p := int32(addr.GetSocketAddress().GetPortValue())
	for _, r := range ranges {
		if r.GetFirst() <= p && p <= r.GetLast() {
			return true
		}
	}
	for _, id := range namedPortSets {
		s := req.GetIPSet(id)
		if s.ContainsAddress(addr) {
			return true
		}
	}
	return false
}

func matchNet(dir string, nets []string, addr *core.Address) bool {
	log.WithFields(log.Fields{
		"nets": nets,
		"addr": addr,
		"dir":  dir,
	}).Debug("matching net")
	if len(nets) == 0 {
		return true
	}
	ip := net.ParseIP(addr.GetSocketAddress().GetAddress())
	if ip == nil {
		// Envoy should not send us malformed IP addresses, but its possible we could get requests from non-IP
		// connections, like Pipes.
		log.WithField("ip", addr.GetSocketAddress().GetAddress()).Warn("unable to parse IP")
		return false
	}
	for _, n := range nets {
		_, ipn, err := net.ParseCIDR(n)
		if err != nil {
			// Don't match CIDRs if they are malformed. This case should generally be weeded out by validation earlier
			// in processing before it gets to Dikastes.
			log.WithField("cidr", n).Warn("unable to parse CIDR")
			return false
		}
		if ipn.Contains(ip) {
			return true
		}
	}
	return false
}

func matchL4Protocol(rule *proto.Rule, dest *authz.AttributeContext_Peer) bool {
	// Extract L4 protocol type of socket address for destination peer context. Match against rules.
	if dest == nil {
		log.Warn("Matching L4 protocol. nil request destination peer.")
		return false
	}

	// Default protocol is TCP. Convert to lowercase.
	reqProtocol := strings.ToLower(dest.GetAddress().GetSocketAddress().GetProtocol().String())
	log.WithFields(log.Fields{
		"isProtocol":      rule.GetProtocol(),
		"isNotProtocol":   rule.NotProtocol,
		"requestProtocol": reqProtocol,
	}).Debug("Matching L4 protocol")

	checkStringInRuleProtocol := func(p *proto.Protocol, s string, defaultResult bool) bool {
		if p == nil {
			return defaultResult
		}

		// Check if given protocol string matches what is specified in rule.
		// Note we compare names in lowercase.
		if name := p.GetName(); name != "" {
			return strings.ToLower(name) == s
		}

		if name, ok := protocolMapL4[p.GetNumber()]; ok {
			return name == s
		}

		return false
	}

	return checkStringInRuleProtocol(rule.GetProtocol(), reqProtocol, true) &&
		!checkStringInRuleProtocol(rule.GetNotProtocol(), reqProtocol, false)
}
