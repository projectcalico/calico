// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

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
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

var protocolMapL4 = map[int32]string{
	1:  "icmp",
	6:  "tcp",
	17: "udp",
}

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

// L4Flow abstracts the common l4 data and behavior needed for the match algorithms.
type L4Flow interface {
	GetSourceIP() net.IP
	GetDestIP() net.IP
	GetSourcePort() int
	GetDestPort() int
	GetProtocol() int
}

// L7Flow abstracts the common l7 data and behavior needed for the match algorithms.
type L7Flow interface {
	GetHttpMethod() *string
	GetHttpPath() *string
	GetSourcePrincipal() *string
	GetDestPrincipal() *string
	GetSourceLabels() map[string]string
	GetDestLabels() map[string]string
}

// flow abstracts the common data and behavior needed for the match algorithms.
//go:generate mockery --name=Flow --output=mocks --outpkg=mocks

type Flow interface {
	L4Flow
	L7Flow
}

// match checks if the Rule matches the request. It returns true if the Rule matches, false otherwise.
func match(policyNamespace string, rule *proto.Rule, req *requestCache) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"rule":       rule,
			"Protocol":   req.GetProtocol(),
			"SourceIP":   req.GetSourceIP(),
			"DestIP":     req.GetDestIP(),
			"SourcePort": req.GetSourcePort(),
			"DestPort":   req.GetDestPort(),
			"HttpMethod": req.GetHttpMethod(),
			"HttpPath":   req.GetHttpPath(),
		}).Debug("Checking rule on request")
	}
	return matchSource(policyNamespace, rule, req) &&
		matchDestination(policyNamespace, rule, req) &&
		matchRequest(rule, req) &&
		matchL4Protocol(rule, int32(req.GetProtocol()))
}

// matchSource checks if the source part of the Rule matches the request. It returns true if the
// Rule matches, false otherwise.
func matchSource(policyNamespace string, r *proto.Rule, req *requestCache) bool {
	nsMatch := computeNamespaceMatch(
		policyNamespace,
		r.GetOriginalSrcNamespaceSelector(),
		r.GetOriginalSrcSelector(),
		r.GetOriginalNotSrcSelector(),
		r.GetSrcServiceAccountMatch())

	return matchServiceAccounts(r.GetSrcServiceAccountMatch(), req.getSrcPeer()) &&
		matchNamespace(nsMatch, req.getSrcNamespace()) &&
		matchSrcIPSets(r, req) &&
		matchSrcPort(r, req) &&
		matchSrcNet(r, req)
}

// matchDestination checks if the destination part of the Rule matches the request. It returns true if the
// Rule matches, false otherwise.
func matchDestination(policyNamespace string, r *proto.Rule, req *requestCache) bool {
	nsMatch := computeNamespaceMatch(
		policyNamespace,
		r.GetOriginalDstNamespaceSelector(),
		r.GetOriginalDstSelector(),
		r.GetOriginalNotDstSelector(),
		r.GetDstServiceAccountMatch())

	return matchServiceAccounts(r.GetDstServiceAccountMatch(), req.getDstPeer()) &&
		matchNamespace(nsMatch, req.getDstNamespace()) &&
		matchDstIPSets(r, req) &&
		matchDstIPPortSetIds(r, req) &&
		matchDstPort(r, req) &&
		matchDstNet(r, req)
}

// computeNamespaceMatch computes the namespace match based on the policyNamespace, namespace
// selector, pod selector,
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

// matchRequest checks if the request part of the Rule matches the request. It returns true if the
// Rule matches, false otherwise.
func matchRequest(rule *proto.Rule, req *requestCache) bool {
	log.WithField("request", req).Debug("Matching request.")
	return matchHTTP(rule.GetHttpMatch(), req.GetHttpMethod(), req.GetHttpPath())
}

// matchServiceAccounts checks if the service account part of the Rule matches the request. It
// returns true if the Rule matches, false otherwise.
func matchServiceAccounts(saMatch *proto.ServiceAccountMatch, p *peer) bool {
	if p == nil {
		log.Debug("nil peer. Return true")
		return true
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"name":      p.Name,
			"namespace": p.Namespace,
			"labels":    p.Labels,
			"rule":      saMatch},
		).Debug("Matching service account.")
	}
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

// matchName checks if the name matches the names. It returns true if the name matches, false
// otherwise.
func matchName(names []string, name string) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"names": names,
			"name":  name,
		}).Debug("Matching name")
	}
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

// matchLabels checks if the selector matches the labels. It returns true if the selector matches,
// false otherwise.
func matchLabels(selectorStr string, labels map[string]string) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"selector": selectorStr,
			"labels":   labels,
		}).Debug("Matching labels")
	}
	sel, err := selector.Parse(selectorStr)
	if err != nil {
		log.Warnf("Could not parse label selector %v, %v", selectorStr, err)
		return false
	}
	log.Debugf("Parsed selector.")
	return sel.Evaluate(labels)
}

// matchNamespace checks if the namespace part of the Rule matches the request. It returns true if
// the Rule matches, false otherwise.
func matchNamespace(nsMatch *namespaceMatch, ns *namespace) bool {
	if ns == nil {
		log.Debug("nil namespace. Return true")
		return true
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"namespace": ns.Name,
			"labels":    ns.Labels,
			"rule":      nsMatch},
		).Debug("Matching namespace.")
	}
	// In case of plain text, Dikastes falls back on IP addresses. In such a case
	// namespace is empty as there is no such information in the authorization header.
	// In case of plain text so Dikastes only matches if the IP addresses are part of
	// IP sets of a policy rule. So empty namespace is considered a match in such a case.
	return ns.Name == "" ||
		(matchName(nsMatch.Names, ns.Name) &&
			matchLabels(nsMatch.Selector, ns.Labels))
}

// matchHTTP checks if the HTTP part of the Rule matches the request. It returns true if the Rule
// matches, false otherwise.
func matchHTTP(rule *proto.HTTPMatch, httpMethod, httpPath *string) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"rule": rule,
		}).Debug("Matching HTTP.")
	}
	if rule == nil {
		log.Debug("nil HTTPRule. Return true")
		return true
	}

	return matchHTTPMethods(rule.GetMethods(), httpMethod) && matchHTTPPaths(rule.GetPaths(), httpPath)
}

// matchHTTPMethods checks if the HTTP methods match. It returns true if the methods match, false
// otherwise.
func matchHTTPMethods(methods []string, reqMethod *string) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"methods":   methods,
			"reqMethod": reqMethod,
		}).Debug("Matching HTTP Methods")
	}
	if reqMethod == nil {
		log.Debug("Request has nil HTTP Method.")
		return true
	}
	if len(methods) == 0 {
		log.Debug("Rule has 0 HTTP Methods, matched.")
		return true
	}

	for _, method := range methods {
		if method == "*" {
			log.Debug("Rule matches all methods with wildcard *")
			return true
		}
		if method == *reqMethod {
			log.Debug("HTTP Method matched.")
			return true
		}
	}
	log.Debug("HTTP Method not matched.")
	return false
}

// matchHTTPPaths checks if the HTTP paths match. It returns true if the paths match, false
// otherwise.
func matchHTTPPaths(paths []*proto.HTTPMatch_PathMatch, reqPath *string) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"paths":   paths,
			"reqPath": reqPath,
		}).Debug("Matching HTTP Paths")
	}
	if len(paths) == 0 {
		log.Debug("Rule has 0 HTTP Paths, matched.")
		return true
	}
	if reqPath == nil {
		log.Debug("nil HTTP Path. Default is /")
		return true
	}
	// Accept only valid paths
	if !strings.HasPrefix(*reqPath, "/") {
		s := fmt.Sprintf("Invalid HTTP Path \"%s\"", *reqPath)
		log.Error(s)
		// Let the caller recover from the panic.
		panic(&InvalidDataFromDataPlane{s})
	}
	// Strip out the query '?' and fragment '#' identifier
	for _, s := range []string{"?", "#"} {
		*reqPath = strings.Split(*reqPath, s)[0]
	}
	for _, pathMatch := range paths {
		switch pathMatch.GetPathMatch().(type) {
		case *proto.HTTPMatch_PathMatch_Exact:
			if *reqPath == pathMatch.GetExact() {
				log.Debug("HTTP Path exact matched.")
				return true
			}
		case *proto.HTTPMatch_PathMatch_Prefix:
			if strings.HasPrefix(*reqPath, pathMatch.GetPrefix()) {
				log.Debugf("HTTP Path prefix %s matched.", pathMatch.GetPrefix())
				return true
			}
		}
	}
	log.Debug("HTTP Path not matched.")
	return false
}

// matchSrcIPSets checks if the source IP is within the IP sets and not in the not IP sets. It
// returns true if the IP sets match, false otherwise.
func matchSrcIPSets(r *proto.Rule, req *requestCache) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"SrcIpSetIds":    r.SrcIpSetIds,
			"NotSrcIpSetIds": r.NotSrcIpSetIds,
		}).Debug("matching source IP sets")
	}
	return matchIPSetsAll(r.SrcIpSetIds, req.getIPSet, req.GetSourceIP().String()) &&
		matchIPSetsNotAny(r.NotSrcIpSetIds, req.getIPSet, req.GetSourceIP().String())
}

// matchDstIPPortSetIds checks if the destination IP, protocol and port is within the IP sets. It
// returns true if the IP sets match, false otherwise. There is no notDstIPPortSetIds.
func matchDstIPPortSetIds(r *proto.Rule, req *requestCache) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"DstIpPortSetIds": r.GetDstIpPortSetIds(),
		}).Debug("matching destination IP port sets")
	}
	protocolStr := protocolMapL4[int32(req.GetProtocol())]
	// The values compared against are of the for "ip,protocol:port".
	ipProtoPort := fmt.Sprintf("%s,%s:%d", req.GetDestIP(), protocolStr, req.GetDestPort())
	return matchIPSetsAll(r.GetDstIpPortSetIds(), req.getIPSet, ipProtoPort)
}

// matchDstIPSets checks if the destination IP is within the IP sets and not in the not IP sets. It
// returns true if the IP sets match, false otherwise.
func matchDstIPSets(r *proto.Rule, req *requestCache) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"DstIpSetIds":    r.GetDstIpSetIds(),
			"NotDstIpSetIds": r.GetNotDstIpSetIds(),
		}).Debug("matching destination IP sets")
	}
	return matchIPSetsAll(r.GetDstIpSetIds(), req.getIPSet, req.GetDestIP().String()) &&
		matchIPSetsNotAny(r.GetNotDstIpSetIds(), req.getIPSet, req.GetDestIP().String())
}

// matchIPSetsAll returns true if the address matches all of the IP set ids, false otherwise.
// The value is either an IP address or an IP address protocol and port.
func matchIPSetsAll(ids []string, ipsSetFunc func(string) policystore.IPSet, value string) bool {
	for _, id := range ids {
		if s := ipsSetFunc(id); s != nil && !s.Contains(value) {
			return false
		}
	}
	return true
}

// matchIPSetsNotAny returns true if the address does not match any of the ipset ids, false
// otherwise. The value is either an IP address or an IP address protocol and port.

func matchIPSetsNotAny(ids []string, ipsSetFunc func(string) policystore.IPSet, value string) bool {
	for _, id := range ids {
		if s := ipsSetFunc(id); s != nil && s.Contains(value) {
			return false
		}
	}
	return true
}

// matchDstPort checks if the destination port is within the port ranges and named port sets. It
// also checks if the destination port is not within the not port ranges and named port sets.
func matchDstPort(r *proto.Rule, req *requestCache) bool {
	return matchPort("dst", r.GetDstPorts(), r.GetDstNamedPortIpSetIds(), req.getIPSet, req.GetDestPort()) &&
		matchNotPort("dst", r.GetNotDstPorts(), r.GetNotDstNamedPortIpSetIds(), req.getIPSet, req.GetDestPort())
}

// matchSrcPort checks if the source port is within the port ranges and named port sets. It also
// checks if the source port is not within the not port ranges and named port sets.
func matchSrcPort(r *proto.Rule, req *requestCache) bool {
	return matchPort("src", r.GetSrcPorts(), r.GetSrcNamedPortIpSetIds(), req.getIPSet, req.GetSourcePort()) &&
		matchNotPort("src", r.GetNotSrcPorts(), r.GetNotSrcNamedPortIpSetIds(), req.getIPSet, req.GetSourcePort())
}

// matchPort checks if the port is within the port ranges and named port sets. It returns true if
// the port matches, false otherwise.
func matchPort(dir string, ranges []*proto.PortRange, namedPortSets []string, ipsSetFunc func(string) policystore.IPSet, port int) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"ranges":        ranges,
			"namedPortSets": namedPortSets,
			"port":          port,
			"dir":           dir,
		}).Debug("matching port")
	}
	if len(ranges) == 0 && len(namedPortSets) == 0 {
		return true
	}
	p := int32(port)
	for _, r := range ranges {
		if r.GetFirst() <= p && p <= r.GetLast() {
			return true
		}
	}
	for _, id := range namedPortSets {
		portStr := fmt.Sprintf("%d", port)
		if s := ipsSetFunc(id); s != nil && s.Contains(portStr) {
			return true
		}
	}
	return false
}

// matchNotPort checks if the port is not within the port ranges and named port sets. It returns
// true if the port matches, false otherwise.
func matchNotPort(dir string, ranges []*proto.PortRange, namedPortSets []string, ipsSetFunc func(string) policystore.IPSet, port int) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"ranges":        ranges,
			"namedPortSets": namedPortSets,
			"port":          port,
			"dir":           dir,
		}).Debug("matching port")
	}
	if len(ranges) == 0 && len(namedPortSets) == 0 {
		return true
	}
	p := int32(port)
	for _, r := range ranges {
		if r.GetFirst() <= p && p <= r.GetLast() {
			return false
		}
	}
	for _, id := range namedPortSets {
		portStr := fmt.Sprintf("%d", port)
		if s := ipsSetFunc(id); s != nil && s.Contains(portStr) {
			return false
		}
	}
	return true
}

// matchDstNet checks if the destination IP is within the CIDRs and not in the not CIDRs.
func matchDstNet(rule *proto.Rule, req *requestCache) bool {
	return matchNet("dst", rule.GetDstNet(), req.GetDestIP()) &&
		matchNotNet("dst", rule.GetNotDstNet(), req.GetDestIP())
}

// matchSrcNet checks if the source IP is within the CIDRs and not in the not CIDRs.
func matchSrcNet(rule *proto.Rule, req *requestCache) bool {
	return matchNet("src", rule.GetSrcNet(), req.GetSourceIP()) &&
		matchNotNet("src", rule.GetNotSrcNet(), req.GetSourceIP())
}

// matchNet checks if the IP is within the CIDRs. It returns true if the IP matches, false
// otherwise.
func matchNet(dir string, nets []string, ip net.IP) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"nets": nets,
			"ip":   ip.String(),
			"dir":  dir,
		}).Debug("matching net")
	}
	if len(nets) == 0 {
		return true
	}

	for _, n := range nets {
		_, ipn, err := net.ParseCIDR(n)
		if err != nil {
			// Don't match CIDRs if they are malformed. This case should generally be weeded out by
			// validation earlier in processing before it gets to Dikastes.
			log.WithField("cidr", n).Warn("unable to parse CIDR")
			return false
		}
		if ipn.Contains(ip) {
			return true
		}
	}
	return false
}

// matchNotNet checks if the IP is not within the CIDRs. It returns false if the IP matches, true
// otherwise.
func matchNotNet(dir string, nets []string, ip net.IP) bool {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"nets": nets,
			"ip":   ip.String(),
			"dir":  dir,
		}).Debug("matching net")
	}
	if len(nets) == 0 {
		return true
	}

	for _, n := range nets {
		_, ipn, err := net.ParseCIDR(n)
		if err != nil {
			// Don't match CIDRs if they are malformed. This case should generally be weeded out by
			// validation earlier in processing before it gets to Dikastes.
			log.WithField("cidr", n).Warn("unable to parse CIDR")
			return false
		}
		if ipn.Contains(ip) {
			return false
		}
	}
	return true
}

var stringToProto = map[string]int32{
	"icmp":    1,
	"icmpv6":  58,
	"tcp":     6,
	"udp":     17,
	"udplite": 136,
	"sctp":    132,
}

// matchL4Protocol checks if the L4 protocol matches the rule. It returns true if the protocol
// matches, false otherwise.
func matchL4Protocol(rule *proto.Rule, protocol int32) bool {
	// Protocol is a 8-bit field.
	if protocol > 255 || protocol < 1 {
		log.WithFields(log.Fields{
			"protocol": protocol,
		}).Warn("Unsupported L4 protocol")
		return false
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"isProtocol":      rule.GetProtocol(),
			"isNotProtocol":   rule.GetNotProtocol(),
			"requestProtocol": protocol,
		}).Debug("Matching L4 protocol")
	}

	checkStringInRuleProtocol := func(p *proto.Protocol, pNumber int32, defaultResult bool) bool {
		if p == nil {
			return defaultResult
		}

		// Check if given protocol matches what is specified in rule.
		var protoNumber int32
		if name := p.GetName(); name != "" {
			var ok bool
			protoNumber, ok = stringToProto[strings.ToLower(name)]
			if !ok {
				return false
			}
		} else {
			protoNumber = p.GetNumber()
		}
		return protoNumber == pNumber
	}

	return checkStringInRuleProtocol(rule.GetProtocol(), protocol, true) &&
		!checkStringInRuleProtocol(rule.GetNotProtocol(), protocol, false)
}
