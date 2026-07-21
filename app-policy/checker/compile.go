// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// This file compiles policies into a form that is cheap to evaluate per flow.
// A proto.Rule has ~20 possible criteria but a typical rule uses one or two;
// the uncompiled match path walks every criterion for every rule for every
// flow, re-reading the large heap-scattered proto.Rule structs each time and
// recomputing rule-constant values (the action enum, the namespace-match
// inputs, selector, CIDR and protocol parses, IP set ID lookups). Compiling
// once per policy update reduces per-flow work to just the criteria each rule
// actually uses, evaluated over compact pre-resolved values.
//
// Compilation is driven by the policy store: it invokes the PolicyCompiler as
// policy/profile updates are applied, and checkTiers picks up the compiled
// form from the store's CompiledPolicyByID/CompiledProfileByID maps. A policy
// without a compiled entry is evaluated by the uncompiled path (checkPolicy /
// checkProfile), which remains the reference implementation: the two paths
// must give identical results (TestCompiledPolicyEquivalence), and the
// compiled path defers to the uncompiled one at debug log level so that every
// criterion logs as it is checked.
//
// IP set references are resolved to the IPSet objects at compile time. The
// calc graph guarantees an IP set is present in the store before any policy
// that references it arrives (see "Flush order is the dependency contract" in
// felix/design/calc-graph.md), so resolution can only fail if felix and the
// store are out of sync (in which case the miss is logged once per compile,
// not once per flow, and the missing set keeps the semantics of the
// uncompiled path). Membership deltas mutate the resolved IPSet objects in
// place; a full IPSetUpdate replaces the object, and the store recompiles
// the policies that reference it (see policystore/compiler.go).

// disableCompilationEnvVar disables policy compilation when set to "true":
// every flow is then evaluated by the uncompiled path. Kill switch only; the
// compiled and uncompiled paths are equivalence-tested against each other.
const disableCompilationEnvVar = "CALICO_DISABLE_POLICY_COMPILATION"

// NewPolicyCompiler returns the PolicyCompiler to plumb into
// policystore.WithPolicyCompiler, or nil (compilation disabled) if the
// CALICO_DISABLE_POLICY_COMPILATION environment variable is set to "true".
func NewPolicyCompiler() policystore.PolicyCompiler {
	if strings.EqualFold(os.Getenv(disableCompilationEnvVar), "true") {
		log.Warnf("Policy compilation disabled by %s", disableCompilationEnvVar)
		return nil
	}
	return policyCompiler{}
}

type policyCompiler struct{}

func (policyCompiler) CompilePolicy(store *policystore.PolicyStore, policy *proto.Policy) policystore.CompiledPolicy {
	if cp := compilePolicy(store, policy.InboundRules, policy.OutboundRules, policy.Namespace); cp != nil {
		return cp
	}
	return nil
}

func (policyCompiler) CompileProfile(store *policystore.PolicyStore, profile *proto.Profile) policystore.CompiledPolicy {
	if cp := compilePolicy(store, profile.InboundRules, profile.OutboundRules, ""); cp != nil {
		return cp
	}
	return nil
}

// compiledPolicy is a policy (or profile) reduced to per-rule slices of
// compiled criteria. It is the concrete type behind the store's
// policystore.CompiledPolicy entries.
type compiledPolicy struct {
	inbound  []compiledRule
	outbound []compiledRule

	// The uncompiled rules and the policy's namespace, for the debug-logging
	// path, which interprets the rules so that every criterion logs as it is
	// checked.
	rawInbound  []*proto.Rule
	rawOutbound []*proto.Rule
	namespace   string
}

// compiledRule is a rule reduced to its active criteria plus its pre-parsed
// action. Every matcher must return true for the rule to match a flow.
type compiledRule struct {
	action   Action
	matchers []ruleMatcher
}

// ruleMatcher is a single compiled criterion of a rule.
type ruleMatcher func(req *requestCache) bool

// compilePolicy compiles the rules of a policy or profile (profiles have no
// namespace). It returns nil if the rules cannot be compiled (e.g. a bad
// action string); the caller then keeps no compiled entry and evaluation
// falls back to the uncompiled path, which preserves that case's semantics
// (panic at evaluate time, recovered into INVALID_ARGUMENT).
func compilePolicy(store *policystore.PolicyStore, inbound, outbound []*proto.Rule, namespace string) (cp *compiledPolicy) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(*InvalidDataFromDataPlane); !ok {
				panic(r)
			}
			log.Warn("Policy failed to compile; it will be interpreted per flow instead")
			cp = nil
		}
	}()
	return &compiledPolicy{
		inbound:     compileRules(store, inbound, namespace),
		outbound:    compileRules(store, outbound, namespace),
		rawInbound:  inbound,
		rawOutbound: outbound,
		namespace:   namespace,
	}
}

// check evaluates the compiled policy against the flow, mirroring checkRules:
// first matching rule wins (LOG rules match but evaluation continues), no
// matching rule means NO_MATCH.
func (cp *compiledPolicy) check(dir rules.RuleDir, req *requestCache) (Action, int) {
	if log.IsLevelEnabled(log.DebugLevel) {
		// Use the uncompiled path so each criterion logs as it is checked.
		if dir == rules.RuleDirEgress {
			return checkRules(cp.rawOutbound, req, cp.namespace)
		}
		return checkRules(cp.rawInbound, req, cp.namespace)
	}

	// matchL4Protocol rejects an out-of-range protocol value no matter what
	// the rule says, but compiled rules only include a protocol matcher when
	// the rule constrains the protocol. Replicate the validity check once per
	// policy.
	if p := req.GetProtocol(); p < 1 || p > 255 {
		log.WithField("protocol", p).Warn("Unsupported L4 protocol")
		return NO_MATCH, tierDefaultActionIndex
	}

	crs := cp.inbound
	if dir == rules.RuleDirEgress {
		crs = cp.outbound
	}
	for i := range crs {
		cr := &crs[i]
		if cr.matches(req) {
			if cr.action != LOG {
				return cr.action, i
			}
		}
	}
	return NO_MATCH, tierDefaultActionIndex
}

func (cr *compiledRule) matches(req *requestCache) bool {
	for _, m := range cr.matchers {
		if !m(req) {
			return false
		}
	}
	return true
}

// compileRules compiles each rule's active criteria, building all the rules'
// matcher slices as views into one shared backing array (one policy-sized
// allocation instead of one per rule).
func compileRules(store *policystore.PolicyStore, rs []*proto.Rule, policyNamespace string) []compiledRule {
	out := make([]compiledRule, len(rs))
	var all []ruleMatcher
	starts := make([]int, len(rs)+1)
	for i, r := range rs {
		starts[i] = len(all)
		all = appendRuleMatchers(all, store, r, policyNamespace)
	}
	starts[len(rs)] = len(all)
	for i, r := range rs {
		out[i] = compiledRule{
			action:   actionFromString(r.Action),
			matchers: all[starts[i]:starts[i+1]:starts[i+1]],
		}
	}
	return out
}

// appendRuleMatchers appends a matcher per criterion the rule actually uses,
// in the same order the uncompiled path (match/matchSource/matchDestination)
// checks them. A criterion whose fields are empty always matches, so it is
// omitted.
func appendRuleMatchers(ms []ruleMatcher, store *policystore.PolicyStore, r *proto.Rule, policyNamespace string) []ruleMatcher {
	add := func(m ruleMatcher) {
		if m != nil {
			ms = append(ms, m)
		}
	}

	// Source criteria.
	srcSA := r.GetSrcServiceAccountMatch()
	add(compileServiceAccountsMatcher(srcSA, (*requestCache).getSrcPeer))
	// The namespace match depends only on the rule and the policy's
	// namespace, so it is computed once here rather than per flow.
	srcNSMatch := computeNamespaceMatch(
		policyNamespace,
		r.GetOriginalSrcNamespaceSelector(),
		r.GetOriginalSrcSelector(),
		r.GetOriginalNotSrcSelector(),
		srcSA)
	add(compileNamespaceMatcher(srcNSMatch, (*requestCache).getSrcNamespace))
	add(compileSrcIPSetsMatcher(store, r))
	add(compilePortsMatcher(r.GetSrcPorts(), r.GetNotSrcPorts(),
		resolveIPSets(store, r.GetSrcNamedPortIpSetIds()), resolveIPSets(store, r.GetNotSrcNamedPortIpSetIds()),
		(*requestCache).GetSourcePort))
	add(compileNetsMatcher(r.GetSrcNet(), r.GetNotSrcNet(), (*requestCache).getSrcIP))

	// Destination criteria.
	dstSA := r.GetDstServiceAccountMatch()
	add(compileServiceAccountsMatcher(dstSA, (*requestCache).getDstPeer))
	dstNSMatch := computeNamespaceMatch(
		policyNamespace,
		r.GetOriginalDstNamespaceSelector(),
		r.GetOriginalDstSelector(),
		r.GetOriginalNotDstSelector(),
		dstSA)
	add(compileNamespaceMatcher(dstNSMatch, (*requestCache).getDstNamespace))
	add(compileDstIPSetsMatcher(store, r))
	add(compileDstIPPortSetsMatcher(store, r))
	add(compilePortsMatcher(r.GetDstPorts(), r.GetNotDstPorts(),
		resolveIPSets(store, r.GetDstNamedPortIpSetIds()), resolveIPSets(store, r.GetNotDstNamedPortIpSetIds()),
		(*requestCache).GetDestPort))
	add(compileNetsMatcher(r.GetDstNet(), r.GetNotDstNet(), (*requestCache).getDstIP))

	// Request (HTTP) and protocol criteria.
	if r.GetHttpMatch() != nil {
		add(func(req *requestCache) bool { return matchRequest(r, req) })
	}
	add(compileProtocolMatcher(r.GetProtocol(), r.GetNotProtocol()))

	return ms
}

// compileServiceAccountsMatcher mirrors matchServiceAccounts, with the
// selector parsed at compile time instead of per flow. A nil peer or an empty
// peer name (plain text traffic carries no service account) matches; a
// selector that fails to parse can never match.
func compileServiceAccountsMatcher(saMatch *proto.ServiceAccountMatch, getPeer func(*requestCache) *peer) ruleMatcher {
	names := saMatch.GetNames()
	if len(names) == 0 && saMatch.GetSelector() == "" {
		return nil
	}
	sel := parseSelector(saMatch.GetSelector())
	return func(req *requestCache) bool {
		p := getPeer(req)
		if p == nil || p.Name == "" {
			return true
		}
		return matchName(names, p.Name) && sel != nil && sel.Evaluate(p.Labels)
	}
}

// compileNamespaceMatcher mirrors matchNamespace, with the selector parsed at
// compile time instead of per flow. A nil namespace or an empty namespace
// name (plain text traffic carries no namespace) matches; a selector that
// fails to parse can never match.
func compileNamespaceMatcher(nsMatch namespaceMatch, getNamespace func(*requestCache) *namespace) ruleMatcher {
	if len(nsMatch.Names) == 0 && nsMatch.Selector == "" {
		return nil
	}
	sel := parseSelector(nsMatch.Selector)
	return func(req *requestCache) bool {
		ns := getNamespace(req)
		if ns == nil || ns.Name == "" {
			return true
		}
		return matchName(nsMatch.Names, ns.Name) && sel != nil && sel.Evaluate(ns.Labels)
	}
}

// parseSelector parses a label selector at compile time, returning nil (can
// never match, as in matchLabels) if it does not parse. Note the empty
// selector parses successfully and matches everything, as in matchLabels.
func parseSelector(selectorStr string) *selector.Selector {
	sel, err := selector.Parse(selectorStr)
	if err != nil {
		log.Warnf("Could not parse label selector %v, %v", selectorStr, err)
		return nil
	}
	return sel
}

// resolvedIPSet is an IP set resolved to its object at compile time, with the
// parsed-IP fast path pre-asserted. A missing set resolves to a zero
// resolvedIPSet, keeping the uncompiled path's missing-set semantics: skipped
// by the all/not-any matchers.
type resolvedIPSet struct {
	set     policystore.IPSet
	addrSet policystore.IPAddrSet // non-nil if the set supports parsed-IP lookup
}

func (s resolvedIPSet) containsSrcIP(req *requestCache) bool {
	if s.addrSet != nil {
		// The flow's IP can be nil (non-IP connections, e.g. pipes); as in
		// ipSetContains, only a non-nil IP may take the parsed-IP fast path.
		if ip := req.getSrcIP(); ip != nil {
			return s.addrSet.ContainsIP(ip)
		}
	}
	return s.set.Contains(req.getSrcIPStr())
}

func (s resolvedIPSet) containsDstIP(req *requestCache) bool {
	if s.addrSet != nil {
		if ip := req.getDstIP(); ip != nil {
			return s.addrSet.ContainsIP(ip)
		}
	}
	return s.set.Contains(req.getDstIPStr())
}

// resolveIPSets looks up IP set IDs in the store. The calc graph sends IP
// sets before the policies that reference them, so a miss means the store is
// out of sync with felix; it is logged once here rather than once per flow.
func resolveIPSets(store *policystore.PolicyStore, ids []string) []resolvedIPSet {
	if len(ids) == 0 {
		return nil
	}
	out := make([]resolvedIPSet, len(ids))
	for i, id := range ids {
		s, ok := store.IPSetByID[id]
		if !ok {
			log.WithField("ipset", id).Warn("IPSet not found")
			continue
		}
		addrSet, _ := s.(policystore.IPAddrSet)
		out[i] = resolvedIPSet{set: s, addrSet: addrSet}
	}
	return out
}

// compileSrcIPSetsMatcher mirrors matchSrcIPSets: the source IP must be in
// all of the SrcIpSetIds sets and none of the NotSrcIpSetIds sets.
func compileSrcIPSetsMatcher(store *policystore.PolicyStore, r *proto.Rule) ruleMatcher {
	if len(r.GetSrcIpSetIds()) == 0 && len(r.GetNotSrcIpSetIds()) == 0 {
		return nil
	}
	sets := resolveIPSets(store, r.GetSrcIpSetIds())
	notSets := resolveIPSets(store, r.GetNotSrcIpSetIds())
	return func(req *requestCache) bool {
		for _, s := range sets {
			if s.set != nil && !s.containsSrcIP(req) {
				return false
			}
		}
		for _, s := range notSets {
			if s.set != nil && s.containsSrcIP(req) {
				return false
			}
		}
		return true
	}
}

// compileDstIPSetsMatcher mirrors matchDstIPSets: the destination IP must be
// in all of the DstIpSetIds sets and none of the NotDstIpSetIds sets.
func compileDstIPSetsMatcher(store *policystore.PolicyStore, r *proto.Rule) ruleMatcher {
	if len(r.GetDstIpSetIds()) == 0 && len(r.GetNotDstIpSetIds()) == 0 {
		return nil
	}
	sets := resolveIPSets(store, r.GetDstIpSetIds())
	notSets := resolveIPSets(store, r.GetNotDstIpSetIds())
	return func(req *requestCache) bool {
		for _, s := range sets {
			if s.set != nil && !s.containsDstIP(req) {
				return false
			}
		}
		for _, s := range notSets {
			if s.set != nil && s.containsDstIP(req) {
				return false
			}
		}
		return true
	}
}

// compileDstIPPortSetsMatcher mirrors matchDstIPPortSetIds: the flow's
// "<IP>,<protocol>:<port>" key must be in all of the DstIpPortSetIds sets.
func compileDstIPPortSetsMatcher(store *policystore.PolicyStore, r *proto.Rule) ruleMatcher {
	if len(r.GetDstIpPortSetIds()) == 0 {
		return nil
	}
	sets := resolveIPSets(store, r.GetDstIpPortSetIds())
	return func(req *requestCache) bool {
		for _, s := range sets {
			if s.set != nil && !s.set.Contains(req.getDstIPProtoPortStr()) {
				return false
			}
		}
		return true
	}
}

// portRange is a compact copy of proto.PortRange, so that port matching walks
// a contiguous slice instead of dereferencing per-range proto structs.
type portRange struct{ first, last int32 }

func flattenPortRanges(ranges []*proto.PortRange) []portRange {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]portRange, len(ranges))
	for i, r := range ranges {
		out[i] = portRange{first: r.GetFirst(), last: r.GetLast()}
	}
	return out
}

// compilePortsMatcher mirrors matchSrcPort/matchDstPort: the port must be in
// one of the ranges or named port sets (if any are specified), and not in any
// of the not-ranges or not-named-port sets.
func compilePortsMatcher(ports, notPorts []*proto.PortRange, namedSets, notNamedSets []resolvedIPSet, getPort func(*requestCache) int) ruleMatcher {
	if len(ports) == 0 && len(notPorts) == 0 && len(namedSets) == 0 && len(notNamedSets) == 0 {
		return nil
	}
	ranges := flattenPortRanges(ports)
	notRanges := flattenPortRanges(notPorts)
	return func(req *requestCache) bool {
		port := int32(getPort(req))
		if len(ranges) > 0 || len(namedSets) > 0 {
			if !portMatches(port, ranges, namedSets, req) {
				return false
			}
		}
		if len(notRanges) > 0 || len(notNamedSets) > 0 {
			if portMatches(port, notRanges, notNamedSets, req) {
				return false
			}
		}
		return true
	}
}

func portMatches(port int32, ranges []portRange, namedSets []resolvedIPSet, req *requestCache) bool {
	for _, r := range ranges {
		if r.first <= port && port <= r.last {
			return true
		}
	}
	if len(namedSets) > 0 {
		portStr := strconv.Itoa(int(port))
		for _, s := range namedSets {
			if s.set != nil && s.set.Contains(portStr) {
				return true
			}
		}
	}
	return false
}

// compileNetsMatcher mirrors matchSrcNet/matchDstNet with the CIDRs parsed at
// compile time: the IP must be in one of the nets (if any are specified) and
// not in any of the not-nets. Malformed CIDRs (which validation should have
// weeded out long before here) are logged once here rather than per flow, and
// keep the uncompiled path's in-order semantics: matchNet checks CIDRs in
// order and fails when it reaches a malformed one, so nets before it can
// still match; matchNotNet can never return true once a malformed not-net is
// present, which makes the whole criterion false.
func compileNetsMatcher(nets, notNets []string, getIP func(*requestCache) net.IP) ruleMatcher {
	if len(nets) == 0 && len(notNets) == 0 {
		return nil
	}
	if _, notNetsOK := parseCIDRs(notNets); !notNetsOK {
		return func(req *requestCache) bool { return false }
	}
	parsed, _ := parseCIDRs(nets)
	notParsed, _ := parseCIDRs(notNets)
	hasNets := len(nets) > 0
	return func(req *requestCache) bool {
		ip := getIP(req)
		if hasNets {
			any := false
			for _, n := range parsed {
				if n.Contains(ip) {
					any = true
					break
				}
			}
			if !any {
				return false
			}
		}
		for _, n := range notParsed {
			if n.Contains(ip) {
				return false
			}
		}
		return true
	}
}

// parseCIDRs parses up to the first malformed CIDR, returning the parsed
// prefixes and whether the whole list was well-formed.
func parseCIDRs(nets []string) ([]*net.IPNet, bool) {
	out := make([]*net.IPNet, 0, len(nets))
	for _, n := range nets {
		_, ipn, err := net.ParseCIDR(n)
		if err != nil {
			log.WithField("cidr", n).Warn("unable to parse CIDR")
			return out, false
		}
		out = append(out, ipn)
	}
	return out, true
}

// compileProtocolMatcher mirrors matchL4Protocol with the rule's protocol
// name/number resolved at compile time. (The flow protocol's range check
// lives in compiledPolicy.check.)
func compileProtocolMatcher(p, notP *proto.Protocol) ruleMatcher {
	if p == nil && notP == nil {
		return nil
	}
	resolve := func(p *proto.Protocol) (int32, bool) {
		if name := p.GetName(); name != "" {
			n, ok := stringToProto[strings.ToLower(name)]
			return n, ok
		}
		return p.GetNumber(), true
	}
	if p != nil {
		n, ok := resolve(p)
		if !ok {
			// Unknown protocol name: the rule can never match.
			return func(req *requestCache) bool { return false }
		}
		if notP == nil {
			return func(req *requestCache) bool { return int32(req.GetProtocol()) == n }
		}
		notN, notOK := resolve(notP)
		return func(req *requestCache) bool {
			proto := int32(req.GetProtocol())
			return proto == n && (!notOK || proto != notN)
		}
	}
	notN, notOK := resolve(notP)
	if !notOK {
		// Unknown not-protocol name never excludes anything.
		return nil
	}
	return func(req *requestCache) bool { return int32(req.GetProtocol()) != notN }
}
