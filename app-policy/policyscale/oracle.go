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

package policyscale

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// Verdict is one entry of the rule trace the engine is expected to report: a Pass on the way, or
// the final Allow or Deny. It carries the fields of calc.RuleID that identify a rule.
type Verdict struct {
	Kind   string // GlobalNetworkPolicy, or Profile for the end-of-profiles deny.
	Tier   string
	Policy string
	Index  int    // Rule index in the policy; TierDefaultIndex for a tier or profile default.
	Action string // allow, deny or pass.
}

const (
	// TierDefaultIndex is the index reported for a tier's default action.
	TierDefaultIndex = -1
	// ProfileName is the tier a profile's verdict is reported under.
	ProfileName = "__PROFILE__"
	// NoMatchName is the name the dataplane reports for the deny when no profile matches, or the
	// endpoint has none.
	NoMatchName = "__NO_MATCH__"
)

func (v Verdict) String() string {
	return fmt.Sprintf("%s/%s/%s[%d]=%s", v.Kind, v.Tier, v.Policy, v.Index, v.Action)
}

// Scope selects the policies a trace counts, as the pending and the enforced verdicts do.
type Scope int

const (
	// PendingScope counts staged policies as enforced: the trace a flow log's pending policies
	// report.
	PendingScope Scope = iota
	// EnforcedScope leaves staged policies out, and with them a tier that has no other policy: the
	// trace the dataplane enforces.
	EnforcedScope
)

// Expect returns the pending trace for the flow; see ExpectIn.
func (fx *Fixture) Expect(dir Direction, f *Flow) []Verdict {
	return fx.ExpectIn(PendingScope, dir, f)
}

// ExpectIn returns the trace the engine must report for the flow in the given direction and
// scope, computed from the generator's own model of each rule rather than from the proto the
// engine reads, so that the two are independent. It follows what the dataplanes enforce: policies
// of a tier in order, first matching rule decides; Allow or Deny ends the evaluation; Pass moves to
// the next tier; a tier none of whose policies matched applies its default action, reported
// against the tier's last policy in scope, with anything but Pass denying; and a flow that gets
// past every tier ends in the endpoint's profile, which allows, or with none, in the deny the
// dataplane reports when no profile matches.
func (fx *Fixture) ExpectIn(scope Scope, dir Direction, f *Flow) []Verdict {
	var trace []Verdict
	for _, t := range fx.tiers {
		var policies []*policyModel
		for _, p := range t.policies[dir] {
			if scope == PendingScope || !p.staged {
				policies = append(policies, p)
			}
		}
		if len(policies) == 0 {
			continue
		}
		matched := false
	Tier:
		for _, p := range policies {
			for i, r := range p.rules {
				if !fx.ruleMatches(r, f) {
					continue
				}
				matched = true
				trace = append(trace, Verdict{Kind: p.kind(), Tier: t.name, Policy: p.name, Index: i, Action: r.action})
				if r.action == "pass" {
					break Tier
				}
				return trace
			}
		}
		if !matched {
			action := "deny"
			if t.defaultAction == string(v3.Pass) {
				action = "pass"
			}
			last := policies[len(policies)-1]
			trace = append(trace, Verdict{Kind: last.kind(), Tier: t.name, Policy: last.name, Index: TierDefaultIndex, Action: action})
			if action != "pass" {
				return trace
			}
		}
	}
	if fx.Spec.Profile != "" {
		return append(trace, Verdict{Kind: v3.KindProfile, Tier: ProfileName, Policy: fx.Spec.Profile, Index: 0, Action: "allow"})
	}
	return append(trace, Verdict{Kind: v3.KindProfile, Tier: ProfileName, Policy: NoMatchName, Index: 0, Action: "deny"})
}

// ruleMatches evaluates a rule's criteria against the flow, the way the dataplanes render them:
//   - a protocol outside 1..255 matches no rule;
//   - a rule for one IP version, explicit or taken from an ICMP protocol name, matches only flows
//     of that family;
//   - ICMP type and code criteria, negated or not, match only ICMP packets of the flow's family,
//     whose type and code the flow carries in its destination port; a negated type and code
//     excludes only packets that have both;
//   - port lists and named ports match when either lists the port; a named port or service is an
//     IP+port set holding the address, protocol and port;
//   - a CIDR list keeps only the entries of the flow's family, and a list with none left drops the
//     rule from that family;
//   - a positive IP set reference requires the address to be a member; a negated one requires it
//     not to be; a reference to a set the store does not hold is skipped, as the engine skips it;
//   - an address that is not an IP (nil) is a member of no set and inside no CIDR.
func (fx *Fixture) ruleMatches(r *ruleModel, f *Flow) bool {
	if f.Protocol < 1 || f.Protocol > 255 {
		return false
	}
	family := flowFamily(f)
	if v := r.effectiveIPVersion(); v != 0 && v != family {
		return false
	}
	if r.protocol != nil && f.Protocol != r.protocol.num() {
		return false
	}
	if r.notProtocol != nil && f.Protocol == r.notProtocol.num() {
		return false
	}
	if !icmpMatches(r, f, family) {
		return false
	}
	if !fx.dstPortMatches(r, f) || !portInRanges(r.srcPortRanges, f.SrcPort, true) {
		return false
	}
	if portInRanges(r.notDstPortRanges, f.DstPort, false) || fx.ipPortSetHolds(r.notDstNamedPortSet, f.DstIP, f.Protocol, f.DstPort, false) {
		return false
	}
	dstNets := r.dstNets
	if r.dstNet.IsValid() {
		dstNets = append([]netip.Prefix{r.dstNet}, dstNets...)
	}
	if !netsMatch(r.srcNets, f.SrcIP, family, false) || !netsMatch(r.notSrcNets, f.SrcIP, family, true) ||
		!netsMatch(dstNets, f.DstIP, family, false) || !netsMatch(r.notDstNets, f.DstIP, family, true) {
		return false
	}
	if r.dstServiceSet != "" && !fx.ipPortSetHolds(r.dstServiceSet, f.DstIP, f.Protocol, f.DstPort, true) {
		return false
	}
	return fx.setAllows(r.srcSet, f.SrcIP, true) &&
		fx.setAllows(r.notSrcSet, f.SrcIP, false) &&
		fx.setAllows(r.dstSet, f.DstIP, true) &&
		fx.setAllows(r.notDstSet, f.DstIP, false)
}

// effectiveIPVersion is the rule's IP version, or the one its ICMP protocol name implies.
func (r *ruleModel) effectiveIPVersion() int {
	if r.ipVersion != 0 || r.protocol == nil {
		return r.ipVersion
	}
	switch strings.ToLower(r.protocol.name) {
	case "icmp":
		return 4
	case "icmpv6":
		return 6
	}
	return 0
}

func icmpMatches(r *ruleModel, f *Flow, family int) bool {
	if r.icmp == nil && r.notICMP == nil {
		return true
	}
	if !(f.Protocol == ProtocolICMP && family == 4) && !(f.Protocol == ProtocolICMPv6 && family == 6) {
		return false
	}
	typ, code := ICMPTypeCode(f)
	if r.icmp != nil && (typ != r.icmp.typ || r.icmp.hasCode && code != r.icmp.code) {
		return false
	}
	if r.notICMP != nil && typ == r.notICMP.typ && (!r.notICMP.hasCode || code == r.notICMP.code) {
		return false
	}
	return true
}

// dstPortMatches applies the rule's destination ports and named port: with either present, the
// flow's port must be listed or be the named port on the destination address.
func (fx *Fixture) dstPortMatches(r *ruleModel, f *Flow) bool {
	if len(r.dstPorts) == 0 && len(r.dstPortRanges) == 0 && r.dstNamedPortSet == "" {
		return true
	}
	return slices.Contains(r.dstPorts, int32(f.DstPort)) ||
		portInRanges(r.dstPortRanges, f.DstPort, false) ||
		fx.ipPortSetHolds(r.dstNamedPortSet, f.DstIP, f.Protocol, f.DstPort, false)
}

// portInRanges reports whether the port is in one of the ranges, or ifEmpty when there are none.
func portInRanges(ranges []portRange, port int, ifEmpty bool) bool {
	if len(ranges) == 0 {
		return ifEmpty
	}
	for _, r := range ranges {
		if int32(port) >= r.first && int32(port) <= r.last {
			return true
		}
	}
	return false
}

// ipPortSetHolds reports whether the IP+port set holds the address, protocol and port. A set the
// store doesn't hold reports ifMissing, matching how the engine treats each kind of reference.
func (fx *Fixture) ipPortSetHolds(setID string, ip net.IP, protocol, port int, ifMissing bool) bool {
	if setID == "" {
		return false
	}
	s := fx.sets[setID]
	if s.missing {
		return ifMissing
	}
	a, ok := toAddr(ip)
	if !ok {
		return false
	}
	_, held := s.ipPorts[ipPortMember{addr: a, protocol: protocol, port: port}]
	return held
}

// netsMatch applies a CIDR list as the dataplanes render it: only the entries of the flow's
// family are kept, and a list with none left drops the rule from that family. A flow whose family
// isn't known keeps every entry.
func netsMatch(nets []netip.Prefix, ip net.IP, family int, negated bool) bool {
	if len(nets) == 0 {
		return true
	}
	kept := nets
	if family != 0 {
		kept = nil
		for _, n := range nets {
			if n.Addr().Is4() == (family == 4) {
				kept = append(kept, n)
			}
		}
		if len(kept) == 0 {
			return false
		}
	}
	a, ok := toAddr(ip)
	contained := false
	for _, n := range kept {
		if ok && n.Contains(a) {
			contained = true
			break
		}
	}
	return contained != negated
}

// setAllows reports whether a (possibly negated) reference to a set lets the address through.
func (fx *Fixture) setAllows(setID string, ip net.IP, positive bool) bool {
	if setID == "" {
		return true
	}
	s := fx.sets[setID]
	if s.missing {
		return true
	}
	a, ok := toAddr(ip)
	if !ok {
		return !positive
	}
	_, member := s.addrs[a]
	return member == positive
}

// flowFamily returns 4 or 6 for the family of the flow's addresses, destination first, or 0 when
// neither is an IP address.
func flowFamily(f *Flow) int {
	for _, ip := range []net.IP{f.DstIP, f.SrcIP} {
		if a, ok := toAddr(ip); ok {
			if a.Is4() {
				return 4
			}
			return 6
		}
	}
	return 0
}

// num is the protocol's number, from its name when it has one.
func (p *protocolModel) num() int {
	if p.name == "" {
		return p.number
	}
	return protocolNumbers[strings.ToLower(p.name)]
}

var protocolNumbers = map[string]int{
	"icmp": ProtocolICMP, "tcp": ProtocolTCP, "udp": ProtocolUDP,
	"icmpv6": ProtocolICMPv6, "sctp": ProtocolSCTP, "udplite": ProtocolUDPLite,
}

func toAddr(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	return a.Unmap(), ok
}
