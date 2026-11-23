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
	"math/rand"
	"net/netip"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/proto"
)

const (
	// SentinelIPSetID names the set that holds the denied flow's addresses. Baseline rules that
	// reference an IP set also carry a negated reference to it; see BaselineParams.
	SentinelIPSetID = "policyscale-sentinel"

	baselineIPSetPrefix = "policyscale-base-"
	egressIPSetPrefix   = "policyscale-egress-"

	// BaselineGuardPort is the destination port that guards baseline rules with no IP set
	// reference. No generated flow uses it, so those rules never match.
	BaselineGuardPort int32 = 65001

	// EgressTailPort is outside the range egress rules draw their ports from, so only the target
	// rule carries it: the extreme of the measured tail, where 90% of ports are on 5 rules or
	// fewer.
	EgressTailPort int32 = 60999

	// egressTailPortMin/Range bound the long tail of otherwise-unique destination ports.
	egressTailPortMin   = 1024
	egressTailPortRange = 55000
)

// Fixture is a built policy set: the model the oracle and flow generators reason about, plus the
// proto policies the store and endpoint are made from.
type Fixture struct {
	Spec Spec

	tiers    []*tierModel
	sets     map[string]*ipSetModel
	setOrder []string

	missingRefs  int
	egressTarget *EgressTarget

	shapeRules     [2][]*ShapeRule
	shapeUnmatched [2][]ShapeFlow
	namedPorts     []NamedPort
	services       []Service
	namedPortBySet map[string]NamedPort
	serviceBySet   map[string]Service
}

// EgressTarget describes the one egress rule a matching flow is built to hit when
// EgressParams.TargetDepth is set.
type EgressTarget struct {
	Policy      string // Policy name, as the trace reports it.
	RuleIndex   int    // Index of the rule within its policy.
	Ordinal     int    // Position of the rule in the egress walk, from 0.
	RulesWalked int    // Rules visited before and including it.
	AddrInCIDR  string // An address inside the rule's destination CIDR.
	TailPort    int32  // A port only the target carries.
	PopularPort int32  // The most popular port, which the target also carries.
}

type tierModel struct {
	name          string
	defaultAction string // "Deny" or "Pass", as TierInfo.DefaultAction spells it.
	policies      [2][]*policyModel
}

type policyModel struct {
	name  string
	rules []*ruleModel

	id     *proto.PolicyID
	policy *proto.Policy
}

// ruleModel is what the generator knows about a rule. Every criterion is ANDed; an unset one is
// unconstrained. The oracle evaluates this, never the proto.
type ruleModel struct {
	action                               string // "allow", "deny" or "pass".
	dstPorts                             []int32
	dstNet                               netip.Prefix
	srcSet, notSrcSet, dstSet, notDstSet string

	// The criteria below are used by the rule-shape preset; see shapes.go.
	protocol, notProtocol *protocolModel
	ipVersion             int // 0 for either family, else 4 or 6.
	icmp, notICMP         *icmpModel
	srcPortRanges         []portRange
	dstPortRanges         []portRange
	notDstPortRanges      []portRange
	srcNets, notSrcNets   []netip.Prefix
	dstNets, notDstNets   []netip.Prefix
	// IP+port sets: a named port on the destination, its negation, and a destination service.
	dstNamedPortSet, notDstNamedPortSet string
	dstServiceSet                       string

	// shape is set on the rules the rule-shape preset builds.
	shape *ShapeRule
}

func (r *ruleModel) hasPorts() bool {
	return len(r.dstPorts) > 0 || len(r.srcPortRanges) > 0 || len(r.dstPortRanges) > 0 || len(r.notDstPortRanges) > 0 ||
		r.dstNamedPortSet != "" || r.notDstNamedPortSet != ""
}

// protocolModel is a rule's protocol as the API spells it: a name, or a number when name is empty.
type protocolModel struct {
	name   string
	number int
}

// tcpProtocol is the protocol of the presets' port rules. The API only takes ports alongside a
// protocol, so the model carries it too: a rendered rule and the store's copy must reject the same
// flows.
func tcpProtocol() *protocolModel { return &protocolModel{name: "TCP"} }

// icmpModel is a rule's ICMP type, and code when hasCode is set.
type icmpModel struct {
	typ, code int
	hasCode   bool
}

type portRange struct{ first, last int32 }

type ipSetModel struct {
	id      string
	members []string // CIDR strings, or "ip,proto:port" for an IP+port set, as the store takes them.
	addrs   map[netip.Addr]struct{}
	// ipPorts holds the members of an IP+port set, which is the kind of set Felix sends for named
	// ports and service matches.
	ipPorts map[ipPortMember]struct{}
	missing bool
}

type ipPortMember struct {
	addr     netip.Addr
	protocol int
	port     int
}

// Build materialises a Spec. Each preset draws from its own generator seeded with Spec.Seed, so a
// preset builds the same rules whether it is used alone or in a composite.
func Build(spec Spec) *Fixture {
	fx := &Fixture{
		Spec:           spec,
		sets:           map[string]*ipSetModel{},
		namedPortBySet: map[string]NamedPort{},
		serviceBySet:   map[string]Service{},
	}
	if spec.Baseline != nil {
		fx.buildBaseline(rand.New(rand.NewSource(spec.Seed)), *spec.Baseline)
	}
	if spec.Egress != nil {
		fx.buildEgress(rand.New(rand.NewSource(spec.Seed)), *spec.Egress)
	}
	if spec.Shapes != nil {
		fx.buildShapes(*spec.Shapes)
	}
	for _, t := range fx.tiers {
		for dir, policies := range t.policies {
			for _, p := range policies {
				for i, r := range p.rules {
					// The API takes ports only alongside a protocol, so a rule without one
					// couldn't be rendered, and adding one would make the cluster reject flows
					// the store accepts.
					if r.hasPorts() && r.protocol == nil {
						panic(fmt.Sprintf("policyscale: rule %d of %s/%s has ports but no protocol", i, t.name, p.name))
					}
				}
				p.buildProto(t.name, Direction(dir))
			}
		}
	}
	return fx
}

func (fx *Fixture) buildBaseline(rng *rand.Rand, p BaselineParams) {
	setIDs := fx.makeBaselineIPSets(rng, p.SizeHistogram)

	// Pick the rule slots that get the few non-Pass actions.
	numRules := p.Policies * p.RulesPerPolicy
	specialAction := map[int]string{}
	for len(specialAction) < p.DenyRules {
		specialAction[rng.Intn(numRules)] = "deny"
	}
	for n := 0; n < p.AllowRules; {
		slot := rng.Intn(numRules)
		if _, ok := specialAction[slot]; !ok {
			specialAction[slot] = "allow"
			n++
		}
	}

	tier := fx.tier(p.Tier, "Deny")
	var referencedIDs []string
	refCount := map[string]int{}
	ruleIdx := 0
	for i := 0; i < p.Policies; i++ {
		pol := &policyModel{name: fmt.Sprintf("policy-%03d", i)}
		for j := 0; j < p.RulesPerPolicy; j++ {
			action := specialAction[ruleIdx]
			if action == "" {
				action = "pass"
			}
			r := &ruleModel{action: action}
			var refID string
			if rng.Float64() < p.IPSetRefFraction {
				refID = setIDs[rng.Intn(len(setIDs))]
				if rng.Intn(2) == 0 {
					r.srcSet, r.notSrcSet = refID, SentinelIPSetID
				} else {
					r.dstSet, r.notDstSet = refID, SentinelIPSetID
				}
			} else {
				r.protocol, r.dstPorts = tcpProtocol(), []int32{BaselineGuardPort}
			}
			pol.rules = append(pol.rules, r)
			if refID != "" {
				if refCount[refID] == 0 {
					referencedIDs = append(referencedIDs, refID)
				}
				refCount[refID]++
			}
			ruleIdx++
		}
		tier.policies[Ingress] = append(tier.policies[Ingress], pol)
	}

	// Leave some referenced sets out of the store to reproduce the "IPSet not found" storm.
	rng.Shuffle(len(referencedIDs), func(a, b int) {
		referencedIDs[a], referencedIDs[b] = referencedIDs[b], referencedIDs[a]
	})
	for _, id := range referencedIDs[:min(p.MissingIPSets, len(referencedIDs))] {
		fx.sets[id].missing = true
		fx.missingRefs += refCount[id]
	}
}

// makeBaselineIPSets adds the sentinel set and the NET sets the baseline rules reference,
// following the size histogram. Members are unique /32s from 10.0.0.0/9.
func (fx *Fixture) makeBaselineIPSets(rng *rand.Rand, hist []SizeBucket) []string {
	fx.addSet(SentinelIPSetID, []string{SourceIP + "/32", DeniedDestIP + "/32"})

	var ids []string
	member := 0
	for _, bucket := range hist {
		for i := 0; i < bucket.Sets; i++ {
			id := fmt.Sprintf("%s%04d", baselineIPSetPrefix, len(ids))
			size := bucket.MinSize + rng.Intn(bucket.MaxSize-bucket.MinSize+1)
			members := make([]string, 0, size)
			for j := 0; j < size; j++ {
				members = append(members, fmt.Sprintf("10.%d.%d.%d/32", member>>16&0x7f, member>>8&0xff, member&0xff))
				member++
			}
			fx.addSet(id, members)
			ids = append(ids, id)
		}
	}
	return ids
}

func (fx *Fixture) buildEgress(rng *rand.Rand, p EgressParams) {
	setIDs := fx.makeEgressIPSets(p.IPSets, p.MembersPerSet)

	numRules := p.Policies * p.RulesPerPolicy
	targetRule := -1
	if p.TargetDepth > 0 {
		targetRule = int(float64(numRules) * p.TargetDepth)
	}

	tier := fx.tier(p.Tier, "Deny")
	// Rule CIDRs are /24s while the set fits the /24 pool, so the reference presets are unchanged;
	// past that they are /28s from the same range. The wide form is keyed on the rule count, not on
	// how many CIDRs end up being used, so a fixture's addressing never depends on the RNG.
	wide := numRules+1 > egressCIDRPool24
	nextCIDR := 0
	ruleIdx := 0
	for i := 0; i < p.Policies; i++ {
		pol := &policyModel{name: fmt.Sprintf("egress-%03d", i)}
		for j := 0; j < p.RulesPerPolicy; j++ {
			// All rules are Pass bar the target: a rule's action is only consulted once it
			// matches, so the action mix does not affect the walk.
			r := &ruleModel{action: "pass", protocol: tcpProtocol(), dstPorts: makeEgressRulePorts(rng, p)}
			if rng.Float64() < p.IPSetRuleFraction {
				r.dstSet = setIDs[rng.Intn(len(setIDs))]
			} else {
				r.dstNet = egressCIDR(nextCIDR, wide)
				nextCIDR++
			}
			if ruleIdx == targetRule {
				// Make the target reachable on address and on a port of its own, and give it a
				// distinct action so a trace assertion is unambiguous. It carries both the tail
				// port and the popular port, so flows aimed at it differ only in how many rules
				// along the way survive the port comparison.
				r.action = "allow"
				r.dstNet = egressCIDR(nextCIDR, wide)
				r.dstSet = ""
				r.dstPorts = append(r.dstPorts, EgressTailPort, p.PortWeights[0].Port)
				fx.egressTarget = &EgressTarget{
					Policy:      pol.name,
					RuleIndex:   j,
					Ordinal:     ruleIdx,
					RulesWalked: ruleIdx + 1,
					AddrInCIDR:  egressAddrInCIDR(nextCIDR, wide),
					TailPort:    EgressTailPort,
					PopularPort: p.PortWeights[0].Port,
				}
				nextCIDR++
			}
			pol.rules = append(pol.rules, r)
			ruleIdx++
		}
		tier.policies[Egress] = append(tier.policies[Egress], pol)
	}
}

// makeEgressIPSets adds the NET sets the selector-matching egress rules reference. Members are
// /32s from 10.128.0.0/9, kept clear of the rule CIDRs handed out from 10.0.0.0/9.
func (fx *Fixture) makeEgressIPSets(numSets, membersPerSet int) []string {
	ids := make([]string, 0, numSets)
	member := 0
	for i := 0; i < numSets; i++ {
		id := fmt.Sprintf("%s%04d", egressIPSetPrefix, i)
		members := make([]string, 0, membersPerSet)
		for j := 0; j < membersPerSet; j++ {
			members = append(members, fmt.Sprintf("10.%d.%d.%d/32", 128+(member>>16&0x7f), member>>8&0xff, member&0xff))
			member++
		}
		fx.addSet(id, members)
		ids = append(ids, id)
	}
	return ids
}

// makeEgressRulePorts picks a rule's destination ports: the measured head with its measured
// frequency, topped up from a wide tail.
func makeEgressRulePorts(rng *rand.Rand, p EgressParams) []int32 {
	var ports []int32
	for _, w := range p.PortWeights {
		if rng.Float64() < w.Fraction {
			ports = append(ports, w.Port)
		}
	}
	for _, n := range p.PortsPerRule {
		if rng.Float64() < n.Fraction {
			for len(ports) < n.Count {
				ports = append(ports, int32(egressTailPortMin+rng.Intn(egressTailPortRange)))
			}
			break
		}
	}
	if len(ports) == 0 {
		ports = append(ports, int32(egressTailPortMin+rng.Intn(egressTailPortRange)))
	}
	return ports
}

// egressCIDRPool24 is how many /24 rule CIDRs 10.0.0.0/9 holds. A set needing more switches to
// /28s, which the same range holds 524,288 of; see buildEgress.
const egressCIDRPool24 = 128 * 256

func egressCIDR(n int, wide bool) netip.Prefix {
	if wide {
		// 16 /28s per /24, 256 /24s per /16, 128 /16s in the /9: 524,288 blocks.
		return netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.%d/28", n>>12&0x7f, n>>4&0xff, (n&0xf)<<4))
	}
	return netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", n>>8&0x7f, n&0xff))
}

func egressAddrInCIDR(n int, wide bool) string {
	if wide {
		return fmt.Sprintf("10.%d.%d.%d", n>>12&0x7f, n>>4&0xff, (n&0xf)<<4+7)
	}
	return fmt.Sprintf("10.%d.%d.7", n>>8&0x7f, n&0xff)
}

func (fx *Fixture) tier(name, defaultAction string) *tierModel {
	for _, t := range fx.tiers {
		if t.name == name {
			return t
		}
	}
	t := &tierModel{name: name, defaultAction: defaultAction}
	fx.tiers = append(fx.tiers, t)
	return t
}

func (fx *Fixture) addSet(id string, members []string) {
	if _, ok := fx.sets[id]; ok {
		return
	}
	s := &ipSetModel{id: id, members: members, addrs: make(map[netip.Addr]struct{}, len(members))}
	for _, m := range members {
		s.addrs[netip.MustParsePrefix(m).Addr().Unmap()] = struct{}{}
	}
	fx.sets[id] = s
	fx.setOrder = append(fx.setOrder, id)
}

// addIPPortSet adds an IP+port set holding the given members.
func (fx *Fixture) addIPPortSet(id string, members []ipPortMember) {
	if _, ok := fx.sets[id]; ok {
		return
	}
	s := &ipSetModel{id: id, ipPorts: make(map[ipPortMember]struct{}, len(members))}
	for _, m := range members {
		s.ipPorts[m] = struct{}{}
		s.members = append(s.members, fmt.Sprintf("%s,%s:%d", m.addr, l4ProtocolName[m.protocol], m.port))
	}
	fx.sets[id] = s
	fx.setOrder = append(fx.setOrder, id)
}

// isIPPort reports whether the set is an IP+port set rather than a set of CIDRs.
func (s *ipSetModel) isIPPort() bool { return s.ipPorts != nil }

// l4ProtocolName is how Felix spells the protocol of an IP+port set member.
var l4ProtocolName = map[int]string{ProtocolTCP: "tcp", ProtocolUDP: "udp", ProtocolSCTP: "sctp"}

func (p *policyModel) buildProto(tier string, dir Direction) {
	protoRules := make([]*proto.Rule, len(p.rules))
	for i, r := range p.rules {
		protoRules[i] = r.proto()
	}
	p.id = &proto.PolicyID{Name: p.name, Kind: v3.KindGlobalNetworkPolicy}
	p.policy = &proto.Policy{Tier: tier}
	if dir == Egress {
		p.policy.OutboundRules = protoRules
	} else {
		p.policy.InboundRules = protoRules
	}
}

func (r *ruleModel) proto() *proto.Rule {
	pr := &proto.Rule{Action: r.action}
	for _, port := range r.dstPorts {
		pr.DstPorts = append(pr.DstPorts, &proto.PortRange{First: port, Last: port})
	}
	if r.dstNet.IsValid() {
		pr.DstNet = []string{r.dstNet.String()}
	}
	pr.Protocol = r.protocol.proto()
	pr.NotProtocol = r.notProtocol.proto()
	pr.IpVersion = r.protoIPVersion()
	if r.icmp != nil {
		if r.icmp.hasCode {
			pr.Icmp = &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: int32(r.icmp.typ), Code: int32(r.icmp.code)}}
		} else {
			pr.Icmp = &proto.Rule_IcmpType{IcmpType: int32(r.icmp.typ)}
		}
	}
	if r.notICMP != nil {
		if r.notICMP.hasCode {
			pr.NotIcmp = &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: int32(r.notICMP.typ), Code: int32(r.notICMP.code)}}
		} else {
			pr.NotIcmp = &proto.Rule_NotIcmpType{NotIcmpType: int32(r.notICMP.typ)}
		}
	}
	pr.SrcPorts = append(pr.SrcPorts, protoPortRanges(r.srcPortRanges)...)
	pr.DstPorts = append(pr.DstPorts, protoPortRanges(r.dstPortRanges)...)
	pr.NotDstPorts = protoPortRanges(r.notDstPortRanges)
	pr.SrcNet = prefixStrings(r.srcNets)
	pr.NotSrcNet = prefixStrings(r.notSrcNets)
	pr.DstNet = append(pr.DstNet, prefixStrings(r.dstNets)...)
	pr.NotDstNet = prefixStrings(r.notDstNets)
	if r.dstNamedPortSet != "" {
		pr.DstNamedPortIpSetIds = []string{r.dstNamedPortSet}
	}
	if r.notDstNamedPortSet != "" {
		pr.NotDstNamedPortIpSetIds = []string{r.notDstNamedPortSet}
	}
	if r.dstServiceSet != "" {
		pr.DstIpPortSetIds = []string{r.dstServiceSet}
	}
	if r.srcSet != "" {
		pr.SrcIpSetIds = []string{r.srcSet}
	}
	if r.notSrcSet != "" {
		pr.NotSrcIpSetIds = []string{r.notSrcSet}
	}
	if r.dstSet != "" {
		pr.DstIpSetIds = []string{r.dstSet}
	}
	if r.notDstSet != "" {
		pr.NotDstIpSetIds = []string{r.notDstSet}
	}
	return pr
}

// proto returns the protocol as Felix sends it: names lower case, as the v1 data model has them.
func (p *protocolModel) proto() *proto.Protocol {
	switch {
	case p == nil:
		return nil
	case p.name != "":
		return &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: strings.ToLower(p.name)}}
	default:
		return &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: int32(p.number)}}
	}
}

// protoIPVersion returns the IP version as Felix sends it, which takes it from the protocol name
// when the rule doesn't give one: ICMP is IPv4 and ICMPv6 is IPv6.
func (r *ruleModel) protoIPVersion() proto.IPVersion {
	v := r.ipVersion
	if v == 0 && r.protocol != nil {
		switch strings.ToLower(r.protocol.name) {
		case "icmp":
			v = 4
		case "icmpv6":
			v = 6
		}
	}
	switch v {
	case 4:
		return proto.IPVersion_IPV4
	case 6:
		return proto.IPVersion_IPV6
	}
	return proto.IPVersion_ANY
}

func protoPortRanges(ranges []portRange) []*proto.PortRange {
	var out []*proto.PortRange
	for _, r := range ranges {
		out = append(out, &proto.PortRange{First: r.first, Last: r.last})
	}
	return out
}

func prefixStrings(prefixes []netip.Prefix) []string {
	var out []string
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

// Tiers returns the tier names in evaluation order.
func (fx *Fixture) Tiers() []string {
	names := make([]string, len(fx.tiers))
	for i, t := range fx.tiers {
		names[i] = t.name
	}
	return names
}

// Policies returns the number of policies with rules in the given direction.
func (fx *Fixture) Policies(dir Direction) int {
	n := 0
	for _, t := range fx.tiers {
		n += len(t.policies[dir])
	}
	return n
}

// Rules returns the number of rules a flow in the given direction walks when nothing matches.
func (fx *Fixture) Rules(dir Direction) int {
	n := 0
	for _, t := range fx.tiers {
		for _, p := range t.policies[dir] {
			n += len(p.rules)
		}
	}
	return n
}

// IPSets returns the number of IP sets the policies reference, including any left out of the
// store; MissingIPSets says how many of those are left out.
func (fx *Fixture) IPSets() int { return len(fx.setOrder) }

func (fx *Fixture) MissingIPSets() int {
	n := 0
	for _, id := range fx.setOrder {
		if fx.sets[id].missing {
			n++
		}
	}
	return n
}

// IPSetMembers returns the total number of members across the IP sets present in the store.
func (fx *Fixture) IPSetMembers() int {
	n := 0
	for _, id := range fx.setOrder {
		if s := fx.sets[id]; !s.missing {
			n += len(s.members)
		}
	}
	return n
}

// MissingSetReferences returns the number of rule references to sets left out of the store,
// which is exactly the number of "IPSet not found" warnings one evaluation of a flow that walks
// the whole baseline set emits.
func (fx *Fixture) MissingSetReferences() int { return fx.missingRefs }

// EgressTarget returns the target rule, or nil when the egress preset has none.
func (fx *Fixture) EgressTarget() *EgressTarget { return fx.egressTarget }

// ruleAt returns the policy and rule at the given position of the walk in a direction.
func (fx *Fixture) ruleAt(dir Direction, ordinal int) (*policyModel, *ruleModel, bool) {
	for _, t := range fx.tiers {
		for _, p := range t.policies[dir] {
			if ordinal < len(p.rules) {
				return p, p.rules[ordinal], true
			}
			ordinal -= len(p.rules)
		}
	}
	return nil, nil, false
}
