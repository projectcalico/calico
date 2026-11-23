// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

// ShapesParams describes the rule-shape preset: a rule for each kind of criterion the evaluator
// checks, in both directions, with flows of both IP families aimed at each rule, some that it
// matches and some that differ from those only in the criterion the rule is there for. It is for
// coverage rather than scale: the differential tests check the evaluator against the oracle with
// it, and a functional test can apply it to a cluster and compare pending with enforced verdicts.
type ShapesParams struct {
	// PassTier comes first and defaults to Pass; it holds the rules whose action is Pass. Tier
	// defaults to Deny and holds the rest, alternately allowing and denying.
	PassTier, Tier string
	// LocalIPv4 and LocalIPv6 are the endpoint's addresses: the source of egress flows and the
	// destination of ingress flows.
	LocalIPv4, LocalIPv6 netip.Addr
	// PeerIPv4 and PeerIPv6 are the pools the other end of each flow comes from. Each rule takes
	// an address from each, in order, and flows that no rule names come from near the end of the
	// pool; a pool needs at least 256 addresses.
	PeerIPv4, PeerIPv6 netip.Prefix
	// RulesPerPolicy spreads the rules over several policies, so that a tier's default action has
	// several policies it could be reported against.
	RulesPerPolicy int
	// Staged makes some of the policies staged, so that the pending and the enforced verdicts
	// differ: a tier of staged policies alone comes first, and in the other tiers every third
	// policy and the last one are staged. It is for testing the evaluator's scopes; a set compared
	// on a cluster for pending verdicts equal to enforced ones wants none.
	Staged bool
}

// shapesStagedTier is the tier of staged policies alone that ShapesParams.Staged adds.
const shapesStagedTier = "shapes-staged"

// DefaultShapes returns the rule-shape preset's defaults.
func DefaultShapes() ShapesParams {
	return ShapesParams{
		PassTier:       "shapes-pass",
		Tier:           "shapes",
		LocalIPv4:      netip.MustParseAddr("10.65.0.10"),
		LocalIPv6:      netip.MustParseAddr("fd00:65::10"),
		PeerIPv4:       netip.MustParsePrefix("10.66.0.0/24"),
		PeerIPv6:       netip.MustParsePrefix("fd00:66::/120"),
		RulesPerPolicy: 4,
	}
}

// RuleShapes is the rule-shape preset on its own.
func RuleShapes() Spec {
	p := DefaultShapes()
	return Spec{Seed: DefaultSeed, Shapes: &p}
}

// ShapeRule is one rule of the rule-shape preset, with the flows aimed at it.
type ShapeRule struct {
	Name      string
	Direction Direction
	Tier      string
	Policy    string
	Index     int
	Flows     []ShapeFlow
}

// ShapeFlow is a flow aimed at a rule of the rule-shape preset.
type ShapeFlow struct {
	Name string
	Flow *Flow
	// Hit is whether the rule should decide the flow; when it isn't, the flow differs from one
	// the rule decides only in the criterion the rule is there for.
	Hit bool
	// Differences are the known differences this flow can expose.
	Differences []Difference
}

// NamedPort is a named port the rule-shape preset's rules use. On a cluster, the endpoints at
// Addrs must declare it.
type NamedPort struct {
	Name     string
	Protocol string
	Port     int
	Addrs    []netip.Addr
}

// Service is a service the rule-shape preset's rules match on. On a cluster it must exist, with
// the endpoints at Addrs behind Port.
type Service struct {
	Name, Namespace string
	Protocol        string
	Port            int
	Addrs           []netip.Addr
}

// ShapeRules returns the rule-shape preset's rules in the direction, in the order a flow walks
// them.
func (fx *Fixture) ShapeRules(dir Direction) []*ShapeRule {
	return fx.shapeRules[dir]
}

// ShapeFlows returns every flow aimed at the rule-shape preset's rules in the direction, and flows
// that match none of them, leaving out the flows that can expose any of the given differences.
func (fx *Fixture) ShapeFlows(dir Direction, exclude ...Difference) []ShapeFlow {
	var out []ShapeFlow
	add := func(flows []ShapeFlow) {
		for _, f := range flows {
			if !slices.ContainsFunc(f.Differences, func(d Difference) bool { return slices.Contains(exclude, d) }) {
				out = append(out, f)
			}
		}
	}
	for _, r := range fx.shapeRules[dir] {
		add(r.Flows)
	}
	add(fx.shapeUnmatched[dir])
	return out
}

// NamedPorts returns the named ports the rule-shape preset's rules use.
func (fx *Fixture) NamedPorts() []NamedPort { return fx.namedPorts }

// Services returns the services the rule-shape preset's rules match on.
func (fx *Fixture) Services() []Service { return fx.services }

const (
	shapePortBase  = 20000
	shapeSPortBase = 40000
	shapeSPort     = 33333
	// shapeOutside is the offset in each peer pool of the address that no rule names.
	shapeOutside = 250
	// ShapesNamespace is the namespace of the services the rule-shape preset matches on.
	ShapesNamespace = "policyscale"
)

type shapeBuilder struct {
	fx   *Fixture
	p    ShapesParams
	next int
}

func (fx *Fixture) buildShapes(p ShapesParams) {
	if p.PeerIPv4.Bits() > 24 || p.PeerIPv6.Bits() > 120 {
		panic("policyscale: rule-shape peer pools need at least 256 addresses")
	}
	b := &shapeBuilder{fx: fx, p: p}
	var stagedTier *tierModel
	if p.Staged {
		stagedTier = fx.tier(shapesStagedTier, string(v3.Pass))
	}
	passTier := fx.tier(p.PassTier, string(v3.Pass))
	tier := fx.tier(p.Tier, string(v3.Deny))
	for _, dir := range []Direction{Ingress, Egress} {
		if stagedTier != nil {
			// No aimed flow reaches the rule, so the tier ends every flow's walk with its
			// default, in the pending scope only.
			stagedTier.policies[dir] = append(stagedTier.policies[dir], &policyModel{
				name:   fmt.Sprintf("shape-staged-%s", dirShort(dir)),
				staged: true,
				rules: []*ruleModel{{
					action: "deny", protocol: &protocolModel{name: "TCP"}, dstPorts: []int32{BaselineGuardPort},
				}},
			})
		}
		b.buildPassTier(passTier, dir)
		b.buildTier(tier, dir)
		if p.Staged {
			for _, t := range []*tierModel{passTier, tier} {
				policies := t.policies[dir]
				for i, pol := range policies {
					pol.staged = i%3 == 1 || i == len(policies)-1
				}
			}
		}
		var unmatched []ShapeFlow
		k := b.key(dir)
		for _, fam := range []int{4, 6} {
			unmatched = append(unmatched,
				ShapeFlow{Name: fmt.Sprintf("tcp v%d matches nothing", fam), Flow: k.flowWith(fam, ProtocolTCP, shapeSPort, 1, k.outside(fam))},
				ShapeFlow{Name: fmt.Sprintf("icmp v%d echo matches nothing", fam), Flow: k.icmpWith(fam, echoType(fam), 0, k.outside(fam))})
		}
		fx.shapeUnmatched[dir] = unmatched
	}
}

// buildPassTier adds a policy with a Pass rule and a policy whose rule no aimed flow reaches, so
// that a flow either passes on the rule or meets the tier's default Pass, reported against the
// second policy.
func (b *shapeBuilder) buildPassTier(t *tierModel, dir Direction) {
	k := b.key(dir)
	r := &ruleModel{action: "pass", protocol: &protocolModel{name: "TCP"}, dstPortRanges: []portRange{{int32(k.port), int32(k.port)}}}
	k.keyed(r)
	var flows []ShapeFlow
	for _, fam := range []int{4, 6} {
		flows = append(flows,
			k.hit(fmt.Sprintf("tcp v%d to the pass port", fam), k.flow(fam, ProtocolTCP, k.port)),
			k.miss(fmt.Sprintf("tcp v%d to another port", fam), k.flow(fam, ProtocolTCP, k.port+1)))
	}
	pass := &policyModel{name: fmt.Sprintf("shape-pass-%s-0", dirShort(dir)), rules: []*ruleModel{r}}
	unreached := &policyModel{name: fmt.Sprintf("shape-pass-%s-1", dirShort(dir)), rules: []*ruleModel{{
		action: "deny", protocol: &protocolModel{name: "TCP"}, dstPorts: []int32{BaselineGuardPort},
	}}}
	r.shape = &ShapeRule{Name: "pass", Direction: dir, Tier: t.name, Policy: pass.name, Index: 0, Flows: nameFlows("pass", flows)}
	b.fx.shapeRules[dir] = append(b.fx.shapeRules[dir], r.shape)
	t.policies[dir] = append(t.policies[dir], pass, unreached)
}

func (b *shapeBuilder) buildTier(t *tierModel, dir Direction) {
	var pol *policyModel
	for i, s := range b.shapes(dir) {
		k := b.key(dir)
		r, flows := s.build(k)
		r.action = "allow"
		if i%2 == 1 {
			r.action = "deny"
		}
		if pol == nil || len(pol.rules) == b.p.RulesPerPolicy {
			pol = &policyModel{name: fmt.Sprintf("shape-%s-%02d", dirShort(dir), len(t.policies[dir]))}
			t.policies[dir] = append(t.policies[dir], pol)
		}
		r.shape = &ShapeRule{Name: s.name, Direction: dir, Tier: t.name, Policy: pol.name, Index: len(pol.rules), Flows: nameFlows(s.name, flows)}
		pol.rules = append(pol.rules, r)
		b.fx.shapeRules[dir] = append(b.fx.shapeRules[dir], r.shape)
	}
}

type shape struct {
	name  string
	build func(k *shapeKey) (*ruleModel, []ShapeFlow)
}

// shapes lists the rules of the main tier. Every rule carries a key, its own peer address or its
// own port, so that a flow aimed at one rule meets no other rule's criteria; the flows aimed at a
// rule then differ only in what the rule is there to check.
func (b *shapeBuilder) shapes(dir Direction) []shape {
	byName := func(name string) *protocolModel { return &protocolModel{name: name} }
	byNumber := func(n int) *protocolModel { return &protocolModel{number: n} }
	tcp := byName("TCP")

	// protocolShape matches one protocol, by name or number, keyed on the peer.
	protocolShape := func(name string, p *protocolModel, protocol, other int, ipVersion int) shape {
		return shape{name, func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: p, ipVersion: ipVersion}
			k.keyed(r)
			var flows []ShapeFlow
			for _, fam := range []int{4, 6} {
				if !familyCarries(fam, protocol) {
					continue
				}
				flows = append(flows,
					k.hit(fmt.Sprintf("protocol %d v%d", protocol, fam), k.protocolFlow(fam, protocol)),
					k.miss(fmt.Sprintf("protocol %d v%d", other, fam), k.protocolFlow(fam, other)))
			}
			return r, flows
		}}
	}
	notProtocolShape := func(name string, p *protocolModel, protocol, other int) shape {
		return shape{name, func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{notProtocol: p}
			k.keyed(r)
			var flows []ShapeFlow
			for _, fam := range []int{4, 6} {
				flows = append(flows,
					k.hit(fmt.Sprintf("protocol %d v%d", other, fam), k.protocolFlow(fam, other)),
					k.miss(fmt.Sprintf("protocol %d v%d", protocol, fam), k.protocolFlow(fam, protocol)))
			}
			return r, flows
		}}
	}
	// icmpShape builds an ICMP rule of one family. hits and misses are type/code pairs; pairs in
	// nftDiffer are where nftables' negated type and code disagrees with the other dataplanes.
	// The types are ones conntrack accepts as the start of a flow (echo, timestamp and information
	// requests; echo and node information queries for IPv6), so that a functional test can send
	// every flow: the dataplanes drop or accept other types before policy, and log no flow.
	icmpShape := func(name string, fam int, positive, negated *icmpModel, hits, misses, nftDiffer [][2]int) shape {
		return shape{name, func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			protoName := "ICMP"
			if fam == 6 {
				protoName = "ICMPv6"
			}
			r := &ruleModel{protocol: byName(protoName), icmp: positive, notICMP: negated}
			k.keyed(r)
			var flows []ShapeFlow
			for _, tc := range hits {
				f := k.hit(fmt.Sprintf("icmp v%d type %d code %d", fam, tc[0], tc[1]), k.icmp(fam, tc[0], tc[1]))
				if slices.Contains(nftDiffer, tc) {
					f.Differences = []Difference{NegatedICMPTypeAndCode}
				}
				flows = append(flows, f)
			}
			for _, tc := range misses {
				flows = append(flows, k.miss(fmt.Sprintf("icmp v%d type %d code %d", fam, tc[0], tc[1]), k.icmp(fam, tc[0], tc[1])))
			}
			// The rule's protocol and family exclude the other family's echo request.
			other := 10 - fam
			flows = append(flows, k.miss(fmt.Sprintf("icmp v%d echo", other), k.icmp(other, echoType(other), 0)))
			return r, flows
		}}
	}
	ipVersionShape := func(name string, version int) shape {
		return shape{name, func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: tcp, ipVersion: version}
			k.keyed(r)
			return r, []ShapeFlow{
				k.hit(fmt.Sprintf("tcp v%d", version), k.flow(version, ProtocolTCP, k.port)),
				k.miss(fmt.Sprintf("tcp v%d", 10-version), k.flow(10-version, ProtocolTCP, k.port)),
			}
		}}
	}
	cidrShape := func(name string, fam int) shape {
		return shape{name, func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{}
			k.peerNets(r, []netip.Prefix{netip.PrefixFrom(k.peer(fam), k.peer(fam).BitLen())}, false)
			return r, []ShapeFlow{
				k.hit(fmt.Sprintf("tcp v%d from the CIDR", fam), k.flow(fam, ProtocolTCP, k.port)),
				k.miss(fmt.Sprintf("tcp v%d from outside it", fam), k.flowWith(fam, ProtocolTCP, shapeSPort, k.port, k.outside(fam))),
				k.miss(fmt.Sprintf("tcp v%d, the other family", 10-fam), k.flow(10-fam, ProtocolTCP, k.port)),
			}
		}}
	}
	// negatedCIDRShape is keyed on its port, since the peer side holds the negated CIDR. The rule
	// has CIDRs of one family only, as the API requires, so a flow of the other family shows the
	// evaluator's known difference.
	negatedCIDRShape := func(name string, fam int) shape {
		return shape{name, func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: tcp, dstPortRanges: []portRange{{int32(k.port), int32(k.port)}}}
			k.peerNets(r, []netip.Prefix{netip.PrefixFrom(k.peer(fam), k.peer(fam).BitLen())}, true)
			other := k.miss(fmt.Sprintf("tcp v%d, the other family", 10-fam), k.flowWith(10-fam, ProtocolTCP, shapeSPort, k.port, k.outside(10-fam)))
			other.Differences = []Difference{OneFamilyNegatedCIDRs}
			return r, []ShapeFlow{
				k.hit(fmt.Sprintf("tcp v%d from outside the CIDR", fam), k.flowWith(fam, ProtocolTCP, shapeSPort, k.port, k.outside(fam))),
				k.miss(fmt.Sprintf("tcp v%d from the CIDR", fam), k.flow(fam, ProtocolTCP, k.port)),
				other,
			}
		}}
	}

	shapes := []shape{
		protocolShape("protocol TCP by name", byName("TCP"), ProtocolTCP, ProtocolUDP, 0),
		protocolShape("protocol UDP by name", byName("UDP"), ProtocolUDP, ProtocolTCP, 0),
		protocolShape("protocol SCTP by name", byName("SCTP"), ProtocolSCTP, ProtocolTCP, 0),
		protocolShape("protocol UDPLite by name", byName("UDPLite"), ProtocolUDPLite, ProtocolUDP, 0),
		protocolShape("protocol ICMP by name", byName("ICMP"), ProtocolICMP, ProtocolTCP, 0),
		protocolShape("protocol ICMPv6 by name", byName("ICMPv6"), ProtocolICMPv6, ProtocolTCP, 0),
		protocolShape("protocol 6", byNumber(ProtocolTCP), ProtocolTCP, ProtocolUDP, 0),
		protocolShape("protocol 17", byNumber(ProtocolUDP), ProtocolUDP, ProtocolTCP, 0),
		protocolShape("protocol 132", byNumber(ProtocolSCTP), ProtocolSCTP, ProtocolUDP, 0),
		protocolShape("protocol 1, IPv4", byNumber(ProtocolICMP), ProtocolICMP, ProtocolTCP, 4),
		protocolShape("protocol 58, IPv6", byNumber(ProtocolICMPv6), ProtocolICMPv6, ProtocolTCP, 6),
		notProtocolShape("not protocol TCP by name", byName("TCP"), ProtocolTCP, ProtocolUDP),
		notProtocolShape("not protocol 17", byNumber(ProtocolUDP), ProtocolUDP, ProtocolTCP),
		icmpShape("ICMP type", 4, &icmpModel{typ: 8}, nil,
			[][2]int{{8, 0}}, [][2]int{{13, 0}}, nil),
		icmpShape("ICMP type and code", 4, &icmpModel{typ: 8, code: 1, hasCode: true}, nil,
			[][2]int{{8, 1}}, [][2]int{{8, 0}, {13, 1}}, nil),
		icmpShape("ICMPv6 type", 6, &icmpModel{typ: 128}, nil,
			[][2]int{{128, 0}}, [][2]int{{139, 0}}, nil),
		icmpShape("ICMPv6 type and code", 6, &icmpModel{typ: 128, code: 1, hasCode: true}, nil,
			[][2]int{{128, 1}}, [][2]int{{128, 0}, {139, 1}}, nil),
		icmpShape("negated ICMP type", 4, nil, &icmpModel{typ: 8},
			[][2]int{{13, 0}, {15, 0}}, [][2]int{{8, 0}}, nil),
		icmpShape("negated ICMP type and code", 4, nil, &icmpModel{typ: 8, code: 1, hasCode: true},
			[][2]int{{8, 0}, {13, 1}, {13, 0}}, [][2]int{{8, 1}}, [][2]int{{8, 0}, {13, 1}}),
		icmpShape("negated ICMPv6 type", 6, nil, &icmpModel{typ: 128},
			[][2]int{{139, 0}}, [][2]int{{128, 0}}, nil),
		icmpShape("negated ICMPv6 type and code", 6, nil, &icmpModel{typ: 128, code: 1, hasCode: true},
			[][2]int{{128, 0}, {139, 0}}, [][2]int{{128, 1}}, [][2]int{{128, 0}}),
		ipVersionShape("IPv4 only", 4),
		ipVersionShape("IPv6 only", 6),
		{"destination port range", func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: tcp, dstPortRanges: []portRange{{int32(k.port), int32(k.port + 2)}}}
			k.keyed(r)
			return r, k.bothFamilies(func(fam int) []ShapeFlow {
				return []ShapeFlow{
					k.hit(fmt.Sprintf("tcp v%d in the range", fam), k.flow(fam, ProtocolTCP, k.port+1)),
					k.miss(fmt.Sprintf("tcp v%d past the range", fam), k.flow(fam, ProtocolTCP, k.port+3)),
				}
			})
		}},
		{"source port range", func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: tcp, srcPortRanges: []portRange{{int32(k.sport), int32(k.sport + 9)}}}
			k.keyed(r)
			return r, k.bothFamilies(func(fam int) []ShapeFlow {
				return []ShapeFlow{
					k.hit(fmt.Sprintf("tcp v%d from a port in the range", fam), k.flowWith(fam, ProtocolTCP, k.sport+5, k.port, k.peer(fam))),
					k.miss(fmt.Sprintf("tcp v%d from a port past it", fam), k.flowWith(fam, ProtocolTCP, k.sport+10, k.port, k.peer(fam))),
				}
			})
		}},
		{"negated destination port", func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: tcp, notDstPortRanges: []portRange{{int32(k.port), int32(k.port)}}}
			k.keyed(r)
			return r, k.bothFamilies(func(fam int) []ShapeFlow {
				return []ShapeFlow{
					k.hit(fmt.Sprintf("tcp v%d to another port", fam), k.flow(fam, ProtocolTCP, k.port+1)),
					k.miss(fmt.Sprintf("tcp v%d to the port", fam), k.flow(fam, ProtocolTCP, k.port)),
				}
			})
		}},
		{"SCTP destination port", func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: byName("SCTP"), dstPortRanges: []portRange{{int32(k.port), int32(k.port)}}}
			k.keyed(r)
			return r, k.bothFamilies(func(fam int) []ShapeFlow {
				f := k.hit(fmt.Sprintf("sctp v%d to the port", fam), k.flow(fam, ProtocolSCTP, k.port))
				f.Differences = []Difference{SCTPPorts}
				return []ShapeFlow{f, k.miss(fmt.Sprintf("sctp v%d to another port", fam), k.flow(fam, ProtocolSCTP, k.port+1))}
			})
		}},
		cidrShape("CIDR IPv4", 4),
		cidrShape("CIDR IPv6", 6),
		negatedCIDRShape("negated CIDR IPv4", 4),
		negatedCIDRShape("negated CIDR IPv6", 6),
		{"negated IP set", func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: tcp, dstPortRanges: []portRange{{int32(k.port), int32(k.port)}}}
			k.peerSetRef(r, true)
			return r, k.bothFamilies(func(fam int) []ShapeFlow {
				return []ShapeFlow{
					k.hit(fmt.Sprintf("tcp v%d from outside the set", fam), k.flowWith(fam, ProtocolTCP, shapeSPort, k.port, k.outside(fam))),
					k.miss(fmt.Sprintf("tcp v%d from the set", fam), k.flow(fam, ProtocolTCP, k.port)),
				}
			})
		}},
		{"named port", func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: tcp, dstNamedPortSet: k.namedPort()}
			if dir == Ingress {
				// The named port is on the local endpoint, which every ingress flow reaches.
				k.keyed(r)
			}
			return r, k.bothFamilies(func(fam int) []ShapeFlow {
				return []ShapeFlow{
					k.hit(fmt.Sprintf("tcp v%d to the named port", fam), k.flow(fam, ProtocolTCP, k.port)),
					k.miss(fmt.Sprintf("tcp v%d to another port", fam), k.flow(fam, ProtocolTCP, k.port+1)),
					k.miss(fmt.Sprintf("udp v%d to the named port's number", fam), k.flow(fam, ProtocolUDP, k.port)),
				}
			})
		}},
		{"negated named port", func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{protocol: tcp, notDstNamedPortSet: k.namedPort()}
			k.keyed(r)
			return r, k.bothFamilies(func(fam int) []ShapeFlow {
				return []ShapeFlow{
					k.hit(fmt.Sprintf("tcp v%d to another port", fam), k.flow(fam, ProtocolTCP, k.port+1)),
					k.miss(fmt.Sprintf("tcp v%d to the named port", fam), k.flow(fam, ProtocolTCP, k.port)),
				}
			})
		}},
	}
	if dir == Egress {
		shapes = append(shapes, shape{"destination service", func(k *shapeKey) (*ruleModel, []ShapeFlow) {
			r := &ruleModel{dstServiceSet: k.service()}
			return r, k.bothFamilies(func(fam int) []ShapeFlow {
				return []ShapeFlow{
					k.hit(fmt.Sprintf("tcp v%d to the service port", fam), k.flow(fam, ProtocolTCP, k.port)),
					k.miss(fmt.Sprintf("tcp v%d to another port", fam), k.flow(fam, ProtocolTCP, k.port+1)),
					k.miss(fmt.Sprintf("udp v%d to the service port", fam), k.flow(fam, ProtocolUDP, k.port)),
				}
			})
		}})
	}
	return shapes
}

// shapeKey is what makes a rule's flows its own: a peer address in each family, and ports.
type shapeKey struct {
	b            *shapeBuilder
	dir          Direction
	idx          int
	port, sport  int
	peer4, peer6 netip.Addr
	peerSet      string
}

func (b *shapeBuilder) key(dir Direction) *shapeKey {
	idx := b.next
	b.next++
	if idx+1 >= shapeOutside {
		panic("policyscale: too many rule shapes for the peer pools")
	}
	return &shapeKey{
		b:     b,
		dir:   dir,
		idx:   idx,
		port:  shapePortBase + 10*idx,
		sport: shapeSPortBase + 10*idx,
		peer4: nthAddr(b.p.PeerIPv4, idx+1),
		peer6: nthAddr(b.p.PeerIPv6, idx+1),
	}
}

func (k *shapeKey) peer(fam int) netip.Addr {
	if fam == 4 {
		return k.peer4
	}
	return k.peer6
}

func (k *shapeKey) outside(fam int) netip.Addr {
	if fam == 4 {
		return nthAddr(k.b.p.PeerIPv4, shapeOutside)
	}
	return nthAddr(k.b.p.PeerIPv6, shapeOutside)
}

func (k *shapeKey) local(fam int) netip.Addr {
	if fam == 4 {
		return k.b.p.LocalIPv4
	}
	return k.b.p.LocalIPv6
}

// keyed restricts the rule to the rule's own peer, through a set holding its address in both
// families, on the peer's side of the flow.
func (k *shapeKey) keyed(r *ruleModel) { k.peerSetRef(r, false) }

func (k *shapeKey) peerSetRef(r *ruleModel, negated bool) {
	if k.peerSet == "" {
		k.peerSet = fmt.Sprintf("shape-peer-%d", k.idx)
		k.b.fx.addSet(k.peerSet, []string{
			netip.PrefixFrom(k.peer4, 32).String(),
			netip.PrefixFrom(k.peer6, 128).String(),
		})
	}
	switch {
	case k.dir == Egress && !negated:
		r.dstSet = k.peerSet
	case k.dir == Egress:
		r.notDstSet = k.peerSet
	case !negated:
		r.srcSet = k.peerSet
	default:
		r.notSrcSet = k.peerSet
	}
}

// peerNets puts the CIDRs on the peer's side of the flow.
func (k *shapeKey) peerNets(r *ruleModel, nets []netip.Prefix, negated bool) {
	switch {
	case k.dir == Egress && !negated:
		r.dstNets = nets
	case k.dir == Egress:
		r.notDstNets = nets
	case !negated:
		r.srcNets = nets
	default:
		r.notSrcNets = nets
	}
}

// namedPort adds a TCP named port on the flow's destination, which is the peer for egress and the
// local endpoint for ingress, and returns the IP+port set Felix would make of it.
func (k *shapeKey) namedPort() string {
	addrs := []netip.Addr{k.peer4, k.peer6}
	if k.dir == Ingress {
		addrs = []netip.Addr{k.local(4), k.local(6)}
	}
	np := NamedPort{Name: fmt.Sprintf("np-%d", k.idx), Protocol: "TCP", Port: k.port, Addrs: addrs}
	k.b.fx.namedPorts = append(k.b.fx.namedPorts, np)
	id := fmt.Sprintf("shape-named-port-%d", k.idx)
	k.b.fx.addIPPortSet(id, ipPortMembers(addrs, ProtocolTCP, k.port))
	k.b.fx.namedPortBySet[id] = np
	return id
}

// service adds a TCP service backed by the rule's peer, and returns the IP+port set Felix would
// make of it.
func (k *shapeKey) service() string {
	addrs := []netip.Addr{k.peer4, k.peer6}
	svc := Service{Name: fmt.Sprintf("svc-%d", k.idx), Namespace: ShapesNamespace, Protocol: "TCP", Port: k.port, Addrs: addrs}
	k.b.fx.services = append(k.b.fx.services, svc)
	id := fmt.Sprintf("shape-service-%d", k.idx)
	k.b.fx.addIPPortSet(id, ipPortMembers(addrs, ProtocolTCP, k.port))
	k.b.fx.serviceBySet[id] = svc
	return id
}

func ipPortMembers(addrs []netip.Addr, protocol, port int) []ipPortMember {
	var out []ipPortMember
	for _, a := range addrs {
		out = append(out, ipPortMember{addr: a, protocol: protocol, port: port})
	}
	return out
}

// flow is a flow between the local endpoint and the rule's peer.
func (k *shapeKey) flow(fam, protocol, dport int) *Flow {
	return k.flowWith(fam, protocol, shapeSPort, dport, k.peer(fam))
}

// flowWith is a flow between the local endpoint and the given peer: from the local endpoint for
// egress, to it for ingress.
func (k *shapeKey) flowWith(fam, protocol, sport, dport int, peer netip.Addr) *Flow {
	local := k.local(fam)
	src, dst := local, peer
	if k.dir == Ingress {
		src, dst = peer, local
	}
	return &Flow{SrcIP: net.IP(src.AsSlice()), DstIP: net.IP(dst.AsSlice()), SrcPort: sport, DstPort: dport, Protocol: protocol}
}

// protocolFlow is a flow of the protocol to the rule's port, or an echo request for ICMP.
func (k *shapeKey) protocolFlow(fam, protocol int) *Flow {
	if protocol == ProtocolICMP || protocol == ProtocolICMPv6 {
		f := k.icmp(fam, echoType(fam), 0)
		f.Protocol = protocol
		return f
	}
	return k.flow(fam, protocol, k.port)
}

func (k *shapeKey) icmp(fam, typ, code int) *Flow {
	return k.icmpWith(fam, typ, code, k.peer(fam))
}

func (k *shapeKey) icmpWith(fam, typ, code int, peer netip.Addr) *Flow {
	protocol := ProtocolICMP
	if fam == 6 {
		protocol = ProtocolICMPv6
	}
	return k.flowWith(fam, protocol, 0, typ<<8|code, peer)
}

// nameFlows prefixes each flow's name with its rule's, so a failure names both.
func nameFlows(rule string, flows []ShapeFlow) []ShapeFlow {
	for i := range flows {
		flows[i].Name = rule + ": " + flows[i].Name
	}
	return flows
}

func (k *shapeKey) hit(name string, f *Flow) ShapeFlow {
	return ShapeFlow{Name: name, Flow: f, Hit: true}
}
func (k *shapeKey) miss(name string, f *Flow) ShapeFlow { return ShapeFlow{Name: name, Flow: f} }

func (k *shapeKey) bothFamilies(flows func(fam int) []ShapeFlow) []ShapeFlow {
	return append(flows(4), flows(6)...)
}

// familyCarries reports whether flows of the family can carry the protocol: ICMP is IPv4's and
// ICMPv6 is IPv6's.
func familyCarries(fam, protocol int) bool {
	switch protocol {
	case ProtocolICMP:
		return fam == 4
	case ProtocolICMPv6:
		return fam == 6
	}
	return true
}

func echoType(fam int) int {
	if fam == 6 {
		return 128
	}
	return 8
}

func dirShort(dir Direction) string {
	if dir == Egress {
		return "out"
	}
	return "in"
}

func nthAddr(p netip.Prefix, n int) netip.Addr {
	a := p.Masked().Addr()
	for range n {
		a = a.Next()
	}
	return a
}
