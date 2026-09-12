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
}

type ipSetModel struct {
	id      string
	members []string // CIDR strings, as the store and the resources take them.
	addrs   map[netip.Addr]struct{}
	missing bool
}

// Build materialises a Spec. Each preset draws from its own generator seeded with Spec.Seed, so a
// preset builds the same rules whether it is used alone or in a composite.
func Build(spec Spec) *Fixture {
	fx := &Fixture{Spec: spec, sets: map[string]*ipSetModel{}}
	if spec.Baseline != nil {
		fx.buildBaseline(rand.New(rand.NewSource(spec.Seed)), *spec.Baseline)
	}
	if spec.Egress != nil {
		fx.buildEgress(rand.New(rand.NewSource(spec.Seed)), *spec.Egress)
	}
	for _, t := range fx.tiers {
		for dir, policies := range t.policies {
			for _, p := range policies {
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
				r.dstPorts = []int32{BaselineGuardPort}
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
	nextCIDR := 0
	ruleIdx := 0
	for i := 0; i < p.Policies; i++ {
		pol := &policyModel{name: fmt.Sprintf("egress-%03d", i)}
		for j := 0; j < p.RulesPerPolicy; j++ {
			// All rules are Pass bar the target: a rule's action is only consulted once it
			// matches, so the action mix does not affect the walk.
			r := &ruleModel{action: "pass", dstPorts: makeEgressRulePorts(rng, p)}
			if rng.Float64() < p.IPSetRuleFraction {
				r.dstSet = setIDs[rng.Intn(len(setIDs))]
			} else {
				r.dstNet = egressCIDR(nextCIDR)
				nextCIDR++
			}
			if ruleIdx == targetRule {
				// Make the target reachable on address and on a port of its own, and give it a
				// distinct action so a trace assertion is unambiguous. It carries both the tail
				// port and the popular port, so flows aimed at it differ only in how many rules
				// along the way survive the port comparison.
				r.action = "allow"
				r.dstNet = egressCIDR(nextCIDR)
				r.dstSet = ""
				r.dstPorts = append(r.dstPorts, EgressTailPort, p.PortWeights[0].Port)
				fx.egressTarget = &EgressTarget{
					Policy:      pol.name,
					RuleIndex:   j,
					Ordinal:     ruleIdx,
					RulesWalked: ruleIdx + 1,
					AddrInCIDR:  egressAddrInCIDR(nextCIDR),
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

func egressCIDR(n int) netip.Prefix {
	return netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", n>>8&0x7f, n&0xff))
}

func egressAddrInCIDR(n int) string {
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
