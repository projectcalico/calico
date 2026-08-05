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

// Benchmark for Evaluate() against a single-tier egress allow-list, the second rule-set shape
// measured in production (the first is in bench_test.go). All data is synthetic; the scale
// parameters and distributions below are anonymized measurements from a policy dump.
//
//	go test ./app-policy/checker/ -run '^$' -bench BenchmarkEvaluateEgressAllowList \
//	    -benchmem -benchtime 100x -cpu 1
//
// Shape: one tier, ~301 policies with no selector (so all of them apply to every endpoint),
// ~18,600 egress rules, almost all Pass. The tier is a destination allow-list: match a rule
// and leave the tier, match nothing and the tier default denies. Every rule's source block is
// empty; each matches a destination address plus a handful of destination ports.
//
// The three cases below must be read separately, because criterion ordering helps them by
// different amounts. A flow whose port is shared by few rules is rejected on the port
// comparison almost everywhere and never pays for the address criteria; a flow on a popular
// port pays the address criteria on every rule that shares it; and a denied flow walks the
// whole tier no matter what, so ordering can only reduce its per-rule cost, never its scan
// depth. Averaging the three hides that.

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

const (
	egressNumPolicies    = 301
	egressRulesPerPolicy = 62 // 18,662 rules.

	// Fraction of rules whose destination is a selector, which reaches Dikastes as an IP set
	// reference; the rest carry a CIDR. Measured: 4,644 of 18,675.
	egressIPSetRuleFraction = 0.25

	// Where in the walk the rule that matches sits, as a fraction of the whole tier. Real
	// flows match at every depth; this picks one representative depth so the two matching
	// cases are comparable with each other.
	egressTargetDepth = 0.65

	// The flow. The denied case keeps this destination, which no rule's CIDR contains; the
	// matching cases replace it with an address inside the target rule's CIDR.
	egressSourceIP   = "192.0.2.10"
	egressDeniedIP   = "198.51.100.20"
	egressSourcePort = 45000
)

// egressPortWeights reproduces the measured head of the port distribution: the fraction of
// rules whose destination ports include each of these. 443 appears in 3,395 of 18,675 rules,
// 11001 in 2,289, 27054 in 2,281 and 80 in 1,505. Rules not drawing a head port get ports from
// a long tail of otherwise-unique values, so a tail port is shared by only a rule or two.
var egressPortWeights = []struct {
	port     int32
	fraction float64
}{
	{443, 0.182},
	{11001, 0.123},
	{27054, 0.122},
	{80, 0.081},
}

// egressPortsPerRule is the measured spread of destination ports per rule: median 2, mean ~5.
var egressPortsPerRule = []struct {
	count    int
	fraction float64
}{
	{1, 0.25},
	{2, 0.45},
	{3, 0.15},
	{8, 0.10},
	{20, 0.05},
}

func BenchmarkEvaluateEgressAllowList(b *testing.B) {
	// A flow on a port few rules share: rejected on the port comparison nearly everywhere.
	b.Run("TailPort", func(b *testing.B) {
		benchEvaluateEgressAllowList(b, egressTailPortFlow)
	})
	// A flow on the most popular port: ~18% of rules share it and go on to the address check.
	b.Run("PopularPort", func(b *testing.B) {
		benchEvaluateEgressAllowList(b, egressPopularPortFlow)
	})
	// No rule matches, so the walk covers the whole tier and ends in the tier default deny.
	// Ordering cannot reduce the scan depth here, only the cost of each rejected rule.
	b.Run("Denied", func(b *testing.B) {
		benchEvaluateEgressAllowList(b, egressDeniedFlow)
	})
}

// egressCase is what one benchmark case measures: the flow, how many rules the walk is
// expected to visit, and whether a rule is expected to match it.
type egressCase struct {
	flow        *MockFlow
	rulesWalked int
	matches     bool
}

// egressCaseFunc builds one case from the fixture's target rule.
type egressCaseFunc func(target egressTarget) egressCase

func egressTailPortFlow(target egressTarget) egressCase {
	return egressCase{
		flow:        egressFlow(target.addrInCIDR, target.tailPort),
		rulesWalked: target.rulesWalked,
		matches:     true,
	}
}

func egressPopularPortFlow(target egressTarget) egressCase {
	return egressCase{
		flow:        egressFlow(target.addrInCIDR, egressPortWeights[0].port),
		rulesWalked: target.rulesWalked,
		matches:     true,
	}
}

func egressDeniedFlow(_ egressTarget) egressCase {
	return egressCase{
		flow:        egressFlow(egressDeniedIP, egressPortWeights[0].port),
		rulesWalked: egressNumPolicies * egressRulesPerPolicy,
	}
}

func egressFlow(destIP string, destPort int32) *MockFlow {
	return &MockFlow{
		SourceIP:   net.ParseIP(egressSourceIP),
		DestIP:     net.ParseIP(destIP),
		SourcePort: egressSourcePort,
		DestPort:   int(destPort),
		Protocol:   6, // TCP
	}
}

func benchEvaluateEgressAllowList(b *testing.B, caseFor egressCaseFunc) {
	_, restoreLogging := withBenchLogging(log.WarnLevel)
	defer restoreLogging()

	store, ep, target := buildEgressAllowListStore()
	c := caseFor(target)

	// Pre-flight outside the timed loop: prove the walk is the one the case intends, so that
	// a fixture change cannot silently turn a full walk into an early exit.
	trace := Evaluate(rules.RuleDirEgress, store, ep, c.flow)
	if c.matches {
		if len(trace) != 1 || trace[0].Action != rules.RuleActionAllow || trace[0].Index != target.ruleIndex {
			b.Fatalf("expected an allow from the target rule at index %d, got %v", target.ruleIndex, trace)
		}
	} else if len(trace) != 1 || trace[0].Action != rules.RuleActionDeny || trace[0].Index != tierDefaultActionIndex {
		b.Fatalf("expected a full walk ending in the tier default deny, got %v", trace)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchTraceSink = Evaluate(rules.RuleDirEgress, store, ep, c.flow)
	}
	b.StopTimer()
	b.ReportMetric(float64(c.rulesWalked), "rules/op")
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(c.rulesWalked), "ns/rule")
}

// egressTarget describes the one rule in the fixture that a matching flow is built to hit.
type egressTarget struct {
	ruleIndex   int    // Index of the rule within its policy, for the trace assertion.
	addrInCIDR  string // An address inside the rule's destination CIDR.
	tailPort    int32  // A port on the rule that few other rules share.
	rulesWalked int    // Rules visited before and including it.
}

// buildEgressAllowListStore builds the policy store and the endpoint whose single tier applies
// every policy, and returns the target rule a matching flow is aimed at.
//
// Destination CIDRs are handed out sequentially rather than at random so that no rule except
// the target can contain the matching flow's address: a second rule matching earlier would
// shorten the walk and make the case measure something other than what it claims to.
func buildEgressAllowListStore() (*policystore.PolicyStore, *proto.WorkloadEndpoint, egressTarget) {
	rng := rand.New(rand.NewSource(20200))
	store := policystore.NewPolicyStore()
	setIDs := makeEgressIPSets(store)

	numRules := egressNumPolicies * egressRulesPerPolicy
	targetRule := int(float64(numRules) * egressTargetDepth)

	tier := &proto.TierInfo{Name: "perimeter", DefaultAction: "Deny"}
	var target egressTarget
	nextCIDR := 0
	ruleIdx := 0
	for i := 0; i < egressNumPolicies; i++ {
		policyID := &proto.PolicyID{Name: fmt.Sprintf("egress-%03d", i), Kind: v3.KindGlobalNetworkPolicy}
		policy := &proto.Policy{Tier: tier.Name}
		for j := 0; j < egressRulesPerPolicy; j++ {
			// All rules are Pass bar the target: a rule's action is only consulted once it
			// matches, so the action mix does not affect the walk.
			rule := &proto.Rule{Action: "pass", DstPorts: makeEgressRulePorts(rng)}
			if rng.Float64() < egressIPSetRuleFraction {
				rule.DstIpSetIds = []string{setIDs[rng.Intn(len(setIDs))]}
			} else {
				rule.DstNet = []string{fmt.Sprintf("10.%d.%d.0/24", nextCIDR>>8&0xff, nextCIDR&0xff)}
				nextCIDR++
			}
			if ruleIdx == targetRule {
				// Make the target reachable on address and on a port of its own, and give it
				// a distinct action so the trace assertion is unambiguous.
				rule.Action = "allow"
				rule.DstNet = []string{fmt.Sprintf("10.%d.%d.0/24", nextCIDR>>8&0xff, nextCIDR&0xff)}
				rule.DstIpSetIds = nil
				// Carry both ports the matching cases use, so they differ only in how many
				// rules along the way survive the port comparison.
				rule.DstPorts = append(rule.DstPorts,
					&proto.PortRange{First: egressTailPort, Last: egressTailPort},
					&proto.PortRange{First: egressPortWeights[0].port, Last: egressPortWeights[0].port},
				)
				target = egressTarget{
					ruleIndex:   j,
					addrInCIDR:  fmt.Sprintf("10.%d.%d.7", nextCIDR>>8&0xff, nextCIDR&0xff),
					tailPort:    egressTailPort,
					rulesWalked: ruleIdx + 1,
				}
				nextCIDR++
			}
			policy.OutboundRules = append(policy.OutboundRules, rule)
			ruleIdx++
		}
		store.PolicyByID[types.ProtoToPolicyID(policyID)] = policy
		tier.EgressPolicies = append(tier.EgressPolicies, policyID)
	}

	ep := &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{tier}}
	return store, ep, target
}

// egressTailPort is outside the range makeEgressRulePorts draws from, so only the target rule
// carries it — the extreme of the measured tail, where 90% of ports are on 5 rules or fewer.
const egressTailPort = 60999

// makeEgressRulePorts picks a rule's destination ports: the measured head with its measured
// frequency, topped up from a wide tail.
func makeEgressRulePorts(rng *rand.Rand) []*proto.PortRange {
	var ports []int32
	for _, w := range egressPortWeights {
		if rng.Float64() < w.fraction {
			ports = append(ports, w.port)
		}
	}
	for _, n := range egressPortsPerRule {
		if rng.Float64() < n.fraction {
			for len(ports) < n.count {
				ports = append(ports, int32(1024+rng.Intn(55000)))
			}
			break
		}
	}
	if len(ports) == 0 {
		ports = append(ports, int32(1024+rng.Intn(55000)))
	}

	ranges := make([]*proto.PortRange, 0, len(ports))
	for _, p := range ports {
		ranges = append(ranges, &proto.PortRange{First: p, Last: p})
	}
	return ranges
}

// makeEgressIPSets populates the store with the NET sets the selector-matching rules reference:
// 3,862 sets at a median of 3 members, none containing the flow's addresses. Members are /32s
// from 10.128.0.0/9, kept clear of the rule CIDRs handed out from 10.0.0.0/9.
func makeEgressIPSets(store *policystore.PolicyStore) []string {
	const numSets = 3862
	ids := make([]string, 0, numSets)
	member := 0
	for i := 0; i < numSets; i++ {
		id := fmt.Sprintf("s:egress-%04d", i)
		s := policystore.NewIPSet(proto.IPSetUpdate_NET)
		for j := 0; j < 3; j++ {
			s.AddString(fmt.Sprintf("10.%d.%d.%d/32", 128+(member>>16&0x7f), member>>8&0xff, member&0xff))
			member++
		}
		store.IPSetByID[id] = s
		ids = append(ids, id)
	}
	return ids
}
