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

package events

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/calc"
	collector "github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/rules"
)

var (
	hostIngressAllow = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "host", "",
		0, rules.RuleDirIngress, rules.RuleActionAllow)
	hostIngressDeny = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "host", "",
		1, rules.RuleDirIngress, rules.RuleActionDeny)
	podEgressPass = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "pod-pass", "",
		0, rules.RuleDirEgress, rules.RuleActionPass)
	podEgressAllow = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "pod-allow", "",
		0, rules.RuleDirEgress, rules.RuleActionAllow)

	// unresolvable stands for a rule ID that the lookups cache does not know.
	unresolvable = &calc.RuleID{}
)

// newTestListener returns a listener and the event rule IDs that it resolves
// to rids.
func newTestListener(rids ...*calc.RuleID) (*CollectorPolicyListener, [state.MaxRuleIDs]uint64) {
	prefixes := map[[64]byte]*calc.RuleID{}
	for i, rid := range rids {
		if rid != unresolvable {
			prefixes[[64]byte{byte('A' + i)}] = rid
		}
	}
	lc := calc.NewLookupsCache()
	lc.EnableID64()
	lc.SetMockData(nil, prefixes, nil, nil)

	var ids [state.MaxRuleIDs]uint64
	for i, rid := range rids {
		ids[i] = lc.GetID64FromNFLOGPrefix([64]byte{byte('A' + i)})
		if rid == unresolvable {
			ids[i] = 0xdead
		}
	}
	return NewCollectorPolicyListener(lc), ids
}

func verdict(ruleIDs [state.MaxRuleIDs]uint64, n int, transitPolicyHits uint8) PolicyVerdict {
	return PolicyVerdict{
		TransitPolicyHits: transitPolicyHits,
		SrcAddr:           net.ParseIP("10.65.0.1").To4(),
		DstAddr:           net.ParseIP("8.8.8.8").To4(),
		PostNATDstAddr:    net.ParseIP("8.8.8.8").To4(),
		SrcPort:           12345,
		DstPort:           53,
		PostNATDstPort:    53,
		IPProto:           17,
		IPSize:            60,
		RulesHit:          uint32(n),
		RuleIDs:           ruleIDs,
	}
}

func ruleIDsOf(hits []collector.RuleHit) []*calc.RuleID {
	var rids []*calc.RuleID
	for _, h := range hits {
		rids = append(rids, h.RuleID)
	}
	return rids
}

func TestPacketInfoKeepsOnlyTheEndpointsOwnHits(t *testing.T) {
	for _, tc := range []struct {
		name              string
		hits              []*calc.RuleID
		transitPolicyHits uint8
		// ok is false if the event has no hits to report.
		ok   bool
		dir  rules.RuleDir
		kept []*calc.RuleID
	}{
		{
			name:              "transit hits then the workload's",
			hits:              []*calc.RuleID{hostIngressAllow, podEgressPass, podEgressAllow},
			transitPolicyHits: 1 + 1,
			ok:                true,
			dir:               rules.RuleDirEgress,
			kept:              []*calc.RuleID{podEgressPass, podEgressAllow},
		},
		{
			// A transit hit can share the endpoint's direction, e.g. in a
			// host interface's program.
			name:              "transit hit in the endpoint's direction",
			hits:              []*calc.RuleID{hostIngressAllow, hostIngressDeny},
			transitPolicyHits: 1 + 1,
			ok:                true,
			dir:               rules.RuleDirIngress,
			kept:              []*calc.RuleID{hostIngressDeny},
		},
		{
			name:              "no transit hits",
			hits:              []*calc.RuleID{podEgressPass, podEgressAllow},
			transitPolicyHits: 0 + 1,
			ok:                true,
			dir:               rules.RuleDirEgress,
			kept:              []*calc.RuleID{podEgressPass, podEgressAllow},
		},
		{
			name:              "transit policy ended the program",
			hits:              []*calc.RuleID{hostIngressAllow, hostIngressDeny},
			transitPolicyHits: state.TransitPolicyHitsAll,
		},
		{
			name:              "every hit is transit",
			hits:              []*calc.RuleID{hostIngressAllow},
			transitPolicyHits: 1 + 1,
		},
		{
			name:              "transit hits fill every slot",
			hits:              []*calc.RuleID{hostIngressAllow},
			transitPolicyHits: state.MaxRuleIDs + 1,
		},
		{
			name:              "host-* normal policy then the workload's",
			hits:              []*calc.RuleID{hostIngressAllow, podEgressAllow},
			transitPolicyHits: 0 + 1,
			ok:                true,
			dir:               rules.RuleDirEgress,
			kept:              []*calc.RuleID{podEgressAllow},
		},
		{
			name:              "transit, then host-* normal policy, then the workload's",
			hits:              []*calc.RuleID{podEgressPass, hostIngressAllow, podEgressAllow},
			transitPolicyHits: 1 + 1,
			ok:                true,
			dir:               rules.RuleDirEgress,
			kept:              []*calc.RuleID{podEgressAllow},
		},
		{
			// For traffic to the host, host-* normal policy can end the
			// program; its hits stay, in their own direction.
			name:              "only host-* normal policy",
			hits:              []*calc.RuleID{hostIngressAllow, hostIngressDeny},
			transitPolicyHits: 0 + 1,
			ok:                true,
			dir:               rules.RuleDirIngress,
			kept:              []*calc.RuleID{hostIngressAllow, hostIngressDeny},
		},
		{
			name:              "older program with hits in both directions",
			hits:              []*calc.RuleID{hostIngressAllow, podEgressPass, podEgressAllow},
			transitPolicyHits: state.TransitPolicyHitsUnknown,
			ok:                true,
			dir:               rules.RuleDirEgress,
			kept:              []*calc.RuleID{podEgressPass, podEgressAllow},
		},
		{
			name:              "older program with hits in one direction",
			hits:              []*calc.RuleID{hostIngressDeny},
			transitPolicyHits: state.TransitPolicyHitsUnknown,
			ok:                true,
			dir:               rules.RuleDirIngress,
			kept:              []*calc.RuleID{hostIngressDeny},
		},
		{
			name:              "no hits resolve",
			hits:              []*calc.RuleID{unresolvable},
			transitPolicyHits: 0 + 1,
		},
		{
			name:              "only the transit hits resolve",
			hits:              []*calc.RuleID{hostIngressAllow, unresolvable},
			transitPolicyHits: 1 + 1,
		},
		{
			name:              "last hit does not resolve",
			hits:              []*calc.RuleID{hostIngressAllow, podEgressAllow, unresolvable},
			transitPolicyHits: 0 + 1,
			ok:                true,
			dir:               rules.RuleDirEgress,
			kept:              []*calc.RuleID{podEgressAllow, nil},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			l, ids := newTestListener(tc.hits...)

			pi, ok := l.PacketInfo(verdict(ids, len(tc.hits), tc.transitPolicyHits))

			Expect(ok).To(Equal(tc.ok))
			if !tc.ok {
				return
			}
			Expect(pi.Direction).To(Equal(tc.dir))
			Expect(ruleIDsOf(pi.RuleHits)).To(Equal(tc.kept))
		})
	}
}

// Converting an event allocates only the hits it keeps.
func TestPacketInfoAllocations(t *testing.T) {
	RegisterTestingT(t)
	l, ids := newTestListener(hostIngressAllow, podEgressPass, podEgressAllow)

	e := verdict(ids, 3, 1+1)

	Expect(testing.AllocsPerRun(100, func() { l.PacketInfo(e) })).To(Equal(1.0))
}
