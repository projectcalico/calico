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
	hostIngressAllow = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "host-fwd", "",
		0, rules.RuleDirIngress, rules.RuleActionAllow)
	hostIngressDeny = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "host-fwd", "",
		1, rules.RuleDirIngress, rules.RuleActionDeny)
	podEgressPass = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "pod-pass", "",
		0, rules.RuleDirEgress, rules.RuleActionPass)
	podEgressAllow = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "pod-allow", "",
		0, rules.RuleDirEgress, rules.RuleActionAllow)
)

// newTestListener returns a listener that resolves the returned event rule
// IDs to rids.
func newTestListener(rids ...*calc.RuleID) (*CollectorPolicyListener, [state.MaxRuleIDs]uint64) {
	prefixes := map[[64]byte]*calc.RuleID{}
	for i, rid := range rids {
		prefixes[[64]byte{byte('A' + i)}] = rid
	}
	lc := calc.NewLookupsCache()
	lc.EnableID64()
	lc.SetMockData(nil, prefixes, nil, nil)

	var ids [state.MaxRuleIDs]uint64
	for i := range rids {
		ids[i] = lc.GetID64FromNFLOGPrefix([64]byte{byte('A' + i)})
	}
	return NewCollectorPolicyListener(lc), ids
}

func verdict(ruleIDs [state.MaxRuleIDs]uint64, n int, hostPolicyHits uint8) PolicyVerdict {
	return PolicyVerdict{
		HostPolicyHits: hostPolicyHits,
		SrcAddr:        net.ParseIP("10.65.0.1").To4(),
		DstAddr:        net.ParseIP("8.8.8.8").To4(),
		PostNATDstAddr: net.ParseIP("8.8.8.8").To4(),
		SrcPort:        12345,
		DstPort:        53,
		PostNATDstPort: 53,
		IPProto:        17,
		IPSize:         60,
		RulesHit:       uint32(n),
		RuleIDs:        ruleIDs,
	}
}

func ruleIDsOf(hits []collector.RuleHit) []*calc.RuleID {
	var rids []*calc.RuleID
	for _, h := range hits {
		rids = append(rids, h.RuleID)
	}
	return rids
}

func TestPacketInfoSplitsHostHitsFromWorkloadHits(t *testing.T) {
	for _, tc := range []struct {
		name           string
		hits           []*calc.RuleID
		hostPolicyHits uint8
		dir            rules.RuleDir
		host, workload []*calc.RuleID
	}{
		{
			name:           "workload program after host-* policy",
			hits:           []*calc.RuleID{hostIngressAllow, podEgressPass, podEgressAllow},
			hostPolicyHits: 1 + 1,
			dir:            rules.RuleDirEgress,
			host:           []*calc.RuleID{hostIngressAllow},
			workload:       []*calc.RuleID{podEgressPass, podEgressAllow},
		},
		{
			name:           "workload program without host-* hits",
			hits:           []*calc.RuleID{podEgressPass, podEgressAllow},
			hostPolicyHits: 0 + 1,
			dir:            rules.RuleDirEgress,
			workload:       []*calc.RuleID{podEgressPass, podEgressAllow},
		},
		{
			name:           "workload program ended by host-* policy",
			hits:           []*calc.RuleID{hostIngressDeny},
			hostPolicyHits: state.HostPolicyHitsAll,
			dir:            rules.RuleDirEgress,
			host:           []*calc.RuleID{hostIngressDeny},
		},
		{
			name:           "workload program whose host-* hits fill every slot",
			hits:           []*calc.RuleID{hostIngressAllow},
			hostPolicyHits: state.MaxRuleIDs + 1,
			dir:            rules.RuleDirEgress,
			host:           []*calc.RuleID{hostIngressAllow},
		},
		{
			name:           "host interface program",
			hits:           []*calc.RuleID{hostIngressDeny},
			hostPolicyHits: state.HostPolicyHitsNone,
			dir:            rules.RuleDirIngress,
			workload:       []*calc.RuleID{hostIngressDeny},
		},
		{
			name:           "older program with hits in both directions",
			hits:           []*calc.RuleID{hostIngressAllow, podEgressPass, podEgressAllow},
			hostPolicyHits: state.HostPolicyHitsUnknown,
			dir:            rules.RuleDirEgress,
			host:           []*calc.RuleID{hostIngressAllow},
			workload:       []*calc.RuleID{podEgressPass, podEgressAllow},
		},
		{
			name:           "older program with hits in one direction",
			hits:           []*calc.RuleID{hostIngressDeny},
			hostPolicyHits: state.HostPolicyHitsUnknown,
			dir:            rules.RuleDirIngress,
			workload:       []*calc.RuleID{hostIngressDeny},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			l, ids := newTestListener(tc.hits...)

			pi, ok := l.PacketInfo(verdict(ids, len(tc.hits), tc.hostPolicyHits))

			Expect(ok).To(BeTrue())
			Expect(pi.Direction).To(Equal(tc.dir))
			Expect(ruleIDsOf(pi.HostRuleHits)).To(Equal(tc.host))
			Expect(ruleIDsOf(pi.RuleHits)).To(Equal(tc.workload))
		})
	}
}

// Converting an event allocates only its rule hits, split or not.
func TestPacketInfoAllocations(t *testing.T) {
	RegisterTestingT(t)
	single, singleIDs := newTestListener(podEgressPass, podEgressAllow)
	mixed, mixedIDs := newTestListener(hostIngressAllow, podEgressPass, podEgressAllow)

	singleEvent, mixedEvent := verdict(singleIDs, 2, 0+1), verdict(mixedIDs, 3, 1+1)

	Expect(testing.AllocsPerRun(100, func() { single.PacketInfo(singleEvent) })).To(Equal(1.0))
	Expect(testing.AllocsPerRun(100, func() { mixed.PacketInfo(mixedEvent) })).To(Equal(1.0))
}
