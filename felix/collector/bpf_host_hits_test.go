//go:build !windows

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

package collector

import (
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf/events"
	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
)

// These tests feed the collector the policy events of a workload's BPF
// program with host-* present: host-* hits, in the opposite direction, then
// the workload's own.  Flows are not reported against host endpoints, so the
// host-* hits must reach no trace; before the listener split them off, they
// were resolved against a workload's policy.

var (
	// Host-* ingress policy.
	gpIngressAllow = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "gp", "",
		0, rules.RuleDirIngress, rules.RuleActionAllow)

	// The pod's egress policy: t1 holds only a staged policy.
	podStagedT1 = calc.PolicyID{Name: "sp", Kind: v3.KindStagedGlobalNetworkPolicy}
	podAllow    = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy1", "",
		0, rules.RuleDirEgress, rules.RuleActionAllow)
	gpEgressAllow = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "gp", "",
		0, rules.RuleDirEgress, rules.RuleActionAllow)

	// End-of-tier actions, as the BPF program reports them.
	t1IngressEOTPass      = calc.NewRuleID("", "t1", "", "", 0, rules.RuleDirIngress, rules.RuleActionPass)
	t1EgressEOTPass       = calc.NewRuleID("", "t1", "", "", 0, rules.RuleDirEgress, rules.RuleActionPass)
	defaultIngressEOTDeny = calc.NewRuleID("", "default", "", "", 0, rules.RuleDirIngress, rules.RuleActionDeny)

	// eventRuleIDs are the rule IDs the tests' events can carry.
	eventRuleIDs = []*calc.RuleID{
		gpIngressAllow, podAllow, gpEgressAllow, t1IngressEOTPass, t1EgressEOTPass, defaultIngressEOTDeny,
	}
)

func newHostHitsTestPod() *calc.LocalEndpointData {
	return &calc.LocalEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(localWlEPKey1, localWlEp1),
		Ingress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{},
			TierData:      map[string]*calc.TierData{},
		},
		Egress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{
				podStagedT1:            0,
				podAllow.PolicyID:      2,
				gpEgressAllow.PolicyID: 2,
			},
			TierData: map[string]*calc.TierData{
				"t1": {EndOfTierMatchIndex: 1},
				"default": {
					TierDefaultActionRuleID: calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy1", "",
						calc.RuleIndexTierDefaultAction, rules.RuleDirEgress, rules.RuleActionDeny),
					EndOfTierMatchIndex: 2,
				},
			},
			ProfileMatchIndex: 3,
		},
	}
}

// newHostHitsTestPeerPod returns a second local pod, which gp also selects.
func newHostHitsTestPeerPod() *calc.LocalEndpointData {
	return &calc.LocalEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(localWlEPKey2, localWlEp2),
		Ingress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{gpIngressAllow.PolicyID: 0},
			TierData: map[string]*calc.TierData{
				"default": {
					TierDefaultActionRuleID: calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "gp", "",
						calc.RuleIndexTierDefaultAction, rules.RuleDirIngress, rules.RuleActionDeny),
					EndOfTierMatchIndex: 0,
				},
			},
			ProfileMatchIndex: 1,
		},
		Egress: &calc.MatchData{
			PolicyMatches: map[calc.PolicyID]int{},
			TierData:      map[string]*calc.TierData{},
		},
	}
}

// hostHitsTest drives a collector with BPF policy events through the policy
// listener.
type hostHitsTest struct {
	c        *collector
	lc       *calc.LookupsCache
	listener *events.CollectorPolicyListener
	tuple    tuple.Tuple
}

// newHostHitsTest returns a test of a flow from the pod to dst.
func newHostHitsTest(t *testing.T, dst [16]byte) *hostHitsTest {
	t.Helper()
	epMap := map[[16]byte]calc.EndpointData{
		localIp1: newHostHitsTestPod(),
		localIp2: newHostHitsTestPeerPod(),
	}
	prefixes := map[[64]byte]*calc.RuleID{}
	for i, rid := range eventRuleIDs {
		prefixes[eventPrefix(i)] = rid
	}
	lc := calc.NewLookupsCache()
	lc.EnableID64()
	lc.SetMockData(epMap, prefixes, nil, nil)
	conf := &Config{
		AgeTimeout:            ageOutTimeout,
		InitialReportingDelay: 0,
		ExportingInterval:     time.Hour, // ticker not used
		FlowLogsFlushInterval: time.Hour,
	}
	return &hostHitsTest{
		c:        newCollector(lc, conf).(*collector),
		lc:       lc,
		listener: events.NewCollectorPolicyListener(lc),
		tuple:    tuple.Make(localIp1, dst, proto_tcp, srcPort, dstPort),
	}
}

func eventPrefix(i int) [64]byte {
	var pfx [64]byte
	copy(pfx[:], fmt.Sprintf("test-rule-%d", i))
	return pfx
}

// applyEvent applies one policy event of a packet of h.tuple: the pod's egress
// program's, with hostHits then podHits.
func (h *hostHitsTest) applyEvent(t *testing.T, hostHits, podHits []*calc.RuleID) {
	t.Helper()
	e := events.PolicyVerdict{
		SrcAddr:        net.IP(h.tuple.Src[:]).To4(),
		DstAddr:        net.IP(h.tuple.Dst[:]).To4(),
		PostNATDstAddr: net.IP(h.tuple.Dst[:]).To4(),
		SrcPort:        uint16(h.tuple.L4Src),
		DstPort:        uint16(h.tuple.L4Dst),
		PostNATDstPort: uint16(h.tuple.L4Dst),
		IPProto:        uint8(h.tuple.Proto),
		IPSize:         60,
		RulesHit:       uint32(len(hostHits) + len(podHits)),
		HostPolicyHits: uint8(len(hostHits) + 1),
	}
	if len(podHits) == 0 {
		e.HostPolicyHits = state.HostPolicyHitsAll
	}
	for i, rid := range slices.Concat(hostHits, podHits) {
		e.RuleIDs[i] = h.id(t, rid)
	}
	if pktInfo, ok := h.listener.PacketInfo(e); ok {
		h.c.applyPacketInfo(pktInfo)
	}
}

// id returns the BPF rule ID of one of eventRuleIDs.
func (h *hostHitsTest) id(t *testing.T, rid *calc.RuleID) uint64 {
	t.Helper()
	i := slices.Index(eventRuleIDs, rid)
	if i < 0 {
		t.Fatalf("rule ID %v not in eventRuleIDs", rid)
	}
	return h.lc.GetID64FromNFLOGPrefix(eventPrefix(i))
}

// traceHits returns a trace's recorded rule IDs by match index.
func traceHits(t *RuleTrace) map[int]*calc.RuleID {
	hits := map[int]*calc.RuleID{}
	for i, rid := range t.path {
		if rid != nil {
			hits[i] = rid
		}
	}
	return hits
}

func TestBPFHostHitsNotResolvedAgainstWorkloads(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dst      [16]byte
		hostHits []*calc.RuleID
		podHits  []*calc.RuleID
		egress   map[int]*calc.RuleID
	}{
		{
			// The pod's t1 would claim host-*'s end-of-tier pass by tier name.
			name:     "host-* end-of-tier pass in a tier the pod also has",
			dst:      utils.IpStrTo16Byte(publicIP1Str),
			hostHits: []*calc.RuleID{t1IngressEOTPass},
			podHits:  []*calc.RuleID{t1EgressEOTPass, podAllow},
			egress:   map[int]*calc.RuleID{1: t1EgressEOTPass, 2: podAllow},
		},
		{
			// gp applies to host-* (ingress) and to the pod (egress).
			name:     "host-* policy that also applies to the pod",
			dst:      utils.IpStrTo16Byte(publicIP1Str),
			hostHits: []*calc.RuleID{gpIngressAllow},
			podHits:  []*calc.RuleID{gpEgressAllow},
			egress:   map[int]*calc.RuleID{2: gpEgressAllow},
		},
		{
			// gp also selects the same-node peer.
			name:     "host-* policy that also applies to a same-node peer",
			dst:      localIp2,
			hostHits: []*calc.RuleID{gpIngressAllow},
			podHits:  []*calc.RuleID{podAllow},
			egress:   map[int]*calc.RuleID{2: podAllow},
		},
		{
			// Host-* ends the pod's program, so the event holds only host-*
			// hits, in the peer's direction.  The peer has policy in a tier
			// of the same name, so it would claim host-*'s end-of-tier drop.
			name:     "host-* end-of-tier drop to a same-node peer",
			dst:      localIp2,
			hostHits: []*calc.RuleID{defaultIngressEOTDeny},
			egress:   map[int]*calc.RuleID{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			h := newHostHitsTest(t, tc.dst)

			h.applyEvent(t, tc.hostHits, tc.podHits)

			data := h.c.epStats[h.tuple]
			g.Expect(data).NotTo(BeNil())
			g.Expect(traceHits(&data.IngressRuleTrace)).To(BeEmpty(), "a host-* hit reached the ingress trace")
			g.Expect(traceHits(&data.EgressRuleTrace)).To(Equal(tc.egress))
		})
	}
}
