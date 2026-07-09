//go:build !windows

// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// These tests verify that a flow whose rule trace verdict changes mid-flow is
// always expired from the per-action flow log aggregators. A leaked active
// reference is permanent: the aggregator re-exports the flow with zeroed
// statistics on every flush until Felix restarts, and downstream Goldmane /
// Whisker keep showing a phantom deny flow in every query window.

// muCapture mirrors FlowLogReporter routing into per-action aggregators,
// mimicking the goldmane dispatch pipeline.
type muCapture struct {
	t        *testing.T
	updates  []metric.Update
	denyAgg  *flowlog.Aggregator
	allowAgg *flowlog.Aggregator
}

func (m *muCapture) Start() error { return nil }
func (m *muCapture) Report(u any) error {
	mu := u.(metric.Update)
	m.updates = append(m.updates, mu)
	if err := m.denyAgg.FeedUpdate(&mu); err != nil {
		m.t.Errorf("denyAgg.FeedUpdate: %v", err)
	}
	if err := m.allowAgg.FeedUpdate(&mu); err != nil {
		m.t.Errorf("allowAgg.FeedUpdate: %v", err)
	}
	return nil
}

var (
	zombieDstKey = model.WorkloadEndpointKey{
		Hostname: "localhost", OrchestratorID: "orchestrator",
		WorkloadID: "monitoring/grafana-1", EndpointID: "ep1",
	}
	zombieSrcKey = model.WorkloadEndpointKey{
		OrchestratorID: "orchestrator",
		WorkloadID:     "monitoring/prometheus-1", EndpointID: "ep1",
	}
	zombieSrcEp = &calc.RemoteEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(zombieSrcKey, remoteWlEp1),
	}

	zombieEOTDenyHit = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "", "",
		calc.RuleIndexTierDefaultAction, rules.RuleDirIngress, rules.RuleActionDeny) // IsEndOfTier => converted to TierDefaultActionRuleID
	zombiePolicyAllow = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy1", "",
		0, rules.RuleDirIngress, rules.RuleActionAllow)
	zombieProfileAllow = calc.NewRuleID("", "", "kns.default", "",
		0, rules.RuleDirIngress, rules.RuleActionAllow) // IsProfile => applied at ProfileMatchIndex
	zombieUnknownPolicyAllow = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy-new", "",
		0, rules.RuleDirIngress, rules.RuleActionAllow) // not in PolicyMatches => dropped
)

// realistic single-default-tier layout as produced by CreateLocalEndpointData:
// all enforced policies and the EOT share index 0; profile match index is 1.
func newZombieTestEp() *calc.LocalEndpointData {
	eotDeny := calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy2", "",
		calc.RuleIndexTierDefaultAction, rules.RuleDirIngress, rules.RuleActionDeny)
	md := &calc.MatchData{
		PolicyMatches: map[calc.PolicyID]int{
			{Name: "policy1", Kind: v3.KindGlobalNetworkPolicy}: 0,
			{Name: "policy2", Kind: v3.KindGlobalNetworkPolicy}: 0,
		},
		TierData: map[string]*calc.TierData{
			"default": {TierDefaultActionRuleID: eotDeny, EndOfTierMatchIndex: 0},
		},
		ProfileMatchIndex: 1,
	}
	return &calc.LocalEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(zombieDstKey, localWlEp1),
		Ingress:            md,
		Egress:             md,
	}
}

func newZombieTestCollector(t *testing.T) (*collector, *muCapture) {
	t.Helper()
	epMap := map[[16]byte]calc.EndpointData{
		localIp1:  newZombieTestEp(),
		remoteIp1: zombieSrcEp,
	}
	lm := newMockLookupsCache(epMap, map[[64]byte]*calc.RuleID{}, nil, nil)
	conf := &Config{
		AgeTimeout:            200 * time.Millisecond,
		InitialReportingDelay: 0,
		ExportingInterval:     time.Hour, // ticker not used; we call checkEpStats directly
		FlowLogsFlushInterval: time.Hour,
	}
	c := newCollector(lm, conf).(*collector)
	cap := &muCapture{
		t:        t,
		denyAgg:  flowlog.NewAggregator().IncludePolicies(true).ForAction(rules.RuleActionDeny),
		allowAgg: flowlog.NewAggregator().IncludePolicies(true).ForAction(rules.RuleActionAllow),
	}
	c.RegisterMetricsReporter(cap)
	return c, cap
}

func ingressHit(t tuple.Tuple, rid *calc.RuleID) types.PacketInfo {
	return types.PacketInfo{
		Tuple:     t,
		Direction: rules.RuleDirIngress,
		RuleHits:  []types.RuleHit{{RuleID: rid, Hits: 1, Bytes: 60}},
	}
}

// assertDenyAggDrains runs flush cycles against the deny aggregator and fails
// if the final cycle still exports anything: a flow surviving repeated flushes
// with no incoming metric updates is a leaked reference that would be
// re-exported forever.
func assertDenyAggDrains(t *testing.T, cap *muCapture) {
	t.Helper()
	var last []*flowlog.FlowLog
	for range 4 {
		last = cap.denyAgg.GetAndCalibrate()
	}
	for _, fl := range last {
		t.Errorf("leaked flow in deny aggregator: action=%v reporter=%v pktsIn=%d numFlows=%d policies=%v",
			fl.Action, fl.Reporter, fl.PacketsIn, fl.NumFlows, fl.FlowEnforcedPolicySet)
	}
}

func denyThenReport(t *testing.T, c *collector, tup tuple.Tuple) {
	t.Helper()
	c.applyPacketInfo(ingressHit(tup, zombieEOTDenyHit))
	time.Sleep(5 * time.Millisecond) // let monotime advance past RuleUpdatedAt
	c.checkEpStats()                 // report (InitialReportingDelay=0)
	if data := c.epStats[tup]; data == nil || !data.Reported {
		t.Fatalf("setup: deny flow not reported, data=%v", data)
	}
}

func ageOut(t *testing.T, c *collector, tup tuple.Tuple) {
	t.Helper()
	time.Sleep(250 * time.Millisecond) // > AgeTimeout
	c.checkEpStats()
	if _, ok := c.epStats[tup]; ok {
		t.Fatalf("flow %v still in epStats after age timeout", tup)
	}
}

// A plain deny that just ages out must drain.
func TestDenyAggregatorDrains_PlainDeny(t *testing.T) {
	c, cap := newZombieTestCollector(t)
	tup := tuple.Make(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
	denyThenReport(t, c, tup)
	ageOut(t, c, tup)
	assertDenyAggDrains(t, cap)
}

// A deny -> allow verdict flip at the SAME match index (allow rule added to an
// existing policy) drains via RuleMatchIsDifferent.
func TestDenyAggregatorDrains_SameIndexVerdictFlip(t *testing.T) {
	c, cap := newZombieTestCollector(t)
	tup := tuple.Make(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
	denyThenReport(t, c, tup)
	c.applyPacketInfo(ingressHit(tup, zombiePolicyAllow)) // same idx 0 -> conflict -> expire+replace
	time.Sleep(5 * time.Millisecond)
	c.checkEpStats() // report new allow state
	ageOut(t, c, tup)
	assertDenyAggDrains(t, cap)
}

// Deny verdict at EOT idx 0, then profile allow at idx 1 (an empty slot). The
// verdict moves to a different match index, which must be treated as a rule
// change so the reported deny flow is expired. Previously this leaked the
// tuple in the deny aggregator forever.
func TestDenyAggregatorDrains_VerdictMovesToEmptySlot(t *testing.T) {
	c, cap := newZombieTestCollector(t)
	tup := tuple.Make(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
	denyThenReport(t, c, tup)
	c.applyPacketInfo(ingressHit(tup, zombieProfileAllow)) // profile idx 1, empty slot
	time.Sleep(5 * time.Millisecond)
	c.checkEpStats()
	ageOut(t, c, tup)
	assertDenyAggDrains(t, cap)
}

// An allow hit from a policy the (stale) MatchData does not know is dropped;
// the trace stays deny. Conntrack then marks the flow a connection; the flow
// must still drain when the conntrack entry expires.
func TestDenyAggregatorDrains_UnknownPolicyHitThenConntrack(t *testing.T) {
	c, cap := newZombieTestCollector(t)
	tup := tuple.Make(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
	denyThenReport(t, c, tup)
	c.applyPacketInfo(ingressHit(tup, zombieUnknownPolicyAllow)) // dropped: unknown PolicyID
	// conntrack now sees the (allowed) connection.
	data := c.getDataAndUpdateEndpoints(tup, false, false)
	c.applyConntrackStatUpdate(data, 10, 1000, 8, 800, false)
	time.Sleep(5 * time.Millisecond)
	c.checkEpStats() // reports conn stats with stale deny trace
	// conntrack entry expires later.
	data = c.getDataAndUpdateEndpoints(tup, true, false)
	c.applyConntrackStatUpdate(data, 12, 1200, 9, 900, true)
	time.Sleep(250 * time.Millisecond)
	c.checkEpStats()
	assertDenyAggDrains(t, cap)
}

// The endpoint's policy set changes (MatchData replaced, same key) and the
// flow now matches the profile at the NEW ProfileMatchIndex.
func TestDenyAggregatorDrains_MatchDataSwapProfileFlip(t *testing.T) {
	c, cap := newZombieTestCollector(t)
	tup := tuple.Make(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
	denyThenReport(t, c, tup)

	// Policies removed from endpoint: new MatchData with no tiers, profile idx 0.
	noPolEp := &calc.LocalEndpointData{
		CommonEndpointData: calc.CalculateCommonEndpointData(zombieDstKey, localWlEp1),
		Ingress: &calc.MatchData{
			PolicyMatches:     map[calc.PolicyID]int{},
			TierData:          map[string]*calc.TierData{},
			ProfileMatchIndex: 0,
		},
		Egress: &calc.MatchData{
			PolicyMatches:     map[calc.PolicyID]int{},
			TierData:          map[string]*calc.TierData{},
			ProfileMatchIndex: 0,
		},
	}
	c.luc.SetMockData(map[[16]byte]calc.EndpointData{
		localIp1:  noPolEp,
		remoteIp1: zombieSrcEp,
	}, nil, nil, nil)

	c.applyPacketInfo(ingressHit(tup, zombieProfileAllow)) // profile idx 0 -> conflict with EOT deny
	time.Sleep(5 * time.Millisecond)
	c.checkEpStats()
	ageOut(t, c, tup)
	assertDenyAggDrains(t, cap)
}
