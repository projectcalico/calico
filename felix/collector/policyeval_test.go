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

package collector

import (
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	clttypes "github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	ftypes "github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// evalTestCollector is a collector with one local workload (172.16.0.1) and one egress policy on
// it: allow to destination port 80, tier default deny. With workers > 0 the pool exists; it is
// only started when start is set, so tests can drive its queues by hand.
type evalTestCollector struct {
	c     *collector
	local [16]byte
	allow *calc.RuleID
	deny  *calc.RuleID
}

// quietLogs keeps the engine's per-rule debug logging out of these tests: another test in the
// package may have left logrus at debug level, and a composite-set evaluation at that level logs
// tens of thousands of lines per flow, which go test buffers in memory.
func quietLogs(t *testing.T) {
	old := log.GetLevel()
	log.SetLevel(log.WarnLevel)
	t.Cleanup(func() { log.SetLevel(old) })
}

func newEvalTestCollector(workers, backlog int, start bool) *evalTestCollector {
	key := model.WorkloadEndpointKey{Hostname: "localhost", OrchestratorID: "k8s", WorkloadID: "test/target", EndpointID: "eth0"}
	wep := &model.WorkloadEndpoint{State: "active", Name: "calitest", IPv4Nets: []net.IPNet{utils.MustParseNet("172.16.0.1/32")}}
	ed := &calc.LocalEndpointData{CommonEndpointData: calc.CalculateCommonEndpointData(key, wep)}
	local := utils.IpStrTo16Byte("172.16.0.1")
	lm := newMockLookupsCache(map[[16]byte]calc.EndpointData{local: ed}, nil, nil, nil)

	pID := &proto.PolicyID{Name: "p", Kind: v3.KindGlobalNetworkPolicy}
	psm := policystore.NewPolicyStoreManager()
	psm.DoWithLock(func(ps *policystore.PolicyStore) {
		ps.PolicyByID[ftypes.ProtoToPolicyID(pID)] = &proto.Policy{Tier: "t", OutboundRules: []*proto.Rule{
			{Action: "allow", DstPorts: []*proto.PortRange{{First: 80, Last: 80}}},
		}}
		ps.Endpoints[ftypes.WorkloadEndpointID{OrchestratorId: key.OrchestratorID, WorkloadId: key.WorkloadID, EndpointId: key.EndpointID}] = &proto.WorkloadEndpoint{
			Tiers: []*proto.TierInfo{{Name: "t", DefaultAction: "Deny", EgressPolicies: []*proto.PolicyID{pID}}},
		}
	})
	psm.OnInSync()

	c := newCollector(lm, &Config{
		AgeTimeout:            time.Hour,
		InitialReportingDelay: time.Hour,
		ExportingInterval:     time.Hour,
		FlowLogsFlushInterval: time.Hour,
		PolicyEvaluationMode:  "Continuous",
		PolicyStoreManager:    psm,
	}).(*collector)
	c.ticker.Stop()
	c.tickerPolicyEval.Stop()
	if workers > 0 {
		c.evalPool = newPolicyEvalPool(backlog)
		if start {
			c.evalPool.start(c, workers)
		}
	}
	return &evalTestCollector{
		c:     c,
		local: local,
		allow: calc.NewRuleID(v3.KindGlobalNetworkPolicy, "t", "p", "", 0, rules.RuleDirEgress, rules.RuleActionAllow),
		deny:  calc.NewRuleID(v3.KindGlobalNetworkPolicy, "t", "p", "", calc.RuleIndexTierDefaultAction, rules.RuleDirEgress, rules.RuleActionDeny),
	}
}

func (e *evalTestCollector) stop() {
	if e.c.evalPool != nil {
		e.c.evalPool.stopAndWait()
	}
}

// flow presents a new egress flow from the local workload to 10.1.2.3:dstPort and returns its Data.
func (e *evalTestCollector) flow(t *testing.T, srcPort, dstPort int) *Data {
	t.Helper()
	var dst [16]byte
	copy(dst[:], net.ParseIP("10.1.2.3").To16())
	tp := tuple.New(e.local, dst, 6, srcPort, dstPort)
	e.c.handleCtInfo(clttypes.ConntrackInfo{Tuple: *tp, Counters: clttypes.ConntrackCounters{Packets: 1, Bytes: 64}})
	data, ok := e.c.epStats[*tp]
	if !ok {
		t.Fatalf("no Data for %v", tp)
	}
	return data
}

// serveOne takes one request off a queue, evaluates it and returns the result, standing in for a
// worker.
func (e *evalTestCollector) serveOne(t *testing.T, queue chan policyEvalRequest) policyEvalResult {
	t.Helper()
	select {
	case req := <-queue:
		return e.c.computePendingTraces(req)
	default:
		t.Fatal("no request queued")
		return policyEvalResult{}
	}
}

func expectTrace(t *testing.T, got []*calc.RuleID, want ...*calc.RuleID) {
	t.Helper()
	if !equal(got, want) {
		t.Fatalf("pending trace %v, want %v", got, want)
	}
}

func TestPolicyEvalInlineWithoutWorkers(t *testing.T) {
	quietLogs(t)
	e := newEvalTestCollector(0, 0, false)
	if e.c.evalPool != nil {
		t.Fatal("pool created with no workers configured")
	}
	expectTrace(t, e.flow(t, 40000, 80).EgressPendingRuleIDs, e.allow)
	expectTrace(t, e.flow(t, 40001, 81).EgressPendingRuleIDs, e.deny)
}

func TestPolicyEvalOffLoop(t *testing.T) {
	quietLogs(t)
	e := newEvalTestCollector(2, 16, true)
	defer e.stop()

	a := e.flow(t, 40000, 80)
	b := e.flow(t, 40001, 81)
	for _, d := range []*Data{a, b} {
		if !d.evalInFlight || d.evalSeq != 1 || len(d.EgressPendingRuleIDs) != 0 {
			t.Fatalf("new flow not queued as expected: inFlight=%v seq=%d trace=%v", d.evalInFlight, d.evalSeq, d.EgressPendingRuleIDs)
		}
	}
	// Results arrive on the results channel; the main loop would drain them. Do that here.
	deadline := time.Now().Add(5 * time.Second)
	for a.evalInFlight || b.evalInFlight {
		if time.Now().After(deadline) {
			t.Fatal("results did not arrive")
		}
		select {
		case res := <-e.c.evalPool.results:
			e.c.applyPolicyEvalResult(res)
		case <-time.After(10 * time.Millisecond):
		}
	}
	expectTrace(t, a.EgressPendingRuleIDs, e.allow)
	expectTrace(t, b.EgressPendingRuleIDs, e.deny)
	if a.lastPolicyEvalAt == 0 || b.lastPolicyEvalAt == 0 {
		t.Fatal("lastPolicyEvalAt not set on apply")
	}
}

func TestPolicyEvalStaleResultsDropped(t *testing.T) {
	quietLogs(t)
	e := newEvalTestCollector(1, 16, false)
	stale := testutil.ToFloat64(counterPolicyEvalStale)

	// A newer request supersedes an older result.
	a := e.flow(t, 40000, 80)
	res := e.serveOne(t, e.c.evalPool.newFlows)
	a.evalSeq++
	e.c.applyPolicyEvalResult(res)
	if len(a.EgressPendingRuleIDs) != 0 || !a.evalInFlight {
		t.Fatalf("stale result was applied: %v", a.EgressPendingRuleIDs)
	}
	// The latest one is applied.
	res.seq = a.evalSeq
	e.c.applyPolicyEvalResult(res)
	expectTrace(t, a.EgressPendingRuleIDs, e.allow)
	if a.evalInFlight {
		t.Fatal("in-flight flag not cleared")
	}

	// A flow that is gone drops its result.
	b := e.flow(t, 40001, 80)
	res = e.serveOne(t, e.c.evalPool.newFlows)
	e.c.deleteDataFromEpStats(b)
	e.c.applyPolicyEvalResult(res)
	if len(b.EgressPendingRuleIDs) != 0 {
		t.Fatal("result applied to a deleted flow")
	}

	// A flow whose endpoints moved while in flight drops its result and is left for the sweep.
	d := e.flow(t, 40002, 80)
	res = e.serveOne(t, e.c.evalPool.newFlows)
	d.SrcEp = nil
	e.c.applyPolicyEvalResult(res)
	if len(d.EgressPendingRuleIDs) != 0 || d.evalInFlight || d.lastPolicyEvalAt != 0 {
		t.Fatalf("result applied after an endpoint change: trace=%v inFlight=%v last=%v", d.EgressPendingRuleIDs, d.evalInFlight, d.lastPolicyEvalAt)
	}

	if got := testutil.ToFloat64(counterPolicyEvalStale) - stale; got != 3 {
		t.Fatalf("stale results counted: %v, want 3", got)
	}
}

func TestPolicyEvalNewFlowFallsBackInlineWhenQueueFull(t *testing.T) {
	quietLogs(t)
	e := newEvalTestCollector(1, 1, false)
	inline := testutil.ToFloat64(counterPolicyEvalInline)

	queued := e.flow(t, 40000, 80)
	if !queued.evalInFlight || len(queued.EgressPendingRuleIDs) != 0 {
		t.Fatal("first flow should be queued")
	}
	direct := e.flow(t, 40001, 80)
	if direct.evalInFlight {
		t.Fatal("second flow should have been evaluated inline")
	}
	expectTrace(t, direct.EgressPendingRuleIDs, e.allow)
	if got := testutil.ToFloat64(counterPolicyEvalInline) - inline; got != 1 {
		t.Fatalf("inline evaluations counted: %v, want 1", got)
	}
	// The queued one still completes.
	e.c.applyPolicyEvalResult(e.serveOne(t, e.c.evalPool.newFlows))
	expectTrace(t, queued.EgressPendingRuleIDs, e.allow)
}

func TestSweepPausesWhenRecalcQueueFull(t *testing.T) {
	quietLogs(t)
	e := newEvalTestCollector(1, 2, false)
	deferred := testutil.ToFloat64(counterPolicyEvalDeferred)
	e.c.policyEvalMinInterval = 0 // every flow is due

	// Three flows, all evaluated (serve the queue by hand, then the fallback ones are inline).
	flows := []*Data{e.flow(t, 40000, 80), e.flow(t, 40001, 80), e.flow(t, 40002, 80)}
	for range 2 {
		e.c.applyPolicyEvalResult(e.serveOne(t, e.c.evalPool.newFlows))
	}
	for _, d := range flows {
		if d.evalInFlight {
			t.Fatal("flow still in flight before the sweep")
		}
	}

	e.c.snapshotFlowsForRecalc()
	if e.c.processRecalcBatch(time.Hour) {
		t.Fatal("sweep drained although the recalc queue holds two")
	}
	if !e.c.recalcStalled || len(e.c.recalcSnapshot) != 1 || len(e.c.evalPool.recalcs) != 2 {
		t.Fatalf("expected a stalled sweep with one flow left: stalled=%v left=%d queued=%d", e.c.recalcStalled, len(e.c.recalcSnapshot), len(e.c.evalPool.recalcs))
	}
	if got := testutil.ToFloat64(counterPolicyEvalDeferred) - deferred; got != 1 {
		t.Fatalf("deferred counted: %v, want 1", got)
	}

	// A result frees a slot; the main loop clears the stall and re-triggers the batch.
	e.c.applyPolicyEvalResult(e.serveOne(t, e.c.evalPool.recalcs))
	e.c.recalcStalled = false
	if !e.c.processRecalcBatch(time.Hour) {
		t.Fatal("sweep did not drain once a slot was free")
	}
	// Serve the rest and check every flow ended with its verdict and nothing in flight.
	for len(e.c.evalPool.recalcs) > 0 {
		e.c.applyPolicyEvalResult(e.serveOne(t, e.c.evalPool.recalcs))
	}
	for _, d := range flows {
		if d.evalInFlight {
			t.Fatal("flow left in flight after the sweep")
		}
		expectTrace(t, d.EgressPendingRuleIDs, e.allow)
	}
}

func TestSweepSkipsFlowsInFlight(t *testing.T) {
	quietLogs(t)
	e := newEvalTestCollector(1, 4, false)
	e.c.policyEvalMinInterval = 0
	d := e.flow(t, 40000, 80)
	if !d.evalInFlight {
		t.Fatal("flow should be queued")
	}
	e.c.snapshotFlowsForRecalc()
	if !e.c.processRecalcBatch(time.Hour) || len(e.c.evalPool.recalcs) != 0 || d.evalSeq != 1 {
		t.Fatalf("an in-flight flow was re-queued: recalcs=%d seq=%d", len(e.c.evalPool.recalcs), d.evalSeq)
	}
}

// TestPolicyEvalWorkersMatchInline runs the same flows on the composite reference set through a
// collector with workers and one without, and requires identical pending traces on every flow.
func TestPolicyEvalWorkersMatchInline(t *testing.T) {
	quietLogs(t)
	fx := policyscale.Build(policyscale.Composite())
	inline := newPolicyEvalBench(fx, 0, 0)
	defer inline.close()
	pooled := newPolicyEvalBench(fx, 1<<16, 4)
	defer pooled.close()

	var infos []clttypes.ConntrackInfo
	infos = append(infos, inline.uniqueFlows(fx, policyscale.Egress, 300, 5)...)
	infos = append(infos, inline.uniqueFlows(fx, policyscale.Ingress, 200, 6)...)
	for _, ct := range infos {
		inline.c.handleCtInfo(ct)
		pooled.c.handleCtInfo(ct)
		pooled.c.drainPolicyEvalResults()
	}
	pooled.awaitIdle()

	if len(inline.c.epStats) != len(infos) || len(pooled.c.epStats) != len(infos) {
		t.Fatalf("flow counts: inline %d pooled %d want %d", len(inline.c.epStats), len(pooled.c.epStats), len(infos))
	}
	mismatches := 0
	for tp, want := range inline.c.epStats {
		got := pooled.c.epStats[tp]
		if got == nil || !equal(got.IngressPendingRuleIDs, want.IngressPendingRuleIDs) || !equal(got.EgressPendingRuleIDs, want.EgressPendingRuleIDs) {
			mismatches++
			if mismatches <= 5 {
				t.Errorf("%v: pooled %v/%v, inline %v/%v", &tp, got.IngressPendingRuleIDs, got.EgressPendingRuleIDs, want.IngressPendingRuleIDs, want.EgressPendingRuleIDs)
			}
		}
	}
	if mismatches > 0 {
		t.Fatalf("%d of %d flows differ", mismatches, len(infos))
	}
}
