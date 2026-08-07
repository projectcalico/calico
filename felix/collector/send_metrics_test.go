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
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/rules"
)

// A connection whose NFLOG verdict has not arrived yet must keep its counters. NFLOG is lossy under
// load, and checkEpStats force-reports after InitialReportingDelay, so clearing the deltas here used
// to discard the connection's traffic one tick at a time with nothing reported in exchange.
func TestSendMetricsKeepsCountersUntilVerdictArrives(t *testing.T) {
	c, rep := newSendMetricsCollector(t)

	tpl := *tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
	data := NewData(tpl, remoteEd1, localEd1)
	c.updateEpStatsCache(tpl, data)

	// Conntrack reports traffic before the verdict is known.
	data.SetConntrackCounters(10, 1000)
	data.SetConntrackCountersReverse(5, 500)

	c.sendMetrics(data, false)

	if len(rep.updates) != 0 {
		t.Fatalf("reported %d update(s) for a flow with no verdict: %+v", len(rep.updates), rep.updates)
	}
	if !data.IsDirty() {
		t.Error("data is no longer dirty, so the unreported counters will never be reported")
	}

	// More traffic arrives, then the verdict finally shows up.
	data.SetConntrackCounters(30, 3000)
	data.AddRuleID(ingressAllowRuleID, 0, 0, 0)

	c.sendMetrics(data, false)

	if len(rep.updates) != 1 {
		t.Fatalf("expected one update once the verdict arrived, got %d: %+v", len(rep.updates), rep.updates)
	}
	// Everything the connection sent, including what accumulated before the verdict, must be in the
	// delta that is finally reported.
	if got, want := rep.updates[0].InMetric.DeltaPackets, 30; got != want {
		t.Errorf("reported %d packets, want %d (counts from before the verdict were dropped)", got, want)
	}
	if got, want := rep.updates[0].InMetric.DeltaBytes, 3000; got != want {
		t.Errorf("reported %d bytes, want %d (counts from before the verdict were dropped)", got, want)
	}
	if data.IsDirty() {
		t.Error("data is still dirty after being reported")
	}
}

// An expired flow that never got a verdict really does lose its counters; that is unavoidable by
// then, but it must not be silent.
func TestSendMetricsCountsFlowsExpiringWithoutVerdict(t *testing.T) {
	c, _ := newSendMetricsCollector(t)

	tpl := *tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
	data := NewData(tpl, remoteEd1, localEd1)
	c.updateEpStatsCache(tpl, data)
	data.SetConntrackCounters(10, 1000)

	before := testutil.ToFloat64(counterFlowsExpiredWithoutVerdict)
	c.sendMetrics(data, true)
	after := testutil.ToFloat64(counterFlowsExpiredWithoutVerdict)

	if delta := after - before; delta != 1 {
		t.Errorf("felix_collector_flows_expired_without_verdict moved by %v, want 1", delta)
	}
}

// A reported NFLOG-only entry must end up clean, or checkEpStats redoes the whole report path for it
// on every tick for as long as it lives — O(entries) of wasted work per tick during a port scan.
func TestSendMetricsClearsDirtyFlagForNonConnections(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ruleID    *calc.RuleID
		wantDirty bool
	}{
		{"with a verdict, the entry is reported and left clean", ingressAllowRuleID, false},
		{"with no verdict, the entry stays dirty so it is retried", ingressPassRuleID, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newSendMetricsCollector(t)

			tpl := *tuple.New(remoteIp1, localIp1, proto_tcp, srcPort, dstPort)
			data := NewData(tpl, remoteEd1, localEd1)
			c.updateEpStatsCache(tpl, data)
			data.AddRuleID(tc.ruleID, 0, 1, 100)

			if data.IsConnection {
				t.Fatal("test precondition: entry should not be a connection")
			}
			if !data.IsDirty() {
				t.Fatal("test precondition: entry should be dirty after a rule hit")
			}

			c.sendMetrics(data, false)

			if data.IsDirty() != tc.wantDirty {
				t.Errorf("after reporting, IsDirty()=%v, want %v", data.IsDirty(), tc.wantDirty)
			}
		})
	}
}

var (
	ingressAllowRuleID = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy1", "",
		0, rules.RuleDirIngress, rules.RuleActionAllow)
	// A pass is not a verdict, so a trace holding only this has nothing to report yet.
	ingressPassRuleID = calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy1", "",
		0, rules.RuleDirIngress, rules.RuleActionPass)
)

func newSendMetricsCollector(t *testing.T) (*collector, *capturingReporter) {
	t.Helper()

	lm := newMockLookupsCache(map[[16]byte]calc.EndpointData{
		localIp1:  localEd1,
		remoteIp1: remoteEd1,
	}, nil, nil, nil)

	c := newCollector(lm, &Config{
		AgeTimeout:            10 * time.Second,
		InitialReportingDelay: 5 * time.Second,
		ExportingInterval:     time.Second,
		FlowLogsFlushInterval: 100 * time.Second,
	}).(*collector)

	rep := &capturingReporter{}
	c.RegisterMetricsReporter(rep)
	return c, rep
}

// capturingReporter keeps the metric updates whole, counters included, unlike the mockReporter in
// collector_test.go which strips them for easier comparison.
type capturingReporter struct {
	updates []metric.Update
}

func (r *capturingReporter) Start() error { return nil }

func (r *capturingReporter) Report(u any) error {
	r.updates = append(r.updates, u.(metric.Update))
	return nil
}
