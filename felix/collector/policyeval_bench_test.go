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

// BenchmarkCollectorPolicyEval measures the pending-policy evaluation inside a real collector, on
// policyscale's Composite set: the main-loop time a node pays per flow, which a benchmark of the
// evaluation engine alone leaves out. The collector is wired for evaluation only (a
// lookups cache that knows one local workload, a policy store loaded with the set and that
// workload's endpoint, no readers and no reporters) and its methods are called directly, so the
// timed loop is exactly the work the main loop would do.
//
//   - NewFlow: conntrack updates for flows the collector hasn't seen, drawn from the sampler's
//     traffic model, each creating its Data and evaluating it. An op is a batch of flows, so the
//     number follows the model rather than whichever kind of flow one draw happened to be.
//   - Sweep: one full re-evaluation sweep over a fixed population of live flows.
//
// ns/flow is main-loop time per flow and flows/s the rate one goroutine could sustain at that
// cost; evals/flow and verdicts/s come from the collector's own evaluation counter. The cases time
// the evaluation inline on the main loop, as the collector does it today.
//
//	go test ./felix/collector/ -run '^$' -bench BenchmarkCollectorPolicyEval -benchmem -benchtime 10x -cpu 1
//
// Scaled up through POLICYSCALE_POLICIES and friends, a run can outlast go test's default
// 10-minute timeout (about 9.5 minutes at 10,000 policies and 10x); pass -timeout.

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	clttypes "github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/hack/perf/perfdoc"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	// benchLocalIP is the local workload's address. It is outside every generated CIDR and IP
	// set, so no rule matches on it and the walk depends only on the remote address and ports.
	benchLocalIP = "172.16.0.1"
	// benchNewFlowBatch is how many new flows one NewFlow op pushes.
	benchNewFlowBatch = 200
	// benchSweepFlows is the live population a sweep covers.
	benchSweepFlows = 2000
)

func BenchmarkCollectorPolicyEval(b *testing.B) {
	// The engine logs per rule at debug level, and an earlier test may have left logrus there:
	// at this policy count that buffers gigabytes of log.
	oldLevel := log.GetLevel()
	log.SetLevel(log.WarnLevel)
	defer log.SetLevel(oldLevel)

	fx := policyscale.Build(policyscale.ScaleFromEnv(policyscale.Composite()))
	for _, dir := range []policyscale.Direction{policyscale.Egress, policyscale.Ingress} {
		b.Run("NewFlow/"+dir.String(), func(b *testing.B) {
			pb := newPolicyEvalBench(b, fx)
			flows := pb.uniqueFlows(dir, b.N*benchNewFlowBatch, 1)
			before := policyEvalCount(policyEvalInitial)
			b.ReportAllocs()
			rec := perfdoc.Start(b)
			for i := 0; i < b.N; i++ {
				for _, f := range flows[i*benchNewFlowBatch : (i+1)*benchNewFlowBatch] {
					pb.c.handleCtInfo(f.ct)
				}
			}
			b.StopTimer()
			pb.report(b, rec, dir, flows, benchNewFlowBatch, policyEvalCount(policyEvalInitial)-before, nil)
		})
	}
	b.Run("Sweep", func(b *testing.B) {
		pb := newPolicyEvalBench(b, fx)
		flows := pb.uniqueFlows(policyscale.Egress, benchSweepFlows, 2)
		for _, f := range flows {
			pb.c.handleCtInfo(f.ct)
		}
		if got := len(pb.c.epStats); got != benchSweepFlows {
			b.Fatalf("expected %d live flows, got %d", benchSweepFlows, got)
		}
		// A sweep skips a flow evaluated less than this long ago, and back-to-back sweeps of a
		// fast evaluation would skip some, so each sweep re-evaluates every live flow only with
		// no minimum at all.
		pb.c.policyEvalMinInterval = 0
		before := policyEvalCount(policyEvalRecalc)
		b.ReportAllocs()
		rec := perfdoc.Start(b)
		for i := 0; i < b.N; i++ {
			pb.c.snapshotFlowsForRecalc()
			for !pb.c.processRecalcBatch(time.Hour) {
			}
		}
		b.StopTimer()
		live := len(pb.c.epStats)
		pb.report(b, rec, policyscale.Egress, flows, benchSweepFlows, policyEvalCount(policyEvalRecalc)-before, &live)
	})
}

// policyEvalBench is a collector wired for policy evaluation only, around a policyscale fixture.
type policyEvalBench struct {
	fx    *policyscale.Fixture
	c     *collector
	local [16]byte
}

func newPolicyEvalBench(b *testing.B, fx *policyscale.Fixture) *policyEvalBench {
	key := model.WorkloadEndpointKey{Hostname: "localhost", OrchestratorID: "k8s", WorkloadID: "bench/target", EndpointID: "eth0"}
	wep := &model.WorkloadEndpoint{
		State:    "active",
		Name:     "calibench",
		IPv4Nets: []net.IPNet{utils.MustParseNet(benchLocalIP + "/32")},
	}
	ed := &calc.LocalEndpointData{CommonEndpointData: calc.CalculateCommonEndpointData(key, wep)}
	local := utils.IpStrTo16Byte(benchLocalIP)
	lm := newMockLookupsCache(map[[16]byte]calc.EndpointData{local: ed}, nil, nil, nil)

	psm := policystore.NewPolicyStoreManager()
	psm.DoWithLock(func(ps *policystore.PolicyStore) {
		fx.LoadStore(ps)
		ps.Endpoints[workloadEndpointID(key)] = fx.Endpoint()
	})
	psm.OnInSync()

	c := newCollector(lm, &Config{
		AgeTimeout:            time.Hour,
		InitialReportingDelay: time.Hour,
		ExportingInterval:     time.Hour,
		// Keeps the "evaluated recently" skip in the sweep far below any sweep's duration, so
		// every sweep re-evaluates every live flow.
		FlowLogsFlushInterval: time.Millisecond,
		PolicyEvaluationMode:  string(apiv3.FlowLogsPolicyEvaluationModeContinuous),
		PolicyStoreManager:    psm,
	}).(*collector)
	pb := &policyEvalBench{fx: fx, c: c, local: local}
	pb.checkTraces(b)
	return pb
}

// benchFlow is a sampled flow as the collector sees it, a conntrack update, and as the fixture's
// oracle sees it, with the local workload's address in place of the sampler's.
type benchFlow struct {
	ct   clttypes.ConntrackInfo
	flow *policyscale.Flow
	// unmatched is whether the flow matches no rule, so its evaluation walks every rule.
	unmatched bool
}

// uniqueFlows draws n flows from the sampler, with the local workload as source (egress) or
// destination (ingress). Tuples are unique, so every update is a new flow to the collector; the
// sampler's repeats still share addresses and destination port with an earlier flow.
func (pb *policyEvalBench) uniqueFlows(dir policyscale.Direction, n int, seed int64) []benchFlow {
	s := pb.fx.NewSampler(seed, policyscale.FlowModel{Direction: dir, MissFraction: 0.1, RepeatFraction: 0.5})
	seen := make(map[tuple.Tuple]struct{}, n)
	flows := make([]benchFlow, 0, n)
	for len(flows) < n {
		f := s.Next()
		aimed := pb.fx.Expect(dir, f)
		if dir == policyscale.Egress {
			f.SrcIP = utils.MustParseIP(benchLocalIP).IP
		} else {
			f.DstIP = utils.MustParseIP(benchLocalIP).IP
		}
		// A flow aimed at a rule on the local side's address no longer matches it from the local
		// workload's address. Kept, it would be a miss the traffic model didn't ask for, so draw
		// again.
		verdict := pb.fx.Expect(dir, f)
		if !slices.Equal(verdict, aimed) {
			continue
		}
		var src, dst [16]byte
		copy(src[:], f.SrcIP.To16())
		copy(dst[:], f.DstIP.To16())
		t := tuple.New(src, dst, f.Protocol, f.SrcPort, f.DstPort)
		if _, dup := seen[*t]; dup {
			continue
		}
		seen[*t] = struct{}{}
		flows = append(flows, benchFlow{
			ct:        clttypes.ConntrackInfo{Tuple: *t, Counters: clttypes.ConntrackCounters{Packets: 1, Bytes: 64}},
			flow:      f,
			unmatched: len(verdict) == 1 && verdict[0].Index == policyscale.TierDefaultIndex,
		})
	}
	return flows
}

// checkTraces pushes a sample of flows through the benchmark's collector, checks each one's
// pending trace against the fixture's oracle, and then forgets the flows again. That way the
// benchmark is known to time real, correct evaluations rather than, say, flows whose endpoint the
// policy store doesn't know.
func (pb *policyEvalBench) checkTraces(b *testing.B) {
	for _, dir := range []policyscale.Direction{policyscale.Egress, policyscale.Ingress} {
		for _, f := range pb.uniqueFlows(dir, 20, 99) {
			pb.c.handleCtInfo(f.ct)
			data := pb.c.epStats[f.ct.Tuple]
			if data == nil {
				b.Fatalf("%v: no flow created", f.flow)
			}
			got := data.IngressPendingRuleIDs
			rd := rules.RuleDirIngress
			if dir == policyscale.Egress {
				got, rd = data.EgressPendingRuleIDs, rules.RuleDirEgress
			}
			want := pb.fx.Expect(dir, f.flow)
			if !traceMatches(got, want, rd) {
				b.Fatalf("%v: pending trace %v, the oracle expects %v", f.flow, got, want)
			}
		}
	}
	clear(pb.c.epStats)
}

// report converts the timed loop into the collector's numbers and, when CI asks for perf
// documents, writes one for the case. timed holds the flows the loop pushed or swept; live is the
// population a sweep covers, nil for the new-flow cases, whose population grows with b.N.
func (pb *policyEvalBench) report(b *testing.B, rec *perfdoc.Recorder, dir policyscale.Direction, timed []benchFlow, flowsPerOp int, evals float64, live *int) {
	flows := float64(b.N * flowsPerOp)
	seconds := b.Elapsed().Seconds()
	nsPerFlow := seconds * 1e9 / flows
	unmatched := 0
	for _, f := range timed {
		if f.unmatched {
			unmatched++
		}
	}
	b.ReportMetric(nsPerFlow, "ns/flow")
	b.ReportMetric(flows/seconds, "flows/s")
	b.ReportMetric(evals/flows, "evals/flow")
	b.ReportMetric(evals/seconds, "verdicts/s")
	b.ReportMetric(float64(unmatched)/float64(len(timed)), "unmatched")
	fields := map[string]any{
		"test_name":          "policy_eval_collector",
		"case":               b.Name(),
		"engine":             "Interpreted",
		"direction":          dir.String(),
		"flows_per_op":       flowsPerOp,
		"ns_per_flow":        nsPerFlow,
		"flows_per_s":        flows / seconds,
		"evals_per_flow":     evals / flows,
		"verdicts_per_s":     evals / seconds,
		"unmatched_fraction": float64(unmatched) / float64(len(timed)),
		"scale_policies":     pb.fx.Policies(dir),
		"scale_rules":        pb.fx.Rules(dir),
		"scale_ipsets":       pb.fx.IPSets(),
	}
	if live != nil {
		fields["scale_live_flows"] = *live
	}
	rec.Finish(os.Getenv(policyscale.PerfArtifactsEnvVar), policyscale.PerfFamily, b.Name(), fields)
}

func policyEvalCount(reason policyEvalReason) float64 {
	return testutil.ToFloat64(counterPolicyEvalFlows.WithLabelValues(string(reason)))
}

// traceMatches compares a pending trace with the oracle's verdicts.
func traceMatches(got []*calc.RuleID, want []policyscale.Verdict, dir rules.RuleDir) bool {
	if len(got) != len(want) {
		return false
	}
	for i, v := range want {
		id := got[i]
		if id.Tier != v.Tier || id.Name != v.Policy || id.Index != v.Index || id.Direction != dir ||
			!strings.EqualFold(id.Action.String(), v.Action) {
			return false
		}
	}
	return true
}
