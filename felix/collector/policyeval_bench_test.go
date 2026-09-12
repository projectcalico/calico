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

// BenchmarkCollectorPolicyEval is the collector-level benchmark of the pending-policy evaluation
// (K2 in felix/design/flow-logs-policy-evaluation.md). It drives a real collector, wired for
// evaluation only, with conntrack updates for flows drawn from the policyscale reference set, and
// measures the two paths that used to run on the collector's main goroutine:
//
//   - NewFlow: handleCtInfo for a tuple the collector has not seen, which creates the Data and
//     requests its evaluation. ns/flow is the main-loop cost of a new flow (with workers, the
//     request plus applying the results that came back); flows/s is the rate the main loop could
//     sustain at that cost; throughput is the rate at which flows actually received their verdict,
//     which with workers is bounded by the workers, without them equals flows/s.
//   - Sweep: one full re-evaluation sweep over a fixed live population, until every flow has its
//     new verdict. ns/flow is the wall time per live flow.
//
// The matrix is cache off/on × inline/workers. Flows follow the sampler's model: a tenth miss
// every rule, the rest are aimed uniformly at the walk, and half repeat an earlier flow's
// endpoints on a new source port.
//
//	go test ./felix/collector/ -run '^$' -bench BenchmarkCollectorPolicyEval -benchmem -benchtime 200x

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	clttypes "github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	ftypes "github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/hack/perf/perfdoc"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	// Set POLICY_EVAL_PERF_ARTIFACTS_DIR to have each case write a hack/perf document under it,
	// for the Lens trend store; CI does, through make bench-policy-eval.
	perfArtifactsEnvVar = "POLICY_EVAL_PERF_ARTIFACTS_DIR"
	perfFamily          = "benchmark_data_policy_eval"

	// benchLocalIP is the local workload's address: outside every generated CIDR and IP set, so no
	// rule matches on it and the walk depends only on the remote address and the ports.
	benchLocalIP = "172.16.0.1"
	// benchSweepFlows is the live population the sweep case covers.
	benchSweepFlows = 2000
)

func BenchmarkCollectorPolicyEval(b *testing.B) {
	oldLevel := log.GetLevel()
	log.SetLevel(log.WarnLevel)
	defer log.SetLevel(oldLevel)

	fx := policyscale.Build(policyscale.Composite())
	workers := max(runtime.NumCPU()-2, 2)
	for _, c := range []struct {
		name    string
		cache   int
		workers int
	}{
		{"Uncached/Inline", 0, 0},
		{"Cached/Inline", 1 << 16, 0},
		{"Uncached/Workers", 0, workers},
		{"Cached/Workers", 1 << 16, workers},
	} {
		for _, dir := range []policyscale.Direction{policyscale.Egress, policyscale.Ingress} {
			name := fmt.Sprintf("NewFlow/%s/%s", dirTitle(dir), c.name)
			b.Run(name, func(b *testing.B) {
				pb := newPolicyEvalBench(fx, c.cache, c.workers)
				defer pb.close()
				infos := pb.uniqueFlows(fx, dir, b.N, 1)
				b.ReportAllocs()
				rec := perfdoc.Start(b)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					pb.c.handleCtInfo(infos[i])
					pb.c.drainPolicyEvalResults()
				}
				b.StopTimer()
				loop := b.Elapsed()
				pb.awaitIdle()
				pb.report(b, rec, name, dir, 1, loop, time.Since(rec.Started()))
			})
		}
		b.Run("Sweep/"+c.name, func(b *testing.B) {
			pb := newPolicyEvalBench(fx, c.cache, c.workers)
			defer pb.close()
			for _, ct := range pb.uniqueFlows(fx, policyscale.Egress, benchSweepFlows, 2) {
				pb.c.handleCtInfo(ct)
				pb.c.drainPolicyEvalResults()
			}
			pb.awaitIdle()
			if got := len(pb.c.epStats); got != benchSweepFlows {
				b.Fatalf("expected %d live flows, got %d", benchSweepFlows, got)
			}
			b.ReportAllocs()
			rec := perfdoc.Start(b)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pb.c.snapshotFlowsForRecalc()
				for !pb.c.processRecalcBatch(time.Hour) {
					if pb.c.recalcStalled {
						// What the main loop does: wait for a result, then resume the sweep.
						pb.c.applyPolicyEvalResult(<-pb.c.evalPool.results)
						pb.c.drainPolicyEvalResults()
						pb.c.recalcStalled = false
					}
				}
				pb.awaitIdle()
			}
			b.StopTimer()
			pb.report(b, rec, "Sweep/"+c.name, policyscale.Egress, benchSweepFlows, b.Elapsed(), b.Elapsed())
		})
	}
}

// policyEvalBench is a collector wired for policy evaluation only: a lookups cache that knows one
// local workload, a policy store loaded with the fixture and that workload's endpoint, no readers
// and no reporters. Its methods are called directly and the main loop is not running, so each
// measurement is exactly the work the loop would do; with workers, the benchmark loop drains
// results as the main loop would.
type policyEvalBench struct {
	fx    *policyscale.Fixture
	c     *collector
	stats *policystore.VerdictCacheStats
	local [16]byte
}

func newPolicyEvalBench(fx *policyscale.Fixture, cacheSize, workers int) *policyEvalBench {
	key := model.WorkloadEndpointKey{Hostname: "localhost", OrchestratorID: "k8s", WorkloadID: "bench/target", EndpointID: "eth0"}
	wep := &model.WorkloadEndpoint{
		State:    "active",
		Name:     "calibench",
		IPv4Nets: []net.IPNet{utils.MustParseNet(benchLocalIP + "/32")},
	}
	ed := &calc.LocalEndpointData{CommonEndpointData: calc.CalculateCommonEndpointData(key, wep)}
	local := utils.IpStrTo16Byte(benchLocalIP)
	lm := newMockLookupsCache(map[[16]byte]calc.EndpointData{local: ed}, nil, nil, nil)

	var (
		opts  []policystore.PolicyStoreManagerOption
		stats *policystore.VerdictCacheStats
	)
	if cacheSize > 0 {
		stats = &policystore.VerdictCacheStats{}
		opts = append(opts, policystore.WithVerdictCache(cacheSize, stats))
	}
	psm := policystore.NewPolicyStoreManagerWithOpts(opts...)
	psm.DoWithLock(func(ps *policystore.PolicyStore) {
		fx.LoadStore(ps)
		ps.Endpoints[ftypes.WorkloadEndpointID{
			OrchestratorId: key.OrchestratorID,
			WorkloadId:     key.WorkloadID,
			EndpointId:     key.EndpointID,
		}] = fx.Endpoint()
	})
	psm.OnInSync()

	c := newCollector(lm, &Config{
		AgeTimeout:            time.Hour,
		InitialReportingDelay: time.Hour,
		ExportingInterval:     time.Hour,
		// Keeps the "evaluated recently" skip in processRecalcBatch below any sweep's duration,
		// so a sweep re-evaluates every live flow.
		FlowLogsFlushInterval:   time.Millisecond,
		PolicyEvaluationMode:    string(apiv3.FlowLogsPolicyEvaluationModeContinuous),
		PolicyStoreManager:      psm,
		PolicyEvaluationWorkers: workers,
		PolicyEvaluationBacklog: 4096,
	}).(*collector)
	return &policyEvalBench{fx: fx, c: c, stats: stats, local: local}
}

func (pb *policyEvalBench) close() {
	pb.c.ticker.Stop()
	if pb.c.tickerPolicyEval != nil {
		pb.c.tickerPolicyEval.Stop()
	}
	if pb.c.evalPool != nil {
		pb.c.evalPool.stopAndWait()
	}
}

// awaitIdle applies results until no flow has an evaluation in flight.
func (pb *policyEvalBench) awaitIdle() {
	if pb.c.evalPool == nil {
		return
	}
	for {
		pb.c.drainPolicyEvalResults()
		inFlight := 0
		for _, d := range pb.c.epStats {
			if d.evalInFlight {
				inFlight++
			}
		}
		if inFlight == 0 {
			return
		}
		pb.c.applyPolicyEvalResult(<-pb.c.evalPool.results)
	}
}

// uniqueFlows draws n flows from the sampler in the given direction and returns them as conntrack
// updates with the local workload as source (egress) or destination (ingress). Tuples are unique,
// so every update is a new flow to the collector; repeats in the sampler's model still share
// addresses and destination port, which is what the verdict cache keys on.
func (pb *policyEvalBench) uniqueFlows(fx *policyscale.Fixture, dir policyscale.Direction, n int, seed int64) []clttypes.ConntrackInfo {
	s := fx.NewSampler(seed, policyscale.FlowModel{Direction: dir, MissFraction: 0.1, RepeatFraction: 0.5})
	seen := make(map[tuple.Tuple]struct{}, n)
	infos := make([]clttypes.ConntrackInfo, 0, n)
	for len(infos) < n {
		f := s.Next()
		var src, dst [16]byte
		if dir == policyscale.Egress {
			src = pb.local
			copy(dst[:], f.DstIP.To16())
		} else {
			copy(src[:], f.SrcIP.To16())
			dst = pb.local
		}
		t := tuple.New(src, dst, f.Protocol, f.SrcPort, f.DstPort)
		if _, dup := seen[*t]; dup {
			continue
		}
		seen[*t] = struct{}{}
		infos = append(infos, clttypes.ConntrackInfo{
			Tuple:    *t,
			Counters: clttypes.ConntrackCounters{Packets: 1, Bytes: 64},
		})
	}
	return infos
}

// report converts the timed loop into the KPIs: nanoseconds of main-loop time per flow, the flow
// rate the main loop could sustain at that cost, the rate at which flows actually received their
// verdict, and the cache hit ratio when caching; and writes the hack/perf document when
// POLICY_EVAL_PERF_ARTIFACTS_DIR is set.
func (pb *policyEvalBench) report(b *testing.B, rec *perfdoc.Recorder, name string, dir policyscale.Direction, flowsPerOp int, loop, total time.Duration) {
	flows := float64(b.N) * float64(flowsPerOp)
	nsPerFlow := float64(loop.Nanoseconds()) / flows
	throughput := flows / total.Seconds()
	b.ReportMetric(nsPerFlow, "ns/flow")
	b.ReportMetric(1e9/nsPerFlow, "flows/s")
	b.ReportMetric(throughput, "throughput")
	fields := map[string]any{
		"test_name":        "policy_eval_collector",
		"case":             name,
		"direction":        dir.String(),
		"cached":           pb.stats != nil,
		"workers":          pb.workers(),
		"ns_per_flow":      nsPerFlow,
		"flows_per_s":      1e9 / nsPerFlow,
		"throughput":       throughput,
		"scale_live_flows": len(pb.c.epStats),
		"scale_rules":      pb.fx.Rules(dir),
		"scale_ipsets":     pb.fx.IPSets(),
	}
	if pb.stats != nil {
		total := pb.stats.Hits.Load() + pb.stats.Misses.Load()
		ratio := float64(pb.stats.Hits.Load()) / float64(max(total, 1))
		b.ReportMetric(ratio, "hit-ratio")
		fields["hit_ratio"] = ratio
	}
	rec.Finish(perfdoc.Dir(perfArtifactsEnvVar), perfFamily, "collector_"+strings.ReplaceAll(name, "/", "_"), fields)
}

func (pb *policyEvalBench) workers() int {
	if pb.c.evalPool == nil {
		return 0
	}
	return pb.c.config.PolicyEvaluationWorkers
}

func dirTitle(d policyscale.Direction) string {
	if d == policyscale.Egress {
		return "Egress"
	}
	return "Ingress"
}
