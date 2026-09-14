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
// measures the two paths on the collector's main goroutine:
//
//   - NewFlow: handleCtInfo for a tuple the collector has not seen, which creates the Data and
//     evaluates it inline. ns/flow is the main-loop cost of a new flow; flows/s is the rate one
//     goroutine could sustain if it did nothing else.
//   - Sweep: one full re-evaluation sweep over a fixed live population. ns/flow is the sweep's
//     cost per live flow.
//
// Both run with and without the verdict cache. The flows follow the sampler's model: a tenth miss
// every rule, the rest are aimed uniformly at the walk, and half repeat an earlier flow's endpoints
// on a new source port.
//
//	go test ./felix/collector/ -run '^$' -bench BenchmarkCollectorPolicyEval -benchmem -benchtime 200x -cpu 1

import (
	"fmt"
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
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
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
	for _, cache := range []struct {
		name string
		size int
	}{
		{"Uncached", 0},
		{"Cached", 1 << 16},
	} {
		for _, dir := range []policyscale.Direction{policyscale.Egress, policyscale.Ingress} {
			b.Run(fmt.Sprintf("NewFlow/%s/%s", dirTitle(dir), cache.name), func(b *testing.B) {
				pb := newPolicyEvalBench(fx, cache.size)
				defer pb.close()
				infos := pb.uniqueFlows(fx, dir, b.N, 1)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					pb.c.handleCtInfo(infos[i])
				}
				b.StopTimer()
				pb.report(b, 1)
			})
		}
		b.Run("Sweep/"+cache.name, func(b *testing.B) {
			pb := newPolicyEvalBench(fx, cache.size)
			defer pb.close()
			for _, ct := range pb.uniqueFlows(fx, policyscale.Egress, benchSweepFlows, 2) {
				pb.c.handleCtInfo(ct)
			}
			if got := len(pb.c.epStats); got != benchSweepFlows {
				b.Fatalf("expected %d live flows, got %d", benchSweepFlows, got)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pb.c.snapshotFlowsForRecalc()
				for !pb.c.processRecalcBatch(time.Hour) {
				}
			}
			b.StopTimer()
			pb.report(b, benchSweepFlows)
		})
	}
}

// policyEvalBench is a collector wired for policy evaluation only: a lookups cache that knows one
// local workload, a policy store loaded with the fixture and that workload's endpoint, no readers
// and no reporters. Its methods are called directly and the main loop is not running, so each
// measurement is exactly the work the loop would do.
type policyEvalBench struct {
	c     *collector
	stats *policystore.VerdictCacheStats
	local [16]byte
}

func newPolicyEvalBench(fx *policyscale.Fixture, cacheSize int) *policyEvalBench {
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
		FlowLogsFlushInterval: time.Millisecond,
		PolicyEvaluationMode:  string(apiv3.FlowLogsPolicyEvaluationModeContinuous),
		PolicyStoreManager:    psm,
	}).(*collector)
	return &policyEvalBench{c: c, stats: stats, local: local}
}

func (pb *policyEvalBench) close() {
	pb.c.ticker.Stop()
	if pb.c.tickerPolicyEval != nil {
		pb.c.tickerPolicyEval.Stop()
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

// report converts the timed loop into the KPIs: nanoseconds of main-loop time per flow and the
// flow rate one goroutine could sustain at that cost, plus the cache hit ratio when caching.
func (pb *policyEvalBench) report(b *testing.B, flowsPerOp int) {
	nsPerFlow := float64(b.Elapsed().Nanoseconds()) / float64(b.N) / float64(flowsPerOp)
	b.ReportMetric(nsPerFlow, "ns/flow")
	b.ReportMetric(1e9/nsPerFlow, "flows/s")
	if pb.stats != nil {
		total := pb.stats.Hits.Load() + pb.stats.Misses.Load()
		b.ReportMetric(float64(pb.stats.Hits.Load())/float64(max(total, 1)), "hit-ratio")
	}
}

func dirTitle(d policyscale.Direction) string {
	if d == policyscale.Egress {
		return "Egress"
	}
	return "Ingress"
}
