// Copyright (c) 2026 Tigera, Inc. All rights reserved.

//go:build loadtest

package fv

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/server"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/lib/std/time"
)

const (
	stormNodes         = 100
	stormBuckets       = 20
	stormBucketSeconds = 15
)

// stormEmissionsPerNode defaults to a tenth of a real five minute cache at 10k flows/sec,
// because the full load needs a couple of GB. Raise it with GOLDMANE_STORM_EMISSIONS.
var stormEmissionsPerNode = envInt("GOLDMANE_STORM_EMISSIONS", 3000)

var stormTotal = stormNodes * stormEmissionsPerNode

func envInt(name string, fallback int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// TestReplayStormBackpressure measures what a mass reconnect does to flows arriving live.
// Duplicates are dropped behind the receive channel rather than ahead of it, so a replay
// competes with real traffic.
func TestReplayStormBackpressure(t *testing.T) {
	for _, keys := range []int{1000, 150000} {
		t.Run(fmt.Sprintf("keys=%d", keys), func(t *testing.T) {
			measureReplayStorm(t, keys)
		})
	}
}

func measureReplayStorm(t *testing.T, keys int) {
	start := alignedBucketStart()
	byNode := buildStormLoad(keys, start)

	gm := goldmane.NewGoldmane()
	<-gm.Run(start)
	defer gm.Stop()

	// Prime the ring, so the storm below is a replay of flows already counted rather than
	// first delivery.
	before := aggrReceivedFlows(t)
	replayAll(t, gm, byNode)
	waitForDedupIngest(t, before+float64(stormTotal))

	// A node sending flows nobody has seen, for the whole duration of the storm. Its
	// latency is the cost the storm imposes on real traffic.
	live := &liveWriter{gm: gm, start: start}
	stop := live.run()

	droppedBefore := aggrDroppedFlows(t)
	stormStart := time.Now()
	replayAll(t, gm, byNode)
	storm := time.Since(stormStart)

	sent, blocked := stop()
	dropped := aggrDroppedFlows(t) - droppedBefore

	t.Logf("keys=%d: replayed %d flows in %s (%.0f/s), aggregator dropped %.0f",
		keys, stormTotal, storm, float64(stormTotal)/storm.Seconds(), dropped)
	t.Logf("keys=%d: live writer sent %d flows, receive blocked p50 %s p99 %s max %s",
		keys, sent, blocked.p50, blocked.p99, blocked.max)
}

// replayAll connects every node at once, which is the shape of a mass reconnect after a
// network blip.
func replayAll(t *testing.T, gm *goldmane.Goldmane, byNode map[string][]*proto.Flow) {
	t.Helper()
	var wg sync.WaitGroup
	for node, flows := range byNode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			collector := server.NewFlowCollector(gm)
			if err := collector.Connect(newReplayStream(node, 45026, flows)); err != nil {
				panic(err)
			}
		}()
	}
	wg.Wait()
}

// liveWriter stands in for a node that never disconnected, so its flows are all new.
type liveWriter struct {
	gm    *goldmane.Goldmane
	start int64

	done  chan struct{}
	sent  int
	waits []time.Duration
}

func (w *liveWriter) run() func() (int, latencies) {
	w.done = make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for i := 0; ; i++ {
			select {
			case <-w.done:
				return
			default:
			}
			f := stormFlow("live-node", i, 1<<30, w.start)
			began := time.Now()
			w.gm.Receive(types.ProtoToFlow(f), "live-node")
			w.waits = append(w.waits, time.Since(began))
			w.sent++
		}
	}()
	return func() (int, latencies) {
		close(w.done)
		<-finished
		return w.sent, summarize(w.waits)
	}
}

type latencies struct {
	p50, p99, max time.Duration
}

func summarize(d []time.Duration) latencies {
	if len(d) == 0 {
		return latencies{}
	}
	sorted := append([]time.Duration{}, d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return latencies{
		p50: sorted[len(sorted)/2],
		p99: sorted[len(sorted)*99/100],
		max: sorted[len(sorted)-1],
	}
}

// buildStormLoad gives every node its own emissions, drawn from a shared pool of flow keys
// so cardinality is set independently of the flow count.
func buildStormLoad(keys int, start int64) map[string][]*proto.Flow {
	byNode := make(map[string][]*proto.Flow, stormNodes)
	for n := range stormNodes {
		node := fmt.Sprintf("10.0.%d.%d", n/256, n%256)
		flows := make([]*proto.Flow, 0, stormEmissionsPerNode)
		for i := range stormEmissionsPerNode {
			flows = append(flows, stormFlow(node, i, (n*stormEmissionsPerNode+i)%keys, start))
		}
		byNode[node] = flows
	}
	return byNode
}

// stormFlow spreads emissions over the buckets a client would replay, and makes each one
// unique within its node by moving the end time.
func stormFlow(node string, i, key int, base int64) *proto.Flow {
	bucketStart := base - int64((i%stormBuckets)*stormBucketSeconds)
	return &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      fmt.Sprintf("client-%d", key),
			SourceNamespace: "storm-ns",
			SourceType:      proto.EndpointType_WorkloadEndpoint,
			DestName:        fmt.Sprintf("server-%d", key),
			DestNamespace:   "storm-ns",
			DestType:        proto.EndpointType_WorkloadEndpoint,
			DestPort:        8080,
			Proto:           "tcp",
			Reporter:        proto.Reporter_Src,
			Action:          proto.Action_Allow,
			Policies:        &proto.PolicyTrace{},
		},
		StartTime:               bucketStart,
		EndTime:                 bucketStart + stormBucketSeconds + int64(i),
		SourceLabels:            []string{"app=storm"},
		DestLabels:              []string{"app=storm"},
		PacketsIn:               10,
		PacketsOut:              10,
		BytesIn:                 1000,
		BytesOut:                1000,
		NumConnectionsStarted:   1,
		NumConnectionsCompleted: 1,
	}
}

// aggrDroppedFlows reads the counter the aggregator bumps when a flow cannot be queued
// within the receive deadline.
func aggrDroppedFlows(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != "goldmane_aggr_dropped_flows_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			return m.GetCounter().GetValue()
		}
	}
	return 0
}
