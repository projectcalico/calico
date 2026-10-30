// Copyright (c) 2026 Tigera, Inc. All rights reserved.

//go:build loadtest

package fv

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/pkg/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/server"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// The load shape: every node reports its own set of flow keys once per bucket, across the
// buckets the client would replay. Emissions are what the deduplicator counts, not keys.
const (
	heapNodes          = 100
	heapKeysPerNode    = 100
	heapBuckets        = 20
	heapBucketSeconds  = 15
	heapTotalEmissions = heapNodes * heapKeysPerNode * heapBuckets
)

// TestHeapWithoutDedup names no reporting node, which skips the claim, so it measures what
// the bucket ring holds on its own.
func TestHeapWithoutDedup(t *testing.T) {
	measureHeap(t, "without-dedup", func(gm *goldmane.Goldmane, byNode map[string][]*proto.Flow) any {
		for _, flows := range byNode {
			for _, f := range flows {
				gm.Receive(types.ProtoToFlow(f), "")
			}
		}
		return nil
	})
}

// TestHeapWithDedup runs the same load through the collector, which names a node, so the
// difference against the run above is what deduplication costs.
func TestHeapWithDedup(t *testing.T) {
	measureHeap(t, "with-dedup", func(gm *goldmane.Goldmane, byNode map[string][]*proto.Flow) any {
		collector := server.NewFlowCollector(gm)
		for node, flows := range byNode {
			if err := collector.Connect(newReplayStream(node, 45026, flows)); err != nil {
				panic(err)
			}
		}
		return collector
	})
}

func measureHeap(t *testing.T, name string, load func(*goldmane.Goldmane, map[string][]*proto.Flow) any) {
	// The generated load is built before the baseline snapshot, so both runs measure only
	// what the pipeline retains rather than what the generator allocated.
	byNode := buildHeapLoad()

	start := alignedBucketStart()
	gm := goldmane.NewGoldmane()
	<-gm.Run(start)
	defer gm.Stop()

	before := aggrReceivedFlows(t)
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	retained := load(gm, byNode)
	waitForDedupIngest(t, before+float64(heapTotalEmissions))

	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// The load and whatever the run built have to outlive the snapshot, or their own
	// garbage lands in the delta.
	runtime.KeepAlive(byNode)
	runtime.KeepAlive(retained)

	held := int64(after.HeapAlloc) - int64(baseline.HeapAlloc)
	t.Logf("%s: %d emissions held %d bytes, %.1f bytes per emission",
		name, heapTotalEmissions, held, float64(held)/float64(heapTotalEmissions))

	f, err := os.Create(fmt.Sprintf("/tmp/goldmane-heap-%s.pprof", name))
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pprof.Lookup("heap").WriteTo(f, 0))
}

// buildHeapLoad returns each node's emissions: its own set of flow keys, reported once per
// bucket across the range a client would replay.
func buildHeapLoad() map[string][]*proto.Flow {
	byNode := make(map[string][]*proto.Flow, heapNodes)
	base := alignedBucketStart()
	for n := range heapNodes {
		node := fmt.Sprintf("10.0.%d.%d", n/256, n%256)
		for b := range heapBuckets {
			bucketStart := base - int64(b*heapBucketSeconds)
			for k := range heapKeysPerNode {
				byNode[node] = append(byNode[node], &proto.Flow{
					Key: &proto.FlowKey{
						SourceName:      fmt.Sprintf("client-%d-%d", n, k),
						SourceNamespace: "heap-ns",
						SourceType:      proto.EndpointType_WorkloadEndpoint,
						DestName:        fmt.Sprintf("server-%d-%d", n, k),
						DestNamespace:   "heap-ns",
						DestType:        proto.EndpointType_WorkloadEndpoint,
						DestPort:        8080,
						Proto:           "tcp",
						Reporter:        proto.Reporter_Src,
						Action:          proto.Action_Allow,
						Policies:        &proto.PolicyTrace{},
					},
					StartTime:               bucketStart,
					EndTime:                 bucketStart + heapBucketSeconds,
					SourceLabels:            []string{"app=heap"},
					DestLabels:              []string{"app=heap"},
					PacketsIn:               10,
					PacketsOut:              10,
					BytesIn:                 1000,
					BytesOut:                1000,
					NumConnectionsStarted:   1,
					NumConnectionsCompleted: 1,
				})
			}
		}
	}
	return byNode
}
