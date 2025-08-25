package storage_test

import (
	"fmt"
	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/sirupsen/logrus"
	"runtime"
	"strings"
	"testing"
	"time"
	"unique"
)

var (
	labelMapSize  = 10
	flowArraySize = 1000
	flows         []*types.Flow
)

// Performance thresholds for the benchmark.
// These constants define the upper limits for each key metric.
const (
	maxNsPerOp     = 400.0 // Max allowed nanoseconds per operation
	maxHeapAllocMB = 5.5   // Max allowed total heap allocation in MB
	maxBytesPerOp  = 400.0 // Max allowed bytes allocated per op
)

// init pre-generates a set of synthetic *Flow objects with unique label combinations,
// which will be reused across benchmark iterations.
//
// This approach serves two purposes:
//  1. **Avoid runtime randomness**: By deterministically generating flows with structured,
//     varied keys and values, we ensure consistency and reproducibility in benchmark results.
//  2. **Reduce per-iteration overhead**: Creating flows ahead of time avoids costly allocations
//     and label encoding during the critical benchmarking loop, making performance measurements
//     more reflective of the AddFlow logic itself.
func init() {
	for i := 1; i <= flowArraySize; i++ {
		srcMap := make(map[string]string)
		dstMap := make(map[string]string)

		for j := 1; j <= labelMapSize; j++ {
			srcKey := fmt.Sprintf("src-k-%d", j*i)
			srcVal := fmt.Sprintf("src-v-%d", j*i)
			dstKey := fmt.Sprintf("dst-k-%d", j*i)
			dstVal := fmt.Sprintf("dst-v-%d", j*i)

			srcMap[srcKey] = srcVal
			dstMap[dstKey] = dstVal
		}

		flow := &types.Flow{
			PacketsIn:               100,
			PacketsOut:              200,
			BytesIn:                 10000,
			BytesOut:                20000,
			NumConnectionsStarted:   1,
			NumConnectionsCompleted: 1,
			NumConnectionsLive:      1,
			SourceLabels:            encodeLabels(srcMap),
			DestLabels:              encodeLabels(dstMap),
		}
		flows = append(flows, flow)
	}
}

// encodeLabels serializes a map of labels into a single string in the format "key1=val1,key2=val2,..."
func encodeLabels(m map[string]string) unique.Handle[string] {
	var parts []string
	for k, v := range m {
		parts = append(parts, (k + "=" + v))
	}
	return unique.Make(strings.Join(parts, ","))
}

func getDiachronicFlow() *storage.DiachronicFlow {
	flowKey := types.NewFlowKey(
		&types.FlowKeySource{
			SourceName:      "frontend",
			SourceNamespace: "default",
			SourceType:      proto.EndpointType_WorkloadEndpoint,
		},
		&types.FlowKeyDestination{
			DestName:             "backend",
			DestNamespace:        "default",
			DestType:             proto.EndpointType_WorkloadEndpoint,
			DestPort:             8080,
			DestServiceName:      "backend-svc",
			DestServiceNamespace: "default",
			DestServicePortName:  "http",
			DestServicePort:      80,
		},
		&types.FlowKeyMeta{
			Proto:    "TCP",
			Reporter: proto.Reporter_Src,
			Action:   proto.Action_Allow,
		},
		&proto.PolicyTrace{},
	)

	df := storage.NewDiachronicFlow(flowKey, 1)
	return df
}

func BenchmarkDiachronicFlow_AddFlow(b *testing.B) {
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)

	df := getDiachronicFlow()
	start := int64(1000)
	end := int64(2000)

	runtime.GC()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Advance the time window every 100 iterations to simulate multiple non-overlapping time buckets.
		// This ensures each 100 flows belong to the same (start, end) interval.
		inc := int64((i / 100) * 100)
		flow := flows[i%len(flows)]
		df.AddFlow(flow, start+inc, end+inc)
	}
	b.StopTimer()

	runtime.GC()
	time.Sleep(time.Second)
	// Read the stats.
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	heapAllocMB := float64(m.HeapAlloc) / (1024 * 1024)
	b.ReportMetric(heapAllocMB, "HeapAllocMB")

	b.Logf("\t=== Benchmark Thresholds (Max allowed values) ===")
	b.Logf("\t\tMax allowed ns/op :\t\t%.1f", maxNsPerOp)
	b.Logf("\t\tMax allowed HeapAllocMB :\t%.3f", maxHeapAllocMB)
	b.Logf("\t\tMax allowed B/op (Bytes/op):\t%.1f", maxBytesPerOp)

	// Threshold-based test failure
	if heapAllocMB > maxHeapAllocMB {
		b.Fatalf("HeapAllocMB too high: got %.2f MB, max %.2f MB", heapAllocMB, maxHeapAllocMB)
	}
}
