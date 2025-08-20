package storage_test

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
	"unique"
)

var keys = []string{"app", "env", "tier", "version", "team", "region", "zone", "instance", "project", "role"}
var values = []string{"frontend", "prod", "backend", "v1", "infra", "us-west", "us-west-2a", "i-1234", "goldmane", "web"}

func generateLabelMap(prefix string, count int) map[string]string {
	labelMap := make(map[string]string, count)
	for i := 0; i < count && i < len(keys); i++ {
		labelMap[fmt.Sprintf("%s-%s", prefix, keys[i])] = values[i]
	}

	return labelMap
}

func generateRandomLabelMap(r *rand.Rand, prefix string, count int) map[string]string {
	r.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
	r.Shuffle(len(values), func(i, j int) { values[i], values[j] = values[j], values[i] })

	return generateLabelMap(prefix, count)
}

func encodeLabels(m map[string]string) unique.Handle[string] {
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return unique.Make(strings.Join(parts, ","))
}

type labelPair struct {
	src unique.Handle[string]
	dst unique.Handle[string]
}

func BenchmarkDiachronicFlow_AddFlow(b *testing.B) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	labelPairs := []labelPair{
		{
			encodeLabels(generateLabelMap("src", 10)),
			encodeLabels(generateLabelMap("dst", 10)),
		},
		{
			encodeLabels(generateRandomLabelMap(r, "src", r.Intn(9)+2)),
			encodeLabels(generateRandomLabelMap(r, "dst", r.Intn(9)+2)),
		},
	}

	b.ResetTimer()
	runAddFlowBenchmark(b, labelPairs)
}

func runAddFlowBenchmark(b *testing.B, labelPairs []labelPair) {
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

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pair := labelPairs[i%len(labelPairs)]
		flow := &types.Flow{
			PacketsIn:               100,
			PacketsOut:              200,
			BytesIn:                 10000,
			BytesOut:                20000,
			NumConnectionsStarted:   1,
			NumConnectionsCompleted: 1,
			NumConnectionsLive:      1,
			SourceLabels:            pair.src,
			DestLabels:              pair.dst,
		}
		df.AddFlow(flow, 1000, 2000)
	}
	b.StopTimer()

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	heapDelta := m2.HeapAlloc - m1.HeapAlloc

	fmt.Printf("\n\n\nGo Benchmark Output:\n")
	fmt.Printf("\nHeap Alloc: %.3f MB\n", float64(heapDelta)/1024/1024)
	fmt.Printf("\n%-20s %-23s %-17s %-5s\n", "[Iterations]", "[ns/op]", "[B/op]", "[allocs/op]")
}
