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

package types_test

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"unique"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	googleproto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

func cacheTestTrace(name string) *proto.PolicyTrace {
	return &proto.PolicyTrace{
		EnforcedPolicies: []*proto.PolicyHit{
			{Name: name + "-second", Tier: "default", PolicyIndex: 1, Action: proto.Action_Deny},
			{Name: name + "-first", Tier: "security", PolicyIndex: 0, Action: proto.Action_Pass},
		},
		PendingPolicies: []*proto.PolicyHit{
			{Name: name + "-staged", Tier: "default", PolicyIndex: 0, Action: proto.Action_Allow},
		},
	}
}

func TestCachedPolicyTrace(t *testing.T) {
	h := types.ProtoToFlowLogPolicy(cacheTestTrace("cached"))

	first := types.CachedPolicyTrace(h)
	require.True(t, googleproto.Equal(types.FlowLogPolicyToProto(h), first), "cached trace differs from a fresh decode")
	require.Equal(t, "cached-first", first.EnforcedPolicies[0].Name, "cached trace is not sorted by policy index")
	require.Same(t, first, types.CachedPolicyTrace(h), "second lookup decoded the trace again")

	// A fresh decode is a new object each time, so the identity check above is meaningful.
	require.NotSame(t, types.FlowLogPolicyToProto(h), types.FlowLogPolicyToProto(h))

	other := types.CachedPolicyTrace(types.ProtoToFlowLogPolicy(cacheTestTrace("other")))
	require.False(t, googleproto.Equal(first, other), "different traces share a cache entry")

	empty := types.CachedPolicyTrace(types.ProtoToFlowLogPolicy(&proto.PolicyTrace{}))
	require.NotNil(t, empty)
	require.Empty(t, empty.EnforcedPolicies)
	require.Empty(t, empty.PendingPolicies)
}

// TestCachedPolicyTraceChurn pushes past both generations and checks every lookup still returns
// its own trace, before and after the cache rotates, and that the rotations are counted.
func TestCachedPolicyTraceChurn(t *testing.T) {
	const n = 2*types.PolicyTraceGenerationSize + 1000
	handles := make([]unique.Handle[string], n)
	for i := range n {
		handles[i] = types.ProtoToFlowLogPolicy(cacheTestTrace(fmt.Sprintf("churn-%d", i)))
	}
	rotationsBefore := types.PolicyTraceCacheRotations()
	for pass := range 2 {
		for i, h := range handles {
			got := types.CachedPolicyTrace(h)
			require.Equal(t, fmt.Sprintf("churn-%d-first", i), got.EnforcedPolicies[0].Name, "pass %d", pass)
		}
	}
	require.Greater(t, types.PolicyTraceCacheRotations(), rotationsBefore, "churn past a generation was not counted")
	require.LessOrEqual(t, types.PolicyTraceCacheSize(), int64(2*types.PolicyTraceGenerationSize))
}

// TestCachedPolicyTraceHitsDoNotRotate checks that lookups of a cached trace neither grow the
// cache nor count as a rotation.
func TestCachedPolicyTraceHitsDoNotRotate(t *testing.T) {
	h := types.ProtoToFlowLogPolicy(cacheTestTrace("hits"))
	types.CachedPolicyTrace(h)
	size, rotations := types.PolicyTraceCacheSize(), types.PolicyTraceCacheRotations()
	for range 100000 {
		types.CachedPolicyTrace(h)
	}
	require.Equal(t, size, types.PolicyTraceCacheSize())
	require.Equal(t, rotations, types.PolicyTraceCacheRotations())
}

// TestPolicyTraceCacheDropsUnusedTraces checks that each full generation rotates exactly once,
// and that a trace looked up once outlives the first rotation, in the previous generation, and is
// gone after the second.
func TestPolicyTraceCacheDropsUnusedTraces(t *testing.T) {
	const generationSize = 4
	cache := types.NewPolicyTraceCache(generationSize)
	unused := types.ProtoToFlowLogPolicy(cacheTestTrace("unused"))
	cache.Trace(unused)

	lookUpFresh(cache, generationSize-1, "drop-first")
	require.Zero(t, cache.Rotations(), "rotated before the first generation was full")
	lookUpFresh(cache, generationSize, "drop-second")
	require.Equal(t, uint64(1), cache.Rotations())
	require.Equal(t, int64(2*generationSize), cache.Size())
	require.True(t, cache.Holds(unused), "trace dropped after one rotation")

	lookUpFresh(cache, 1, "drop-third")
	require.Equal(t, uint64(2), cache.Rotations())
	require.False(t, cache.Holds(unused), "trace unused for a whole generation still cached after two rotations")
}

// lookUpFresh looks up n traces, named after prefix, that cache has not seen.
func lookUpFresh(cache *types.PolicyTraceCache, n int, prefix string) {
	for i := range n {
		cache.Trace(types.ProtoToFlowLogPolicy(cacheTestTrace(fmt.Sprintf("%s-%d", prefix, i))))
	}
}

// TestPolicyTraceCacheKeepsLiveTraces checks that a trace looked up in every generation survives
// many rotations and is never decoded again.
func TestPolicyTraceCacheKeepsLiveTraces(t *testing.T) {
	cache := types.NewPolicyTraceCache(4)
	live := types.ProtoToFlowLogPolicy(cacheTestTrace("live"))
	want := cache.Trace(live)

	for r := uint64(1); r <= 10; r++ {
		rotateTo(cache, r, "keep")
		require.Same(t, want, cache.Trace(live), "live trace decoded again after rotation %d", r)
	}
	require.True(t, cache.Holds(live))
}

// rotateTo looks up fresh traces, named after prefix, until cache has rotated n times.
func rotateTo(cache *types.PolicyTraceCache, n uint64, prefix string) {
	for i := 0; cache.Rotations() < n; i++ {
		lookUpFresh(cache, 1, fmt.Sprintf("%s-%d-%d", prefix, n, i))
	}
}

// TestPolicyTraceCacheConcurrentMisses has many goroutines look up overlapping traces while a
// small generation size forces repeated rotations. Each generation must stay within its size, each
// rotation must retire a full one, the cache's count must match its maps, and a trace must not be
// decoded twice within a generation.
func TestPolicyTraceCacheConcurrentMisses(t *testing.T) {
	const (
		generationSize = 8
		hotTraces      = 4
		numTraces      = 4 * generationSize
		goroutines     = 32
		lookups        = 2000
	)
	handles := make([]unique.Handle[string], numTraces)
	wantNames := make([]string, numTraces)
	for i := range handles {
		handles[i] = types.ProtoToFlowLogPolicy(cacheTestTrace(fmt.Sprintf("concurrent-%d", i)))
		wantNames[i] = fmt.Sprintf("concurrent-%d-first", i)
	}
	cache := types.NewPolicyTraceCache(generationSize)

	// Every other lookup goes to a small hot set, so some traces are promoted rather than decoded.
	results := make([][]traceLookup, goroutines)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for g := range goroutines {
		workers.Go(func() {
			<-start
			for i := range lookups {
				idx := hotTraces + (g+i)%(numTraces-hotTraces)
				if i%2 == 0 {
					idx = (g + i) % hotTraces
				}
				before := cache.Rotations()
				got := cache.Trace(handles[idx])
				results[g] = append(results[g], traceLookup{handle: idx, before: before, after: cache.Rotations(), trace: got})
				if got.EnforcedPolicies[0].Name != wantNames[idx] {
					t.Errorf("lookup of trace %d returned %q", idx, got.EnforcedPolicies[0].Name)
					return
				}
			}
		})
	}

	done := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if size := cache.Size(); size > 2*generationSize {
				t.Errorf("cache counts %d entries, above two generations of %d", size, generationSize)
				return
			}
			current, previous := cache.Lens()
			if current > generationSize || (previous != 0 && previous != generationSize) {
				t.Errorf("generations hold %d and %d traces, want at most %d and exactly %d", current, previous, generationSize, generationSize)
				return
			}
		}
	})

	close(start)
	workers.Wait()
	close(done)
	sampler.Wait()

	current, previous := cache.Lens()
	rotations := cache.Rotations()
	require.Equal(t, current+previous, cache.Size(), "cache count differs from the traces in its maps")
	require.Positive(t, rotations, "the cache never rotated")

	// A lookup that saw no rotation ran within one generation, which holds one trace per handle,
	// so each such handle and generation pair was an insert.
	within := map[traceGeneration]*proto.PolicyTrace{}
	for _, r := range results {
		for _, l := range r {
			if l.before != l.after {
				continue
			}
			key := traceGeneration{handle: l.handle, generation: l.before}
			if prev, ok := within[key]; ok {
				require.Same(t, prev, l.trace, "trace %d decoded twice in generation %d", l.handle, l.before)
			}
			within[key] = l.trace
		}
	}
	require.Equal(t, int64(generationSize), previous, "a rotation retired a generation that was not full")
	require.GreaterOrEqual(t, int64(rotations)*generationSize+current, int64(len(within)), "fewer rotations counted than generations filled")
}

// traceLookup is one lookup in TestPolicyTraceCacheConcurrentMisses, with the rotation count
// read before and after it.
type traceLookup struct {
	handle int
	before uint64
	after  uint64
	trace  *proto.PolicyTrace
}

// traceGeneration names one handle's entry in one generation of the cache.
type traceGeneration struct {
	handle     int
	generation uint64
}

// BenchmarkPolicyTraceCacheRetainedHeap reports the heap the trace cache retains with both
// generations full, for traces with the given number of hits in each of the enforced and pending
// lists.
func BenchmarkPolicyTraceCacheRetainedHeap(b *testing.B) {
	for _, hits := range []int{2, 4, 8} {
		b.Run(fmt.Sprintf("hits=%d", hits), func(b *testing.B) {
			handles := make([]unique.Handle[string], 2*types.PolicyTraceGenerationSize)
			for i := range handles {
				handles[i] = types.ProtoToFlowLogPolicy(heapTestTrace(i, hits))
			}
			var retained int64
			for b.Loop() {
				retained = retainedHeap(handles)
			}
			b.ReportMetric(float64(retained)/1e6, "MB-retained")
		})
	}
}

// retainedHeap fills both generations of a production-sized cache with handles and returns the
// live heap it adds.
func retainedHeap(handles []unique.Handle[string]) int64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	c := types.NewPolicyTraceCache(types.PolicyTraceGenerationSize)
	for _, h := range handles {
		c.Trace(h)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(c)
	return int64(after.HeapAlloc) - int64(before.HeapAlloc)
}

func heapTestTrace(i, hits int) *proto.PolicyTrace {
	list := func(prefix string) []*proto.PolicyHit {
		out := make([]*proto.PolicyHit, hits)
		for j := range out {
			out[j] = &proto.PolicyHit{
				Kind:        proto.PolicyKind_CalicoNetworkPolicy,
				Namespace:   fmt.Sprintf("namespace-%d", i),
				Name:        fmt.Sprintf("%s-policy-%d", prefix, j),
				Tier:        "default",
				Action:      proto.Action_Allow,
				PolicyIndex: int64(j),
				RuleIndex:   int64(j),
			}
		}
		return out
	}
	return &proto.PolicyTrace{EnforcedPolicies: list("enforced"), PendingPolicies: list("pending")}
}

// TestReadPathsLeaveCachedTraceIntact runs every consumer of the shared trace and checks the
// cached copy still matches a fresh decode afterwards.
func TestReadPathsLeaveCachedTraceIntact(t *testing.T) {
	flow := types.ProtoToFlow(&proto.Flow{
		Key: &proto.FlowKey{
			SourceName: "client",
			DestName:   "server",
			Reporter:   proto.Reporter_Dst,
			Action:     proto.Action_Allow,
			Policies:   cacheTestTrace("readonly"),
		},
		SourceLabels: []string{"b=2", "a=1"},
	})
	h := flow.Key.Policies()

	pf := &proto.Flow{}
	types.FlowIntoProto(flow, pf)
	require.Same(t, types.CachedPolicyTrace(h), pf.Key.Policies, "FlowIntoProto did not share the cached trace")

	_, err := googleproto.Marshal(pf)
	require.NoError(t, err)
	require.True(t, types.Matches(&proto.Filter{
		PendingActions: []proto.Action{proto.Action_Allow},
		Policies:       []*proto.PolicyMatch{{Name: &proto.StringMatch{Value: "staged", Type: proto.MatchType_Fuzzy}}},
	}, flow.Key))
	types.FlowIntoProto(flow, pf)

	require.True(t, googleproto.Equal(types.FlowLogPolicyToProto(h), types.CachedPolicyTrace(h)), "a read path modified the shared trace")
}

// TestFlowIntoProtoUncachedSkipsCache checks that the conversion Felix uses decodes the trace
// without filling the process-wide cache, while FlowIntoProto still fills it.
func TestFlowIntoProtoUncachedSkipsCache(t *testing.T) {
	trace := cacheTestTrace("uncached")
	flow := types.ProtoToFlow(&proto.Flow{
		Key: &proto.FlowKey{SourceName: "client", DestName: "server", Policies: trace},
	})
	h := flow.Key.Policies()

	pf := &proto.Flow{}
	types.FlowIntoProtoUncached(flow, pf)
	require.True(t, googleproto.Equal(types.FlowLogPolicyToProto(h), pf.Key.Policies))
	require.False(t, types.DefaultPolicyTraceCacheHolds(h), "FlowIntoProtoUncached filled the trace cache")

	types.FlowIntoProto(flow, pf)
	require.True(t, types.DefaultPolicyTraceCacheHolds(h), "FlowIntoProto did not fill the trace cache")
}

// TestFlowIntoProtoOverwritesEveryField converts into a message with every field already set,
// as a reused message is, plus unknown fields that no assignment can clear. Anything the previous
// flow left behind fails the comparison with a fresh conversion.
func TestFlowIntoProtoOverwritesEveryField(t *testing.T) {
	full := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:           "source-name",
			SourceNamespace:      "source-namespace",
			SourceType:           proto.EndpointType_WorkloadEndpoint,
			DestName:             "dest-name",
			DestNamespace:        "dest-namespace",
			DestType:             proto.EndpointType_NetworkSet,
			DestPort:             1234,
			DestServiceName:      "dest-service-name",
			DestServiceNamespace: "dest-service-namespace",
			DestServicePortName:  "dest-service-port-name",
			DestServicePort:      5678,
			Proto:                "tcp",
			Reporter:             proto.Reporter_Src,
			Action:               proto.Action_Allow,
			Policies:             cacheTestTrace("full"),
		},
		StartTime:               10,
		EndTime:                 20,
		SourceLabels:            []string{"src-b", "src-a"},
		DestLabels:              []string{"dst-a"},
		PacketsIn:               1,
		PacketsOut:              2,
		BytesIn:                 3,
		BytesOut:                4,
		NumConnectionsStarted:   5,
		NumConnectionsCompleted: 6,
		NumConnectionsLive:      7,
	}

	for _, tc := range []flowIntoProtoCase{
		{name: "all fields set", flow: full},
		{name: "only an empty key", flow: &proto.Flow{Key: &proto.FlowKey{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := types.ProtoToFlow(tc.flow)

			stale := &proto.Flow{}
			fillMessage(stale.ProtoReflect(), 2)
			requireAllFieldsSet(t, stale.ProtoReflect())
			requireAllFieldsSet(t, stale.Key.ProtoReflect())
			stale.ProtoReflect().SetUnknown(staleUnknownField())
			stale.Key.ProtoReflect().SetUnknown(staleUnknownField())

			types.FlowIntoProto(f, stale)
			want := types.FlowToProto(f)
			require.True(t, googleproto.Equal(want, stale), "reused message differs from a fresh conversion:\nwant %v\ngot  %v", want, stale)
		})
	}
}

// staleUnknownField encodes a field number the schema doesn't define, as a message parsed from a
// newer sender would carry.
func staleUnknownField() protoreflect.RawFields {
	b := protowire.AppendTag(nil, 999, protowire.VarintType)
	return protowire.AppendVarint(b, 1)
}

// TestFlowIntoProtoReusesLabelBuffers alternates labeled and unlabeled flows through one message
// and checks the label slices are never reallocated.
func TestFlowIntoProtoReusesLabelBuffers(t *testing.T) {
	labeled := types.ProtoToFlow(&proto.Flow{
		Key:          &proto.FlowKey{SourceName: "client", Policies: cacheTestTrace("labels")},
		SourceLabels: []string{"a=1", "b=2", "c=3"},
		DestLabels:   []string{"d=4", "e=5"},
	})
	unlabeled := types.ProtoToFlow(&proto.Flow{
		Key: &proto.FlowKey{SourceName: "client", Policies: cacheTestTrace("labels")},
	})

	pf := &proto.Flow{}
	types.FlowIntoProto(labeled, pf)
	types.FlowIntoProto(unlabeled, pf)
	require.Empty(t, pf.SourceLabels)
	require.Empty(t, pf.DestLabels)

	allocs := testing.AllocsPerRun(100, func() {
		types.FlowIntoProto(unlabeled, pf)
		types.FlowIntoProto(labeled, pf)
	})
	require.Zero(t, allocs, "an unlabeled flow dropped the reusable label slices")
	require.Equal(t, []string{"a=1", "b=2", "c=3"}, pf.SourceLabels)
	require.Equal(t, []string{"d=4", "e=5"}, pf.DestLabels)
}

// flowIntoProtoCase is a flow to convert into a reused message that starts fully populated.
type flowIntoProtoCase struct {
	name string
	flow *proto.Flow
}

// fillMessage sets every field of m to a non-zero value, descending depth levels into nested
// messages.
func fillMessage(m protoreflect.Message, depth int) {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		switch {
		case field.IsMap():
			panic(fmt.Sprintf("fillMessage does not handle map field %s", field.FullName()))
		case field.IsList():
			l := m.Mutable(field).List()
			if field.Kind() == protoreflect.MessageKind {
				if depth > 0 {
					e := l.NewElement()
					fillMessage(e.Message(), depth-1)
					l.Append(e)
				}
				continue
			}
			l.Append(staleScalar(field))
		case field.Kind() == protoreflect.MessageKind:
			if depth > 0 {
				fillMessage(m.Mutable(field).Message(), depth-1)
			}
		default:
			m.Set(field, staleScalar(field))
		}
	}
}

func staleScalar(field protoreflect.FieldDescriptor) protoreflect.Value {
	switch field.Kind() {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString("stale-" + string(field.Name()))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte("stale"))
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		vals := field.Enum().Values()
		return protoreflect.ValueOfEnum(vals.Get(vals.Len() - 1).Number())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(99)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(99)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(99)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(99)
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(99)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(99)
	}
	panic(fmt.Sprintf("staleScalar does not handle kind %s", field.Kind()))
}

func requireAllFieldsSet(t *testing.T, m protoreflect.Message) {
	t.Helper()
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		require.True(t, m.Has(fields.Get(i)), "fillMessage left %s unset", fields.Get(i).FullName())
	}
}
