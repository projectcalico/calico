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

// TestCachedPolicyTraceChurn pushes past the cache bound and checks every lookup still returns
// its own trace, before and after the cache clears, and that the clears are counted.
func TestCachedPolicyTraceChurn(t *testing.T) {
	const n = types.MaxCachedPolicyTraces + 1000
	handles := make([]unique.Handle[string], n)
	for i := range n {
		handles[i] = types.ProtoToFlowLogPolicy(cacheTestTrace(fmt.Sprintf("churn-%d", i)))
	}
	resetsBefore := types.PolicyTraceCacheResets()
	for pass := range 2 {
		for i, h := range handles {
			got := types.CachedPolicyTrace(h)
			require.Equal(t, fmt.Sprintf("churn-%d-first", i), got.EnforcedPolicies[0].Name, "pass %d", pass)
		}
	}
	require.Greater(t, types.PolicyTraceCacheResets(), resetsBefore, "churn past the bound was not counted")
	require.LessOrEqual(t, types.PolicyTraceCacheSize(), int64(types.MaxCachedPolicyTraces))
}

// TestCachedPolicyTraceHitsDoNotReset checks that lookups of a cached trace neither grow the
// cache nor count as a reset.
func TestCachedPolicyTraceHitsDoNotReset(t *testing.T) {
	h := types.ProtoToFlowLogPolicy(cacheTestTrace("hits"))
	types.CachedPolicyTrace(h)
	size, resets := types.PolicyTraceCacheSize(), types.PolicyTraceCacheResets()
	for range 100000 {
		types.CachedPolicyTrace(h)
	}
	require.Equal(t, size, types.PolicyTraceCacheSize())
	require.Equal(t, resets, types.PolicyTraceCacheResets())
}

// TestPolicyTraceCacheConcurrentMisses has many goroutines miss on overlapping traces while a
// small bound forces repeated clears. The cache's count must match the map, the map must stay
// within the bound, and each fill must count as exactly one reset.
func TestPolicyTraceCacheConcurrentMisses(t *testing.T) {
	const (
		limit      = 8
		numTraces  = 3 * limit
		goroutines = 32
		lookups    = 2000
	)
	handles := make([]unique.Handle[string], numTraces)
	wantNames := make([]string, numTraces)
	for i := range handles {
		handles[i] = types.ProtoToFlowLogPolicy(cacheTestTrace(fmt.Sprintf("concurrent-%d", i)))
		wantNames[i] = fmt.Sprintf("concurrent-%d-first", i)
	}
	cache := types.NewPolicyTraceCache(limit)

	// Every trace a lookup returns was inserted once, so the distinct results count the inserts.
	returned := make([]map[*proto.PolicyTrace]struct{}, goroutines)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for g := range goroutines {
		returned[g] = map[*proto.PolicyTrace]struct{}{}
		workers.Go(func() {
			<-start
			for i := range lookups {
				idx := (g + i) % numTraces
				got := cache.Trace(handles[idx])
				if got.EnforcedPolicies[0].Name != wantNames[idx] {
					t.Errorf("lookup of trace %d returned %q", idx, got.EnforcedPolicies[0].Name)
					return
				}
				returned[g][got] = struct{}{}
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
			if size := cache.Size(); size > limit {
				t.Errorf("cache counts %d traces, above the bound of %d", size, limit)
				return
			}
			if n := cache.Len(); n > limit+goroutines {
				t.Errorf("map holds %d traces, above the bound of %d plus %d in flight", n, limit, goroutines)
				return
			}
		}
	})

	close(start)
	workers.Wait()
	close(done)
	sampler.Wait()

	inserts := map[*proto.PolicyTrace]struct{}{}
	for _, r := range returned {
		for p := range r {
			inserts[p] = struct{}{}
		}
	}
	size, resets := cache.Size(), cache.Resets()
	require.Equal(t, cache.Len(), size, "cache count differs from the traces in the map")
	require.LessOrEqual(t, size, int64(limit))
	require.Positive(t, resets, "the bound was never crossed")
	require.Equal(t, int64(len(inserts)), int64(resets)*limit+size, "resets do not match one per fill")
}

// BenchmarkPolicyTraceCacheRetainedHeap reports the heap a full trace cache retains, for traces
// with the given number of hits in each of the enforced and pending lists.
func BenchmarkPolicyTraceCacheRetainedHeap(b *testing.B) {
	for _, hits := range []int{2, 4, 8} {
		b.Run(fmt.Sprintf("hits=%d", hits), func(b *testing.B) {
			handles := make([]unique.Handle[string], types.MaxCachedPolicyTraces)
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

// retainedHeap fills a cache sized to hold every handle and returns the live heap it adds.
func retainedHeap(handles []unique.Handle[string]) int64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	c := types.NewPolicyTraceCache(int64(len(handles)))
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

// TestFlowIntoProtoOverwritesEveryField converts into a message with every field already set,
// as a reused message is. Any field FlowIntoProto forgets to assign keeps its stale value and
// fails the comparison with a fresh conversion.
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

			types.FlowIntoProto(f, stale)
			want := types.FlowToProto(f)
			require.True(t, googleproto.Equal(want, stale), "reused message differs from a fresh conversion:\nwant %v\ngot  %v", want, stale)
		})
	}
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
