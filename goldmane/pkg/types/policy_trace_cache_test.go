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

// TestCachedPolicyTraceChurn pushes well past the cache bound and checks every lookup still
// returns its own trace, before and after the cache clears.
func TestCachedPolicyTraceChurn(t *testing.T) {
	const n = 10000
	handles := make([]unique.Handle[string], n)
	for i := range n {
		handles[i] = types.ProtoToFlowLogPolicy(cacheTestTrace(fmt.Sprintf("churn-%d", i)))
	}
	for pass := range 2 {
		for i, h := range handles {
			got := types.CachedPolicyTrace(h)
			require.Equal(t, fmt.Sprintf("churn-%d-first", i), got.EnforcedPolicies[0].Name, "pass %d", pass)
		}
	}
}

// TestReadPathsLeaveCachedTraceIntact runs every consumer of the shared trace and checks the
// cached copy still matches a fresh decode afterwards.
func TestReadPathsLeaveCachedTraceIntact(t *testing.T) {
	f := types.ProtoToFlow(&proto.Flow{
		Key: &proto.FlowKey{
			SourceName: "client",
			DestName:   "server",
			Reporter:   proto.Reporter_Dst,
			Action:     proto.Action_Allow,
			Policies:   cacheTestTrace("readonly"),
		},
		SourceLabels: []string{"b=2", "a=1"},
	})
	h := f.Key.Policies()

	pf := &proto.Flow{}
	types.FlowIntoProto(f, pf)
	require.Same(t, types.CachedPolicyTrace(h), pf.Key.Policies, "FlowIntoProto did not share the cached trace")

	_, err := googleproto.Marshal(pf)
	require.NoError(t, err)
	require.True(t, types.Matches(&proto.Filter{
		PendingActions: []proto.Action{proto.Action_Allow},
		Policies:       []*proto.PolicyMatch{{Name: &proto.StringMatch{Value: "staged", Type: proto.MatchType_Fuzzy}}},
	}, f.Key))
	types.FlowIntoProto(f, pf)

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

	for _, tc := range []struct {
		name string
		flow *proto.Flow
	}{
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

// fillMessage sets every field of m to a non-zero value, descending depth levels into nested
// messages.
func fillMessage(m protoreflect.Message, depth int) {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		switch {
		case fd.IsMap():
			panic(fmt.Sprintf("fillMessage does not handle map field %s", fd.FullName()))
		case fd.IsList():
			l := m.Mutable(fd).List()
			if fd.Kind() == protoreflect.MessageKind {
				if depth > 0 {
					e := l.NewElement()
					fillMessage(e.Message(), depth-1)
					l.Append(e)
				}
				continue
			}
			l.Append(staleScalar(fd))
		case fd.Kind() == protoreflect.MessageKind:
			if depth > 0 {
				fillMessage(m.Mutable(fd).Message(), depth-1)
			}
		default:
			m.Set(fd, staleScalar(fd))
		}
	}
}

func staleScalar(fd protoreflect.FieldDescriptor) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString("stale-" + string(fd.Name()))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte("stale"))
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		vals := fd.Enum().Values()
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
	panic(fmt.Sprintf("staleScalar does not handle kind %s", fd.Kind()))
}

func requireAllFieldsSet(t *testing.T, m protoreflect.Message) {
	t.Helper()
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		require.True(t, m.Has(fields.Get(i)), "fillMessage left %s unset", fields.Get(i).FullName())
	}
}
