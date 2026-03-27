// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"reflect"
	"testing"
	"unique"

	"github.com/stretchr/testify/require"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

type fromProtoTest struct {
	name  string
	proto proto.Flow
}

func TestTranslation(t *testing.T) {
	// Assert that bidirection translation works.
	tests := []*fromProtoTest{
		{
			name:  "empty proto.Flow",
			proto: proto.Flow{},
		},
		{
			name: "proto.Flow with all fields set",
			proto: proto.Flow{
				Key: &proto.FlowKey{
					SourceName:           "source-name",
					SourceNamespace:      "source-namespace",
					SourceType:           proto.EndpointType_WorkloadEndpoint,
					SourceIp:             "10.0.0.1",
					SourcePort:           12345,
					DestName:             "dest-name",
					DestNamespace:        "dest-namespace",
					DestType:             proto.EndpointType_NetworkSet,
					DestPort:             1234,
					DestServiceName:      "dest-service-name",
					DestServiceNamespace: "dest-service-namespace",
					DestServicePortName:  "dest-service-port-name",
					DestServicePort:      5678,
					Proto:                "proto",
					Reporter:             proto.Reporter_Dst,
					Action:               proto.Action_Allow,
					Policies: &proto.PolicyTrace{
						EnforcedPolicies: []*proto.PolicyHit{
							{Name: "policy-1"},
							{Name: "policy-2"},
						},
						PendingPolicies: []*proto.PolicyHit{
							{Name: "pending-policy-1"},
							{Name: "pending-policy-2"},
						},
					},
				},
				StartTime:               1234567890,
				EndTime:                 1234567891,
				SourceLabels:            []string{"source-label-1", "source-label-2"},
				DestLabels:              []string{"dest-label-1", "dest-label-2"},
				SourceIps:               []string{"192.168.1.1", "192.168.1.2"},
				SourcePorts:             []int64{8080, 9090},
				PacketsIn:               123,
				PacketsOut:              456,
				BytesIn:                 789,
				BytesOut:                101112,
				NumConnectionsStarted:   131415,
				NumConnectionsCompleted: 161718,
				NumConnectionsLive:      192021,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := types.ProtoToFlow(&test.proto)
			p := types.FlowToProto(f)
			if !googleproto.Equal(&test.proto, p) {
				t.Fatalf("translated proto.Flow does not match the original proto.Flow: %v != %v", p, test.proto.String())
			}
		})
	}
}

func TestKeyEquality(t *testing.T) {
	// We need to assert that key translation works and that translating the same flow
	// results in the same key.
	keys := []*proto.FlowKey{
		{
			// Fully specified.
			SourceName:           "source-name",
			SourceNamespace:      "source-namespace",
			SourceType:           proto.EndpointType_WorkloadEndpoint,
			SourceIp:             "192.168.1.1",
			SourcePort:           8080,
			DestName:             "dest-name",
			DestNamespace:        "dest-namespace",
			DestType:             proto.EndpointType_NetworkSet,
			DestPort:             1234,
			DestServiceName:      "dest-service-name",
			DestServiceNamespace: "dest-service-namespace",
			DestServicePortName:  "dest-service-port-name",
			DestServicePort:      5678,
			Proto:                "proto",
			Reporter:             proto.Reporter_Dst,
			Action:               proto.Action_Allow,
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{Name: "policy-1"},
					{Name: "policy-2"},
				},
				PendingPolicies: []*proto.PolicyHit{
					{Name: "pending-policy-1"},
					{Name: "pending-policy-2"},
				},
			},
		},
		{
			// No Policies.
			SourceName:           "source-name",
			SourceNamespace:      "source-namespace",
			SourceType:           proto.EndpointType_HostEndpoint,
			DestName:             "dest-name",
			DestNamespace:        "dest-namespace",
			DestType:             proto.EndpointType_WorkloadEndpoint,
			DestPort:             1234,
			DestServiceName:      "dest-service-name",
			DestServiceNamespace: "dest-service-namespace",
			DestServicePortName:  "dest-service-port-name",
			DestServicePort:      5678,
			Proto:                "proto",
			Reporter:             proto.Reporter_Src,
			Action:               proto.Action_Deny,
		},
	}

	// For each key, translate it and use it as a map key. Then, translate it again and
	// confirm it is the same. This ensures we don't accidentally introduce inequality by, for example,
	// using pointer fields in the struct.
	for _, key := range keys {
		m := map[types.FlowKey]struct{}{}
		t.Run(key.String(), func(t *testing.T) {
			k := types.ProtoToFlowKey(key)
			m[*k] = struct{}{}
			k2 := types.ProtoToFlowKey(key)
			require.Equal(t, k, k2)
			if _, ok := m[*k2]; !ok {
				t.Fatalf("expected key to be in map")
			}
		})
	}
}

// TestIdentical verifies that the exported fields on types.Flow and proto.Flow are identical. This ensures
// we don't accidentally add new fields to one type and forget to add them to the other.
func TestIdentical(t *testing.T) {
	p := reflect.ValueOf(proto.Flow{})
	f := reflect.ValueOf(types.Flow{})

	// Check each field in types.Flow is present in proto.Flow.
	for _, fField := range reflect.VisibleFields(f.Type()) {
		found := false
		if !fField.IsExported() {
			continue
		}
		for _, pField := range reflect.VisibleFields(p.Type()) {
			if fField.Name == pField.Name {
				found = true
				break
			}
		}
		require.True(t, found, "field %s not found in proto.Flow", fField.Name)
	}

	// Check each field in proto.Flow is present in types.Flow.
	for _, pField := range reflect.VisibleFields(p.Type()) {
		found := false
		if !pField.IsExported() {
			continue
		}
		for _, fField := range reflect.VisibleFields(f.Type()) {
			if pField.Name == fField.Name {
				found = true
				break
			}
		}
		require.True(t, found, "field %s not found in types.Flow", pField.Name)
	}
}

func TestFlowConfig(t *testing.T) {
	t.Run("DefaultFlowConfig", func(t *testing.T) {
		config := types.DefaultFlowConfig()
		require.Equal(t, 100, config.MaxSourceIPs)
		require.Equal(t, 100, config.MaxSourcePorts)
	})

	t.Run("CustomFlowConfig", func(t *testing.T) {
		config := &types.FlowConfig{
			MaxSourceIPs:   50,
			MaxSourcePorts: 75,
		}
		require.Equal(t, 50, config.MaxSourceIPs)
		require.Equal(t, 75, config.MaxSourcePorts)
	})
}

func TestMergeFlows(t *testing.T) {
	t.Run("NilInputs", func(t *testing.T) {
		f1 := createTestFlow([]string{"1.1.1.1"}, []int64{80})
		
		// Test nil second flow
		result := types.MergeFlows(f1, nil, 10, 10)
		require.Equal(t, f1, result)
		
		// Test nil first flow
		result = types.MergeFlows(nil, f1, 10, 10)
		require.Equal(t, f1, result)
		
		// Test both nil
		result = types.MergeFlows(nil, nil, 10, 10)
		require.Nil(t, result)
	})

	t.Run("BasicMerge", func(t *testing.T) {
		f1 := createTestFlow([]string{"1.1.1.1", "2.2.2.2"}, []int64{80, 443})
		f2 := createTestFlow([]string{"3.3.3.3", "2.2.2.2"}, []int64{8080, 80})
		
		result := MergeFlows(f1, f2, 10, 10)
		
		// Check merged IPs (should be deduplicated and sorted)
		expectedIPs := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
		require.Equal(t, expectedIPs, result.SourceIPs)
		
		// Check merged ports (should be deduplicated and sorted)
		expectedPorts := []int64{80, 443, 8080}
		require.Equal(t, expectedPorts, result.SourcePorts)
		
		// Check aggregated statistics
		require.Equal(t, f1.PacketsIn+f2.PacketsIn, result.PacketsIn)
		require.Equal(t, f1.PacketsOut+f2.PacketsOut, result.PacketsOut)
		require.Equal(t, f1.BytesIn+f2.BytesIn, result.BytesIn)
		require.Equal(t, f1.BytesOut+f2.BytesOut, result.BytesOut)
	})

	t.Run("LimitEnforcement", func(t *testing.T) {
		f1 := createTestFlow([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, []int64{80, 443, 8080})
		f2 := createTestFlow([]string{"4.4.4.4", "5.5.5.5"}, []int64{9090, 3000})
		
		// Limit to 3 IPs and 4 ports
		result := MergeFlows(f1, f2, 3, 4)
		
		require.LessOrEqual(t, len(result.SourceIPs), 3)
		require.LessOrEqual(t, len(result.SourcePorts), 4)
		
		// Should contain no duplicates
		ipSet := make(map[string]bool)
		for _, ip := range result.SourceIPs {
			require.False(t, ipSet[ip], "Duplicate IP found: %s", ip)
			ipSet[ip] = true
		}
		
		portSet := make(map[int64]bool)
		for _, port := range result.SourcePorts {
			require.False(t, portSet[port], "Duplicate port found: %d", port)
			portSet[port] = true
		}
	})

	t.Run("NoLimits", func(t *testing.T) {
		f1 := createTestFlow([]string{"1.1.1.1", "2.2.2.2"}, []int64{80, 443})
		f2 := createTestFlow([]string{"3.3.3.3", "4.4.4.4"}, []int64{8080, 9090})
		
		// No limits (0 means unlimited)
		result := MergeFlows(f1, f2, 0, 0)
		
		require.Equal(t, 4, len(result.SourceIPs))
		require.Equal(t, 4, len(result.SourcePorts))
	})

	t.Run("TimeRangeHandling", func(t *testing.T) {
		f1 := createTestFlowWithTime([]string{"1.1.1.1"}, []int64{80}, 1000, 2000)
		f2 := createTestFlowWithTime([]string{"2.2.2.2"}, []int64{443}, 1500, 2500)
		
		result := MergeFlows(f1, f2, 10, 10)
		
		require.Equal(t, int64(1000), result.StartTime) // Min start time
		require.Equal(t, int64(2500), result.EndTime)   // Max end time
	})

	t.Run("FastPathWhenAtCapacity", func(t *testing.T) {
		// Create flow already at capacity
		largeIPs := make([]string, 5)
		largePorts := make([]int64, 5)
		for i := 0; i < 5; i++ {
			largeIPs[i] = fmt.Sprintf("1.1.1.%d", i+1)
			largePorts[i] = int64(8000 + i)
		}
		
		f1 := createTestFlow(largeIPs, largePorts)
		f2 := createTestFlow([]string{"9.9.9.9"}, []int64{9999})
		
		// Limit is less than f1's current size - should use fast path
		result := MergeFlows(f1, f2, 3, 3)
		
		// Should not exceed the current size of f1
		require.LessOrEqual(t, len(result.SourceIPs), 5)
		require.LessOrEqual(t, len(result.SourcePorts), 5)
	})
}

func TestMergeFlowsWithConfig(t *testing.T) {
	t.Run("WithConfig", func(t *testing.T) {
		f1 := createTestFlow([]string{"1.1.1.1", "2.2.2.2"}, []int64{80, 443})
		f2 := createTestFlow([]string{"3.3.3.3"}, []int64{8080})
		
		config := &FlowConfig{MaxSourceIPs: 2, MaxSourcePorts: 2}
		result := MergeFlowsWithConfig(f1, f2, config)
		
		require.LessOrEqual(t, len(result.SourceIPs), 2)
		require.LessOrEqual(t, len(result.SourcePorts), 2)
	})

	t.Run("WithNilConfig", func(t *testing.T) {
		f1 := createTestFlow([]string{"1.1.1.1"}, []int64{80})
		f2 := createTestFlow([]string{"2.2.2.2"}, []int64{443})
		
		result := MergeFlowsWithConfig(f1, f2, nil)
		
		// Should use default config
		require.Equal(t, 2, len(result.SourceIPs))
		require.Equal(t, 2, len(result.SourcePorts))
	})
}

func TestMergeUniqueStrings(t *testing.T) {
	t.Run("BasicMerge", func(t *testing.T) {
		s1 := []string{"a", "b", "c"}
		s2 := []string{"b", "d", "e"}
		
		result := mergeUniqueStrings(s1, s2, 0)
		expected := []string{"a", "b", "c", "d", "e"}
		
		require.Equal(t, expected, result)
	})

	t.Run("WithLimit", func(t *testing.T) {
		s1 := []string{"a", "b", "c"}
		s2 := []string{"d", "e", "f"}
		
		result := mergeUniqueStrings(s1, s2, 4)
		
		require.LessOrEqual(t, len(result), 4)
		// Should be sorted for small arrays
		for i := 1; i < len(result); i++ {
			require.True(t, result[i-1] < result[i])
		}
	})

	t.Run("EmptyInputs", func(t *testing.T) {
		result := mergeUniqueStrings([]string{}, []string{"a", "b"}, 0)
		require.Equal(t, []string{"a", "b"}, result)
		
		result = mergeUniqueStrings([]string{"a", "b"}, []string{}, 0)
		require.Equal(t, []string{"a", "b"}, result)
		
		result = mergeUniqueStrings([]string{}, []string{}, 0)
		require.Equal(t, []string{}, result)
	})

	t.Run("EarlyTermination", func(t *testing.T) {
		s1 := []string{"a", "b", "c", "d", "e"}
		s2 := []string{"f", "g", "h", "i", "j"}
		
		result := mergeUniqueStrings(s1, s2, 3)
		
		require.Equal(t, 3, len(result))
		// Should terminate early when limit is reached
	})
}

func TestMergeUniqueInt64s(t *testing.T) {
	t.Run("BasicMerge", func(t *testing.T) {
		s1 := []int64{1, 2, 3}
		s2 := []int64{2, 4, 5}
		
		result := mergeUniqueInt64s(s1, s2, 0)
		expected := []int64{1, 2, 3, 4, 5}
		
		require.Equal(t, expected, result)
	})

	t.Run("WithLimit", func(t *testing.T) {
		s1 := []int64{1, 2, 3}
		s2 := []int64{4, 5, 6}
		
		result := mergeUniqueInt64s(s1, s2, 4)
		
		require.LessOrEqual(t, len(result), 4)
		// Should be sorted for small arrays
		for i := 1; i < len(result); i++ {
			require.True(t, result[i-1] < result[i])
		}
	})

	t.Run("DuplicateRemoval", func(t *testing.T) {
		s1 := []int64{1, 2, 2, 3}
		s2 := []int64{2, 3, 4}
		
		result := mergeUniqueInt64s(s1, s2, 0)
		expected := []int64{1, 2, 3, 4}
		
		require.Equal(t, expected, result)
	})
}

func TestSourceIPPortArraysInProtoConversion(t *testing.T) {
	t.Run("ProtoToFlowWithSourceArrays", func(t *testing.T) {
		protoFlow := &proto.Flow{
			Key: &proto.FlowKey{
				SourceName:      "test-pod",
				SourceNamespace: "default",
				SourceType:      proto.WorkloadEndpoint,
				DestName:        "dest-pod", 
				DestNamespace:   "default",
				DestType:        proto.WorkloadEndpoint,
				DestPort:        80,
				Proto:           "TCP",
				Reporter:        proto.Src,
				Action:          proto.Allow,
			},
			StartTime:               1000,
			EndTime:                 2000,
			SourceLabels:            []string{"app=test"},
			DestLabels:              []string{"app=dest"},
			SourceIps:               []string{"1.1.1.1", "2.2.2.2"},
			SourcePorts:             []int64{8080, 9090},
			PacketsIn:               100,
			PacketsOut:              50,
			BytesIn:                 5000,
			BytesOut:                2500,
			NumConnectionsStarted:   5,
			NumConnectionsCompleted: 4,
			NumConnectionsLive:      1,
		}
		
		flow := ProtoToFlow(protoFlow)
		
		require.Equal(t, protoFlow.StartTime, flow.StartTime)
		require.Equal(t, protoFlow.EndTime, flow.EndTime)
		require.Equal(t, protoFlow.SourceIps, flow.SourceIPs)
		require.Equal(t, protoFlow.SourcePorts, flow.SourcePorts)
		require.Equal(t, protoFlow.PacketsIn, flow.PacketsIn)
		require.Equal(t, protoFlow.NumConnectionsLive, flow.NumConnectionsLive)
	})

	t.Run("FlowToProtoWithSourceArrays", func(t *testing.T) {
		flow := createTestFlow([]string{"1.1.1.1", "2.2.2.2"}, []int64{8080, 9090})
		
		protoFlow := FlowToProto(flow)
		
		require.Equal(t, flow.StartTime, protoFlow.StartTime)
		require.Equal(t, flow.EndTime, protoFlow.EndTime)
		require.Equal(t, flow.SourceIPs, protoFlow.SourceIps)
		require.Equal(t, flow.SourcePorts, protoFlow.SourcePorts)
		require.Equal(t, flow.PacketsIn, protoFlow.PacketsIn)
		require.Equal(t, flow.NumConnectionsLive, protoFlow.NumConnectionsLive)
	})

	t.Run("FlowIntoProtoWithSourceArrays", func(t *testing.T) {
		flow := createTestFlow([]string{"1.1.1.1"}, []int64{8080})
		protoFlow := &proto.Flow{Key: &proto.FlowKey{Policies: &proto.PolicyTrace{}}}
		
		FlowIntoProto(flow, protoFlow)
		
		require.Equal(t, flow.StartTime, protoFlow.StartTime)
		require.Equal(t, flow.SourceIPs, protoFlow.SourceIps)
		require.Equal(t, flow.SourcePorts, protoFlow.SourcePorts)
	})

	t.Run("FlowIntoProtoNilPanic", func(t *testing.T) {
		flow := createTestFlow([]string{"1.1.1.1"}, []int64{8080})
		
		require.Panics(t, func() {
			FlowIntoProto(flow, nil)
		})
	})
}

func TestFlowKeyWithoutSourceIPPort(t *testing.T) {
	t.Run("FlowKeyCreation", func(t *testing.T) {
		source := &FlowKeySource{
			SourceName:      "test-pod",
			SourceNamespace: "default",
			SourceType:      proto.WorkloadEndpoint,
		}
		dest := &FlowKeyDestination{
			DestName:      "dest-pod",
			DestNamespace: "default",
			DestType:      proto.WorkloadEndpoint,
			DestPort:      80,
		}
		meta := &FlowKeyMeta{
			Proto:    "TCP",
			Reporter: proto.Src,
			Action:   proto.Allow,
		}
		
		flowKey := NewFlowKey(source, dest, meta, &proto.PolicyTrace{})
		
		require.Equal(t, "test-pod", flowKey.SourceName())
		require.Equal(t, "default", flowKey.SourceNamespace())
		require.Equal(t, proto.WorkloadEndpoint, flowKey.SourceType())
		require.Equal(t, "dest-pod", flowKey.DestName())
		require.Equal(t, int64(80), flowKey.DestPort())
		require.Equal(t, "TCP", flowKey.Proto())
		require.Equal(t, proto.Src, flowKey.Reporter())
		require.Equal(t, proto.Allow, flowKey.Action())
	})

	t.Run("ProtoToFlowKeyConversion", func(t *testing.T) {
		protoKey := &proto.FlowKey{
			SourceName:      "test-pod",
			SourceNamespace: "default",
			SourceType:      proto.WorkloadEndpoint,
			SourceIp:        "1.1.1.1", // This should be ignored in key conversion
			SourcePort:      8080,      // This should be ignored in key conversion
			DestName:        "dest-pod",
			DestNamespace:   "default",
			DestType:        proto.WorkloadEndpoint,
			DestPort:        80,
			Proto:           "TCP",
			Reporter:        proto.Src,
			Action:          proto.Allow,
			Policies:        &proto.PolicyTrace{},
		}
		
		flowKey := ProtoToFlowKey(protoKey)
		
		// Source IP and port should not be accessible from FlowKey
		require.Equal(t, "test-pod", flowKey.SourceName())
		require.Equal(t, "default", flowKey.SourceNamespace())
		require.Equal(t, proto.WorkloadEndpoint, flowKey.SourceType())
	})
}

// Helper functions for creating test data

func createTestFlow(sourceIPs []string, sourcePorts []int64) *Flow {
	return createTestFlowWithTime(sourceIPs, sourcePorts, 1000, 2000)
}

func createTestFlowWithTime(sourceIPs []string, sourcePorts []int64, startTime, endTime int64) *Flow {
	return &Flow{
		Key: &FlowKey{
			source: unique.Make(FlowKeySource{
				SourceName:      "test-pod",
				SourceNamespace: "default",
				SourceType:      proto.WorkloadEndpoint,
			}),
			dest: unique.Make(FlowKeyDestination{
				DestName:      "dest-pod",
				DestNamespace: "default",
				DestType:      proto.WorkloadEndpoint,
				DestPort:      80,
			}),
			meta: unique.Make(FlowKeyMeta{
				Proto:    "TCP",
				Reporter: proto.Src,
				Action:   proto.Allow,
			}),
			policies: unique.Make(""),
		},
		StartTime:               startTime,
		EndTime:                 endTime,
		SourceLabels:            unique.Make("app=test"),
		DestLabels:              unique.Make("app=dest"),
		SourceIPs:               sourceIPs,
		SourcePorts:             sourcePorts,
		PacketsIn:               100,
		PacketsOut:              50,
		BytesIn:                 5000,
		BytesOut:                2500,
		NumConnectionsStarted:   5,
		NumConnectionsCompleted: 4,
		NumConnectionsLive:      1,
	}
}
