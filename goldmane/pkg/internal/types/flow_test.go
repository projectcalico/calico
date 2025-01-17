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
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
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
					SourceType:           "source-type",
					DestName:             "dest-name",
					DestNamespace:        "dest-namespace",
					DestType:             "dest-type",
					DestPort:             1234,
					DestServiceName:      "dest-service-name",
					DestServiceNamespace: "dest-service-namespace",
					DestServicePortName:  "dest-service-port-name",
					DestServicePort:      5678,
					Proto:                "proto",
					Reporter:             "reporter",
					Action:               "action",
					Policies: &proto.FlowLogPolicy{
						AllPolicies: []string{"policy-1", "policy-2"},
					},
				},
				StartTime:               1234567890,
				EndTime:                 1234567891,
				SourceLabels:            []string{"source-label-1", "source-label-2"},
				DestLabels:              []string{"dest-label-1", "dest-label-2"},
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
