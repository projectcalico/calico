// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
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

package types

import (
	"testing"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/felix/proto"
)

func TestProtoToWorkloadEndpointID(t *testing.T) {
	tests := []struct {
		name string
		w    *proto.WorkloadEndpointID
		want WorkloadEndpointID
	}{
		{"empty", &proto.WorkloadEndpointID{}, WorkloadEndpointID{}},
		{"non-empty",
			&proto.WorkloadEndpointID{OrchestratorId: "oid", WorkloadId: "wid", EndpointId: "eid"},
			WorkloadEndpointID{OrchestratorId: "oid", WorkloadId: "wid", EndpointId: "eid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProtoToWorkloadEndpointID(tt.w); got != tt.want {
				t.Errorf("ProtoToWorkloadEndpointID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWorkloadEndpointIDToProto(t *testing.T) {
	tests := []struct {
		name string
		w    WorkloadEndpointID
		want *proto.WorkloadEndpointID
	}{
		{"empty", WorkloadEndpointID{}, &proto.WorkloadEndpointID{}},
		{"non-empty",
			WorkloadEndpointID{OrchestratorId: "oid", WorkloadId: "wid", EndpointId: "eid"},
			&proto.WorkloadEndpointID{OrchestratorId: "oid", WorkloadId: "wid", EndpointId: "eid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WorkloadEndpointIDToProto(tt.w); !googleproto.Equal(got, tt.want) {
				t.Errorf("WorkloadEndpointIDToProto() = %v, want %v", got, tt.want)
			}
		})
	}
}
