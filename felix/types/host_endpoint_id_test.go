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

func TestHostEndpointID_String(t *testing.T) {
	tests := []struct {
		name string
		h    HostEndpointID
		want string
	}{
		{"empty", HostEndpointID{}, ""},
		{"non-empty", HostEndpointID{"foo"}, "foo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.h.String(); got != tt.want {
				t.Errorf("HostEndpointID.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtoToHostEndpointID(t *testing.T) {
	tests := []struct {
		name string
		h    *proto.HostEndpointID
		want HostEndpointID
	}{
		{"empty", &proto.HostEndpointID{}, HostEndpointID{}},
		{"non-empty", &proto.HostEndpointID{EndpointId: "foo"}, HostEndpointID{"foo"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProtoToHostEndpointID(tt.h); got != tt.want {
				t.Errorf("ProtoToHostEndpointID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHostEndpointIDToProto(t *testing.T) {
	tests := []struct {
		name string
		h    HostEndpointID
		want *proto.HostEndpointID
	}{
		{"empty", HostEndpointID{}, &proto.HostEndpointID{}},
		{"non-empty", HostEndpointID{"foo"}, &proto.HostEndpointID{EndpointId: "foo"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HostEndpointIDToProto(tt.h); !googleproto.Equal(got, tt.want) {
				t.Errorf("HostEndpointIDToProto() = %v, want %v", got, tt.want)
			}
		})
	}
}
