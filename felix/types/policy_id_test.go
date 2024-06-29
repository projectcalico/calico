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

func TestPolicyID_String(t *testing.T) {
	tests := []struct {
		name string
		p    PolicyID
		want string
	}{
		{"empty", PolicyID{}, "{Tier: , Name: }"},
		{"non-empty", PolicyID{"foo", "bar"}, "{Tier: foo, Name: bar}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("PolicyID.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtoToPolicyID(t *testing.T) {
	tests := []struct {
		name string
		p    *proto.PolicyID
		want PolicyID
	}{
		{"empty", nil, PolicyID{}},
		{"non-empty", &proto.PolicyID{Tier: "foo", Name: "bar"}, PolicyID{Tier: "foo", Name: "bar"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProtoToPolicyID(tt.p); got != tt.want {
				t.Errorf("ProtoToPolicyID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyIDToProto(t *testing.T) {
	tests := []struct {
		name string
		p    PolicyID
		want *proto.PolicyID
	}{
		{"empty", PolicyID{}, &proto.PolicyID{}},
		{"non-empty", PolicyID{Tier: "foo", Name: "bar"}, &proto.PolicyID{Tier: "foo", Name: "bar"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PolicyIDToProto(tt.p); !googleproto.Equal(got, tt.want) {
				t.Errorf("PolicyIDToProto() = %v, want %v", got, tt.want)
			}
		})
	}
}
