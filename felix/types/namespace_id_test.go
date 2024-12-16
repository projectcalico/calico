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

func TestProtoToNamespaceID(t *testing.T) {
	tests := []struct {
		name string
		n    *proto.NamespaceID
		want NamespaceID
	}{
		{"empty", &proto.NamespaceID{}, NamespaceID{}},
		{"non-empty", &proto.NamespaceID{Name: "foo"}, NamespaceID{"foo"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProtoToNamespaceID(tt.n); got != tt.want {
				t.Errorf("ProtoToNamespaceID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamespaceIDToProto(t *testing.T) {
	tests := []struct {
		name string
		n    NamespaceID
		want *proto.NamespaceID
	}{
		{"empty", NamespaceID{}, &proto.NamespaceID{}},
		{"non-empty", NamespaceID{"foo"}, &proto.NamespaceID{Name: "foo"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NamespaceIDToProto(tt.n); !googleproto.Equal(got, tt.want) {
				t.Errorf("NamespaceIDToProto() = %v, want %v", got, tt.want)
			}
		})
	}
}
