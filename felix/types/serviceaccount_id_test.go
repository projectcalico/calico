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

func TestProtoToServiceAccountID(t *testing.T) {
	tests := []struct {
		name string
		s    *proto.ServiceAccountID
		want ServiceAccountID
	}{
		{"empty", &proto.ServiceAccountID{}, ServiceAccountID{}},
		{"non-empty",
			&proto.ServiceAccountID{Namespace: "foo", Name: "bar"},
			ServiceAccountID{Namespace: "foo", Name: "bar"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProtoToServiceAccountID(tt.s); got != tt.want {
				t.Errorf("ProtoToServiceAccountID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceAccountIDToProto(t *testing.T) {
	tests := []struct {
		name string
		s    ServiceAccountID
		want *proto.ServiceAccountID
	}{
		{"empty", ServiceAccountID{}, &proto.ServiceAccountID{}},
		{"non-empty",
			ServiceAccountID{Namespace: "foo", Name: "bar"},
			&proto.ServiceAccountID{Namespace: "foo", Name: "bar"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ServiceAccountIDToProto(tt.s); !googleproto.Equal(got, tt.want) {
				t.Errorf("ServiceAccountIDToProto() = %v, want %v", got, tt.want)
			}
		})
	}
}
