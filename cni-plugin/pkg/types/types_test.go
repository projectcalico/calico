// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"encoding/json"
	"testing"
)

func TestNetConfDeviceTypeParsing(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"omitted", `{}`, ""},
		{"empty", `{"device_type":""}`, ""},
		{"veth", `{"device_type":"veth"}`, DeviceTypeVeth},
		{"netkit", `{"device_type":"netkit"}`, DeviceTypeNetkit},
		// Parsing itself doesn't reject unknown values; plugin.go cmdAdd
		// normalises unknown values to "" at runtime.
		{"unknown-passes-through", `{"device_type":"bogus"}`, "bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c NetConf
			if err := json.Unmarshal([]byte(tc.raw), &c); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.DeviceType != tc.want {
				t.Errorf("DeviceType = %q, want %q", c.DeviceType, tc.want)
			}
		})
	}
}
