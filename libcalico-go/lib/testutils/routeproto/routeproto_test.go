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

package routeproto

import "testing"

func TestParseAndString(t *testing.T) {
	cases := []struct {
		protocol string
		want     Proto
		wantStr  string
	}{
		{"", Unknown, "unknown"},
		{"bird", BIRD, "bird"},
		{"80", Felix, "felix"},
		{"12", BIRD, "bird"},
		{"42", Proto(42), "proto-42"},
		{"bogus", Unknown, "unknown"},
	}
	for _, c := range cases {
		got := Parse(c.protocol)
		if got != c.want {
			t.Errorf("Parse(%q) = %d, want %d", c.protocol, got, c.want)
		}
		if got.String() != c.wantStr {
			t.Errorf("Proto(%d).String() = %q, want %q", got, got.String(), c.wantStr)
		}
	}
}
