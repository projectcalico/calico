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

package runonvm

import "testing"

func TestSplitPair(t *testing.T) {
	for _, tc := range []struct {
		in   string
		a, b string
		ok   bool
	}{
		{"local:remote", "local", "remote", true},
		{"/a/b:/c/d", "/a/b", "/c/d", true},
		// Splits on the FIRST colon, so a remote path may contain one.
		{"VAR:/tmp/x:y", "VAR", "/tmp/x:y", true},
		{"", "", "", false},
		{"nocolon", "", "", false},
	} {
		a, b, ok := splitPair(tc.in)
		if a != tc.a || b != tc.b || ok != tc.ok {
			t.Errorf("splitPair(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, a, b, ok, tc.a, tc.b, tc.ok)
		}
	}
}
