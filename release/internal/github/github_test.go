// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package github

import "testing"

// Pinned to literals: deriving them from the builders would pass for any URL.
func TestDownloadURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		file []string
		want string
	}{
		{"release", nil, "https://github.com/projectcalico/calico/releases/download/v3.30.0"},
		{"artifact", []string{"SHA256SUMS"}, "https://github.com/projectcalico/calico/releases/download/v3.30.0/SHA256SUMS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DownloadURL("projectcalico", "calico", "v3.30.0", tc.file...)
			if err != nil {
				t.Fatalf("building url: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
