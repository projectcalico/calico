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
func TestURLs(t *testing.T) {
	build := func(f func() (string, error)) string {
		t.Helper()
		got, err := f()
		if err != nil {
			t.Fatalf("building url: %v", err)
		}
		return got
	}
	for _, tc := range []struct {
		name string
		got  func() (string, error)
		want string
	}{
		{"repo", func() (string, error) { return RepoURL("projectcalico", "calico") },
			"https://github.com/projectcalico/calico"},
		{"download", func() (string, error) { return DownloadURL("projectcalico", "calico", "v3.30.0") },
			"https://github.com/projectcalico/calico/releases/download/v3.30.0"},
		{"artifact", func() (string, error) { return DownloadURL("projectcalico", "calico", "v3.30.0", "SHA256SUMS") },
			"https://github.com/projectcalico/calico/releases/download/v3.30.0/SHA256SUMS"},
		{"release", func() (string, error) { return ReleaseURL("projectcalico", "calico", "v3.30.0") },
			"https://github.com/projectcalico/calico/releases/tag/v3.30.0"},
		{"open pulls", func() (string, error) { return OpenPullsURL("projectcalico", "calico", "build-v3.30.0") },
			"https://github.com/projectcalico/calico/pulls?q=is%3Aopen+head%3Abuild-v3.30.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := build(tc.got); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
