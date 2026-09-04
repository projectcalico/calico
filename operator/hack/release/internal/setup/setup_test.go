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

package setup

import "testing"

// TestReleaseVersionFormats checks the release-version validator directly, via matchesFormat.
func TestReleaseVersionFormats(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "plain release", version: "v1.44.0", want: true},
		{name: "suffixed release", version: "v1.44.0-cloud", want: false},
		{name: "enterprise-suffixed", version: "v3.22.0-1.0", want: false},
		{name: "not a version", version: "nope", want: false},
	}

	valid := matchesFormat(releaseVersionFormat)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := valid(tc.version); err != nil || got != tc.want {
				t.Fatalf("valid(%q) = %v, %v; want %v", tc.version, got, err, tc.want)
			}
		})
	}
}
