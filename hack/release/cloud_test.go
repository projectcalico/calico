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

package main

import "testing"

func TestIsCloudReleaseVersionFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		version string
		want    bool
	}{
		{
			version: "v3.22.1",
			want:    false,
		},
		{
			version: "v3.22.0-1.0",
			want:    false,
		},
		{
			version: "cloud-v3.22.1-0",
			want:    true,
		},
		{
			version: "cloud-v3.22.0-3.0-4",
			want:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			got, err := isCloudReleaseVersionFormat(tc.version)
			if err != nil {
				t.Fatalf("isCloudReleaseVersionFormat(%q) unexpected error: %v", tc.version, err)
			}
			if got != tc.want {
				t.Fatalf("isCloudReleaseVersionFormat(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}
