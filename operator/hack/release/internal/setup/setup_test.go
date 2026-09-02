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

// TestReleaseVersionFormats checks the enterprise and cloud release-version validators directly
// (via matchesFormat), independent of the VARIANT env var, so both branches are covered in one run.
func TestReleaseVersionFormats(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		version      string
		enterpriseOK bool
		cloudOK      bool
	}{
		{name: "plain release", version: "v1.44.0", enterpriseOK: true, cloudOK: false},
		{name: "cloud release", version: "v1.44.0-cloud", enterpriseOK: false, cloudOK: true},
		{name: "old bespoke cloud format", version: "cloud-v3.22.1-0", enterpriseOK: false, cloudOK: false},
		{name: "enterprise-suffixed", version: "v3.22.0-1.0", enterpriseOK: false, cloudOK: false},
		{name: "not a version", version: "nope", enterpriseOK: false, cloudOK: false},
	}

	enterprise := matchesFormat(releaseVersionFormat)
	cloud := matchesFormat(cloudReleaseVersionFormat)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := enterprise(tc.version); err != nil || got != tc.enterpriseOK {
				t.Fatalf("enterprise(%q) = %v, %v; want %v", tc.version, got, err, tc.enterpriseOK)
			}
			if got, err := cloud(tc.version); err != nil || got != tc.cloudOK {
				t.Fatalf("cloud(%q) = %v, %v; want %v", tc.version, got, err, tc.cloudOK)
			}
		})
	}
}
