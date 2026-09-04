// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

import (
	"testing"

	"github.com/projectcalico/calico/operator/hack/release/internal/setup"
)

func TestIsReleaseVersionFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		version string
		want    bool
	}{
		{
			version: "v3.25.0",
			want:    true,
		},
		{
			version: "v3.25.0-rc1",
			want:    false,
		},
		{
			version: "v3.25.0-1.0",
			want:    false,
		},
		{
			version: "3.25.0-1.0-rc1",
			want:    false,
		},
		{
			version: "not-a-version",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			got, err := setup.IsValidReleaseVersion(tc.version)
			if err != nil {
				t.Fatalf("isReleaseVersionFormat(%q) unexpected error: %v", tc.version, err)
			}
			if got != tc.want {
				t.Fatalf("isReleaseVersionFormat(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestIsEnterpriseReleaseVersionFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		version string
		want    bool
	}{
		{
			version: "v3.25.0",
			want:    true,
		},
		{
			version: "v3.25.0-rc1",
			want:    false,
		},
		{
			version: "v3.25.0-1.0",
			want:    true,
		},
		{
			version: "3.25.0-1.0-rc1",
			want:    false,
		},
		{
			version: "not-a-version",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			got, err := isEnterpriseReleaseVersionFormat(tc.version)
			if err != nil {
				t.Fatalf("isEnterpriseReleaseVersionFormat(%q) unexpected error: %v", tc.version, err)
			}
			if got != tc.want {
				t.Fatalf("isEnterpriseReleaseVersionFormat(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestAddTrailingSlash(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input    string
		expected string
	}{
		{"docker.io", "docker.io/"},
		{"quay.io/", "quay.io/"},
		{"gcr.io/some-repo", "gcr.io/some-repo/"},
		{"", ""},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := addTrailingSlash(tc.input)
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestIsPrereleaseVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		version string
		want    bool
	}{
		{
			version: "v1.44.0",
			want:    false,
		},
		{
			version: "v1.44.0-rc1",
			want:    true,
		},
		{
			version: "v1.44.0-0.dev-12-gabcdef123456",
			want:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			got, err := isPrereleaseVersion(tc.version)
			if err != nil {
				t.Fatalf("isPrereleaseVersion(%q) unexpected error: %v", tc.version, err)
			}
			if got != tc.want {
				t.Fatalf("isPrereleaseVersion(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}
