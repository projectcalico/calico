// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package version

import (
	"testing"
)

func TestNew(t *testing.T) {
	t.Run("adds a missing v", func(t *testing.T) {
		if got := mustNew(t, "3.29.0").String(); got != "v3.29.0" {
			t.Errorf("String() = %q, want %q", got, "v3.29.0")
		}
	})

	t.Run("zero value prints empty", func(t *testing.T) {
		if got := (Version{}).String(); got != "" {
			t.Errorf("String() = %q, want empty", got)
		}
	})

	t.Run("rejects a non-semver version", func(t *testing.T) {
		if _, err := New("release-v3.29"); err == nil {
			t.Error("want an error")
		}
	})
}

func TestStream(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    string
	}{
		{"v3.29.0", "v3.29"},
		{"v3.29.0-0.dev-424-gfd40f1838223", "v3.29"},
		{"v3.28.0-1.0", "v3.28-1"},
		{"v3.28.0-1.0-0.dev-424-gfd40f1838223", "v3.28-1"},
		{"v3.27.0-2.0", "v3.27"},
		{"v3.27.0-2.0-0.dev-424-gfd40f1838223", "v3.27"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			if got := mustNew(t, tc.version).Stream(); got != tc.want {
				t.Errorf("Stream() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNextBranchVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    string
	}{
		{"v3.29.0", "v3.30.0"},
		{"v3.29.0-0.dev-424-gfd40f1838223", "v3.30.0"},
		{"v3.28.0-1.0", "v3.28.0-2.0"},
		{"v3.27.0-2.0", "v3.28.0-1.0"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			if got := mustNew(t, tc.version).NextBranchVersion().String(); got != tc.want {
				t.Errorf("NextBranchVersion() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNextReleaseVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    string
	}{
		{"v3.29.0", "v3.29.1"},
		{"v3.29.0-0.dev-424-gfd40f1838223", "v3.29.0"},
		{"v3.28.0-1.0", "v3.28.0-1.1"},
		{"v3.28.0-1.0-0.dev-424-gfd40f1838223", "v3.28.0-1.1"},
		{"v3.27.0-2.0", "v3.27.1"},
		{"v3.27.0-2.0-0.dev-424-gfd40f1838223", "v3.27.1"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			got, err := mustNew(t, tc.version).NextReleaseVersion()
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Errorf("NextReleaseVersion() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDetermineReleaseVersion(t *testing.T) {
	for current, want := range map[string]string{
		"v3.20.0":  "v3.20.1",
		"v3.20.1":  "v3.20.2",
		"v3.22.0":  "v3.22.1",
		"v3.22.10": "v3.22.11",
		"v3.0.0":   "v3.0.1",

		"v3.29.0-0.dev-424-gfd40f1838223": "v3.29.0",

		"v3.15.0-12-gfd40f1838223": "v3.15.1",
		"v3.15.1-15-gfd40f1838223": "v3.15.2",
	} {
		t.Run(current, func(t *testing.T) {
			got, err := DetermineReleaseVersion(mustNew(t, current), "0.dev")
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != want {
				t.Errorf("DetermineReleaseVersion() = %q, want %q", got.String(), want)
			}
		})
	}
}

func TestDeterminePublishStream(t *testing.T) {
	for _, tc := range []struct {
		branch  string
		version string
		want    string
	}{
		{"release-v3.29", "v3.29.0", "v3.29"},
		{"master", "v3.29.0-0.dev-424-gfd40f1838223", "master"},
	} {
		t.Run(tc.branch, func(t *testing.T) {
			got, err := DeterminePublishStream(tc.branch, tc.version)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("DeterminePublishStream() = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("rejects a non-semver version", func(t *testing.T) {
		if _, err := DeterminePublishStream("release-v3.29", "not-a-version"); err == nil {
			t.Error("want an error")
		}
	})
}

func mustNew(t *testing.T, s string) Version {
	t.Helper()
	v, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
