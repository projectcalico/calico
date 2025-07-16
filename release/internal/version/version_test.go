// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestVersionStream(t *testing.T) {
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
			v := New(tc.version)
			require.Equal(t, tc.want, v.Stream())
		})
	}
}

func TestVersionNextBranchVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    Version
	}{
		{"v3.29.0", New("v3.30.0")},
		{"v3.29.0-0.dev-424-gfd40f1838223", New("v3.30.0")},
		{"v3.28.0-1.0", New("v3.28.0-2.0")},
		{"v3.27.0-2.0", New("v3.28.0-1.0")},
	} {
		t.Run(tc.version, func(t *testing.T) {
			v := New(tc.version)
			got := v.NextBranchVersion()
			require.Equal(t, tc.want.String(), got.String())
		})
	}
}

func TestVersionNextReleaseVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    Version
	}{
		{"v3.29.0", New("v3.29.1")},
		{"v3.29.0-0.dev-424-gfd40f1838223", New("v3.29.0")},
		{"v3.28.0-1.0", New("v3.28.0-1.1")},
		{"v3.28.0-1.0-0.dev-424-gfd40f1838223", New("v3.28.0-1.1")},
		{"v3.27.0-2.0", New("v3.27.1")},
		{"v3.27.0-2.0-0.dev-424-gfd40f1838223", New("v3.27.1")},
	} {
		t.Run(tc.version, func(t *testing.T) {
			v := New(tc.version)
			got, err := v.NextReleaseVersion()
			require.NoError(t, err)
			require.Equal(t, tc.want.String(), got.String())
		})
	}
}

func TestDetermineReleaseVersion(t *testing.T) {
	expectations := map[string]string{
		// Simple base case - increment the patch number if cutting from an existing tag.
		"v3.20.0":  "v3.20.1",
		"v3.20.1":  "v3.20.2",
		"v3.22.0":  "v3.22.1",
		"v3.22.10": "v3.22.11",
		"v3.0.0":   "v3.0.1",

		// A dev tag leading up to a minor release should return the minor release number.
		"v3.29.0-0.dev-424-gfd40f1838223": "v3.29.0",

		// Previous tag was a patch release, should increment the patch number.
		"v3.15.0-12-gfd40f1838223": "v3.15.1",
		"v3.15.1-15-gfd40f1838223": "v3.15.2",
	}

	for current, next := range expectations {
		logrus.Infof("Test current version = %v", current)
		actual, err := DetermineReleaseVersion(New(current), "0.dev")
		require.NoError(t, err)
		require.Equal(t, next, actual.FormattedString())
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
		t.Run(tc.version, func(t *testing.T) {
			require.Equal(t, tc.want, DeterminePublishStream(tc.branch, tc.version))
		})
	}
}
