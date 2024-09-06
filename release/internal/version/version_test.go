// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package version_test

import (
	"testing"

	"github.com/projectcalico/calico/release/internal/version"
	"github.com/stretchr/testify/require"
)

func TestNextVersion(t *testing.T) {
	expectations := map[string]string{
		"v3.20.0":                         "v3.21.0",
		"v3.29.0-0.dev-424-gfd40f1838223": "v3.30.0",
		"v3.15.0-12-gfd40f1838223":        "v3.16.0",
		"v3.15.1-15-gfd40f1838223":        "v3.16.0",
	}

	for current, next := range expectations {
		cv := version.Version(current)
		nv := cv.NextVersion()
		require.Equal(t, next, nv.FormattedString())
	}
}

func TestDetermineReleaseVersion(t *testing.T) {
	expectations := map[string]string{
		// Simple base case - increment the patch number if cutting from an existing tag.
		"v3.20.0": "v3.20.1",
		"v3.20.1": "v3.20.2",
		"v3.0.0":  "v3.0.1",

		// A dev tag leading up to a minor release should return the minor release number.
		"v3.29.0-0.dev-424-gfd40f1838223": "v3.29.0",

		// Previous tag was a patch release, should increment the patch number.
		"v3.15.0-12-gfd40f1838223": "v3.15.1",
		"v3.15.1-15-gfd40f1838223": "v3.15.2",
	}

	for current, next := range expectations {
		actual, err := version.DetermineReleaseVersion(version.New(current))
		require.NoError(t, err)
		require.Equal(t, next, actual.FormattedString())
	}
}

func TestIsDevVersion(t *testing.T) {
	expectations := map[string]bool{
		"v3.20.0":                               false,
		"v3.29.0-0.dev-424-gfd40f1838223":       true,
		"v3.15.0-12-gfd40f1838223":              false,
		"v3.29.0-0.dev-430-g59af68ddd525":       true,
		"v3.29.0-0.dev-430-g59af68ddd525-dirty": true,
	}

	for v, expected := range expectations {
		require.Equal(t, expected, version.IsDevVersion(v, "0.dev"), v)
	}
}
