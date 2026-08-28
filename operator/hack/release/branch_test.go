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

import (
	"fmt"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
)

func TestIsReleaseBranch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		prefix string
		branch string
		want   bool
	}{
		// Default prefix "release"
		{"release", "release-v1.43", true},
		{"release", "release-v1.0", true},
		{"release", "release-v10.20", true},
		{"release", "master", false},
		{"release", "main", false},
		{"release", "release-v1.43.1", false},
		{"release", "release-v1", false},
		{"release", "release-1.43", false},
		{"release", "feature/release-v1.43", false},
		{"release", "release-v1.43-rc1", false},
		{"release", "", false},

		// Custom prefix
		{"rel", "rel-v1.43", true},
		{"rel", "release-v1.43", false},

		// Prefix with regex metacharacters should be escaped
		{"release.test", "release.test-v1.43", true},
		{"release.test", "releasextest-v1.43", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.prefix, tt.branch), func(t *testing.T) {
			t.Parallel()
			got, err := isReleaseBranch(tt.prefix, tt.branch)
			if err != nil {
				t.Fatalf("isReleaseBranch(%q, %q) unexpected error: %v", tt.prefix, tt.branch, err)
			}
			if got != tt.want {
				t.Fatalf("isReleaseBranch(%q, %q) = %v, want %v", tt.prefix, tt.branch, got, tt.want)
			}
		})
	}
}

func TestNextDevRelease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		stream     string
		devSuffix  string
		wantStream string

		wantTag      string
		wantParseErr bool
	}{
		{"v1.43", "0.dev", "v1.44", "v1.44.0-0.dev", false},
		{"v1.0", "0.dev", "v1.1", "v1.1.0-0.dev", false},
		{"v10.20", "0.dev", "v10.21", "v10.21.0-0.dev", false},
		{"v0.1", "0.dev", "v0.2", "v0.2.0-0.dev", false},
		{"invalid", "0.dev", "", "", true},
		{"v1", "0.dev", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.stream, func(t *testing.T) {
			t.Parallel()
			gotStream, gotTag, err := nextDevRelease(tt.stream, tt.devSuffix)
			if tt.wantParseErr && err == nil {
				t.Fatalf("nextDevRelease(%q, %q) expected parse error but got none", tt.stream, tt.devSuffix)
			} else if !tt.wantParseErr && err != nil {
				t.Fatalf("nextDevRelease(%q, %q) unexpected error: %v", tt.stream, tt.devSuffix, err)
			}
			if gotStream != tt.wantStream {
				t.Fatalf("nextDevRelease(%q, %q) stream = %q, want %q", tt.stream, tt.devSuffix, gotStream, tt.wantStream)
			}
			if gotTag != tt.wantTag {
				t.Fatalf("nextDevRelease(%q, %q) tag = %q, want %q", tt.stream, tt.devSuffix, gotTag, tt.wantTag)
			}
			if tt.wantParseErr {
				return // if we expected a parse error, we don't need to check the tag format
			}
			// sanity: verify that the generated tag is a valid semver
			if _, err := semver.Parse(strings.TrimPrefix(gotTag, "v")); err != nil {
				t.Fatalf("nextDevRelease(%q, %q) generated invalid semver tag %q: %v", tt.stream, tt.devSuffix, gotTag, err)
			}
		})
	}
}

func TestValidateStreamFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		stream string
		want   bool
	}{
		{"v1.43", true},
		{"v1.0", true},
		{"v10.20", true},
		{"v0.1", true},
		{"1.43", false},
		{"v1.43.1", false},
		{"v1", false},
		{"vX.Y", false},
		{"master", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.stream), func(t *testing.T) {
			t.Parallel()
			got, err := isValidStream(tt.stream)
			if err != nil {
				t.Fatalf("isValidStreamFormat(%q) unexpected error: %v", tt.stream, err)
			}
			if got != tt.want {
				t.Fatalf("isValidStreamFormat(%q) = %v, want %v", tt.stream, got, tt.want)
			}
		})
	}
}
