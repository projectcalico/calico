// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package defaults

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// setValues replaces the cached loader with one that returns v. Tests defer
// resetValues to ensure state does not leak between cases.
func setValues(v map[string]string) {
	load = sync.OnceValue(func() map[string]string { return v })
}

func resetValues() {
	load = sync.OnceValue(readMetadata)
}

func TestParseMetadata(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "metadata.mk"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m, err := parseMetadata(data)
	if err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	cases := map[string]string{
		KeyOrganization:        "testorg",
		KeyGitRepo:             "testrepo",
		KeyGitRemote:           "testremote",
		KeyReleaseBranchPrefix: "testprefix",
		KeyDevTagSuffix:        "testsuffix",
	}
	for k, want := range cases {
		if got := m[k]; got != want {
			t.Errorf("key %q: got %q, want %q", k, got, want)
		}
	}
}

func TestParseMetadataIgnoresPreExistingVars(t *testing.T) {
	m, err := parseMetadata([]byte("ORGANIZATION ?= newvalue\n"))
	if err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	if got := m[KeyOrganization]; got != "newvalue" {
		t.Errorf("ORGANIZATION: got %q, want %q", got, "newvalue")
	}
	for _, k := range []string{"VARS_OLD", "MAKEFLAGS", "SHELL", ".VARIABLES"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s should not appear in parsed output", k)
		}
	}
}

func TestAccessors(t *testing.T) {
	type values struct{ org, repo, remote, prefix, suffix string }
	get := func() values {
		return values{Organization(), Repo(), Remote(), ReleaseBranchPrefix(), DevTagSuffix()}
	}

	t.Run("metadata set", func(t *testing.T) {
		t.Cleanup(resetValues)
		setValues(map[string]string{
			KeyOrganization:        "o",
			KeyGitRepo:             "r",
			KeyGitRemote:           "rem",
			KeyReleaseBranchPrefix: "rp",
			KeyDevTagSuffix:        "ds",
		})
		if diff := cmp.Diff(values{"o", "r", "rem", "rp", "ds"}, get(), cmp.AllowUnexported(values{})); diff != "" {
			t.Errorf("accessors (-want +got):\n%s", diff)
		}
	})

	t.Run("metadata unset", func(t *testing.T) {
		t.Cleanup(resetValues)
		setValues(map[string]string{})
		want := values{organization, repo, remote, releaseBranchPrefix, devTagSuffix}
		if diff := cmp.Diff(want, get(), cmp.AllowUnexported(values{})); diff != "" {
			t.Errorf("accessors (-want +got):\n%s", diff)
		}
	})
}
