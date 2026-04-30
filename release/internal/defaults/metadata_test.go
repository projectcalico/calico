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
		KeyOrganization:         "testorg",
		KeyGitRepo:              "testrepo",
		KeyGitRemote:            "testremote",
		KeyReleaseBranchPrefix:  "testprefix",
		KeyDevTagSuffix:         "testsuffix",
		KeyOperatorBranch:       "test-operator-branch",
		KeyOperatorOrganization: "testopsorg",
		KeyOperatorGitRepo:      "testopsrepo",
	}
	for k, want := range cases {
		if got := m[k]; got != want {
			t.Errorf("key %q: got %q, want %q", k, got, want)
		}
	}
}

func TestAccessorsWithInjectedValues(t *testing.T) {
	t.Cleanup(resetValues)
	setValues(map[string]string{
		KeyOrganization:         "o",
		KeyGitRepo:              "r",
		KeyGitRemote:            "rem",
		KeyReleaseBranchPrefix:  "rp",
		KeyDevTagSuffix:         "ds",
		KeyOperatorBranch:       "ob",
		KeyOperatorOrganization: "oo",
		KeyOperatorGitRepo:      "orepo",
	})
	if got := Organization(); got != "o" {
		t.Errorf("Organization: got %q, want %q", got, "o")
	}
	if got := Repo(); got != "r" {
		t.Errorf("Repo: got %q, want %q", got, "r")
	}
	if got := Remote(); got != "rem" {
		t.Errorf("Remote: got %q, want %q", got, "rem")
	}
	if got := ReleaseBranchPrefix(); got != "rp" {
		t.Errorf("ReleaseBranchPrefix: got %q, want %q", got, "rp")
	}
	if got := DevTagSuffix(); got != "ds" {
		t.Errorf("DevTagSuffix: got %q, want %q", got, "ds")
	}
	if got := OperatorBranch(); got != "ob" {
		t.Errorf("OperatorBranch: got %q, want %q", got, "ob")
	}
	if got := OperatorOrganization(); got != "oo" {
		t.Errorf("OperatorOrganization: got %q, want %q", got, "oo")
	}
	if got := OperatorRepo(); got != "orepo" {
		t.Errorf("OperatorRepo: got %q, want %q", got, "orepo")
	}
}

func TestAccessorsEmptyWhenUnset(t *testing.T) {
	t.Cleanup(resetValues)
	setValues(map[string]string{})
	if got := Organization(); got != "" {
		t.Errorf("Organization with empty map: got %q, want empty", got)
	}
}
