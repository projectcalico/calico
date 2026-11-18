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

//go:build fv

package defaults

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMetadata(t *testing.T) {
	t.Run("reads each key", func(t *testing.T) {
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
	})

	t.Run("ignores make's own variables", func(t *testing.T) {
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
	})
}
