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

package calico

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnerFromRemoteURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{
			name: "SSH with .git suffix",
			url:  "git@github.com:projectcalico/calico.git",
			want: "projectcalico",
		},
		{
			name: "SSH without .git suffix",
			url:  "git@github.com:projectcalico/calico",
			want: "projectcalico",
		},
		{
			name: "HTTPS with .git suffix",
			url:  "https://github.com/projectcalico/calico.git",
			want: "projectcalico",
		},
		{
			name: "HTTPS without .git suffix",
			url:  "https://github.com/projectcalico/calico",
			want: "projectcalico",
		},
		{
			name: "SSH fork",
			url:  "git@github.com:myFork/calico.git",
			want: "myFork",
		},
		{
			name: "HTTPS fork",
			url:  "https://github.com/myFork/calico.git",
			want: "myFork",
		},
		{
			name: "SSH with nested path",
			url:  "git@github.com:org/sub/repo.git",
			want: "sub",
		},
		{
			name:    "bare hostname no path",
			url:     "github.com",
			wantErr: true,
		},
		{
			name:    "empty string",
			url:     "",
			wantErr: true,
		},
		{
			name:    "local path",
			url:     "/tmp/repo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ownerFromRemoteURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ownerFromRemoteURL(%q) = %q, want error", tt.url, got)
				}
				return
			}
			if err != nil {
				t.Errorf("ownerFromRemoteURL(%q) error = %v", tt.url, err)
				return
			}
			if got != tt.want {
				t.Errorf("ownerFromRemoteURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestUpdateDefaultsYAML(t *testing.T) {
	const input = `# Header comment
git:
  organization: projectcalico
  # Operator repo
  operator_branch: master
  operator_organization: tigera
versions:
  kubernetes: v1.35.2
`

	writeFixture := func(t *testing.T) string {
		t.Helper()
		f := filepath.Join(t.TempDir(), "defaults.yaml")
		if err := os.WriteFile(f, []byte(input), 0644); err != nil {
			t.Fatal(err)
		}
		return f
	}

	t.Run("update existing key", func(t *testing.T) {
		f := writeFixture(t)

		if err := updateDefaultsYAML(f, []string{"git", "operator_branch"}, "release-v3.29"); err != nil {
			t.Fatal(err)
		}

		got, _ := os.ReadFile(f)
		s := string(got)
		if !strings.Contains(s, "operator_branch: release-v3.29") {
			t.Errorf("expected updated value, got:\n%s", s)
		}
		if !strings.Contains(s, "# Operator repo") {
			t.Error("comment was not preserved")
		}
		if !strings.Contains(s, "# Header comment") {
			t.Error("header comment was not preserved")
		}
		if !strings.Contains(s, "organization: projectcalico") {
			t.Error("sibling key was modified")
		}
	})

	t.Run("nested key in different section", func(t *testing.T) {
		f := writeFixture(t)

		if err := updateDefaultsYAML(f, []string{"versions", "kubernetes"}, "v1.36.0"); err != nil {
			t.Fatal(err)
		}

		got, _ := os.ReadFile(f)
		if !strings.Contains(string(got), "kubernetes: v1.36.0") {
			t.Errorf("expected updated value, got:\n%s", string(got))
		}
	})

	t.Run("missing top-level key", func(t *testing.T) {
		f := writeFixture(t)

		err := updateDefaultsYAML(f, []string{"nonexistent", "key"}, "val")
		if err == nil {
			t.Fatal("expected error for missing key")
		}
		if !strings.Contains(err.Error(), `"nonexistent"`) {
			t.Errorf("error should mention missing key, got: %v", err)
		}
	})

	t.Run("missing nested key", func(t *testing.T) {
		f := writeFixture(t)

		err := updateDefaultsYAML(f, []string{"git", "nonexistent"}, "val")
		if err == nil {
			t.Fatal("expected error for missing nested key")
		}
		if !strings.Contains(err.Error(), `"git.nonexistent"`) {
			t.Errorf("error should mention full key path, got: %v", err)
		}
	})
}

// TestUpdateDefaultsYAMLKeyPathsExist verifies that the key paths used by the
// release tooling actually exist in the real defaults.yaml.  If someone renames
// a key in the YAML without updating manager.go, this test fails.
func TestUpdateDefaultsYAMLKeyPathsExist(t *testing.T) {
	// Walk up from the test file to find the repo root (contains defaults.yaml).
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Skip("could not find repo root:", err)
	}
	defaultsFile := filepath.Join(repoRoot, "defaults.yaml")
	if _, err := os.Stat(defaultsFile); err != nil {
		t.Skip("defaults.yaml not found:", err)
	}

	// These are the key paths used in manager.go's SetupReleaseBranch.
	// Keep this list in sync with the actual updateDefaultsYAML calls.
	requiredPaths := [][]string{
		{"git", "operator_branch"},
	}

	for _, keyPath := range requiredPaths {
		t.Run(strings.Join(keyPath, "."), func(t *testing.T) {
			// Copy the real file to a temp location so we don't modify it.
			data, err := os.ReadFile(defaultsFile)
			if err != nil {
				t.Fatal(err)
			}
			f := filepath.Join(t.TempDir(), "defaults.yaml")
			if err := os.WriteFile(f, data, 0644); err != nil {
				t.Fatal(err)
			}
			if err := updateDefaultsYAML(f, keyPath, "test-value"); err != nil {
				t.Errorf("key path %v does not exist in defaults.yaml: %v", keyPath, err)
			}
		})
	}
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "defaults.yaml")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("defaults.yaml not found in any parent directory")
		}
		dir = parent
	}
}
