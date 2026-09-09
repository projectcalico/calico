// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReportPath(t *testing.T) {
	root := fakeRepoRoot(t, "felix/bpf/proxy")
	tests := []struct {
		name    string
		giveDir string // working directory, relative to the repo root
		want    string // expected report path, relative to the repo root
	}{
		{
			name:    "component directory",
			giveDir: "felix",
			want:    "felix/report/x.xml",
		},
		{
			name:    "nested package directory",
			giveDir: "felix/bpf/proxy",
			want:    "felix/report/x.xml",
		},
		{
			name:    "repo root",
			giveDir: ".",
			want:    "report/x.xml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Chdir(filepath.Join(root, tt.giveDir))
			got, err := reportPath("x.xml")
			if err != nil {
				t.Fatalf("reportPath: %v", err)
			}
			if want := filepath.Join(root, filepath.FromSlash(tt.want)); got != want {
				t.Errorf("reportPath = %q, want %q", got, want)
			}
		})
	}
}

func TestReportPathOutsideRepo(t *testing.T) {
	t.Chdir(t.TempDir())
	if path, err := reportPath("x.xml"); err == nil {
		t.Errorf("reportPath = %q, want error when working directory is outside the repo", path)
	}
}

// fakeRepoRoot creates a directory tree that FindRepoRoot recognises as the
// calico repo root, plus the given subdirectories.  It returns the
// symlink-resolved root path so expectations match os.Getwd, which resolves
// symlinks (t.TempDir may sit behind one, e.g. /tmp on macOS).
func fakeRepoRoot(t *testing.T, subdirs ...string) string {
	t.Helper()
	root := t.TempDir()
	err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module github.com/projectcalico/calico\n"), 0o644)
	if err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	for _, dir := range subdirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve symlinks: %v", err)
	}
	return root
}
