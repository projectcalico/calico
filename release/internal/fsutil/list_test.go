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

package fsutil

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestListFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.tgz": "a", "SUMS": "s"})

	t.Run("lists nothing without filters", func(t *testing.T) {
		got, err := ListFiles(dir)
		if err != nil || got != nil {
			t.Errorf("ListFiles() = %v, %v, want nil, nil", got, err)
		}
	})

	t.Run("runs the filters in order", func(t *testing.T) {
		got, err := ListFiles(dir, DirFiles, Exclude("SUMS"))
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{filepath.Join(dir, "a.tgz")}; !slices.Equal(got, want) {
			t.Errorf("ListFiles() = %v, want %v", got, want)
		}
	})

	t.Run("stops at the first error", func(t *testing.T) {
		if _, err := ListFiles(dir, DirFiles, Include("missing.tgz"), Exclude("SUMS")); err == nil {
			t.Error("ListFiles() error = nil, want the Include error")
		}
	})
}

func TestDirFiles(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.tgz": "a", "SUMS": "s", "sub/b.tgz": "b"})
	symlink(t, filepath.Join(dir, "a.tgz"), filepath.Join(dir, "link.tgz"))

	t.Run("lists regular files but not subdirectories or symlinks", func(t *testing.T) {
		got, err := DirFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{filepath.Join(dir, "SUMS"), filepath.Join(dir, "a.tgz")}
		if !slices.Equal(got, want) {
			t.Errorf("DirFiles = %v, want %v", got, want)
		}
	})

	t.Run("fails on a missing directory", func(t *testing.T) {
		if _, err := DirFiles(filepath.Join(dir, "missing")); err == nil {
			t.Error("DirFiles error = nil, want an error")
		}
	})
}

func TestRecursive(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"top.txt": "top", "sub/deep/leaf.txt": "leaf"})
	symlink(t, filepath.Join(dir, "top.txt"), filepath.Join(dir, "link.txt"))

	t.Run("lists regular files at any depth but not symlinks", func(t *testing.T) {
		got, err := Recursive(dir)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{filepath.Join(dir, "sub/deep/leaf.txt"), filepath.Join(dir, "top.txt")}
		if !slices.Equal(got, want) {
			t.Errorf("Recursive = %v, want %v", got, want)
		}
	})

	t.Run("fails on a missing directory", func(t *testing.T) {
		if _, err := Recursive(filepath.Join(dir, "missing")); err == nil {
			t.Error("Recursive error = nil, want an error")
		}
	})
}

func TestMatch(t *testing.T) {
	t.Run("passes each file's path relative to dir", func(t *testing.T) {
		files := []string{"/d/a.txt", "/d/sub/a.txt", "/d/b.log"}
		var seen []string
		got, err := Match(func(relPath string) bool {
			seen = append(seen, relPath)
			return filepath.Ext(relPath) == ".txt"
		})("/d", files...)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"/d/a.txt", "/d/sub/a.txt"}; !slices.Equal(got, want) {
			t.Errorf("Match() = %v, want %v", got, want)
		}
		if want := []string{"a.txt", "sub/a.txt", "b.log"}; !slices.Equal(seen, want) {
			t.Errorf("relative paths = %v, want %v", seen, want)
		}
	})
}

func TestExclude(t *testing.T) {
	files := []string{"/d/a.tgz", "/d/SUMS", "/d/b.tgz", "/d/sub/c.src.rpm"}

	t.Run("leaves out files matching a name or glob", func(t *testing.T) {
		got, err := Exclude("SUMS", "*.src.rpm")("/d", files...)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"/d/a.tgz", "/d/b.tgz"}; !slices.Equal(got, want) {
			t.Errorf("Exclude() = %v, want %v", got, want)
		}
	})

	t.Run("does not change its input", func(t *testing.T) {
		in := slices.Clone(files)
		if _, err := Exclude("a.tgz")("/d", in...); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(in, files) {
			t.Errorf("input = %v, want %v", in, files)
		}
	})

	t.Run("fails on a malformed glob", func(t *testing.T) {
		if _, err := Exclude("[bad")("/d", files...); err == nil {
			t.Error("Exclude() error = nil, want an error")
		}
	})
}

func TestInclude(t *testing.T) {
	files := []string{"/d/a.tgz", "/d/b.tgz"}

	t.Run("keeps only the named files", func(t *testing.T) {
		got, err := Include("b.tgz")("/d", files...)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"/d/b.tgz"}; !slices.Equal(got, want) {
			t.Errorf("Include() = %v, want %v", got, want)
		}
	})

	t.Run("matches the path relative to dir, not the base name", func(t *testing.T) {
		if _, err := Include("c.tgz")("/d", "/d/sub/c.tgz"); err == nil {
			t.Error("Include() error = nil, want sub/c.tgz not to match c.tgz")
		}
		got, err := Include("sub/c.tgz")("/d", "/d/sub/c.tgz")
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"/d/sub/c.tgz"}; !slices.Equal(got, want) {
			t.Errorf("Include() = %v, want %v", got, want)
		}
	})

	t.Run("fails when a named file is missing", func(t *testing.T) {
		if _, err := Include("a.tgz", "missing.tgz")("/d", files...); err == nil || !strings.Contains(err.Error(), "missing.tgz") {
			t.Errorf("Include() error = %v, want one naming missing.tgz", err)
		}
	})
}

func TestIsRegular(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "a", "b.txt": "b", "sub/c.txt": "c"})
	fileA, fileB := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	link := filepath.Join(dir, "link.txt")
	symlink(t, fileA, link)

	t.Run("drops directories and symlinks", func(t *testing.T) {
		got, err := IsRegular(fileA, filepath.Join(dir, "sub"), link, fileB)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{fileA, fileB}; !slices.Equal(got, want) {
			t.Errorf("IsRegular() = %v, want %v", got, want)
		}
	})

	t.Run("fails on a file it cannot lstat", func(t *testing.T) {
		if _, err := IsRegular(fileA, filepath.Join(dir, "missing.txt")); err == nil {
			t.Error("IsRegular() error = nil, want an error")
		}
	})
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s: %v", link, err)
	}
}
