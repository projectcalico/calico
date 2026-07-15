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

package utils

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestMoveFile(t *testing.T) {
	t.Run("moves the single matching file", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "artifact-v1.2.3.tar")
		dst := filepath.Join(dir, "artifact.tar")
		if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
			t.Fatalf("failed to write src: %v", err)
		}

		if err := MoveFile(filepath.Join(dir, "artifact-*.tar"), dst); err != nil {
			t.Fatalf("MoveFile failed: %v", err)
		}

		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read dst: %v", err)
		}
		if string(got) != "payload" {
			t.Errorf("dst content = %q, want %q", got, "payload")
		}
		if _, err := os.Stat(src); !os.IsNotExist(err) {
			t.Errorf("expected src to be gone, stat err = %v", err)
		}
	})

	t.Run("errors when no file matches", func(t *testing.T) {
		dir := t.TempDir()
		if err := MoveFile(filepath.Join(dir, "nope-*.tar"), filepath.Join(dir, "out.tar")); err == nil {
			t.Error("expected an error when no file matches, got nil")
		}
	})

	t.Run("errors when multiple files match", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"a-1.tar", "a-2.tar"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatalf("failed to write %s: %v", name, err)
			}
		}
		if err := MoveFile(filepath.Join(dir, "a-*.tar"), filepath.Join(dir, "out.tar")); err == nil {
			t.Error("expected an error when multiple files match, got nil")
		}
	})
}

func TestCopyFile(t *testing.T) {
	t.Run("copies contents", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src.txt")
		dst := filepath.Join(dir, "dst.txt")
		if err := os.WriteFile(src, []byte("contents"), 0o644); err != nil {
			t.Fatalf("failed to write src: %v", err)
		}

		if err := CopyFile(src, dst); err != nil {
			t.Fatalf("CopyFile failed: %v", err)
		}

		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read dst: %v", err)
		}
		if string(got) != "contents" {
			t.Errorf("dst content = %q, want %q", got, "contents")
		}

		// A copy, not a link: the two paths must be distinct files.
		srcInfo, err := os.Stat(src)
		if err != nil {
			t.Fatalf("failed to stat src: %v", err)
		}
		dstInfo, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("failed to stat dst: %v", err)
		}
		if os.SameFile(srcInfo, dstInfo) {
			t.Error("expected src and dst to be distinct files (copy, not link)")
		}
	})

	t.Run("errors when source does not exist", func(t *testing.T) {
		dir := t.TempDir()
		if err := CopyFile(filepath.Join(dir, "missing.txt"), filepath.Join(dir, "dst.txt")); err == nil {
			t.Error("expected an error for a missing source, got nil")
		}
	})
}

func TestDirExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	cases := map[string]struct {
		path string
		want bool
	}{
		"existing directory": {path: dir, want: true},
		"regular file":       {path: file, want: false},
		"missing path":       {path: filepath.Join(dir, "missing"), want: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := DirExists(tc.path)
			if err != nil {
				t.Fatalf("DirExists failed: %v", err)
			}
			if got != tc.want {
				t.Errorf("DirExists(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	cases := map[string]struct {
		path string
		want bool
	}{
		"regular file":       {path: file, want: true},
		"existing directory": {path: dir, want: false},
		"missing path":       {path: filepath.Join(dir, "missing"), want: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := FileExists(tc.path)
			if err != nil {
				t.Fatalf("FileExists failed: %v", err)
			}
			if got != tc.want {
				t.Errorf("FileExists(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestPathExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	cases := map[string]struct {
		path string
		want bool
	}{
		"regular file":       {path: file, want: true},
		"existing directory": {path: dir, want: true},
		"missing path":       {path: filepath.Join(dir, "missing"), want: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := PathExists(tc.path)
			if err != nil {
				t.Fatalf("PathExists failed: %v", err)
			}
			if got != tc.want {
				t.Errorf("PathExists(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestCheckBinary(t *testing.T) {
	t.Run("finds a binary on PATH", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "mytool")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("failed to write binary: %v", err)
		}
		t.Setenv("PATH", dir)

		if err := CheckBinary("mytool", "testing"); err != nil {
			t.Errorf("CheckBinary failed: %v", err)
		}
	})

	t.Run("errors when the binary is absent", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if err := CheckBinary("definitely-not-a-real-binary", "testing"); err == nil {
			t.Error("expected an error for a missing binary, got nil")
		}
	})
}

func TestFilterRegularFiles(t *testing.T) {
	t.Run("keeps regular files and drops non-regular ones", func(t *testing.T) {
		dir := t.TempDir()
		fileA := filepath.Join(dir, "a.txt")
		fileB := filepath.Join(dir, "b.txt")
		subDir := filepath.Join(dir, "subdir")
		link := filepath.Join(dir, "link.txt")
		for _, f := range []string{fileA, fileB} {
			if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
				t.Fatalf("write %s: %v", f, err)
			}
		}
		if err := os.Mkdir(subDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Symlink(fileA, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		got, err := FilterRegularFiles([]string{fileA, subDir, link, fileB})
		if err != nil {
			t.Fatalf("FilterRegularFiles: unexpected error: %v", err)
		}
		want := []string{fileA, fileB}
		sort.Strings(got)
		sort.Strings(want)
		if len(got) != len(want) {
			t.Fatalf("filtered = %v, want %v", got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("filtered = %v, want %v", got, want)
				break
			}
		}
	})

	t.Run("empty input yields empty output", func(t *testing.T) {
		got, err := FilterRegularFiles(nil)
		if err != nil {
			t.Fatalf("FilterRegularFiles(nil): unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty result, got %v", got)
		}
	})

	t.Run("errors when a path cannot be lstat'd", func(t *testing.T) {
		dir := t.TempDir()
		good := filepath.Join(dir, "good.txt")
		if err := os.WriteFile(good, []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		missing := filepath.Join(dir, "missing.txt")
		if _, err := FilterRegularFiles([]string{good, missing}); err == nil {
			t.Error("expected an error for a missing path, got nil")
		}
	})
}

func TestLinkOrCopyFile(t *testing.T) {
	t.Run("hard links a file", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src.txt")
		dst := filepath.Join(dir, "dst.txt")
		if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
			t.Fatalf("failed to write src: %v", err)
		}

		if err := LinkOrCopyFile(src, dst); err != nil {
			t.Fatalf("LinkOrCopyFile failed: %v", err)
		}

		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read dst: %v", err)
		}
		if string(got) != "hello" {
			t.Errorf("dst content = %q, want %q", got, "hello")
		}

		// Within a single temp dir the two paths should share an inode,
		// confirming a hard link rather than a copy was used.
		srcInfo, err := os.Stat(src)
		if err != nil {
			t.Fatalf("failed to stat src: %v", err)
		}
		dstInfo, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("failed to stat dst: %v", err)
		}
		if !os.SameFile(srcInfo, dstInfo) {
			t.Error("expected src and dst to be the same file (hard link)")
		}
	})

	t.Run("overwrites an existing destination", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src.txt")
		dst := filepath.Join(dir, "dst.txt")
		if err := os.WriteFile(src, []byte("new"), 0o644); err != nil {
			t.Fatalf("failed to write src: %v", err)
		}
		if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
			t.Fatalf("failed to write dst: %v", err)
		}

		if err := LinkOrCopyFile(src, dst); err != nil {
			t.Fatalf("LinkOrCopyFile failed: %v", err)
		}

		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read dst: %v", err)
		}
		if string(got) != "new" {
			t.Errorf("dst content = %q, want %q", got, "new")
		}
	})

	t.Run("errors when source does not exist", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "missing.txt")
		dst := filepath.Join(dir, "dst.txt")

		if err := LinkOrCopyFile(src, dst); err == nil {
			t.Error("expected an error for a missing source, got nil")
		}
	})

	t.Run("preserves the source file mode", func(t *testing.T) {
		// Whether LinkOrCopyFile hard-links (dst shares the inode, hence the
		// mode) or falls back to copying (which chmods dst to match src), the
		// destination must end up with the source's mode — notably executable
		// bits, which the plain CopyFile fallback would otherwise drop.
		dir := t.TempDir()
		src := filepath.Join(dir, "script.sh")
		dst := filepath.Join(dir, "copy.sh")
		if err := os.WriteFile(src, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("failed to write src: %v", err)
		}

		if err := LinkOrCopyFile(src, dst); err != nil {
			t.Fatalf("LinkOrCopyFile failed: %v", err)
		}

		srcInfo, err := os.Stat(src)
		if err != nil {
			t.Fatalf("failed to stat src: %v", err)
		}
		dstInfo, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("failed to stat dst: %v", err)
		}
		if dstInfo.Mode() != srcInfo.Mode() {
			t.Errorf("dst mode = %v, want %v", dstInfo.Mode(), srcInfo.Mode())
		}
	})
}

func TestLinkOrCopyDir(t *testing.T) {
	// includeAll matches every file.
	includeAll := func(_, _, _ string) bool { return true }

	t.Run("copies all files preserving structure", func(t *testing.T) {
		srcDir := t.TempDir()
		dstDir := t.TempDir()
		files := map[string]string{
			"top.txt":            "top",
			"sub/nested.txt":     "nested",
			"sub/deep/leaf.txt":  "leaf",
			"other/sibling.json": "sibling",
		}
		writeTree(t, srcDir, files)

		if err := LinkOrCopyDir(srcDir, dstDir, includeAll); err != nil {
			t.Fatalf("LinkOrCopyDir failed: %v", err)
		}

		assertTree(t, dstDir, files)
	})

	t.Run("only copies included files", func(t *testing.T) {
		srcDir := t.TempDir()
		dstDir := t.TempDir()
		writeTree(t, srcDir, map[string]string{
			"keep.txt":     "keep",
			"skip.log":     "skip",
			"sub/keep.txt": "keep2",
			"sub/skip.log": "skip2",
		})

		onlyTxt := func(_, _, relPath string) bool {
			return filepath.Ext(relPath) == ".txt"
		}
		if err := LinkOrCopyDir(srcDir, dstDir, onlyTxt); err != nil {
			t.Fatalf("LinkOrCopyDir failed: %v", err)
		}

		assertTree(t, dstDir, map[string]string{
			"keep.txt":     "keep",
			"sub/keep.txt": "keep2",
		})
		for _, rel := range []string{"skip.log", "sub/skip.log"} {
			if _, err := os.Stat(filepath.Join(dstDir, rel)); !os.IsNotExist(err) {
				t.Errorf("expected %s to be excluded, stat err = %v", rel, err)
			}
		}
	})

	t.Run("skips non-regular entries", func(t *testing.T) {
		// A symlink (even one pointing at a regular file) is not a regular file
		// and must be skipped rather than copied.
		srcDir := t.TempDir()
		dstDir := t.TempDir()
		writeTree(t, srcDir, map[string]string{"real.txt": "real"})
		if err := os.Symlink(filepath.Join(srcDir, "real.txt"), filepath.Join(srcDir, "link.txt")); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		if err := LinkOrCopyDir(srcDir, dstDir, includeAll); err != nil {
			t.Fatalf("LinkOrCopyDir failed: %v", err)
		}

		// Only the regular file is copied; the symlink is skipped.
		assertTree(t, dstDir, map[string]string{"real.txt": "real"})
		if _, err := os.Lstat(filepath.Join(dstDir, "link.txt")); !os.IsNotExist(err) {
			t.Errorf("expected symlink to be skipped, lstat err = %v", err)
		}
	})

	t.Run("errors when source does not exist", func(t *testing.T) {
		dstDir := t.TempDir()
		if err := LinkOrCopyDir(filepath.Join(t.TempDir(), "missing"), dstDir, includeAll); err == nil {
			t.Error("expected an error for a missing source directory, got nil")
		}
	})
}

func TestFindRecursiveFiles(t *testing.T) {
	t.Run("returns only included files", func(t *testing.T) {
		srcDir := t.TempDir()
		writeTree(t, srcDir, map[string]string{
			"keep.txt":     "keep",
			"skip.log":     "skip",
			"sub/keep.txt": "keep2",
			"sub/skip.log": "skip2",
		})

		onlyTxt := func(_, _, relPath string) bool {
			return filepath.Ext(relPath) == ".txt"
		}
		got, err := FindRecursiveFiles(srcDir, onlyTxt)
		if err != nil {
			t.Fatalf("FindRecursiveFiles failed: %v", err)
		}

		want := []string{
			filepath.Join(srcDir, "keep.txt"),
			filepath.Join(srcDir, "sub/keep.txt"),
		}
		sort.Strings(got)
		sort.Strings(want)
		if len(got) != len(want) {
			t.Fatalf("found files = %v, want %v", got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("found files = %v, want %v", got, want)
				break
			}
		}
	})

	t.Run("skips non-regular entries", func(t *testing.T) {
		// A symlink is not a regular file and must not appear in the results,
		// matching the doc comment's "regular file" contract.
		srcDir := t.TempDir()
		writeTree(t, srcDir, map[string]string{"real.txt": "real"})
		if err := os.Symlink(filepath.Join(srcDir, "real.txt"), filepath.Join(srcDir, "link.txt")); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}

		includeAll := func(_, _, _ string) bool { return true }
		got, err := FindRecursiveFiles(srcDir, includeAll)
		if err != nil {
			t.Fatalf("FindRecursiveFiles failed: %v", err)
		}

		want := []string{filepath.Join(srcDir, "real.txt")}
		if len(got) != len(want) || (len(got) == 1 && got[0] != want[0]) {
			t.Errorf("found files = %v, want %v", got, want)
		}
	})

	t.Run("errors when source does not exist", func(t *testing.T) {
		includeAll := func(_, _, _ string) bool { return true }
		if _, err := FindRecursiveFiles(filepath.Join(t.TempDir(), "missing"), includeAll); err == nil {
			t.Error("expected an error for a missing source directory, got nil")
		}
	})
}

func TestMatchRegexp(t *testing.T) {
	match, err := MatchRegexp(`^.*_test\.go$`)
	if err != nil {
		t.Fatalf("MatchRegexp failed: %v", err)
	}
	cases := map[string]bool{
		"files_test.go":     true,
		"sub/dir_test.go":   true,
		"files.go":          false,
		"test_helper.go":    false,
		"sub/dir/notes.txt": false,
	}
	for relPath, want := range cases {
		if got := match("", "", relPath); got != want {
			t.Errorf("match(%q) = %v, want %v", relPath, got, want)
		}
	}

	if _, err := MatchRegexp(`(`); err == nil {
		t.Error("expected an error for an invalid regexp, got nil")
	}
}

func TestMatchGlobs(t *testing.T) {
	match, err := MatchGlobs("*.txt", "README*")
	if err != nil {
		t.Fatalf("MatchGlobs failed: %v", err)
	}
	cases := map[string]bool{
		"notes.txt":        true,
		"sub/deep/foo.txt": true,
		"README.md":        true,
		"sub/README":       true,
		"main.go":          false,
		"sub/data.json":    false,
	}
	for relPath, want := range cases {
		if got := match("", "", relPath); got != want {
			t.Errorf("match(%q) = %v, want %v", relPath, got, want)
		}
	}

	if _, err := MatchGlobs("[bad"); err == nil {
		t.Error("expected an error for a malformed glob, got nil")
	}
}

func TestMatchExtensions(t *testing.T) {
	// Mix of dotted and bare extensions, plus differing case.
	match := MatchExtensions(".txt", "json", "GO")
	cases := map[string]bool{
		"notes.txt":        true,
		"sub/data.json":    true,
		"main.go":          true,
		"IMAGE.JSON":       true,
		"archive.tar.gz":   false,
		"sub/no_extension": false,
	}
	for relPath, want := range cases {
		if got := match("", "", relPath); got != want {
			t.Errorf("match(%q) = %v, want %v", relPath, got, want)
		}
	}
}

// writeTree writes the given relPath -> contents map under root, creating
// intermediate directories as needed.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, contents := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("failed to create dir for %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatalf("failed to write %s: %v", rel, err)
		}
	}
}

// assertTree verifies that root contains exactly the given relPath -> contents
// map (no extra files, all contents matching).
func assertTree(t *testing.T, root string, want map[string]string) {
	t.Helper()
	var got []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		got = append(got, rel)
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(contents) != want[rel] {
			t.Errorf("%s content = %q, want %q", rel, contents, want[rel])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk dst: %v", err)
	}

	wantPaths := make([]string, 0, len(want))
	for rel := range want {
		wantPaths = append(wantPaths, rel)
	}
	sort.Strings(got)
	sort.Strings(wantPaths)
	if len(got) != len(wantPaths) {
		t.Errorf("copied files = %v, want %v", got, wantPaths)
		return
	}
	for i := range got {
		if got[i] != wantPaths[i] {
			t.Errorf("copied files = %v, want %v", got, wantPaths)
			return
		}
	}
}
