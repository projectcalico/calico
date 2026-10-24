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

package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Restored modes depend on the umask when not running as root.
	syscall.Umask(0o022)
	os.Exit(m.Run())
}

// buildTree creates, in the working directory, the kinds of entries a cache
// holds, including a read-only directory like Go's module cache, and returns
// the paths to archive.
func buildTree(t *testing.T) []string {
	t.Helper()
	files := []struct {
		name    string
		mode    os.FileMode
		content string
	}{
		{"tree/bin/tool", 0o755, "#!/bin/sh\n"},
		{"tree/data.txt", 0o644, "data"},
		{"tree/.hidden", 0o600, "hidden"},
		{"tree/with space.txt", 0o644, "space"},
		{"tree/" + strings.Repeat("d", 60) + "/" + strings.Repeat("f", 70) + ".txt", 0o644, "long name"},
		{"pkg/mod/m@v1.0.0/go.mod", 0o444, "module m\n"},
		{"other.txt", 0o640, "other"},
	}
	for _, f := range files {
		writeFile(t, f.name, f.content)
		if err := os.Chmod(f.name, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	must(t, os.Mkdir("tree/empty", 0o750))
	must(t, os.Symlink("data.txt", "tree/link"))
	must(t, os.Link("tree/data.txt", "tree/hard"))
	must(t, os.Chmod("pkg/mod/m@v1.0.0", 0o555))

	var paths []string
	for _, root := range []string{"tree", "pkg", "other.txt"} {
		must(t, filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
			paths = append(paths, p)
			return err
		}))
	}
	// Children before parents, so setting a child does not move its
	// parent's mtime.
	base := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	for i, p := range slices.Backward(paths) {
		if fi, _ := os.Lstat(p); fi.Mode()&fs.ModeSymlink == 0 {
			ts := base.Add(time.Duration(i) * time.Minute)
			must(t, os.Chtimes(p, ts, ts))
		}
	}
	return []string{"tree", "pkg", "other.txt"}
}

// snapshot describes every entry under roots, for comparing a tree before
// archiving with the same tree after restoring.
func snapshot(t *testing.T, roots []string) map[string]string {
	t.Helper()
	s := map[string]string{}
	for _, root := range roots {
		must(t, filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			fi, err := os.Lstat(p)
			if err != nil {
				return err
			}
			switch {
			case fi.Mode()&fs.ModeSymlink != 0:
				target, err := os.Readlink(p)
				if err != nil {
					return err
				}
				s[p] = "symlink -> " + target
			case fi.IsDir():
				s[p] = fmt.Sprintf("dir %v %d", fi.Mode().Perm(), fi.ModTime().Unix())
			default:
				data, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				s[p] = fmt.Sprintf("file %v %d %q", fi.Mode().Perm(), fi.ModTime().Unix(), data)
			}
			return nil
		}))
	}
	return s
}

func wipe(t *testing.T, roots []string) {
	t.Helper()
	makeWritable(".")
	for _, r := range roots {
		must(t, os.RemoveAll(r))
	}
}

func checkRestored(t *testing.T, roots []string, want map[string]string) {
	t.Helper()
	got := snapshot(t, roots)
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if got[k] != want[k] {
			t.Errorf("%s: got %q, want %q", k, got[k], want[k])
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s: unexpected", k)
		}
	}
	a, errA := os.Stat("tree/data.txt")
	b, errB := os.Stat("tree/hard")
	if errA != nil || errB != nil || !os.SameFile(a, b) {
		t.Errorf("tree/hard is no longer a hard link to tree/data.txt")
	}
}

func gnuTar(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("tar")
	if err != nil {
		t.Skip("tar not installed")
	}
	out, err := exec.Command(p, "--version").Output()
	if err != nil || !bytes.Contains(out, []byte("GNU tar")) {
		t.Skip("tar is not GNU tar")
	}
	return p
}

func TestTarGoRoundTrip(t *testing.T) {
	newHarness(t)
	roots := buildTree(t)
	want := snapshot(t, roots)
	var buf bytes.Buffer
	must(t, writeTar(&buf, roots, io.Discard))
	wipe(t, roots)
	must(t, extractTar(&buf, ".", io.Discard))
	checkRestored(t, roots, want)
}

// The script stored `tar -cf - -- paths`; those entries must restore here.
func TestTarExtractsGNUTar(t *testing.T) {
	tarBin := gnuTar(t)
	newHarness(t)
	roots := buildTree(t)
	want := snapshot(t, roots)
	archive, err := exec.Command(tarBin, append([]string{"-cf", "-", "--"}, roots...)...).Output()
	must(t, err)
	wipe(t, roots)
	must(t, extractTar(bytes.NewReader(archive), ".", io.Discard))
	checkRestored(t, roots, want)
}

// The script restored with `tar -xf -`; entries written here must work there.
func TestGNUTarExtractsTar(t *testing.T) {
	tarBin := gnuTar(t)
	newHarness(t)
	roots := buildTree(t)
	want := snapshot(t, roots)
	var buf bytes.Buffer
	must(t, writeTar(&buf, roots, io.Discard))
	wipe(t, roots)
	cmd := exec.Command(tarBin, "-xf", "-")
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tar -xf: %v\n%s", err, out)
	}
	checkRestored(t, roots, want)
}

type member struct {
	name, link string
	typ        byte
	body       string
}

func archive(t *testing.T, members ...member) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		hdr := &tar.Header{Name: m.name, Linkname: m.link, Typeflag: m.typ, Mode: 0o644, Size: int64(len(m.body)), ModTime: time.Now()}
		if m.typ == tar.TypeDir {
			hdr.Mode = 0o755
		}
		must(t, tw.WriteHeader(hdr))
		_, err := tw.Write([]byte(m.body))
		must(t, err)
	}
	must(t, tw.Close())
	return &buf
}

func TestExtractRefusesDotDot(t *testing.T) {
	newHarness(t)
	must(t, os.Mkdir("x", 0o755))
	err := extractTar(archive(t,
		member{name: "ok.txt", typ: tar.TypeReg, body: "ok"},
		member{name: "../evil.txt", typ: tar.TypeReg, body: "evil"},
	), "x", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "contains '..'") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat("evil.txt"); err == nil {
		t.Fatalf("wrote outside the extraction directory")
	}
}

func TestExtractStripsLeadingSlash(t *testing.T) {
	newHarness(t)
	must(t, os.Mkdir("x", 0o755))
	must(t, extractTar(archive(t, member{name: "/abs/file.txt", typ: tar.TypeReg, body: "a"}), "x", io.Discard))
	if got := readFile(t, "x/abs/file.txt"); got != "a" {
		t.Fatalf("content %q", got)
	}
}

func TestExtractReplacesSymlinkInsteadOfWritingThrough(t *testing.T) {
	newHarness(t)
	writeFile(t, "outside.txt", "keep")
	must(t, os.Mkdir("x", 0o755))
	must(t, os.Symlink("../outside.txt", "x/f"))
	must(t, extractTar(archive(t, member{name: "f", typ: tar.TypeReg, body: "new"}), "x", io.Discard))
	if got := readFile(t, "outside.txt"); got != "keep" {
		t.Fatalf("wrote through the symlink: %q", got)
	}
	if fi, err := os.Lstat("x/f"); err != nil || !fi.Mode().IsRegular() || readFile(t, "x/f") != "new" {
		t.Fatalf("x/f not replaced: %v %v", fi, err)
	}
}

func TestExtractCannotEscapeThroughArchivedSymlink(t *testing.T) {
	newHarness(t)
	must(t, os.Mkdir("x", 0o755))
	must(t, os.Mkdir("target", 0o755))
	abs, err := filepath.Abs("target")
	must(t, err)
	err = extractTar(archive(t,
		member{name: "l", typ: tar.TypeSymlink, link: abs},
		member{name: "l/pwned", typ: tar.TypeReg, body: "p"},
	), "x", io.Discard)
	if err == nil {
		t.Fatalf("extracted through a symlink leaving the directory")
	}
	if _, err := os.Stat("target/pwned"); err == nil {
		t.Fatalf("wrote outside the extraction directory")
	}
}

func TestExtractKeepsExistingDirectories(t *testing.T) {
	newHarness(t)
	writeFile(t, "keep/old.txt", "old")
	writeFile(t, "keep/replace.txt", "before")
	must(t, extractTar(archive(t,
		member{name: "keep/", typ: tar.TypeDir},
		member{name: "keep/new.txt", typ: tar.TypeReg, body: "new"},
		member{name: "keep/replace.txt", typ: tar.TypeReg, body: "after"},
	), ".", io.Discard))
	if got := readFile(t, "keep/old.txt") + readFile(t, "keep/new.txt") + readFile(t, "keep/replace.txt"); got != "oldnewafter" {
		t.Fatalf("got %q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
