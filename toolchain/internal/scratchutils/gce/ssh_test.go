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

package gce

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tarDir and untar are the two halves of PutDir/GetDir: a tree that survives both
// unchanged is the contract.
func TestTarDirUntarRoundTrip(t *testing.T) {
	src := t.TempDir()
	files := map[string]string{
		"top.txt":            "top",
		"sub/nested.txt":     "nested",
		"sub/deep/leaf.txt":  "leaf",
		"sub/deep/empty.txt": "",
	}
	for rel, content := range files {
		p := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	if err := tarDir(src, &buf); err != nil {
		t.Fatalf("tarDir: %v", err)
	}
	dst := t.TempDir()
	if err := untar(&buf, dst); err != nil {
		t.Fatalf("untar: %v", err)
	}
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
}

// GetDir untars whatever the remote sends; ../ entries must not escape destDir.
func TestUntarRejectsPathEscape(t *testing.T) {
	for _, name := range []string{
		"../escaped.txt",
		"../../escaped.txt",
		"sub/../../escaped.txt",
		"/absolute.txt",
	} {
		dst := t.TempDir()
		// Where a successful escape would land.
		outside := filepath.Join(filepath.Dir(dst), "escaped.txt")
		_ = os.Remove(outside)

		err := untar(bytes.NewReader(tarWith(t, name, "pwned")), dst)
		if _, statErr := os.Stat(outside); statErr == nil {
			os.Remove(outside)
			t.Fatalf("%q escaped the destination directory", name)
		}
		// An absolute path is cleaned into destDir rather than rejected; both are
		// safe, so only require that nothing escaped.
		if err != nil && !strings.Contains(err.Error(), "escapes dest") {
			t.Errorf("%q: unexpected error %v", name, err)
		}
	}
}

// A missing remote dir makes GetDir's `cd ... || true` emit nothing -- the normal
// "no artifacts this run" case, not a failure.
func TestUntarEmptyStreamIsNotAnError(t *testing.T) {
	dst := t.TempDir()
	if err := untar(bytes.NewReader(nil), dst); err != nil {
		t.Fatalf("empty stream: %v", err)
	}
}

func TestUntarCreatesDestination(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "does", "not", "exist")
	if err := untar(bytes.NewReader(tarWith(t, "f.txt", "x")), dst); err != nil {
		t.Fatalf("untar: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "f.txt"))
	if err != nil || string(got) != "x" {
		t.Fatalf("f.txt = %q, %v", got, err)
	}
}

// tarWith writes one file at the given (possibly hostile) name; archive/tar emits
// it verbatim, which is the point.
func tarWith(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tw, content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
