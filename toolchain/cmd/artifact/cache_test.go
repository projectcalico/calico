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
	"bytes"
	"os"
	"os/exec"
	"slices"
	"testing"
)

// The cache level is $CI_CACHE_STORAGE/$CI_GIT_REPO_NAME, with the
// harness's trailing slash on the former trimmed.
const cachePrefix = "c/calico/"

func TestCacheArgumentErrors(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		unset string
		want  string
	}{
		{args: []string{"cache", "list"}, unset: "CI_CACHE_STORAGE", want: "cache: CI_CACHE_STORAGE is not set"},
		{args: []string{"cache", "list"}, unset: "CI_GIT_REPO_NAME", want: "cache: CI_GIT_REPO_NAME is not set"},
		{args: []string{"cache"}, want: "cache: missing operation (expected store, restore, has_key, delete or list)"},
		{args: []string{"cache", "save"}, want: "cache: unknown operation 'save' (expected store, restore, has_key, delete or list)"},
		{args: []string{"cache", "restore"}, want: "cache restore: missing key"},
		{args: []string{"cache", "store", "k"}, want: "cache store: need a file or directory to cache"},
		{args: []string{"cache", "store", "k", "/abs"}, want: "cache store: '/abs' must be relative to the working directory"},
		{args: []string{"cache", "store", "k", "a/../b"}, want: "cache store: 'a/../b' must not contain '..'"},
		{args: []string{"cache", "store", "k", "missing"}, want: "cache store: 'missing' does not exist"},
	} {
		h := newHarness(t)
		if tc.unset != "" {
			delete(h.env, tc.unset)
		}
		h.mustRun(1, tc.args...)
		h.wantStderr("[ERROR] artifact: " + tc.want + "\n")
	}
}

func TestCacheKeyValidation(t *testing.T) {
	keys := map[string]string{
		"gs://b/k": "cache: 'gs://b/k' is a location, not a key",
		"/k":       "cache: key '/k' must not start with '/'",
		"a..b":     "cache: key 'a..b' must not contain '..'",
		"-k":       "cache: unexpected option '-k'",
	}
	for _, op := range []string{"store", "restore", "has_key", "delete"} {
		for key, want := range keys {
			h := newHarness(t)
			writeFile(t, "f", "f")
			h.mustRun(1, "cache", op, key, "f")
			h.wantStderr("[ERROR] artifact: " + want + "\n")
		}
	}
	for _, op := range []string{"store", "has_key", "delete"} {
		h := newHarness(t)
		h.mustRun(1, "cache", op)
		h.wantStderr("[ERROR] artifact: cache: missing key\n")
	}
}

func TestCacheStoreRestore(t *testing.T) {
	h := newHarness(t)
	roots := buildTree(t)
	want := snapshot(t, roots)

	h.mustRun(0, append([]string{"cache", "store", "deps-1"}, roots...)...)
	h.wantStdout("stored deps-1\n")
	o := h.bucket("cache").get(t, cachePrefix+"deps-1")
	if o.contentType != "application/octet-stream" {
		t.Errorf("content type %q", o.contentType)
	}

	wipe(t, roots)
	h.mustRun(0, "cache", "restore", "deps-1")
	h.wantStdout("restored deps-1\n")
	checkRestored(t, roots, want)
}

func TestCacheStoreReplaces(t *testing.T) {
	h := newHarness(t)
	writeFile(t, "f", "one")
	h.mustRun(0, "cache", "store", "k", "f")
	writeFile(t, "f", "two")
	h.mustRun(0, "cache", "store", "k", "f")
	must(t, os.Remove("f"))
	h.mustRun(0, "cache", "restore", "k")
	if got := readFile(t, "f"); got != "two" {
		t.Fatalf("restored %q", got)
	}
}

func TestCacheStoreFailureKeepsExistingEntry(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read the unreadable file")
	}
	h := newHarness(t)
	h.bucket("cache").put(cachePrefix+"k", []byte("previous"), "", nil)
	writeFile(t, "dir/a", "a")
	writeFile(t, "dir/secret", "s")
	must(t, os.Chmod("dir/secret", 0))
	h.mustRun(1, "cache", "store", "k", "dir")
	h.wantStderr("permission denied")
	if got := string(h.bucket("cache").get(t, cachePrefix+"k").data); got != "previous" {
		t.Fatalf("a failed store replaced the entry with %d bytes", len(got))
	}
}

func TestCacheRestoreFallback(t *testing.T) {
	h := newHarness(t)
	writeFile(t, "vendor/x", "main")
	h.mustRun(0, "cache", "store", "deps-main", "vendor")
	must(t, os.RemoveAll("vendor"))

	h.mustRun(0, "cache", "restore", "deps-abc,,deps-main")
	h.wantStdout("restored deps-main\n")
	if got := readFile(t, "vendor/x"); got != "main" {
		t.Fatalf("restored %q", got)
	}

	// Later keys are only checked when reached.
	h.mustRun(0, "cache", "restore", "deps-main,/bad")
	h.mustRun(1, "cache", "restore", "deps-abc,/bad,deps-main")
	h.wantStderr("cache: key '/bad' must not start with '/'")
}

func TestCacheRestoreMiss(t *testing.T) {
	h := newHarness(t)
	h.mustRun(0, "cache", "restore", "a,b")
	h.wantStdout("MISS a,b\n")
}

func TestCacheHasKey(t *testing.T) {
	h := newHarness(t)
	h.bucket("cache").put(cachePrefix+"warm", nil, "", nil)
	h.mustRun(0, "cache", "has_key", "warm")
	h.wantStdout("HIT warm\n")
	h.mustRun(1, "cache", "has_key", "cold")
	h.wantStdout("MISS cold\n")
	if h.stderr.Len() != 0 {
		t.Errorf("a miss printed an error: %q", h.stderr.String())
	}
}

func TestCacheDelete(t *testing.T) {
	h := newHarness(t)
	h.bucket("cache").put(cachePrefix+"k", nil, "", nil)
	h.mustRun(0, "cache", "delete", "k")
	h.wantStdout("deleted k\n")
	h.mustRun(0, "cache", "delete", "k")
	h.wantStdout("MISS k\n")
	if got := h.bucket("cache").names(); len(got) != 0 {
		t.Fatalf("objects left %v", got)
	}
}

func TestCacheList(t *testing.T) {
	h := newHarness(t)
	h.mustRun(0, "cache", "list")
	h.wantStdout("")

	b := h.bucket("cache")
	for _, k := range []string{"b-key", "a-key", "group/k1", "group/k2"} {
		b.put(cachePrefix+k, nil, "", nil)
	}
	b.put("c/calico-other/k", nil, "", nil)
	h.mustRun(0, "cache", "list")
	h.wantStdout("gs://cache/c/calico/a-key\ngs://cache/c/calico/b-key\ngs://cache/c/calico/group/\n")
}

// Entries the script stored with `tar -cf - -- paths | gsutil cp - <key>`
// must restore with this tool.
func TestCacheRestoresScriptEntry(t *testing.T) {
	tarBin := gnuTar(t)
	h := newHarness(t)
	roots := buildTree(t)
	want := snapshot(t, roots)
	data, err := exec.Command(tarBin, append([]string{"-cf", "-", "--"}, roots...)...).Output()
	must(t, err)
	h.bucket("cache").put(cachePrefix+"k", data, "", nil)
	wipe(t, roots)
	h.mustRun(0, "cache", "restore", "k")
	checkRestored(t, roots, want)
}

// Entries stored here must restore with the script's
// `gsutil cp <key> - | tar -xf -`.
func TestScriptRestoresCacheEntry(t *testing.T) {
	tarBin := gnuTar(t)
	h := newHarness(t)
	roots := buildTree(t)
	want := snapshot(t, roots)
	h.mustRun(0, append([]string{"cache", "store", "k"}, roots...)...)
	wipe(t, roots)
	cmd := exec.Command(tarBin, "-xf", "-")
	cmd.Stdin = bytes.NewReader(h.bucket("cache").get(t, cachePrefix+"k").data)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tar -xf: %v\n%s", err, out)
	}
	checkRestored(t, roots, want)
	if got := h.bucket("cache").names(); !slices.Equal(got, []string{cachePrefix + "k"}) {
		t.Fatalf("objects %v", got)
	}
}
