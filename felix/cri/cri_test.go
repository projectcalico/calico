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

package cri

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectSocketPath(t *testing.T) {
	// Build a fake host root with a containerd.sock at /run/containerd/.
	// DetectSocketPath looks under hostRootPrefix; point that at the
	// tmp dir.
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "run", "containerd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "run", "containerd", "containerd.sock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	orig := hostRootPrefix
	hostRootPrefix = tmp
	t.Cleanup(func() { hostRootPrefix = orig })

	got, err := DetectSocketPath()
	if err != nil {
		t.Fatalf("DetectSocketPath: %v", err)
	}
	if got != "/run/containerd/containerd.sock" {
		t.Fatalf("DetectSocketPath got %q", got)
	}
}

func TestDetectSocketPath_None(t *testing.T) {
	tmp := t.TempDir()
	orig := hostRootPrefix
	hostRootPrefix = tmp
	t.Cleanup(func() { hostRootPrefix = orig })

	if _, err := DetectSocketPath(); err == nil {
		t.Fatalf("expected error when no socket present at any well-known path")
	}
}

func TestDetectSocketPath_CRIO(t *testing.T) {
	// /var/run/crio/crio.sock should be found via the /var/run -> /run
	// alias.
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "run", "crio"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "run", "crio", "crio.sock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	orig := hostRootPrefix
	hostRootPrefix = tmp
	t.Cleanup(func() { hostRootPrefix = orig })

	got, err := DetectSocketPath()
	if err != nil {
		t.Fatalf("DetectSocketPath: %v", err)
	}
	if got != "/run/crio/crio.sock" {
		t.Fatalf("DetectSocketPath got %q", got)
	}
}

func TestPidFromInfo(t *testing.T) {
	cases := []struct {
		name    string
		info    map[string]string
		wantPid int
		wantOK  bool
	}{
		{"containerd-style", map[string]string{"info": `{"sandboxID":"abc","pid":4321,"runtime":"runc"}`}, 4321, true},
		{"with-whitespace", map[string]string{"info": `{ "pid":  17 }`}, 17, true},
		{"no-info-key", map[string]string{}, 0, false},
		{"no-pid-key", map[string]string{"info": `{"sandbox":"x"}`}, 0, false},
		{"pid-not-numeric", map[string]string{"info": `{"pid":"abc"}`}, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := pidFromInfo(c.info)
			if got != c.wantPid || ok != c.wantOK {
				t.Fatalf("pidFromInfo got (%d,%v), want (%d,%v)", got, ok, c.wantPid, c.wantOK)
			}
		})
	}
}

func TestViaHostRoot(t *testing.T) {
	// Build a fake host root: /var/run is a symlink to /run, with real
	// dirs underneath. viaHostRoot uses SecureJoin against
	// hostRootPrefix so the /var/run symlink must be followed against
	// that root, not the test process's real /.
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "run", "containerd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "var"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/run", filepath.Join(tmp, "var", "run")); err != nil {
		t.Fatal(err)
	}
	orig := hostRootPrefix
	hostRootPrefix = tmp
	t.Cleanup(func() { hostRootPrefix = orig })

	cases := []struct {
		in, want string
	}{
		// Plain pass-through under /run (no symlink to follow).
		{"/run/containerd/containerd.sock", tmp + "/run/containerd/containerd.sock"},
		// /var/run -> /run symlink is followed against the fake root.
		{"/var/run/containerd/containerd.sock", tmp + "/run/containerd/containerd.sock"},
		// Special cases that should pass through unchanged.
		{"", ""},
		{"relative/path", "relative/path"},
		{tmp + "/already", tmp + "/already"},
	}
	for _, c := range cases {
		if got := viaHostRoot(c.in); got != c.want {
			t.Errorf("viaHostRoot(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
