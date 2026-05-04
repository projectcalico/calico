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

package flexvol

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallDriverCopiesRunningBinary(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "uds")

	if err := installDriver(dst); err != nil {
		t.Fatalf("installDriver: %v", err)
	}

	// Source is whatever runs the test (the test binary). We assert the
	// destination is byte-identical so the symlink-by-argv[0] dispatch in
	// cmd/calico/main.go gets the same binary kubelet would have called
	// directly.
	src, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	srcBytes, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}
	dstBytes, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !bytes.Equal(srcBytes, dstBytes) {
		t.Fatalf("dst (%d bytes) does not match src (%d bytes)", len(dstBytes), len(srcBytes))
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o550 {
		t.Errorf("dst permissions = %#o, want 0550", mode)
	}
}

func TestInstallDriverRequiresTarget(t *testing.T) {
	if err := installDriver(""); err == nil {
		t.Fatal("expected error when target is empty")
	}
}

func TestInstallDriverOverwritesExistingFile(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "uds")
	if err := os.WriteFile(dst, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed dst: %v", err)
	}

	if err := installDriver(dst); err != nil {
		t.Fatalf("installDriver: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if bytes.Equal(got, []byte("stale")) {
		t.Fatal("install did not overwrite existing file")
	}
}
