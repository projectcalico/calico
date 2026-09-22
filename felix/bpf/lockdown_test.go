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

package bpf

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestKernelLockdownConfidentiality(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{"confidentiality active", "none integrity [confidentiality]\n", true},
		{"integrity active", "none [integrity] confidentiality\n", false},
		{"none active", "[none] integrity confidentiality\n", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lockdown")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}
			if got := kernelLockdownConfidentiality(path); got != tc.want {
				t.Errorf("kernelLockdownConfidentiality(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if kernelLockdownConfidentiality(filepath.Join(t.TempDir(), "does-not-exist")) {
			t.Error("expected false when the lockdown file is absent")
		}
	})
}

// fakeSecurityfs models the mount as the appearance of the lockdown file, so a
// read that happens outside the mount window sees nothing.
type fakeSecurityfs struct {
	mounted    bool
	mountErr   error
	file       string
	mountCalls int
	umountCall int
}

func (f *fakeSecurityfs) asSecurityfs() securityfs {
	return securityfs{
		isMounted: func(string) bool { return f.mounted },
		mount: func(string) error {
			f.mountCalls++
			if f.mountErr != nil {
				return f.mountErr
			}
			f.mounted = true
			return os.WriteFile(f.file, []byte("none integrity [confidentiality]\n"), 0o644)
		},
		unmount: func(string) error {
			f.umountCall++
			f.mounted = false
			return os.Remove(f.file)
		},
	}
}

func TestReadLockdown(t *testing.T) {
	t.Run("mounts and unmounts when securityfs is absent", func(t *testing.T) {
		fs := &fakeSecurityfs{file: filepath.Join(t.TempDir(), "lockdown")}
		if got := readLockdown(fs.asSecurityfs(), "/mnt", fs.file); !got {
			t.Error("expected the lockdown file to be read while securityfs was mounted")
		}
		if fs.mountCalls != 1 || fs.umountCall != 1 {
			t.Errorf("mount calls = %d, unmount calls = %d, want 1 and 1", fs.mountCalls, fs.umountCall)
		}
	})

	t.Run("leaves a pre-existing mount alone", func(t *testing.T) {
		fs := &fakeSecurityfs{mounted: true, file: filepath.Join(t.TempDir(), "lockdown")}
		if err := os.WriteFile(fs.file, []byte("none integrity [confidentiality]\n"), 0o644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
		if got := readLockdown(fs.asSecurityfs(), "/mnt", fs.file); !got {
			t.Error("expected true when securityfs is already mounted")
		}
		if fs.mountCalls != 0 || fs.umountCall != 0 {
			t.Errorf("mount calls = %d, unmount calls = %d, want 0 and 0", fs.mountCalls, fs.umountCall)
		}
	})

	t.Run("tolerates a kernel without securityfs", func(t *testing.T) {
		fs := &fakeSecurityfs{
			mountErr: unix.ENOENT,
			file:     filepath.Join(t.TempDir(), "lockdown"),
		}
		if readLockdown(fs.asSecurityfs(), "/mnt", fs.file) {
			t.Error("expected false when securityfs cannot be mounted")
		}
		if fs.umountCall != 0 {
			t.Errorf("unmount calls = %d, want 0 — nothing was mounted", fs.umountCall)
		}
	})
}
