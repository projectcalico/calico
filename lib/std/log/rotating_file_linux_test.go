//go:build linux

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

package log

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingFileFollowsRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := newRotatingFile(path, 0644)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("before-rotate\n")); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	// Simulate logrotate: rename current file aside.
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// Next write should reopen at the original path.
	if _, err := w.Write([]byte("after-rotate\n")); err != nil {
		t.Fatalf("post-rotate Write: %v", err)
	}

	// The rotated file should contain only the pre-rotate line.
	got, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatalf("read rotated: %v", err)
	}
	if string(got) != "before-rotate\n" {
		t.Errorf("rotated file: want %q, got %q", "before-rotate\n", string(got))
	}

	// The original path should contain only the post-rotate line.
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read post-rotate: %v", err)
	}
	if string(got) != "after-rotate\n" {
		t.Errorf("new file: want %q, got %q", "after-rotate\n", string(got))
	}
}

func TestRotatingFileReopensWhenDeleted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := newRotatingFile(path, 0644)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	defer w.Close()

	if _, err := w.Write([]byte("before\n")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := w.Write([]byte("after\n")); err != nil {
		t.Fatalf("post-remove Write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "after\n" {
		t.Errorf("post-remove file: want %q, got %q", "after\n", string(got))
	}
}
