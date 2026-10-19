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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageRefusesSrcEqualsDst(t *testing.T) {
	d := t.TempDir()
	binPath := filepath.Join(d, "calico")
	const payload = "binary contents"
	if err := os.WriteFile(binPath, []byte(payload), 0o755); err != nil {
		t.Fatal(err)
	}

	err := stage(d, d)
	if err == nil {
		t.Fatal("stage(src=dst) returned nil; expected error to avoid self-truncation")
	}
	if !strings.Contains(err.Error(), "same path") {
		t.Errorf("unexpected error %q", err)
	}

	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Errorf("source file was modified: got %q, want %q", got, payload)
	}
}

func TestStageCopiesPlugins(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "stage")
	for _, name := range []string{"portmap", "host-local"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := stage(src, dst); err != nil {
		t.Fatalf("stage: %v", err)
	}

	for _, name := range []string{"portmap", "host-local"} {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != name {
			t.Errorf("%s: got %q, want %q", name, got, name)
		}
	}
}
