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
