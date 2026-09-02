// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package versions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestEnterpriseConfigVersions(t *testing.T) {
	t.Parallel()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		td := t.TempDir()
		full := filepath.Join(td, EnterpriseConfigPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("failed to create config directory: %v", err)
		}
		content := "title: v3.25.0\n"
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write version file: %v", err)
		}

		got, err := EnterpriseConfigVersions(td)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := &CalicoVersion{Title: "v3.25.0"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("retrieved version mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("unmarshal error", func(t *testing.T) {
		t.Parallel()
		td := t.TempDir()
		full := filepath.Join(td, EnterpriseConfigPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("failed to create config directory: %v", err)
		}
		// invalid YAML that will cause unmarshal to fail for expected struct
		if err := os.WriteFile(full, []byte(":::: not yaml :::"), 0o644); err != nil {
			t.Fatalf("failed to write bad yaml file: %v", err)
		}

		_, err := EnterpriseConfigVersions(td)
		if err == nil {
			t.Fatalf("expected unmarshal error, got nil")
		}
		if !strings.Contains(err.Error(), "parsing config versions YAML") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}
