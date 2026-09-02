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

func TestExcludedComponent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{"coreos-foo", true},
		{"eck-bar", true},
		{"not-excluded", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := excludedComponent(tt.name)
			if got != tt.want {
				t.Fatalf("excludedComponent(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestUpdateConfigVersions(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := "versions.yml"
	path := filepath.Join(tmpDir, configFile)

	origYAML := `# Components defined here are required to be kept in sync with hack/gen-versions/enterprise.go.tpl
title: master
components:
  node:
    version: master
  cni:
    version: master
  eck-kibana:
    version: 8.19.10
  # coreos-prometheus holds the version of prometheus built for tigera/prometheus,
  # which prometheus operator uses to validate.
  coreos-prometheus:
    version: v3.9.1
  gateway-api-envoy-gateway:
    image: envoy-gateway
    version: master
`
	if err := os.WriteFile(path, []byte(origYAML), 0o644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	newVersion := "v1.32.4"
	if err := updateConfigVersions(tmpDir, configFile, newVersion); err != nil {
		t.Fatalf("modifyConfig failed: %v", err)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read modified config: %v", err)
	}
	got := string(out)
	want := `# Components defined here are required to be kept in sync with hack/gen-versions/enterprise.go.tpl
title: v1.32.4
components:
  node:
    version: v1.32.4
  cni:
    version: v1.32.4
  eck-kibana:
    version: 8.19.10
  # coreos-prometheus holds the version of prometheus built for tigera/prometheus,
  # which prometheus operator uses to validate.
  coreos-prometheus:
    version: v3.9.1
  gateway-api-envoy-gateway:
    image: envoy-gateway
    version: v1.32.4
`
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("modified config mismatch (-want +got):\n%s", diff)
	}
}

func TestCalicoConfigVersions(t *testing.T) {
	t.Parallel()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		td := t.TempDir()
		full := filepath.Join(td, CalicoConfigPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("failed to create config directory: %v", err)
		}
		content := "title: v3.25.0\n"
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("failed to write version file: %v", err)
		}

		got, err := CalicoConfigVersions(td)
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
		full := filepath.Join(td, CalicoConfigPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("failed to create config directory: %v", err)
		}
		// invalid YAML that will cause unmarshal to fail for expected struct
		if err := os.WriteFile(full, []byte(":::: not yaml :::"), 0o644); err != nil {
			t.Fatalf("failed to write bad yaml file: %v", err)
		}

		_, err := CalicoConfigVersions(td)
		if err == nil {
			t.Fatalf("expected unmarshal error, got nil")
		}
		if !strings.Contains(err.Error(), "parsing config versions YAML") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}
