// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package outputs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestWriteSummary(t *testing.T) {
	tmpDir := t.TempDir()

	started := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	completed := time.Date(2026, 1, 15, 10, 5, 0, 0, time.UTC)

	s := StepSummary{
		Status:    "success",
		Started:   started,
		Completed: completed,
		Outputs: map[string]any{
			"branch": "build-v3.32.0",
		},
	}

	if err := WriteSummary(tmpDir, "v3.32.0", "release-prep", s); err != nil {
		t.Fatalf("WriteSummary() error = %v", err)
	}

	outPath := filepath.Join(tmpDir, "summary", "v3.32.0", "release-prep.yaml")
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read summary file: %v", err)
	}

	var got StepSummary
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("failed to unmarshal summary: %v", err)
	}

	if got.Status != s.Status {
		t.Errorf("Status = %q, want %q", got.Status, s.Status)
	}
	if got.Outputs["branch"] != s.Outputs["branch"] {
		t.Errorf("Outputs[branch] = %v, want %v", got.Outputs["branch"], s.Outputs["branch"])
	}
}

func TestWriteSummary_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "nested", "_output")

	s := StepSummary{
		Status: "success",
	}

	if err := WriteSummary(baseDir, "v3.32.0", "release-prep", s); err != nil {
		t.Fatalf("WriteSummary() error = %v", err)
	}

	outPath := filepath.Join(baseDir, "summary", "v3.32.0", "release-prep.yaml")
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Error("expected summary file to be created")
	}
}

func TestWriteSummary_FailureStatus(t *testing.T) {
	tmpDir := t.TempDir()

	s := StepSummary{
		Status: "failure",
	}

	if err := WriteSummary(tmpDir, "v3.32.0", "release-prep", s); err != nil {
		t.Fatalf("WriteSummary() error = %v", err)
	}

	outPath := filepath.Join(tmpDir, "summary", "v3.32.0", "release-prep.yaml")
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read summary file: %v", err)
	}

	var got StepSummary
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("failed to unmarshal summary: %v", err)
	}

	if got.Status != "failure" {
		t.Errorf("Status = %q, want %q", got.Status, "failure")
	}
}

func TestWriteSummary_OmitsEmptyOutputs(t *testing.T) {
	tmpDir := t.TempDir()

	s := StepSummary{
		Status: "success",
	}

	if err := WriteSummary(tmpDir, "v3.32.0", "release-prep", s); err != nil {
		t.Fatalf("WriteSummary() error = %v", err)
	}

	outPath := filepath.Join(tmpDir, "summary", "v3.32.0", "release-prep.yaml")
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read summary file: %v", err)
	}

	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if _, ok := m["outputs"]; ok {
		t.Error("expected 'outputs' to be omitted when empty")
	}
}
