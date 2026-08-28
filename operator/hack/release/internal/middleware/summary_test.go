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

package middleware

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

func TestWriteSummary(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "hack", "release", "_output")

	started := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	completed := time.Date(2026, 1, 15, 10, 5, 0, 0, time.UTC)

	s := StepSummary{
		Status:    "success",
		Started:   started,
		Completed: completed,
		Outputs: map[string]any{
			"branch": "build-v1.36.0",
		},
	}

	if err := WriteSummary(baseDir, "v1.36.0", "release-prep", s); err != nil {
		t.Fatalf("WriteSummary() error = %v", err)
	}

	outPath := filepath.Join(baseDir, "summary", "v1.36.0", "release-prep.yaml")
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read summary file: %v", err)
	}

	var got StepSummary
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("failed to unmarshal summary: %v", err)
	}

	if got.Status != "success" {
		t.Errorf("Status = %q, want %q", got.Status, "success")
	}
	if !got.Started.Equal(started) {
		t.Errorf("Started = %v, want %v", got.Started, started)
	}
	if !got.Completed.Equal(completed) {
		t.Errorf("Completed = %v, want %v", got.Completed, completed)
	}
	if got.Outputs["branch"] != "build-v1.36.0" {
		t.Errorf("Outputs[branch] = %v, want %q", got.Outputs["branch"], "build-v1.36.0")
	}
}

func TestWriteSummary_CreatesDirectory(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "nested", "output")

	s := StepSummary{
		Status: "success",
	}

	if err := WriteSummary(baseDir, "v1.36.0", "release-build", s); err != nil {
		t.Fatalf("WriteSummary() error = %v", err)
	}

	outPath := filepath.Join(baseDir, "summary", "v1.36.0", "release-build.yaml")
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Error("expected summary file to be created")
	}
}

func TestWriteSummary_FailureStatus(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "_output")

	s := StepSummary{
		Status: "failure",
	}

	if err := WriteSummary(baseDir, "v1.36.0", "release-publish", s); err != nil {
		t.Fatalf("WriteSummary() error = %v", err)
	}

	outPath := filepath.Join(baseDir, "summary", "v1.36.0", "release-publish.yaml")
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
	baseDir := filepath.Join(t.TempDir(), "_output")

	s := StepSummary{
		Status: "success",
	}

	if err := WriteSummary(baseDir, "v1.36.0", "release-build", s); err != nil {
		t.Fatalf("WriteSummary() error = %v", err)
	}

	outPath := filepath.Join(baseDir, "summary", "v1.36.0", "release-build.yaml")
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

func TestWithSummary(t *testing.T) {
	tests := []struct {
		name            string
		actionKey       string
		actionOutputs   map[string]any
		actionErr       error
		repoRootErr     error
		wantStatus      string
		wantKey         string // key used in the on-disk path
		wantFileWritten bool   // whether a summary file should exist
		wantReturnedErr bool   // whether WithSummary should return an error
		wantHasOutputs  bool   // whether the YAML contains an outputs key
	}{
		{
			name:            "success with outputs",
			actionKey:       "v1.36.0",
			actionOutputs:   map[string]any{"branch": "build-v1.36.0"},
			actionErr:       nil,
			wantStatus:      "success",
			wantKey:         "v1.36.0",
			wantFileWritten: true,
			wantReturnedErr: false,
			wantHasOutputs:  true,
		},
		{
			name:            "failure status when action errors",
			actionKey:       "v1.36.0",
			actionErr:       errors.New("boom"),
			wantStatus:      "failure",
			wantKey:         "v1.36.0",
			wantFileWritten: true,
			wantReturnedErr: true,
		},
		{
			name:            "empty key falls back to unknown",
			actionKey:       "",
			actionErr:       errors.New("early exit"),
			wantStatus:      "failure",
			wantKey:         "unknown",
			wantFileWritten: true,
			wantReturnedErr: true,
		},
		{
			name:            "repo-root resolver failure does not mask action error",
			actionKey:       "v1.36.0",
			actionErr:       errors.New("action failed"),
			repoRootErr:     errors.New("not a git repo"),
			wantFileWritten: false,
			wantReturnedErr: true,
		},
		{
			name:            "repo-root resolver failure on success path returns nil",
			actionKey:       "v1.36.0",
			actionErr:       nil,
			repoRootErr:     errors.New("not a git repo"),
			wantFileWritten: false,
			wantReturnedErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repoRoot := t.TempDir()
			repoRootFn := func() (string, error) {
				if tc.repoRootErr != nil {
					return "", tc.repoRootErr
				}
				return repoRoot, nil
			}

			action := func(_ context.Context, _ *cli.Command) (string, map[string]any, error) {
				return tc.actionKey, tc.actionOutputs, tc.actionErr
			}

			err := withSummary("release-prep", action, repoRootFn)(context.Background(), &cli.Command{})

			if tc.wantReturnedErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantReturnedErr && err != nil {
				t.Errorf("expected nil error, got %v", err)
			}
			if tc.wantReturnedErr && err != nil && !errors.Is(err, tc.actionErr) {
				t.Errorf("expected error to wrap action error %v, got %v", tc.actionErr, err)
			}

			outPath := filepath.Join(repoRoot, ReleaseDir, "_output", "summary", tc.wantKey, "release-prep.yaml")
			_, statErr := os.Stat(outPath)

			if tc.wantFileWritten && statErr != nil {
				t.Fatalf("expected summary file at %s, stat err: %v", outPath, statErr)
			}
			if !tc.wantFileWritten && statErr == nil {
				t.Fatalf("expected no summary file at %s, but it exists", outPath)
			}
			if !tc.wantFileWritten {
				return
			}

			data, readErr := os.ReadFile(outPath)
			if readErr != nil {
				t.Fatalf("read summary: %v", readErr)
			}
			var got StepSummary
			if err := yaml.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal summary: %v", err)
			}
			if got.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", got.Status, tc.wantStatus)
			}
			if got.Started.IsZero() {
				t.Error("Started is zero time")
			}
			if got.Completed.Before(got.Started) {
				t.Errorf("Completed (%v) is before Started (%v)", got.Completed, got.Started)
			}

			var raw map[string]any
			if err := yaml.Unmarshal(data, &raw); err != nil {
				t.Fatalf("unmarshal raw: %v", err)
			}
			_, hasOutputs := raw["outputs"]
			if hasOutputs != tc.wantHasOutputs {
				t.Errorf("outputs key present = %v, want %v", hasOutputs, tc.wantHasOutputs)
			}
		})
	}
}

func TestWithSummary_WriteFailureDoesNotMaskActionResult(t *testing.T) {
	// Point the repo root at a path where MkdirAll will fail (a regular file).
	tmp := t.TempDir()
	notADir := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(notADir, []byte{}, 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	repoRootFn := func() (string, error) { return notADir, nil }

	t.Run("action success is preserved when summary write fails", func(t *testing.T) {
		action := func(_ context.Context, _ *cli.Command) (string, map[string]any, error) {
			return "v1.36.0", nil, nil
		}
		if err := withSummary("release-prep", action, repoRootFn)(context.Background(), &cli.Command{}); err != nil {
			t.Errorf("expected nil error from successful action, got %v", err)
		}
	})

	t.Run("action error is preserved when summary write fails", func(t *testing.T) {
		actionErr := errors.New("action failed")
		action := func(_ context.Context, _ *cli.Command) (string, map[string]any, error) {
			return "v1.36.0", nil, actionErr
		}
		err := withSummary("release-prep", action, repoRootFn)(context.Background(), &cli.Command{})
		if !errors.Is(err, actionErr) {
			t.Errorf("expected action error to be preserved, got %v", err)
		}
	})
}
